package eventd

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/nacl/box"

	"github.com/beekamai/network-scheme/internal/config"
	"github.com/beekamai/network-scheme/internal/creds/credstest"
	"github.com/beekamai/network-scheme/internal/devices"
	_ "github.com/beekamai/network-scheme/internal/drivers/all"
	"github.com/beekamai/network-scheme/internal/testdb"
)

func TestMain(m *testing.M) { testdb.Main(m) }

const (
	goodCommunity = "community-0123456789"
	authKey       = "auth-key-0123456789"
	privKey       = "priv-key-0123456789"
)

var seq atomic.Int64

/* harness is one eventd instance on the shared test database, with devices on 127.x.x.x addresses. */
type harness struct {
	t        *testing.T
	env      *testdb.Env
	pg       *pgxpool.Pool /* superuser: set-up and checks */
	pub      *[32]byte
	priv     *[32]byte
	group    int64
	instance string
	cfg      config.EventD
	addrs    Addrs
	cancel   context.CancelFunc
	done     chan error
	pool     *pgxpool.Pool /* what eventd uses; nms_eventd unless a test replaces it */
	enq      PollEnqueuer
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	env := testdb.New(t)
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, env: env, pg: env.Pool("postgres"), pub: pub, priv: priv, pool: env.Pool("nms_eventd"),
		instance: fmt.Sprintf("t%d", seq.Add(1))}
	ctx := context.Background()
	/* every test starts from an empty device list: eventd reads all devices of the database */
	if _, err := h.pg.Exec(ctx, `TRUNCATE core.device, core.access_profile, events.syslog, events.trap, events.storm,
		events.trap_rule, events.eventd_stats, jobs.river_job CASCADE`); err != nil {
		t.Fatal(err)
	}
	if err := h.pg.QueryRow(ctx, `INSERT INTO core.device_group (name) VALUES ('eventd-'||gen_random_uuid()) RETURNING id`).Scan(&h.group); err != nil {
		t.Fatal(err)
	}
	h.cfg = config.EventD{
		Instance: h.instance, SyslogUDP: "127.0.0.1:0", SyslogTCP: "127.0.0.1:0", SyslogTLS: config.Off, TrapUDP: "127.0.0.1:0",
	}
	h.cfg.ApplyDefaults()
	h.cfg.BatchInterval = 50 * time.Millisecond
	return h
}

/* device inserts a device with the given source address and returns its id. */
func (h *harness) device(ip string) int64 {
	h.t.Helper()
	var id int64
	if err := h.pg.QueryRow(context.Background(), `INSERT INTO core.device (name, address, group_id) VALUES ($1, $2, $3) RETURNING id`,
		"dev-"+ip, ip, h.group).Scan(&id); err != nil {
		h.t.Fatal(err)
	}
	return id
}

func (h *harness) rawProfile(id int64, kind string, ct []byte, status string) {
	h.t.Helper()
	if _, err := h.pg.Exec(context.Background(), `INSERT INTO core.access_profile (owner_kind, owner_id, kind, ciphertext, key_version, status)
		VALUES ('device', $1, $2, $3, 1, $4) ON CONFLICT (owner_kind, owner_id, kind) DO UPDATE SET ciphertext = EXCLUDED.ciphertext, status = EXCLUDED.status`,
		id, kind, ct, status); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) profile(id int64, kind string, secret any) {
	h.t.Helper()
	ct := credstest.Seal(h.pub, devices.Owner{Kind: devices.OwnerDevice, ID: id}, kind, secret, time.Now().Add(-time.Minute))
	h.rawProfile(id, kind, ct, "pending")
}

func (h *harness) community(id int64, c string) {
	h.profile(id, "snmp2c", map[string]string{"community": c})
}

func v3Secret(user string) map[string]string {
	return map[string]string{"user": user, "auth_proto": "SHA256", "auth_key": authKey, "priv_proto": "AES", "priv_key": privKey}
}

func (h *harness) v3(id int64, user string) { h.profile(id, "snmp3", v3Secret(user)) }

/* start runs eventd until stop (also registered as cleanup) and waits for the listeners. */
func (h *harness) start(mods ...func(*config.EventD)) {
	h.t.Helper()
	for _, m := range mods {
		m(&h.cfg)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.done = make(chan error, 1)
	ready := make(chan Addrs, 1)
	go func() {
		h.done <- Run(ctx, h.cfg, Deps{
			Pool: h.pool, Priv: h.priv, Pub: h.pub, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			Enqueuer: h.enq, Ready: func(a Addrs) { ready <- a }, StatsEvery: 100 * time.Millisecond,
		})
	}()
	select {
	case h.addrs = <-ready:
	case err := <-h.done:
		h.t.Fatalf("Run: %v", err)
	case <-time.After(30 * time.Second):
		h.t.Fatal("eventd did not start")
	}
	h.t.Cleanup(h.stop)
}

/* stop shuts eventd down and waits for the final writes. */
func (h *harness) stop() {
	if h.cancel == nil {
		return
	}
	h.cancel()
	h.cancel = nil
	select {
	case err := <-h.done:
		if err != nil {
			h.t.Errorf("Run: %v", err)
		}
	case <-time.After(30 * time.Second):
		h.t.Error("eventd did not stop")
	}
}

func (h *harness) count(sql string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.pg.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		h.t.Fatalf("%s: %v", sql, err)
	}
	return n
}

/* stat reads a counter of this instance from events.eventd_stats. */
func (h *harness) stat(col string) int {
	h.t.Helper()
	var n int
	err := h.pg.QueryRow(context.Background(), `SELECT coalesce((SELECT `+col+` FROM events.eventd_stats WHERE instance = $1), 0)`, h.instance).Scan(&n)
	if err != nil {
		h.t.Fatal(err)
	}
	return n
}

func eventually(t *testing.T, within time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %v", what, within)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

/* udpFrom opens a UDP socket bound to source address src towards dst. */
func udpFrom(t *testing.T, src string, dst net.Addr) *net.UDPConn {
	t.Helper()
	c, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP(src)}, dst.(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

/* snmpClient is a gosnmp sender bound to source address src. */
func snmpClient(src string, to net.Addr, mod func(*gosnmp.GoSNMP)) *gosnmp.GoSNMP {
	a := to.(*net.UDPAddr)
	g := &gosnmp.GoSNMP{
		Target: a.IP.String(), Port: uint16(a.Port), Transport: "udp4", LocalAddr: src + ":0", Version: gosnmp.Version2c, // #nosec G115 -- port
		Community: goodCommunity, Timeout: 700 * time.Millisecond, Retries: 0, Logger: quiet,
	}
	mod(g)
	return g
}

func v3Client(src string, to net.Addr, user, ak, pk string) *gosnmp.GoSNMP {
	return snmpClient(src, to, func(g *gosnmp.GoSNMP) {
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		g.MsgFlags = gosnmp.AuthPriv
		g.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName: user, AuthenticationProtocol: gosnmp.SHA256, AuthenticationPassphrase: ak,
			PrivacyProtocol: gosnmp.AES, PrivacyPassphrase: pk,
			AuthoritativeEngineID: "\x80\x00\x1f\x88\x80\x01\x02\x03\x04", AuthoritativeEngineBoots: 1, AuthoritativeEngineTime: 100,
		}
	})
}

var (
	oidLinkDown = ".1.3.6.1.6.3.1.1.5.3"
	oidTrapOID  = ".1.3.6.1.6.3.1.1.4.1.0"
	oidIfIndex  = ".1.3.6.1.2.1.2.2.1.1.7"
)

/* linkDownTrap is a v2 trap body: sysUpTime.0 is added by SendTrap. */
func linkDownTrap(inform bool) gosnmp.SnmpTrap {
	return gosnmp.SnmpTrap{IsInform: inform, Variables: []gosnmp.SnmpPDU{
		{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(12345)},
		{Name: oidTrapOID, Type: gosnmp.ObjectIdentifier, Value: oidLinkDown},
		{Name: oidIfIndex, Type: gosnmp.Integer, Value: 7},
	}}
}

/* sendTrap connects, sends and closes; it returns the send error (informs: also a missing acknowledgement). */
func sendTrap(g *gosnmp.GoSNMP, tr gosnmp.SnmpTrap) error {
	if err := g.Connect(); err != nil {
		return err
	}
	defer func() { _ = g.Conn.Close() }()
	_, err := g.SendTrap(tr)
	return err
}

/* tcpProxy forwards 127.0.0.1:port to target and can be cut and restored: a database outage. */
type tcpProxy struct {
	target string
	addr   string
	mu     sync.Mutex
	l      net.Listener
	conns  []net.Conn
}

func newProxy(t *testing.T, target string) *tcpProxy {
	p := &tcpProxy{target: target, addr: "127.0.0.1:0"}
	if err := p.up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.down)
	return p
}

func (p *tcpProxy) up() error {
	l, err := net.Listen("tcp", p.addr)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.l, p.addr = l, l.Addr().String()
	p.mu.Unlock()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", p.target)
			if err != nil {
				_ = c.Close()
				continue
			}
			p.mu.Lock()
			p.conns = append(p.conns, c, up)
			p.mu.Unlock()
			go func() { _, _ = io.Copy(up, c); _ = up.Close(); _ = c.Close() }()
			go func() { _, _ = io.Copy(c, up); _ = up.Close(); _ = c.Close() }()
		}
	}()
	return nil
}

/* down closes the listener and every connection: the database is unreachable. */
func (p *tcpProxy) down() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.l != nil {
		_ = p.l.Close()
		p.l = nil
	}
	for _, c := range p.conns {
		_ = c.Close()
	}
	p.conns = nil
}

/* depth reads the queue depth the process last reported. */
func (h *harness) depth() int { return h.stat("queue_depth") }
