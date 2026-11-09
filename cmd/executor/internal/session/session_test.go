package session_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/nacl/box"
	gossh "golang.org/x/crypto/ssh"

	"github.com/beekamai/network-scheme/cmd/executor/internal/admin"
	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/backups"
	_ "github.com/beekamai/network-scheme/cmd/executor/internal/drivers/mes6"
	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/cmd/executor/internal/policy"
	"github.com/beekamai/network-scheme/cmd/executor/internal/pub"
	"github.com/beekamai/network-scheme/cmd/executor/internal/recording"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/session"
	"github.com/beekamai/network-scheme/cmd/executor/internal/terminal"
	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/drivers/eltexmes"
	"github.com/beekamai/network-scheme/internal/execadmin"
	"github.com/beekamai/network-scheme/internal/secret"
	"github.com/beekamai/network-scheme/internal/ssh"
	"github.com/beekamai/network-scheme/internal/testdb"
	"github.com/beekamai/network-scheme/internal/ticket"
	"github.com/beekamai/network-scheme/test/sim/devemu"
	"github.com/beekamai/network-scheme/test/sim/sshemu"
)

func TestMain(m *testing.M) { testdb.Main(m) }

const pw = "session-test-password-1"

/* The registry address of the emulated MES 6.x: its fixture's interface vlan 99 carries it. */
var devAddr = netip.MustParseAddr("192.0.2.10")

var addrs atomic.Int64

var ticketKey = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

/* Device output the emulator lacks: the default gateway, its ARP entry and where its MAC was learned (guesses of the format). */
const (
	gatewayLine = "ip default-gateway 192.0.2.1\n"
	arpOut      = "  VLAN    Interface     IP address        HW address          status\n" +
		"--------------------- --------------- ------------------- -----------\n" +
		" vlan 99  gi1/0/1      192.0.2.1        a8:f9:4b:00:00:01   dynamic\n"
	macOut = "  Vlan        Mac Address         Port       Type\n" +
		"-------- --------------------- ---------- ----------\n" +
		"   99     a8:f9:4b:00:00:01     gi1/0/1    dynamic\n"
)

/* fx is one executor (registry, guard, policy, authz, publisher, backups, sessions) and one emulated MES 6.x. */
type fx struct {
	env    *testdb.Env
	guard  *freeze.Guard
	pol    *policy.Holder
	polF   string
	az     *authz.Authorizer
	adm    *admin.Admin
	pub    *pub.Publisher
	locks  *backups.Locks
	m      *session.Manager
	cfg    session.Config
	d      *devemu.Device
	key    gossh.PublicKey
	log    *sshemu.Log
	emu    netip.AddrPort
	id     int64
	row    map[string]any
	mu     sync.Mutex
	dialed []string
	offset atomic.Int64
	start  time.Time
	bpub   *[32]byte /* the backup domain: the pre-session envelopes */
	rec    *recording.Store
	users  string /* ESR: what show users lists (under mu) */
	noDial atomic.Bool
}

/* setUsers sets what the ESR's show users lists. */
func (f *fx) setUsers(u string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users = u
}

func (f *fx) now() time.Time { return f.start.Add(time.Duration(f.offset.Load())) }

type dialer struct{ f *fx }

func (d dialer) Dial(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
	d.f.mu.Lock()
	d.f.dialed = append(d.f.dialed, ap.String())
	d.f.mu.Unlock()
	if d.f.noDial.Load() {
		return nil, errors.New("test: the device refuses new connections")
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", d.f.emu.String())
}

func newFx(t *testing.T) *fx { return newLineFx(t, "mes6") }

/*
lineOf is what an emulated line needs for a session: the registry address
its fixture's interface carries, the default route appended to its
configuration, the next hop's ARP entry and MAC table row on its uplink, and
(ESR) show users listing only this session.
*/
var lineOf = map[string]struct {
	addr                      netip.Addr
	gateway, arp, macs, users string
}{
	"mes6": {devAddr, gatewayLine, arpOut, macOut, ""},
	"mes10": {netip.MustParseAddr("192.0.2.20"), gatewayLine, strings.ReplaceAll(arpOut, "gi1/0/1", "gi0/1"),
		strings.ReplaceAll(macOut, "gi1/0/1", "gi0/1"), ""},
	"esr": {netip.MustParseAddr("192.0.2.1"), "ip route 0.0.0.0/0 192.0.2.254\n",
		"Interface   IP address     MAC address        State\ngi1/0/1     192.0.2.254    a8:f9:4b:00:00:01  reachable\n",
		"Vlan  MAC address        Interface  Type\n1     a8:f9:4b:00:00:01  gi1/0/1    dynamic\n",
		"SID  User  Timeout  Level  Protocol  Host\n*  1  admin  00:29:59  15  ssh  192.0.2.200"},
}

/* newLineFx is fx over an emulated device of line (mes6, mes10, esr) whose running configuration follows what the session does. */
func newLineFx(t *testing.T, line string) *fx {
	t.Helper()
	lo := lineOf[line]
	env := testdb.New(t)
	attacktest.Reset(t, env)
	ctx := context.Background()
	keys, err := seal.Derive(&[32]byte{5})
	if err != nil {
		t.Fatal(err)
	}
	f := &fx{env: env, start: time.Now()}
	pool := env.Pool("nms_executor")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()
	reg := registry.New(pool, keys, filepath.Join(dir, "state"))
	f.guard = freeze.New(reg, pool, log)
	if err := f.guard.Start(ctx); err != nil {
		t.Fatal(err)
	}
	f.polF = filepath.Join(dir, "executor.yaml")
	f.pol = policy.New(f.polF)
	f.policy(t, "")
	if f.az, err = authz.New(authz.Config{Guard: f.guard, Reg: reg, Keys: keys, Policy: f.pol, Log: log, Now: f.now,
		TicketKey: ticketKey.Public().(ed25519.PublicKey), Started: f.start, GuardsFile: filepath.Join(dir, "guards")}); err != nil {
		t.Fatal(err)
	}
	f.adm = &admin.Admin{Guard: f.guard, Reg: reg, Keys: keys, Policy: f.pol, Log: log, Lockouts: f.az}
	f.pub = pub.New(pool, log)

	dfx, err := devemu.LoadLine(line)
	if err != nil {
		t.Fatal(err)
	}
	dfx.Running = strings.TrimRight(dfx.Running, "\n") + "\n" + lo.gateway
	f.d = devemu.New(dfx, devemu.Options{})
	f.users = lo.users
	f.d.SetShowLookup(func(cmd string) (string, bool) {
		switch cmd {
		case "show arp":
			return lo.arp, true
		case "show mac address-table":
			return lo.macs, true
		case "show users":
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.users, f.users != ""
		}
		return "", false
	})
	/* every RSA signature, so that the poller's SSH (no ssh-rsa) meets the host key gate, not an algorithm mismatch */
	f.emu, f.key, f.log = devemu.StartSSH(t, f.d, func(c *sshemu.Config) { c.Username, c.Password, c.HostKeyAlgorithms = "admin", pw, nil })
	f.id = f.panelDevice(t, fmt.Sprintf("10.%d.%d.%d", 1+addrs.Add(1)%250, time.Now().UnixNano()%250, 1+time.Now().UnixNano()/1000%250))
	f.row = map[string]any{"device_id": f.id, "address": lo.addr, "port": 22, "protocol": "ssh", "write_group": "core",
		"write_driver": line, "hostkey_algo": f.key.Type(), "hostkey_fp": gossh.FingerprintSHA256(f.key),
		"allow_ssh_rsa_sha1": true, "writes_enabled": true, "backup_via_executor": false}
	f.put(t, "write_device", f.row)
	mp := map[string]any{"id": int64(1), "write_driver": line, "model_re": "^(?:.*)$", "firmware_re": "^(?:.*)$",
		"strategies": json.RawMessage(`{}`), "note": "stand"}
	if line == "mes6" {
		mp["model_re"], mp["firmware_re"] = "^(?:MES2324)$", `^(?:6\.6\..*)$`
	}
	f.put(t, "model_profile", mp)
	f.put(t, "write_credential", map[string]any{"device_id": f.id, "kind": "ssh_write", "ciphertext": []byte{1},
		"created_at": time.Now(), "nonce": make([]byte, 16)})

	bpub, bpriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.bpub = bpub
	open := func(*registry.Snapshot, int64) (creds.Credential, error) {
		return creds.Credential{Username: "admin", Password: secret.New(pw)}, nil
	}
	f.locks = &backups.Locks{}
	sched := backups.New(backups.Config{Registry: f.guard, Net: dialer{f}, Open: open, Pool: pool, BackupPub: bpub,
		Locks: f.locks, Alert: f.pub.Alert, Log: log})
	if f.rec, err = recording.New(recording.Config{Pool: pool, MAC: keys.MAC(), Pub: bpub, Priv: bpriv, Clean: terminal.Clean,
		Policy: f.pol.Current, Live: func(id [16]byte) bool { return f.m.Live(id) }, Alert: f.pub.Alert, Audit: f.az.Record, Log: log,
		Now: f.now}); err != nil {
		t.Fatal(err)
	}
	f.cfg = session.Config{Gate: f.guard, Auth: f.az, Policy: f.pol.Current, Pool: pool, MAC: keys.MAC(), Net: dialer{f},
		Open: open, Backups: sched, Locks: f.locks, Pub: f.pub, Log: log, Now: f.now, BackupPriv: bpriv, BackupPub: bpub, Recordings: f.rec}
	f.m = session.New(f.cfg)
	return f
}

/* policy writes the policy file (enabled, plus extra YAML) and reloads it. */
func (f *fx) policy(t *testing.T, extra string) {
	t.Helper()
	if err := os.WriteFile(f.polF, []byte("enabled: true\n"+extra), 0o600); err != nil {
		t.Fatal(err)
	}
	_, cur, _ := f.pol.Reload(true)
	if cur.Err != nil {
		t.Fatalf("policy: %v", cur.Err)
	}
}

func (f *fx) put(t *testing.T, table string, row map[string]any) {
	t.Helper()
	if err := f.guard.HostWrite(context.Background(), func(_ context.Context, _ *registry.Snapshot, tx *registry.Tx) error {
		return tx.Put(table, row)
	}); err != nil {
		t.Fatal(err)
	}
}

func (f *fx) panelDevice(t *testing.T, addr string) int64 {
	t.Helper()
	p := f.env.Pool("postgres")
	var gid, id int64
	if err := p.QueryRow(context.Background(), `INSERT INTO core.device_group (name) VALUES ('ss-' || gen_random_uuid()) RETURNING id`).Scan(&gid); err != nil {
		t.Fatal(err)
	}
	if err := p.QueryRow(context.Background(), `INSERT INTO core.device (name, address, group_id) VALUES ('ss-' || gen_random_uuid(), $1, $2) RETURNING id`,
		addr, gid).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *fx) host(req execadmin.Request) execadmin.Response {
	req.V, req.Operator = execadmin.Version, "tester"
	return f.adm.Handle(context.Background(), req)
}

type who struct {
	id         int64
	name, totp string
}

/* user is a panel user with a change TOTP and write grants on groups (nmsctl). */
func (f *fx) user(t *testing.T, groups ...string) who {
	t.Helper()
	name := fmt.Sprintf("op-%d", time.Now().UnixNano()%1e9)
	var u who
	if err := f.env.Pool("postgres").QueryRow(context.Background(),
		`INSERT INTO core."user" (username, password_phc) VALUES ($1, 'x') RETURNING id`, name).Scan(&u.id); err != nil {
		t.Fatal(err)
	}
	u.name = name
	reqs := []execadmin.Request{{Cmd: execadmin.CmdEnroll}}
	for _, g := range groups {
		reqs = append(reqs, execadmin.Request{Cmd: execadmin.CmdGrant, Kind: execadmin.KindWrite, Group: g})
	}
	for _, req := range reqs {
		req.User = name
		resp := f.host(req)
		if resp.OK && resp.Confirm != nil {
			req.UserID, req.UserCreated = resp.Confirm.ID, resp.Confirm.CreatedAt
			resp = f.host(req)
		}
		if !resp.OK {
			t.Fatalf("%s: %s", req.Cmd, resp.Error)
		}
		if resp.Enrollment != nil {
			u.totp = resp.Enrollment.Secret
		}
	}
	return u
}

/* req is a request of u: a fresh ticket and the next change TOTP code. */
func (f *fx) req(t *testing.T, u who) authz.Request {
	t.Helper()
	tok, _, err := ticket.Issue(ticketKey, u.id, u.name, f.now())
	if err != nil {
		t.Fatal(err)
	}
	f.offset.Add(int64(30 * time.Second))
	c, err := totp.GenerateCodeCustom(u.totp, f.now(), totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return authz.Request{Ticket: tok, Code: c, IP: "192.0.2.200"}
}

func (f *fx) open(t *testing.T, u who) session.Opened {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	o, err := f.m.Open(ctx, f.req(t, u), []int64{f.id})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return o
}

func (f *fx) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := f.env.Pool("postgres").QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (f *fx) busy(t *testing.T) int {
	return f.count(t, `SELECT count(*) FROM execpub.device_busy WHERE device_id = $1`, f.id)
}

func (f *fx) status(t *testing.T, sid string) string {
	t.Helper()
	var s string
	if err := f.env.Pool("postgres").QueryRow(context.Background(), `SELECT status FROM execpub.session_summary
		WHERE session_id = $1 AND device_id = $2`, sid, f.id).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func (f *fx) alerts(t *testing.T, kind string) int {
	return f.count(t, `SELECT count(*) FROM execpub.alert WHERE kind = $1`, kind)
}

/* free: the device is free again: no busy row, and its lease can be taken. */
func (f *fx) free(t *testing.T, what string) {
	t.Helper()
	if n := f.busy(t); n != 0 {
		t.Errorf("%s: %d device_busy rows", what, n)
	}
	le, ok := f.locks.TryLock(f.id)
	if !ok {
		t.Errorf("%s: the device's lease is still held", what)
		return
	}
	le.Release()
}

/*
A session opens on the verified registry and closes cleanly: the
pre-session snapshot (a 'pre_session' version and exec.session_device, its
hash the driver session's Pre), device_busy from the write_device row, an
open summary; closing frees the device and ends the summary with the hash
after.
*/
func TestOpenAndClose(t *testing.T) {
	f := newFx(t)
	u := f.user(t, "core")
	o := f.open(t, u)
	if len(o.Devices) != 1 || o.Token == "" || o.Devices[0].Line != "mes6" {
		t.Fatalf("opened %+v", o)
	}
	s, err := f.m.Lookup(o.ID, o.Token)
	if err != nil {
		t.Fatal(err)
	}
	d := s.Devices[0]
	if d.Session.Pre().SHA256 != d.Pre || fmt.Sprintf("%x", d.Pre) != o.Devices[0].PreSHA256 {
		t.Fatal("the driver's pre-session snapshot is not the recorded one")
	}
	if n := f.count(t, `SELECT count(*) FROM exec.session_device WHERE session_id = $1 AND device_id = $2 AND pre_sha256 = $3`,
		o.ID, f.id, d.Pre[:]); n != 1 {
		t.Fatalf("session_device rows %d", n)
	}
	if n := f.count(t, `SELECT count(*) FROM backups.config_version WHERE device_id = $1 AND source = 'pre_session' AND sha256 = $2`,
		f.id, d.Pre[:]); n != 1 {
		t.Fatalf("pre_session versions %d", n)
	}
	if n := f.count(t, `SELECT count(*) FROM execpub.backup_taken WHERE device_id = $1`, f.id); n != 0 {
		t.Fatal("a device the executor does not back up got the poller's stamp")
	}
	if f.busy(t) != 1 || f.status(t, o.ID) != "open" {
		t.Fatal("busy row or summary missing")
	}
	if _, ok := f.locks.TryLock(f.id); ok {
		t.Fatal("the device's lease is free during the session")
	}
	if err := f.m.Close(context.Background(), o.ID, "wrong"); !errors.Is(err, session.ErrNoSession) {
		t.Fatalf("close with a wrong token: %v", err)
	}
	if err := f.m.Close(context.Background(), o.ID, o.Token); err != nil {
		t.Fatal(err)
	}
	if f.status(t, o.ID) != "closed" || f.count(t, `SELECT count(*) FROM execpub.session_summary WHERE session_id = $1 AND post_sha256 = $2`,
		o.ID, d.Pre[:]) != 1 {
		t.Fatal("summary not closed with the configuration after")
	}
	f.free(t, "closed")
	if n := f.count(t, `SELECT count(*) FROM exec.session_event WHERE session_id = $1 AND kind = 'closed'`, o.ID); n != 1 {
		t.Fatalf("closed events %d", n)
	}
	if _, err := f.m.Lookup(o.ID, o.Token); !errors.Is(err, session.ErrNoSession) {
		t.Fatal("a closed session is still found")
	}
}

/* refused opens a session and wants err; nothing may be left behind. */
func (f *fx) refused(t *testing.T, what string, u who, ids []int64, want error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := f.m.Open(ctx, f.req(t, u), ids); !errors.Is(err, want) {
		t.Fatalf("%s: %v, want %v", what, err, want)
	}
	f.free(t, what)
	if n := f.count(t, `SELECT count(*) FROM execpub.session_summary WHERE device_id = $1 AND status = 'open'`, f.id); n != 0 {
		t.Fatalf("%s: an open summary", what)
	}
}

/*
Every refusal path, in the order of the checks: the executor disabled after
the install (C1), a freeze, and after authz the device limit, outside the window (an
alert), a two-person group, no grant on the group (C2b), writes_enabled,
model, host key mismatch at the connection (C5, its alert), no credential,
policy rules that do not fit the grammar (an alert). Nothing is left open.
*/
func TestRefusals(t *testing.T) {
	f := newFx(t)
	u := f.user(t, "core")
	other := f.user(t, "edge")
	ids := []int64{f.id}

	f.policy(t, "max_devices_per_session: 1\n")
	second := f.panelDevice(t, fmt.Sprintf("10.250.%d.%d", 1+addrs.Add(1)%250, 1+time.Now().UnixNano()%250))
	row2 := maps.Clone(f.row)
	row2["device_id"], row2["address"] = second, netip.MustParseAddr("192.0.2.11")
	f.put(t, "write_device", row2)
	f.refused(t, "device limit", u, []int64{f.id, second}, session.ErrTooManyDevices)
	f.refused(t, "duplicate devices", u, []int64{f.id, f.id}, session.ErrBadDevices)

	day := strings.ToLower(f.now().UTC().Add(48 * time.Hour).Weekday().String()[:3])
	f.policy(t, "windows:\n  - days: ["+day+"]\n    start: \"00:00\"\n    end: \"24:00\"\n")
	f.refused(t, "outside the window", u, ids, session.ErrOutsideWindow)
	if f.alerts(t, session.KindOutsideWindow) != 1 {
		t.Fatal("no outside-window alert")
	}
	f.policy(t, "two_person_groups: [core]\n")
	f.refused(t, "two-person group", u, ids, session.ErrTwoPerson)
	f.policy(t, "")

	f.refused(t, "no grant on the group (C2b)", other, ids, authz.ErrDenied)
	f.refused(t, "unknown device", u, []int64{f.id + 1000}, authz.ErrDenied)

	f.row["writes_enabled"] = false
	f.put(t, "write_device", f.row)
	f.refused(t, "writes off", u, ids, session.ErrWritesDisabled)
	f.row["writes_enabled"] = true

	f.row["write_driver"] = "mes10"
	f.put(t, "write_device", f.row)
	f.refused(t, "model not verified", u, ids, session.ErrModelUnverified)
	f.row["write_driver"] = "mes6"

	other1, _, _ := ed25519.GenerateKey(rand.Reader)
	pk, _ := gossh.NewPublicKey(other1)
	f.row["hostkey_fp"] = gossh.FingerprintSHA256(pk)
	f.put(t, "write_device", f.row)
	f.refused(t, "host key mismatch (C5)", u, ids, session.ErrHostKey)
	if f.alerts(t, "hostkey_mismatch_write") == 0 {
		t.Fatal("no host key alert")
	}
	f.row["hostkey_fp"] = gossh.FingerprintSHA256(f.key)
	f.put(t, "write_device", f.row)

	f.policy(t, "class_overrides:\n  - driver: mes6\n    command: frobnicate\n    class: denied\n")
	f.refused(t, "policy rules", u, ids, session.ErrPolicyRules)
	if f.alerts(t, session.KindPolicyInvalid) == 0 {
		t.Fatal("no policy alert")
	}
	f.policy(t, "")

	if err := f.guard.HostWrite(context.Background(), func(_ context.Context, _ *registry.Snapshot, tx *registry.Tx) error {
		return tx.Delete("write_credential", f.id)
	}); err != nil {
		t.Fatal(err)
	}
	f.refused(t, "no credential", u, ids, session.ErrNoCredential)

	if r := f.host(execadmin.Request{Cmd: execadmin.CmdFreezeOn, Reason: "test"}); !r.OK {
		t.Fatal(r.Error)
	}
	f.refused(t, "frozen", u, ids, authz.ErrFrozen)

	if err := os.WriteFile(f.polF, []byte("enabled: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.pol.Reload(true)
	f.refused(t, "disabled (C1)", u, ids, authz.ErrDisabled)
	if n := f.count(t, `SELECT count(*) FROM exec.session_event WHERE kind = 'interrupted'`); n != 0 {
		t.Fatal("a refusal recorded an interruption")
	}
}

/*
C2c at the session level and the poller: the api moves core.device to
another address and adds a second core.device row with the registry's
address (another snmp_port). The session connects to the write_device
address only and publishes that address and the pinned host key in
device_busy, so the poller's gate (internal/poller checkNotInSession: id
or address) refuses both rows, and its SSH (internal/ssh, the poller's
host key store) refuses the emulator before any login.
*/
func TestBusyDeviceSilencesThePoller(t *testing.T) {
	f := newFx(t)
	api := f.env.Pool("nms_api")
	ctx := context.Background()
	if _, err := api.Exec(ctx, `UPDATE core.device SET address = '203.0.113.7' WHERE id = $1`, f.id); err != nil {
		t.Fatal(err)
	}
	var alias int64
	if err := api.QueryRow(ctx, `INSERT INTO core.device (name, address, snmp_port, group_id)
		SELECT 'alias-' || gen_random_uuid(), $1, 1161, group_id FROM core.device WHERE id = $2 RETURNING id`, devAddr, f.id).Scan(&alias); err != nil {
		t.Fatal(err)
	}
	u := f.user(t, "core")
	o := f.open(t, u)
	defer func() { _ = f.m.Close(ctx, o.ID, o.Token) }()
	f.mu.Lock()
	for _, a := range f.dialed {
		if a != devAddr.String()+":22" {
			t.Errorf("dialed %s, not the registry's address", a)
		}
	}
	f.mu.Unlock()
	var addr netip.Addr
	var fp string
	if err := f.env.Pool("nms_poller").QueryRow(ctx, `SELECT address, hostkey_fp FROM execpub.device_busy WHERE device_id = $1`, f.id).Scan(&addr, &fp); err != nil {
		t.Fatal(err)
	}
	if addr != devAddr || fp != gossh.FingerprintSHA256(f.key) {
		t.Fatalf("device_busy has %s %s, not the write_device row's", addr, fp)
	}
	for _, d := range []struct {
		id   int64
		addr string
	}{{f.id, "203.0.113.7"}, {alias, devAddr.String()}} {
		var busy bool
		if err := f.env.Pool("nms_poller").QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM execpub.device_busy WHERE device_id = $1 OR address = $2)`,
			d.id, d.addr).Scan(&busy); err != nil || !busy {
			t.Errorf("the poller's gate lets device %d at %s through: %v", d.id, d.addr, err)
		}
	}
	logins := len(f.log.AuthAttempts())
	r, err := ssh.Dial(ctx, f.emu, alias, creds.Credential{Kind: "ssh_read", Username: "admin", Password: secret.New(pw)},
		ssh.NewHostKeys(f.env.Pool("nms_poller")), eltexmes.New().Dialect())
	if r != nil {
		_ = r.Close()
	}
	if !errors.Is(err, ssh.ErrHostKeyInSession) || len(f.log.AuthAttempts()) != logins {
		t.Fatalf("the poller's SSH to the busy switch: %v, %d new logins", err, len(f.log.AuthAttempts())-logins)
	}
}

/* Idle and session time: a session unused for idle_minutes, or past its end, ends as timeout; extending (a new TOTP) moves the end. */
func TestTimeouts(t *testing.T) {
	f := newFx(t)
	u := f.user(t, "core")
	ctx := context.Background()
	o := f.open(t, u)
	f.offset.Add(int64(9 * time.Minute))
	f.m.Check(ctx)
	if _, err := f.m.Lookup(o.ID, o.Token); err != nil {
		t.Fatal("ended before idle_minutes")
	}
	f.offset.Add(int64(10*time.Minute + time.Second))
	f.m.Check(ctx)
	if f.status(t, o.ID) != "timeout" {
		t.Fatalf("idle: %s", f.status(t, o.ID))
	}
	f.free(t, "idle")

	o = f.open(t, u)
	for range 3 { /* used every 9 minutes: idle never ends it, the 30 minutes do */
		f.offset.Add(int64(9 * time.Minute))
		if _, err := f.m.Lookup(o.ID, o.Token); err != nil {
			t.Fatal(err)
		}
		f.m.Check(ctx)
	}
	f.offset.Add(int64(4 * time.Minute))
	f.m.Check(ctx)
	if f.status(t, o.ID) != "timeout" {
		t.Fatalf("session time: %s", f.status(t, o.ID))
	}

	o = f.open(t, u)
	for _, m := range []time.Duration{9, 9, 8} { /* used within idle_minutes, 26 minutes in */
		f.offset.Add(int64(m * time.Minute))
		if _, err := f.m.Lookup(o.ID, o.Token); err != nil {
			t.Fatal(err)
		}
	}
	ext, err := f.m.Extend(ctx, o.ID, f.req(t, u))
	if err != nil || !ext.Expires.After(f.now().Add(29*time.Minute)) {
		t.Fatalf("extend: %v %v", ext.Expires, err)
	}
	f.offset.Add(int64(6 * time.Minute))
	if _, err := f.m.Lookup(o.ID, o.Token); err != nil {
		t.Fatal(err)
	}
	f.m.Check(ctx)
	if f.status(t, o.ID) != "open" {
		t.Fatal("an extended session ended at the old time")
	}
	other := f.user(t, "core")
	if _, err := f.m.Extend(ctx, o.ID, f.req(t, other)); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("another user extended the session: %v", err)
	}
	_ = f.m.Close(ctx, o.ID, o.Token)
}

/* Attach: the session's own user gets a new token (new TOTP), the old one stops working; another user is refused. */
func TestAttach(t *testing.T) {
	f := newFx(t)
	u := f.user(t, "core")
	ctx := context.Background()
	o := f.open(t, u)
	if _, err := f.m.Attach(ctx, o.ID, f.req(t, f.user(t, "core"))); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("another user attached: %v", err)
	}
	a, err := f.m.Attach(ctx, o.ID, f.req(t, u))
	if err != nil || a.Token == "" || a.Token == o.Token {
		t.Fatalf("attach: %v", err)
	}
	if _, err := f.m.Lookup(o.ID, o.Token); !errors.Is(err, session.ErrNoSession) {
		t.Fatal("the old token still works")
	}
	if err := f.m.Close(ctx, o.ID, a.Token); err != nil {
		t.Fatal(err)
	}
}

/* A dropped device connection ends the session as interrupted, with an alert (the snapshot stays for a rollback). */
func TestConnectionLoss(t *testing.T) {
	f := newFx(t)
	u := f.user(t, "core")
	o := f.open(t, u)
	f.d.Disconnect()
	deadline := time.Now().Add(10 * time.Second)
	for f.status(t, o.ID) == "open" && time.Now().Before(deadline) {
		f.m.Check(context.Background())
		time.Sleep(100 * time.Millisecond)
	}
	if f.status(t, o.ID) != "interrupted" || f.alerts(t, session.KindInterrupted) != 1 {
		t.Fatalf("status %s, alerts %d", f.status(t, o.ID), f.alerts(t, session.KindInterrupted))
	}
	f.free(t, "lost connection")
	if n := f.count(t, `SELECT count(*) FROM exec.session_device WHERE session_id = $1`, o.ID); n != 1 {
		t.Fatal("the snapshot is gone")
	}
}

/*
The executor restarts mid-session: the new process (Recover, before /x)
ends the session as interrupted with an alert, frees the old process's
device_busy row, and ignores a planted session row that fails its MAC.
*/
func TestRestartMidSession(t *testing.T) {
	f := newFx(t)
	u := f.user(t, "core")
	ctx := context.Background()
	o := f.open(t, u)
	attacktest.Tamper(t, f.env, `INSERT INTO exec.session (id, user_id, opened_at, policy_snapshot, mac)
		VALUES (gen_random_uuid(), 1, now(), '{}', $1)`, make([]byte, 32))
	f.d.Disconnect() /* the old process is gone, and so is its connection */
	restarted := session.New(f.cfg)
	if err := restarted.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if f.status(t, o.ID) != "interrupted" || f.alerts(t, session.KindInterrupted) != 1 || f.busy(t) != 0 {
		t.Fatalf("status %s, alerts %d, busy %d", f.status(t, o.ID), f.alerts(t, session.KindInterrupted), f.busy(t))
	}
	if n := f.count(t, `SELECT count(*) FROM exec.session_event WHERE kind = 'interrupted'`); n != 1 {
		t.Fatalf("interrupted events %d (the planted row must be ignored)", n)
	}
	if err := restarted.Recover(ctx); err != nil || f.alerts(t, session.KindInterrupted) != 1 {
		t.Fatal("a second start alerted again")
	}
	/* the recording the old process left open gets the marker of its loss and its manifest (4c.5) */
	sid, _ := session.ParseID(o.ID)
	r, err := f.rec.Replay(ctx, sid, f.id)
	if err != nil || !strings.HasPrefix(r.Events[len(r.Events)-1].Data, "recording recovered after an executor restart") {
		t.Fatalf("recovered recording: %v", err)
	}
}

/*
I1: before authz nothing tells about the devices or the user. A ticket that
does not verify, without a code, gets the same answer for an unknown
device, a device in a two-person group and one outside the window, and
leaves no alert and no audit row naming the user.
*/
func TestNothingBeforeAuthz(t *testing.T) {
	f := newFx(t)
	u := f.user(t, "core")
	forged := func() authz.Request {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		tok, _, err := ticket.Issue(priv, u.id, u.name, f.now())
		if err != nil {
			t.Fatal(err)
		}
		return authz.Request{Ticket: tok, IP: "192.0.2.201"}
	}
	ctx := context.Background()
	day := strings.ToLower(f.now().UTC().Add(48 * time.Hour).Weekday().String()[:3])
	var answers []string
	for _, c := range []struct {
		policy string
		ids    []int64
	}{
		{"", []int64{f.id + 1000}},
		{"two_person_groups: [core]\n", []int64{f.id}},
		{"windows:\n  - days: [" + day + "]\n    start: \"00:00\"\n    end: \"24:00\"\n", []int64{f.id}},
	} {
		f.policy(t, c.policy)
		_, err := f.m.Open(ctx, forged(), c.ids)
		answers = append(answers, fmt.Sprint(err))
	}
	if answers[0] != answers[1] || answers[1] != answers[2] || !strings.Contains(answers[0], authz.ErrDenied.Error()) {
		t.Fatalf("answers differ: %q", answers)
	}
	if n := f.count(t, `SELECT count(*) FROM execpub.alert`); n != 0 {
		t.Fatalf("%d alerts before authz", n)
	}
	if n := f.count(t, `SELECT count(*) FROM exec.audit_event WHERE user_id = $1`, u.id); n != 0 {
		t.Fatalf("%d audit rows name the user", n)
	}
}

/*
M2: a freeze ends the session as interrupted with an alert and leaves the
MES reload-in safety net armed (no driver Close, no reload cancel).
*/
func TestFreezeKeepsTheSafetyNet(t *testing.T) {
	f := newFx(t)
	f.policy(t, "mes_reload_in_min: 5\n")
	u := f.user(t, "core")
	o := f.open(t, u)
	if f.d.ReloadAt().IsZero() {
		t.Fatal("the safety net is not armed")
	}
	if r := f.host(execadmin.Request{Cmd: execadmin.CmdFreezeOn, Reason: "test"}); !r.OK {
		t.Fatal(r.Error)
	}
	f.m.Check(context.Background())
	if f.status(t, o.ID) != "interrupted" || f.alerts(t, session.KindInterrupted) != 1 {
		t.Fatalf("status %s", f.status(t, o.ID))
	}
	if f.d.ReloadAt().IsZero() || slices.Contains(f.d.Lines(), "reload cancel") {
		t.Fatal("the safety net was cancelled")
	}
	f.free(t, "frozen")
}

/* M3: once Run has stopped, no session registers (nothing would time it out); the device is left free. */
func TestNoSessionAfterRun(t *testing.T) {
	f := newFx(t)
	u := f.user(t, "core")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.m.Run(ctx)
	if _, err := f.m.Open(context.Background(), f.req(t, u), []int64{f.id}); !errors.Is(err, authz.ErrUnavailable) {
		t.Fatalf("open after Run: %v", err)
	}
	f.free(t, "after Run")
}

/*
M1: Recover pages through every session row; a forged end event or a
session_device row failing its MAC raises a high tamper alert and does not
count (the session still ends as interrupted, its forged device gets no
alert); planted rows cannot starve the real session.
*/
func TestRecoverChecksEveryMAC(t *testing.T) {
	f := newFx(t)
	defer session.SetRecoverPage(2)()
	u := f.user(t, "core")
	o := f.open(t, u)
	for range 5 {
		attacktest.Tamper(t, f.env, `INSERT INTO exec.session (id, user_id, opened_at, policy_snapshot, mac)
			VALUES (gen_random_uuid(), 1, now(), '{}', $1)`, make([]byte, 32))
	}
	attacktest.Tamper(t, f.env, `INSERT INTO exec.session_event (session_id, at, kind, payload, mac) VALUES ($1, now(), 'closed', '{}', $2)`,
		o.ID, make([]byte, 32))
	attacktest.Tamper(t, f.env, `INSERT INTO exec.session_device (session_id, device_id, pre_sha256, pre_ct, pre_dek_ct, mac)
		VALUES ($1, 424242, $2, '\x01', '\x01', $2)`, o.ID, make([]byte, 32))
	f.d.Disconnect()
	if err := session.New(f.cfg).Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.status(t, o.ID) != "interrupted" || f.alerts(t, session.KindInterrupted) != 1 {
		t.Fatalf("status %s, interrupted alerts %d", f.status(t, o.ID), f.alerts(t, session.KindInterrupted))
	}
	var sev string
	if err := f.env.Pool("postgres").QueryRow(context.Background(), `SELECT severity FROM execpub.alert WHERE kind = $1`,
		session.KindTamper).Scan(&sev); err != nil || sev != "high" {
		t.Fatalf("tamper alert: %q %v", sev, err)
	}
}
