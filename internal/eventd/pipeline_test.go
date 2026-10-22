package eventd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/beekamai/network-scheme/internal/config"
	"github.com/beekamai/network-scheme/internal/secret"
	"github.com/beekamai/network-scheme/internal/store"
)

func dialTCP(t *testing.T, src string, to net.Addr) net.Conn {
	t.Helper()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: 5 * time.Second}
	c, err := d.Dial("tcp", to.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

/* closedByPeer reports whether the peer closes the connection within a short time. */
func closedByPeer(c net.Conn) bool {
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err := bufio.NewReader(c).ReadByte()
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return false
	}
	return err != nil
}

func TestSyslogTCPFraming(t *testing.T) {
	h := newHarness(t)
	id := h.device("127.0.0.2")
	h.start()

	c := dialTCP(t, "127.0.0.2", h.addrs.SyslogTCP)
	m1, m2, m3 := "<14>Oct 22 10:00:00 sw1 octet counted", "<14>Oct 22 10:00:01 sw1 line one", "<14>Oct 22 10:00:02 sw1 line two"
	/* octet counting, then LF framing (with CRLF and a blank line) on the same connection */
	if _, err := fmt.Fprintf(c, "%d %s%s\n\r\n%s\r\n", len(m1), m1, m2, m3); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "three frames stored", func() bool { return h.count(`SELECT count(*) FROM events.syslog WHERE device_id = $1`, id) == 3 })
	if n := h.count(`SELECT count(*) FROM events.syslog WHERE msg = 'octet counted'`); n != 1 {
		t.Errorf("octet-counted frame not stored intact")
	}
}

func TestSyslogTCPRefusals(t *testing.T) {
	h := newHarness(t)
	h.device("127.0.0.2")
	h.start(func(c *config.EventD) { c.MaxTCPConns = 2 })

	/* a frame over 8 KiB closes the connection and stores nothing */
	big := dialTCP(t, "127.0.0.2", h.addrs.SyslogTCP)
	if _, err := fmt.Fprintf(big, "9000 <14>%s", strings.Repeat("a", 9000)); err != nil {
		t.Fatal(err)
	}
	if !closedByPeer(big) {
		t.Error("oversized frame did not close the connection")
	}
	/* garbage framing closes it too */
	junk := dialTCP(t, "127.0.0.2", h.addrs.SyslogTCP)
	if _, err := junk.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	if !closedByPeer(junk) {
		t.Error("garbage did not close the connection")
	}
	/* an unknown peer is closed without being read */
	stranger := dialTCP(t, "127.0.0.9", h.addrs.SyslogTCP)
	if !closedByPeer(stranger) {
		t.Error("unknown peer was kept")
	}
	eventually(t, 10*time.Second, "unknown_source counted", func() bool { return h.stat("unknown_source") == 1 })
	/* the connection limit */
	a, b := dialTCP(t, "127.0.0.2", h.addrs.SyslogTCP), dialTCP(t, "127.0.0.2", h.addrs.SyslogTCP)
	time.Sleep(200 * time.Millisecond)
	over := dialTCP(t, "127.0.0.2", h.addrs.SyslogTCP)
	if !closedByPeer(over) {
		t.Error("connection over the limit was kept")
	}
	_, _ = a, b
	if n := h.count(`SELECT count(*) FROM events.syslog`); n != 0 {
		t.Errorf("%d rows from refused frames", n)
	}
}

func TestSyslogTCPIdleTimeout(t *testing.T) {
	h := newHarness(t)
	h.device("127.0.0.2")
	h.start(func(c *config.EventD) { c.TCPIdle = time.Second })
	c := dialTCP(t, "127.0.0.2", h.addrs.SyslogTCP)
	if !closedByPeer(c) {
		t.Error("idle connection was kept")
	}
}

func selfSigned(t *testing.T) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "eventd-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool = x509.NewCertPool()
	pool.AddCert(cert)
	return certFile, keyFile, pool
}

func TestSyslogTLS(t *testing.T) {
	h := newHarness(t)
	id := h.device("127.0.0.2")
	cert, key, roots := selfSigned(t)
	h.start(func(c *config.EventD) { c.SyslogTLS, c.TLSCertFile, c.TLSKeyFile = "127.0.0.1:0", cert, key })
	if h.addrs.SyslogTLS == nil {
		t.Fatal("TLS listener not started")
	}
	d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}, Timeout: 5 * time.Second}
	c, err := tls.DialWithDialer(d, "tcp", h.addrs.SyslogTLS.String(), &tls.Config{RootCAs: roots, ServerName: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if c.ConnectionState().Version < tls.VersionTLS12 {
		t.Errorf("negotiated TLS version %x", c.ConnectionState().Version)
	}
	msg := "<14>Oct 22 10:00:00 sw1 over tls"
	if _, err := fmt.Fprintf(c, "%d %s", len(msg), msg); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "tls frame stored", func() bool { return h.count(`SELECT count(*) FROM events.syslog WHERE device_id = $1`, id) == 1 })

	/* TLS 1.1 is refused, and so is an unknown peer (closed before the handshake) */
	old, err := tls.DialWithDialer(d, "tcp", h.addrs.SyslogTLS.String(), &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11})
	if err == nil {
		_ = old.Close()
		t.Error("TLS 1.1 handshake succeeded")
	}
	d9 := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.9")}, Timeout: 5 * time.Second}
	if s, err := tls.DialWithDialer(d9, "tcp", h.addrs.SyslogTLS.String(), &tls.Config{RootCAs: roots, ServerName: "127.0.0.1"}); err == nil {
		_ = s.Close()
		t.Error("handshake with an unknown peer succeeded")
	}
	eventually(t, 10*time.Second, "unknown tls peer counted", func() bool { return h.stat("unknown_source") == 1 })
}

/*
A sender that writes and drops the connection without close_notify while the server's
session tickets are still unread (it never reads them) makes the kernel answer with RST; with
tickets enabled the message was lost in front of the application. No tickets, no loss.
*/
func TestSyslogTLSAbruptClose(t *testing.T) {
	h := newHarness(t)
	id := h.device("127.0.0.2")
	cert, key, roots := selfSigned(t)
	h.start(func(c *config.EventD) { c.SyslogTLS, c.TLSCertFile, c.TLSKeyFile = "127.0.0.1:0", cert, key })
	d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}, Timeout: 5 * time.Second}
	for i := range 5 {
		raw, err := d.Dial("tcp", h.addrs.SyslogTLS.String())
		if err != nil {
			t.Fatal(err)
		}
		cache := tls.NewLRUClientSessionCache(1)
		c := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", ClientSessionCache: cache})
		if err := c.Handshake(); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond)) /* reading takes in a ticket, if one was sent */
		_, _ = c.Read(make([]byte, 1))
		_ = c.SetReadDeadline(time.Time{})
		if _, ok := cache.Get("127.0.0.1"); ok {
			t.Fatal("the server sent a session ticket")
		}
		if _, err := fmt.Fprintf(c, "<14>Oct 22 10:00:00 sw1 abrupt%d\n", i); err != nil {
			t.Fatal(err)
		}
		_ = raw.Close()
	}
	eventually(t, 10*time.Second, "all frames stored", func() bool { return h.count(`SELECT count(*) FROM events.syslog WHERE device_id = $1`, id) == 5 })
}

func TestLogHandshakeIsRateLimited(t *testing.T) {
	var buf bytes.Buffer
	s := &server{log: slog.New(slog.NewTextHandler(&buf, nil))}
	ip := netip.MustParseAddr("10.0.0.1")
	for range 5 {
		s.logHandshake(ip, errors.New("boom"))
	}
	if n := strings.Count(buf.String(), "handshake failed"); n != 1 {
		t.Fatalf("%d log lines, want 1: %s", n, buf.String())
	}
	if !strings.Contains(buf.String(), "10.0.0.1") || !strings.Contains(buf.String(), "boom") {
		t.Errorf("peer or error missing: %s", buf.String())
	}
	if s.hsSkip.Load() != 4 {
		t.Errorf("skipped %d, want 4", s.hsSkip.Load())
	}
}

func TestSyslogTLSDisabledWithoutCertificate(t *testing.T) {
	h := newHarness(t)
	h.device("127.0.0.2")
	h.start(func(c *config.EventD) { c.SyslogTLS = "127.0.0.1:0" })
	if h.addrs.SyslogTLS != nil {
		t.Errorf("TLS listener bound without a certificate: %v", h.addrs.SyslogTLS)
	}
}

func TestStormFoldsRepeatsAndKeepsOtherDevices(t *testing.T) {
	h := newHarness(t)
	noisy := h.device("127.0.0.2")
	quiet := h.device("127.0.0.3")
	h.start()
	n := udpFrom(t, "127.0.0.2", h.addrs.SyslogUDP)
	q := udpFrom(t, "127.0.0.3", h.addrs.SyslogUDP)

	const total = 10_000
	start := time.Now()
	for i := range total {
		if _, err := fmt.Fprintf(n, "<14>Oct 22 10:00:00 sw1 flood %d", i); err != nil {
			t.Fatal(err)
		}
		if i == total/2 {
			if _, err := q.Write([]byte("<14>Oct 22 10:00:00 sw2 quiet device")); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Logf("sent %d in %v", total, time.Since(start))
	eventually(t, 20*time.Second, "all datagrams seen", func() bool { return h.stat("received") >= total+1 })
	eventually(t, 10*time.Second, "quiet device stored", func() bool { return h.count(`SELECT count(*) FROM events.syslog WHERE device_id = $1`, quiet) == 1 })
	h.stop() /* writes the pending storm rows */

	stored := h.count(`SELECT count(*) FROM events.syslog WHERE device_id = $1`, noisy)
	folded := h.count(`SELECT coalesce(sum(count), 0) FROM events.storm WHERE device_id = $1 AND kind = 'syslog'`, noisy)
	if stored < 400 || stored > 700 {
		t.Errorf("stored %d rows of the flood, want about burst (400) plus the refill", stored)
	}
	if stored+folded != total {
		t.Errorf("stored %d + folded %d = %d, want %d: the count must not be lost", stored, folded, stored+folded, total)
	}
	if got := h.stat("rate_limited"); got != folded {
		t.Errorf("rate_limited = %d, storm rows say %d", got, folded)
	}
	if rows := h.count(`SELECT count(*) FROM events.storm WHERE device_id = $1`, noisy); rows < 1 || rows > 2 {
		t.Errorf("%d storm rows for one minute", rows)
	}
	if h.count(`SELECT count(*) FROM events.storm WHERE device_id = $1`, quiet) != 0 {
		t.Error("the quiet device has a storm row")
	}
	if got := h.stat("dropped"); got != 0 {
		t.Errorf("dropped = %d", got)
	}
}

func TestRemovedDeviceIsNotAcceptedAnyMore(t *testing.T) {
	h := newHarness(t)
	id := h.device("127.0.0.2")
	h.start()
	c := udpFrom(t, "127.0.0.2", h.addrs.SyslogUDP)
	send := func() {
		if _, err := c.Write([]byte("<14>Oct 22 10:00:00 sw1 hello")); err != nil {
			t.Fatal(err)
		}
	}
	send()
	eventually(t, 10*time.Second, "stored while known", func() bool { return h.count(`SELECT count(*) FROM events.syslog`) == 1 })

	if _, err := h.pg.Exec(context.Background(), `DELETE FROM core.device WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	removed := time.Now()
	eventually(t, 5*time.Second, "unknown after removal (NOTIFY)", func() bool {
		send()
		time.Sleep(100 * time.Millisecond)
		return h.stat("unknown_source") > 0
	})
	t.Logf("removal took effect after %v", time.Since(removed))
	before := h.count(`SELECT count(*) FROM events.syslog`)
	send()
	time.Sleep(500 * time.Millisecond)
	if after := h.count(`SELECT count(*) FROM events.syslog`); after != before {
		t.Errorf("rows grew from %d to %d after removal", before, after)
	}
}

func TestOperatorTrapRuleAppliesOnNotify(t *testing.T) {
	h := newHarness(t)
	id := h.device("127.0.0.2")
	h.community(id, goodCommunity)
	h.start()
	custom := gosnmp.SnmpTrap{Variables: []gosnmp.SnmpPDU{
		{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(1)},
		{Name: oidTrapOID, Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.99999.1.1"},
		{Name: ".1.3.6.1.4.1.99999.1.2", Type: gosnmp.OctetString, Value: "payload <b>text</b>"},
	}}
	send := func() {
		if err := sendTrap(snmpClient("127.0.0.2", h.addrs.TrapUDP, func(*gosnmp.GoSNMP) {}), custom); err != nil {
			t.Fatal(err)
		}
	}
	send()
	eventually(t, 10*time.Second, "unidentified trap stored", func() bool { return h.count(`SELECT count(*) FROM events.trap`) == 1 })
	var name string
	var sev *string
	var ident bool
	if err := h.pg.QueryRow(context.Background(), `SELECT name, severity, identified FROM events.trap`).Scan(&name, &sev, &ident); err != nil {
		t.Fatal(err)
	}
	if name != "1.3.6.1.4.1.99999.1.1" || sev != nil || ident {
		t.Errorf("unidentified trap = %q %v %v, want its OID, NULL severity, false", name, sev, ident)
	}
	if _, err := h.pg.Exec(context.Background(), `INSERT INTO events.trap_rule (trap_oid, name, severity) VALUES ('1.3.6.1.4.1.99999.1.1', 'customAlarm', 'high')`); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "rule applied", func() bool {
		send()
		time.Sleep(150 * time.Millisecond)
		return h.count(`SELECT count(*) FROM events.trap WHERE name = 'customAlarm' AND severity = 'high' AND identified`) > 0
	})
}

func TestHealthcheck(t *testing.T) {
	h := newHarness(t)
	h.start()
	ctx := context.Background()
	eventually(t, 10*time.Second, "healthy", func() bool { return Healthy(ctx, h.pool, h.instance) == nil })
	if err := Healthy(ctx, h.pool, "someone-else"); err == nil {
		t.Error("an instance that never wrote stats is healthy")
	}
}

func TestDatabaseOutageDropsAndRecovers(t *testing.T) {
	h := newHarness(t)
	id := h.device("127.0.0.2")
	dbc, pw := h.env.Config("nms_eventd")
	proxy := newProxy(t, fmt.Sprintf("%s:%d", dbc.Host, dbc.Port))
	host, port, _ := net.SplitHostPort(proxy.addr)
	dbc.Host, dbc.MaxConns = host, 8
	dbc.Port, _ = strconv.Atoi(port)
	pool, err := store.Open(context.Background(), dbc, secret.New(pw.Reveal()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	h.pool = pool
	h.start(func(c *config.EventD) {
		c.QueueSize, c.BatchSize, c.RatePerSource, c.RateBurst = 200, 50, 1_000_000, 1_000_000
	})
	c := udpFrom(t, "127.0.0.2", h.addrs.SyslogUDP)
	send := func(n int, tag string) {
		for i := range n {
			if _, err := fmt.Fprintf(c, "<14>Oct 22 10:00:00 sw1 %s %d", tag, i); err != nil {
				t.Fatal(err)
			}
		}
	}
	send(1, "before")
	eventually(t, 10*time.Second, "stored while the database is up", func() bool { return h.count(`SELECT count(*) FROM events.syslog`) == 1 })

	proxy.down()
	time.Sleep(300 * time.Millisecond)
	const flood = 2000
	send(flood, "outage")
	time.Sleep(3 * time.Second) /* the outage; production uses 30 s, the logic is the same */
	select {
	case err := <-h.done:
		t.Fatalf("eventd exited during the outage: %v", err)
	default:
	}
	if err := proxy.up(); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "drops counted after recovery", func() bool { return h.stat("dropped") > 0 })
	sent := flood + 1
	eventually(t, 30*time.Second, "writing continues", func() bool { /* the queue may still be full right after the recovery */
		send(1, "after")
		sent++
		time.Sleep(200 * time.Millisecond)
		return h.count(`SELECT count(*) FROM events.syslog WHERE msg LIKE 'after%'`) >= 1
	})
	h.stop()
	stored := h.count(`SELECT count(*) FROM events.syslog WHERE device_id = $1`, id)
	dropped := h.stat("dropped")
	t.Logf("sent %d, stored %d, dropped %d", sent, stored, dropped)
	if stored+dropped != sent {
		t.Errorf("stored %d + dropped %d != sent %d: events were lost without being counted", stored, dropped, sent)
	}
	if dropped < flood-200-50-100 { /* queue 200 + batch 50 + what the kernel and the readers held */
		t.Errorf("dropped only %d of %d during the outage", dropped, flood)
	}
}
