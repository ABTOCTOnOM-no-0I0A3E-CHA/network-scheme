package eventd

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/beekamai/network-scheme/internal/jobs"
)

/* The harness uses the real River enqueuer in these tests. */
func (h *harness) realEnqueuer() {
	e, err := jobs.NewEnqueuer(h.pool)
	if err != nil {
		h.t.Fatal(err)
	}
	h.enq = e
}

func TestSyslogKnownAndUnknownSource(t *testing.T) {
	h := newHarness(t)
	id := h.device("127.0.0.2")
	h.start()
	known := udpFrom(t, "127.0.0.2", h.addrs.SyslogUDP)
	stranger := udpFrom(t, "127.0.0.9", h.addrs.SyslogUDP)

	if _, err := known.Write([]byte("<189>Oct 22 10:00:00 sw1 LINK: port 7 down")); err != nil {
		t.Fatal(err)
	}
	if _, err := stranger.Write([]byte("<189>Oct 22 10:00:00 sw1 LINK: forged")); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "event stored", func() bool { return h.count(`SELECT count(*) FROM events.syslog WHERE device_id = $1`, id) == 1 })
	eventually(t, 10*time.Second, "unknown_source counted", func() bool { return h.stat("unknown_source") == 1 })
	if n := h.count(`SELECT count(*) FROM events.syslog`); n != 1 {
		t.Errorf("%d rows, want only the known device's", n)
	}
	var host, app, msg string
	var sev, fac int
	if err := h.pg.QueryRow(context.Background(), `SELECT host, app, msg, severity, facility FROM events.syslog`).Scan(&host, &app, &msg, &sev, &fac); err != nil {
		t.Fatal(err)
	}
	if host != "sw1" || msg == "" || sev != 5 || fac != 23 {
		t.Errorf("row = %q %q %q sev=%d fac=%d", host, app, msg, sev, fac)
	}
	if got := h.stat("accepted"); got != 1 {
		t.Errorf("accepted = %d, want 1", got)
	}
	/* nothing is ever sent back */
	assertSilent(t, known)
	assertSilent(t, stranger)
}

/* assertSilent: the peer receives no datagram. */
func assertSilent(t *testing.T, c *net.UDPConn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 64)
	if n, err := c.Read(buf); err == nil {
		t.Errorf("received %d bytes back", n)
	}
}

func TestSyslogHostClaimDoesNotChangeSource(t *testing.T) {
	h := newHarness(t)
	a := h.device("127.0.0.2")
	h.device("127.0.0.3")
	h.start()
	c := udpFrom(t, "127.0.0.2", h.addrs.SyslogUDP)
	/* the message claims to come from the host of device B and lists B's address */
	if _, err := c.Write([]byte("<14>1 2026-10-22T10:00:00Z 127.0.0.3 app - - - claims to be 127.0.0.3")); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "event stored", func() bool { return h.count(`SELECT count(*) FROM events.syslog WHERE device_id = $1`, a) == 1 })
	if n := h.count(`SELECT count(*) FROM events.syslog WHERE device_id <> $1`, a); n != 0 {
		t.Errorf("%d rows for other devices", n)
	}
}

func TestTrapV2cStoresAndPollsOnLinkDown(t *testing.T) {
	h := newHarness(t)
	h.realEnqueuer()
	id := h.device("127.0.0.2")
	h.community(id, goodCommunity)
	h.start()

	g := snmpClient("127.0.0.2", h.addrs.TrapUDP, func(*gosnmp.GoSNMP) {})
	if err := sendTrap(g, linkDownTrap(false)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "trap stored", func() bool { return h.count(`SELECT count(*) FROM events.trap WHERE device_id = $1`, id) == 1 })
	var name, oid string
	var sev *string
	var ident bool
	var ver int
	var vb string
	if err := h.pg.QueryRow(context.Background(), `SELECT name, trap_oid, severity, identified, version, varbinds::text FROM events.trap`).Scan(&name, &oid, &sev, &ident, &ver, &vb); err != nil {
		t.Fatal(err)
	}
	if name != "linkDown" || oid != "1.3.6.1.6.3.1.1.5.3" || sev == nil || *sev != "average" || !ident || ver != 2 {
		t.Errorf("row = %q %q %v %v %d", name, oid, sev, ident, ver)
	}
	eventually(t, 10*time.Second, "poll_now queued", func() bool {
		return h.count(`SELECT count(*) FROM jobs.river_job WHERE kind = 'poll_now' AND args->>'device_id' = $1`, itoa(id)) == 1
	})
	/* a second linkDown inside 30 s does not queue a second request (and River coalesces anyway) */
	if err := sendTrap(snmpClient("127.0.0.2", h.addrs.TrapUDP, func(*gosnmp.GoSNMP) {}), linkDownTrap(false)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "second trap stored", func() bool { return h.count(`SELECT count(*) FROM events.trap`) == 2 })
	if n := h.count(`SELECT count(*) FROM jobs.river_job WHERE kind = 'poll_now'`); n != 1 {
		t.Errorf("%d poll_now jobs", n)
	}
}

func itoa(i int64) string { return fmtInt(i) }

func TestTrapWrongCommunityAndNoProfile(t *testing.T) {
	h := newHarness(t)
	h.realEnqueuer()
	withProfile := h.device("127.0.0.2")
	h.community(withProfile, goodCommunity)
	h.device("127.0.0.3") /* no profile at all */
	h.start()

	bad := snmpClient("127.0.0.2", h.addrs.TrapUDP, func(g *gosnmp.GoSNMP) { g.Community = "community-WRONG-0123" })
	if err := sendTrap(bad, linkDownTrap(false)); err != nil {
		t.Fatal(err)
	}
	noprof := snmpClient("127.0.0.3", h.addrs.TrapUDP, func(*gosnmp.GoSNMP) {})
	if err := sendTrap(noprof, linkDownTrap(false)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "auth_failed counted", func() bool { return h.stat("auth_failed") == 2 })
	if n := h.count(`SELECT count(*) FROM events.trap`); n != 0 {
		t.Errorf("%d trap rows after failed auth", n)
	}
	if n := h.count(`SELECT count(*) FROM jobs.river_job`); n != 0 {
		t.Errorf("%d jobs after failed auth", n)
	}
}

func TestTrapFromUnknownAddressCountedNotStored(t *testing.T) {
	h := newHarness(t)
	id := h.device("127.0.0.2")
	h.community(id, goodCommunity)
	h.start()
	if err := sendTrap(snmpClient("127.0.0.77", h.addrs.TrapUDP, func(*gosnmp.GoSNMP) {}), linkDownTrap(false)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "unknown_source counted", func() bool { return h.stat("unknown_source") == 1 })
	if n := h.count(`SELECT count(*) FROM events.trap`); n != 0 {
		t.Errorf("%d trap rows", n)
	}
}

func TestInformAcknowledgedOnlyAfterAuth(t *testing.T) {
	h := newHarness(t)
	id := h.device("127.0.0.2")
	h.community(id, goodCommunity)
	other := h.device("127.0.0.3")
	h.community(other, goodCommunity)
	h.start()

	/* the right community from the right address: acknowledged and stored */
	if err := sendTrap(snmpClient("127.0.0.2", h.addrs.TrapUDP, func(*gosnmp.GoSNMP) {}), linkDownTrap(true)); err != nil {
		t.Fatalf("inform not acknowledged: %v", err)
	}
	eventually(t, 10*time.Second, "inform stored", func() bool { return h.count(`SELECT count(*) FROM events.trap WHERE device_id = $1`, id) == 1 })
	/* wrong community, unknown address: no answer at all */
	if err := sendTrap(snmpClient("127.0.0.2", h.addrs.TrapUDP, func(g *gosnmp.GoSNMP) { g.Community = "community-WRONG-0123" }), linkDownTrap(true)); err == nil {
		t.Error("inform with a wrong community was acknowledged")
	}
	if err := sendTrap(snmpClient("127.0.0.88", h.addrs.TrapUDP, func(*gosnmp.GoSNMP) {}), linkDownTrap(true)); err == nil {
		t.Error("inform from an unknown address was acknowledged")
	}
	if n := h.count(`SELECT count(*) FROM events.trap`); n != 1 {
		t.Errorf("%d trap rows, want 1", n)
	}
}

func TestTrapV1(t *testing.T) {
	h := newHarness(t)
	id := h.device("127.0.0.2")
	h.community(id, goodCommunity)
	h.start()
	g := snmpClient("127.0.0.2", h.addrs.TrapUDP, func(g *gosnmp.GoSNMP) { g.Version = gosnmp.Version1 })
	tr := gosnmp.SnmpTrap{Enterprise: ".1.3.6.1.4.1.8072", AgentAddress: "10.9.9.9", GenericTrap: 2, SpecificTrap: 0, Timestamp: 300,
		Variables: []gosnmp.SnmpPDU{{Name: oidIfIndex, Type: gosnmp.Integer, Value: 7}}}
	if err := sendTrap(g, tr); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "v1 trap stored", func() bool {
		return h.count(`SELECT count(*) FROM events.trap WHERE device_id = $1 AND version = 1`, id) == 1
	})
	var name string
	if err := h.pg.QueryRow(context.Background(), `SELECT name FROM events.trap`).Scan(&name); err != nil || name != "linkDown" {
		t.Errorf("name = %q %v", name, err)
	}
}

func TestTrapV3AuthPriv(t *testing.T) {
	h := newHarness(t)
	a := h.device("127.0.0.2")
	b := h.device("127.0.0.3")
	h.v3(a, "user-a")
	h.v3(b, "user-b")
	h.start()

	/* the right user and keys */
	if err := sendTrap(v3Client("127.0.0.2", h.addrs.TrapUDP, "user-a", authKey, privKey), linkDownTrap(false)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "v3 trap stored", func() bool {
		return h.count(`SELECT count(*) FROM events.trap WHERE device_id = $1 AND version = 3`, a) == 1
	})

	/* a foreign key: authentication fails */
	if err := sendTrap(v3Client("127.0.0.2", h.addrs.TrapUDP, "user-a", "other-auth-key-0123456", privKey), linkDownTrap(false)); err != nil {
		t.Fatal(err)
	}
	/* a user that is valid for device B, sent from the address of device A */
	if err := sendTrap(v3Client("127.0.0.2", h.addrs.TrapUDP, "user-b", authKey, privKey), linkDownTrap(false)); err != nil {
		t.Fatal(err)
	}
	/* a user that exists nowhere */
	if err := sendTrap(v3Client("127.0.0.2", h.addrs.TrapUDP, "nobody", authKey, privKey), linkDownTrap(false)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "auth_failed counted", func() bool { return h.stat("auth_failed") == 3 })
	if n := h.count(`SELECT count(*) FROM events.trap`); n != 1 {
		t.Errorf("%d trap rows, want 1", n)
	}
	/* and the right user from its own address still works */
	if err := sendTrap(v3Client("127.0.0.3", h.addrs.TrapUDP, "user-b", authKey, privKey), linkDownTrap(false)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "device B trap stored", func() bool { return h.count(`SELECT count(*) FROM events.trap WHERE device_id = $1`, b) == 1 })
}

func TestTrapV3WeakLevelsRefused(t *testing.T) {
	h := newHarness(t)
	a := h.device("127.0.0.2")
	h.v3(a, "user-a")
	h.start()
	for name, flags := range map[string]gosnmp.SnmpV3MsgFlags{"noAuthNoPriv": gosnmp.NoAuthNoPriv, "authNoPriv": gosnmp.AuthNoPriv} {
		g := v3Client("127.0.0.2", h.addrs.TrapUDP, "user-a", authKey, privKey)
		g.MsgFlags = flags
		if err := sendTrap(g, linkDownTrap(false)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	eventually(t, 10*time.Second, "both refused", func() bool { return h.stat("auth_failed") == 2 })
	if n := h.count(`SELECT count(*) FROM events.trap`); n != 0 {
		t.Errorf("%d trap rows from weak security levels", n)
	}
}

func TestV3AndV2cAreIndependent(t *testing.T) {
	h := newHarness(t)
	a := h.device("127.0.0.2")
	h.v3(a, "user-a") /* only an snmp3 profile */
	h.start()
	if err := sendTrap(snmpClient("127.0.0.2", h.addrs.TrapUDP, func(*gosnmp.GoSNMP) {}), linkDownTrap(false)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "v2c refused without an snmp2c profile", func() bool { return h.stat("auth_failed") == 1 })
}

func fmtInt(i int64) string { return strconv.FormatInt(i, 10) }

func TestMalformedPacketsFromKnownSourceAreNotStored(t *testing.T) {
	h := newHarness(t)
	id := h.device("127.0.0.2")
	h.community(id, goodCommunity)
	h.start()
	sys := udpFrom(t, "127.0.0.2", h.addrs.SyslogUDP)
	trapSock := udpFrom(t, "127.0.0.2", h.addrs.TrapUDP)
	for _, p := range []string{"no priority here", "<999>bad pri", strings.Repeat("<14>x", 2000)} {
		if _, err := sys.Write([]byte(p)); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = sys.Write(make([]byte, 20000)) /* longer than any syslog message */
	for _, p := range [][]byte{[]byte("garbage"), {0x30, 0x03, 0x02, 0x01, 0x01}, {0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x02, 0x01, 0x01}, make([]byte, 70000)[:65000]} {
		_, _ = trapSock.Write(p)
	}
	time.Sleep(500 * time.Millisecond)
	if _, err := sys.Write([]byte("<14>Oct 22 10:00:00 sw1 still alive")); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "later message stored", func() bool { return h.count(`SELECT count(*) FROM events.syslog`) >= 1 })
	if n := h.count(`SELECT count(*) FROM events.syslog WHERE msg <> 'still alive'`); n != 0 {
		t.Errorf("%d rows from malformed input", n)
	}
	if n := h.count(`SELECT count(*) FROM events.trap`); n != 0 {
		t.Errorf("%d trap rows from garbage", n)
	}
	assertSilent(t, trapSock)
}
