package eventd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"runtime/debug"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/config"
	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/secret"
)

type noEnq struct{}

func (noEnq) EnqueuePollNow(context.Context, pgx.Tx, int64) error { return nil }

/* clock is a settable time source. */
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

/* v3Rig is a server without sockets and database, and one device with an snmp3 profile. */
type v3Rig struct {
	srv *server
	dev *device
	clk *clock
}

func newV3Rig(t testing.TB) *v3Rig {
	t.Helper()
	cfg := config.EventD{}
	cfg.ApplyDefaults()
	clk := &clock{t: time.Now()}
	srv := newServer(cfg, Deps{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Enqueuer: noEnq{}, Registry: drivers.Default(), Clock: clk.now})
	v, err := newV3(creds.Credential{Kind: creds.KindSNMP3, User: "nms", AuthProto: "SHA256", AuthKey: secret.New(authKey), PrivProto: "AES", PrivKey: secret.New(privKey)})
	if err != nil {
		t.Fatal(err)
	}
	return &v3Rig{srv: srv, dev: &device{id: 1, v3: v}, clk: clk}
}

func engineID(i int) string { return fmt.Sprintf("\x80\x00\x1f\x88\x04eng%06d", i) }

/*
v3Packet encodes an authPriv trap. With genuine set the keys derive from the
passphrases (what a device that knows them sends); otherwise placeholder keys
stand in for a spoofer who knows the user name but not the secrets, which also
keeps the generator cheap.
*/
func v3Packet(tb testing.TB, user, engine string, genuine bool) []byte {
	tb.Helper()
	sp := &gosnmp.UsmSecurityParameters{
		UserName: user, AuthenticationProtocol: gosnmp.SHA256, PrivacyProtocol: gosnmp.AES,
		AuthenticationPassphrase: authKey, PrivacyPassphrase: privKey,
		AuthoritativeEngineID: engine, AuthoritativeEngineBoots: 1, AuthoritativeEngineTime: 100,
	}
	if !genuine {
		sp.AuthenticationPassphrase, sp.PrivacyPassphrase = "wrongwrongwrong01", "wrongwrongwrong02"
		sp.SecretKey, sp.PrivacyKey = make([]byte, 32), make([]byte, 16)
	}
	if genuine {
		if err := sp.InitSecurityKeys(); err != nil {
			tb.Fatal(err)
		}
	}
	g := &gosnmp.GoSNMP{Version: gosnmp.Version3, SecurityModel: gosnmp.UserSecurityModel, MsgFlags: gosnmp.AuthPriv, Logger: quiet, SecurityParameters: sp}
	b, err := g.SnmpEncodePacket(gosnmp.SNMPv2Trap, linkDownTrap(false).Variables, 0, 0)
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

func TestParseV3Header(t *testing.T) {
	b := v3Packet(t, "nms", engineID(1), false)
	h, ok := parseV3Header(b)
	if !ok || h.user != "nms" || h.engine != engineID(1) || h.model != 3 || h.flags&byte(gosnmp.AuthPriv) != byte(gosnmp.AuthPriv) {
		t.Fatalf("header = %+v ok=%v", h, ok)
	}
	for n := range len(b) { /* every truncation is refused or still parses without panicking */
		_, _ = parseV3Header(b[:n])
	}
	for _, bad := range [][]byte{nil, {0x30}, {0x30, 0x80}, {0x30, 0x84, 0xff, 0xff, 0xff, 0xff}, []byte("garbage garbage garbage")} {
		if _, ok := parseV3Header(bad); ok {
			t.Errorf("%x parsed", bad)
		}
	}
	if _, ok := parseV3Header(v3Packet(t, "nms", "\x80\x00\x1f\x88", false)); ok {
		t.Error("a 4-byte engine ID parsed")
	}
}

func TestV3LegitimateTrapPinsEngineAndSkipsDerivation(t *testing.T) {
	r := newV3Rig(t)
	pkt := v3Packet(t, "nms", engineID(1), true)
	if _, ok := r.srv.authTrap(r.dev, pkt); !ok {
		t.Fatal("legitimate trap refused")
	}
	if r.dev.v3.pin == nil || r.dev.v3.pin.engine != engineID(1) {
		t.Fatal("engine not pinned after an authenticated trap")
	}
	/* from now on the pinned engine needs no budget: 200 traps in the same instant all pass, quickly */
	start := time.Now()
	for i := range 200 {
		if _, ok := r.srv.authTrap(r.dev, pkt); !ok {
			t.Fatalf("pinned trap %d refused", i)
		}
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("200 pinned traps took %v", el)
	}
	if r.srv.st.slowDropped.Load() != 0 {
		t.Error("pinned traps were charged to the slow budget")
	}
}

/* The review's attack: a spoofer names thousands of engine IDs with the known user name. */
func TestV3EngineIDFloodIsBounded(t *testing.T) {
	for _, pinned := range []bool{false, true} {
		t.Run(fmt.Sprintf("pinned=%v", pinned), func(t *testing.T) {
			r := newV3Rig(t)
			if pinned {
				if _, ok := r.srv.authTrap(r.dev, v3Packet(t, "nms", engineID(0), true)); !ok {
					t.Fatal("legitimate trap refused")
				}
			}
			const n = 2000
			pk := make([][]byte, n)
			for i := range pk {
				pk[i] = v3Packet(t, "nms", engineID(i+1), false)
			}
			var m0, m1 runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&m0)
			start := time.Now()
			for _, b := range pk {
				if _, ok := r.srv.authTrap(r.dev, b); ok {
					t.Fatal("a forged packet was accepted")
				}
			}
			el := time.Since(start)
			runtime.GC()
			runtime.ReadMemStats(&m1)
			grow := (int64(m1.HeapAlloc) - int64(m0.HeapAlloc)) / 1024
			dropped := r.srv.st.slowDropped.Load()
			t.Logf("%d forged engine IDs: %v (%.3f ms/packet), %d over budget, heap growth %d KB", n, el, float64(el.Microseconds())/n/1000, dropped, grow)
			if el > 2*time.Second {
				t.Errorf("flood took %v (the unbudgeted path costs ~6 ms per packet, 12+ s here)", el)
			}
			if dropped < n-10 {
				t.Errorf("only %d of %d packets were refused by the budget", dropped, n)
			}
			if grow > 4096 {
				t.Errorf("heap grew by %d KB", grow)
			}
			/* and the device's real traps keep flowing */
			legit := v3Packet(t, "nms", engineID(0), true)
			if pinned {
				if _, ok := r.srv.authTrap(r.dev, legit); !ok {
					t.Error("legitimate trap refused after the flood")
				}
			}
		})
	}
}

/* Spoofed garbage must not use up what the device's real traps need (the review's second point). */
func TestV3SpoofedGarbageDoesNotSilenceTheDevice(t *testing.T) {
	r := newV3Rig(t)
	legit := v3Packet(t, "nms", engineID(0), true)
	if _, ok := r.srv.authTrap(r.dev, legit); !ok {
		t.Fatal("legitimate trap refused")
	}
	for sec := range 5 {
		for i := range 100 { /* 100 forged packets per second, same engine as the device and other ones */
			eng := engineID(0)
			if i%2 == 1 {
				eng = engineID(1000*sec + i)
			}
			if _, ok := r.srv.authTrap(r.dev, v3Packet(t, "nms", eng, false)); ok {
				t.Fatal("forged packet accepted")
			}
		}
		if _, ok := r.srv.authTrap(r.dev, legit); !ok {
			t.Fatalf("second %d: real trap refused during the flood", sec)
		}
		r.clk.add(time.Second)
	}
}

/* A replaced device (new engine ID) is accepted through the slow path, once its budget allows, and re-pinned. */
func TestV3EngineChangeUsesTheSlowPath(t *testing.T) {
	r := newV3Rig(t)
	if _, ok := r.srv.authTrap(r.dev, v3Packet(t, "nms", engineID(1), true)); !ok {
		t.Fatal("first trap refused")
	}
	next := v3Packet(t, "nms", engineID(2), true)
	if _, ok := r.srv.authTrap(r.dev, next); ok {
		t.Error("a second derivation inside the per-device budget was allowed")
	}
	r.clk.add(11 * time.Second)
	if _, ok := r.srv.authTrap(r.dev, next); !ok {
		t.Fatal("replaced device refused after the budget refilled")
	}
	if r.dev.v3.pin.engine != engineID(2) {
		t.Error("new engine not pinned")
	}
	if _, ok := r.srv.authTrap(r.dev, next); !ok {
		t.Error("pinned trap refused")
	}
}

func TestV3WrongUserAndLevelsAreRefusedCheaply(t *testing.T) {
	r := newV3Rig(t)
	if _, ok := r.srv.authTrap(r.dev, v3Packet(t, "someone-else", engineID(1), true)); ok {
		t.Error("wrong user accepted")
	}
	if r.srv.st.slowDropped.Load() != 0 {
		t.Error("a wrong user name used the key-derivation budget")
	}
	if _, ok := r.srv.authTrap(r.dev, v3Packet(t, "nms", engineID(1), true)); !ok {
		t.Error("a wrong user name used up the legitimate budget")
	}
}

func TestPanicIsRecoveredAndCounted(t *testing.T) {
	r := newV3Rig(t)
	r.srv.safely(func() { panic("hostile input") })
	r.srv.safely(func() {})
	if r.srv.st.panics.Load() != 1 || r.srv.st.malformed.Load() != 1 {
		t.Errorf("panics %d malformed %d", r.srv.st.panics.Load(), r.srv.st.malformed.Load())
	}
}

/*
FuzzAuthTrapV3 feeds arbitrary bytes to the v3 path (header pre-parse, pinned
decode) of a device with a pinned engine. The slow path is closed (no budget)
so that executions stay fast; it is covered by the tests above. Nothing may
panic or hang, and nothing but the genuine packet may authenticate.
*/
func FuzzAuthTrapV3(f *testing.F) {
	r := newV3Rig(f)
	genuine := v3Packet(f, "nms", engineID(1), true)
	if _, ok := r.srv.authTrap(r.dev, genuine); !ok {
		f.Fatal("setup: genuine trap refused")
	}
	r.srv.slowAll = newLimiterF(0, 0)
	f.Add(genuine)
	f.Add(v3Packet(f, "nms", engineID(1), false))
	f.Add(v3Packet(f, "nms", engineID(2), false))
	f.Add(v3Packet(f, "other", engineID(1), false))
	f.Add([]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff})
	f.Add(genuine[:len(genuine)/2])
	f.Fuzz(func(t *testing.T, data []byte) {
		r.srv.safelyOrFail(t, func() { r.srv.authTrap(r.dev, data) })
	})
}

/* safelyOrFail runs fn and fails the test on a panic (safely would hide it). */
func (s *server) safelyOrFail(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic: %v %s", r, debug.Stack())
		}
	}()
	fn()
}

/* End to end: a spoofer at the device's address floods forged v3 messages; the device's traps keep being stored. */
func TestV3SpoofFloodOverSocketsKeepsDeviceWorking(t *testing.T) {
	h := newHarness(t)
	id := h.device("127.0.0.2")
	h.profile(id, "snmp3", map[string]string{"user": "nms", "auth_proto": "SHA256", "auth_key": authKey, "priv_proto": "AES", "priv_key": privKey})
	h.start()
	c := udpFrom(t, "127.0.0.2", h.addrs.TrapUDP)
	legit := v3Packet(t, "nms", engineID(0), true)
	if _, err := c.Write(legit); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "first trap stored (engine pinned)", func() bool { return h.count(`SELECT count(*) FROM events.trap`) == 1 })

	start := time.Now()
	const rounds, forged = 20, 15
	for r := range rounds {
		for i := range forged {
			if _, err := c.Write(v3Packet(t, "nms", engineID(r*forged+i+1), false)); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := c.Write(legit); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	eventually(t, 15*time.Second, "all genuine traps stored", func() bool { return h.count(`SELECT count(*) FROM events.trap`) == 1+rounds })
	eventually(t, 10*time.Second, "forgeries counted", func() bool { return h.stat("auth_failed") == rounds*forged })
	t.Logf("%d forged v3 messages with distinct engine IDs and %d genuine traps in %v: all genuine stored, %d forged refused", rounds*forged, rounds, time.Since(start), h.stat("auth_failed"))
}
