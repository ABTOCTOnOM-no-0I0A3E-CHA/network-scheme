package eventd

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/secret"
)

/* pinnedEngine reads the engine the device's v3 state is pinned to ("" when none). */
func pinnedEngine(d *device) string {
	d.v3.mu.Lock()
	defer d.v3.mu.Unlock()
	if d.v3.pin == nil {
		return ""
	}
	return d.v3.pin.engine
}

func (h *harness) setEngine(id int64, engine string) {
	h.t.Helper()
	if _, err := h.pg.Exec(context.Background(), `INSERT INTO core.device_v3_engine (device_id, engine_id) VALUES ($1, $2)
		ON CONFLICT (device_id) DO UPDATE SET engine_id = EXCLUDED.engine_id`, id, []byte(engine)); err != nil {
		h.t.Fatal(err)
	}
}

func TestReloadPinsTheEngineThePollerLearned(t *testing.T) {
	h := newHarness(t)
	a, b := h.device("127.0.0.2"), h.device("127.0.0.3")
	h.v3(a, "nms")
	h.v3(b, "nms")
	h.setEngine(a, engineID(1))
	s := h.sources()
	h.reload(s)
	s.seedPending(context.Background())
	da, rel, _ := s.acquire(netip.MustParseAddr("127.0.0.2"))
	rel()
	db, rel, _ := s.acquire(netip.MustParseAddr("127.0.0.3"))
	rel()
	if got := pinnedEngine(da); got != engineID(1) {
		t.Fatalf("pinned engine = %q, want the recorded one", got)
	}
	if pinnedEngine(db) != "" {
		t.Fatal("a device without a recorded engine is pinned")
	}
	/* The keys are real: a genuine trap of the pinned engine decodes without any slow-path budget. */
	pkt := v3Packet(t, "nms", engineID(1), true)
	if _, ok := da.v3.decode(pkt, time.Now(), func() bool { t.Error("slow path used"); return false }, func() {}); !ok {
		t.Fatal("genuine trap of the recorded engine refused")
	}
	/* Unchanged reread keeps the object (and its keys); a changed engine replaces it with a new pin. */
	h.reload(s)
	s.seedPending(context.Background())
	if d, rel, _ := s.acquire(netip.MustParseAddr("127.0.0.2")); d != da {
		t.Error("unchanged device was rebuilt")
	} else {
		rel()
	}
	h.setEngine(a, engineID(2))
	h.reload(s)
	s.seedPending(context.Background())
	d2, rel, _ := s.acquire(netip.MustParseAddr("127.0.0.2"))
	rel()
	if d2 == da || pinnedEngine(d2) != engineID(2) {
		t.Fatalf("changed engine: same object %v, pinned %q", d2 == da, pinnedEngine(d2))
	}
}

/* After a restart a flood of foreign engine IDs does not delay the first genuine trap: it is on the fast path at once. */
func TestFloodAfterRestartDoesNotDelayTheFirstGenuineTrap(t *testing.T) {
	h := newHarness(t)
	a := h.device("127.0.0.2")
	h.v3(a, "nms")
	h.setEngine(a, engineID(0))
	s := h.sources()
	h.reload(s)
	s.seedPending(context.Background())
	d, rel, _ := s.acquire(netip.MustParseAddr("127.0.0.2"))
	rel()
	r := newV3Rig(t)
	r.dev = d
	for i := range 2000 {
		if _, ok := r.srv.authTrap(d, v3Packet(t, "nms", engineID(i+1), false)); ok {
			t.Fatal("a forged packet was accepted")
		}
	}
	dropped := r.srv.st.slowDropped.Load()
	if dropped < 1900 {
		t.Fatalf("the flood was not over budget (%d dropped)", dropped)
	}
	if _, ok := r.srv.authTrap(d, v3Packet(t, "nms", engineID(0), true)); !ok {
		t.Fatal("the first genuine trap after the flood was refused")
	}
	if r.srv.st.slowDropped.Load() != dropped {
		t.Error("the genuine trap was charged to the slow budget")
	}
}

/* A recorded engine that no longer matches (device replaced) costs the slow path once, then the new engine is pinned. */
func TestReplacedDeviceTakesTheSlowPathOnce(t *testing.T) {
	h := newHarness(t)
	a := h.device("127.0.0.2")
	h.v3(a, "nms")
	h.setEngine(a, engineID(1))
	s := h.sources()
	h.reload(s)
	s.seedPending(context.Background())
	d, rel, _ := s.acquire(netip.MustParseAddr("127.0.0.2"))
	rel()
	r := newV3Rig(t)
	if _, ok := r.srv.authTrap(d, v3Packet(t, "nms", engineID(9), true)); !ok {
		t.Fatal("trap of the replacement device refused")
	}
	if pinnedEngine(d) != engineID(9) {
		t.Fatalf("pinned %q after the slow path", pinnedEngine(d))
	}
}

func TestEventdMayReadButNotWriteEngineIDs(t *testing.T) {
	h := newHarness(t)
	a := h.device("127.0.0.2")
	h.setEngine(a, engineID(1))
	ctx := context.Background()
	var n int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM core.device_v3_engine`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("nms_eventd read: n=%d err=%v", n, err)
	}
	for _, sql := range []string{
		`INSERT INTO core.device_v3_engine (device_id, engine_id) VALUES (1, '\x8000000001')`,
		`UPDATE core.device_v3_engine SET engine_id = '\x8000000001'`,
		`DELETE FROM core.device_v3_engine`,
	} {
		_, err := h.pool.Exec(ctx, sql)
		if pe, ok := err.(*pgconn.PgError); !ok || pe.Code != "42501" {
			t.Errorf("%s as nms_eventd: %v", sql, err)
		}
	}
}

/* Seeding is parallel, bounded and does not need the listeners to wait: timing of 1000 synthetic v3 devices. */
func TestSeedPendingIsParallelAndStopsWithTheContext(t *testing.T) {
	const n = 1000
	mk := func() *sources {
		s := newSources(nil, nil, nil, time.Now, slog.New(slog.NewTextHandler(io.Discard, nil)))
		snap := &snapshot{byAddr: map[netip.Addr]*device{}}
		for i := range n {
			v, err := newV3(creds.Credential{Kind: creds.KindSNMP3, User: "nms", AuthProto: "SHA256", AuthKey: secret.New(authKey), PrivProto: "AES", PrivKey: secret.New(privKey)})
			if err != nil {
				t.Fatal(err)
			}
			snap.all = append(snap.all, &device{id: int64(i + 1), v3: v, engine: []byte(engineID(i))})
		}
		s.cur.Store(snap)
		return s
	}
	s := mk()
	start := time.Now()
	s.seedPending(context.Background())
	el := time.Since(start)
	for _, d := range s.cur.Load().all {
		if pinnedEngine(d) != string(d.engine) {
			t.Fatalf("device %d not seeded", d.id)
		}
	}
	t.Logf("seeded %d v3 devices on %d CPUs in %v (%.1f ms/device wall)", n, runtime.GOMAXPROCS(0), el, float64(el.Microseconds())/n/1000)

	/* A cancelled context stops the work early and leaves the rest on the slow path. */
	s2 := mk()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s2.seedPending(ctx)
	seeded := 0
	for _, d := range s2.cur.Load().all {
		if pinnedEngine(d) != "" {
			seeded++
		}
	}
	if seeded > runtime.GOMAXPROCS(0) {
		t.Errorf("%d devices seeded after cancellation", seeded)
	}
}

/* Startup asks for seeding twice (Run, then the reload after LISTEN): every device is derived exactly once. */
func TestSeedingDerivesEachDeviceOnce(t *testing.T) {
	h := newHarness(t)
	const n = 12
	for i := range n {
		ip := "127.0.1." + string(rune('1'+i%9))
		if i >= 9 {
			ip = "127.0.2." + string(rune('1'+i-9))
		}
		id := h.device(ip)
		h.v3(id, "nms")
		h.setEngine(id, engineID(i))
	}
	s := h.sources()
	h.reload(s)
	ctx := context.Background()
	s.startSeeding(ctx)
	s.startSeeding(ctx)
	s.startSeeding(ctx)
	s.seedWG.Wait()
	if got := s.derived.Load(); got != n {
		t.Fatalf("derivations = %d, want %d", got, n)
	}
	for _, d := range s.cur.Load().all {
		if pinnedEngine(d) != string(d.engine) {
			t.Fatalf("device %d not seeded", d.id)
		}
	}
}

/* A device notification is applied at once while seeding is still running; seeding never blocks reloadAll. */
func TestReloadDoesNotWaitForSeeding(t *testing.T) {
	h := newHarness(t)
	a := h.device("127.0.0.2")
	h.v3(a, "nms")
	h.setEngine(a, engineID(1))
	srv := newServer(h.cfg, Deps{Pool: h.pool, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Enqueuer: noEnq{}, Priv: h.priv, Pub: h.pub})
	gate := make(chan struct{})
	srv.src.seedGate = func() { <-gate }
	ctx := context.Background()
	done := make(chan error, 1)
	go func() { done <- srv.reloadAll(ctx, true, false) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("reloadAll waits for the seeding worker")
	}
	b := h.device("127.0.0.3") /* appears in the next reload although the first seeding is still blocked */
	if err := srv.reloadAll(ctx, true, false); err != nil {
		t.Fatal(err)
	}
	if _, rel, ok := srv.src.acquire(netip.MustParseAddr("127.0.0.3")); !ok {
		t.Fatalf("device %d not applied while seeding runs", b)
	} else {
		rel()
	}
	close(gate)
	srv.src.seedWG.Wait()
	d, rel, _ := srv.src.acquire(netip.MustParseAddr("127.0.0.2"))
	rel()
	if pinnedEngine(d) != engineID(1) {
		t.Fatal("device not seeded after the gate opened")
	}
}

/* A pin set by an authenticated slow-path message while seeding derives keys is never replaced by the seed. */
func TestSeedNeverReplacesASlowPathPin(t *testing.T) {
	r := newV3Rig(t)
	if _, ok := r.srv.authTrap(r.dev, v3Packet(t, "nms", engineID(9), true)); !ok {
		t.Fatal("genuine trap refused")
	}
	if got := pinnedEngine(r.dev); got != engineID(9) {
		t.Fatalf("pinned %q", got)
	}
	r.dev.v3.seedEngine([]byte(engineID(1))) /* early exit: already pinned */
	sp := &gosnmp.UsmSecurityParameters{
		UserName: "nms", AuthenticationProtocol: gosnmp.SHA256, PrivacyProtocol: gosnmp.AES,
		AuthenticationPassphrase: authKey, PrivacyPassphrase: privKey, AuthoritativeEngineID: engineID(1),
	}
	if err := sp.InitSecurityKeys(); err != nil {
		t.Fatal(err)
	}
	r.dev.v3.setPin(sp, true) /* the check-then-set race: keys derived before the pin appeared */
	if got := pinnedEngine(r.dev); got != engineID(9) {
		t.Fatalf("seed replaced the pin: %q", got)
	}
}
