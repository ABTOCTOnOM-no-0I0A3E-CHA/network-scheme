package eventd

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
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
	if d, rel, _ := s.acquire(netip.MustParseAddr("127.0.0.2")); d != da {
		t.Error("unchanged device was rebuilt")
	} else {
		rel()
	}
	h.setEngine(a, engineID(2))
	h.reload(s)
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
