package topology_test

import (
	"context"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/topology"
)

/* One builder runs per database; Reload makes it build at once. */
func TestRunHoldsLockAndReloads(t *testing.T) {
	h := newHarness(t)
	a, aIP := h.dev("a")
	b, bIP := h.dev("b")
	h.up()
	ctx, cancel := context.WithCancel(h.ctx)
	defer cancel()
	b1 := topology.New(topology.Config{Pool: h.api})
	b2 := topology.New(topology.Config{Pool: h.api})
	go func() { _ = b1.Run(ctx) }()
	time.Sleep(500 * time.Millisecond) /* b1 wins the lock */
	go func() { _ = b2.Run(ctx) }()
	time.Sleep(500 * time.Millisecond)
	var holders int
	if err := h.root.QueryRow(h.ctx, `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted AND objid = $1 AND classid = $2`,
		int64(0x6e6d73746f706f)&0xffffffff, int64(0x6e6d73746f706f)>>32).Scan(&holders); err != nil {
		t.Fatal(err)
	}
	if holders != 1 {
		t.Errorf("lock holders %d", holders)
	}
	h.nb(a, 1, "02:00:00:00:00:0b", "g2", "b", bIP)
	h.nb(b, 2, "02:00:00:00:00:0a", "g1", "a", aIP)
	b1.Reload()
	b2.Reload() /* the idle one ignores it */
	deadline := time.Now().Add(15 * time.Second)
	for len(h.links()) == 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if got := len(h.links()); got != 1 {
		t.Fatalf("links after Reload: %d", got)
	}
}
