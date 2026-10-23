package topology_test

import (
	"context"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/topology"
)

/* One device reporting 200 000 neighbours that all name b: the build stays bounded, keeps at most 64 links for the pair, and stops on cancel. */
func TestHostileInventoryIsBounded(t *testing.T) {
	h := newHarness(t)
	x, _ := h.dev("x")
	b, _ := h.dev("b")
	h.exec(`INSERT INTO inventory.interface SELECT $1, i, 'g' || i, '', 1000000000, true, now() FROM generate_series(5, 5000) i`, x)
	h.exec(`INSERT INTO inventory.lldp_neighbor (device_id, local_if_index, chassis_id, port_id, sys_name, mgmt_addr, seen_at)
		SELECT $1, 1 + i % 5000, 'c' || i, 'p' || i, 'b', NULL, now() FROM generate_series(1, 200000) i`, x)
	start := time.Now()
	h.build()
	d := time.Since(start)
	t.Logf("200000 LLDP rows from one device: build %v", d)
	if n := len(h.between(x, b)); n == 0 || n > 64 {
		t.Errorf("links %d", n)
	}
	if d > 10*time.Second {
		t.Errorf("too slow: %v", d)
	}
	/* a cancelled context ends Run promptly */
	ctx, cancel := context.WithCancel(h.ctx)
	done := make(chan struct{})
	go func() { _ = topology.New(topology.Config{Pool: h.api}).Run(ctx); close(done) }()
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

/* Mutual rows without any agreeing port name are not proof: 0.8, not 1.0. */
func TestMutualWithoutPortProofIsCapped(t *testing.T) {
	h := newHarness(t)
	a, aIP := h.dev("a")
	b, bIP := h.dev("b")
	h.nb(a, 1, "02:00:00:00:00:0b", "weird-1", "b", bIP)
	h.nb(b, 2, "02:00:00:00:00:0a", "weird-2", "a", aIP)
	h.build()
	if l := h.one(a, b); l.conf != 80 {
		t.Errorf("%+v", l)
	}
}
