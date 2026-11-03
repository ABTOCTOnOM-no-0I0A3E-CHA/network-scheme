package web

import (
	"testing"
	"time"
)

/* A full limiter forgets only refilled buckets for a new key, and refuses the new key while none has refilled. */
func TestLimiterEvictsRefilledAndRefusesWhenFull(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	l := newLimiter(1, 2, 2, func() time.Time { return now })
	for _, k := range []string{"a", "b"} {
		if ok, _ := l.allow(k); !ok {
			t.Fatalf("first request of %s refused", k)
		}
	}
	if ok, wait := l.allow("c"); ok || wait <= 0 {
		t.Fatalf("a third key while both buckets are drawn: %v %v, want refused", ok, wait)
	}
	if len(l.buckets) != 2 {
		t.Fatalf("%d buckets kept, want the bound 2", len(l.buckets))
	}
	now = now.Add(time.Second) /* both buckets back at their burst */
	if ok, _ := l.allow("c"); !ok {
		t.Fatal("a new key refused although the old buckets refilled")
	}
	if _, kept := l.buckets["a"]; kept || len(l.buckets) != 1 {
		t.Fatalf("refilled buckets not forgotten: %v", l.buckets)
	}
	/* A key's own bucket: burst 2, then refused with the time to the next token. */
	l = newLimiter(1, 2, 10, func() time.Time { return now })
	l.allow("x")
	l.allow("x")
	if ok, wait := l.allow("x"); ok || wait != time.Second {
		t.Fatalf("third request: %v, wait %v", ok, wait)
	}
}
