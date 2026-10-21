package poller

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/snmp"
)

func TestAvailabilityWhileDeviceBusyUsesSessionStamp(t *testing.T) {
	h := newHarness(t, "")
	p := h.poller(Intervals{Availability: time.Minute, Metrics: time.Hour, Inventory: time.Hour})
	ctx := context.Background()
	addr := netip.MustParseAddrPort("198.51.100.160:161")
	id := h.device(addr)
	h.simProfile(id)
	devs, err := p.loadDevices(ctx)
	if err != nil || len(devs) != 1 {
		t.Fatalf("devices = %v, %v", devs, err)
	}
	lk := newDeviceLock()
	if err := lk.Lock(ctx); err != nil { /* an inventory of the device is in progress */
		t.Fatal(err)
	}
	cache := newDevCache()
	for _, c := range []struct {
		age   time.Duration
		icmp  bool
		state string
	}{
		{5 * time.Second, true, "up"},       /* the running session answered recently */
		{90 * time.Second, true, "partial"}, /* it stopped answering more than an interval ago */
		{90 * time.Second, false, "down"},
		{5 * time.Second, false, "up"},
	} {
		cache.lastSNMP.Store(time.Now().Add(-c.age).UnixNano())
		p.pinger = fakePinger{ok: c.icmp}
		if err := p.run(ctx, devs[0], cache, classAvail, lk); err != nil {
			t.Fatal(err)
		}
		if s := h.str(`SELECT state FROM inventory.device_status WHERE device_id = $1`, id); s != c.state {
			t.Fatalf("stamp %v old, icmp %v: state %q, want %q", c.age, c.icmp, s, c.state)
		}
	}
	/* No second session, and nothing of the locked device state was touched. */
	if n := h.dialer.count(addr); n != 0 {
		t.Fatalf("%d SNMP sessions while the device was busy", n)
	}
	if s := h.str(`SELECT status FROM core.access_profile WHERE owner_kind = 'device' AND owner_id = $1`, id); s != "pending" {
		t.Fatalf("profile status %q: the busy path opened the credential", s)
	}
	if len(cache.creds) != 0 {
		t.Fatal("the busy path filled the credential cache")
	}
	/* Lock free again: a real probe through its own session. */
	lk.Unlock()
	p.pinger = fakePinger{ok: true}
	_ = p.run(ctx, devs[0], cache, classAvail, lk)
	if n := h.dialer.count(addr); n != 1 {
		t.Fatalf("SNMP sessions with the lock free = %d", n)
	}
}

/* stubReader answers every request with err (nil: one variable). */
type stubReader struct{ err error }

func (r stubReader) Get(context.Context, ...string) ([]snmp.Var, error) {
	return []snmp.Var{{OID: oidSysUpTime, Type: snmp.TypeTimeTicks, Value: uint64(1)}}, r.err
}

func (r stubReader) BulkGet(ctx context.Context, oids []string) ([]snmp.Var, error) {
	return r.Get(ctx, oids...)
}

func (r stubReader) Walk(_ context.Context, _ string, fn func(snmp.Var) error) error {
	if r.err != nil {
		return r.err
	}
	return fn(snmp.Var{OID: "1.3.6.1.2.1.2.2.1.1.1", Type: snmp.TypeInteger, Value: int64(1)})
}

func TestStampReaderMarksResponses(t *testing.T) {
	var at atomic.Int64
	now := time.Unix(1000, 0)
	clock := func() time.Time { return now }
	ctx := context.Background()
	failing := stampReader{r: stubReader{err: snmp.ErrTimeout}, at: &at, now: clock}
	_, _ = failing.Get(ctx, oidSysUpTime)
	_, _ = failing.BulkGet(ctx, []string{oidSysUpTime})
	_ = failing.Walk(ctx, "1.3", func(snmp.Var) error { return nil })
	if at.Load() != 0 {
		t.Fatal("a failed request was stamped")
	}
	ok := stampReader{r: stubReader{}, at: &at, now: clock}
	for name, call := range map[string]func(){
		"get":     func() { _, _ = ok.Get(ctx, oidSysUpTime) },
		"bulkget": func() { _, _ = ok.BulkGet(ctx, []string{oidSysUpTime}) },
		"walk":    func() { _ = ok.Walk(ctx, "1.3", func(snmp.Var) error { return nil }) },
	} {
		at.Store(0)
		now = now.Add(time.Second)
		call()
		if at.Load() != now.UnixNano() {
			t.Fatalf("%s: stamp %d, want %d", name, at.Load(), now.UnixNano())
		}
	}
}
