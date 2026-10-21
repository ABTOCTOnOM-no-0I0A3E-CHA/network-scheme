package poller

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testDevice(id int64, every time.Duration) device {
	return device{ID: id, Addr: netip.MustParseAddrPort("192.0.2.1:161"), Driver: "auto",
		Intervals: [numClasses]time.Duration{every, time.Hour, time.Hour}}
}

func TestJitterSpreadsStartup(t *testing.T) {
	s := newScheduler(4, func(context.Context, device, *devCache, class, *deviceLock) error { return nil }, nil)
	now := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	devs := make([]device, 100)
	for i := range devs {
		devs[i] = testDevice(int64(i+1), 30*time.Second)
	}
	s.apply(devs)
	seconds := map[int64]bool{}
	for _, d := range devs {
		off := s.nextDue(d.ID, classAvail).Sub(now)
		if off < 0 || off >= 30*time.Second {
			t.Fatalf("device %d first run at +%v, outside the interval", d.ID, off)
		}
		seconds[int64(off/time.Second)] = true
	}
	if len(seconds) < 20 {
		t.Fatalf("first runs fall into %d distinct seconds, want >= 20", len(seconds))
	}
}

func TestSlowDeviceDoesNotBlockOthers(t *testing.T) {
	const every = 100 * time.Millisecond
	var mu sync.Mutex
	runs := map[int64][]time.Time{}
	s := newScheduler(8, func(ctx context.Context, d device, _ *devCache, _ class, _ *deviceLock) error {
		if d.ID == 1 { /* an unreachable device: every request runs into its timeout */
			select {
			case <-ctx.Done():
			case <-time.After(3 * time.Second):
			}
			return errors.New("timeout")
		}
		mu.Lock()
		runs[d.ID] = append(runs[d.ID], time.Now())
		mu.Unlock()
		return nil
	}, nil)
	devs := []device{testDevice(1, every)}
	for id := int64(2); id <= 20; id++ {
		devs = append(devs, testDevice(id, every))
	}
	s.apply(devs)
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	start := time.Now()
	s.loop(ctx)
	mu.Lock()
	defer mu.Unlock()
	for id := int64(2); id <= 20; id++ {
		ts := runs[id]
		if len(ts) < 10 {
			t.Fatalf("device %d ran %d times in 2.5s", id, len(ts))
		}
		prev := start
		for _, at := range ts {
			if gap := at.Sub(prev); gap > every+time.Second {
				t.Fatalf("device %d waited %v between runs", id, gap)
			}
			prev = at
		}
	}
}

func TestNoOverlappingPollsPerDevice(t *testing.T) {
	inflight := map[int64]*atomic.Int32{}
	var worst atomic.Int32
	var total atomic.Int64
	enter := func(id int64) {
		if n := inflight[id].Add(1); n > worst.Load() {
			worst.Store(n)
		}
		total.Add(1)
		time.Sleep(time.Millisecond)
		inflight[id].Add(-1)
	}
	s := newScheduler(64, func(_ context.Context, d device, _ *devCache, _ class, lk *deviceLock) error {
		if lk != nil { /* availability without the lock never opens a session: not a poll of the device */
			return nil
		}
		enter(d.ID)
		return nil
	}, nil)
	var devs []device
	for id := int64(1); id <= 5; id++ {
		inflight[id] = &atomic.Int32{}
		d := testDevice(id, 2*time.Millisecond)
		d.Intervals = [numClasses]time.Duration{2 * time.Millisecond, 3 * time.Millisecond, 5 * time.Millisecond}
		devs = append(devs, d)
	}
	s.apply(devs)
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	var wg sync.WaitGroup
	for id := int64(1); id <= 5; id++ {
		wg.Go(func() { /* poll_now requests racing the schedule */
			for ctx.Err() == nil {
				_ = s.runNow(ctx, id, func(d device, _ *devCache) error { enter(d.ID); return nil })
			}
		})
	}
	s.loop(ctx)
	wg.Wait()
	if worst.Load() != 1 || total.Load() < 100 {
		t.Fatalf("max concurrent polls of one device = %d over %d polls, want 1", worst.Load(), total.Load())
	}
	if err := s.runNow(context.Background(), 99, func(device, *devCache) error { return nil }); !errors.Is(err, errNotMine) {
		t.Fatalf("runNow of an unknown device: %v", err)
	}
}

func TestApplyReschedulesAndForgets(t *testing.T) {
	var forgotten []int64
	s := newScheduler(1, func(context.Context, device, *devCache, class, *deviceLock) error { return nil }, func(id int64) { forgotten = append(forgotten, id) })
	now := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	s.apply([]device{testDevice(1, time.Hour), testDevice(2, time.Hour)})
	cache := s.devs[1].cache
	/* An interval change takes effect within the new interval, not after the old one. */
	d1 := testDevice(1, 10*time.Second)
	s.apply([]device{d1, testDevice(2, time.Hour)})
	if off := s.nextDue(1, classAvail).Sub(now); off < 0 || off >= 10*time.Second {
		t.Fatalf("rescheduled to +%v", off)
	}
	if s.interval(1, classAvail) != 10*time.Second || cache.readdressed.Load() || cache.redriven.Load() {
		t.Fatal("interval not updated, or cache reset without an address change")
	}
	/* A new address invalidates what was learned about the device. */
	d1.Addr = netip.MustParseAddrPort("192.0.2.2:161")
	s.apply([]device{d1, testDevice(2, time.Hour)})
	if !cache.readdressed.Load() {
		t.Fatal("address change kept the device cache")
	}
	/* Another driver only invalidates the identified driver. */
	d1.Driver = "eltex-esr"
	s.apply([]device{d1, testDevice(2, time.Hour)})
	if !cache.redriven.Load() {
		t.Fatal("driver change kept the identified driver")
	}
	/* Gone from the list (deleted or moved to another poller): unscheduled and forgotten. */
	s.apply([]device{d1})
	if _, ok := s.devs[2]; ok || len(forgotten) != 1 || forgotten[0] != 2 {
		t.Fatalf("device 2 still known, forgotten = %v", forgotten)
	}
}

func TestBackoff(t *testing.T) {
	for _, c := range []struct {
		every time.Duration
		fails int
		want  time.Duration
	}{
		{time.Minute, 0, time.Minute},
		{time.Minute, 1, 2 * time.Minute},
		{time.Minute, 2, 4 * time.Minute},
		{time.Minute, 3, 5 * time.Minute},
		{time.Minute, 60, 5 * time.Minute},
		{10 * time.Minute, 3, 10 * time.Minute}, /* never shorter than the interval itself */
	} {
		if got := backoff(c.every, c.fails); got != c.want {
			t.Errorf("backoff(%v, %d) = %v, want %v", c.every, c.fails, got, c.want)
		}
	}
}

func TestAvailabilityNeverBacksOff(t *testing.T) {
	var avail, metrics atomic.Int32
	s := newScheduler(4, func(_ context.Context, _ device, _ *devCache, c class, _ *deviceLock) error {
		if c == classAvail {
			avail.Add(1)
		} else {
			metrics.Add(1)
		}
		return errors.New("device down")
	}, nil)
	d := testDevice(1, 50*time.Millisecond)
	d.Intervals[classMetrics] = 50 * time.Millisecond
	s.apply([]device{d})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s.loop(ctx)
	/* ~20 availability runs at a fixed interval; metrics backs off 50, 100, 200, 400 ms: ~5 runs. */
	if avail.Load() < 14 || metrics.Load() > 7 {
		t.Fatalf("availability ran %d times, metrics %d times", avail.Load(), metrics.Load())
	}
}

/* busyRun blocks metrics and inventory of the slow devices for 3 s and records availability runs. */
type busyRun struct {
	mu     sync.Mutex
	slow   map[int64]bool
	avail  map[int64][]time.Time
	locked map[int64]int /* availability runs that found the device lock free */
}

func newBusyRun() *busyRun {
	return &busyRun{slow: map[int64]bool{}, avail: map[int64][]time.Time{}, locked: map[int64]int{}}
}

func (b *busyRun) run(ctx context.Context, d device, _ *devCache, c class, lk *deviceLock) error {
	if c == classAvail {
		got := lk == nil || lk.TryLock()
		if got && lk != nil {
			lk.Unlock()
		}
		b.mu.Lock()
		b.avail[d.ID] = append(b.avail[d.ID], time.Now())
		if got {
			b.locked[d.ID]++
		}
		b.mu.Unlock()
		return nil
	}
	if b.slow[d.ID] {
		select {
		case <-ctx.Done():
		case <-time.After(3 * time.Second):
		}
	}
	return nil
}

func TestAvailabilityRunsWhileDeviceBusy(t *testing.T) {
	b := newBusyRun()
	b.slow[1] = true
	s := newScheduler(8, b.run, nil)
	d := testDevice(1, 100*time.Millisecond)
	d.Intervals[classInventory] = 10 * time.Millisecond /* a long inventory takes the device lock almost at once */
	s.apply([]device{d})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s.loop(ctx)
	b.mu.Lock()
	defer b.mu.Unlock()
	if n := len(b.avail[1]); n < 12 {
		t.Fatalf("availability ran %d times in 2 s while the inventory held the device", n)
	}
	if b.locked[1] > 2 {
		t.Fatalf("availability got the device lock %d times while the inventory held it", b.locked[1])
	}
}

func TestSlowDevicesDoNotPinWorkers(t *testing.T) {
	const workers, every = 6, 100 * time.Millisecond
	b := newBusyRun()
	var devs []device
	for id := int64(1); id <= 13; id++ {
		d := testDevice(id, every)
		if id <= 3 { /* more slow devices than workers/3 */
			b.slow[id] = true
			d.Intervals[classMetrics], d.Intervals[classInventory] = 10*time.Millisecond, 10*time.Millisecond
		}
		devs = append(devs, d)
	}
	s := newScheduler(workers, b.run, nil)
	s.apply(devs)
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	start := time.Now()
	s.loop(ctx)
	b.mu.Lock()
	defer b.mu.Unlock()
	for id := int64(4); id <= 13; id++ {
		ts := b.avail[id]
		if len(ts) < 10 {
			t.Fatalf("device %d ran %d times in 2.5 s", id, len(ts))
		}
		prev := start
		for _, at := range ts {
			if gap := at.Sub(prev); gap > every+time.Second {
				t.Fatalf("device %d waited %v between runs", id, gap)
			}
			prev = at
		}
	}
}

func TestStartedReportsDueTime(t *testing.T) {
	const every = 100 * time.Millisecond
	type start struct {
		c       class
		due, at time.Time
	}
	var mu sync.Mutex
	starts := map[int64][]start{}
	s := newScheduler(4, func(context.Context, device, *devCache, class, *deviceLock) error { return nil }, nil)
	s.started = func(id int64, c class, due, at time.Time) {
		mu.Lock()
		starts[id] = append(starts[id], start{c, due, at})
		mu.Unlock()
	}
	s.apply([]device{testDevice(1, every), testDevice(2, every)})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s.loop(ctx)
	mu.Lock()
	defer mu.Unlock()
	for id := int64(1); id <= 2; id++ {
		var prev time.Time
		n := 0
		for _, st := range starts[id] {
			if st.c != classAvail {
				continue
			}
			if st.at.Before(st.due) {
				t.Fatalf("device %d started at %v, before it was due (%v)", id, st.at, st.due)
			}
			if !prev.IsZero() && st.due.Sub(prev) != every {
				t.Fatalf("device %d: due times %v apart, want %v", id, st.due.Sub(prev), every)
			}
			prev = st.due
			n++
		}
		if n < 5 {
			t.Fatalf("device %d: %d availability starts reported in 1 s", id, n)
		}
	}
}

func TestAvailabilityStartedHook(t *testing.T) {
	var got []int64
	p := New(Config{Workers: 1}, Deps{AvailabilityStarted: func(id int64, _, _ time.Time) { got = append(got, id) }})
	now := time.Now()
	p.sched.started(1, classMetrics, now, now)
	p.sched.started(2, classAvail, now, now)
	p.sched.started(3, classInventory, now, now)
	if len(got) != 1 || got[0] != 2 {
		t.Fatalf("hook saw devices %v, want only the availability start of device 2", got)
	}
	if New(Config{Workers: 1}, Deps{}).sched.started != nil {
		t.Fatal("scheduler reports starts without a hook")
	}
}

/*
Slow metrics and inventory runs of every device (a slow network) must not
take every worker slot: availability keeps a quarter of them and stays on
schedule.
*/
func TestSlowPollsLeaveSlotsForAvailability(t *testing.T) {
	const every = 100 * time.Millisecond
	var mu sync.Mutex
	runs := map[int64][]time.Time{}
	s := newScheduler(8, func(ctx context.Context, d device, _ *devCache, c class, _ *deviceLock) error {
		if c != classAvail {
			select {
			case <-ctx.Done():
			case <-time.After(3 * time.Second):
			}
			return nil
		}
		mu.Lock()
		runs[d.ID] = append(runs[d.ID], time.Now())
		mu.Unlock()
		return nil
	}, nil)
	var devs []device
	for id := int64(1); id <= 20; id++ {
		d := testDevice(id, every)
		d.Intervals = [numClasses]time.Duration{every, every, every}
		devs = append(devs, d)
	}
	s.apply(devs)
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	start := time.Now()
	s.loop(ctx)
	mu.Lock()
	defer mu.Unlock()
	for _, d := range devs {
		ts := runs[d.ID]
		if len(ts) < 10 {
			t.Fatalf("device %d: availability ran %d times in 2.5 s while slow polls ran", d.ID, len(ts))
		}
		prev := start
		for _, at := range ts {
			if gap := at.Sub(prev); gap > every+time.Second {
				t.Fatalf("device %d: availability waited %v", d.ID, gap)
			}
			prev = at
		}
	}
}
