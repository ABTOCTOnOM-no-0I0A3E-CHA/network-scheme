package poller

import (
	"container/heap"
	"context"
	"errors"
	"math/rand/v2"
	"net/netip"
	"sync"
	"time"
)

/* class is a kind of periodic poll with its own interval. */
type class int

const (
	classAvail class = iota
	classMetrics
	classInventory
	numClasses
)

/* maxBackoff caps the retry delay of failing metrics and inventory polls. */
const maxBackoff = 5 * time.Minute

/* errNotMine: the device is not (or no longer) assigned to this poller. */
var errNotMine = errors.New("poller: device is not assigned to this poller")

/* device is what the scheduler knows of a device; Intervals are effective (device ?? group ?? config). */
type device struct {
	ID        int64
	Addr      netip.AddrPort
	Driver    string
	Intervals [numClasses]time.Duration
}

/*
runFunc polls one class of a device. lk is nil when the caller holds the
device lock. Availability is called with the device's lock not held (lk set):
it may only TryLock it and must not touch the device cache without it.
*/
type runFunc func(ctx context.Context, d device, cache *devCache, c class, lk *deviceLock) error

/* deviceLock serialises the polls of one device: one SNMP and one SSH session at most. */
type deviceLock struct{ ch chan struct{} }

func newDeviceLock() *deviceLock { return &deviceLock{ch: make(chan struct{}, 1)} }

/* Lock takes the lock unless ctx ends first. */
func (l *deviceLock) Lock(ctx context.Context) error {
	select {
	case l.ch <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

/* TryLock takes the lock if it is free, without waiting. */
func (l *deviceLock) TryLock() bool {
	select {
	case l.ch <- struct{}{}:
		return true
	default:
		return false
	}
}

func (l *deviceLock) Unlock() { <-l.ch }

type devState struct {
	dev   device
	lock  *deviceLock /* one poll of the device at a time, whatever the class or source */
	cache *devCache   /* touched only with lock held, apart from its atomics */
	next  [numClasses]time.Time
	gen   [numClasses]uint64 /* invalidates queued items when the class is rescheduled */
	busy  [numClasses]bool
	fails [numClasses]int
}

type item struct {
	at  time.Time
	id  int64
	c   class
	gen uint64
}

type itemHeap []item

func (h itemHeap) Len() int           { return len(h) }
func (h itemHeap) Less(i, j int) bool { return h[i].at.Before(h[j].at) }
func (h itemHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *itemHeap) Push(x any)        { *h = append(*h, x.(item)) }
func (h *itemHeap) Pop() any {
	old := *h
	it := old[len(old)-1]
	*h = old[:len(old)-1]
	return it
}

/*
scheduler runs every class of every device at its interval on a bounded
worker pool. A device's first run is at a random point within its interval,
so a restart does not poll every device at once. A class is queued again only
when its run has finished, and every session-opening run holds the device
lock, so polls of one device never overlap; availability never waits for the
lock, so a long inventory cannot delay it. Failing metrics and inventory runs back off
exponentially; availability always keeps its interval.
*/
type scheduler struct {
	mu       sync.Mutex
	devs     map[int64]*devState
	q        itemHeap
	wake     chan struct{}
	sem      chan struct{}
	run      runFunc
	onRemove func(id int64) /* called without mu held */
	now      func() time.Time
	wg       sync.WaitGroup
}

func newScheduler(workers int, run runFunc, onRemove func(int64)) *scheduler {
	if onRemove == nil {
		onRemove = func(int64) {}
	}
	return &scheduler{
		devs: map[int64]*devState{}, wake: make(chan struct{}, 1), sem: make(chan struct{}, workers),
		run: run, onRemove: onRemove, now: time.Now,
	}
}

/* jitter returns a uniformly random offset in [0, d). */
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return rand.N(d) // #nosec G404 -- spreading load, not a secret
}

/* backoff is the delay after fails consecutive failures: the interval doubled per failure, at most max(5 min, interval). */
func backoff(every time.Duration, fails int) time.Duration {
	limit := max(maxBackoff, every)
	d := every
	for i := 0; i < fails && d < limit; i++ {
		d *= 2
	}
	return min(d, limit)
}

/* schedule queues class c of ds at at; mu must be held. */
func (s *scheduler) schedule(ds *devState, c class, at time.Time) {
	ds.gen[c]++
	ds.next[c] = at
	heap.Push(&s.q, item{at: at, id: ds.dev.ID, c: c, gen: ds.gen[c]})
}

func (s *scheduler) poke() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

/*
apply replaces the device list: new devices start at a random point of each
interval, changed intervals take effect within the new interval, a changed
address or driver invalidates what the worker learned, and devices missing
from the list (deleted or assigned to another poller) are dropped and passed
to onRemove.
*/
func (s *scheduler) apply(devs []device) {
	now := s.now()
	seen := make(map[int64]bool, len(devs))
	var gone []int64
	s.mu.Lock()
	for _, d := range devs {
		seen[d.ID] = true
		ds, ok := s.devs[d.ID]
		if !ok {
			ds = &devState{dev: d, lock: newDeviceLock(), cache: newDevCache()}
			s.devs[d.ID] = ds
			for c := range numClasses {
				s.schedule(ds, c, now.Add(jitter(d.Intervals[c])))
			}
			continue
		}
		old := ds.dev
		ds.dev = d
		if d.Addr != old.Addr {
			ds.cache.readdressed.Store(true)
		}
		if d.Driver != old.Driver {
			ds.cache.redriven.Store(true)
		}
		for c := range numClasses {
			if d.Intervals[c] != old.Intervals[c] && !ds.busy[c] {
				s.schedule(ds, c, now.Add(jitter(d.Intervals[c])))
			}
		}
	}
	for id := range s.devs {
		if !seen[id] {
			delete(s.devs, id)
			gone = append(gone, id)
		}
	}
	s.mu.Unlock()
	s.poke()
	for _, id := range gone {
		s.onRemove(id)
	}
}

/* loop dispatches due runs until ctx ends, then waits for the runs in flight. */
func (s *scheduler) loop(ctx context.Context) {
	defer s.wg.Wait()
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		wait := time.Hour
		s.mu.Lock()
		now := s.now()
		for s.q.Len() > 0 {
			it := s.q[0]
			ds := s.devs[it.id]
			if ds == nil || ds.gen[it.c] != it.gen || ds.busy[it.c] {
				heap.Pop(&s.q) /* stale: removed device or rescheduled class */
				continue
			}
			if d := it.at.Sub(now); d > 0 {
				wait = d
				break
			}
			heap.Pop(&s.q)
			ds.busy[it.c] = true
			s.wg.Add(1)
			go s.exec(ctx, ds, it)
		}
		s.mu.Unlock()
		timer.Reset(wait)
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-timer.C:
		}
	}
}

/* exec runs one due class on a worker slot (under the device lock unless availability) and queues the next run. */
func (s *scheduler) exec(ctx context.Context, ds *devState, it item) {
	defer s.wg.Done()
	err := func() error {
		/*
			Device lock first, worker slot second: a run waiting for its busy device
			must not hold a slot. Availability does not wait for the lock at all; it
			gets the lock to TryLock.
		*/
		lk := ds.lock
		if it.c != classAvail {
			if err := ds.lock.Lock(ctx); err != nil {
				return err
			}
			defer ds.lock.Unlock()
			lk = nil
		}
		select {
		case s.sem <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		defer func() { <-s.sem }()
		s.mu.Lock()
		d := ds.dev
		s.mu.Unlock()
		return s.run(ctx, d, ds.cache, it.c, lk)
	}()

	s.mu.Lock()
	ds.busy[it.c] = false
	if s.devs[it.id] != ds {
		s.mu.Unlock()
		s.onRemove(it.id) /* removed while running: drop what this run may have recorded */
		return
	}
	now := s.now()
	every := ds.dev.Intervals[it.c]
	var next time.Time
	if err != nil && it.c != classAvail {
		ds.fails[it.c]++
		next = now.Add(backoff(every, ds.fails[it.c]))
	} else {
		ds.fails[it.c] = 0
		next = it.at.Add(every)
		if next.Before(now) {
			next = now /* overran its interval: run once more now, never in a burst */
		}
	}
	s.schedule(ds, it.c, next)
	s.mu.Unlock()
	s.poke()
}

/*
runNow runs fn for device id under its lock, waiting for a poll in progress
to finish; errNotMine when the device is not scheduled here.
*/
func (s *scheduler) runNow(ctx context.Context, id int64, fn func(d device, cache *devCache) error) error {
	s.mu.Lock()
	ds := s.devs[id]
	s.mu.Unlock()
	if ds == nil {
		return errNotMine
	}
	if err := ds.lock.Lock(ctx); err != nil {
		return err
	}
	defer ds.lock.Unlock()
	s.mu.Lock()
	if s.devs[id] != ds {
		s.mu.Unlock()
		return errNotMine
	}
	d := ds.dev
	s.mu.Unlock()
	return fn(d, ds.cache)
}

/* known reports whether device id is scheduled. */
func (s *scheduler) known(id int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.devs[id] != nil
}

/* interval is the effective interval of class c of device id; 0 when unknown. */
func (s *scheduler) interval(id int64, c class) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ds := s.devs[id]; ds != nil {
		return ds.dev.Intervals[c]
	}
	return 0
}

/* nextDue is when class c of device id runs next. */
func (s *scheduler) nextDue(id int64, c class) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ds := s.devs[id]; ds != nil {
		return ds.next[c]
	}
	return time.Time{}
}
