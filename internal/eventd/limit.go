package eventd

import (
	"math"
	"sync"
	"time"
)

/* bucket is a token bucket. */
type bucket struct {
	tokens float64
	last   time.Time
}

/*
limiter is a token bucket per source device: rate tokens per second, burst at
most. The state of a device is dropped by prune when the device disappears.
*/
type limiter struct {
	mu          sync.Mutex
	rate, burst float64
	m           map[int64]*bucket
}

func newLimiter(rate, burst int) *limiter {
	return &limiter{rate: float64(rate), burst: float64(burst), m: map[int64]*bucket{}}
}

/* allow takes one token of device id, if there is one. */
func (l *limiter) allow(id int64, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.m[id]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.m[id] = b
	}
	if d := now.Sub(b.last); d > 0 {
		b.tokens = min(l.burst, b.tokens+d.Seconds()*l.rate)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

/* prune forgets the devices for which keep is false. */
func (l *limiter) prune(keep func(id int64) bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for id := range l.m {
		if !keep(id) {
			delete(l.m, id)
		}
	}
}

type stormKey struct {
	dev  int64
	kind string
}

type stormEntry struct {
	minute time.Time
	n      int64
}

/*
storm folds the events a source sent above its rate limit into one row per
source, kind and minute, so the count is kept without the rows. An entry is
written when its minute is over (sweep) or at shutdown (flush).
*/
type storm struct {
	mu   sync.Mutex
	m    map[stormKey]*stormEntry
	emit func(e event)
}

func newStorm(emit func(event)) *storm {
	return &storm{m: map[stormKey]*stormEntry{}, emit: emit}
}

func (s *storm) add(dev int64, k kind, now time.Time) {
	key := stormKey{dev, "syslog"}
	if k == kindTrap {
		key.kind = "trap"
	}
	minute := now.Truncate(time.Minute)
	var done []event
	s.mu.Lock()
	e := s.m[key]
	if e != nil && !e.minute.Equal(minute) {
		done = append(done, stormRow(key, e))
		e = nil
	}
	if e == nil {
		e = &stormEntry{minute: minute}
		s.m[key] = e
	}
	e.n++
	s.mu.Unlock()
	for _, d := range done {
		s.emit(d)
	}
}

/* sweep writes the entries whose minute has ended. */
func (s *storm) sweep(now time.Time) {
	minute := now.Truncate(time.Minute)
	var done []event
	s.mu.Lock()
	for key, e := range s.m {
		if e.minute.Before(minute) {
			done = append(done, stormRow(key, e))
			delete(s.m, key)
		}
	}
	s.mu.Unlock()
	for _, d := range done {
		s.emit(d)
	}
}

/* flush writes every entry, finished or not (shutdown). */
func (s *storm) flush() {
	var done []event
	s.mu.Lock()
	for key, e := range s.m {
		done = append(done, stormRow(key, e))
		delete(s.m, key)
	}
	s.mu.Unlock()
	for _, d := range done {
		s.emit(d)
	}
}

func stormRow(key stormKey, e *stormEntry) event {
	return event{kind: kindStorm, ts: e.minute, dev: key.dev, stormKind: key.kind, count: int32(min(e.n, math.MaxInt32))} // #nosec G115 -- clamped
}
