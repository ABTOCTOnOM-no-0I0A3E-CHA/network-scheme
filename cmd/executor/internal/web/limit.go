package web

import (
	"math"
	"net"
	"sync"
	"time"
)

/*
limiter is a token bucket per key (a client IP, a user, or one global key):
rate tokens a second up to burst. It holds at most maxKeys buckets; when
full it forgets the buckets that have refilled (they equal a fresh one),
and if none has, it refuses a new key (fail closed: memory stays bounded).
*/
type limiter struct {
	rate, burst float64
	maxKeys     int
	now         func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	at     time.Time
}

func newLimiter(rate, burst float64, maxKeys int, now func() time.Time) *limiter {
	return &limiter{rate: rate, burst: burst, maxKeys: maxKeys, now: now, buckets: map[string]*bucket{}}
}

/* allow takes a token of key; if there is none it returns how long until one is there. */
func (l *limiter) allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			for k, o := range l.buckets {
				if o.refill(now, l.rate, l.burst) >= l.burst {
					delete(l.buckets, k)
				}
			}
			if len(l.buckets) >= l.maxKeys {
				return false, time.Second
			}
		}
		b = &bucket{tokens: l.burst, at: now}
		l.buckets[key] = b
	}
	if t := b.refill(now, l.rate, l.burst); t < 1 {
		return false, time.Duration(math.Ceil((1-t)/l.rate*1e3)) * time.Millisecond
	}
	b.tokens--
	return true, 0
}

/* refill adds the tokens earned since the bucket was last seen and returns them. */
func (b *bucket) refill(now time.Time, rate, burst float64) float64 {
	if d := now.Sub(b.at).Seconds(); d > 0 {
		b.tokens = math.Min(burst, b.tokens+d*rate)
		b.at = now
	}
	return b.tokens
}

/* limitListener accepts at most n connections at once: the next Accept waits until one closes. */
func limitListener(ln net.Listener, n int) net.Listener {
	return &capListener{Listener: ln, sem: make(chan struct{}, n), done: make(chan struct{})}
}

type capListener struct {
	net.Listener
	sem  chan struct{}
	done chan struct{}
	once sync.Once
}

func (l *capListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

func (l *capListener) Accept() (net.Conn, error) {
	select {
	case l.sem <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitedConn{Conn: c, release: func() { <-l.sem }}, nil
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
