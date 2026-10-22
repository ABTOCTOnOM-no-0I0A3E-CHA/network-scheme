package eventd

import (
	"sync/atomic"
	"time"
)

/* kind selects the events table a row goes to. */
type kind uint8

const (
	kindSyslog kind = iota
	kindTrap
	kindStorm
)

/*
event is one row for the writer. Only the fields of its kind are set. Every
string was bounded by the parsers (or is built here), so the table CHECKs only
guard against bugs.
*/
type event struct {
	kind kind
	ts   time.Time
	dev  int64

	facility, severity int16 /* syslog */
	host, app, msg     string
	rawLen             int32

	version    int16 /* trap */
	trapOID    string
	name       string
	sev        string /* "" is stored as NULL */
	varbinds   []byte
	identified bool

	stormKind string /* storm: "syslog" or "trap" */
	count     int32
}

/*
queue is the bounded in-memory buffer between the receivers and the writer. It is
bounded twice: by the number of events and by their memory (cost). The bytes of
a batch stay reserved until the writer has finished it (release), so the budget
covers the batch in flight too.
*/
type queue struct {
	ch     chan event
	budget int64
	bytes  atomic.Int64
}

/* eventOverhead is the fixed memory charged per event on top of its variable parts (struct, slice headers, allocator slack). */
const eventOverhead = 256

/* cost is the memory an event holds while queued. */
func (e *event) cost() int64 {
	return int64(eventOverhead + len(e.host) + len(e.app) + len(e.msg) + len(e.trapOID) + len(e.name) + len(e.varbinds) + len(e.stormKind))
}

func newQueue(size int, budget int64) *queue {
	return &queue{ch: make(chan event, size), budget: budget}
}

/* push never blocks: it reports false when the queue is full by count or by bytes (the caller counts the drop). */
func (q *queue) push(e event) bool {
	c := e.cost()
	if q.bytes.Add(c) > q.budget {
		q.bytes.Add(-c)
		return false
	}
	select {
	case q.ch <- e:
		return true
	default:
		q.bytes.Add(-c)
		return false
	}
}

/* release returns the bytes of a batch the writer has finished with. */
func (q *queue) release(batch []event) {
	var c int64
	for i := range batch {
		c += batch[i].cost()
	}
	q.bytes.Add(-c)
}

/* usedBytes is the memory currently held by queued and in-flight events. */
func (q *queue) usedBytes() int64 { return q.bytes.Load() }

func (q *queue) depth() int { return len(q.ch) }

/* close ends the queue; the writer drains what is left. No push may follow. */
func (q *queue) close() { close(q.ch) }

/*
next returns up to size events: it waits for the first one, then collects until
size is reached or the interval since the first has passed. ok is false when the
queue is closed and empty.
*/
func (q *queue) next(size int, every time.Duration) (batch []event, ok bool) {
	first, open := <-q.ch
	if !open {
		return nil, false
	}
	batch = append(make([]event, 0, min(size, 1024)), first)
	timer := time.NewTimer(every)
	defer timer.Stop()
	for len(batch) < size {
		select {
		case e, open := <-q.ch:
			if !open {
				return batch, true
			}
			batch = append(batch, e)
		case <-timer.C:
			return batch, true
		}
	}
	return batch, true
}
