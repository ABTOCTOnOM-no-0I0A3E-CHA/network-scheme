package notify

import "sync"

/* subscriberBuffer is the per-subscriber queue; a subscriber that falls this far behind is dropped. */
const subscriberBuffer = 256

type subscriber struct {
	ch     chan Message
	filter func(ProblemSummary) bool
}

/*
Hub fans messages out to subscribers. Publish never blocks: a subscriber
whose buffer is full is removed and its channel closed, so a slow consumer
cannot delay the engine or the other subscribers.
*/
type Hub struct {
	mu   sync.Mutex
	subs map[*subscriber]struct{}
	buf  int
}

// NewHub returns an empty hub.
func NewHub() *Hub { return &Hub{subs: map[*subscriber]struct{}{}, buf: subscriberBuffer} }

/*
Publish offers m to every subscriber whose filter accepts its problem. A nil
Hub drops the message. Filters run under the hub lock and must be cheap and
must not call the hub.
*/
func (h *Hub) Publish(m Message) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs {
		if s.filter != nil && !s.filter(m.Problem) {
			continue
		}
		select {
		case s.ch <- m:
		default:
			delete(h.subs, s)
			close(s.ch)
		}
	}
}

/*
Subscribe registers a subscriber (a nil filter accepts everything). The
channel is closed when the subscriber is dropped for being slow or when
cancel is called; cancel is idempotent.
*/
func (h *Hub) Subscribe(filter func(ProblemSummary) bool) (msgs <-chan Message, cancel func()) {
	s := &subscriber{ch: make(chan Message, h.buf), filter: filter}
	h.mu.Lock()
	h.subs[s] = struct{}{}
	h.mu.Unlock()
	return s.ch, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if _, ok := h.subs[s]; ok {
			delete(h.subs, s)
			close(s.ch)
		}
	}
}
