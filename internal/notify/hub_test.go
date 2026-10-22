package notify

import (
	"context"
	"testing"
	"time"
)

func msg(id int64, group int64) Message {
	return Message{Type: MessageTypeProblem, Event: EventOpened, Problem: ProblemSummary{ID: id, GroupID: &group}}
}

func TestHubFiltersBySubscriber(t *testing.T) {
	h := NewHub()
	a, cancelA := h.Subscribe(func(p ProblemSummary) bool { return *p.GroupID == 1 })
	defer cancelA()
	all, cancelAll := h.Subscribe(nil)
	defer cancelAll()
	h.Publish(msg(1, 1))
	h.Publish(msg(2, 2))
	if m := <-a; m.Problem.ID != 1 {
		t.Fatalf("filtered subscriber got problem %d, want 1", m.Problem.ID)
	}
	if len(a) != 0 {
		t.Fatal("filtered subscriber received a foreign problem")
	}
	if len(all) != 2 {
		t.Fatalf("unfiltered subscriber has %d messages, want 2", len(all))
	}
}

func TestHubDropsSlowSubscriberWithoutBlocking(t *testing.T) {
	h := NewHub()
	slow, _ := h.Subscribe(nil)
	fast, cancel := h.Subscribe(nil)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 3 * subscriberBuffer {
			h.Publish(msg(int64(i), 1))
			select { /* the fast subscriber keeps up */
			case <-fast:
			default:
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Publish blocked on a slow subscriber")
	}
	n := 0
	for range slow { /* closed once dropped, after its buffered messages */
		n++
	}
	if n != subscriberBuffer {
		t.Fatalf("slow subscriber drained %d messages, want %d", n, subscriberBuffer)
	}
	h.Publish(msg(9999, 1))
	if m := <-fast; m.Problem.ID != 9999 {
		t.Fatalf("fast subscriber got %d, want 9999", m.Problem.ID)
	}
}

func TestHubCancelIsIdempotent(t *testing.T) {
	h := NewHub()
	ch, cancel := h.Subscribe(nil)
	cancel()
	cancel()
	if _, ok := <-ch; ok {
		t.Fatal("channel not closed by cancel")
	}
	h.Publish(msg(1, 1)) /* no subscribers, no panic */
	var nilHub *Hub
	nilHub.Publish(msg(1, 1))
}

func TestPanelChannelPublishesToHub(t *testing.T) {
	h := NewHub()
	ch, cancel := h.Subscribe(nil)
	defer cancel()
	var c Channel = Panel{Hub: h}
	if c.Name() != "panel" {
		t.Fatalf("name = %q", c.Name())
	}
	if err := c.Deliver(context.Background(), Message{Event: EventResolved, Problem: ProblemSummary{ID: 7}}); err != nil {
		t.Fatal(err)
	}
	m := <-ch
	if m.Type != MessageTypeProblem || m.Event != EventResolved || m.Problem.ID != 7 {
		t.Fatalf("message = %+v", m)
	}
}
