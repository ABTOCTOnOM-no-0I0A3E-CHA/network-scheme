package triggers_test

import (
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/notify"
)

func TestAvailabilityDurationAndFlapping(t *testing.T) {
	h := newHarness(t)
	dev := h.newDevice()
	trig := h.newTrigger(h.group, "availability", `{"states":["down"]}`, 60, "high")
	t0 := h.clk.Now()

	h.setState(dev, "down", t0)
	h.step()
	if got := h.openProblems(dev); len(got) != 0 {
		t.Fatalf("opened before the duration elapsed: %+v", got)
	}
	h.advance(59 * time.Second)
	if got := h.openProblems(dev); len(got) != 0 {
		t.Fatalf("opened at 59 s: %+v", got)
	}
	h.advance(2 * time.Second)
	got := h.openProblems(dev)
	if len(got) != 1 || got[0].Trigger != trig || got[0].Object != "" || got[0].State != "problem" {
		t.Fatalf("want one problem for the trigger after 61 s, got %+v", got)
	}
	if ev := events(h.take()); ev[notify.EventOpened] != 1 {
		t.Fatalf("notifications after open: %v", ev)
	}

	/* A single up evaluation does not resolve; the state flapping back keeps the problem and resets the count. */
	h.setState(dev, "up", h.clk.Now())
	h.advance(5 * time.Second)
	if len(h.openProblems(dev)) != 1 {
		t.Fatal("resolved after one false evaluation")
	}
	h.setState(dev, "down", h.clk.Now())
	h.advance(5 * time.Second)
	h.setState(dev, "up", h.clk.Now())
	h.advance(5 * time.Second)
	if len(h.openProblems(dev)) != 1 {
		t.Fatal("false evaluations separated by a true one must not add up")
	}
	h.advance(5 * time.Second) /* second consecutive false evaluation */
	if len(h.openProblems(dev)) != 0 {
		t.Fatal("not resolved after two consecutive false evaluations")
	}
	all := h.problems(dev)
	if len(all) != 1 || all[0].State != "resolved" || all[0].Reason != "recovered" {
		t.Fatalf("resolved problem = %+v", all)
	}
	if ev := events(h.take()); ev[notify.EventResolved] != 1 || ev[notify.EventOpened] != 0 {
		t.Fatalf("notifications after resolve: %v", ev)
	}

	/* A new outage opens a new problem; steady evaluation never duplicates it. */
	h.setState(dev, "down", h.clk.Now())
	for range 4 {
		h.advance(30 * time.Second)
	}
	if got := h.openProblems(dev); len(got) != 1 {
		t.Fatalf("second outage: %+v", got)
	}
	if n := len(h.problems(dev)); n != 2 {
		t.Fatalf("problem rows = %d, want 2", n)
	}
}

func TestUnknownStateNeitherOpensNorResolves(t *testing.T) {
	h := newHarness(t)
	dev := h.newDevice()
	h.newTrigger(h.group, "availability", `{"states":["down"]}`, 0, "high")
	h.setState(dev, "down", h.clk.Now())
	h.step()
	if len(h.openProblems(dev)) != 1 {
		t.Fatal("down with duration 0 must open at once")
	}
	/* The poller goes silent: the view reports unknown, which must not recover the problem. */
	h.exec(h.root, `UPDATE inventory.poller_heartbeat SET at = now() - interval '5 minutes'`)
	for range 3 {
		h.advance(5 * time.Second)
	}
	if len(h.openProblems(dev)) != 1 {
		t.Fatal("unknown state resolved the problem")
	}
}

func TestPartialStateTriggerAndSeverity(t *testing.T) {
	h := newHarness(t)
	dev := h.newDevice()
	h.newTrigger(h.group, "availability", `{"states":["partial"]}`, 0, "average")
	h.setState(dev, "partial", h.clk.Now())
	h.step()
	got := h.problems(dev)
	if len(got) != 1 {
		t.Fatalf("problems = %+v", got)
	}
	var sev string
	if err := h.api.QueryRow(h.ctx, `SELECT severity FROM problems.problem WHERE id = $1`, got[0].ID).Scan(&sev); err != nil || sev != "average" {
		t.Fatalf("severity = %q, %v", sev, err)
	}
	h.setState(dev, "down", h.clk.Now()) /* down is not in the trigger's states: counts as false */
	h.advance(5 * time.Second)
	h.advance(5 * time.Second)
	if len(h.openProblems(dev)) != 0 {
		t.Fatal("partial problem should resolve when the state is no longer partial")
	}
}
