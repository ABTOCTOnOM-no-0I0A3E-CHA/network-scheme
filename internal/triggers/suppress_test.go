package triggers_test

import (
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/notify"
)

func (h *harness) setStates(devs []int64, state string, since time.Time) {
	h.t.Helper()
	h.heartbeat("tp")
	h.exec(h.poller, `INSERT INTO inventory.device_status (device_id, state, since, last_poll_at, poller_id, last_error)
		SELECT d, $2, $3, $3, 'tp', '' FROM unnest($1::bigint[]) d
		ON CONFLICT (device_id) DO UPDATE SET state = $2, since = $3, last_poll_at = $3`, devs, state, since)
}

func byDevice(ps []prob) map[int64]prob {
	out := map[int64]prob{}
	for _, p := range ps {
		out[p.Device] = p
	}
	return out
}

func TestParentOutageSuppressesChildrenThenReleasesThem(t *testing.T) {
	h := newHarness(t)
	parent := h.newDevice()
	child := h.newDevice(withParent(parent))
	grandchild := h.newDevice(withParent(child))
	h.newTrigger(h.group, "availability", `{"states":["down"]}`, 0, "high")
	all := []int64{parent, child, grandchild}

	h.setStates(all, "down", h.clk.Now())
	h.step()
	ps := byDevice(h.openProblems(0))
	if len(ps) != 3 || ps[parent].Suppressed || !ps[child].Suppressed || !ps[grandchild].Suppressed {
		t.Fatalf("suppression = %+v", ps)
	}
	if ev := events(h.take()); ev[notify.EventOpened] != 1 || len(ev) != 1 {
		t.Fatalf("only the parent may notify: %v", ev)
	}

	/* The parent recovers; the child stays down: it is released with one suppressed_changed, not re-announced.
	   The grandchild is still behind the child's open availability problem. */
	h.setStates([]int64{parent}, "up", h.clk.Now())
	h.advance(5 * time.Second)
	h.advance(5 * time.Second)
	ps = byDevice(h.openProblems(0))
	if len(ps) != 2 || ps[child].Suppressed || !ps[grandchild].Suppressed {
		t.Fatalf("after the parent recovered: %+v", ps)
	}
	ev := events(h.take())
	if ev[notify.EventSuppressedChanged] != 1 || ev[notify.EventOpened] != 0 || ev[notify.EventResolved] != 1 {
		t.Fatalf("release notifications = %v, want 1 suppressed_changed + 1 resolved and no opened", ev)
	}
	/* Nothing more is said while the situation is stable. */
	h.advance(10 * time.Second)
	if ev := events(h.take()); len(ev) != 0 {
		t.Fatalf("repeated notifications: %v", ev)
	}
	/* The child recovers: its resolution is announced (it had been released) and the grandchild is released. */
	h.setStates([]int64{child}, "up", h.clk.Now())
	h.advance(5 * time.Second)
	h.advance(5 * time.Second)
	ev = events(h.take())
	if ev[notify.EventResolved] != 1 || ev[notify.EventSuppressedChanged] != 1 {
		t.Fatalf("second release: %v", ev)
	}
	if ps = byDevice(h.openProblems(0)); len(ps) != 1 || ps[grandchild].Suppressed {
		t.Fatalf("grandchild = %+v", ps)
	}
}

func TestSuppressedProblemResolvesQuietly(t *testing.T) {
	h := newHarness(t)
	parent := h.newDevice()
	child := h.newDevice(withParent(parent))
	h.newTrigger(h.group, "availability", `{"states":["down"]}`, 0, "high")
	h.setStates([]int64{parent, child}, "down", h.clk.Now())
	h.step()
	h.take()
	h.setStates([]int64{child}, "up", h.clk.Now())
	h.advance(5 * time.Second)
	h.advance(5 * time.Second)
	if p := byDevice(h.problems(0))[child]; p.State != "resolved" {
		t.Fatalf("child = %+v", p)
	}
	if ev := events(h.take()); len(ev) != 0 {
		t.Fatalf("a never-announced problem must not announce its resolution: %v", ev)
	}
}

func TestChildOpeningIsHeldWhileTheParentOutageIsPending(t *testing.T) {
	h := newHarness(t)
	parent := h.newDevice()
	child := h.newDevice(withParent(parent))
	h.newTrigger(h.group, "availability", `{"states":["down"]}`, 30, "high")
	t0 := h.clk.Now()
	h.setStates([]int64{child}, "down", t0.Add(-35*time.Second)) /* its own timer is already over */
	h.setStates([]int64{parent}, "down", t0)
	h.step()
	if ps := h.problems(0); len(ps) != 0 {
		t.Fatalf("the child opened while the parent's outage is pending: %+v", ps)
	}
	h.advance(31 * time.Second)
	ps := byDevice(h.openProblems(0))
	if len(ps) != 2 || !ps[child].Suppressed || ps[parent].Suppressed {
		t.Fatalf("after the parent opened: %+v", ps)
	}
	if ev := events(h.take()); ev[notify.EventOpened] != 1 || len(ev) != 1 {
		t.Fatalf("notifications = %v, want only the parent's opened", ev)
	}
}

func TestPendingParentThatRecoversReleasesTheChild(t *testing.T) {
	h := newHarness(t)
	parent := h.newDevice()
	child := h.newDevice(withParent(parent))
	h.newTrigger(h.group, "availability", `{"states":["down"]}`, 30, "high")
	t0 := h.clk.Now()
	h.setStates([]int64{child}, "down", t0.Add(-35*time.Second))
	h.setStates([]int64{parent}, "down", t0)
	h.step()
	h.setStates([]int64{parent}, "up", h.clk.Now()) /* the blip is over before the duration */
	h.advance(5 * time.Second)
	ps := byDevice(h.openProblems(0))
	if len(ps) != 1 || ps[child].Suppressed {
		t.Fatalf("child after the parent recovered: %+v", ps)
	}
	if ev := events(h.take()); ev[notify.EventOpened] != 1 {
		t.Fatalf("notifications = %v", ev)
	}
}

func TestChildThatOpenedBeforeTheParentFailedIsSuppressedRetroactively(t *testing.T) {
	h := newHarness(t)
	parent := h.newDevice()
	child := h.newDevice(withParent(parent))
	h.newTrigger(h.group, "availability", `{"states":["down"]}`, 30, "high")
	t0 := h.clk.Now()
	h.setStates([]int64{child}, "down", t0.Add(-35*time.Second))
	h.setStates([]int64{parent}, "up", t0)
	h.step()
	if ps := byDevice(h.openProblems(0)); len(ps) != 1 || ps[child].Suppressed {
		t.Fatalf("child alone: %+v", ps)
	}
	h.take()
	h.setStates([]int64{parent}, "down", h.clk.Now())
	h.advance(31 * time.Second)
	ps := byDevice(h.openProblems(0))
	if len(ps) != 2 || !ps[child].Suppressed || ps[parent].Suppressed {
		t.Fatalf("after the parent opened: %+v", ps)
	}
	ev := events(h.take())
	if ev[notify.EventOpened] != 1 || ev[notify.EventSuppressedChanged] != 1 {
		t.Fatalf("notifications = %v", ev)
	}
}

/* TestStaggeredStormNeverNotifiesForChildren: children whose timers end before and after the parent's. */
func TestStaggeredStormNeverNotifiesForChildren(t *testing.T) {
	h := newHarness(t)
	parent := h.newDevice()
	h.newTrigger(h.group, "availability", `{"states":["down"]}`, 60, "high")
	kids := make([]int64, 500)
	for i := range kids {
		kids[i] = h.newDevice(withParent(parent))
	}
	t0 := h.clk.Now()
	h.setStates([]int64{parent}, "down", t0)
	for i, k := range kids { /* since spread over [-40 s, +40 s] around the parent's */
		h.setStates([]int64{k}, "down", t0.Add(time.Duration(i*80/len(kids)-40)*time.Second))
	}
	h.step()
	for range 30 { /* 150 s in 5 s rounds: every child timer ends, some before and some after the parent's */
		h.advance(5 * time.Second)
	}
	ps := h.openProblems(0)
	suppressed := 0
	for _, p := range ps {
		if p.Suppressed {
			suppressed++
		}
	}
	if len(ps) != 501 || suppressed != 500 {
		t.Fatalf("problems = %d, suppressed = %d", len(ps), suppressed)
	}
	var childEv, parentEv int
	for _, m := range h.take() {
		if m.Event != notify.EventOpened {
			t.Fatalf("unexpected event %v", m.Event)
		}
		if m.Problem.DeviceID != nil && *m.Problem.DeviceID == parent {
			parentEv++
		} else {
			childEv++
		}
	}
	if childEv != 0 || parentEv != 1 {
		t.Fatalf("opened notifications: children %d, parent %d, want 0 and 1", childEv, parentEv)
	}
}

func TestPartialParentStillSuppressesNothingWithoutAvailabilityProblem(t *testing.T) {
	h := newHarness(t)
	parent := h.newDevice()
	child := h.newDevice(withParent(parent))
	h.newTrigger(h.group, "availability", `{"states":["down"]}`, 0, "high")
	h.setStates([]int64{parent}, "up", h.clk.Now())
	h.setStates([]int64{child}, "down", h.clk.Now())
	h.step()
	if ps := byDevice(h.openProblems(0)); len(ps) != 1 || ps[child].Suppressed {
		t.Fatalf("a healthy parent must not suppress: %+v", ps)
	}
}

func TestMaintenanceWindowSuppressesGroupAndSubgroups(t *testing.T) {
	h := newHarness(t)
	sub := h.newGroup(&h.group)
	other := h.newGroup(nil)
	inGrp := h.newDevice()
	inSub := h.newDevice(inGroup(sub))
	outside := h.newDevice(inGroup(other))
	h.newTrigger(h.group, "availability", `{"states":["down"]}`, 0, "high")
	h.newTrigger(other, "availability", `{"states":["down"]}`, 0, "high")

	now := h.clk.Now()
	h.exec(h.api, `INSERT INTO core.maintenance_window (group_id, starts_at, ends_at, comment) VALUES ($1, $2, $3, 'test')`,
		h.group, now.Add(-time.Minute), now.Add(10*time.Minute))
	h.setStates([]int64{inGrp, inSub, outside}, "down", now)
	h.step()
	ps := byDevice(h.openProblems(0))
	if len(ps) != 3 || !ps[inGrp].Suppressed || !ps[inSub].Suppressed || ps[outside].Suppressed {
		t.Fatalf("window suppression = %+v", ps)
	}
	if ev := events(h.take()); ev[notify.EventOpened] != 1 {
		t.Fatalf("only the device outside the window may notify: %v", ev)
	}
	/* The window ends: the two are released with one suppressed_changed each. */
	h.advance(11 * time.Minute)
	ps = byDevice(h.openProblems(0))
	if ps[inGrp].Suppressed || ps[inSub].Suppressed {
		t.Fatalf("still suppressed after the window: %+v", ps)
	}
	if ev := events(h.take()); ev[notify.EventSuppressedChanged] != 2 || ev[notify.EventOpened] != 0 {
		t.Fatalf("release notifications = %v", ev)
	}
}

func TestProblemOlderThanTheWindowIsNotHidden(t *testing.T) {
	h := newHarness(t)
	dev := h.newDevice()
	h.newTrigger(h.group, "availability", `{"states":["down"]}`, 0, "high")
	h.setStates([]int64{dev}, "down", h.clk.Now())
	h.step()
	h.take()
	now := h.clk.Now()
	h.exec(h.api, `INSERT INTO core.maintenance_window (group_id, starts_at, ends_at) VALUES ($1, $2, $3)`, h.group, now.Add(time.Minute), now.Add(time.Hour))
	h.advance(2 * time.Minute)
	if p := byDevice(h.openProblems(0))[dev]; p.Suppressed {
		t.Fatal("a window that started after the problem hid it")
	}
}

/* TestOutageStorm: 500 children behind one dead parent - one notification, one transaction, no dropped subscriber on release. */
func TestOutageStorm(t *testing.T) {
	h := newHarness(t)
	parent := h.newDevice()
	h.newTrigger(h.group, "availability", `{"states":["down"]}`, 0, "high")
	kids := make([]int64, 500)
	for i := range kids {
		kids[i] = h.newDevice(withParent(parent))
	}
	h.setStates(append([]int64{parent}, kids...), "down", h.clk.Now())
	start := time.Now()
	h.step()
	t.Logf("storm round with 501 new problems: %v", time.Since(start))
	ps := h.openProblems(0)
	suppressed := 0
	for _, p := range ps {
		if p.Suppressed {
			suppressed++
		}
	}
	if len(ps) != 501 || suppressed != 500 {
		t.Fatalf("problems = %d, suppressed = %d", len(ps), suppressed)
	}
	if ev := events(h.take()); ev[notify.EventOpened] != 1 || len(ev) != 1 {
		t.Fatalf("storm notifications = %v, want exactly one opened", ev)
	}

	h.setStates([]int64{parent}, "up", h.clk.Now())
	h.advance(5 * time.Second)
	h.advance(5 * time.Second)
	deadline := time.Now().Add(5 * time.Second)
	var ev map[notify.ProblemEvent]int
	got := 0
	for time.Now().Before(deadline) && got < 500 {
		for k, v := range events(h.take()) {
			if ev == nil {
				ev = map[notify.ProblemEvent]int{}
			}
			ev[k] += v
		}
		got = ev[notify.EventSuppressedChanged]
	}
	if ev[notify.EventSuppressedChanged] != 500 || ev[notify.EventResolved] != 1 || ev[notify.EventOpened] != 0 {
		t.Fatalf("release notifications = %v, want 500 suppressed_changed + 1 resolved", ev)
	}
}
