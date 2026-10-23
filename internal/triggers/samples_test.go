package triggers_test

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestInterfaceOperDownDurationAndRecovery(t *testing.T) {
	h := newHarness(t)
	dev := h.newDevice()
	trig := h.newTrigger(h.group, "if_oper_down", `{}`, 30, "average")
	t0 := h.clk.Now()
	h.exec(h.poller, `INSERT INTO inventory.interface (device_id, if_index, name, alias, speed_bps, oper_up, seen_at) VALUES ($1, 7, 'ge1/0/7', '', 1000000000, true, $2)`, dev, t0)

	/* Duration counts on the sample timestamps: down at +0 and +20 s is not yet 30 s. */
	h.writeIf(dev, 7, t0.Add(-5*time.Second), true)
	h.writeIf(dev, 7, t0, false)
	h.step()
	h.clk.Advance(20 * time.Second)
	h.writeIf(dev, 7, h.clk.Now(), false)
	h.step()
	if len(h.openProblems(dev)) != 0 {
		t.Fatalf("opened after 20 s of data: %+v", h.openProblems(dev))
	}
	h.clk.Advance(20 * time.Second)
	h.writeIf(dev, 7, h.clk.Now(), false)
	h.step()
	got := h.openProblems(dev)
	if len(got) != 1 || got[0].Trigger != trig || got[0].Object != "if:7" {
		t.Fatalf("want one problem for if:7, got %+v", got)
	}
	if got[0].Value != "ge1/0/7: oper down" {
		t.Fatalf("last_value = %q", got[0].Value)
	}

	/* Re-reading the overlapping window and a stale device (no new samples) changes nothing. */
	for range 3 {
		h.advance(10 * time.Second)
	}
	if len(h.problems(dev)) != 1 || len(h.openProblems(dev)) != 1 {
		t.Fatalf("stale data changed the problems: %+v", h.problems(dev))
	}

	/* Two up samples recover it; one is not enough. */
	h.writeIf(dev, 7, h.clk.Now(), true)
	h.advance(10 * time.Second)
	if len(h.openProblems(dev)) != 1 {
		t.Fatal("resolved after a single up sample")
	}
	h.writeIf(dev, 7, h.clk.Now(), true)
	h.advance(10 * time.Second)
	if len(h.openProblems(dev)) != 0 {
		t.Fatal("not resolved after two up samples")
	}
}

func TestInterfaceTriggerIfIndexFilter(t *testing.T) {
	h := newHarness(t)
	dev := h.newDevice()
	h.newTrigger(h.group, "if_oper_down", `{"if_index":3}`, 0, "high")
	t0 := h.clk.Now()
	h.writeIf(dev, 2, t0, false)
	h.writeIf(dev, 3, t0, false)
	h.step()
	got := h.openProblems(dev)
	if len(got) != 1 || got[0].Object != "if:3" {
		t.Fatalf("problems = %+v", got)
	}
}

func TestMetricThresholds(t *testing.T) {
	h := newHarness(t)
	dev := h.newDevice()
	cpu := h.newTrigger(h.group, "metric_threshold", `{"metric":"cpu","op":"gt","value":90}`, 20, "warning")
	util := h.newTrigger(h.group, "metric_threshold", `{"metric":"if_util_in","op":"gt","value":80}`, 0, "high")
	t0 := h.clk.Now()

	h.writeCPU(dev, t0, 95)
	h.writeIfRates(dev, 4, t0, 900_000_000) /* 90 % of 1 Gb/s */
	h.step()
	got := h.openProblems(dev)
	if len(got) != 1 || got[0].Trigger != util || got[0].Object != "if:4" {
		t.Fatalf("only the utilisation trigger (duration 0) should be open: %+v", got)
	}
	h.clk.Advance(10 * time.Second)
	h.writeCPU(dev, h.clk.Now(), 96)
	h.step()
	if len(h.openProblems(dev)) != 1 {
		t.Fatal("cpu opened after 10 s of a 20 s duration")
	}
	h.clk.Advance(15 * time.Second)
	h.writeCPU(dev, h.clk.Now(), 97)
	h.step()
	opened := map[int64]bool{}
	for _, p := range h.openProblems(dev) {
		opened[p.Trigger] = true
	}
	if !opened[cpu] || !opened[util] {
		t.Fatalf("open triggers = %v, want cpu and utilisation", opened)
	}
	/* cpu drops: two low samples resolve it; the utilisation problem has no new samples and stays. */
	h.clk.Advance(5 * time.Second)
	h.writeCPU(dev, h.clk.Now(), 20)
	h.step()
	h.clk.Advance(5 * time.Second)
	h.writeCPU(dev, h.clk.Now(), 21)
	h.step()
	left := h.openProblems(dev)
	if len(left) != 1 || left[0].Trigger != util {
		t.Fatalf("after cpu recovery: %+v", left)
	}
}

func TestTrapOpensAtOnceAndLinkUpCloses(t *testing.T) {
	h := newHarness(t)
	dev := h.newDevice()
	trig := h.newTrigger(h.group, "trap", `{"name":"linkDown"}`, 0, "average")
	t0 := h.clk.Now()
	polled := map[int64]int{}
	h.eng = h.newEngine(func(_ context.Context, id int64) error { polled[id]++; return nil })

	h.writeTrap(dev, t0, "linkDown", 12)
	h.advance(6 * time.Second) /* eventSettle is 5 s */
	got := h.openProblems(dev)
	if len(got) != 1 || got[0].Trigger != trig || got[0].Object != "if:12" {
		t.Fatalf("linkDown trap: %+v", got)
	}
	if polled[dev] != 1 {
		t.Fatalf("extra polls requested = %d, want 1", polled[dev])
	}
	/* The same trap read again (a restart's overlap) or repeated does not duplicate. */
	h.advance(10 * time.Second)
	if len(h.problems(dev)) != 1 {
		t.Fatalf("duplicates: %+v", h.problems(dev))
	}
	/* A linkUp for another interface does not close it; the paired one does. */
	h.writeTrap(dev, h.clk.Now(), "linkUp", 13)
	h.advance(10 * time.Second)
	if len(h.openProblems(dev)) != 1 {
		t.Fatal("linkUp of if:13 closed the problem of if:12")
	}
	h.writeTrap(dev, h.clk.Now(), "linkUp", 12)
	h.advance(10 * time.Second)
	if len(h.openProblems(dev)) != 0 {
		t.Fatalf("linkUp did not close the problem: %+v", h.problems(dev))
	}
	if p := h.problems(dev); len(p) != 1 || p[0].Reason != "recovered" {
		t.Fatalf("problem = %+v", p)
	}
}

/* TestTrapAndPollAreOneProblem: FR-TRG-5 - the linkDown trap and the poll that sees the port down are one problem, closed by linkUp. */
func TestTrapAndPollAreOneProblem(t *testing.T) {
	h := newHarness(t)
	dev := h.newDevice()
	trig := h.newTrigger(h.group, "if_oper_down", `{}`, 0, "average")
	t0 := h.clk.Now()
	h.writeIf(dev, 5, t0.Add(-10*time.Second), true)

	h.writeTrap(dev, t0, "linkDown", 5)
	h.advance(6 * time.Second)
	if got := h.openProblems(dev); len(got) != 1 || got[0].Trigger != trig || got[0].Object != "if:5" {
		t.Fatalf("after the trap: %+v", got)
	}
	/* An older "up" poll (taken before the trap) must not close it, however often it is re-read. */
	for range 3 {
		h.advance(10 * time.Second)
	}
	if len(h.openProblems(dev)) != 1 {
		t.Fatal("a poll older than the trap resolved the problem")
	}
	/* The poll that confirms the port down adds nothing. */
	h.writeIf(dev, 5, h.clk.Now(), false)
	h.advance(10 * time.Second)
	if len(h.problems(dev)) != 1 {
		t.Fatalf("trap + poll produced %d problems", len(h.problems(dev)))
	}
	h.writeTrap(dev, h.clk.Now(), "linkUp", 5)
	h.advance(10 * time.Second)
	if len(h.openProblems(dev)) != 0 {
		t.Fatal("linkUp did not close the merged problem")
	}
	/* A poll that sees the port down again (after the linkUp) opens a fresh problem; the older down sample does not. */
	h.writeIf(dev, 5, h.clk.Now(), false)
	h.advance(10 * time.Second)
	if len(h.openProblems(dev)) != 1 || len(h.problems(dev)) != 2 {
		t.Fatalf("after a new down poll: %+v", h.problems(dev))
	}
}

func TestPollConfirmsRecoveryOfTrapProblem(t *testing.T) {
	h := newHarness(t)
	dev := h.newDevice()
	h.newTrigger(h.group, "trap", `{"name":"linkDown"}`, 0, "average")
	t0 := h.clk.Now()
	h.writeTrap(dev, t0, "linkDown", 9)
	h.advance(6 * time.Second)
	if len(h.openProblems(dev)) != 1 {
		t.Fatal("trap problem not open")
	}
	/* The linkUp trap is lost; two polls that see the interface up confirm the recovery. */
	h.clk.Advance(10 * time.Second)
	h.writeIf(dev, 9, h.clk.Now(), true)
	h.step()
	if len(h.openProblems(dev)) != 1 {
		t.Fatal("one up poll resolved it")
	}
	h.clk.Advance(10 * time.Second)
	h.writeIf(dev, 9, h.clk.Now(), true)
	h.step()
	if len(h.openProblems(dev)) != 0 {
		t.Fatal("polls confirming the port up did not resolve the trap problem")
	}
	/* And a down poll alone never opens a problem for a trap trigger. */
	h.writeIf(dev, 9, h.clk.Now(), false)
	h.advance(10 * time.Second)
	if len(h.openProblems(dev)) != 0 {
		t.Fatal("a poll opened a trap-trigger problem")
	}
}

func TestSyslogMatchingAndQuietExpiry(t *testing.T) {
	h := newHarness(t)
	dev := h.newDevice()
	trig := h.newTrigger(h.group, "syslog", `{"severity_min":3,"contains":"PoE Overload"}`, 120, "high")
	t0 := h.clk.Now()
	h.writeSyslog(dev, t0, 6, "poe overload on gi1")  /* too mild */
	h.writeSyslog(dev, t0, 3, "link flapping on gi2") /* no substring */
	h.advance(6 * time.Second)
	if len(h.problems(dev)) != 0 {
		t.Fatalf("non-matching syslog opened: %+v", h.problems(dev))
	}
	h.writeSyslog(dev, h.clk.Now(), 2, "PORT gi1: poe OVERLOAD detected") /* case-insensitive */
	h.advance(6 * time.Second)
	got := h.openProblems(dev)
	if len(got) != 1 || got[0].Trigger != trig || got[0].Value != "PORT gi1: poe OVERLOAD detected" {
		t.Fatalf("syslog: %+v", got)
	}
	/* A repeat keeps it open and does not duplicate; silence for the duration resolves it. */
	h.advance(60 * time.Second)
	h.writeSyslog(dev, h.clk.Now(), 2, "poe overload again")
	h.advance(60 * time.Second)
	h.advance(30 * time.Second)
	if len(h.openProblems(dev)) != 1 {
		t.Fatalf("expired while messages kept coming: %+v", h.problems(dev))
	}
	h.advance(90 * time.Second)
	if len(h.openProblems(dev)) != 0 {
		t.Fatal("did not resolve after the quiet period")
	}
	if p := h.problems(dev); len(p) != 1 || p[0].Reason != "recovered" {
		t.Fatalf("problems = %+v", p)
	}
}

func TestSyslogBadClockAndLongMessageAreBounded(t *testing.T) {
	h := newHarness(t)
	dev := h.newDevice()
	h.newTrigger(h.group, "syslog", `{"severity_min":7}`, 0, "info")
	long := ""
	for i := 0; i < 600; i++ {
		long += "x\u0007\n"
	}
	h.writeSyslog(dev, h.clk.Now(), 4, long)
	h.advance(6 * time.Second)
	got := h.openProblems(dev)
	if len(got) != 1 {
		t.Fatalf("problems = %+v", got)
	}
	if n := len([]rune(got[0].Value)); n > 200 {
		t.Fatalf("last_value has %d runes", n)
	}
	for _, r := range got[0].Value {
		if r < 0x20 {
			t.Fatalf("control character in last_value: %q", got[0].Value)
		}
	}
	/* A message dated in the future is processed when its time comes. */
	h.writeSyslog(dev, h.clk.Now().Add(30*time.Minute), 4, "from the future")
	h.advance(6 * time.Second)
	if len(h.problems(dev)) != 1 {
		t.Fatalf("future message processed early: %+v", h.problems(dev))
	}
}

/* TestSyslogFilterBeyondCapDoesNotAliasFirstFilter: a trigger whose filter was skipped at the cap must stay quiet instead of firing on filter 0's matches. */
func TestSyslogFilterBeyondCapDoesNotAliasFirstFilter(t *testing.T) {
	h := newHarness(t)
	dev := h.newDevice()
	for i := 0; i <= 256; i++ { /* one more distinct filter than the engine reads (maxSyslogFilters) */
		h.newTrigger(h.group, "syslog", fmt.Sprintf(`{"severity_min":7,"contains":"key-%03d"}`, i), 0, "info")
	}
	h.writeSyslog(dev, h.clk.Now(), 3, "key-000 happened")
	h.advance(6 * time.Second)
	got := h.openProblems(dev)
	if len(got) != 1 {
		t.Fatalf("problems = %+v, want only the trigger of the matching filter", got)
	}
}

/* TestUnusedPortsStayQuiet: "any interface" reports transitions only (R5). */
func TestUnusedPortsStayQuiet(t *testing.T) {
	h := newHarness(t)
	dev := h.newDevice()
	trig := h.newTrigger(h.group, "if_oper_down", `{}`, 0, "average")
	h.newTrigger(h.group, "trap", `{"name":"linkDown"}`, 0, "average")
	now := h.clk.Now()
	/* 24 ports: 20 never up; 4 up in the inventory. */
	for i := 1; i <= 4; i++ {
		h.exec(h.poller, `INSERT INTO inventory.interface (device_id, if_index, name, alias, speed_bps, oper_up, seen_at) VALUES ($1, $2, 'p', '', 1, true, now())`, dev, i)
	}
	for i := 1; i <= 24; i++ {
		h.writeIf(dev, i, now, i <= 4)
	}
	h.step()
	if got := h.openProblems(dev); len(got) != 0 {
		t.Fatalf("never-up ports opened problems: %+v", got)
	}
	/* A port that was up goes down: one problem. */
	h.clk.Advance(10 * time.Second)
	h.writeIf(dev, 2, h.clk.Now(), false)
	h.step()
	got := h.openProblems(dev)
	if len(got) != 1 || got[0].Trigger != trig || got[0].Object != "if:2" {
		t.Fatalf("up->down: %+v", got)
	}
	/* A linkDown trap for a never-seen port is a device-reported transition. */
	h.writeTrap(dev, h.clk.Now(), "linkDown", 9)
	h.advance(6 * time.Second)
	objs := map[string]bool{}
	for _, p := range h.openProblems(dev) {
		if p.Trigger == trig {
			objs[p.Object] = true
		}
	}
	if !objs["if:9"] || !objs["if:2"] || len(objs) != 2 {
		t.Fatalf("after the trap: %v", objs)
	}
}
