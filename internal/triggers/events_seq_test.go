package triggers_test

import (
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/notify"
	"github.com/beekamai/network-scheme/internal/triggers"
)

func (h *harness) syslogFlood(dev int64, n int, sev int, msg string) {
	h.t.Helper()
	h.exec(h.eventd, `INSERT INTO events.syslog (ts, device_id, facility, severity, host, app, msg, raw_len)
		SELECT $1::timestamptz + (i * interval '1 millisecond'), $2, 1, $3, 'h', 'a', $4 || i, 10 FROM generate_series(1, $5) i`,
		h.clk.Now(), dev, sev, msg, n)
}

func (h *harness) eventSeq(stream string) int64 {
	h.t.Helper()
	var s int64
	if err := h.root.QueryRow(h.ctx, `SELECT seq FROM problems.engine_state WHERE name = $1`, stream).Scan(&s); err != nil {
		h.t.Fatal(err)
	}
	return s
}

/* TestSyslogFloodDoesNotHideOtherDevices: 6000 matching rows from one device, then one from another, in a single round. */
func TestSyslogFloodDoesNotHideOtherDevices(t *testing.T) {
	h := newHarness(t)
	a, b := h.newDevice(), h.newDevice()
	h.newTrigger(h.group, "syslog", `{"severity_min":3}`, 0, "high")
	h.syslogFlood(a, 6000, 3, "storm ")
	h.writeSyslog(b, h.clk.Now(), 3, "the one that matters")
	start := time.Now()
	h.advance(time.Second)
	t.Logf("round with 6001 matching rows: %v", time.Since(start))
	if len(h.openProblems(a)) != 1 || len(h.openProblems(b)) != 1 {
		t.Fatalf("A: %+v, B: %+v", h.problems(a), h.problems(b))
	}
	if v := h.openProblems(b)[0].Value; v != "the one that matters" {
		t.Fatalf("B value = %q", v)
	}
	before := h.eventSeq("syslog")
	h.advance(5 * time.Second)
	if after := h.eventSeq("syslog"); after != before {
		t.Fatalf("position moved without new rows: %d -> %d", before, after)
	}
}

/* TestLateCommittedTrapIsEvaluated: a trap committed after the position moved, with a timestamp from the past, is still read. */
func TestLateCommittedTrapIsEvaluated(t *testing.T) {
	h := newHarness(t)
	dev := h.newDevice()
	trig := h.newTrigger(h.group, "trap", `{"name":"coldStart"}`, 0, "warning")
	for range 3 {
		h.advance(10 * time.Second)
	}
	h.writeTrap(dev, h.clk.Now().Add(-90*time.Second), "coldStart", 0) /* receipt time long before the commit */
	h.advance(time.Second)
	if got := h.openProblems(dev); len(got) != 1 || got[0].Trigger != trig {
		t.Fatalf("late trap not evaluated: %+v", h.problems(dev))
	}
}

/* TestFloodingDevicesDoNotDelayALinkDown: 50 devices flooding syslog and traps, one normal device's linkDown. */
func TestFloodingDevicesDoNotDelayALinkDown(t *testing.T) {
	h := newHarness(t)
	h.newTrigger(h.group, "syslog", `{"severity_min":7}`, 0, "info")
	ifTrig := h.newTrigger(h.group, "if_oper_down", `{}`, 0, "average")
	normal := h.newDevice()
	for range 50 {
		d := h.newDevice()
		h.syslogFlood(d, 2000, 4, "flood ")
		h.exec(h.eventd, `INSERT INTO events.trap (ts, device_id, version, trap_oid, name, severity, varbinds, identified)
			SELECT $1, $2, 2, '1.3.6.1.6.3.1.1.5.4', 'linkUp', 'info', '[{"oid":"1.3.6.1.2.1.2.2.1.1.1","type":"Integer","value":"1"}]', true FROM generate_series(1, 400)`, h.clk.Now(), d)
	}
	h.writeTrap(normal, h.clk.Now(), "linkDown", 4)
	start := time.Now()
	h.advance(time.Second)
	t.Logf("round with 100k syslog + 20k trap rows: %v", time.Since(start))
	got := h.openProblems(normal)
	var link bool
	for _, p := range got {
		link = link || (p.Trigger == ifTrig && p.Object == "if:4")
	}
	if !link {
		t.Fatalf("linkDown not turned into a problem in one round: %+v", got)
	}
}

/* TestEventPositionSurvivesRestartAndNeverRepeats: syslog and traps are neither lost nor replayed across engines. */
func TestEventPositionSurvivesRestartAndNeverRepeats(t *testing.T) {
	h := newHarness(t)
	dev := h.newDevice()
	sys := h.newTrigger(h.group, "syslog", `{"severity_min":3}`, 30, "high")
	h.writeSyslog(dev, h.clk.Now(), 2, "first")
	h.advance(time.Second)
	if len(h.openProblems(dev)) != 1 {
		t.Fatal("syslog problem not opened")
	}
	h.advance(40 * time.Second) /* quiet period over: resolved */
	if len(h.openProblems(dev)) != 0 {
		t.Fatalf("not expired: %+v", h.problems(dev))
	}
	pos := h.eventSeq("syslog")

	/* Restart: the same rows are not read again (a replay would reopen the problem), rows written meanwhile are. */
	h.eng = h.newEngine(nil)
	h.advance(5 * time.Second)
	if len(h.problems(dev)) != 1 || len(h.openProblems(dev)) != 0 {
		t.Fatalf("restart replayed an old message: %+v", h.problems(dev))
	}
	h.writeSyslog(dev, h.clk.Now().Add(-20*time.Hour), 2, "written while the engine was down; device clock far in the past")
	h.eng = h.newEngine(nil)
	h.advance(5 * time.Second)
	got := h.openProblems(dev)
	if len(got) != 1 || got[0].Trigger != sys || h.eventSeq("syslog") <= pos {
		t.Fatalf("message written during the restart was lost: %+v", h.problems(dev))
	}
}

/* TestEventPositionNeverRegressesAndCoversBacklogs: small ranges force several rounds; every row is read once. */
func TestEventPositionNeverRegressesAndCoversBacklogs(t *testing.T) {
	defer triggers.SetPaging(200_000, 10, 100, 2)()
	h := newHarness(t)
	var devs []int64
	for range 6 {
		devs = append(devs, h.newDevice())
	}
	h.newTrigger(h.group, "syslog", `{"severity_min":3}`, 0, "high")
	h.syslogFlood(devs[0], 450, 6, "noise ") /* does not match */
	for _, d := range devs[1:] {
		h.writeSyslog(d, h.clk.Now(), 3, "match")
	}
	last := h.eventSeq("syslog")
	rounds := 0
	for len(h.openProblems(0)) < 5 && rounds < 10 {
		h.advance(time.Second)
		rounds++
		if cur := h.eventSeq("syslog"); cur < last {
			t.Fatalf("position regressed: %d -> %d", last, cur)
		} else {
			last = cur
		}
	}
	if len(h.openProblems(0)) != 5 {
		t.Fatalf("problems = %d after %d rounds", len(h.openProblems(0)), rounds)
	}
	if rounds < 3 {
		t.Fatalf("backlog of 455 rows with 200-row cycles took %d rounds, expected several", rounds)
	}
}

func TestSampleBacklogIsPagedWithoutStalling(t *testing.T) {
	defer triggers.SetPaging(50, 2, 200_000, 4)()
	h := newHarness(t)
	h.newTrigger(h.group, "metric_threshold", `{"metric":"cpu","op":"gt","value":90}`, 0, "warning")
	base := h.clk.Now()
	for i := range 300 {
		d := h.newDevice()
		h.writeCPU(d, base.Add(-20*time.Second+time.Duration(i)*50*time.Millisecond), 99) /* all within the 45 s overlap */
	}
	h.advance(time.Second)
	rounds := 1
	for len(h.openProblems(0)) < 300 && rounds < 8 {
		h.advance(time.Second)
		rounds++
	}
	if n := len(h.openProblems(0)); n != 300 {
		t.Fatalf("problems = %d after %d rounds: the page limit stalled the stream", n, rounds)
	}
}

/* TestAnyInterfaceLearnsUpFromSamplesOfUnwatchedDevices: no inventory row; the port was only ever seen up in the metrics. */
func TestAnyInterfaceLearnsUpFromSamplesOfUnwatchedDevices(t *testing.T) {
	h := newHarness(t)
	dev := h.newDevice()
	h.newTrigger(h.group, "if_oper_down", `{}`, 0, "average")
	h.writeIf(dev, 4, h.clk.Now(), true)
	h.writeIf(dev, 5, h.clk.Now(), false) /* never up */
	h.advance(10 * time.Second)
	if len(h.openProblems(dev)) != 0 {
		t.Fatalf("problems = %+v", h.problems(dev))
	}
	h.writeIf(dev, 4, h.clk.Now(), false)
	h.writeIf(dev, 5, h.clk.Now(), false)
	h.advance(10 * time.Second)
	got := h.openProblems(dev)
	if len(got) != 1 || got[0].Object != "if:4" {
		t.Fatalf("up -> down: %+v", got)
	}
}

/* TestInventoryRowsWithOldTimestampsAreNotMissed: the inventory is re-read in full, whatever seen_at says. */
func TestInventoryRowsWithOldTimestampsAreNotMissed(t *testing.T) {
	h := newHarness(t)
	dev := h.newDevice()
	h.newTrigger(h.group, "if_oper_down", `{}`, 0, "average")
	h.advance(10 * time.Second) /* the first full inventory read happens here (empty) */
	h.exec(h.poller, `INSERT INTO inventory.interface (device_id, if_index, name, alias, speed_bps, oper_up, seen_at) VALUES ($1, 3, 'p3', '', 1, true, now() - interval '2 hours')`, dev)
	h.advance(6 * time.Minute) /* next full read */
	h.writeIf(dev, 3, h.clk.Now(), false)
	h.advance(10 * time.Second)
	if got := h.openProblems(dev); len(got) != 1 || got[0].Object != "if:3" {
		t.Fatalf("problems = %+v", h.problems(dev))
	}
}

/* TestRacingEnginesAnnounceOnce: the engine that loses the race to resolve a problem says nothing. */
func TestRacingEnginesAnnounceOnce(t *testing.T) {
	h := newHarness(t)
	dev := h.newDevice()
	parent := h.newDevice()
	h.newTrigger(h.group, "availability", `{"states":["down"]}`, 0, "high")
	h.setStates([]int64{dev, parent}, "down", h.clk.Now())
	h.step()
	h.take()
	h.setStates([]int64{dev}, "up", h.clk.Now())
	h.advance(5 * time.Second) /* first false evaluation of the main engine */
	rival := h.newEngine(nil)
	if err := rival.StepAll(h.ctx); err != nil { /* and of the rival */
		t.Fatal(err)
	}
	loser := h.eng
	fired := false
	loser.AfterLoad(func() {
		if fired {
			return
		}
		fired = true
		/* The rival resolves the problem between the loser's load and its write. */
		if err := rival.StepAll(h.ctx); err != nil {
			t.Error(err)
		}
	})
	h.clk.Advance(5 * time.Second)
	h.step()
	if open := h.openProblems(dev); len(open) != 0 {
		t.Fatalf("still open: %+v", open)
	}
	if ev := events(h.take()); ev[notify.EventResolved] != 1 {
		t.Fatalf("resolved announced %d times, want exactly once", ev[notify.EventResolved])
	}
}

/* TestSeenUpRespectsTimeOrder: a down sample that precedes the port's first up sample is not a transition. */
func TestSeenUpRespectsTimeOrder(t *testing.T) {
	h := newHarness(t)
	dev := h.newDevice()
	h.newTrigger(h.group, "if_oper_down", `{}`, 0, "average")
	now := h.clk.Now()
	h.writeIf(dev, 6, now.Add(-10*time.Second), false) /* an unused port that later came up */
	h.writeIf(dev, 6, now.Add(-5*time.Second), true)
	h.advance(time.Second)
	if len(h.problems(dev)) != 0 {
		t.Fatalf("problems = %+v", h.problems(dev))
	}
	h.writeIf(dev, 6, h.clk.Now(), false)
	h.advance(5 * time.Second)
	if got := h.openProblems(dev); len(got) != 1 || got[0].Object != "if:6" {
		t.Fatalf("up -> down: %+v", h.problems(dev))
	}
}
