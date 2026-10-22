package triggers_test

import (
	"context"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/notify"
	"github.com/beekamai/network-scheme/internal/triggers"
)

/* TestRestartKeepsProblemsAndWatermark: a new engine continues where the old one stopped - no duplicates, no lost or replayed events. */
func TestRestartKeepsProblemsAndWatermark(t *testing.T) {
	h := newHarness(t)
	dev := h.newDevice()
	trig := h.newTrigger(h.group, "trap", `{"name":"linkDown"}`, 0, "average")
	avail := h.newTrigger(h.group, "availability", `{"states":["down"]}`, 0, "high")
	h.setStates([]int64{dev}, "down", h.clk.Now())

	h.writeTrap(dev, h.clk.Now(), "linkDown", 1)
	h.advance(6 * time.Second)
	if len(h.openProblems(dev)) != 2 {
		t.Fatalf("setup: %+v", h.problems(dev))
	}
	h.take()

	/* The engine is gone; during the outage interface 1 comes back and interface 2 goes down. */
	h.clk.Advance(20 * time.Second)
	h.writeTrap(dev, h.clk.Now(), "linkUp", 1)
	h.clk.Advance(time.Second)
	h.writeTrap(dev, h.clk.Now(), "linkDown", 2)
	h.clk.Advance(30 * time.Second)

	h.eng = h.newEngine(nil)
	h.step()
	byObj := map[string]prob{}
	open := 0
	for _, p := range h.problems(dev) {
		if p.Trigger == trig {
			byObj[p.Object] = p
		}
		if p.State != "resolved" {
			open++
		}
	}
	if byObj["if:1"].State != "resolved" || byObj["if:2"].State != "problem" || open != 2 || len(h.problems(dev)) != 3 {
		t.Fatalf("after restart: %+v", h.problems(dev))
	}
	ev := events(h.take())
	if ev[notify.EventOpened] != 1 || ev[notify.EventResolved] != 1 {
		t.Fatalf("restart notifications = %v, want one opened (if:2) and one resolved (if:1)", ev)
	}

	/* A second restart with nothing new changes and says nothing: already processed events are not replayed. */
	h.eng = h.newEngine(nil)
	h.advance(10 * time.Second)
	if len(h.problems(dev)) != 3 {
		t.Fatalf("second restart duplicated problems: %+v", h.problems(dev))
	}
	if ev := events(h.take()); len(ev) != 0 {
		t.Fatalf("second restart notified: %v", ev)
	}
	/* The availability problem stayed single through both restarts. */
	n := 0
	for _, p := range h.problems(dev) {
		if p.Trigger == avail {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("availability problems = %d", n)
	}
}

/* TestTwoEnginesNeverDuplicate: even if two engines evaluate the same data (the advisory lock failed), the open-key index admits one problem. */
func TestTwoEnginesNeverDuplicate(t *testing.T) {
	h := newHarness(t)
	dev := h.newDevice()
	h.newTrigger(h.group, "availability", `{"states":["down"]}`, 0, "high")
	h.setStates([]int64{dev}, "down", h.clk.Now())
	other := h.newEngine(nil)
	for range 3 {
		h.step()
		if err := other.StepAll(h.ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(h.problems(dev)); n != 1 {
		t.Fatalf("problems = %d, want 1", n)
	}
}

func TestEngineHoldsAnAdvisoryLock(t *testing.T) {
	h := newHarness(t)
	held := func() int {
		var n int
		err := h.root.QueryRow(h.ctx, `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted AND (classid::bigint << 32 | objid::bigint) = $1`, int64(triggers.LockKey)).Scan(&n)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	wait := func(want int) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			if held() == want {
				return
			}
		}
		t.Fatalf("advisory lock holders = %d, want %d", held(), want)
	}
	ctx1, cancel1 := context.WithCancel(h.ctx)
	done1 := make(chan struct{})
	go func() { _ = h.newEngine(nil).Run(ctx1); close(done1) }()
	wait(1)
	ctx2, cancel2 := context.WithCancel(h.ctx)
	done2 := make(chan struct{})
	go func() { _ = h.newEngine(nil).Run(ctx2); close(done2) }()
	time.Sleep(500 * time.Millisecond)
	if held() != 1 {
		t.Fatalf("second engine got the lock: holders = %d", held())
	}
	cancel1()
	<-done1
	wait(0)
	cancel2()
	<-done2
}

func TestRemovedDevicesAndTriggersResolveTheirProblems(t *testing.T) {
	h := newHarness(t)
	gone := h.newDevice()
	disabled := h.newDevice()
	overridden := h.newDevice()
	moved := h.newDevice()
	staying := h.newDevice()
	elsewhere := h.newGroup(nil)
	availTrig := h.newTrigger(h.group, "availability", `{"states":["down"]}`, 0, "high")
	ifTrig := h.newTrigger(h.group, "if_oper_down", `{}`, 0, "average")
	all := []int64{gone, disabled, overridden, moved, staying}
	h.setStates(all, "down", h.clk.Now())
	for _, d := range all {
		h.exec(h.poller, `INSERT INTO inventory.interface (device_id, if_index, name, alias, speed_bps, oper_up, seen_at) VALUES ($1, 3, 'p3', '', 1, true, now())`, d)
		h.writeIf(d, 3, h.clk.Now(), false)
	}
	h.step()
	if n := len(h.openProblems(0)); n != 10 {
		t.Fatalf("setup problems = %d, want 10", n)
	}

	h.exec(h.api, `DELETE FROM core.device WHERE id = $1`, gone)
	h.exec(h.api, `INSERT INTO core.trigger_override (trigger_id, device_id, enabled) VALUES ($1, $2, false)`, ifTrig, overridden)
	h.exec(h.api, `UPDATE core.device SET group_id = $2 WHERE id = $1`, moved, elsewhere)
	h.advance(time.Second)
	for _, p := range h.problems(0) {
		switch {
		case p.Device == gone, p.Device == moved, p.Device == overridden && p.Trigger == ifTrig:
			if p.State != "resolved" || p.Reason != "removed" {
				t.Errorf("problem %+v should be resolved as removed", p)
			}
		default:
			if p.State == "resolved" {
				t.Errorf("problem %+v must stay open", p)
			}
		}
	}
	/* Deleting a trigger (through its template) and disabling one resolve the rest of theirs. */
	h.exec(h.api, `UPDATE core.trigger SET enabled = false WHERE id = $1`, ifTrig)
	h.exec(h.api, `DELETE FROM core.monitoring_template WHERE id = (SELECT template_id FROM core.trigger WHERE id = $1)`, availTrig)
	h.advance(time.Second)
	if open := h.openProblems(0); len(open) != 0 {
		t.Fatalf("open after the triggers went away: %+v", open)
	}
	_ = disabled
	_ = staying
}

func TestEffectiveTriggersAndOverrides(t *testing.T) {
	h := newHarness(t)
	sub := h.newGroup(&h.group)
	devTop := h.newDevice()
	devSub := h.newDevice(inGroup(sub))
	devOtherDriver := h.newDevice(withDriver("other-driver"))

	/* A trigger on the parent group reaches the subgroup's devices; a driver template reaches only that driver. */
	groupTrig := h.newTrigger(h.group, "availability", `{"states":["down"]}`, 0, "high")
	var tpl, driverTrig int64
	if err := h.api.QueryRow(h.ctx, `INSERT INTO core.monitoring_template (name, driver) VALUES ('T:driver', $1) RETURNING id`, testDriver).Scan(&tpl); err != nil {
		t.Fatal(err)
	}
	if err := h.api.QueryRow(h.ctx, `INSERT INTO core.trigger (template_id, kind, params, severity, name) VALUES ($1, 'availability', '{"states":["partial"]}', 'warning', 'driver') RETURNING id`, tpl).Scan(&driverTrig); err != nil {
		t.Fatal(err)
	}
	/* An override can change severity and params of one device. */
	h.exec(h.api, `INSERT INTO core.trigger_override (trigger_id, device_id, params, severity) VALUES ($1, $2, '{"states":["down","partial"]}', 'disaster')`, groupTrig, devSub)

	h.setStates([]int64{devTop, devSub, devOtherDriver}, "down", h.clk.Now())
	h.step()
	type key struct{ dev, trig int64 }
	got := map[key]string{}
	for _, p := range h.problems(0) {
		var sev string
		if err := h.api.QueryRow(h.ctx, `SELECT severity FROM problems.problem WHERE id = $1`, p.ID).Scan(&sev); err != nil {
			t.Fatal(err)
		}
		got[key{p.Device, p.Trigger}] = sev
	}
	want := map[key]string{{devTop, groupTrig}: "high", {devSub, groupTrig}: "disaster", {devOtherDriver, groupTrig}: "high"}
	if len(got) != len(want) {
		t.Fatalf("problems = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("problems = %v, want %v", got, want)
		}
	}
	/* The override's merged params now also match "partial". */
	h.setStates([]int64{devTop, devSub}, "partial", h.clk.Now())
	h.advance(5 * time.Second)
	h.advance(5 * time.Second)
	open := byDevice(h.openProblems(0))
	if _, ok := open[devSub]; !ok {
		t.Fatalf("override params ignored: %+v", h.problems(0))
	}
	for _, p := range h.openProblems(devTop) {
		if p.Trigger == groupTrig {
			t.Fatalf("devTop still has its group problem after leaving 'down': %+v", p)
		}
	}
	if p := h.openProblems(devTop); len(p) != 1 || p[0].Trigger != driverTrig {
		t.Fatalf("driver template trigger for devTop = %+v", p)
	}
}

/* TestInvalidStoredParamsAreSkipped: the engine re-validates what it loads and never trusts the database. */
func TestInvalidStoredParamsAreSkipped(t *testing.T) {
	h := newHarness(t)
	dev := h.newDevice()
	h.newTrigger(h.group, "availability", `{"states":["bogus"]}`, 0, "high")
	h.newTrigger(h.group, "metric_threshold", `{"metric":"cpu","op":"gt","value":900}`, 0, "high")
	h.newTrigger(h.group, "syslog", `{"severity_min":3,"extra":1}`, 0, "high")
	good := h.newTrigger(h.group, "availability", `{"states":["down"]}`, 0, "high")
	h.setStates([]int64{dev}, "down", h.clk.Now())
	h.step()
	if got := h.openProblems(dev); len(got) != 1 || got[0].Trigger != good {
		t.Fatalf("problems = %+v", got)
	}
}

func TestSystemProblems(t *testing.T) {
	h := newHarness(t)
	dev := h.newDevice(onPoller("px"))

	/* Poller without a heartbeat: its devices report unknown. */
	h.exec(h.poller, `INSERT INTO inventory.device_status (device_id, state, since, last_poll_at, poller_id) VALUES ($1, 'up', now(), now(), 'px')`, dev)
	h.exec(h.poller, `INSERT INTO inventory.poller_heartbeat (poller_id, at) VALUES ('px', now() - interval '5 minutes')`)
	h.step()
	sys := func() map[string]prob {
		out := map[string]prob{}
		for _, p := range h.openProblems(0) {
			if p.Sys != "" {
				out[p.Sys+"/"+p.Object] = p
			}
		}
		return out
	}
	got := sys()
	if p, ok := got["poller_unavailable/poller:px"]; !ok || p.Device != 0 {
		t.Fatalf("system problems = %+v", got)
	}
	if ev := events(h.take()); ev[notify.EventOpened] != 1 {
		t.Fatalf("notifications: %v", ev)
	}
	h.exec(h.poller, `UPDATE inventory.poller_heartbeat SET at = now() WHERE poller_id = 'px'`)
	h.advance(30 * time.Second)
	if len(sys()) != 1 {
		t.Fatal("resolved after one healthy evaluation")
	}
	h.advance(30 * time.Second)
	if len(sys()) != 0 {
		t.Fatalf("poller problem not resolved: %+v", sys())
	}

	/* Flood of packets from unknown sources: growth over 100 in 5 minutes; counter resets count from zero. */
	h.exec(h.eventd, `INSERT INTO events.eventd_stats (instance, updated_at, unknown_source) VALUES ('ev1', now(), 10)`)
	h.advance(30 * time.Second)
	h.exec(h.eventd, `UPDATE events.eventd_stats SET unknown_source = 90`)
	h.advance(30 * time.Second)
	if len(sys()) != 0 {
		t.Fatalf("flood below the limit: %+v", sys())
	}
	h.exec(h.eventd, `UPDATE events.eventd_stats SET unknown_source = 150`)
	h.advance(30 * time.Second)
	if _, ok := sys()["unknown_source/eventd"]; !ok {
		t.Fatalf("flood not reported: %+v", sys())
	}
	for range 12 { /* the counter stays flat for 6 minutes: the window empties */
		h.advance(30 * time.Second)
	}
	if len(sys()) != 0 {
		t.Fatalf("flood problem not resolved: %+v", sys())
	}
	h.exec(h.eventd, `UPDATE events.eventd_stats SET unknown_source = 40`) /* eventd restarted: 40 new, below the limit */
	h.advance(30 * time.Second)
	if len(sys()) != 0 {
		t.Fatalf("counter reset counted as growth: %+v", sys())
	}

	/* Access profile in status mismatch; removed with its device. */
	h.exec(h.api, `INSERT INTO core.access_profile (owner_kind, owner_id, kind, ciphertext, key_version, status) VALUES ('device', $1, 'snmp2c', '\x00', 1, 'mismatch')`, dev)
	h.advance(30 * time.Second)
	p, ok := sys()["access_profile_mismatch/profile:snmp2c"]
	if !ok || p.Device != dev {
		t.Fatalf("profile mismatch not reported: %+v", sys())
	}
	h.exec(h.poller, `UPDATE core.access_profile SET status = 'ok' WHERE owner_id = $1`, dev)
	h.advance(30 * time.Second)
	h.advance(30 * time.Second)
	if len(sys()) != 0 {
		t.Fatalf("profile problem not resolved: %+v", sys())
	}
	h.exec(h.poller, `UPDATE core.access_profile SET status = 'mismatch' WHERE owner_id = $1`, dev)
	h.advance(30 * time.Second)
	h.exec(h.api, `DELETE FROM core.device WHERE id = $1`, dev)
	h.advance(30 * time.Second)
	all := h.problems(dev)
	if last := all[len(all)-1]; last.Sys != "access_profile_mismatch" || last.State != "resolved" || last.Reason != "removed" {
		t.Fatalf("profile problem of a deleted device: %+v", all)
	}
}

/* TestEngineNeverTouchesDevices: the package cannot reach devices at all - it imports no SNMP, SSH or driver code. */
func TestEngineNeverTouchesDevices(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/beekamai/network-scheme/internal/triggers").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for _, dep := range strings.Fields(string(out)) {
		for _, bad := range []string{"network-scheme/internal/snmp", "network-scheme/internal/ssh", "network-scheme/internal/drivers",
			"network-scheme/cmd/", "gosnmp", "golang.org/x/crypto/ssh", "network-scheme/internal/jobs", "network-scheme/internal/poller"} {
			if strings.Contains(dep, bad) {
				t.Errorf("internal/triggers depends on %s", dep)
			}
		}
	}
}

/* Reload makes the running engine do a configuration round at once instead of waiting for the next 5 s tick. */
func TestReloadRunsARoundAtOnce(t *testing.T) {
	h := newHarness(t)
	var rounds atomic.Int64
	h.eng.AfterLoad(func() { rounds.Add(1) })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = h.eng.Run(ctx) }()
	defer func() { cancel(); <-done }()
	waitFor := func(n int64) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second) /* the tick is 5 s */
		for rounds.Load() < n {
			if time.Now().After(deadline) {
				t.Fatalf("only %d rounds, want %d", rounds.Load(), n)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitFor(1)
	h.eng.Reload()
	waitFor(2)
	h.eng.Reload()
	h.eng.Reload() /* collapses */
	waitFor(3)
}
