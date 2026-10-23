package triggers_test

import (
	"testing"
	"time"
)

/* bulkTriggers adds one template for the group with a trigger per row of the generated series; params is a SQL expression over i. */
func (h *harness) bulkTriggers(group int64, kind, params string, n int) []int64 {
	h.t.Helper()
	var tpl int64
	if err := h.api.QueryRow(h.ctx, `INSERT INTO core.monitoring_template (name, group_id) VALUES ($1, $2) RETURNING id`,
		"T:bulk:"+time.Now().Format(time.RFC3339Nano), group).Scan(&tpl); err != nil {
		h.t.Fatal(err)
	}
	rows, err := h.api.Query(h.ctx, `INSERT INTO core.trigger (template_id, kind, params, duration_s, severity, name)
		SELECT $1, $2, `+params+`, 0, 'high', 'bulk ' || i FROM generate_series(1, $3::int) i RETURNING id`, tpl, kind, n)
	if err != nil {
		h.t.Fatal(err)
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			h.t.Fatal(err)
		}
		ids = append(ids, id)
	}
	return ids
}

func TestEffectiveTriggersPerDeviceAreCapped(t *testing.T) {
	h := newHarness(t)
	dev := h.newDevice()
	ids := h.bulkTriggers(h.group, "availability", `'{"states":["down"]}'::jsonb`, 510)
	h.setStates([]int64{dev}, "down", h.clk.Now())
	h.step()
	open := h.openProblems(dev)
	if len(open) != 500 {
		t.Fatalf("open problems = %d, want 500", len(open))
	}
	have := map[int64]bool{}
	for _, p := range open {
		have[p.Trigger] = true
	}
	for i, id := range ids {
		if have[id] != (i < 500) {
			t.Fatalf("trigger #%d (id %d) evaluated = %v, want the lowest 500 ids only", i, id, have[id])
		}
	}
}

func TestSyslogFiltersAreCaseInsensitiveAndBounded(t *testing.T) {
	h := newHarness(t)
	dev := h.newDevice()
	ids := h.bulkTriggers(h.group, "syslog", `jsonb_build_object('severity_min', 4, 'contains', 'm' || i)`, 257)
	upper := h.newTrigger(h.group, "syslog", `{"severity_min":4,"contains":"M5"}`, 0, "high") /* the same filter as m5 */
	h.writeSyslog(dev, h.clk.Now(), 3, "xx m5 xx")
	h.writeSyslog(dev, h.clk.Now(), 3, "xx m257 xx")
	h.advance(6 * time.Second)
	have := map[int64]bool{}
	for _, p := range h.openProblems(dev) {
		have[p.Trigger] = true
	}
	if !have[ids[4]] || !have[upper] {
		t.Errorf("m5 and M5 must share one filter and both fire: %v", have)
	}
	if have[ids[256]] {
		t.Error("the 257th distinct filter must be skipped by the engine")
	}
}

func TestMovedDeviceNotifiesItsNewGroup(t *testing.T) {
	h := newHarness(t)
	gB := h.newGroup(nil)
	dev := h.newDevice()
	h.newTrigger(h.group, "availability", `{"states":["down"]}`, 0, "high")
	h.newTrigger(gB, "availability", `{"states":["down"]}`, 0, "high")
	h.setStates([]int64{dev}, "up", h.clk.Now())
	h.step()
	h.take()
	h.exec(h.api, `UPDATE core.device SET group_id = $2 WHERE id = $1`, dev, gB)
	h.advance(time.Second)
	h.setStates([]int64{dev}, "down", h.clk.Now())
	h.advance(time.Second)
	opened := 0
	for _, m := range h.take() {
		if m.Event != "opened" {
			continue
		}
		if opened++; m.Problem.GroupID == nil || *m.Problem.GroupID != gB {
			t.Fatalf("opened for group %v, want %d", m.Problem.GroupID, gB)
		}
	}
	if opened == 0 {
		t.Fatal("no problem opened after the move")
	}
}
