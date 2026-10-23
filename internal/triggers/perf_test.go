package triggers_test

import (
	"testing"
	"time"
)

/* TestFiveThousandDevices measures the engine on 5 000 devices with the default templates (batched queries, no per-device round trips). */
func TestFiveThousandDevices(t *testing.T) {
	if testing.Short() {
		t.Skip("load test")
	}
	h := newHarness(t)
	const n = 5000
	now := h.clk.Now()
	h.exec(h.root, `INSERT INTO core.device (name, address, group_id, poller_id, driver, parent_id)
		SELECT 'perf-' || i, ('10.64.0.0'::inet + i), $1, 'tp', 'generic-snmp', NULL FROM generate_series(1, $2) i`, h.group, n)
	h.exec(h.root, `UPDATE core.device c SET parent_id = p.id FROM
		(SELECT id, row_number() OVER (ORDER BY id) rn FROM core.device) p, (SELECT id, row_number() OVER (ORDER BY id) rn FROM core.device) k
		WHERE c.id = k.id AND k.rn > 100 AND k.rn <= 600 AND p.rn = 1 + (k.rn % 10)`)
	h.heartbeat("tp")
	/* 4% down, 2% partial, the rest up. */
	h.exec(h.root, `INSERT INTO inventory.device_status (device_id, state, since, last_poll_at, poller_id)
		SELECT id, CASE WHEN id % 25 = 0 THEN 'down' WHEN id % 50 = 1 THEN 'partial' ELSE 'up' END, $1, $1, 'tp' FROM core.device`, now.Add(-10*time.Minute))
	h.exec(h.root, `INSERT INTO metrics.sys_metrics (device_id, ts, cpu_pct, mem_used_pct, temp_c) SELECT id, $1, 10 + id % 90, 40, 35 FROM core.device`, now.Add(-5*time.Second))
	/* 24 interfaces per device; every tenth device has two ports down. */
	h.exec(h.root, `INSERT INTO metrics.if_metrics (device_id, if_index, ts, in_bps, out_bps, oper_up, speed_bps)
		SELECT d.id, x, $1, 1000, 1000, NOT (d.id % 10 = 0 AND x <= 2), 1000000000 FROM core.device d, generate_series(1, 24) x`, now.Add(-5*time.Second))
	h.exec(h.root, `INSERT INTO events.trap (ts, device_id, version, trap_oid, name, severity, varbinds, identified)
		SELECT $1, id, 2, '1.3.6.1.6.3.1.1.5.3', 'linkDown', 'average',
		       '[{"oid":"1.3.6.1.2.1.2.2.1.1.5","type":"Integer","value":"5"}]', true FROM core.device WHERE id % 10 = 3`, now.Add(2*time.Second))
	h.newTrigger(h.group, "metric_threshold", `{"metric":"cpu","op":"gt","value":90}`, 0, "warning")
	h.newTrigger(h.group, "trap", `{"name":"linkDown"}`, 0, "average")
	h.newTrigger(h.group, "syslog", `{"severity_min":3}`, 0, "high")

	timed := func(name string, f func()) time.Duration {
		start := time.Now()
		f()
		d := time.Since(start)
		t.Logf("%-46s %v", name, d)
		return d
	}
	h.clk.Advance(10 * time.Second)
	first := timed("first full round (cold, opens everything)", h.step)
	var open int
	if err := h.api.QueryRow(h.ctx, `SELECT count(*) FROM problems.problem WHERE state <> 'resolved'`).Scan(&open); err != nil {
		t.Fatal(err)
	}
	t.Logf("open problems after the first round: %d", open)
	h.clk.Advance(5 * time.Second)
	fast := timed("steady 5 s round (availability + events)", func() {
		if err := h.eng.StepFast(h.ctx); err != nil {
			t.Fatal(err)
		}
	})
	h.clk.Advance(5 * time.Second)
	h.heartbeat("tp")
	timed("steady full round (30 s)", h.step)
	var after int
	if err := h.api.QueryRow(h.ctx, `SELECT count(*) FROM problems.problem WHERE state <> 'resolved'`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != open {
		t.Errorf("steady rounds changed the problem count: %d -> %d", open, after)
	}
	if first > 30*time.Second || fast > 5*time.Second {
		t.Errorf("too slow: first %v, steady fast %v", first, fast)
	}
}
