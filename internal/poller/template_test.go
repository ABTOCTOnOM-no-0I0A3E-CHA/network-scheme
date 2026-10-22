package poller

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestTemplateIntervalsAreOverriddenByGroupAndDevice(t *testing.T) {
	h := newHarness(t, "")
	p := h.poller(Intervals{Availability: time.Hour, Metrics: time.Hour, Inventory: time.Hour})
	ctx := context.Background()
	api := h.env.Pool("nms_api")
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := api.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	var parent, child, plain int64
	for _, q := range []struct {
		dst  *int64
		sql  string
		args []any
	}{
		{&parent, `INSERT INTO core.device_group (name) VALUES ('p-'||gen_random_uuid()) RETURNING id`, nil},
		{&child, `INSERT INTO core.device_group (name, parent_id) VALUES ('c-'||gen_random_uuid(), $1) RETURNING id`, []any{&parent}},
		{&plain, `INSERT INTO core.device_group (name, interval_avail_s) VALUES ('g-'||gen_random_uuid(), 25) RETURNING id`, nil},
	} {
		if err := api.QueryRow(ctx, q.sql, q.args...).Scan(q.dst); err != nil {
			t.Fatal(err)
		}
	}
	/* Templates, lowest id first within a target: the parent group, the child group, the driver, a second driver template. */
	exec(`INSERT INTO core.monitoring_template (name, group_id, interval_avail_s, interval_metrics_s) VALUES ('t-'||gen_random_uuid(), $1, 20, 40)`, parent)
	exec(`INSERT INTO core.monitoring_template (name, group_id, interval_avail_s) VALUES ('t-'||gen_random_uuid(), $1, 15)`, child)
	exec(`INSERT INTO core.monitoring_template (name, driver, interval_avail_s, interval_inventory_s) VALUES ('t-'||gen_random_uuid(), 'eltex-mes', 999, 600)`)
	exec(`INSERT INTO core.monitoring_template (name, driver, interval_inventory_s) VALUES ('t-'||gen_random_uuid(), 'eltex-mes', 700)`)

	inChild := h.device(netip.MustParseAddrPort("198.51.100.190:161"))
	inGroup := h.device(netip.MustParseAddrPort("198.51.100.191:161"))
	own := h.device(netip.MustParseAddrPort("198.51.100.192:161"))
	untouched := h.device(netip.MustParseAddrPort("198.51.100.193:161"))
	exec(`UPDATE core.device SET group_id = $2, driver = 'eltex-mes' WHERE id = $1`, inChild, child)
	exec(`UPDATE core.device SET group_id = $2, driver = 'eltex-mes' WHERE id = $1`, inGroup, plain)
	exec(`UPDATE core.device SET group_id = $2, driver = 'eltex-mes', interval_metrics_s = 77 WHERE id = $1`, own, child)
	exec(`UPDATE core.device SET driver = 'generic-snmp' WHERE id = $1`, untouched)

	devs, err := p.loadDevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s := time.Second
	want := map[int64][numClasses]time.Duration{
		inChild:   {15 * s, 40 * s, 600 * s},    /* child template, ancestor template, driver template */
		inGroup:   {25 * s, time.Hour, 600 * s}, /* group interval beats the driver template (999); nothing sets metrics */
		own:       {15 * s, 77 * s, 600 * s},    /* the device's own interval beats the ancestor template */
		untouched: {time.Hour, time.Hour, time.Hour},
	}
	for _, d := range devs {
		if w, ok := want[d.ID]; ok {
			if d.Intervals != w {
				t.Errorf("device %d intervals = %v, want %v", d.ID, d.Intervals, w)
			}
			delete(want, d.ID)
		}
	}
	if len(want) != 0 {
		t.Fatalf("devices not loaded: %v", want)
	}
}

func TestTemplateIntervalsHonourFloors(t *testing.T) {
	h := newHarness(t, "")
	p := h.poller(Intervals{Availability: time.Hour, Metrics: time.Hour, Inventory: time.Hour})
	ctx := context.Background()
	api := h.env.Pool("nms_api")
	if _, err := api.Exec(ctx, `INSERT INTO core.monitoring_template (name, group_id, interval_avail_s, interval_metrics_s, interval_inventory_s)
		VALUES ('t-'||gen_random_uuid(), $1, 1, 1, 2000000000)`, h.group); err != nil {
		t.Fatal(err)
	}
	id := h.device(netip.MustParseAddrPort("198.51.100.194:161"))
	devs, err := p.loadDevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range devs {
		if d.ID == id {
			if want := [numClasses]time.Duration{minAvailInterval, minMetricsInterval, maxIntervalDuration}; d.Intervals != want {
				t.Fatalf("intervals = %v, want %v", d.Intervals, want)
			}
			return
		}
	}
	t.Fatal("device not loaded")
}

func TestTemplateChangeNotifiesThePoller(t *testing.T) {
	h := newHarness(t, "")
	ctx := context.Background()
	conn, err := h.env.Pool("nms_poller").Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `LISTEN device_changed`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.env.Pool("nms_api").Exec(ctx, `INSERT INTO core.monitoring_template (name, group_id, interval_avail_s) VALUES ('t-'||gen_random_uuid(), $1, 30)`, h.group); err != nil {
		t.Fatal(err)
	}
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := conn.Conn().WaitForNotification(wctx); err != nil {
		t.Fatalf("no device_changed notification: %v", err)
	}
}
