package metrics

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/beekamai/network-scheme/internal/testdb"
)

func TestMain(m *testing.M) { testdb.Main(m) }

func TestHypertablesAndPolicies(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	db := env.Pool("postgres")

	raw := []string{"availability", "if_metrics", "sys_metrics"}
	for _, h := range raw {
		var chunk time.Duration
		var compressed bool
		var owner, segmentby string
		err := db.QueryRow(ctx, `
			SELECT d.time_interval, h.compression_enabled, h.owner, s.segmentby
			FROM timescaledb_information.hypertables h
			JOIN timescaledb_information.dimensions d USING (hypertable_schema, hypertable_name)
			JOIN timescaledb_information.hypertable_compression_settings s
			  ON s.hypertable = format('%I.%I', h.hypertable_schema, h.hypertable_name)::regclass
			WHERE h.hypertable_schema = 'metrics' AND h.hypertable_name = $1`, h).
			Scan(&chunk, &compressed, &owner, &segmentby)
		if err != nil {
			t.Fatalf("%s: %v", h, err)
		}
		if chunk != 24*time.Hour || !compressed || owner != "nms_migrator" || segmentby != "device_id" {
			t.Errorf("%s: chunk=%v compressed=%v owner=%s segmentby=%s", h, chunk, compressed, owner, segmentby)
		}
	}

	type job struct{ proc, rel, key, value string }
	want := map[job]bool{}
	for _, h := range raw {
		want[job{"policy_compression", h, "compress_after", "2 days"}] = true
		want[job{"policy_retention", h, "drop_after", "14 days"}] = true
	}
	for _, c := range []string{"if_metrics_5m", "sys_metrics_5m"} {
		want[job{"policy_retention", c, "drop_after", "90 days"}] = true
		want[job{"policy_refresh_continuous_aggregate", c, "start_offset", "1 day"}] = true
	}
	for _, c := range []string{"if_metrics_1h", "sys_metrics_1h", "availability_1h"} {
		want[job{"policy_retention", c, "drop_after", "730 days"}] = true
		want[job{"policy_refresh_continuous_aggregate", c, "start_offset", "3 days"}] = true
	}
	/*
	   Policies on a continuous aggregate are registered against its
	   materialization hypertable; map it back to the view name.
	*/
	rows, err := db.Query(ctx, `
		SELECT j.proc_name, coalesce(ca.view_name, j.hypertable_name), j.owner::regrole::text,
		       coalesce(j.config->>'compress_after', j.config->>'drop_after', j.config->>'start_offset')
		FROM timescaledb_information.jobs j
		LEFT JOIN timescaledb_information.continuous_aggregates ca
		  ON ca.materialization_hypertable_schema = j.hypertable_schema
		 AND ca.materialization_hypertable_name = j.hypertable_name
		WHERE j.hypertable_schema = 'metrics' OR ca.view_schema = 'metrics'`)
	if err != nil {
		t.Fatal(err)
	}
	got := map[job]bool{}
	for rows.Next() {
		var j job
		var owner string
		if err := rows.Scan(&j.proc, &j.rel, &owner, &j.value); err != nil {
			t.Fatal(err)
		}
		if owner != "nms_migrator" {
			t.Errorf("job %+v owned by %s", j, owner)
		}
		switch j.proc {
		case "policy_compression":
			j.key = "compress_after"
		case "policy_retention":
			j.key = "drop_after"
		default:
			j.key = "start_offset"
		}
		got[j] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for j := range want {
		if !got[j] {
			t.Errorf("missing job %+v", j)
		}
	}
	for j := range got {
		if !want[j] {
			t.Errorf("unexpected job %+v", j)
		}
	}

	var caggs int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM timescaledb_information.continuous_aggregates
		WHERE view_schema = 'metrics' AND materialized_only AND view_owner = 'nms_migrator'`).Scan(&caggs); err != nil {
		t.Fatal(err)
	}
	if caggs != 5 {
		t.Errorf("continuous aggregates = %d, want 5", caggs)
	}

	/* The policies actually run as their owner, which is not a superuser. */
	ids, err := db.Query(ctx, `SELECT job_id FROM timescaledb_information.jobs
		WHERE owner::regrole::text = 'nms_migrator' ORDER BY job_id`)
	if err != nil {
		t.Fatal(err)
	}
	var jobIDs []int
	for ids.Next() {
		var id int
		if err := ids.Scan(&id); err != nil {
			t.Fatal(err)
		}
		jobIDs = append(jobIDs, id)
	}
	if err := ids.Err(); err != nil {
		t.Fatal(err)
	}
	for _, id := range jobIDs {
		if _, err := env.Pool("nms_migrator").Exec(ctx, `CALL run_job($1)`, id); err != nil {
			t.Errorf("run_job(%d) as nms_migrator: %v", id, err)
		}
	}
}

func f64(v float64) *float64 { return &v }

func TestQueryPicksResolution(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	const dev, ifIdx = 9001, 3
	base := time.Now().UTC().Truncate(time.Hour).Add(-30 * time.Hour)

	var pts []IfPoint
	for i := range 120 {
		pts = append(pts, IfPoint{DeviceID: dev, IfIndex: ifIdx, TS: base.Add(time.Duration(i) * time.Minute),
			InBps: float64(i), OutBps: 2 * float64(i), InErrPS: f64(1), OperUp: true, SpeedBps: 1000})
	}
	/* Another interface and device must never leak into the result. */
	pts = append(pts, IfPoint{DeviceID: dev, IfIndex: ifIdx + 1, TS: base, InBps: 1e9, OperUp: true},
		IfPoint{DeviceID: dev + 1, IfIndex: ifIdx, TS: base, InBps: 1e9, OperUp: true})
	if err := NewStore(env.Pool("nms_poller")).WriteIf(ctx, pts); err != nil {
		t.Fatal(err)
	}
	for _, view := range []string{"metrics.if_metrics_5m", "metrics.if_metrics_1h"} {
		if _, err := env.Pool("nms_migrator").Exec(ctx, `CALL refresh_continuous_aggregate($1::regclass, $2::timestamptz, $3::timestamptz)`,
			view, base.Add(-time.Hour), base.Add(3*time.Hour)); err != nil {
			t.Fatalf("refresh %s: %v", view, err)
		}
	}

	api := NewStore(env.Pool("nms_api"))
	end := base.Add(2 * time.Hour)
	cases := []struct {
		name        string
		from        time.Time
		step        time.Duration
		n           int
		in, inMax   float64
		out, outMax float64
		firstTS     time.Time
		later       time.Duration /* the clock reads end + later */
	}{
		{"raw", base, 0, 120, 0, 0, 0, 0, base, 0},
		{"raw-at-2-days", end.Add(-48 * time.Hour), 0, 120, 0, 0, 0, 0, base, 0},
		{"raw-rebucketed", base, 10 * time.Minute, 12, 4.5, 9, 9, 18, base, 0},
		{"5m", end.Add(-48*time.Hour - time.Second), 0, 24, 2, 4, 4, 8, base, 0},
		{"5m-at-60-days", end.Add(-60 * 24 * time.Hour), time.Minute, 24, 2, 4, 4, 8, base, 0},
		{"5m-rebucketed", base.Add(-10 * 24 * time.Hour), 30 * time.Minute, 4, 14.5, 29, 29, 58, base, 0},
		{"1h", end.Add(-60*24*time.Hour - time.Second), 0, 2, 29.5, 59, 59, 118, base, 0},
		/* A narrow range older than a source's retention moves to the next source. */
		{"raw-13-days-ago", base, 0, 120, 0, 0, 0, 0, base, 13 * 24 * time.Hour},
		{"5m-20-days-ago", base, 0, 24, 2, 4, 4, 8, base, 20 * 24 * time.Hour},
		{"1h-100-days-ago", base, 0, 2, 29.5, 59, 59, 118, base, 100 * 24 * time.Hour},
		{"5m-wide-100-days-ago", end.Add(-10 * 24 * time.Hour), 0, 2, 29.5, 59, 59, 118, base, 100 * 24 * time.Hour},
		/* Sub-second steps are clamped (1s on raw, the source resolution on aggregates). */
		{"raw-step-1ns", base, time.Nanosecond, 120, 0, 0, 0, 0, base, 0},
		{"raw-step-500ms", base, 500 * time.Millisecond, 120, 0, 0, 0, 0, base, 0},
		{"5m-step-1ns", end.Add(-72 * time.Hour), time.Nanosecond, 24, 2, 4, 4, 8, base, 0},
		{"1h-step-1m", base, time.Minute, 2, 29.5, 59, 59, 118, base, 100 * 24 * time.Hour},
	}
	for _, c := range cases {
		api.now = func() time.Time { return end.Add(c.later) }
		got, err := api.QueryIf(ctx, dev, ifIdx, c.from, end, c.step)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(got) != c.n {
			t.Errorf("%s: %d points, want %d", c.name, len(got), c.n)
			continue
		}
		p := got[0]
		if !p.TS.Equal(c.firstTS) || p.InBps != c.in || p.InBpsMax != c.inMax || p.OutBps != c.out || p.OutBpsMax != c.outMax {
			t.Errorf("%s: first = %+v", c.name, p)
		}
		if p.DeviceID != dev || p.IfIndex != ifIdx || !p.OperUp || p.SpeedBps != 1000 ||
			p.InErrPS == nil || *p.InErrPS != 1 || p.OutErrPS != nil {
			t.Errorf("%s: fields = %+v", c.name, p)
		}
		for i := 1; i < len(got); i++ {
			if !got[i].TS.After(got[i-1].TS) {
				t.Errorf("%s: not ascending at %d", c.name, i)
			}
		}
	}

	if _, err := api.QueryIf(ctx, dev, ifIdx, end, base, 0); err == nil {
		t.Error("inverted range accepted")
	}
}

func TestWriteSysAndAvailability(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	s := NewStore(env.Pool("nms_poller"))
	at := time.Now().UTC().Truncate(time.Second)
	psu := true
	if err := s.WriteSys(ctx, []SysPoint{
		{DeviceID: 9100, TS: at, CPUPct: f64(12.5), MemUsedPct: f64(40), PSUOk: &psu},
		{DeviceID: 9100, TS: at.Add(time.Minute)},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteAvailability(ctx, []AvailPoint{
		{DeviceID: 9100, TS: at, ICMPOk: true, SNMPOk: true, RTTms: f64(1.25), State: StateUp},
		{DeviceID: 9100, TS: at.Add(time.Minute), ICMPOk: true, State: StatePartial},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteAvailability(ctx, []AvailPoint{{DeviceID: 9100, TS: at, State: "sideways"}}); err == nil {
		t.Error("unknown state accepted")
	}

	db := env.Pool("nms_api")
	var cpu, temp *float32
	var psuOk *bool
	if err := db.QueryRow(ctx, `SELECT cpu_pct, temp_c, psu_ok FROM metrics.sys_metrics
		WHERE device_id = 9100 AND ts = $1`, at).Scan(&cpu, &temp, &psuOk); err != nil {
		t.Fatal(err)
	}
	if cpu == nil || *cpu != 12.5 || temp != nil || psuOk == nil || !*psuOk {
		t.Errorf("sys row = %v %v %v", cpu, temp, psuOk)
	}
	var n int
	var rtt *float32
	if err := db.QueryRow(ctx, `SELECT count(*), max(rtt_ms) FROM metrics.availability WHERE device_id = 9100`).
		Scan(&n, &rtt); err != nil {
		t.Fatal(err)
	}
	if n != 2 || rtt == nil || *rtt != 1.25 {
		t.Errorf("availability rows = %d, rtt %v", n, rtt)
	}
	if err := s.WriteIf(ctx, nil); err != nil {
		t.Errorf("empty write: %v", err)
	}
}

func TestPollerCannotUpdateMetrics(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	if err := NewStore(env.Pool("nms_poller")).WriteIf(ctx, []IfPoint{
		{DeviceID: 9200, IfIndex: 1, TS: time.Now(), OperUp: true}}); err != nil {
		t.Fatal(err)
	}
	for role, stmts := range map[string][]string{
		"nms_poller": {
			`UPDATE metrics.if_metrics SET in_bps = 0 WHERE device_id = 9200`,
			`DELETE FROM metrics.if_metrics WHERE device_id = 9200`,
			`UPDATE metrics.sys_metrics SET cpu_pct = 0`,
			`DELETE FROM metrics.availability`,
			`TRUNCATE metrics.if_metrics`,
			`SELECT count(*) FROM metrics.if_metrics_5m`,
		},
		"nms_api": {
			`INSERT INTO metrics.if_metrics (device_id, if_index, ts, in_bps, out_bps, oper_up, speed_bps)
			 VALUES (1, 1, now(), 0, 0, true, 0)`,
			`UPDATE metrics.if_metrics SET in_bps = 0 WHERE device_id = 9200`,
			`DELETE FROM metrics.availability`,
		},
		"nms_cli": {`SELECT count(*) FROM metrics.if_metrics`},
	} {
		for _, q := range stmts {
			_, err := env.Pool(role).Exec(ctx, q)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
				t.Errorf("%s: %q: err = %v, want 42501", role, q, err)
			}
		}
	}
}

/* TestIfStep: the bucket QueryIf will use, after source selection and step clamping. */
func TestIfStep(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	s := &Store{now: func() time.Time { return now }}
	day := 24 * time.Hour
	cases := []struct {
		name     string
		from, to time.Time
		step     time.Duration
		want     time.Duration
	}{
		{"raw", now.Add(-time.Hour), now, 0, 0},
		{"raw-step-1ns", now.Add(-time.Hour), now, time.Nanosecond, time.Second},
		{"raw-step-10m", now.Add(-time.Hour), now, 10 * time.Minute, 10 * time.Minute},
		{"5m", now.Add(-3 * day), now, 0, 5 * time.Minute},
		{"5m-step-1m", now.Add(-3 * day), now, time.Minute, 5 * time.Minute},
		{"5m-old-narrow", now.Add(-20 * day), now.Add(-20*day + time.Hour), 0, 5 * time.Minute},
		{"1h", now.Add(-100 * day), now, 0, time.Hour},
		{"1h-step-2h", now.Add(-100 * day), now, 2 * time.Hour, 2 * time.Hour},
	}
	for _, c := range cases {
		if got := s.IfStep(c.from, c.to, c.step); got != c.want {
			t.Errorf("%s: IfStep = %v, want %v", c.name, got, c.want)
		}
	}
}
