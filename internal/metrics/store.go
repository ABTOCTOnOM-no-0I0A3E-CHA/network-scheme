// Package metrics stores and queries time series in TimescaleDB (schema metrics)
// and computes interface rates on the poller side.
package metrics

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

/*
IfPoint is one interface sample: rates in bits (octets) or packets per
second. Error and discard rates are nil when unknown. InBpsMax and OutBpsMax
are the peaks inside an aggregated bucket; for raw points they equal InBps and
OutBps, and writers ignore them.
*/
type IfPoint struct {
	DeviceID            int64
	IfIndex             int
	TS                  time.Time
	InBps, OutBps       float64
	InBpsMax, OutBpsMax float64
	InErrPS, OutErrPS   *float64
	InDiscPS, OutDiscPS *float64
	OperUp              bool
	SpeedBps            int64
}

// SysPoint is one system resource sample; nil means not reported.
type SysPoint struct {
	DeviceID           int64
	TS                 time.Time
	CPUPct, MemUsedPct *float64
	TempC              *float64
	PSUOk              *bool
}

// Availability states.
const (
	StateUp      = "up"
	StatePartial = "partial"
	StateDown    = "down"
	StateUnknown = "unknown"
)

// AvailPoint is one availability probe result; RTTms is nil without an ICMP reply.
type AvailPoint struct {
	DeviceID       int64
	TS             time.Time
	ICMPOk, SNMPOk bool
	RTTms          *float64
	State          string
}

/*
MetricStore is the only way other packages reach metric storage, so the
backend can be replaced.
*/
type MetricStore interface {
	WriteIf(ctx context.Context, pts []IfPoint) error
	WriteSys(ctx context.Context, pts []SysPoint) error
	WriteAvailability(ctx context.Context, pts []AvailPoint) error
	QueryIf(ctx context.Context, deviceID int64, ifIndex int, from, to time.Time, step time.Duration) ([]IfPoint, error)
	/* SysSince returns the raw system samples in (from, to], oldest first, at most limit. */
	SysSince(ctx context.Context, from, to time.Time, limit int) ([]SysPoint, error)
	/*
		IfSince returns the raw interface samples in (from, to], oldest first, at most
		limit. Only the samples of filter.DeviceIDs are returned (all devices when
		empty); with DownOrDeviceIDs set it returns the down samples of every
		device plus all samples of DownOrDeviceIDs (the cheap form for link-down checks).
	*/
	IfSince(ctx context.Context, from, to time.Time, filter IfFilter, limit int) ([]IfPoint, error)
	/* IfUpSince lists the (device, interface) pairs that reported oper_up in (from, to] with their first such sample. */
	IfUpSince(ctx context.Context, from, to time.Time) ([]IfFirstUp, error)
}

// IfFirstUp is an interface and the time of its first oper_up sample in a range.
type IfFirstUp struct {
	DeviceID int64
	IfIndex  int
	FirstUp  time.Time
}

/*
IfFilter narrows IfSince. DeviceIDs restricts the result to those devices;
when DownOrDeviceIDs is non-nil, samples with oper_up = false of any device
(inside DeviceIDs when set) are returned together with every sample of the
DownOrDeviceIDs devices.
*/
type IfFilter struct {
	DeviceIDs       []int64
	DownOrDeviceIDs []int64
}

// Store is the TimescaleDB MetricStore.
type Store struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

var _ MetricStore = (*Store)(nil)

// NewStore returns a Store over pool (nms_poller writes, nms_api reads).
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool, now: time.Now} }

func (s *Store) copy(ctx context.Context, table string, cols []string, n int, row func(i int) []any) error {
	if n == 0 {
		return nil
	}
	_, err := s.pool.CopyFrom(ctx, pgx.Identifier{"metrics", table}, cols, pgx.CopyFromSlice(n, func(i int) ([]any, error) {
		return row(i), nil
	}))
	if err != nil {
		return fmt.Errorf("write metrics.%s: %w", table, err)
	}
	return nil
}

// WriteIf appends interface points.
func (s *Store) WriteIf(ctx context.Context, pts []IfPoint) error {
	return s.copy(ctx, "if_metrics", []string{"device_id", "if_index", "ts", "in_bps", "out_bps",
		"in_err_ps", "out_err_ps", "in_disc_ps", "out_disc_ps", "oper_up", "speed_bps"}, len(pts),
		func(i int) []any {
			p := pts[i]
			return []any{p.DeviceID, p.IfIndex, p.TS, p.InBps, p.OutBps,
				p.InErrPS, p.OutErrPS, p.InDiscPS, p.OutDiscPS, p.OperUp, p.SpeedBps}
		})
}

// WriteSys appends system resource points.
func (s *Store) WriteSys(ctx context.Context, pts []SysPoint) error {
	return s.copy(ctx, "sys_metrics", []string{"device_id", "ts", "cpu_pct", "mem_used_pct", "temp_c", "psu_ok"},
		len(pts), func(i int) []any {
			p := pts[i]
			return []any{p.DeviceID, p.TS, p.CPUPct, p.MemUsedPct, p.TempC, p.PSUOk}
		})
}

// WriteAvailability appends availability points.
func (s *Store) WriteAvailability(ctx context.Context, pts []AvailPoint) error {
	return s.copy(ctx, "availability", []string{"device_id", "ts", "icmp_ok", "snmp_ok", "rtt_ms", "state"},
		len(pts), func(i int) []any {
			p := pts[i]
			return []any{p.DeviceID, p.TS, p.ICMPOk, p.SNMPOk, p.RTTms, p.State}
		})
}

/* Source tables of QueryIf, finest first, with their retention. */
var ifSources = []struct {
	table, inMax, outMax string
	res, maxWidth        time.Duration
	retention            time.Duration
}{
	{"metrics.if_metrics", "in_bps", "out_bps", 0, 48 * time.Hour, 14 * 24 * time.Hour},
	{"metrics.if_metrics_5m", "in_bps_max", "out_bps_max", 5 * time.Minute, 60 * 24 * time.Hour, 90 * 24 * time.Hour},
	{"metrics.if_metrics_1h", "in_bps_max", "out_bps_max", time.Hour, 0, 0},
}

/*
ifSource picks the finest source that both covers the range width (raw up to
2 days, 5-minute aggregates up to 60 days, hourly beyond) and still keeps data
as old as the range start (age = now - from).
*/
func ifSource(width, age time.Duration) int {
	for i, src := range ifSources[:len(ifSources)-1] {
		if width <= src.maxWidth && age <= src.retention {
			return i
		}
	}
	return len(ifSources) - 1
}

/* ifPlan returns the source QueryIf reads for the range and the bucket it regroups into (0: none). */
func (s *Store) ifPlan(from, to time.Time, step time.Duration) (int, time.Duration) {
	i := ifSource(to.Sub(from), s.now().Sub(from))
	bucket := ifSources[i].res
	if step > 0 {
		/* date_bin needs a non-zero interval; pgx sends microseconds. */
		bucket = max(step, time.Second, ifSources[i].res)
	}
	return i, bucket
}

/*
IfStep returns the bucket width QueryIf would use for the same arguments
now: max(step, 1s, source resolution) for a positive step, the source
resolution otherwise. 0 means raw points at the poll interval.
*/
func (s *Store) IfStep(from, to time.Time, step time.Duration) time.Duration {
	_, bucket := s.ifPlan(from, to, step)
	return bucket
}

/*
QueryIf returns the points of one interface in [from, to), oldest first. The
source follows the range width and age; a positive step regroups the points
into buckets of max(step, 1s, source resolution) (average, peak for the maxima);
step <= 0 keeps the source's own resolution.
*/
func (s *Store) QueryIf(ctx context.Context, deviceID int64, ifIndex int, from, to time.Time, step time.Duration) ([]IfPoint, error) {
	if !to.After(from) {
		return nil, errors.New("metrics: empty time range")
	}
	i, bucket := s.ifPlan(from, to, step)
	table, inMax, outMax := ifSources[i].table, ifSources[i].inMax, ifSources[i].outMax
	/* Identifiers come from the ifSources constants only; values are parameters. */
	q := `SELECT ts, in_bps, ` + inMax + `, out_bps, ` + outMax + `,
	             in_err_ps, out_err_ps, in_disc_ps, out_disc_ps, oper_up, speed_bps
	      FROM ` + table + `
	      WHERE device_id = $1 AND if_index = $2 AND ts >= $3 AND ts < $4
	      ORDER BY ts`
	args := []any{deviceID, ifIndex, from, to}
	if bucket > 0 {
		/* date_bin (core PostgreSQL) aligns buckets like the aggregates' time_bucket. */
		q = `SELECT date_bin($5::interval, ts, '2000-01-01 00:00:00+00') AS b,
		            avg(in_bps), max(` + inMax + `), avg(out_bps), max(` + outMax + `),
		            avg(in_err_ps), avg(out_err_ps), avg(in_disc_ps), avg(out_disc_ps),
		            bool_and(oper_up), max(speed_bps)
		     FROM ` + table + `
		     WHERE device_id = $1 AND if_index = $2 AND ts >= $3 AND ts < $4
		     GROUP BY b ORDER BY b`
		args = append(args, bucket)
	}
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query interface metrics: %w", err)
	}
	pts, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (IfPoint, error) {
		p := IfPoint{DeviceID: deviceID, IfIndex: ifIndex}
		err := row.Scan(&p.TS, &p.InBps, &p.InBpsMax, &p.OutBps, &p.OutBpsMax,
			&p.InErrPS, &p.OutErrPS, &p.InDiscPS, &p.OutDiscPS, &p.OperUp, &p.SpeedBps)
		return p, err
	})
	if err != nil {
		return nil, fmt.Errorf("query interface metrics: %w", err)
	}
	return pts, nil
}

/* Source tables of QuerySys, tier for tier with ifSources (same resolutions and retention). */
var sysTables = []string{"metrics.sys_metrics", "metrics.sys_metrics_5m", "metrics.sys_metrics_1h"}

/*
QuerySys returns the CPU, memory and temperature samples of one device in
[from, to), oldest first. It reads the same tier and regroups into the same
buckets as QueryIf for the same arguments (IfStep gives the bucket width);
the aggregates contribute their averages. PSUOk is not filled.
*/
func (s *Store) QuerySys(ctx context.Context, deviceID int64, from, to time.Time, step time.Duration) ([]SysPoint, error) {
	if !to.After(from) {
		return nil, errors.New("metrics: empty time range")
	}
	i, bucket := s.ifPlan(from, to, step)
	/* The identifier comes from the sysTables constants only; values are parameters. */
	q := `SELECT ts, cpu_pct, mem_used_pct, temp_c FROM ` + sysTables[i] + `
	      WHERE device_id = $1 AND ts >= $2 AND ts < $3 ORDER BY ts`
	args := []any{deviceID, from, to}
	if bucket > 0 {
		q = `SELECT date_bin($4::interval, ts, '2000-01-01 00:00:00+00') AS b, avg(cpu_pct), avg(mem_used_pct), avg(temp_c)
		     FROM ` + sysTables[i] + `
		     WHERE device_id = $1 AND ts >= $2 AND ts < $3
		     GROUP BY b ORDER BY b`
		args = append(args, bucket)
	}
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query system metrics: %w", err)
	}
	pts, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (SysPoint, error) {
		p := SysPoint{DeviceID: deviceID}
		err := row.Scan(&p.TS, &p.CPUPct, &p.MemUsedPct, &p.TempC)
		return p, err
	})
	if err != nil {
		return nil, fmt.Errorf("query system metrics: %w", err)
	}
	return pts, nil
}

// SysSince implements MetricStore.
func (s *Store) SysSince(ctx context.Context, from, to time.Time, limit int) ([]SysPoint, error) {
	rows, err := s.pool.Query(ctx, `SELECT device_id, ts, cpu_pct, mem_used_pct, temp_c, psu_ok
		FROM metrics.sys_metrics WHERE ts > $1 AND ts <= $2 ORDER BY ts LIMIT $3`, from, to, limit)
	if err != nil {
		return nil, fmt.Errorf("query system samples: %w", err)
	}
	pts, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (SysPoint, error) {
		var p SysPoint
		err := row.Scan(&p.DeviceID, &p.TS, &p.CPUPct, &p.MemUsedPct, &p.TempC, &p.PSUOk)
		return p, err
	})
	if err != nil {
		return nil, fmt.Errorf("query system samples: %w", err)
	}
	return pts, nil
}

// IfSince implements MetricStore.
func (s *Store) IfSince(ctx context.Context, from, to time.Time, f IfFilter, limit int) ([]IfPoint, error) {
	q := `SELECT device_id, if_index, ts, in_bps, out_bps, in_err_ps, out_err_ps, oper_up, speed_bps
	      FROM metrics.if_metrics
	      WHERE ts > $1 AND ts <= $2
	        AND (coalesce(cardinality($3::bigint[]), 0) = 0 OR device_id = ANY($3))
	        AND ($4::bigint[] IS NULL OR NOT oper_up OR device_id = ANY($4))
	      ORDER BY ts LIMIT $5`
	var down any
	if f.DownOrDeviceIDs != nil {
		down = f.DownOrDeviceIDs
	}
	rows, err := s.pool.Query(ctx, q, from, to, f.DeviceIDs, down, limit)
	if err != nil {
		return nil, fmt.Errorf("query interface samples: %w", err)
	}
	pts, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (IfPoint, error) {
		var p IfPoint
		err := row.Scan(&p.DeviceID, &p.IfIndex, &p.TS, &p.InBps, &p.OutBps, &p.InErrPS, &p.OutErrPS, &p.OperUp, &p.SpeedBps)
		return p, err
	})
	if err != nil {
		return nil, fmt.Errorf("query interface samples: %w", err)
	}
	return pts, nil
}

// IfUpSince implements MetricStore.
func (s *Store) IfUpSince(ctx context.Context, from, to time.Time) ([]IfFirstUp, error) {
	rows, err := s.pool.Query(ctx, `SELECT device_id, if_index, min(ts) FROM metrics.if_metrics WHERE ts > $1 AND ts <= $2 AND oper_up GROUP BY device_id, if_index`, from, to)
	if err != nil {
		return nil, fmt.Errorf("query up interfaces: %w", err)
	}
	pairs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (IfFirstUp, error) {
		var u IfFirstUp
		err := row.Scan(&u.DeviceID, &u.IfIndex, &u.FirstUp)
		return u, err
	})
	if err != nil {
		return nil, fmt.Errorf("query up interfaces: %w", err)
	}
	return pairs, nil
}
