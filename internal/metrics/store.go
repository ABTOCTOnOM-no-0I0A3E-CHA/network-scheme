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
	src := ifSources[ifSource(to.Sub(from), s.now().Sub(from))]
	table, inMax, outMax := src.table, src.inMax, src.outMax
	bucket := src.res
	if step > 0 {
		/* date_bin needs a non-zero interval; pgx sends microseconds. */
		bucket = max(step, time.Second, src.res)
	}
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
