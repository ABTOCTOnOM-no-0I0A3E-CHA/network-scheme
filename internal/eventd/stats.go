package eventd

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	statsEvery    = 10 * time.Second
	healthyWithin = 30 * time.Second
)

/*
stats are the process counters. The first six are mirrored into
events.eventd_stats; malformed and rejected are only logged (the table has no
column for them).
*/
type stats struct {
	received      atomic.Uint64 /* datagrams and frames read, from known or unknown peers */
	accepted      atomic.Uint64 /* rows put into the queue */
	unknownSource atomic.Uint64
	authFailed    atomic.Uint64
	rateLimited   atomic.Uint64 /* folded into storm rows */
	dropped       atomic.Uint64 /* lost: queue full, refused by the database, refused connections */
	malformed     atomic.Uint64 /* authenticated source, unparsable content */
	rejected      atomic.Uint64 /* rows the database refused (also counted in dropped) */
	slowDropped   atomic.Uint64 /* SNMPv3 messages over the key-derivation budget (also in auth_failed) */
	v3Inform      atomic.Uint64 /* authenticated SNMPv3 INFORMs: unsupported (also in malformed) */
	panics        atomic.Uint64 /* recovered panics while processing one packet (also in malformed) */

	flushed [6]uint64 /* values already written to the database; only the stats loop touches it */
}

func (s *stats) snapshot() [6]uint64 {
	return [6]uint64{s.received.Load(), s.accepted.Load(), s.unknownSource.Load(), s.authFailed.Load(), s.rateLimited.Load(), s.dropped.Load()}
}

/*
flush adds what changed since the last successful flush to the instance's row
and refreshes updated_at (the healthcheck reads it) and queue_depth.
*/
func (s *stats) flush(ctx context.Context, pool *pgxpool.Pool, instance string, depth int) error {
	cur := s.snapshot()
	var d [6]int64
	for i := range d {
		d[i] = int64(cur[i] - s.flushed[i]) // #nosec G115 -- a delta stays far below 2^63
	}
	_, err := pool.Exec(ctx, `
		INSERT INTO events.eventd_stats AS t (instance, updated_at, received, accepted, unknown_source, auth_failed, rate_limited, dropped, queue_depth)
		VALUES ($1, now(), $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (instance) DO UPDATE SET updated_at = now(),
			received = t.received + EXCLUDED.received, accepted = t.accepted + EXCLUDED.accepted,
			unknown_source = t.unknown_source + EXCLUDED.unknown_source, auth_failed = t.auth_failed + EXCLUDED.auth_failed,
			rate_limited = t.rate_limited + EXCLUDED.rate_limited, dropped = t.dropped + EXCLUDED.dropped,
			queue_depth = EXCLUDED.queue_depth`,
		instance, d[0], d[1], d[2], d[3], d[4], d[5], depth)
	if err != nil {
		return fmt.Errorf("eventd: write stats: %w", err)
	}
	s.flushed = cur
	return nil
}

/* Healthy reports whether instance wrote its stats within the last 30 s, by the database clock. */
func Healthy(ctx context.Context, pool *pgxpool.Pool, instance string) error {
	var fresh bool
	err := pool.QueryRow(ctx, `SELECT coalesce(bool_or(updated_at >= now() - make_interval(secs => $2)), false)
		FROM events.eventd_stats WHERE instance = $1`, instance, healthyWithin.Seconds()).Scan(&fresh)
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	if !fresh {
		return fmt.Errorf("healthcheck: no stats of eventd %q within %v", instance, healthyWithin)
	}
	return nil
}
