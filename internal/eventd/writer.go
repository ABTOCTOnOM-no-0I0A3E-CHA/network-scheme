package eventd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	attemptTimeout = 10 * time.Second /* one COPY or INSERT; a paused database must not hang the writer */
	backoffStart   = 250 * time.Millisecond
	backoffMax     = 5 * time.Second
)

var (
	syslogCols = []string{"ts", "device_id", "facility", "severity", "host", "app", "msg", "raw_len"}
	trapCols   = []string{"ts", "device_id", "version", "trap_oid", "name", "severity", "varbinds", "identified"}
	stormCols  = []string{"ts", "device_id", "kind", "count"}
)

/*
writer inserts batches. A batch is one COPY per table. When the database is not
reachable (or busy) the batch is kept and retried with backoff: meanwhile the
queue fills up and the receivers count drops, nothing blocks them. When the
database refuses data (a constraint, an encoding error) the batch falls back to
single INSERTs so that one bad row never costs the other rows; the refused rows
are counted.
*/
type writer struct {
	pool *pgxpool.Pool
	st   *stats
	log  *slog.Logger
	size int
	wait time.Duration
}

/* run writes until the queue is closed and empty, or ctx ends (the rest is then dropped and counted). */
func (w *writer) run(ctx context.Context, q *queue) {
	for {
		batch, ok := q.next(w.size, w.wait)
		if !ok {
			return
		}
		w.write(ctx, batch)
	}
}

func (w *writer) write(ctx context.Context, batch []event) {
	var sys, trp, stm [][]any
	for _, e := range batch {
		switch e.kind {
		case kindSyslog:
			sys = append(sys, []any{e.ts, e.dev, e.facility, e.severity, e.host, e.app, e.msg, e.rawLen})
		case kindTrap:
			var sev any
			if e.sev != "" {
				sev = e.sev
			}
			trp = append(trp, []any{e.ts, e.dev, e.version, e.trapOID, e.name, sev, e.varbinds, e.identified})
		case kindStorm:
			stm = append(stm, []any{e.ts, e.dev, e.stormKind, e.count})
		}
	}
	w.table(ctx, "syslog", syslogCols, sys)
	w.table(ctx, "trap", trapCols, trp)
	w.table(ctx, "storm", stormCols, stm)
}

func (w *writer) table(ctx context.Context, name string, cols []string, rows [][]any) {
	if len(rows) == 0 {
		return
	}
	backoff := backoffStart
	for {
		err := w.copyRows(ctx, name, cols, rows)
		switch {
		case err == nil:
			return
		case ctx.Err() != nil:
			w.st.dropped.Add(uint64(len(rows)))
			return
		case !retryable(err):
			w.rowByRow(ctx, name, cols, rows)
			return
		}
		w.log.Warn("event write failed, retrying", slog.String("table", name), slog.Int("rows", len(rows)),
			slog.String("err", err.Error()), slog.Duration("in", backoff))
		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, backoffMax)
	}
}

func (w *writer) copyRows(ctx context.Context, name string, cols []string, rows [][]any) error {
	ctx, cancel := context.WithTimeout(ctx, attemptTimeout)
	defer cancel()
	_, err := w.pool.CopyFrom(ctx, pgx.Identifier{"events", name}, cols, pgx.CopyFromRows(rows))
	return err
}

/* rowByRow stores what the database accepts; the others are counted as rejected and dropped. */
func (w *writer) rowByRow(ctx context.Context, name string, cols []string, rows [][]any) {
	ph := make([]string, len(cols))
	for i := range ph {
		ph[i] = fmt.Sprintf("$%d", i+1)
	}
	sql := "INSERT INTO events." + name + " (" + strings.Join(cols, ", ") + ") VALUES (" + strings.Join(ph, ", ") + ")"
	var bad uint64
	for _, r := range rows {
		for {
			cctx, cancel := context.WithTimeout(ctx, attemptTimeout)
			_, err := w.pool.Exec(cctx, sql, r...)
			cancel()
			if err == nil {
				break
			}
			if ctx.Err() != nil || !retryable(err) {
				bad++
				break
			}
			select { /* the database went away in the middle of the fallback */
			case <-ctx.Done():
			case <-time.After(backoffStart):
			}
		}
	}
	if bad > 0 {
		w.st.rejected.Add(bad)
		w.st.dropped.Add(bad)
		w.log.Warn("rows refused by the database", slog.String("table", name), slog.Uint64("rows", bad))
	}
}

/*
retryable reports whether the same statement may succeed later: any failure that
is not a verdict of the server on the data (network, timeout, closed pool), and
the server states "not now" (class 08 connection, 53 resources, 57 operator
intervention, serialization failures).
*/
func retryable(err error) bool {
	var pe *pgconn.PgError
	if !errors.As(err, &pe) {
		return true
	}
	c := pe.Code
	return strings.HasPrefix(c, "08") || strings.HasPrefix(c, "53") || strings.HasPrefix(c, "57") || c == "40001" || c == "40P01"
}
