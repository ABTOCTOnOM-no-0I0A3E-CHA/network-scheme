package eventd

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
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
	/* retryBase is the first retry delay; zero selects the default (tests). */
	retryBase time.Duration
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
	backoff, unknown := cmp.Or(w.retryBase, backoffStart), 0
	for {
		err := w.copyRows(ctx, name, cols, rows)
		switch c := classify(err); {
		case err == nil:
			return
		case ctx.Err() != nil:
			w.st.dropped.Add(uint64(len(rows)))
			return
		case c == errData, c == errUnknown && unknown >= maxUnknownTries:
			w.rowByRow(ctx, name, cols, rows)
			return
		case c == errUnknown:
			unknown++
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
			/*
				A single INSERT cannot fail at the client as "query canceled" (an
				encoding error is not a PgError), so 57014 here is the server
				cancelling the statement (restart, admin): retry, do not drop.
			*/
			var pe *pgconn.PgError
			canceled := errors.As(err, &pe) && pe.Code == "57014"
			if ctx.Err() != nil || (classify(err) != errTransient && !canceled) {
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

type errClass int

const (
	errTransient errClass = iota /* the same statement may succeed later */
	errData                      /* the server refused the data */
	errUnknown                   /* a client-side error of no known kind */
)

/* maxUnknownTries bounds the retries of an error that is neither a server verdict nor a connectivity problem. */
const maxUnknownTries = 5

/*
classify sorts a failed statement. Transient: connectivity (network, timeouts,
closed connections) and the server saying "not now" (class 08 connection, 53
resources, 57 operator intervention, serialization failures); retried for as
long as it takes. Data: any other verdict of the server; the rows go one by
one. Unknown: a client-side error that is not recognizably connectivity (for
example an encoding error, which no retry fixes); retried a few times, then
the rows go one by one.
*/
func classify(err error) errClass {
	if err == nil {
		return errTransient
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		c := pe.Code
		if c == "57014" { /* query_canceled: also how pgx reports a COPY aborted by a client-side encoding error */
			return errUnknown
		}
		if strings.HasPrefix(c, "08") || strings.HasPrefix(c, "53") || strings.HasPrefix(c, "57") || c == "40001" || c == "40P01" {
			return errTransient
		}
		return errData
	}
	var ne net.Error
	var ce *pgconn.ConnectError
	if errors.As(err, &ne) || errors.As(err, &ce) || pgconn.Timeout(err) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return errTransient
	}
	return errUnknown
}
