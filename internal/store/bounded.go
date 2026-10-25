package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrTimeout means a statement of BoundedRead ran longer than its limit and was cancelled by the server.
var ErrTimeout = errors.New("store: statement timeout")

/*
BoundedRead runs fn in a read-only transaction whose statements the server
cancels after timeout each (SET LOCAL statement_timeout); a cancelled
statement is ErrTimeout. A cancellation by ctx stays the context's error.
*/
func BoundedRead(ctx context.Context, pool *pgxpool.Pool, timeout time.Duration, fn func(pgx.Tx) error) error {
	err := pgx.BeginTxFunc(ctx, pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		ms := strconv.FormatInt(max(timeout.Milliseconds(), 1), 10)
		if _, err := tx.Exec(ctx, `SELECT set_config('statement_timeout', $1, true)`, ms); err != nil {
			return err
		}
		return fn(tx)
	})
	var pe *pgconn.PgError
	if err != nil && ctx.Err() == nil && errors.As(err, &pe) && pe.Code == "57014" { /* query_canceled */
		return fmt.Errorf("%w: %w", ErrTimeout, err)
	}
	return err
}

// QueryTimeout is the statement limit of interactive reads that scan large tables (search, dashboard aggregates).
const QueryTimeout = 2 * time.Second
