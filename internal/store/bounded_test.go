package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/store"
	"github.com/beekamai/network-scheme/internal/testdb"
)

func TestBoundedReadTimesOutAndIsReadOnly(t *testing.T) {
	pool := testdb.New(t).Pool("nms_api")
	ctx := context.Background()
	err := store.BoundedRead(ctx, pool, 50*time.Millisecond, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT pg_sleep(2)`)
		return err
	})
	if !errors.Is(err, store.ErrTimeout) {
		t.Fatalf("slow statement: %v", err)
	}
	var setting string
	if err := store.BoundedRead(ctx, pool, 1500*time.Millisecond, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SHOW statement_timeout`).Scan(&setting)
	}); err != nil || setting != "1500ms" {
		t.Fatalf("statement_timeout = %q, %v", setting, err)
	}
	/* SET LOCAL: the pooled connection keeps no limit afterwards. */
	if err := pool.QueryRow(ctx, `SHOW statement_timeout`).Scan(&setting); err != nil || setting != "0" {
		t.Fatalf("statement_timeout after the transaction = %q, %v", setting, err)
	}
	err = store.BoundedRead(ctx, pool, time.Second, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `CREATE TEMP TABLE x (i int)`)
		return err
	})
	if err == nil || errors.Is(err, store.ErrTimeout) {
		t.Fatalf("write in a bounded read: %v", err)
	}
}

func TestBoundedSnapshotIsRepeatableRead(t *testing.T) {
	pool := testdb.New(t).Pool("nms_api")
	ctx := context.Background()
	var iso, ro, limit string
	if err := store.BoundedSnapshot(ctx, pool, 15*time.Second, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT current_setting('transaction_isolation'), current_setting('transaction_read_only'), current_setting('statement_timeout')`).Scan(&iso, &ro, &limit)
	}); err != nil || iso != "repeatable read" || ro != "on" || limit != "15s" {
		t.Fatalf("isolation %q, read only %q, statement_timeout %q: %v", iso, ro, limit, err)
	}
}
