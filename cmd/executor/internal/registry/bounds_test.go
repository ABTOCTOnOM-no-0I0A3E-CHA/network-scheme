package registry

import (
	"context"
	"errors"
	"runtime"
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/internal/store"
)

/*
Many planted rows (no MAC key) cannot make the executor hold them: the read
stops at the first row whose MAC fails, so a superuser cannot exhaust the
executor's memory (and have it restarted) with rows it deletes afterwards.
*/
func TestPlantedRowsDoNotFillMemory(t *testing.T) {
	env, r := fresh(t)
	ctx := context.Background()
	attacktest.Tamper(t, env, `INSERT INTO exec.write_credential (device_id, kind, ciphertext, created_at, nonce, version, mac)
		SELECT g, 'ssh_write', decode(repeat('ab', 4000), 'hex'), now(), decode(repeat('00', 16), 'hex'), 1, decode(repeat('11', 32), 'hex')
		FROM generate_series(1, 20000) g`)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := r.Verify(ctx)
	runtime.ReadMemStats(&after)
	if !errors.Is(err, ErrTampered) {
		t.Fatalf("planted rows: %v", err)
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > 32<<20 {
		t.Fatalf("verifying allocated %d MiB for rows it refuses", got>>20)
	}
}

/*
The writer refuses a change that would cross a table's row bound with
ErrFull before writing (no freeze: the registry still verifies); a table
over its bound when read is tampering, even with valid MACs (fail closed).
*/
func TestRowBound(t *testing.T) {
	_, r := fresh(t)
	ctx := context.Background()
	old := maxRows["write_grant"]
	maxRows["write_grant"] = 2
	defer func() { maxRows["write_grant"] = old }()
	for _, u := range []int64{1, 2} {
		if err := grant(ctx, r, u); err != nil {
			t.Fatal(err)
		}
	}
	if err := grant(ctx, r, 3); !errors.Is(err, ErrFull) || errors.Is(err, ErrTampered) {
		t.Fatalf("third grant: %v, want ErrFull", err)
	}
	if err := grant(ctx, r, 2); err != nil {
		t.Fatalf("replacing a row at the bound: %v", err)
	}
	if _, err := r.Verify(ctx); err != nil {
		t.Fatalf("a refused write froze the registry: %v", err)
	}
	maxRows["write_grant"] = 1
	if _, err := r.Verify(ctx); !errors.Is(err, ErrTampered) {
		t.Fatalf("two rows read over a bound of one: %v", err)
	}
}

/* The same for the byte bound of the snapshot. */
func TestByteBound(t *testing.T) {
	_, r := fresh(t)
	ctx := context.Background()
	if err := grant(ctx, r, 1); err != nil {
		t.Fatal(err)
	}
	size := 0
	if err := r.View(ctx, func(s *Snapshot) error {
		for _, rw := range s.rows {
			size += rowSize(rw.pk) + rowSize(rw.content)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	old := maxSnapshotBytes
	defer func() { maxSnapshotBytes = old }()
	maxSnapshotBytes = size + 4 /* one more grant row does not fit */
	if err := grant(ctx, r, 2); !errors.Is(err, ErrFull) || errors.Is(err, ErrTampered) {
		t.Fatalf("grant over the byte bound: %v, want ErrFull", err)
	}
	if _, err := r.Verify(ctx); err != nil {
		t.Fatalf("a refused write froze the registry: %v", err)
	}
	maxSnapshotBytes = size - 1
	if _, err := r.Verify(ctx); !errors.Is(err, ErrTampered) {
		t.Fatalf("a snapshot read over the byte bound: %v", err)
	}
}

/* Every registry table has a row bound (a missing entry is 0: its first row would freeze), and no bound names a table that is gone. */
func TestEveryTableHasRowBound(t *testing.T) {
	for _, tb := range tables {
		if maxRows[tb.name] <= 0 {
			t.Errorf("table %s has no row bound", tb.name)
		}
	}
	if len(maxRows) != len(tables) {
		t.Errorf("%d row bounds for %d tables", len(maxRows), len(tables))
	}
}

/* The bounds are the ones security.md 5.2 documents. */
func TestBoundsAsDocumented(t *testing.T) {
	want := map[string]int{"registry_counter": 1, "exec_state": 1, "write_device": 10000, "write_credential": 10000,
		"write_grant": 20000, "change_totp": 10000, "model_profile": 1024}
	for k, v := range want {
		if maxRows[k] != v {
			t.Errorf("maxRows[%s] = %d, documented %d", k, maxRows[k], v)
		}
	}
	if maxSnapshotBytes != 64<<20 || MaxMessage != 1<<20 {
		t.Errorf("maxSnapshotBytes = %d, MaxMessage = %d; documented 64 MiB and 1 MiB", maxSnapshotBytes, MaxMessage)
	}
}

/*
A message over MaxMessage from the database is tampering, not a failed
verification: a constraint with a 2 MiB definition (only a superuser can add
one) freezes instead of leaving the executor merely unverifiable.
*/
func TestOversizedMessageIsTampering(t *testing.T) {
	env, r := fresh(t)
	ctx := context.Background()
	db, pw := env.Config("nms_executor")
	pool, err := store.Open(ctx, db, pw, PinSession, BoundMessages)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	attacktest.Tamper(t, env, `DO $$ BEGIN EXECUTE format('ALTER TABLE exec.write_device ADD CONSTRAINT zz_big CHECK (port > 0 OR %L = '''')', repeat('a', 2097152)); END $$`)
	t.Cleanup(func() { attacktest.Tamper(t, env, `ALTER TABLE exec.write_device DROP CONSTRAINT zz_big`) })
	if _, err := New(pool, keys(t), r.path).Verify(ctx); !errors.Is(err, ErrTampered) {
		t.Fatalf("oversized catalog message: %v", err)
	}
}
