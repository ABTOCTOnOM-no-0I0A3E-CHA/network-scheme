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

/* A table over its row bound is tampering, even with valid MACs (fail closed). */
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
	if err := grant(ctx, r, 3); !errors.Is(err, ErrTampered) {
		t.Fatalf("third grant: %v", err)
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
