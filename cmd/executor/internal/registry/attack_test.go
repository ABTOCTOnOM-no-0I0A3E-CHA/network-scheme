package registry_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/state"
	"github.com/beekamai/network-scheme/internal/testdb"
)

/* Attacks timed inside the executor's own transactions (the C1 class): each ends in freeze, nothing forged is sealed. */

func executor(t *testing.T, env *testdb.Env, dir string) (*registry.Registry, *freeze.Guard) {
	t.Helper()
	k, err := seal.Derive(&[32]byte{42})
	if err != nil {
		t.Fatal(err)
	}
	reg := registry.New(env.Pool("nms_executor"), k, filepath.Join(dir, "state"))
	return reg, freeze.New(reg, env.Pool("nms_executor"), slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func grant(user int) func(context.Context, *registry.Snapshot, *registry.Tx) error {
	return func(_ context.Context, _ *registry.Snapshot, tx *registry.Tx) error {
		return tx.Put("write_grant", map[string]any{"user_id": user, "kind": "write", "write_group": "core", "username_snapshot": "u"})
	}
}

func forged(t *testing.T, env *testdb.Env) int {
	t.Helper()
	var n int
	if err := env.Pool("postgres").QueryRow(context.Background(),
		`SELECT count(*) FROM exec.write_grant WHERE username_snapshot = 'evil'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

/*
C1 PoC and the re-review's "second catalog check is blind" PoC: a trigger
created while a write runs, on registry_counter (forges a write-admin
grant), on the target table (rewrites the declared row) or on another
registry table. The write holds every registry table in EXCLUSIVE mode from
before its snapshot, so the DDL waits for the COMMIT and never fires inside
it: nothing forged is written; the next verification sees the trigger and
freezes, also after a restart.
*/
func TestTriggerCreatedDuringWriteWaitsAndFreezes(t *testing.T) {
	for name, c := range map[string]struct{ create, drop string }{
		"on registry_counter": {`CREATE TRIGGER forge AFTER UPDATE ON exec.registry_counter FOR EACH ROW EXECUTE FUNCTION attack.forge()`,
			`DROP TRIGGER forge ON exec.registry_counter`},
		"on the target table": {`CREATE TRIGGER forge BEFORE INSERT ON exec.write_grant FOR EACH ROW EXECUTE FUNCTION attack.rewrite()`,
			`DROP TRIGGER forge ON exec.write_grant`},
		"on another registry table": {`CREATE TRIGGER forge BEFORE UPDATE ON exec.model_profile FOR EACH ROW EXECUTE FUNCTION attack.rewrite()`,
			`DROP TRIGGER forge ON exec.model_profile`},
	} {
		t.Run(name, func(t *testing.T) {
			env := testdb.New(t)
			attacktest.Reset(t, env)
			attacktest.Tamper(t, env, `CREATE SCHEMA IF NOT EXISTS attack`)
			attacktest.Tamper(t, env, `CREATE OR REPLACE FUNCTION attack.forge() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN INSERT INTO exec.write_grant (user_id, kind, username_snapshot, version, mac)
					VALUES (66, 'write-admin', 'evil', NEW.seq, decode(repeat('00', 32), 'hex')); RETURN NEW; END $$`)
			attacktest.Tamper(t, env, `CREATE OR REPLACE FUNCTION attack.rewrite() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN NEW.username_snapshot := 'evil'; RETURN NEW; END $$`)
			dir := t.TempDir()
			reg, guard := executor(t, env, dir)
			if err := guard.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			created := make(chan error, 1)
			registry.SetHook(reg, func(stage string, _ pgx.Tx) {
				if stage == "verified" {
					go func() {
						_, err := env.Pool("postgres").Exec(context.Background(), c.create)
						created <- err
					}()
					time.Sleep(300 * time.Millisecond) /* the DDL is now queued behind the write's locks */
				}
			})
			if err := guard.Write(context.Background(), grant(1)); err != nil {
				t.Fatalf("write: %v", err)
			}
			registry.SetHook(reg, nil)
			if err := <-created; err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { attacktest.Tamper(t, env, c.drop) })
			if forged(t, env) != 0 {
				t.Fatal("forged row committed")
			}
			if err := guard.Check(context.Background()); !errors.Is(err, freeze.ErrFrozen) {
				t.Fatalf("check with the trigger: %v", err)
			}
			_, guard = executor(t, env, dir)
			if err := guard.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := guard.Check(context.Background()); !errors.Is(err, freeze.ErrFrozen) {
				t.Fatalf("restart: %v", err)
			}
		})
	}
}

/* within runs fn and fails the test if it has not returned after d (fn may then stay blocked). */
func within(t *testing.T, d time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s: still blocked after %v", what, d)
	}
}

func alerts(t *testing.T, env *testdb.Env, kind, severity string) int {
	t.Helper()
	var n int
	if err := env.Pool("postgres").QueryRow(context.Background(),
		`SELECT count(*) FROM execpub.alert WHERE kind = $1 AND severity = $2`, kind, severity).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

/*
Review I1 PoC: a superuser stops (SIGSTOP) the backend of a write in flight,
so neither lock_timeout nor statement_timeout ever fires and the write holds
the registry's lock. Callers waiting for the lock give up with their context
and count as failed verifications (the unverifiable alert goes out); a
freeze is still marked sticky in the state file and alerted at once; the
stalled write ends at its client-side deadline; a restart comes up frozen.
*/
func TestStalledBackendDoesNotStallTheFreeze(t *testing.T) {
	env := testdb.New(t)
	attacktest.Reset(t, env)
	dir := t.TempDir()
	reg, guard := executor(t, env, dir)
	const op = 6 * time.Second
	registry.SetTimeouts(reg, op, time.Second)
	ctx := context.Background()
	if err := guard.Start(ctx); err != nil {
		t.Fatal(err)
	}
	pids, stopped := make(chan uint32, 1), make(chan struct{})
	registry.SetHook(reg, func(stage string, tx pgx.Tx) {
		if stage == "verified" {
			pids <- tx.Conn().PgConn().PID()
			<-stopped
		}
	})
	began := time.Now()
	wrote := make(chan error, 1)
	go func() { wrote <- guard.Write(ctx, grant(1)) }()
	t.Cleanup(attacktest.Stall(t, env, <-pids))
	close(stopped)

	for i := range 3 {
		var err error
		within(t, 2*time.Second, "check", func() {
			cctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
			defer cancel()
			err = guard.Check(cctx)
		})
		if err == nil || errors.Is(err, freeze.ErrFrozen) {
			t.Fatalf("check %d while stalled: %v", i, err)
		}
	}
	if n := alerts(t, env, freeze.KindUnverifiable, "high"); n != 1 {
		t.Fatalf("unverifiable alerts %d", n)
	}

	triggered := make(chan struct{})
	go func() { defer close(triggered); guard.Trigger(ctx, freeze.KindTamper, "stalled") }()
	k, err := seal.Derive(&[32]byte{42})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		f, err := state.Load(filepath.Join(dir, "state"), k.State())
		if err == nil && f.Frozen && alerts(t, env, freeze.KindTamper, "disaster") == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no sticky freeze or disaster alert while the write is stalled: %+v %v", f, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if time.Since(began) >= op {
		t.Fatal("the stalled write ended before the freeze was checked: the test proves nothing")
	}

	select {
	case err := <-wrote:
		if err == nil {
			t.Fatal("the stalled write reported success")
		}
	case <-time.After(op + 5*time.Second):
		t.Fatal("the stalled write never ended")
	}
	_, guard = executor(t, env, dir)
	if err := guard.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := guard.Check(ctx); !errors.Is(err, freeze.ErrFrozen) {
		t.Fatalf("restart: %v", err)
	}
	within(t, 30*time.Second, "trigger", func() { <-triggered })
}

/*
C1 PoC: a row planted between the fresh-install check and the bootstrap's
first insert. The check now runs under table locks inside the bootstrap
transaction, so the planted row is seen: the bootstrap is refused and the
executor freezes, the row is never sealed.
*/
func TestRowPlantedDuringBootstrapFreezes(t *testing.T) {
	env := testdb.New(t)
	attacktest.Reset(t, env)
	reg, guard := executor(t, env, t.TempDir())
	registry.SetHook(reg, func(stage string, _ pgx.Tx) {
		if stage == "begin" {
			attacktest.Tamper(t, env, `INSERT INTO exec.write_grant (user_id, kind, username_snapshot, version, mac)
				VALUES (66, 'write-admin', 'evil', 1, decode(repeat('00', 32), 'hex'))`)
		}
	})
	if err := guard.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := guard.Check(context.Background()); !errors.Is(err, freeze.ErrFrozen) {
		t.Fatalf("check: %v", err)
	}
	var n int
	if err := env.Pool("postgres").QueryRow(context.Background(), `SELECT count(*) FROM exec.registry_counter`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("bootstrap went on: %d %v", n, err)
	}
}
