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
