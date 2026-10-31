package registry_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

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
C1 PoC: a trigger created after the executor checked the catalog, on
registry_counter (forges a write-admin grant inside the executor's
transaction) or on the target table (rewrites the declared row). The write
is refused as tampering, the guard freezes, and nothing forged is left
sealed once the trigger is gone.
*/
func TestTriggerCreatedDuringWriteFreezes(t *testing.T) {
	for name, ddl := range map[string]string{
		"on registry_counter": `CREATE TRIGGER forge AFTER UPDATE ON exec.registry_counter FOR EACH ROW EXECUTE FUNCTION attack.forge()`,
		"on the target table": `CREATE TRIGGER forge BEFORE INSERT ON exec.write_grant FOR EACH ROW EXECUTE FUNCTION attack.rewrite()`,
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
			registry.SetHook(reg, func(stage string, _ pgx.Tx) {
				if stage == "verified" {
					attacktest.Tamper(t, env, ddl)
				}
			})
			if err := guard.Write(context.Background(), grant(1)); !errors.Is(err, freeze.ErrFrozen) {
				t.Fatalf("write: %v", err)
			}
			registry.SetHook(reg, nil)
			attacktest.Tamper(t, env, dropTrigger(name))
			if forged(t, env) != 0 {
				t.Fatal("forged row committed")
			}
			if frozen, _ := guard.Frozen(); !frozen {
				t.Fatal("not frozen")
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

func dropTrigger(name string) string {
	if name == "on registry_counter" {
		return `DROP TRIGGER forge ON exec.registry_counter`
	}
	return `DROP TRIGGER forge ON exec.write_grant`
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
