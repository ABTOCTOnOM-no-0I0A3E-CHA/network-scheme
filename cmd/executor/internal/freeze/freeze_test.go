package freeze_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/state"
	"github.com/beekamai/network-scheme/internal/testdb"
)

func TestMain(m *testing.M) { testdb.Main(m) }

var master = [32]byte{7}

/* executor is one executor process: its registry and guard over the test database and a state file. */
type executor struct {
	env   *testdb.Env
	keys  *seal.Keys
	path  string
	reg   *registry.Registry
	guard *freeze.Guard
}

func start(t *testing.T, env *testdb.Env, path string) *executor {
	t.Helper()
	k, err := seal.Derive(&master)
	if err != nil {
		t.Fatal(err)
	}
	e := &executor{env: env, keys: k, path: path}
	e.reg = registry.New(env.Pool("nms_executor"), k, path)
	e.guard = freeze.New(e.reg, env.Pool("nms_executor"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := e.guard.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *executor) restart(t *testing.T) *executor { t.Helper(); return start(t, e.env, e.path) }

/* seeded is a fresh install with two grants and one write device, not frozen. */
func seeded(t *testing.T) *executor {
	t.Helper()
	env := testdb.New(t)
	attacktest.Reset(t, env)
	e := start(t, env, filepath.Join(t.TempDir(), "state"))
	e.grant(t, 1)
	e.grant(t, 2)
	e.write(t, `INSERT INTO exec.write_device (device_id, address, write_group, write_driver, version, mac)
		VALUES (1, '10.0.0.1', 'core', 'esr', $1, $2)`)
	if err := e.guard.Check(context.Background()); err != nil {
		t.Fatalf("seeded registry: %v", err)
	}
	return e
}

/* write runs one registry change; sql takes $1 = version and $2 = placeholder MAC. */
func (e *executor) write(t *testing.T, sql string) {
	t.Helper()
	if err := e.reg.Write(context.Background(), func(ctx context.Context, tx *registry.Tx) error {
		_, err := tx.Exec(ctx, sql, tx.Seq(), registry.Unsealed())
		return err
	}); err != nil {
		t.Fatalf("write %q: %v", sql, err)
	}
}

func (e *executor) grant(t *testing.T, user int) {
	t.Helper()
	e.write(t, `INSERT INTO exec.write_grant (user_id, kind, write_group, username_snapshot, version, mac)
		VALUES (`+strconv.Itoa(user)+`, 'write', 'core', 'u', $1, $2)`)
}

func (e *executor) alerts(t *testing.T) int {
	t.Helper()
	var n int
	if err := e.env.Pool("postgres").QueryRow(context.Background(),
		`SELECT count(*) FROM execpub.alert WHERE kind = 'executor_tamper' AND severity = 'disaster'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

/* mustFreeze: the next decision is refused, the latch is set and a disaster alert is out. */
func (e *executor) mustFreeze(t *testing.T) {
	t.Helper()
	if err := e.guard.Check(context.Background()); !errors.Is(err, freeze.ErrFrozen) {
		t.Fatalf("decision allowed: %v", err)
	}
	if frozen, reason := e.guard.Frozen(); !frozen || reason == "" {
		t.Fatalf("latch %v %q", frozen, reason)
	}
	if e.alerts(t) == 0 {
		t.Fatal("no disaster alert")
	}
}

func TestFreshInstallIsNotFrozen(t *testing.T) {
	e := seeded(t)
	if frozen, _ := e.guard.Frozen(); frozen || e.alerts(t) != 0 {
		t.Fatal("fresh install frozen")
	}
	e = e.restart(t)
	if err := e.guard.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
}

/* Each tampering with the database ends in freeze + disaster (C2e, C2f, security.md 5.1a). */
func TestDatabaseTamperingFreezes(t *testing.T) {
	for name, attack := range map[string]func(t *testing.T, e *executor){
		"C2e wrong MAC": func(t *testing.T, e *executor) {
			attacktest.Tamper(t, e.env, `UPDATE exec.write_device SET port = 23`)
		},
		"C2e MAC of another row": func(t *testing.T, e *executor) {
			attacktest.Tamper(t, e.env, `UPDATE exec.write_grant SET mac = (SELECT mac FROM exec.write_grant WHERE user_id = 1) WHERE user_id = 2`)
		},
		"C2e planted row": func(t *testing.T, e *executor) {
			attacktest.Tamper(t, e.env, `INSERT INTO exec.write_grant (user_id, kind, username_snapshot, version, mac)
				VALUES (9, 'write-admin', 'evil', 1, decode(repeat('00', 32), 'hex'))`)
		},
		"C2f old exec_state without freeze": func(t *testing.T, e *executor) {
			restore := attacktest.Copy(t, e.env, "exec_state")
			e.write(t, `UPDATE exec.exec_state SET "freeze" = true, freeze_reason = 'host', version = $1, mac = $2`)
			restore()
		},
		"C2f revoked grant restored": func(t *testing.T, e *executor) {
			restore := attacktest.Copy(t, e.env, "write_grant")
			e.write(t, `DELETE FROM exec.write_grant WHERE user_id = 2 AND version < $1 AND $2::bytea IS NOT NULL`)
			restore()
		},
		"deleted row": func(t *testing.T, e *executor) {
			attacktest.Tamper(t, e.env, `DELETE FROM exec.write_device`)
		},
		"deleted exec_state": func(t *testing.T, e *executor) {
			attacktest.Tamper(t, e.env, `DELETE FROM exec.exec_state`)
		},
		"registry_counter rolled back": func(t *testing.T, e *executor) {
			restore := attacktest.Copy(t, e.env, "registry_counter")
			e.grant(t, 3)
			restore()
		},
		"whole registry replayed": func(t *testing.T, e *executor) {
			var restores []func()
			for _, tb := range []string{"registry_counter", "write_grant", "write_device", "exec_state"} {
				restores = append(restores, attacktest.Copy(t, e.env, tb))
			}
			e.write(t, `UPDATE exec.write_device SET writes_enabled = false, version = $1, mac = $2`)
			for _, r := range restores {
				r()
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := seeded(t)
			attack(t, e)
			e.mustFreeze(t)
			/* The tampered state is never sealed: the freeze is in the state file, not laundered into the registry. */
			if f, err := state.Load(e.path, e.keys.State()); err != nil || !f.Frozen {
				t.Fatalf("state file not frozen: %+v %v", f, err)
			}
			if _, err := e.reg.Verify(context.Background()); !errors.Is(err, registry.ErrTampered) {
				t.Fatalf("registry verifies after tampering: %v", err)
			}
			e.restart(t).mustFreeze(t)
		})
	}
}

/* Removing or replacing the state file while the registry is not empty freezes the next start. */
func TestStateFileTamperingFreezes(t *testing.T) {
	for name, attack := range map[string]func(t *testing.T, e *executor){
		"deleted": func(t *testing.T, e *executor) {
			if err := os.Remove(e.path); err != nil {
				t.Fatal(err)
			}
		},
		"replaced by an older copy": func(t *testing.T, e *executor) {
			old, err := os.ReadFile(e.path)
			if err != nil {
				t.Fatal(err)
			}
			e.grant(t, 3)
			if err := os.WriteFile(e.path, old, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"from another install": func(t *testing.T, e *executor) {
			f, err := state.Load(e.path, e.keys.State())
			if err != nil {
				t.Fatal(err)
			}
			other, _ := seal.Derive(&[32]byte{8})
			if err := state.Save(e.path, other.State(), f); err != nil {
				t.Fatal(err)
			}
		},
		"garbage": func(t *testing.T, e *executor) {
			if err := os.WriteFile(e.path, []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := seeded(t)
			attack(t, e)
			e.restart(t).mustFreeze(t)
		})
	}
}

/*
The freeze outlives restarts, even once the database is put back exactly as
it was and Verify passes again: lifting it is host-only (nmsctl, 4a.4).
*/
func TestFreezeSurvivesRestart(t *testing.T) {
	e := seeded(t)
	attacktest.Tamper(t, e.env, `UPDATE exec.write_device SET port = 23`)
	e.mustFreeze(t)
	e = e.restart(t)
	e.mustFreeze(t)
	attacktest.Tamper(t, e.env, `UPDATE exec.write_device SET port = 22`)
	if _, err := e.reg.Verify(context.Background()); err != nil {
		t.Fatalf("verify after repair: %v", err)
	}
	e = e.restart(t)
	if err := e.guard.Check(context.Background()); !errors.Is(err, freeze.ErrFrozen) {
		t.Fatalf("repaired database unfroze the executor: %v", err)
	}
}

/* A freeze over a sound registry is recorded in exec_state (sealed), the state file and one alert per kind. */
func TestTriggerRecordsTheFreeze(t *testing.T) {
	e := seeded(t)
	ctx := context.Background()
	e.guard.Trigger(ctx, freeze.KindTamper, "requested")
	e.guard.Trigger(ctx, freeze.KindTamper, "again")
	e.mustFreeze(t)
	if n := e.alerts(t); n != 1 {
		t.Fatalf("alerts %d", n)
	}
	rep, err := e.reg.Verify(ctx)
	if err != nil || !rep.Frozen || rep.Reason != "requested" {
		t.Fatalf("report %+v, %v", rep, err)
	}
	var frozen bool
	var reason string
	if err := e.env.Pool("postgres").QueryRow(ctx, `SELECT "freeze", freeze_reason FROM exec.exec_state`).Scan(&frozen, &reason); err != nil || !frozen || reason != "requested" {
		t.Fatalf("exec_state %v %q %v", frozen, reason, err)
	}
	if err := e.restart(t).guard.Check(ctx); !errors.Is(err, freeze.ErrFrozen) {
		t.Fatalf("after restart: %v", err)
	}
}
