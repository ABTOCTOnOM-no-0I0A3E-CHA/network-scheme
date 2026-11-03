package freeze_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/state"
	"github.com/beekamai/network-scheme/internal/store"
	"github.com/beekamai/network-scheme/internal/testdb"
)

func TestMain(m *testing.M) { testdb.Main(m) }

var master = [32]byte{7}

/* executor is one executor process: its registry and guard over the test database and a state file. */
type executor struct {
	env   *testdb.Env
	pool  *pgxpool.Pool
	keys  *seal.Keys
	path  string
	reg   *registry.Registry
	guard *freeze.Guard
}

func startOn(t *testing.T, env *testdb.Env, pool *pgxpool.Pool, path string) *executor {
	t.Helper()
	k, err := seal.Derive(&master)
	if err != nil {
		t.Fatal(err)
	}
	e := &executor{env: env, pool: pool, keys: k, path: path}
	e.reg = registry.New(pool, k, path)
	e.guard = freeze.New(e.reg, pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := e.guard.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	return e
}

func start(t *testing.T, env *testdb.Env, path string) *executor {
	t.Helper()
	return startOn(t, env, env.Pool("nms_executor"), path)
}

func (e *executor) restart(t *testing.T) *executor {
	t.Helper()
	return startOn(t, e.env, e.pool, e.path)
}

/* seeded is a fresh install with a row in every registry table, not frozen. */
func seeded(t *testing.T) *executor {
	t.Helper()
	env := testdb.New(t)
	attacktest.Reset(t, env)
	e := start(t, env, filepath.Join(t.TempDir(), "state"))
	e.grant(t, 1)
	e.grant(t, 2)
	e.put(t, "write_device", map[string]any{"device_id": 1, "address": netip.MustParseAddr("10.0.0.1"), "port": 22,
		"protocol": "ssh", "write_group": "core", "write_driver": "esr", "hostkey_algo": nil, "hostkey_fp": nil,
		"allow_ssh_rsa_sha1": false, "writes_enabled": false, "backup_via_executor": false})
	e.put(t, "change_totp", map[string]any{"user_id": 1, "username_snapshot": "u", "ciphertext": []byte{1, 2, 3},
		"key_version": 1, "last_step": 10, "failures": 0, "lock_until": nil, "lock_count": 0})
	e.put(t, "model_profile", map[string]any{"id": 1, "write_driver": "esr", "model_re": "^ESR", "firmware_re": ".",
		"strategies": json.RawMessage(`{}`), "note": "n"})
	e.put(t, "write_credential", map[string]any{"device_id": 1, "kind": "ssh_write", "ciphertext": []byte{9, 9},
		"created_at": time.Now(), "nonce": make([]byte, 16)})
	if err := e.guard.Check(context.Background()); err != nil {
		t.Fatalf("seeded registry: %v", err)
	}
	return e
}

func (e *executor) put(t *testing.T, table string, vals map[string]any) {
	t.Helper()
	if err := e.guard.Write(context.Background(), func(_ context.Context, _ *registry.Snapshot, tx *registry.Tx) error {
		return tx.Put(table, vals)
	}); err != nil {
		t.Fatalf("put %s: %v", table, err)
	}
}

func (e *executor) grant(t *testing.T, user int) {
	t.Helper()
	e.put(t, "write_grant", map[string]any{"user_id": user, "kind": "write", "write_group": "core", "username_snapshot": "u"})
}

func (e *executor) alerts(t *testing.T, kind, severity string) int {
	t.Helper()
	var n int
	if err := e.env.Pool("postgres").QueryRow(context.Background(),
		`SELECT count(*) FROM execpub.alert WHERE kind = $1 AND severity = $2`, kind, severity).Scan(&n); err != nil {
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
	if e.alerts(t, freeze.KindTamper, "disaster") == 0 {
		t.Fatal("no disaster alert")
	}
	if err := e.guard.Write(context.Background(), func(context.Context, *registry.Snapshot, *registry.Tx) error { return nil }); !errors.Is(err, freeze.ErrFrozen) {
		t.Fatalf("write allowed: %v", err)
	}
}

func TestFreshInstallIsNotFrozen(t *testing.T) {
	e := seeded(t)
	if frozen, _ := e.guard.Frozen(); frozen || e.alerts(t, freeze.KindTamper, "disaster") != 0 {
		t.Fatal("fresh install frozen")
	}
	if err := e.restart(t).guard.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
}

type attack struct {
	do   func(t *testing.T, e *executor)
	undo string /* SQL that puts the schema back for the next test */
}

func tamper(sql string) func(t *testing.T, e *executor) {
	return func(t *testing.T, e *executor) { attacktest.Tamper(t, e.env, sql) }
}

/* Each tampering with the database ends in freeze + disaster (C2e, C2f, C1, C2, M1, security.md 5.1a). */
func TestDatabaseTamperingFreezes(t *testing.T) {
	registryTables := []string{"registry_counter", "write_device", "write_grant", "change_totp", "exec_state",
		"model_profile", "write_credential"}
	for name, a := range map[string]attack{
		"C2e wrong MAC":          {do: tamper(`UPDATE exec.write_device SET port = 23`)},
		"C2e MAC of another row": {do: tamper(`UPDATE exec.write_grant SET mac = (SELECT mac FROM exec.write_grant WHERE user_id = 1) WHERE user_id = 2`)},
		"C2e planted row": {do: tamper(`INSERT INTO exec.write_grant (user_id, kind, username_snapshot, version, mac)
			VALUES (9, 'write-admin', 'evil', 1, decode(repeat('00', 32), 'hex'))`)},
		"C2e ciphertext swapped": {do: tamper(`UPDATE exec.change_totp SET ciphertext = '\x010204'`)},
		"C2f old exec_state without freeze": {do: func(t *testing.T, e *executor) {
			restore := attacktest.Copy(t, e.env, "exec_state")
			e.put(t, "exec_state", map[string]any{"singleton": true, "freeze": true, "freeze_reason": "host",
				"global_fail_window": json.RawMessage(`[]`)})
			restore()
		}},
		"C2f revoked grant restored": {do: func(t *testing.T, e *executor) {
			restore := attacktest.Copy(t, e.env, "write_grant")
			if err := e.guard.Write(context.Background(), func(_ context.Context, _ *registry.Snapshot, tx *registry.Tx) error {
				return tx.Delete("write_grant", 2, "write", "core")
			}); err != nil {
				t.Fatal(err)
			}
			restore()
		}},
		"deleted row":        {do: tamper(`DELETE FROM exec.write_device`)},
		"deleted exec_state": {do: tamper(`DELETE FROM exec.exec_state`)},
		"registry_counter rolled back": {do: func(t *testing.T, e *executor) {
			r := attacktest.Copy(t, e.env, "registry_counter")
			e.grant(t, 3)
			r()
		}},
		"whole registry replayed": {do: func(t *testing.T, e *executor) {
			var restores []func()
			for _, tb := range registryTables {
				restores = append(restores, attacktest.Copy(t, e.env, tb))
			}
			e.put(t, "write_device", map[string]any{"device_id": 1, "address": netip.MustParseAddr("10.0.0.2"), "port": 22,
				"protocol": "ssh", "write_group": "core", "write_driver": "esr", "hostkey_algo": nil, "hostkey_fp": nil,
				"allow_ssh_rsa_sha1": false, "writes_enabled": false, "backup_via_executor": false})
			for _, r := range restores {
				r()
			}
		}},
		/* The catalog: anything that can make the database store or show other values than the executor's. */
		"trigger on registry_counter": {
			do: tamper(`CREATE SCHEMA IF NOT EXISTS attack;
				CREATE OR REPLACE FUNCTION attack.noop() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$;
				CREATE TRIGGER t AFTER UPDATE ON exec.registry_counter FOR EACH ROW EXECUTE FUNCTION attack.noop()`),
			undo: `DROP TRIGGER t ON exec.registry_counter`},
		"trigger on a registry table": {
			do: tamper(`CREATE SCHEMA IF NOT EXISTS attack;
				CREATE OR REPLACE FUNCTION attack.noop() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$;
				CREATE TRIGGER t BEFORE INSERT ON exec.write_grant FOR EACH ROW EXECUTE FUNCTION attack.noop()`),
			undo: `DROP TRIGGER t ON exec.write_grant`},
		"view in place of a table": {
			do: tamper(`ALTER TABLE exec.write_grant RENAME TO write_grant_real;
				CREATE VIEW exec.write_grant AS SELECT * FROM exec.write_grant_real WHERE user_id <> 2;
				GRANT SELECT ON exec.write_grant TO nms_executor`),
			undo: `DROP VIEW exec.write_grant; ALTER TABLE exec.write_grant_real RENAME TO write_grant`},
		"rule": {do: tamper(`CREATE RULE r AS ON INSERT TO exec.write_grant DO INSTEAD NOTHING`),
			undo: `DROP RULE r ON exec.write_grant`},
		"row-level security": {
			do: tamper(`ALTER TABLE exec.write_grant ENABLE ROW LEVEL SECURITY;
				CREATE POLICY hide ON exec.write_grant USING (user_id <> 2)`),
			undo: `DROP POLICY hide ON exec.write_grant; ALTER TABLE exec.write_grant DISABLE ROW LEVEL SECURITY`},
		"altered DEFAULT": {do: tamper(`ALTER TABLE exec.write_device ALTER COLUMN port SET DEFAULT 23`),
			undo: `ALTER TABLE exec.write_device ALTER COLUMN port SET DEFAULT 22`},
		"renamed column": {do: tamper(`ALTER TABLE exec.model_profile RENAME COLUMN note TO note2`),
			undo: `ALTER TABLE exec.model_profile RENAME COLUMN note2 TO note`},
		"dropped column": {do: tamper(`ALTER TABLE exec.write_device DROP COLUMN backup_via_executor`),
			undo: `ALTER TABLE exec.write_device ADD COLUMN backup_via_executor boolean NOT NULL DEFAULT false`},
		"NULL version": {do: tamper(`ALTER TABLE exec.write_grant ALTER COLUMN version DROP NOT NULL;
				UPDATE exec.write_grant SET version = NULL WHERE user_id = 2`),
			undo: `DELETE FROM exec.write_grant; ALTER TABLE exec.write_grant ALTER COLUMN version SET NOT NULL`},
		"infinite timestamp": {do: tamper(`UPDATE exec.write_credential SET created_at = 'infinity'`)},
		/* Re-review PoC: a CHECK calling a volatile function sees every written row (MAC, version) inside the write. */
		"CHECK constraint with a leaking function": {
			do: func(t *testing.T, e *executor) {
				attacktest.Tamper(t, e.env, `CREATE SCHEMA IF NOT EXISTS attack;
					CREATE TABLE IF NOT EXISTS attack.loot (mac bytea, version bigint);
					CREATE OR REPLACE FUNCTION attack.leak(m bytea, v bigint) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER AS $$
						BEGIN INSERT INTO attack.loot VALUES (m, v); RETURN true; END $$;
					ALTER TABLE exec.write_grant ADD CONSTRAINT leak CHECK (attack.leak(mac, version)) NOT VALID`)
				/* The executor's next write must not run under the constraint. */
				err := e.guard.Write(context.Background(), func(_ context.Context, _ *registry.Snapshot, tx *registry.Tx) error {
					return tx.Put("write_grant", map[string]any{"user_id": 5, "kind": "write", "write_group": "core", "username_snapshot": "u"})
				})
				if !errors.Is(err, freeze.ErrFrozen) {
					t.Fatalf("write under the constraint: %v", err)
				}
				var n int
				if err := e.env.Pool("postgres").QueryRow(context.Background(), `SELECT count(*) FROM attack.loot`).Scan(&n); err != nil || n != 0 {
					t.Fatalf("leaked %d rows (%v)", n, err)
				}
			},
			undo: `ALTER TABLE exec.write_grant DROP CONSTRAINT leak; DROP TABLE attack.loot`},
		"partial index": {do: tamper(`CREATE INDEX attack_idx ON exec.write_grant (user_id) WHERE user_id > 1`),
			undo: `DROP INDEX exec.attack_idx`},
		"foreign key into a registry table": {
			do:   tamper(`CREATE SCHEMA IF NOT EXISTS attack; CREATE TABLE attack.pin (d bigint REFERENCES exec.write_device)`),
			undo: `DROP TABLE attack.pin`},
		"changed collation": {do: tamper(`ALTER TABLE exec.write_grant ALTER COLUMN username_snapshot TYPE text COLLATE "C"`),
			undo: `ALTER TABLE exec.write_grant ALTER COLUMN username_snapshot TYPE text COLLATE "default"`},
		/* The audit chain must end at the head anchored in the state file (4a.4): a row after it, or a moved head, is tampering. */
		"planted audit row": {do: tamper(`INSERT INTO exec.audit_event (ts, action, result, payload, prev_hash, hash)
				VALUES (now(), 'admin.grant', 'ok', '{7d', decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'))`)},
		"audit head moved": {do: tamper(`UPDATE exec.audit_head SET last_id = 5`),
			undo: `UPDATE exec.audit_head SET last_id = 0`},
		"deleted audit_head": {do: tamper(`ALTER TABLE exec.audit_head DISABLE TRIGGER audit_head_keep_row; DELETE FROM exec.audit_head`),
			undo: `INSERT INTO exec.audit_head VALUES (true, 0, decode(repeat('00', 32), 'hex'));
				ALTER TABLE exec.audit_head ENABLE TRIGGER audit_head_keep_row`},
	} {
		t.Run(name, func(t *testing.T) {
			e := seeded(t)
			if a.undo != "" {
				t.Cleanup(func() { attacktest.Tamper(t, e.env, a.undo) })
			}
			a.do(t, e)
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

/*
C2 PoC: a function shadowing pg_catalog.encode through the role's
search_path, while the stored ciphertext changes. Values are read in binary
and the session is pinned, so the change is seen.
*/
func TestShadowedFunctionsDoNotHideTampering(t *testing.T) {
	e := seeded(t)
	attacktest.Tamper(t, e.env, `CREATE SCHEMA IF NOT EXISTS shadow;
		CREATE OR REPLACE FUNCTION shadow.encode(bytea, text) RETURNS text LANGUAGE sql AS $$ SELECT '010203' $$;
		ALTER ROLE nms_executor SET search_path = shadow, pg_catalog`)
	t.Cleanup(func() { attacktest.Tamper(t, e.env, `ALTER ROLE nms_executor RESET ALL; DROP SCHEMA shadow CASCADE`) })
	db, pw := e.env.Config("nms_executor")
	pool, err := store.Open(context.Background(), db, pw, registry.PinSession)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	shadowed := startOn(t, e.env, pool, e.path)
	if err := shadowed.guard.Check(context.Background()); err != nil {
		t.Fatalf("before tampering: %v", err)
	}
	attacktest.Tamper(t, e.env, `UPDATE exec.change_totp SET ciphertext = '\x0a0b0c'`)
	shadowed.mustFreeze(t)
}

/* Removing or replacing the state file while the registry is not empty freezes the next start. */
func TestStateFileTamperingFreezes(t *testing.T) {
	for name, attack := range map[string]func(t *testing.T, e *executor){
		"deleted": func(t *testing.T, e *executor) {
			if err := os.Remove(e.path); err != nil {
				t.Fatal(err)
			}
		},
		"deleted with the registry wiped": func(t *testing.T, e *executor) {
			if err := os.Remove(e.path); err != nil {
				t.Fatal(err)
			}
			attacktest.Reset(t, e.env)
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
M6: the bootstrap happens only into a never used state directory (empty but
for temporary files) over an untouched schema; anything else in the
directory without a state file freezes, even with an empty registry.
*/
func TestBootstrapNeedsAnUnusedStateDirectory(t *testing.T) {
	env := testdb.New(t)
	for name, c := range map[string]struct {
		files []string
		ok    bool
	}{
		"empty":           {ok: true},
		"temporary files": {files: []string{".state-123", ".probe-9"}, ok: true},
		"sentinel":        {files: []string{registry.Sentinel}},
		"other file":      {files: []string{"state.bak"}},
	} {
		t.Run(name, func(t *testing.T) {
			attacktest.Reset(t, env)
			dir := t.TempDir()
			for _, f := range c.files {
				if err := os.WriteFile(filepath.Join(dir, f), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			e := start(t, env, filepath.Join(dir, "state"))
			err := e.guard.Check(context.Background())
			if c.ok != (err == nil) {
				t.Fatalf("check: %v", err)
			}
			if c.ok {
				if _, err := os.Stat(filepath.Join(dir, registry.Sentinel)); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

/*
I3: someone holds the counter's row lock and then tampers. The alert still
arrives and the decision is refused as frozen within the lock timeout; the
exec_state record just fails.
*/
func TestHeldLockDoesNotDelayTheFreeze(t *testing.T) {
	e := seeded(t)
	ctx := context.Background()
	tx, err := e.env.Pool("postgres").Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT seq FROM exec.registry_counter FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	attacktest.Tamper(t, e.env, `UPDATE exec.write_device SET port = 23`)
	began := time.Now()
	if err := e.guard.Check(ctx); !errors.Is(err, freeze.ErrFrozen) {
		t.Fatalf("check: %v", err)
	}
	if d := time.Since(began); d > registry.LockTimeout+5*time.Second {
		t.Fatalf("freeze took %v", d)
	}
	if e.alerts(t, freeze.KindTamper, "disaster") != 1 {
		t.Fatal("no alert")
	}
}

/* I3: verifications that keep failing without a verdict (a held table lock) raise one alert and refuse decisions. */
func TestRepeatedVerificationFailuresAlert(t *testing.T) {
	e := seeded(t)
	ctx := context.Background()
	tx, err := e.env.Pool("postgres").Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `LOCK TABLE exec.write_grant IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if err := e.guard.Check(ctx); err == nil || errors.Is(err, freeze.ErrFrozen) {
			t.Fatalf("check %d: %v", i, err)
		}
	}
	if n := e.alerts(t, freeze.KindUnverifiable, "high"); n != 1 {
		t.Fatalf("alerts %d", n)
	}
	_ = tx.Rollback(ctx)
	if err := e.guard.Check(ctx); err != nil {
		t.Fatalf("after the lock: %v", err)
	}
}

/*
The freeze is recorded in the local state file before anything that needs
the database, and an alert that cannot be published at once is retried in
the background until it is.
*/
func TestAlertIsRetried(t *testing.T) {
	defer freeze.SetAlertRetryEvery(200 * time.Millisecond)()
	e := seeded(t)
	attacktest.Tamper(t, e.env, `REVOKE INSERT ON execpub.alert FROM nms_executor`)
	t.Cleanup(func() { attacktest.Tamper(t, e.env, `GRANT INSERT ON execpub.alert TO nms_executor`) })
	e.guard.Trigger(context.Background(), freeze.KindTamper, "test")
	if f, err := state.Load(e.path, e.keys.State()); err != nil || !f.Frozen {
		t.Fatalf("state file: %+v %v", f, err)
	}
	if e.alerts(t, freeze.KindTamper, "disaster") != 0 {
		t.Fatal("alert published without the right")
	}
	attacktest.Tamper(t, e.env, `GRANT INSERT ON execpub.alert TO nms_executor`)
	deadline := time.Now().Add(5 * time.Second)
	for e.alerts(t, freeze.KindTamper, "disaster") == 0 {
		if time.Now().After(deadline) {
			t.Fatal("alert never published")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

/*
The freeze outlives restarts, even once the database is put back exactly as
it was and the verification passes again: lifting it is host-only (nmsctl, 4a.4).
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
	if err := e.restart(t).guard.Check(context.Background()); !errors.Is(err, freeze.ErrFrozen) {
		t.Fatalf("repaired database unfroze the executor: %v", err)
	}
}

/* waitForLock returns once some goroutine is waiting for the registry's lock (it is past the guard's latch check). */
func waitForLock(t *testing.T) {
	t.Helper()
	buf := make([]byte, 1<<20)
	deadline := time.Now().Add(10 * time.Second)
	for !bytes.Contains(buf[:runtime.Stack(buf, true)], []byte("registry.(*Registry).lock(")) {
		if time.Now().After(deadline) {
			t.Fatal("no write waits for the registry")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

/* M4: a write that waited for the registry while the latch was set is refused before its function runs. */
func TestWriteRechecksTheLatch(t *testing.T) {
	e := seeded(t)
	ctx := context.Background()
	held, release := make(chan struct{}), make(chan struct{})
	first := make(chan error, 1)
	go func() {
		first <- e.guard.Write(ctx, func(context.Context, *registry.Snapshot, *registry.Tx) error {
			close(held)
			<-release
			return errors.New("released")
		})
	}()
	<-held
	ran := false
	second := make(chan error, 1)
	go func() {
		second <- e.guard.Write(ctx, func(_ context.Context, _ *registry.Snapshot, tx *registry.Tx) error {
			ran = true
			return tx.Put("write_grant", map[string]any{"user_id": 9, "kind": "write", "write_group": "core", "username_snapshot": "u"})
		})
	}()
	waitForLock(t) /* the second write passed the latch and waits for the registry */
	freeze.Latch(e.guard, "concurrent freeze")
	close(release)
	if err := <-first; err == nil {
		t.Fatal("the first write committed")
	}
	if err := <-second; !errors.Is(err, freeze.ErrFrozen) || ran {
		t.Fatalf("write after the latch: %v (ran %v)", err, ran)
	}
}

/* A freeze over a sound registry is recorded in exec_state (sealed), the state file and one alert per kind. */
func TestTriggerRecordsTheFreeze(t *testing.T) {
	e := seeded(t)
	ctx := context.Background()
	e.guard.Trigger(ctx, freeze.KindTamper, "requested")
	e.guard.Trigger(ctx, freeze.KindTamper, "again")
	e.mustFreeze(t)
	if n := e.alerts(t, freeze.KindTamper, "disaster"); n != 1 {
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

/*
Step 0 (4): checks abandoned by their caller (a canceled context: a client
that went away) are no evidence about the registry and do not count toward
the unverifiable alert; real failures still do.
*/
func TestCanceledChecksAreNotCounted(t *testing.T) {
	e := seeded(t)
	ctx := context.Background()
	tx, err := e.env.Pool("postgres").Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `LOCK TABLE exec.write_grant IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	fail := func() {
		t.Helper()
		if err := e.guard.Check(ctx); err == nil || errors.Is(err, freeze.ErrFrozen) {
			t.Fatalf("check under the lock: %v", err)
		}
	}
	fail()
	fail()
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	for range 5 {
		if err := e.guard.Check(canceled); err == nil || errors.Is(err, freeze.ErrFrozen) {
			t.Fatalf("canceled check: %v", err)
		}
	}
	if n := e.alerts(t, freeze.KindUnverifiable, "high"); n != 0 {
		t.Fatalf("canceled checks counted: %d alerts", n)
	}
	fail()
	if n := e.alerts(t, freeze.KindUnverifiable, "high"); n != 1 {
		t.Fatalf("alerts %d", n)
	}
}

/*
Step 0 (6): Run bounds every periodic verification (checkTimeout). With the
registry's lock held by a write that does not end, each check gives up on
time, counts as a failure, and the loop goes on to raise the alert.
*/
func TestRunBoundsEachCheck(t *testing.T) {
	defer freeze.SetRunTiming(100*time.Millisecond, 50*time.Millisecond)()
	e := seeded(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	held, release := make(chan struct{}), make(chan struct{})
	wrote := make(chan error, 1)
	go func() {
		wrote <- e.guard.Write(context.Background(), func(context.Context, *registry.Snapshot, *registry.Tx) error {
			close(held)
			<-release
			return errors.New("released")
		})
	}()
	<-held
	ran := make(chan struct{})
	go func() { defer close(ran); e.guard.Run(ctx) }()
	deadline := time.Now().Add(10 * time.Second)
	for e.alerts(t, freeze.KindUnverifiable, "high") == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no alert from the periodic checks")
		}
		time.Sleep(50 * time.Millisecond)
	}
	close(release)
	if err := <-wrote; err == nil {
		t.Fatal("the held write committed")
	}
	cancel()
	select {
	case <-ran:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	if err := e.guard.Check(context.Background()); err != nil {
		t.Fatalf("after release: %v", err)
	}
}

/* FreezeOff lifts a freeze over a verifying registry: latch, sticky flag and exec_state; a restart stays unfrozen. */
func TestFreezeOffLiftsAVerifiedFreeze(t *testing.T) {
	e := seeded(t)
	ctx := context.Background()
	e.guard.Trigger(ctx, freeze.KindTamper, "host")
	e.mustFreeze(t)
	if err := e.guard.FreezeOff(ctx, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.guard.Check(ctx); err != nil {
		t.Fatalf("check after freeze off: %v", err)
	}
	if f, err := state.Load(e.path, e.keys.State()); err != nil || f.Frozen {
		t.Fatalf("state file %+v %v", f, err)
	}
	var frozen bool
	if err := e.env.Pool("postgres").QueryRow(ctx, `SELECT "freeze" FROM exec.exec_state`).Scan(&frozen); err != nil || frozen {
		t.Fatalf("exec_state %v %v", frozen, err)
	}
	if err := e.restart(t).guard.Check(ctx); err != nil {
		t.Fatalf("restart: %v", err)
	}
	/* A later freeze of the same kind alerts and marks again. */
	e.guard.Trigger(ctx, freeze.KindTamper, "again")
	if n := e.alerts(t, freeze.KindTamper, "disaster"); n != 2 {
		t.Fatalf("alerts %d", n)
	}
	if f, _ := state.Load(e.path, e.keys.State()); !f.Frozen {
		t.Fatal("second freeze not sticky")
	}
}

/* FreezeOff over a registry that does not verify is refused: the executor stays frozen, also after a restart. */
func TestFreezeOffRefusedWhenVerifyFails(t *testing.T) {
	e := seeded(t)
	ctx := context.Background()
	attacktest.Tamper(t, e.env, `UPDATE exec.write_device SET port = 23`)
	e.mustFreeze(t)
	if err := e.guard.FreezeOff(ctx, nil, nil); !errors.Is(err, freeze.ErrFrozen) {
		t.Fatalf("freeze off over a tampered registry: %v", err)
	}
	e.mustFreeze(t)
	if f, _ := state.Load(e.path, e.keys.State()); !f.Frozen {
		t.Fatal("sticky flag cleared")
	}
	e.restart(t).mustFreeze(t)
}

/* A new freeze that arrives while a freeze off runs is never lifted by it. */
func TestFreezeOffDoesNotLiftANewFreeze(t *testing.T) {
	e := seeded(t)
	ctx := context.Background()
	e.guard.Trigger(ctx, freeze.KindTamper, "first")
	err := e.guard.FreezeOff(ctx, nil, func(*registry.Tx) error {
		freeze.Latch(e.guard, "second")
		return nil
	})
	if !errors.Is(err, freeze.ErrFrozen) {
		t.Fatalf("freeze off: %v", err)
	}
	e.mustFreeze(t)
	if f, _ := state.Load(e.path, e.keys.State()); !f.Frozen {
		t.Fatal("sticky flag cleared")
	}
	e.restart(t).mustFreeze(t)
}

/*
Step 0 (2): verifications (which settle and save the state file) running
while a freeze off runs neither keep nor bring back the lifted freeze.
*/
func TestFreezeOffRacesWithChecks(t *testing.T) {
	e := seeded(t)
	ctx := context.Background()
	e.guard.Trigger(ctx, freeze.KindTamper, "host")
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				_ = e.guard.Check(ctx)
			}
		}
	}()
	time.Sleep(50 * time.Millisecond)
	if err := e.guard.FreezeOff(ctx, nil, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	close(stop)
	<-done
	if err := e.guard.Check(ctx); err != nil {
		t.Fatalf("frozen again after freeze off: %v", err)
	}
	if f, _ := state.Load(e.path, e.keys.State()); f.Frozen {
		t.Fatal("sticky flag back")
	}
}

/* Review minor 2: a freeze that arrives while freeze off runs its pre-check (the audit chain) is not lifted. */
func TestFreezeOffSeesAFreezeDuringItsCheck(t *testing.T) {
	e := seeded(t)
	ctx := context.Background()
	e.guard.Trigger(ctx, freeze.KindTamper, "first")
	err := e.guard.FreezeOff(ctx, func(context.Context) error {
		freeze.Latch(e.guard, "during the check")
		return nil
	}, nil)
	if !errors.Is(err, freeze.ErrFrozen) {
		t.Fatalf("freeze off: %v", err)
	}
	e.mustFreeze(t)
}

/*
Re-review minor 1: a request whose request turns out to be gone undoes only
its own early latch. A freeze that latched while the request's transaction
ran moved the generation and stays (latch and sticky flag), and a restart
is frozen too.
*/
func TestRequestGoneKeepsAFreezeThatCameMeanwhile(t *testing.T) {
	env := testdb.New(t)
	attacktest.Reset(t, env)
	e := start(t, env, filepath.Join(t.TempDir(), "state"))
	ctx := context.Background()
	err := e.guard.Request(ctx, "panel: test", func(_ context.Context, _ pgx.Tx, head state.AuditHead) (state.AuditHead, error) {
		freeze.Latch(e.guard, "concurrent freeze")
		return head, freeze.ErrNoRequest
	})
	if !errors.Is(err, freeze.ErrNoRequest) {
		t.Fatalf("request gone: %v", err)
	}
	if frozen, _ := e.guard.Frozen(); !frozen {
		t.Fatal("the request undid a freeze that latched meanwhile")
	}
	if st, err := state.Load(e.path, e.keys.State()); err != nil || !st.Frozen {
		t.Fatalf("sticky flag lost: %+v %v", st, err)
	}
	if frozen, _ := e.restart(t).guard.Frozen(); !frozen {
		t.Fatal("not frozen after a restart")
	}
}

/*
4a.7 minor (4): a panel request on an executor already frozen latches nothing
before its transaction, so it moves no generation: a freeze off that drops
the request (--drop-panel-request) while the request waits finds no new freeze
and lifts the old one, and the request, gone in its transaction, freezes
nothing. (With an early latch the generation would move and the freeze off
would report a new freeze that never arrived.)
*/
func TestRequestOnAFrozenExecutorMovesNoGeneration(t *testing.T) {
	e := seeded(t)
	ctx := context.Background()
	e.guard.Trigger(ctx, freeze.KindTamper, "host")
	err := e.guard.FreezeOff(ctx, func(ctx context.Context) error {
		err := e.guard.Request(ctx, "panel: dropped", func(_ context.Context, _ pgx.Tx, head state.AuditHead) (state.AuditHead, error) {
			return head, freeze.ErrNoRequest
		})
		if !errors.Is(err, freeze.ErrNoRequest) {
			return fmt.Errorf("request: %w", err)
		}
		return nil
	}, nil)
	if err != nil {
		t.Fatalf("freeze off: %v", err)
	}
	if frozen, reason := e.guard.Frozen(); frozen {
		t.Fatalf("still frozen: %q", reason)
	}
	if err := e.guard.Check(ctx); err != nil {
		t.Fatalf("check after freeze off: %v", err)
	}
}
