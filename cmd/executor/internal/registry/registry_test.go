package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/state"
	"github.com/beekamai/network-scheme/internal/store"
	"github.com/beekamai/network-scheme/internal/testdb"
)

func TestMain(m *testing.M) { testdb.Main(m) }

func keys(t *testing.T) *seal.Keys {
	t.Helper()
	k, err := seal.Derive(&[32]byte{42})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

/* fresh empties the registry and returns an initialised Registry over a new state directory. */
func fresh(t *testing.T) (*testdb.Env, *Registry) {
	t.Helper()
	env := testdb.New(t)
	attacktest.Reset(t, env)
	r := New(env.Pool("nms_executor"), keys(t), filepath.Join(t.TempDir(), "state"))
	if err := r.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	return env, r
}

/* restart is a new process over the same database and state file. */
func restart(t *testing.T, env *testdb.Env, r *Registry) *Registry {
	t.Helper()
	n := New(env.Pool("nms_executor"), keys(t), r.path)
	if err := n.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	return n
}

func verify(t *testing.T, r *Registry) Report {
	t.Helper()
	rep, err := r.Verify(context.Background())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return rep
}

func grantRow(user int64, name string) map[string]any {
	return map[string]any{"user_id": user, "kind": "write", "write_group": "core", "username_snapshot": name}
}

func grant(ctx context.Context, r *Registry, user int64) error {
	return r.Write(ctx, func(_ context.Context, _ *Snapshot, tx *Tx) error { return tx.Put("write_grant", grantRow(user, "u")) })
}

func count(t *testing.T, env *testdb.Env, sql string) int {
	t.Helper()
	var n int
	if err := env.Pool("postgres").QueryRow(context.Background(), sql).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func loadState(t *testing.T, r *Registry) state.File {
	t.Helper()
	f, err := state.Load(r.path, r.keys.State())
	if err != nil {
		t.Fatal(err)
	}
	return f
}

/* A fresh install gets registry_counter, an unfrozen exec_state, a committed state file and the sentinel; a second Init changes nothing. */
func TestInitBootstrapsAFreshInstall(t *testing.T) {
	env, r := fresh(t)
	if rep := verify(t, r); rep.Seq != 1 || rep.Frozen {
		t.Fatalf("report %+v", rep)
	}
	if f := loadState(t, r); f.Committed.HWM != 1 || f.Pending != nil || f.Frozen {
		t.Fatalf("state %+v", f)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(r.path), Sentinel)); err != nil {
		t.Fatal(err)
	}
	if n := count(t, env, `SELECT count(*) FROM exec.exec_state WHERE NOT "freeze" AND version = 1`); n != 1 {
		t.Fatalf("exec_state rows %d", n)
	}
	if rep := verify(t, restart(t, env, r)); rep.Seq != 1 {
		t.Fatalf("after restart %+v", rep)
	}
}

/* Puts and deletes take consecutive versions and verify; View hands out the verified Go values. */
func TestWriteAndView(t *testing.T) {
	env, r := fresh(t)
	ctx := context.Background()
	for u := int64(1); u <= 3; u++ {
		if err := grant(ctx, r, u); err != nil {
			t.Fatal(err)
		}
	}
	at := time.Date(2026, 10, 26, 12, 34, 56, 789012345, time.FixedZone("x", 3*3600))
	if err := r.Write(ctx, func(_ context.Context, _ *Snapshot, tx *Tx) error {
		return errors.Join(
			tx.Put("write_grant", grantRow(2, "v")),
			tx.Delete("write_grant", 3, "write", "core"),
			tx.Put("write_grant", map[string]any{"user_id": 4, "kind": "unmask", "write_group": nil, "username_snapshot": "w"}),
			tx.Put("write_device", map[string]any{"device_id": 1, "address": netip.MustParseAddr("2001:db8::1"), "port": 22,
				"protocol": "ssh", "write_group": "core", "write_driver": "esr", "hostkey_algo": nil, "hostkey_fp": nil,
				"allow_ssh_rsa_sha1": false, "writes_enabled": false, "backup_via_executor": true}),
			tx.Put("write_credential", map[string]any{"device_id": 1, "kind": "ssh_write", "ciphertext": []byte{0xde, 0xad},
				"created_at": at, "nonce": make([]byte, 16)}),
			tx.Put("model_profile", map[string]any{"id": 5, "write_driver": "mes6", "model_re": "^MES", "firmware_re": ".",
				"strategies": json.RawMessage(`{"b": [1, 2.50, 100], "a": null,  "a": "x"}`), "note": "n"}),
		)
	}); err != nil {
		t.Fatal(err)
	}
	if n := count(t, env, `SELECT count(*) FROM exec.write_grant`); n != 3 {
		t.Fatalf("grants %d", n)
	}
	err := r.View(ctx, func(s *Snapshot) error {
		if s.Seq() != 5 {
			t.Errorf("seq %d", s.Seq())
		}
		g, ok := s.Get("write_grant", 2, "write", "core")
		if !ok || g.Get("username_snapshot") != "v" || g.Version() != 5 {
			t.Errorf("grant 2: %v %v", ok, g.r)
		}
		if _, ok := s.Get("write_grant", 4, "unmask", nil); !ok {
			t.Error("unmask grant missing")
		}
		d, _ := s.Get("write_device", 1)
		if d.Get("address") != netip.MustParseAddr("2001:db8::1") || d.Get("port") != int64(22) {
			t.Errorf("device %v", d.r.typed)
		}
		c, _ := s.Get("write_credential", 1)
		if !c.Get("created_at").(time.Time).Equal(at.Truncate(time.Microsecond)) {
			t.Errorf("created_at %v", c.Get("created_at"))
		}
		if m, _ := s.Get("model_profile", 5); string(m.Get("strategies").(json.RawMessage)) != `{"a":"x","b":[1,2.50,100]}` {
			t.Errorf("strategies %s", m.Get("strategies"))
		}
		if len(s.Rows("write_grant")) != 3 {
			t.Error("rows")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	/* A failing function leaves nothing behind; a bad declaration is refused before any write. */
	boom := errors.New("boom")
	if err := r.Write(ctx, func(_ context.Context, _ *Snapshot, tx *Tx) error {
		_ = tx.Delete("write_grant", 2, "write", "core")
		return boom
	}); !errors.Is(err, boom) {
		t.Fatalf("err %v", err)
	}
	for _, bad := range []func(tx *Tx) error{
		func(tx *Tx) error { return tx.Put("write_grant", map[string]any{"user_id": 1}) },
		func(tx *Tx) error { return tx.Put("registry_counter", map[string]any{"singleton": true}) },
		func(tx *Tx) error { return tx.Delete("exec_state", true) },
		func(tx *Tx) error { return tx.Put("write_grant", grantRow(1, "")) }, /* CHECK in the database */
	} {
		if err := r.Write(ctx, func(_ context.Context, _ *Snapshot, tx *Tx) error { return bad(tx) }); err == nil || errors.Is(err, ErrTampered) {
			t.Fatalf("bad declaration: %v", err)
		}
	}
	if rep := verify(t, r); rep.Seq != 5 || count(t, env, `SELECT count(*) FROM exec.write_grant`) != 3 {
		t.Fatalf("failed writes left traces: %+v", rep)
	}
	if f := loadState(t, r); f.Pending != nil || f.Committed.HWM != 5 {
		t.Fatalf("state %+v", f)
	}
}

/* crashAt runs a Write that dies (as the process would) at stage: no deferred cleanup but the transaction's. */
func crashAt(t *testing.T, r *Registry, stage string, fn func() error) {
	t.Helper()
	r.hook = func(s string, _ pgx.Tx) {
		if s == stage {
			runtime.Goexit()
		}
	}
	done := make(chan error, 1)
	go func() {
		defer close(done)
		done <- fn()
	}()
	if err, ok := <-done; ok {
		t.Fatalf("no crash at %s: %v", stage, err)
	}
	r.hook = nil
}

/*
Crash windows: dying after the pending record and before COMMIT leaves the
database at committed, and the next verification drops the pending record;
dying after COMMIT and before "committed" leaves it at pending, which the
next verification advances. Both are accepted, also for the bootstrap.
*/
func TestCrashWindowsAreAccepted(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		stage  string
		seq    int64
		grants int
	}{{"pending", 1, 0}, {"committed", 2, 1}} {
		env, r := fresh(t)
		crashAt(t, r, c.stage, func() error { return grant(ctx, r, 1) })
		if f := loadState(t, r); f.Pending == nil {
			t.Fatalf("%s: no pending record", c.stage)
		}
		r = restart(t, env, r)
		if rep := verify(t, r); rep.Seq != c.seq || rep.Frozen {
			t.Fatalf("%s: report %+v", c.stage, rep)
		}
		if f := loadState(t, r); f.Pending != nil || f.Committed.HWM != c.seq {
			t.Fatalf("%s: state %+v", c.stage, f)
		}
		if n := count(t, env, `SELECT count(*) FROM exec.write_grant`); n != c.grants {
			t.Fatalf("%s: grants %d", c.stage, n)
		}
		if err := grant(ctx, r, 2); err != nil {
			t.Fatalf("%s: next write: %v", c.stage, err)
		}
	}
	for _, stage := range []string{"pending", "committed"} {
		env := testdb.New(t)
		attacktest.Reset(t, env)
		r := New(env.Pool("nms_executor"), keys(t), filepath.Join(t.TempDir(), "state"))
		crashAt(t, r, stage, func() error { return r.Init(ctx) })
		r = restart(t, env, r)
		if rep := verify(t, r); rep.Seq != 1 || rep.Frozen {
			t.Fatalf("bootstrap %s: %+v", stage, rep)
		}
	}
}

/* capture reads, inside the writer's transaction, the rows a change is about to commit (as a spying superuser could). */
func capture(t *testing.T, tx pgx.Tx) (seq int64, counterMAC []byte, grantMAC []byte) {
	t.Helper()
	ctx := context.Background()
	if err := tx.QueryRow(ctx, `SELECT seq, mac FROM exec.registry_counter`).Scan(&seq, &counterMAC); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `SELECT mac FROM exec.write_grant WHERE user_id = 7`).Scan(&grantMAC); err != nil {
		t.Fatal(err)
	}
	return
}

/* replay puts the captured, never committed change into the database as the superuser. */
func replay(t *testing.T, env *testdb.Env, seq int64, counterMAC, grantMAC []byte) {
	t.Helper()
	attacktest.Tamper(t, env, `UPDATE exec.registry_counter SET seq = $1, mac = $2`, seq, counterMAC)
	attacktest.Tamper(t, env, `INSERT INTO exec.write_grant (user_id, kind, write_group, username_snapshot, version, mac)
		VALUES (7, 'write', 'core', 'u', $1, $2)`, seq, grantMAC)
}

/*
I1: a change whose COMMIT failed must never be accepted later. A definite
failure drops the pending record at once; an ambiguous one is resolved at
once; a crash before COMMIT is settled by the next verification. Replaying
the captured rows afterwards is tampering in every case.
*/
var heldLock pgx.Tx

func TestFailedCommitCannotBeReplayed(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct {
		commit func(ctx context.Context, tx pgx.Tx) error
		crash  bool
	}{
		/*
			A server with lc_messages = ru_RU localizes Severity; only
			SeverityUnlocalized says ERROR. The transaction is left open here, so
			only the definite branch drops the record: settling by the fate would
			find it in progress and keep the record (and the write would fail).
		*/
		"definite": {commit: func(context.Context, pgx.Tx) error {
			return &pgconn.PgError{Severity: "ОШИБКА", SeverityUnlocalized: "ERROR", Code: "23514", Message: "check violation at commit"}
		}},
		"ambiguous, not committed": {commit: func(ctx context.Context, tx pgx.Tx) error {
			_ = tx.Rollback(ctx)
			return errors.New("connection reset")
		}},
		"crash before commit": {crash: true},
		/*
			Re-review PoC (I-A): the COMMIT fails ambiguously and the change rolled
			back; the attacker holds ACCESS EXCLUSIVE on the table so that a
			re-verification would time out, replays the captured rows and releases.
			The fate of the transaction is read from pg_xact_status, which no table
			lock delays: the record is dropped and the replay is never accepted.
		*/
		"ambiguous, re-verification blocked by a lock": {commit: func(ctx context.Context, tx pgx.Tx) error {
			_ = tx.Rollback(ctx)
			lock, err := testdb.New(t).Pool("postgres").Begin(ctx)
			if err != nil {
				return err
			}
			if _, err := lock.Exec(ctx, `LOCK TABLE exec.write_grant IN ACCESS EXCLUSIVE MODE`); err != nil {
				return err
			}
			heldLock = lock
			return errors.New("unexpected EOF")
		}},
	} {
		t.Run(name, func(t *testing.T) {
			env, r := fresh(t)
			r.settleFor = time.Second
			var seq int64
			var cm, gm []byte
			write := func() error {
				return r.Write(ctx, func(_ context.Context, _ *Snapshot, tx *Tx) error { return tx.Put("write_grant", grantRow(7, "u")) })
			}
			if c.crash {
				r.hook = func(s string, tx pgx.Tx) {
					if s == "pending" {
						seq, cm, gm = capture(t, tx)
						runtime.Goexit()
					}
				}
				done := make(chan struct{})
				go func() { defer close(done); _ = write() }()
				<-done
				r.hook = nil
				r = restart(t, env, r)
				verify(t, r) /* settles: the database never reached pending */
			} else {
				r.hook = func(s string, tx pgx.Tx) {
					if s == "pending" {
						seq, cm, gm = capture(t, tx)
					}
				}
				r.commitTx = c.commit
				if err := write(); err == nil {
					t.Fatal("write reported success")
				}
			}
			if heldLock != nil {
				/* The replay goes in under the attacker's lock, then the lock is released. */
				if _, err := heldLock.Exec(ctx, `UPDATE exec.registry_counter SET seq = $1, mac = $2`, seq, cm); err != nil {
					t.Fatal(err)
				}
				if _, err := heldLock.Exec(ctx, `INSERT INTO exec.write_grant (user_id, kind, write_group, username_snapshot, version, mac)
					VALUES (7, 'write', 'core', 'u', $1, $2)`, seq, gm); err != nil {
					t.Fatal(err)
				}
				if err := heldLock.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				heldLock = nil
				if _, err := r.Verify(ctx); !errors.Is(err, ErrTampered) {
					t.Fatalf("replay under a lock accepted: %v", err)
				}
				return
			}
			if f := loadState(t, r); f.Pending != nil || f.Committed.HWM != 1 {
				t.Fatalf("pending record kept: %+v", f)
			}
			replay(t, env, seq, cm, gm)
			if _, err := restart(t, env, r).Verify(ctx); !errors.Is(err, ErrTampered) {
				t.Fatalf("replayed change accepted: %v", err)
			}
		})
	}
}

/*
A pending record is settled by its transaction alone. Here the database
holds exactly the pending state, but the recorded transaction is first in
progress (nothing is verified: fail closed, not tampering) and then aborted:
the record is dropped and the database, which never reached it through that
transaction, is tampering. A hash match is never enough.
*/
func TestPendingIsSettledOnlyByItsTransaction(t *testing.T) {
	env, r := fresh(t)
	ctx := context.Background()
	before := loadState(t, r)
	if err := grant(ctx, r, 1); err != nil {
		t.Fatal(err)
	}
	after := loadState(t, r)
	other, err := env.Pool("postgres").Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Rollback(ctx) }()
	var xid string
	if err := other.QueryRow(ctx, `SELECT pg_current_xact_id()::text`).Scan(&xid); err != nil {
		t.Fatal(err)
	}
	x, _ := strconv.ParseUint(xid, 10, 64)
	forged := before
	forged.Pending, forged.PendingXID = &after.Committed, x
	if err := state.Save(r.path, r.keys.State(), forged); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Verify(ctx); err == nil || errors.Is(err, ErrTampered) {
		t.Fatalf("in progress: %v", err)
	}
	if err := grant(ctx, r, 2); err == nil {
		t.Fatal("write over an unsettled change")
	}
	_ = other.Rollback(ctx)
	if _, err := r.Verify(ctx); !errors.Is(err, ErrTampered) {
		t.Fatalf("aborted: %v", err)
	}
	if f := loadState(t, r); f.Pending != nil {
		t.Fatalf("pending kept: %+v", f)
	}
}

/*
M2: a pending transaction beyond the database's next transaction id means the
database was put back behind the state file (pg_xact_status: 22023): tampering.
*/
func TestPendingFromTheFutureIsTampering(t *testing.T) {
	env, r := fresh(t)
	ctx := context.Background()
	var xid string
	if err := env.Pool("postgres").QueryRow(ctx, `SELECT pg_current_xact_id()::text`).Scan(&xid); err != nil {
		t.Fatal(err)
	}
	x, err := strconv.ParseUint(xid, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	f := loadState(t, r)
	pending := f.Committed
	f.Pending, f.PendingXID = &pending, x+1_000_000
	if err := state.Save(r.path, r.keys.State(), f); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Verify(ctx); !errors.Is(err, ErrTampered) {
		t.Fatalf("verify: %v", err)
	}
	if err := grant(ctx, r, 1); !errors.Is(err, ErrTampered) {
		t.Fatalf("write: %v", err)
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

/*
I1: MarkFrozen does not wait for the registry's lock, so it can mark the
state file in the middle of a write; the write's later save keeps the mark.
*/
func TestMarkFrozenDuringAWriteIsKept(t *testing.T) {
	_, r := fresh(t)
	r.hook = func(s string, _ pgx.Tx) {
		if s == "pending" {
			if err := r.MarkFrozen("mid-write"); err != nil {
				t.Error(err)
			}
		}
	}
	within(t, time.Minute, "write", func() {
		if err := grant(context.Background(), r, 1); err != nil {
			t.Error(err)
		}
	})
	if f := loadState(t, r); !f.Frozen || f.FreezeReason != "mid-write" || f.Pending != nil || f.Committed.HWM != 2 {
		t.Fatalf("state %+v", f)
	}
}

/*
Step 0 (1, 2): the sticky freeze belongs to the file. A write that loaded the
file while frozen and saves after the host cleared the flag does not freeze
it again (and, above, one that loaded it unfrozen does not lift a later mark).
*/
func TestStaleSaveDoesNotRefreeze(t *testing.T) {
	_, r := fresh(t)
	if err := r.MarkFrozen("host"); err != nil {
		t.Fatal(err)
	}
	r.hook = func(s string, _ pgx.Tx) {
		if s == "pending" {
			if err := r.ClearFrozen(); err != nil {
				t.Error(err)
			}
		}
	}
	within(t, time.Minute, "write", func() {
		if err := grant(context.Background(), r, 1); err != nil {
			t.Error(err)
		}
	})
	if f := loadState(t, r); f.Frozen || f.FreezeReason != "" || f.Pending != nil || f.Committed.HWM != 2 {
		t.Fatalf("state %+v", f)
	}
	if rep := verify(t, r); rep.Frozen {
		t.Fatalf("report %+v", rep)
	}
}

/* Step 0 (1): a save never writes over a state file it cannot read (deleted or replaced mid-write): tampering, nothing committed. */
func TestSaveRefusesAnUnreadableStateFile(t *testing.T) {
	for name, attack := range map[string]func(path string) error{
		"deleted":  os.Remove,
		"replaced": func(p string) error { return os.WriteFile(p, []byte("x\n{}"), 0o600) },
	} {
		t.Run(name, func(t *testing.T) {
			env, r := fresh(t)
			r.hook = func(s string, _ pgx.Tx) {
				if s == "verified" {
					if err := attack(r.path); err != nil {
						t.Error(err)
					}
				}
			}
			if err := grant(context.Background(), r, 1); !errors.Is(err, ErrTampered) {
				t.Fatalf("write: %v", err)
			}
			if _, err := os.Stat(r.path); name == "deleted" && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("state file recreated: %v", err)
			}
			if n := count(t, env, `SELECT count(*) FROM exec.write_grant`); n != 0 {
				t.Fatalf("grants %d", n)
			}
		})
	}
}

/* Step 0 (3): a function that panics inside Write releases the registry's lock. */
func TestPanicReleasesTheLock(t *testing.T) {
	_, r := fresh(t)
	ctx := context.Background()
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("no panic")
			}
		}()
		_ = r.Write(ctx, func(context.Context, *Snapshot, *Tx) error { panic("boom") })
	}()
	within(t, 30*time.Second, "verify after a panic", func() { verify(t, r) })
	within(t, 30*time.Second, "write after a panic", func() {
		if err := grant(ctx, r, 1); err != nil {
			t.Error(err)
		}
	})
}

/*
Step 0 (6): the backend of a write is stopped (SIGSTOP) after the pending
record, so the COMMIT is sent but not answered and the write's own deadline
expires. The settle after the failed COMMIT reads the fate under a context
of its own (WithoutCancel): resumed while it waits, the backend commits and
the write reports success. Resumed only after the write gave up, the change
stays pending, nothing verifies meanwhile, and the next verification settles it.
*/
func TestStallAtPendingSettles(t *testing.T) {
	for _, late := range []bool{false, true} {
		t.Run(fmt.Sprintf("resumed late %v", late), func(t *testing.T) {
			env, r := fresh(t)
			ctx := context.Background()
			r.opTimeout, r.settleFor = 3*time.Second, 20*time.Second /* the settle must outlast a resumed backend on a loaded runner */
			if late {
				r.settleFor = time.Second
			}
			var resume func()
			r.hook = func(s string, tx pgx.Tx) {
				if s == "pending" {
					resume = attacktest.Stall(t, env, tx.Conn().PgConn().PID())
				}
			}
			r.commitTx = func(ctx context.Context, tx pgx.Tx) error {
				err := tx.Commit(ctx)
				if !late {
					resume() /* the write's deadline has passed: only a settle with a context of its own sees the outcome */
				}
				return err
			}
			var err error
			within(t, time.Minute, "stalled write", func() { err = grant(ctx, r, 1) })
			r.hook = nil
			if !late {
				if err != nil {
					t.Fatalf("write: %v", err)
				}
			} else {
				if err == nil || errors.Is(err, ErrTampered) {
					t.Fatalf("write: %v", err)
				}
				if f := loadState(t, r); f.Pending == nil {
					t.Fatalf("pending dropped while unsettled: %+v", f)
				}
				if _, err := r.Verify(ctx); err == nil || errors.Is(err, ErrTampered) {
					t.Fatalf("verify while stalled: %v", err)
				}
				resume()
				deadline := time.Now().Add(30 * time.Second)
				for {
					if _, err = r.Verify(ctx); err == nil || errors.Is(err, ErrTampered) || time.Now().After(deadline) {
						break
					}
					time.Sleep(200 * time.Millisecond)
				}
				if err != nil {
					t.Fatalf("verify after resume: %v", err)
				}
			}
			if f := loadState(t, r); f.Pending != nil || f.Committed.HWM != 2 {
				t.Fatalf("state %+v", f)
			}
			if rep := verify(t, r); rep.Seq != 2 || count(t, env, `SELECT count(*) FROM exec.write_grant`) != 1 {
				t.Fatalf("not settled as committed: %+v", rep)
			}
		})
	}
}

/*
Step 0 (5): each read of a pending transaction's fate ends by the settle
deadline. Here no connection is free (the pool's only one is held), so every
read waits: the settle still ends after settleFor, not StatementTimeout.
*/
func TestSettleWaitIsBounded(t *testing.T) {
	env, r := fresh(t)
	ctx := context.Background()
	f := loadState(t, r)
	pending := f.Committed
	f.Pending, f.PendingXID = &pending, 1
	if err := state.Save(r.path, r.keys.State(), f); err != nil {
		t.Fatal(err)
	}
	db, pw := env.Config("nms_executor")
	pool, err := store.Open(ctx, db, pw, PinSession, func(c *pgxpool.Config) { c.MaxConns = 1 })
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	held, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	n := New(pool, keys(t), r.path)
	n.settleFor = time.Second
	began := time.Now()
	if err := n.Init(ctx); err == nil || errors.Is(err, ErrTampered) {
		t.Fatalf("init: %v", err)
	}
	if d := time.Since(began); d > StatementTimeout/2 {
		t.Fatalf("settle took %v", d)
	}
}

/* An ambiguous COMMIT failure that did commit is resolved as committed. */
func TestAmbiguousCommitThatCommitted(t *testing.T) {
	_, r := fresh(t)
	r.commitTx = func(ctx context.Context, tx pgx.Tx) error {
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		return errors.New("connection reset")
	}
	if err := grant(context.Background(), r, 1); err != nil {
		t.Fatalf("write: %v", err)
	}
	if f := loadState(t, r); f.Pending != nil || f.Committed.HWM != 2 {
		t.Fatalf("state %+v", f)
	}
}

/*
Inside the write, the database ends up holding something else than what
was declared (as a trigger, rule or default would make it): refused as
tampering, nothing sealed, nothing committed.
*/
func TestWriteRefusesUndeclaredChanges(t *testing.T) {
	ctx := context.Background()
	for name, sql := range map[string]string{
		"rewritten value": `UPDATE exec.write_grant SET username_snapshot = 'evil' WHERE user_id = 1`,
		"extra row":       `INSERT INTO exec.write_grant (user_id, kind, username_snapshot, version, mac) SELECT 9, 'write-admin', 'evil', version, mac FROM exec.write_grant WHERE user_id = 1`,
		"vanished row":    `DELETE FROM exec.write_grant WHERE user_id = 2`,
		"counter moved":   `UPDATE exec.registry_counter SET seq = seq + 1`,
	} {
		t.Run(name, func(t *testing.T) {
			env, r := fresh(t)
			if err := grant(ctx, r, 2); err != nil {
				t.Fatal(err)
			}
			r.hook = func(s string, tx pgx.Tx) {
				if s == "written" {
					if _, err := tx.Exec(ctx, sql); err != nil {
						t.Error(err)
					}
				}
			}
			if err := grant(ctx, r, 1); !errors.Is(err, ErrTampered) {
				t.Fatalf("err %v", err)
			}
			r.hook = nil
			if rep := verify(t, r); rep.Seq != 2 || count(t, env, `SELECT count(*) FROM exec.write_grant`) != 1 {
				t.Fatalf("state after refused write: %+v", rep)
			}
		})
	}
}

/*
I-B: inside the write, the database ends up with the same number of rows,
each validly MACed and no newer than the counter, but not the declared
ones: an older valid version of a row put back (content only), or a row
swapped for an old valid one that was deleted. Only the per-row comparison
with the declared state catches these; the state hash would otherwise seal
them.
*/
func TestWriteRefusesOldValidRows(t *testing.T) {
	ctx := context.Background()
	oldRow := func(t *testing.T, env *testdb.Env, user int) (int64, []byte) {
		var v int64
		var m []byte
		if err := env.Pool("postgres").QueryRow(ctx, `SELECT version, mac FROM exec.write_grant WHERE user_id = $1`, user).Scan(&v, &m); err != nil {
			t.Fatal(err)
		}
		return v, m
	}
	for name, attack := range map[string]func(v2 int64, m2 []byte, v4 int64, m4 []byte) []string{
		"old content of the same row": func(v2 int64, m2 []byte, _ int64, _ []byte) []string {
			return []string{fmt.Sprintf(`UPDATE exec.write_grant SET username_snapshot = 'u', version = %d, mac = '\x%x' WHERE user_id = 2`, v2, m2)}
		},
		"row swapped for an old deleted one": func(_ int64, _ []byte, v4 int64, m4 []byte) []string {
			return []string{`DELETE FROM exec.write_grant WHERE user_id = 3`,
				fmt.Sprintf(`INSERT INTO exec.write_grant (user_id, kind, write_group, username_snapshot, version, mac)
					VALUES (4, 'write', 'core', 'u', %d, '\x%x')`, v4, m4)}
		},
	} {
		t.Run(name, func(t *testing.T) {
			env, r := fresh(t)
			for _, u := range []int64{2, 3, 4} {
				if err := grant(ctx, r, u); err != nil {
					t.Fatal(err)
				}
			}
			v2, m2 := oldRow(t, env, 2)
			v4, m4 := oldRow(t, env, 4)
			if err := r.Write(ctx, func(_ context.Context, _ *Snapshot, tx *Tx) error {
				return errors.Join(tx.Put("write_grant", grantRow(2, "v")), tx.Delete("write_grant", 4, "write", "core"))
			}); err != nil {
				t.Fatal(err)
			}
			r.hook = func(s string, tx pgx.Tx) {
				if s == "written" {
					for _, q := range attack(v2, m2, v4, m4) {
						if _, err := tx.Exec(ctx, q); err != nil {
							t.Error(err)
						}
					}
				}
			}
			if err := grant(ctx, r, 1); !errors.Is(err, ErrTampered) {
				t.Fatalf("err %v", err)
			}
			r.hook = nil
			if rep := verify(t, r); rep.Seq != 5 {
				t.Fatalf("seq %d", rep.Seq)
			}
		})
	}
}

/* Concurrent read-modify-write updates are serialized: no update is lost. */
func TestWritersAreSerialized(t *testing.T) {
	env, r := fresh(t)
	ctx := context.Background()
	totp := func(failures int64) map[string]any {
		return map[string]any{"user_id": 1, "username_snapshot": "u", "ciphertext": []byte{1}, "key_version": 1,
			"last_step": 0, "failures": failures, "lock_until": nil, "lock_count": 0}
	}
	if err := r.Write(ctx, func(_ context.Context, _ *Snapshot, tx *Tx) error { return tx.Put("change_totp", totp(0)) }); err != nil {
		t.Fatal(err)
	}
	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Go(func() {
			errs <- r.Write(ctx, func(_ context.Context, s *Snapshot, tx *Tx) error {
				row, _ := s.Get("change_totp", 1)
				return tx.Put("change_totp", totp(row.Get("failures").(int64)+1))
			})
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := count(t, env, `SELECT failures FROM exec.change_totp`); got != n {
		t.Fatalf("failures = %d, want %d", got, n)
	}
	if rep := verify(t, r); rep.Seq != 2+n {
		t.Fatalf("seq %d", rep.Seq)
	}
}

/* The writer's lock is the registry_counter row: a second transaction taking it waits for the first. */
func TestCounterRowLockOrdersTransactions(t *testing.T) {
	env, _ := fresh(t)
	ctx := context.Background()
	pool := env.Pool("nms_executor")
	tx1, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx1.Rollback(ctx) }()
	var seq int64
	if err := tx1.QueryRow(ctx, `SELECT seq FROM exec.registry_counter FOR UPDATE`).Scan(&seq); err != nil {
		t.Fatal(err)
	}
	got := make(chan int64, 1)
	go func() {
		var s int64
		_ = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT seq FROM exec.registry_counter FOR UPDATE`).Scan(&s)
		})
		got <- s
	}()
	select {
	case s := <-got:
		t.Fatalf("second lock taken while held (seq %d)", s)
	case <-time.After(500 * time.Millisecond):
	}
	if _, err := tx1.Exec(ctx, `UPDATE exec.registry_counter SET seq = seq + 1`); err != nil {
		t.Fatal(err)
	}
	if err := tx1.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if s := <-got; s != seq+1 {
		t.Fatalf("second saw %d, want %d", s, seq+1)
	}
}

/*
What is verified does not depend on session settings, including a
search_path that shadows pg_catalog functions (the pool here is not
pinned: pinSession alone must hold).
*/
func TestVerifyIgnoresSessionSettings(t *testing.T) {
	env, r := fresh(t)
	ctx := context.Background()
	if err := r.Write(ctx, func(_ context.Context, _ *Snapshot, tx *Tx) error {
		return errors.Join(
			tx.Put("write_credential", map[string]any{"device_id": 1, "kind": "ssh_write", "ciphertext": []byte{0xde, 0xad},
				"created_at": time.Now(), "nonce": make([]byte, 16)}),
			tx.Put("exec_state", map[string]any{"singleton": true, "freeze": false, "freeze_reason": nil,
				"global_fail_window": json.RawMessage(`{"b": [1, 2.50], "a": null}`)}))
	}); err != nil {
		t.Fatal(err)
	}
	attacktest.Tamper(t, env, `CREATE SCHEMA IF NOT EXISTS shadow`)
	attacktest.Tamper(t, env, `CREATE OR REPLACE FUNCTION shadow.encode(bytea, text) RETURNS text LANGUAGE sql AS $$ SELECT 'x' $$`)
	t.Cleanup(func() {
		attacktest.Tamper(t, env, `ALTER ROLE nms_executor RESET ALL`)
		attacktest.Tamper(t, env, `DROP SCHEMA shadow CASCADE`)
	})
	for _, s := range []string{`TimeZone = 'Asia/Kathmandu'`, `DateStyle = 'SQL, DMY'`, `bytea_output = 'escape'`,
		`search_path = shadow, pg_catalog`, `extra_float_digits = 3`, `IntervalStyle = 'iso_8601'`} {
		attacktest.Tamper(t, env, `ALTER ROLE nms_executor SET `+s)
	}
	db, pw := env.Config("nms_executor")
	pool, err := store.Open(ctx, db, pw)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := New(pool, keys(t), r.path).Verify(ctx); err != nil {
		t.Fatal(err)
	}
}

/* M2: a validly MACed row whose version is above the counter is refused. */
func TestCheckRefusesVersionAboveCounter(t *testing.T) {
	k := keys(t)
	pk := []*string{p("1")}
	s := &Snapshot{seq: 3, rows: []*row{{t: lookup("write_grant"), pk: pk, version: 4,
		mac: macOf(k.MAC(), Canonical("write_grant", pk, nil, 4))}}}
	if _, err := s.check(); !errors.Is(err, ErrTampered) {
		t.Fatalf("err %v", err)
	}
	s.seq = 4
	if _, err := s.check(); err != nil {
		t.Fatal(err)
	}
}

/* jsonb reorders keys and drops whitespace and duplicates but keeps decimal scale: so does the canonical form. */
func TestCanonJSON(t *testing.T) {
	a, err := canonJSON([]byte(`{"b": [1, 2.50, 100], "a": null, "a": "x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if a != `{"a":"x","b":[1,2.50,100]}` {
		t.Fatalf("canonical %s", a)
	}
	b, _ := canonJSON([]byte(`{"a":"x","b":[1,2.50,100]}`))
	c, _ := canonJSON([]byte(`{"a":"x","b":[1.0,2.50,100]}`))
	d, _ := canonJSON([]byte(`{"a":"x","b":[1,2.5,100]}`))
	if a != b || a == c || a == d || b == c {
		t.Fatalf("%s %s %s %s", a, b, c, d)
	}
	for _, bad := range []string{``, `{`, `{} {}`, `[1,]`, `[1e2]`, `[1E2]`, `[-0]`, `[-0.00]`, `[.5]`} {
		if _, err := canonJSON([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
