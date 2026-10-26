package registry

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

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

func grant(ctx context.Context, r *Registry, user int64) error {
	return r.Write(ctx, func(ctx context.Context, tx *Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO exec.write_grant (user_id, kind, write_group, username_snapshot, version, mac)
			VALUES ($1, 'write', 'core', 'u', $2, $3)`, user, tx.Seq(), Unsealed())
		return err
	})
}

func count(t *testing.T, env *testdb.Env, sql string) int {
	t.Helper()
	var n int
	if err := env.Pool("postgres").QueryRow(context.Background(), sql).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

/* A fresh install gets registry_counter, an unfrozen exec_state and a committed state file; a second Init changes nothing. */
func TestInitBootstrapsAFreshInstall(t *testing.T) {
	env, r := fresh(t)
	if rep := verify(t, r); rep.Seq != 1 || rep.Frozen {
		t.Fatalf("report %+v", rep)
	}
	f, err := state.Load(r.path, r.keys.State())
	if err != nil || f.Committed.HWM != 1 || f.Pending != nil || f.Frozen {
		t.Fatalf("state %+v, %v", f, err)
	}
	if n := count(t, env, `SELECT count(*) FROM exec.exec_state WHERE NOT "freeze" AND version = 1`); n != 1 {
		t.Fatalf("exec_state rows %d", n)
	}
	r = restart(t, env, r)
	if rep := verify(t, r); rep.Seq != 1 {
		t.Fatalf("after restart %+v", rep)
	}
}

/* Writes take consecutive versions, and inserts, updates and deletes all verify. */
func TestWriteKeepsTheRegistryVerified(t *testing.T) {
	env, r := fresh(t)
	ctx := context.Background()
	for u := int64(1); u <= 3; u++ {
		if err := grant(ctx, r, u); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Write(ctx, func(ctx context.Context, tx *Tx) error {
		_, err := tx.Exec(ctx, `UPDATE exec.write_grant SET username_snapshot = 'v', version = $1, mac = $2 WHERE user_id = 2`, tx.Seq(), Unsealed())
		if err == nil {
			_, err = tx.Exec(ctx, `DELETE FROM exec.write_grant WHERE user_id = 3`)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if rep := verify(t, r); rep.Seq != 5 {
		t.Fatalf("seq %d", rep.Seq)
	}
	if n := count(t, env, `SELECT count(*) FROM exec.write_grant`); n != 2 {
		t.Fatalf("grants %d", n)
	}
	/* A failing function leaves nothing behind. */
	boom := errors.New("boom")
	if err := r.Write(ctx, func(ctx context.Context, tx *Tx) error {
		_, _ = tx.Exec(ctx, `DELETE FROM exec.write_grant`)
		return boom
	}); !errors.Is(err, boom) {
		t.Fatalf("err %v", err)
	}
	if rep := verify(t, r); rep.Seq != 5 || count(t, env, `SELECT count(*) FROM exec.write_grant`) != 2 {
		t.Fatalf("failed write left traces: %+v", rep)
	}
}

/* A row written without the new version is a caller bug: the write is refused, not sealed, and it is not tampering. */
func TestWriteRefusesRowsOutsideTheVersion(t *testing.T) {
	_, r := fresh(t)
	err := r.Write(context.Background(), func(ctx context.Context, tx *Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO exec.write_grant (user_id, kind, username_snapshot, version, mac)
			VALUES (9, 'unmask', 'u', 1, $1)`, Unsealed())
		return err
	})
	if err == nil || errors.Is(err, ErrTampered) {
		t.Fatalf("err %v", err)
	}
	verify(t, r)
}

/*
Crash windows: dying after the pending record and before COMMIT leaves the
database at committed; dying after COMMIT and before "committed" leaves it
at pending, which the next start advances. Both are accepted. The same holds
for the bootstrap.
*/
func TestCrashWindowsAreAccepted(t *testing.T) {
	ctx := context.Background()
	crash := errors.New("crash")
	for _, c := range []struct {
		stage   string
		seq     int64
		grants  int
		pending bool
	}{{"pending", 1, 0, true}, {"committed", 2, 1, false}} {
		env, r := fresh(t)
		r.hook = func(s string) error {
			if s == c.stage {
				return crash
			}
			return nil
		}
		if err := grant(ctx, r, 1); !errors.Is(err, crash) {
			t.Fatalf("%s: %v", c.stage, err)
		}
		r = restart(t, env, r)
		if rep := verify(t, r); rep.Seq != c.seq || rep.Frozen {
			t.Fatalf("%s: report %+v", c.stage, rep)
		}
		if n := count(t, env, `SELECT count(*) FROM exec.write_grant`); n != c.grants {
			t.Fatalf("%s: grants %d", c.stage, n)
		}
		if f, _ := state.Load(r.path, r.keys.State()); f.Pending != nil != c.pending || f.Committed.HWM != c.seq {
			t.Fatalf("%s: state %+v", c.stage, f)
		}
		if err := grant(ctx, r, 2); err != nil {
			t.Fatalf("%s: next write: %v", c.stage, err)
		}
	}
	for _, stage := range []string{"pending", "committed"} {
		env := testdb.New(t)
		attacktest.Reset(t, env)
		r := New(env.Pool("nms_executor"), keys(t), filepath.Join(t.TempDir(), "state"))
		r.hook = func(s string) error {
			if s == stage {
				return crash
			}
			return nil
		}
		if err := r.Init(ctx); !errors.Is(err, crash) {
			t.Fatalf("bootstrap %s: %v", stage, err)
		}
		r = restart(t, env, r)
		if rep := verify(t, r); rep.Seq != 1 || rep.Frozen {
			t.Fatalf("bootstrap %s: %+v", stage, rep)
		}
	}
}

/* Concurrent read-modify-write updates are serialized: no update is lost. */
func TestWritersAreSerialized(t *testing.T) {
	env, r := fresh(t)
	ctx := context.Background()
	if err := r.Write(ctx, func(ctx context.Context, tx *Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO exec.change_totp (user_id, username_snapshot, ciphertext, key_version, version, mac)
			VALUES (1, 'u', '\x01', 1, $1, $2)`, tx.Seq(), Unsealed())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Go(func() {
			errs <- r.Write(ctx, func(ctx context.Context, tx *Tx) error {
				var f int
				if err := tx.QueryRow(ctx, `SELECT failures FROM exec.change_totp WHERE user_id = 1`).Scan(&f); err != nil {
					return err
				}
				_, err := tx.Exec(ctx, `UPDATE exec.change_totp SET failures = $1, version = $2, mac = $3 WHERE user_id = 1`,
					f+1, tx.Seq(), Unsealed())
				return err
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

/* Every column of every registry table is covered by the MAC (key, content or version). */
func TestTablesCoverEveryColumn(t *testing.T) {
	env := testdb.New(t)
	for _, tb := range tables {
		rows, err := env.Pool("postgres").Query(context.Background(),
			`SELECT column_name FROM information_schema.columns WHERE table_schema = 'exec' AND table_name = $1`, tb.name)
		if err != nil {
			t.Fatal(err)
		}
		got, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		want := []string{tb.version, "mac"}
		for _, c := range append(append([]column(nil), tb.pk...), tb.content...) {
			want = append(want, c.name)
		}
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s: columns %v, covered %v", tb.name, got, want)
		}
	}
}

/* The canonical text of every column type does not depend on session settings. */
func TestVerifyIgnoresSessionSettings(t *testing.T) {
	env, r := fresh(t)
	ctx := context.Background()
	if err := r.Write(ctx, func(ctx context.Context, tx *Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO exec.write_credential (device_id, kind, ciphertext, created_at, nonce, version, mac)
			VALUES (1, 'ssh_write', '\xdeadbeef', '2026-10-26 12:34:56.789012+03', '\x00112233445566778899aabbccddeeff', $1, $2)`, tx.Seq(), Unsealed())
		if err == nil {
			_, err = tx.Exec(ctx, `UPDATE exec.exec_state SET global_fail_window = '{"b": [1, 2.50], "a": null}', version = $1, mac = $2`, tx.Seq(), Unsealed())
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	attacktest.Tamper(t, env, `ALTER ROLE nms_executor SET TimeZone = 'Asia/Kathmandu'`)
	attacktest.Tamper(t, env, `ALTER ROLE nms_executor SET DateStyle = 'SQL, DMY'`)
	attacktest.Tamper(t, env, `ALTER ROLE nms_executor SET bytea_output = 'escape'`)
	t.Cleanup(func() { attacktest.Tamper(t, env, `ALTER ROLE nms_executor RESET ALL`) })
	db, pw := env.Config("nms_executor")
	pool, err := store.Open(ctx, db, pw)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	other := New(pool, keys(t), r.path)
	if _, err := other.Verify(ctx); err != nil {
		t.Fatal(err)
	}
}
