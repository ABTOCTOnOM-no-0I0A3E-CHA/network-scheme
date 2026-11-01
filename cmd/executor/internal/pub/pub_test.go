package pub_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/cmd/executor/internal/pub"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/state"
	"github.com/beekamai/network-scheme/internal/testdb"
)

func TestMain(m *testing.M) { testdb.Main(m) }

var master = [32]byte{9}

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

/* executor is one executor process: registry, guard and the execpub consumer over the test database. */
type executor struct {
	env  *testdb.Env
	pool *pgxpool.Pool
	path string
	g    *freeze.Guard
	c    *pub.Consumer
}

func open(t *testing.T, env *testdb.Env, path string) *executor {
	t.Helper()
	k, err := seal.Derive(&master)
	if err != nil {
		t.Fatal(err)
	}
	pool := env.Pool("nms_executor")
	e := &executor{env: env, pool: pool, path: path}
	e.g = freeze.New(registry.New(pool, k, path), pool, discard)
	if err := e.g.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.c = pub.NewConsumer(pub.New(pool, discard), e.g, func() (bool, bool) {
		frozen, _ := e.g.Frozen()
		return true, frozen
	})
	e.g.Published = func(context.Context, string) { e.c.Wake() }
	return e
}

/* fresh is a fresh install, not frozen, with no pending request. */
func fresh(t *testing.T) *executor {
	t.Helper()
	env := testdb.New(t)
	attacktest.Reset(t, env)
	return open(t, env, filepath.Join(t.TempDir(), "state"))
}

/* restart is a new process over the same database and state file. */
func (e *executor) restart(t *testing.T) *executor {
	t.Helper()
	return open(t, e.env, e.path)
}

/* run runs the consumer loop until the test ends. */
func (e *executor) run(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.c.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

func (e *executor) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := e.env.Pool("postgres").QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

/* recorded reports whether exec_state in the database says frozen. */
func (e *executor) recorded(t *testing.T) bool {
	t.Helper()
	var f bool
	if err := e.env.Pool("postgres").QueryRow(context.Background(), `SELECT "freeze" FROM exec.exec_state`).Scan(&f); err != nil {
		t.Fatal(err)
	}
	return f
}

func (e *executor) frozen() bool {
	f, _ := e.g.Frozen()
	return f
}

/* request is what the api's POST /api/executor/freeze does. */
func (e *executor) request(t *testing.T, uid int64) {
	t.Helper()
	if _, err := e.env.Pool("nms_api").Exec(context.Background(),
		`INSERT INTO execpub.freeze_request (requested_by) VALUES ($1) ON CONFLICT DO NOTHING`, uid); err != nil {
		t.Fatalf("api freeze request: %v", err)
	}
}

func within(t *testing.T, d time.Duration, what string, ok func() bool) time.Duration {
	t.Helper()
	start := time.Now()
	for !ok() {
		if time.Since(start) > d {
			t.Fatalf("%s: not within %s", what, d)
		}
		time.Sleep(20 * time.Millisecond)
	}
	return time.Since(start)
}

/*
C2d: the api's freeze request freezes the real executor within 5 s, through
LISTEN and through polling alone (an insert that notifies nobody): the latch,
exec_state and the published status say frozen, the request is consumed, and
one audit row and one alert record it.
*/
func TestPanelRequestFreezesWithinFiveSeconds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		insert func(e *executor)
	}{
		{"listen", func(e *executor) { e.request(t, 7) }},
		{"polling", func(e *executor) {
			/* A replica session fires no trigger: no NOTIFY, only polling can see it. */
			if err := pgx.BeginFunc(context.Background(), e.env.Pool("postgres"), func(tx pgx.Tx) error {
				if _, err := tx.Exec(context.Background(), `SET LOCAL session_replication_role = replica`); err != nil {
					return err
				}
				_, err := tx.Exec(context.Background(), `INSERT INTO execpub.freeze_request (requested_by) VALUES (7)`)
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := fresh(t)
			e.run(t)
			within(t, 5*time.Second, "status published", func() bool {
				return e.count(t, `SELECT count(*) FROM execpub.status WHERE enabled AND NOT frozen AND at > now() - interval '10 s'`) == 1
			})
			time.Sleep(300 * time.Millisecond) /* the listener is up (it wakes the loop once when it is) */
			tc.insert(e)
			took := within(t, 5*time.Second, "frozen", e.frozen)
			t.Logf("%s: frozen after %s", tc.name, took)
			within(t, 5*time.Second, "status frozen", func() bool {
				return e.count(t, `SELECT count(*) FROM execpub.status WHERE frozen`) == 1
			})
			if !e.recorded(t) {
				t.Fatal("exec_state not frozen")
			}
			if n := e.count(t, `SELECT count(*) FROM execpub.freeze_request`); n != 0 {
				t.Fatalf("%d requests left", n)
			}
			if n := e.count(t, `SELECT count(*) FROM exec.audit_event WHERE action = 'executor.freeze.panel'
				AND convert_from(payload, 'UTF8')::jsonb->'details'->>'claimed_user_id' = '7'
				AND convert_from(payload, 'UTF8')::jsonb->'details'->>'requests' = '1'`); n != 1 {
				t.Fatalf("%d audit rows of the consumption", n)
			}
			if n := e.count(t, `SELECT count(*) FROM execpub.alert WHERE kind = 'executor_freeze' AND severity = 'warning'`); n != 1 {
				t.Fatalf("%d executor_freeze alerts", n)
			}
			if frozen, _ := e.restart(t).g.Frozen(); !frozen {
				t.Fatal("the panel's freeze did not survive a restart")
			}
		})
	}
}

/*
The api cannot lift a freeze: a notification with any payload is a wake-up
only, more requests only freeze, and it has no UPDATE, DELETE or TRUNCATE on
any execpub table (there is no column or route that means "off").
*/
func TestPanelCannotLiftFreeze(t *testing.T) {
	e := fresh(t)
	e.run(t)
	api := e.env.Pool("nms_api")
	ctx := context.Background()
	/* A wake-up with a payload and no request changes nothing. */
	if _, err := api.Exec(ctx, `SELECT pg_notify('execpub_freeze', 'freeze off')`); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	if e.frozen() || e.recorded(t) {
		t.Fatal("a bare notification froze")
	}
	e.request(t, 3)
	within(t, 5*time.Second, "frozen", e.frozen)
	for _, payload := range []string{"off", "unfreeze", `{"freeze":false}`, ""} {
		if _, err := api.Exec(ctx, `SELECT pg_notify('execpub_freeze', $1)`, payload); err != nil {
			t.Fatal(err)
		}
	}
	e.request(t, 3)
	rows, err := e.env.Pool("postgres").Query(ctx, `SELECT format('%I.%I', schemaname, tablename) FROM pg_tables WHERE schemaname = 'execpub'`)
	if err != nil {
		t.Fatal(err)
	}
	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || len(tables) != 5 {
		t.Fatalf("execpub tables %v, %v", tables, err)
	}
	for _, tb := range tables {
		for _, sql := range []string{"UPDATE " + tb + " SET at = now()", "DELETE FROM " + tb, "TRUNCATE " + tb} {
			if strings.HasSuffix(tb, "device_busy") {
				sql = strings.Replace(sql, "SET at", "SET since", 1)
			} else if strings.HasSuffix(tb, "session_summary") {
				sql = strings.Replace(sql, "SET at", "SET closed_at", 1)
			}
			var pe *pgconn.PgError
			if _, err := api.Exec(ctx, sql); !errors.As(err, &pe) || pe.Code != "42501" {
				t.Errorf("api %q: %v, want permission denied", sql, err)
			}
		}
	}
	time.Sleep(2 * time.Second)
	if !e.frozen() || !e.recorded(t) {
		t.Fatal("the api lifted the freeze")
	}
}

/*
A flood of requests while frozen grows nothing: the table stays one row,
consumptions (and their audit rows) are paced by frozenEvery, and no alert
repeats. After the host's freeze off a pending request freezes again at
once (it was never dropped).
*/
func TestFreezeRequestFlood(t *testing.T) {
	defer pub.SetPace(500*time.Millisecond, time.Hour)()
	e := fresh(t)
	e.run(t)
	e.request(t, 1)
	within(t, 5*time.Second, "frozen", e.frozen)
	for i := range 300 {
		e.request(t, int64(i+2))
	}
	time.Sleep(2 * time.Second)
	if n := e.count(t, `SELECT count(*) FROM execpub.freeze_request`); n != 1 {
		t.Fatalf("%d pending requests after the flood", n)
	}
	if n := e.count(t, `SELECT count(*) FROM exec.audit_event WHERE action = 'executor.freeze.panel'`); n != 1 {
		t.Fatalf("%d consumptions during the flood", n)
	}
	if n := e.count(t, `SELECT count(*) FROM execpub.alert WHERE kind = 'executor_freeze'`); n != 1 {
		t.Fatalf("%d executor_freeze alerts", n)
	}
	if err := e.g.FreezeOff(context.Background(), nil, nil); err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, `SELECT count(*) FROM execpub.alert WHERE kind = 'executor_unfrozen'`); n != 1 {
		t.Fatalf("%d executor_unfrozen markers", n)
	}
	within(t, 5*time.Second, "frozen again by the pending request", e.frozen)
	within(t, 5*time.Second, "request consumed", func() bool { return e.count(t, `SELECT count(*) FROM execpub.freeze_request`) == 0 })
	if !e.recorded(t) {
		t.Fatal("exec_state not frozen")
	}
}

/*
A request consumed while the host's freeze off runs is never lifted by it:
the consumption latches before its commit, so the freeze off that started
earlier finds a new generation and leaves the executor frozen (latch and
sticky flag; a restart is frozen too).
*/
func TestFreezeOffCannotLiftAConcurrentRequest(t *testing.T) {
	e := fresh(t)
	ctx := context.Background()
	e.g.Trigger(ctx, freeze.KindHostFreeze, "host: test")
	e.request(t, 4)
	err := e.g.FreezeOff(ctx, func(ctx context.Context) error {
		/* Runs after freeze off took its generation and before it writes. */
		return e.c.Consume(ctx)
	}, nil)
	if !errors.Is(err, freeze.ErrFrozen) {
		t.Fatalf("freeze off during a consumption: %v, want ErrFrozen", err)
	}
	if !e.frozen() {
		t.Fatal("freeze off lifted the panel's freeze")
	}
	if n := e.count(t, `SELECT count(*) FROM execpub.freeze_request`); n != 0 {
		t.Fatalf("%d requests left", n)
	}
	if !e.restart(t).frozen() {
		t.Fatal("not frozen after a restart")
	}
	/* The other order: a freeze off that commits first is followed by the request's freeze. */
	e2 := e.restart(t)
	if err := e2.g.FreezeOff(ctx, nil, nil); err != nil {
		t.Fatal(err)
	}
	e2.request(t, 5)
	if err := e2.c.Consume(ctx); err != nil {
		t.Fatal(err)
	}
	if !e2.frozen() || !e2.recorded(t) {
		t.Fatal("a request after freeze off did not freeze")
	}
}

/*
The request is deleted in the transaction that records the freeze: a crash
after the DELETE and before the COMMIT (here an error from the same
transaction) leaves the request in place and nothing recorded, while the
latch and the sticky flag (set before) keep the executor frozen, also across
a restart, which then consumes it.
*/
func TestCrashBetweenDeleteAndFreezeImpossible(t *testing.T) {
	e := fresh(t)
	ctx := context.Background()
	e.request(t, 6)
	err := e.g.Request(ctx, "panel: test", func(ctx context.Context, tx pgx.Tx, head state.AuditHead) (state.AuditHead, error) {
		if _, err := pub.ConsumeRequest(ctx, tx, head); err != nil {
			return head, err
		}
		if n := 0; tx.QueryRow(ctx, `SELECT count(*) FROM execpub.freeze_request`).Scan(&n) != nil || n != 0 {
			return head, errors.New("the request was not deleted in the transaction")
		}
		if !e.frozen() {
			return head, errors.New("not latched before the commit")
		}
		return head, errors.New("crash after the delete")
	})
	if err == nil || !strings.Contains(err.Error(), "crash after the delete") {
		t.Fatalf("request: %v", err)
	}
	if n := e.count(t, `SELECT count(*) FROM execpub.freeze_request`); n != 1 {
		t.Fatalf("%d requests after the crash, want the request kept", n)
	}
	if e.recorded(t) {
		t.Fatal("exec_state frozen by a transaction that did not commit")
	}
	if n := e.count(t, `SELECT count(*) FROM exec.audit_event WHERE action = 'executor.freeze.panel'`); n != 0 {
		t.Fatalf("%d audit rows of an uncommitted consumption", n)
	}
	if !e.frozen() {
		t.Fatal("not latched before the commit")
	}
	e2 := e.restart(t)
	if !e2.frozen() {
		t.Fatal("not frozen after a restart (sticky flag)")
	}
	if err := e2.c.Consume(ctx); err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, `SELECT count(*) FROM execpub.freeze_request`); n != 0 || !e2.recorded(t) {
		t.Fatalf("after the retry: %d requests, recorded %v", n, e2.recorded(t))
	}
	if err := e2.c.Consume(ctx); !errors.Is(err, pub.ErrNoRequest) {
		t.Fatalf("nothing pending: %v", err)
	}
}

/* The writer API: alerts bounded and cleaned, busy devices held by one session, session summaries. */
func TestPublisherWriters(t *testing.T) {
	e := fresh(t)
	ctx := context.Background()
	p := pub.New(e.pool, discard)
	for _, bad := range [][2]string{{"Bad!", "high"}, {"", "high"}, {"x", "critical"}, {strings.Repeat("a", 65), "high"}} {
		if err := p.Alert(ctx, bad[0], bad[1], 0, "x"); err == nil {
			t.Errorf("alert %q %q accepted", bad[0], bad[1])
		}
	}
	evil := "<script>alert(1)</script>\x1b[2J\x1b]52;c;cGF5bG9hZA==\a\u202eevil\x00" + strings.Repeat("я", 2000)
	if err := p.Alert(ctx, "hostkey_mismatch_write", "high", 900001, evil); err != nil {
		t.Fatal(err)
	}
	var text string
	var dev int64
	if err := e.env.Pool("postgres").QueryRow(ctx, `SELECT text, device_id FROM execpub.alert WHERE kind = 'hostkey_mismatch_write'`).Scan(&text, &dev); err != nil {
		t.Fatal(err)
	}
	if dev != 900001 || len(text) > pub.MaxAlertText || !utf8.ValidString(text) || !strings.HasPrefix(text, "<script>alert(1)</script> [2J ]52;c;") ||
		strings.ContainsAny(text, "\x1b\a\x00\u202e") {
		t.Fatalf("stored alert text %q (%d bytes)", text[:min(len(text), 80)], len(text))
	}

	a, b := [16]byte{1}, [16]byte{2}
	t.Cleanup(func() {
		_, _ = e.env.Pool("postgres").Exec(context.Background(), `DELETE FROM execpub.device_busy WHERE device_id = 900001;
			DELETE FROM execpub.session_summary WHERE device_id = 900001`)
	})
	if err := p.Busy(ctx, 900001, a); err != nil {
		t.Fatal(err)
	}
	if err := p.Busy(ctx, 900001, b); !errors.Is(err, pub.ErrDeviceBusy) {
		t.Fatalf("second session on a busy device: %v", err)
	}
	if err := p.Free(ctx, 900001, b); err != nil || e.count(t, `SELECT count(*) FROM execpub.device_busy WHERE device_id = 900001`) != 1 {
		t.Fatalf("another session freed the device: %v", err)
	}
	if err := p.Free(ctx, 900001, a); err != nil || e.count(t, `SELECT count(*) FROM execpub.device_busy WHERE device_id = 900001`) != 0 {
		t.Fatalf("free: %v", err)
	}

	if err := p.SessionOpened(ctx, a, 11, 900001, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := p.SessionClosed(ctx, a, 900001, "done", nil); err == nil {
		t.Error("unknown end status accepted")
	}
	if err := p.SessionClosed(ctx, a, 900001, "closed", []byte{1}); err == nil {
		t.Error("short post hash accepted")
	}
	post := make([]byte, 32)
	post[0] = 0xab
	if err := p.SessionClosed(ctx, a, 900001, "closed", post); err != nil {
		t.Fatal(err)
	}
	if err := p.SessionClosed(ctx, a, 900001, "rolled_back", nil); err == nil {
		t.Error("a closed summary closed again")
	}
	if n := e.count(t, `SELECT count(*) FROM execpub.session_summary WHERE device_id = 900001 AND status = 'closed'
		AND closed_at IS NOT NULL AND post_sha256 = $1`, post); n != 1 {
		t.Fatalf("%d closed summaries", n)
	}
}

/*
The consumer's own path: when the freeze cannot be recorded (here the
registry's tables are locked past its timeouts), the request stays in place
and the executor frozen; the next consumption records both.
*/
func TestFailedFreezeWriteKeepsTheRequest(t *testing.T) {
	e := fresh(t)
	ctx := context.Background()
	e.request(t, 8)
	tx, err := e.env.Pool("postgres").Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `LOCK TABLE exec.exec_state IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	cerr := e.c.Consume(ctx)
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if cerr == nil || errors.Is(cerr, pub.ErrNoRequest) {
		t.Fatalf("consumption with the registry locked: %v", cerr)
	}
	if n := e.count(t, `SELECT count(*) FROM execpub.freeze_request`); n != 1 {
		t.Fatalf("%d requests after a failed freeze write, want the request kept", n)
	}
	if !e.frozen() || e.recorded(t) {
		t.Fatalf("after a failed write: latched %v, recorded %v", e.frozen(), e.recorded(t))
	}
	if err := e.c.Consume(ctx); err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, `SELECT count(*) FROM execpub.freeze_request`); n != 0 || !e.recorded(t) {
		t.Fatalf("retry: %d requests, recorded %v", n, e.recorded(t))
	}
}
