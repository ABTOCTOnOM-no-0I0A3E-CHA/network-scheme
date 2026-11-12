package pub_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/audit"
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

/* row returns a row of a verified snapshot, as the executor's session code gets it (registry.View). */
func (e *executor) row(t *testing.T, table string, pk ...any) registry.Row {
	t.Helper()
	var r registry.Row
	if err := e.g.View(context.Background(), func(s *registry.Snapshot) error {
		var ok bool
		if r, ok = s.Get(table, pk...); !ok {
			return fmt.Errorf("no %s row %v", table, pk)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return r
}

/* writeDevice registers a write device through the registry (fp nil: no host key accepted yet) and returns its verified row. */
func (e *executor) writeDevice(t *testing.T, id int64, address string, fp any) registry.Row {
	t.Helper()
	algo := any(nil)
	if fp != nil {
		algo = "ssh-ed25519"
	}
	if err := e.g.HostWrite(context.Background(), func(_ context.Context, _ *registry.Snapshot, tx *registry.Tx) error {
		return tx.Put("write_device", map[string]any{"device_id": id, "address": netip.MustParseAddr(address), "port": 22,
			"protocol": "ssh", "write_group": "core", "write_driver": "esr", "hostkey_algo": algo, "hostkey_fp": fp,
			"allow_ssh_rsa_sha1": false, "writes_enabled": false, "backup_via_executor": false})
	}); err != nil {
		t.Fatal(err)
	}
	return e.row(t, "write_device", id)
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
	if err != nil || len(tables) != 7 {
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
	t.Cleanup(pub.SetPace(500*time.Millisecond, time.Hour))
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
	/* Only a write_device row of a verified snapshot: the zero row and other tables are refused. */
	if err := p.Busy(ctx, registry.Row{}, a); err == nil {
		t.Error("busy from a zero row accepted")
	}
	if err := p.Busy(ctx, e.row(t, "exec_state", true), a); err == nil {
		t.Error("busy from an exec_state row accepted")
	}
	const fp = "SHA256:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
	if err := p.Busy(ctx, e.writeDevice(t, 900001, "10.9.9.9", fp), a); err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, `SELECT count(*) FROM execpub.device_busy WHERE device_id = 900001 AND address = '10.9.9.9' AND hostkey_fp = $1`, fp); n != 1 {
		t.Fatal("busy row without the registry's address and host key")
	}
	if err := p.Busy(ctx, e.writeDevice(t, 900001, "10.9.9.9", fp), b); !errors.Is(err, pub.ErrDeviceBusy) {
		t.Fatalf("second session on a busy device: %v", err)
	}
	if err := p.Free(ctx, 900001, b); err != nil || e.count(t, `SELECT count(*) FROM execpub.device_busy WHERE device_id = 900001`) != 1 {
		t.Fatalf("another session freed the device: %v", err)
	}
	if err := p.Free(ctx, 900001, a); err != nil || e.count(t, `SELECT count(*) FROM execpub.device_busy WHERE device_id = 900001`) != 0 {
		t.Fatalf("free: %v", err)
	}
	/* A device whose host key is not accepted yet: no fingerprint, the id and address still published. */
	if err := p.Busy(ctx, e.writeDevice(t, 900001, "10.9.9.10", nil), a); err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, `SELECT count(*) FROM execpub.device_busy WHERE device_id = 900001 AND address = '10.9.9.10' AND hostkey_fp IS NULL`); n != 1 {
		t.Fatal("busy row of a device without a host key")
	}
	_ = p.Free(ctx, 900001, a)

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

/* The status row is rewritten every heartbeat even when nothing changes, so its "at" tells the panel the executor is alive. */
func TestStatusHeartbeat(t *testing.T) {
	t.Cleanup(pub.SetTiming(300*time.Millisecond, time.Hour))
	e := fresh(t)
	e.run(t)
	at := func() (ts time.Time) {
		t.Helper()
		if err := e.env.Pool("postgres").QueryRow(context.Background(), `SELECT coalesce(max(at), '2000-01-01') FROM execpub.status`).Scan(&ts); err != nil {
			t.Fatal(err)
		}
		return ts
	}
	within(t, 5*time.Second, "status published", func() bool { return time.Since(at()) < time.Minute })
	first := at()
	within(t, 5*time.Second, "status rewritten without a change", func() bool { return at().After(first) })
}

/* A flood of wake-ups (anyone may NOTIFY) reads freeze_request at most once every minProbe. */
func TestWakeFloodIsBounded(t *testing.T) {
	t.Cleanup(pub.SetPace(time.Hour, time.Hour))
	e := fresh(t)
	e.run(t)
	time.Sleep(500 * time.Millisecond)
	before := e.c.Probes()
	start := time.Now()
	for time.Since(start) < 2*time.Second {
		e.c.Wake()
		time.Sleep(time.Millisecond)
	}
	got := e.c.Probes() - before
	if limit := int64(2*time.Second/pub.MinProbe) + 2; got > limit || got < 2 {
		t.Fatalf("%d reads in 2 s of wake-ups, want 2..%d", got, limit)
	}
}

/* A lost LISTEN connection is opened again: with polling off, a request still freezes through the new one. */
func TestListenReconnects(t *testing.T) {
	t.Cleanup(pub.SetPace(time.Hour, time.Hour))
	t.Cleanup(pub.SetTiming(30*time.Second, 200*time.Millisecond))
	e := fresh(t)
	e.run(t)
	listener := func() (pid int) {
		t.Helper()
		_ = e.env.Pool("postgres").QueryRow(context.Background(), `SELECT coalesce(max(pid), 0) FROM pg_stat_activity
			WHERE usename = 'nms_executor' AND query ILIKE 'LISTEN%'`).Scan(&pid)
		return pid
	}
	within(t, 5*time.Second, "listening", func() bool { return listener() != 0 })
	old := listener()
	if _, err := e.env.Pool("postgres").Exec(context.Background(), `SELECT pg_terminate_backend($1)`, old); err != nil {
		t.Fatal(err)
	}
	within(t, 5*time.Second, "listening again", func() bool { p := listener(); return p != 0 && p != old })
	time.Sleep(200 * time.Millisecond)
	e.request(t, 12)
	within(t, 5*time.Second, "frozen through the new LISTEN", e.frozen)
}

/* A panel request on an executor the host already froze keeps the host's reason in exec_state. */
func TestRequestKeepsAnExistingFreezeReason(t *testing.T) {
	e := fresh(t)
	ctx := context.Background()
	e.g.Trigger(ctx, freeze.KindHostFreeze, "host: maintenance")
	e.request(t, 13)
	if err := e.c.Consume(ctx); err != nil {
		t.Fatal(err)
	}
	var reason string
	if err := e.env.Pool("postgres").QueryRow(ctx, `SELECT freeze_reason FROM exec.exec_state`).Scan(&reason); err != nil || reason != "host: maintenance" {
		t.Fatalf("freeze_reason %q (%v)", reason, err)
	}
}

/* The guard's own alerts (reasons carry database errors) are cleaned at the database boundary as well. */
func TestGuardAlertTextIsCleaned(t *testing.T) {
	e := fresh(t)
	e.g.Trigger(context.Background(), freeze.KindTamper, "bad MAC\x1b[31m in \u202eexec\x00"+strings.Repeat("я", 800))
	var text string
	if err := e.env.Pool("postgres").QueryRow(context.Background(), `SELECT text FROM execpub.alert WHERE kind = 'executor_tamper'`).Scan(&text); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(text, "bad MAC [31m in  exec ") || len(text) > freeze.MaxAlertText || !utf8.ValidString(text) {
		t.Fatalf("alert text %q (%d bytes)", text[:min(len(text), 40)], len(text))
	}
}

/*
A request that freezes an unfrozen executor owes its executor_freeze alert
until a write succeeds: the first write fails (registry locked), the retry
on the then frozen executor still publishes it, once.
*/
func TestFreezeAlertOwedAcrossAFailedWrite(t *testing.T) {
	e := fresh(t)
	ctx := context.Background()
	e.request(t, 14)
	tx, err := e.env.Pool("postgres").Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `LOCK TABLE exec.exec_state IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	cerr := e.c.Consume(ctx)
	_ = tx.Rollback(ctx)
	if cerr == nil || !e.frozen() {
		t.Fatalf("first consumption: %v, frozen %v", cerr, e.frozen())
	}
	if n := e.count(t, `SELECT count(*) FROM execpub.alert WHERE kind = 'executor_freeze'`); n != 0 {
		t.Fatalf("%d alerts before any write succeeded", n)
	}
	if err := e.c.Consume(ctx); err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, `SELECT count(*) FROM execpub.alert WHERE kind = 'executor_freeze'`); n != 1 {
		t.Fatalf("%d executor_freeze alerts, want the owed one", n)
	}
}

/*
The host drops the pending request in its freeze off transaction while a
consumption that already read it waits for the registry: the consumption
finds nothing in its own transaction, writes nothing, does not latch again,
and the freeze off lifts the freeze (no "new freeze arrived"). The
consumption is held inside freeze off's write, so it always comes second.
*/
func TestDroppedRequestDoesNotFreeze(t *testing.T) {
	e := fresh(t)
	ctx := context.Background()
	e.g.Trigger(ctx, freeze.KindHostFreeze, "host: drill")
	e.request(t, 15)
	done := make(chan error, 1)
	err := e.g.FreezeOff(ctx, nil, func(tx *registry.Tx) error {
		tx.Audit(func(ctx context.Context, tx pgx.Tx, head state.AuditHead) (state.AuditHead, error) {
			if n, _, _, err := pub.DropRequests(ctx, tx); err != nil || n != 1 {
				return head, fmt.Errorf("dropped %d: %v", n, err)
			}
			/* The consumption starts now: it reads the request (not deleted yet for it) and waits for the registry's lock. */
			go func() { done <- e.c.Consume(context.Background()) }()
			time.Sleep(300 * time.Millisecond)
			return audit.Append(audit.Event{UA: "nmsctl", Action: "admin.freeze-off", Object: "executor", Result: audit.OK})(ctx, tx, head)
		})
		return nil
	})
	if err != nil {
		t.Fatalf("freeze off: %v", err)
	}
	if cerr := <-done; !errors.Is(cerr, freeze.ErrNoRequest) {
		t.Fatalf("consumption after the drop: %v, want freeze.ErrNoRequest", cerr)
	}
	if e.frozen() || e.recorded(t) || e.restart(t).frozen() {
		t.Fatal("a dropped request froze the executor")
	}
}

/* The consumption finds the request gone in its own transaction: freeze.ErrNoRequest, nothing written, the early latch undone. */
func TestRequestGoneInTheTransaction(t *testing.T) {
	e := fresh(t)
	ctx := context.Background()
	e.request(t, 16)
	err := e.g.Request(ctx, "panel: test", func(ctx context.Context, tx pgx.Tx, head state.AuditHead) (state.AuditHead, error) {
		if _, _, _, err := pub.DropRequests(ctx, tx); err != nil {
			return head, err
		}
		return pub.ConsumeRequest(ctx, tx, head)
	})
	if !errors.Is(err, freeze.ErrNoRequest) {
		t.Fatalf("request gone: %v", err)
	}
	if e.frozen() || e.recorded(t) || e.restart(t).frozen() {
		t.Fatal("frozen without a request")
	}
	if n := e.count(t, `SELECT count(*) FROM execpub.freeze_request`); n != 1 {
		t.Fatalf("%d requests: the rolled back transaction must keep it", n)
	}
	if n := e.count(t, `SELECT count(*) FROM execpub.alert WHERE kind = 'executor_freeze'`); n != 0 {
		t.Fatalf("%d alerts for a freeze that did not happen", n)
	}
}
