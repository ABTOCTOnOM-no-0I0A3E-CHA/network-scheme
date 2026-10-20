package audit_test

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/internal/audit"
	"github.com/beekamai/network-scheme/internal/testdb"
)

func TestMain(m *testing.M) { testdb.Main(m) }

/*
reset empties the log as an attacker with superuser rights would have to:
the guard trigger is disabled for the duration of one transaction.
*/
func reset(t *testing.T, env *testdb.Env) {
	t.Helper()
	superExec(t, env,
		`TRUNCATE audit.event RESTART IDENTITY`,
		`INSERT INTO audit.chain_head (singleton, last_id, hash) VALUES (true, 0, decode(repeat('00', 32), 'hex'))
		 ON CONFLICT (singleton) DO UPDATE SET last_id = 0, hash = EXCLUDED.hash`)
}

/* superExec runs statements as postgres with the audit guard triggers disabled. */
func superExec(t *testing.T, env *testdb.Env, stmts ...string) {
	t.Helper()
	ctx := context.Background()
	err := pgx.BeginFunc(ctx, env.Pool("postgres"), func(tx pgx.Tx) error {
		all := append([]string{
			`ALTER TABLE audit.event DISABLE TRIGGER USER`,
			`ALTER TABLE audit.chain_head DISABLE TRIGGER USER`,
		}, stmts...)
		all = append(all,
			`ALTER TABLE audit.event ENABLE TRIGGER USER`,
			`ALTER TABLE audit.chain_head ENABLE TRIGGER USER`)
		for _, s := range all {
			if _, err := tx.Exec(ctx, s); err != nil {
				return fmt.Errorf("%s: %w", s, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func appendN(t *testing.T, pool *pgxpool.Pool, n int) {
	t.Helper()
	ctx := context.Background()
	for i := range n {
		uid := int64(i % 7)
		e := audit.Event{
			TS:         time.Now(),
			UserID:     &uid,
			IP:         "192.0.2.10",
			UserAgent:  "test",
			Action:     fmt.Sprintf("test.action%d", i%3),
			ObjectType: "device",
			ObjectID:   fmt.Sprint(i),
			Result:     "ok",
			Details:    map[string]any{"i": i, "z": "last", "a": []any{1, "x"}},
		}
		if i%5 == 0 {
			e.UserID = nil
		}
		err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			_, err := audit.Append(ctx, tx, e)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func verify(t *testing.T, env *testdb.Env) audit.VerifyResult {
	t.Helper()
	res, err := audit.Verify(context.Background(), env.Pool("nms_cli"))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestAppendAndVerify(t *testing.T) {
	env := testdb.New(t)
	reset(t, env)

	empty := verify(t, env)
	if empty.Count != 0 || empty.Break != nil {
		t.Fatalf("empty log: %+v", empty)
	}

	appendN(t, env.Pool("nms_api"), 100)
	res := verify(t, env)
	if res.Count != 100 || res.Break != nil {
		t.Fatalf("got Count=%d Break=%+v, want 100 and no break", res.Count, res.Break)
	}
	if res.LastID != 100 || len(res.LastHash) != 32 {
		t.Fatalf("LastID=%d len(LastHash)=%d", res.LastID, len(res.LastHash))
	}
}

func TestAppendTimestampIsUTCMicroseconds(t *testing.T) {
	env := testdb.New(t)
	reset(t, env)
	ctx := context.Background()
	ts := time.Date(2026, 10, 19, 15, 4, 5, 123456789, time.FixedZone("MSK", 3*3600))
	var id int64
	err := pgx.BeginFunc(ctx, env.Pool("nms_api"), func(tx pgx.Tx) (err error) {
		id, err = audit.Append(ctx, tx, audit.Event{TS: ts, Action: "login"})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var payload []byte
	if err := env.Pool("nms_cli").QueryRow(ctx,
		`SELECT payload FROM audit.event WHERE id = $1`, id).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(payload, []byte(`"2026-10-19T12:04:05.123456Z"`)) {
		t.Fatalf("payload timestamp not UTC/µs: %s", payload)
	}
	if res := verify(t, env); res.Break != nil {
		t.Fatalf("unexpected break %+v", res.Break)
	}
}

func TestConcurrentAppendKeepsChain(t *testing.T) {
	env := testdb.New(t)
	reset(t, env)
	ctx := context.Background()
	pool := env.Pool("nms_api")

	var wg sync.WaitGroup
	errs := make(chan error, 50*10)
	for g := range 50 {
		wg.Go(func() {
			for i := range 10 {
				err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
					_, err := audit.Append(ctx, tx, audit.Event{
						TS: time.Now(), Action: "concurrent", ObjectID: fmt.Sprintf("%d-%d", g, i),
					})
					return err
				})
				if err != nil {
					errs <- err
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	res := verify(t, env)
	if res.Count != 500 || res.Break != nil {
		t.Fatalf("got Count=%d Break=%+v, want 500 and no break", res.Count, res.Break)
	}
}

func TestRolledBackAppendLeavesNoGapBreak(t *testing.T) {
	env := testdb.New(t)
	reset(t, env)
	ctx := context.Background()
	pool := env.Pool("nms_api")
	appendN(t, pool, 3)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Append(ctx, tx, audit.Event{TS: time.Now(), Action: "rolled.back"}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	appendN(t, pool, 3)

	if res := verify(t, env); res.Count != 6 || res.Break != nil {
		t.Fatalf("got Count=%d Break=%+v", res.Count, res.Break)
	}
}

func TestTamperDetected(t *testing.T) {
	env := testdb.New(t)
	cases := []struct {
		name   string
		stmts  []string
		wantID int64
		reason string
	}{
		{"payload changed", []string{
			`UPDATE audit.event SET payload = convert_to(replace(convert_from(payload, 'UTF8'), '"ok"', '"denied"'), 'UTF8') WHERE id = 10`,
		}, 10, "hash mismatch"},
		{"row deleted", []string{`DELETE FROM audit.event WHERE id = 20`}, 21, "prev mismatch"},
		{"indexed action changed", []string{`UPDATE audit.event SET action = 'forged' WHERE id = 30`}, 30, "indexed column mismatch"},
		{"indexed user changed", []string{`UPDATE audit.event SET user_id = 999 WHERE id = 31`}, 31, "indexed column mismatch"},
		{"indexed ts changed", []string{`UPDATE audit.event SET ts = ts - interval '1 day' WHERE id = 32`}, 32, "indexed column mismatch"},
		{"tail deleted, head kept", []string{`DELETE FROM audit.event WHERE id > 90`}, 100, "head mismatch"},
		{"head rewritten", []string{`UPDATE audit.chain_head SET hash = sha256('x')`}, 100, "head mismatch"},
		{"head row deleted", []string{`DELETE FROM audit.chain_head`}, 0, "head mismatch"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reset(t, env)
			appendN(t, env.Pool("nms_api"), 100)
			superExec(t, env, c.stmts...)
			res := verify(t, env)
			if res.Break == nil || res.Break.ID != c.wantID || res.Break.Reason != c.reason {
				t.Fatalf("Break = %+v, want {ID:%d Reason:%q}", res.Break, c.wantID, c.reason)
			}
		})
	}
}

func TestAuditImmutableForAllRoles(t *testing.T) {
	env := testdb.New(t)
	reset(t, env)
	appendN(t, env.Pool("nms_api"), 5)
	ctx := context.Background()

	for _, role := range []string{"nms_migrator", "nms_api", "nms_cli"} {
		for _, sql := range []string{
			`UPDATE audit.event SET action = 'x'`,
			`UPDATE audit.event SET action = 'x' WHERE false`,
			`DELETE FROM audit.event`,
			`DELETE FROM audit.event WHERE false`,
			`TRUNCATE audit.event`,
			`DELETE FROM audit.chain_head`,
			`TRUNCATE audit.chain_head`,
		} {
			if _, err := env.Pool(role).Exec(ctx, sql); err == nil {
				t.Errorf("%s: %q succeeded, want error", role, sql)
			}
		}
	}
	if res := verify(t, env); res.Count != 5 || res.Break != nil {
		t.Fatalf("log changed: Count=%d Break=%+v", res.Count, res.Break)
	}
}

func TestAnchorsDetectTruncation(t *testing.T) {
	env := testdb.New(t)
	reset(t, env)
	appendN(t, env.Pool("nms_api"), 100)
	ctx := context.Background()
	cli := env.Pool("nms_cli")

	var h []byte
	if err := cli.QueryRow(ctx, `SELECT hash FROM audit.event WHERE id = 50`).Scan(&h); err != nil {
		t.Fatal(err)
	}
	line := audit.Anchor{ID: 50, Hash: h, At: time.Now()}.String()
	anchors, err := audit.ParseAnchors(strings.NewReader("\n" + line + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors) != 1 || anchors[0].ID != 50 || !bytes.Equal(anchors[0].Hash, h) {
		t.Fatalf("round trip: %+v", anchors)
	}
	if err := audit.CheckAnchors(ctx, cli, anchors); err != nil {
		t.Fatalf("intact log: %v", err)
	}

	/* The attacker drops the tail and rewrites the head, so Verify alone passes. */
	superExec(t, env,
		`DELETE FROM audit.event WHERE id >= 50`,
		`UPDATE audit.chain_head SET (last_id, hash) = (SELECT id, hash FROM audit.event WHERE id = 49)`)
	if res := verify(t, env); res.Break != nil || res.Count != 49 {
		t.Fatalf("Verify after consistent truncation: Count=%d Break=%+v", res.Count, res.Break)
	}
	if err := audit.CheckAnchors(ctx, cli, anchors); err == nil {
		t.Fatal("CheckAnchors = nil after truncation, want error")
	}
}

func TestCheckAnchorsHashMismatch(t *testing.T) {
	env := testdb.New(t)
	reset(t, env)
	appendN(t, env.Pool("nms_api"), 3)
	bad := []audit.Anchor{{ID: 2, Hash: make([]byte, 32)}}
	if err := audit.CheckAnchors(context.Background(), env.Pool("nms_cli"), bad); err == nil {
		t.Fatal("CheckAnchors = nil for wrong hash")
	}
}

func TestParseAnchorsRejectsMalformed(t *testing.T) {
	good := "7 " + strings.Repeat("ab", 32) + " 2026-10-19T12:00:00Z"
	if _, err := audit.ParseAnchors(strings.NewReader(good)); err != nil {
		t.Fatalf("good line: %v", err)
	}
	for _, line := range []string{
		"7 " + strings.Repeat("ab", 32),
		"x " + strings.Repeat("ab", 32) + " 2026-10-19T12:00:00Z",
		"0 " + strings.Repeat("ab", 32) + " 2026-10-19T12:00:00Z",
		"7 " + strings.Repeat("ab", 31) + " 2026-10-19T12:00:00Z",
		"7 " + strings.Repeat("zz", 32) + " 2026-10-19T12:00:00Z",
		"7 " + strings.Repeat("ab", 32) + " yesterday",
		"7 " + strings.Repeat("ab", 32) + " 2026-10-19T12:00:00Z extra",
	} {
		if _, err := audit.ParseAnchors(strings.NewReader(line)); err == nil {
			t.Errorf("ParseAnchors(%q) = nil error", line)
		}
	}
}
