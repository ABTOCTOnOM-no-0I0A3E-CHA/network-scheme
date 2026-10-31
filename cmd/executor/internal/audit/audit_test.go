package audit_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/audit"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/state"
	"github.com/beekamai/network-scheme/internal/testdb"
)

func TestMain(m *testing.M) { testdb.Main(m) }

func setup(t *testing.T) (*testdb.Env, *registry.Registry) {
	t.Helper()
	env := testdb.New(t)
	attacktest.Reset(t, env)
	k, err := seal.Derive(&[32]byte{5})
	if err != nil {
		t.Fatal(err)
	}
	r := registry.New(env.Pool("nms_executor"), k, filepath.Join(t.TempDir(), "state"))
	if err := r.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	return env, r
}

func verify(t *testing.T, r *registry.Registry, anchor state.AuditHead) audit.Result {
	t.Helper()
	var res audit.Result
	base, _, err := r.AuditBounds()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Read(context.Background(), time.Minute, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		res, err = audit.Verify(ctx, tx, base, anchor)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return res
}

func ev(action string, uid *int64) audit.Event {
	return audit.Event{Action: action, Result: audit.OK, UserID: uid, IP: "::ffff:192.0.2.7", UA: "ua", Object: "obj",
		Details: map[string]any{"k": "v"}}
}

/*
Rows appended alone and inside a registry change chain on each other; the
head moves in exec.audit_head and in the state file's anchor; Verify finds
the chain intact and containing every older anchor (a prefix).
*/
func TestAppendAndVerify(t *testing.T) {
	_, r := setup(t)
	ctx := context.Background()
	_, empty, _ := r.AuditBounds()
	if res := verify(t, r, empty); res.Break != nil || res.Count != 0 {
		t.Fatalf("empty chain: %+v", res)
	}
	uid := int64(3)
	if err := r.Append(ctx, audit.Append(ev("a.one", nil), ev("a.two", &uid))); err != nil {
		t.Fatal(err)
	}
	_, mid, _ := r.AuditBounds()
	if err := r.Write(ctx, func(_ context.Context, _ *registry.Snapshot, tx *registry.Tx) error {
		tx.Audit(audit.Append(ev("a.three", nil)))
		return tx.Put("write_grant", map[string]any{"user_id": 1, "kind": "unmask", "write_group": nil, "username_snapshot": "u"})
	}); err != nil {
		t.Fatal(err)
	}
	_, last, _ := r.AuditBounds()
	if mid.LastID == 0 || last.LastID <= mid.LastID {
		t.Fatalf("anchors %d %d", mid.LastID, last.LastID)
	}
	for _, a := range []state.AuditHead{empty, mid, last} {
		if res := verify(t, r, a); res.Break != nil || res.Count != 3 || res.LastID != last.LastID {
			t.Fatalf("anchor %d: %+v", a.LastID, res)
		}
	}
	/* A refused change appends nothing. */
	if err := r.Write(ctx, func(_ context.Context, _ *registry.Snapshot, tx *registry.Tx) error {
		tx.Audit(audit.Append(ev("a.four", nil)))
		return tx.Put("write_grant", map[string]any{"user_id": 1})
	}); err == nil {
		t.Fatal("bad change accepted")
	}
	if res := verify(t, r, last); res.Count != 3 {
		t.Fatalf("refused change left rows: %+v", res)
	}
	if err := r.Append(ctx, audit.Append(audit.Event{Action: "Bad Action", Result: audit.OK})); err == nil {
		t.Fatal("bad action accepted")
	}
}

/* Each kind of tampering with the rows is a break, at the right row, also with a matching exec.audit_head. */
func TestVerifyFindsBreaks(t *testing.T) {
	for name, c := range map[string]struct {
		sql    string
		reason string
	}{
		"payload rewritten":  {`UPDATE exec.audit_event SET payload = convert_to(replace(convert_from(payload, 'UTF8'), 'a.two', 'a.tw0'), 'UTF8') WHERE action = 'a.two'`, audit.ReasonHashMismatch},
		"indexed column":     {`UPDATE exec.audit_event SET action = 'a.other' WHERE action = 'a.two'`, audit.ReasonIndexedMismatch},
		"indexed ip":         {`UPDATE exec.audit_event SET ip = '192.0.2.8' WHERE action = 'a.two'`, audit.ReasonIndexedMismatch},
		"middle row deleted": {`DELETE FROM exec.audit_event WHERE action = 'a.two'`, audit.ReasonPrevMismatch},
		"tail truncated, head rewound": {`DELETE FROM exec.audit_event WHERE action = 'a.three';
			UPDATE exec.audit_head SET (last_id, hash) = (SELECT id, hash FROM exec.audit_event WHERE action = 'a.two')`, audit.ReasonAnchorMissing},
		"head moved": {`UPDATE exec.audit_head SET last_id = last_id - 1`, audit.ReasonHeadMismatch},
	} {
		t.Run(name, func(t *testing.T) {
			env, r := setup(t)
			for _, a := range []string{"a.one", "a.two", "a.three"} {
				if err := r.Append(context.Background(), audit.Append(ev(a, nil))); err != nil {
					t.Fatal(err)
				}
			}
			_, anchor, _ := r.AuditBounds()
			attacktest.Tamper(t, env, `ALTER TABLE exec.audit_event DISABLE TRIGGER audit_event_append_only; `+c.sql+
				`; ALTER TABLE exec.audit_event ENABLE TRIGGER audit_event_append_only`)
			if res := verify(t, r, anchor); res.Break == nil || res.Break.Reason != c.reason {
				t.Fatalf("result %+v, want %s", res, c.reason)
			}
		})
	}
}

/* Review M3: a trigger that rewrites the row being appended is caught by reading the row back: tampering, nothing anchored. */
func TestAppendReadsTheRowBack(t *testing.T) {
	env, r := setup(t)
	attacktest.Tamper(t, env, `CREATE SCHEMA IF NOT EXISTS attack;
		CREATE OR REPLACE FUNCTION attack.rewrite() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN NEW.payload := convert_to(replace(convert_from(NEW.payload, 'UTF8'), 'a.one', 'a.0ne'), 'UTF8'); RETURN NEW; END $$;
		CREATE TRIGGER rewrite BEFORE INSERT ON exec.audit_event FOR EACH ROW EXECUTE FUNCTION attack.rewrite()`)
	t.Cleanup(func() { attacktest.Tamper(t, env, `DROP TRIGGER rewrite ON exec.audit_event`) })
	_, before, _ := r.AuditBounds()
	if err := r.Append(context.Background(), audit.Append(ev("a.one", nil))); !errors.Is(err, registry.ErrTampered) {
		t.Fatalf("append: %v", err)
	}
	if _, after, _ := r.AuditBounds(); after.LastID != before.LastID {
		t.Fatal("rewritten row anchored")
	}
}
