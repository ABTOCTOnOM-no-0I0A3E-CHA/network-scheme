package audit_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
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
	c, err := r.AuditChain()
	if err != nil {
		t.Fatal(err)
	}
	c.Anchor = anchor
	return verifyChain(t, r, c)
}

func verifyChain(t *testing.T, r *registry.Registry, c state.Chain) audit.Result {
	t.Helper()
	var res audit.Result
	if err := r.Read(context.Background(), time.Minute, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		res, err = audit.Verify(ctx, tx, c)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return res
}

/* anchorOf is the anchor committed in the state file. */
func anchorOf(t *testing.T, r *registry.Registry) state.AuditHead {
	t.Helper()
	c, err := r.AuditChain()
	if err != nil {
		t.Fatal(err)
	}
	return c.Anchor
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
	empty := anchorOf(t, r)
	if res := verify(t, r, empty); res.Break != nil || res.Count != 0 {
		t.Fatalf("empty chain: %+v", res)
	}
	uid := int64(3)
	if err := r.Append(ctx, audit.Append(ev("a.one", nil), ev("a.two", &uid))); err != nil {
		t.Fatal(err)
	}
	mid := anchorOf(t, r)
	if err := r.Write(ctx, func(_ context.Context, _ *registry.Snapshot, tx *registry.Tx) error {
		tx.Audit(audit.Append(ev("a.three", nil)))
		return tx.Put("write_grant", map[string]any{"user_id": 1, "kind": "unmask", "write_group": nil, "username_snapshot": "u"})
	}); err != nil {
		t.Fatal(err)
	}
	last := anchorOf(t, r)
	if mid.LastID == 0 || last.LastID <= mid.LastID {
		t.Fatalf("anchors %d %d", mid.LastID, last.LastID)
	}
	for _, a := range []state.AuditHead{empty, mid, last} {
		if res := verify(t, r, a); res.Break != nil || res.Count+res.Unanchored != 3 || res.LastID != last.LastID {
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
			anchor := anchorOf(t, r)
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
	before := anchorOf(t, r)
	if err := r.Append(context.Background(), audit.Append(ev("a.one", nil))); !errors.Is(err, registry.ErrTampered) {
		t.Fatalf("append: %v", err)
	}
	if after := anchorOf(t, r); after.LastID != before.LastID {
		t.Fatal("rewritten row anchored")
	}
}

func sum(prev, payload []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write(payload)
	return h.Sum(nil)
}

/*
rewrite rewrites the payload of every row up to id upTo (0: all) as the
superuser can, recomputing prev_hash and hash (an unkeyed SHA-256 chain),
and points exec.audit_head at the new last row when the whole chain was
rewritten: a chain consistent in itself, only the anchor can tell.
*/
func rewrite(t *testing.T, env *testdb.Env, upTo int64, mutate func([]byte) []byte) {
	t.Helper()
	ctx := context.Background()
	db := env.Pool("postgres")
	attacktest.Tamper(t, env, `ALTER TABLE exec.audit_event DISABLE TRIGGER audit_event_append_only`)
	defer attacktest.Tamper(t, env, `ALTER TABLE exec.audit_event ENABLE TRIGGER audit_event_append_only`)
	rows, err := db.Query(ctx, `SELECT id, payload, prev_hash FROM exec.audit_event WHERE $1 = 0 OR id <= $1 ORDER BY id`, upTo)
	if err != nil {
		t.Fatal(err)
	}
	type rw struct {
		id      int64
		payload []byte
	}
	var all []rw
	var prev []byte
	for rows.Next() {
		var r rw
		var p []byte
		if err := rows.Scan(&r.id, &r.payload, &p); err != nil {
			t.Fatal(err)
		}
		if prev == nil {
			prev = p
		}
		all = append(all, r)
	}
	rows.Close()
	for _, r := range all {
		payload := mutate(r.payload)
		h := sum(prev, payload)
		if _, err := db.Exec(ctx, `UPDATE exec.audit_event SET payload = $2, prev_hash = $3, hash = $4 WHERE id = $1`, r.id, payload, prev, h); err != nil {
			t.Fatal(err)
		}
		prev = h
	}
	if upTo == 0 {
		attacktest.Tamper(t, env, `UPDATE exec.audit_head SET (last_id, hash) = (SELECT id, hash FROM exec.audit_event ORDER BY id DESC LIMIT 1)`)
	}
}

/* forge appends a row chained on the current last row, as the superuser can, and moves exec.audit_head to it. */
func forge(t *testing.T, env *testdb.Env, action string) int64 {
	t.Helper()
	ctx := context.Background()
	var prev []byte
	if err := env.Pool("postgres").QueryRow(ctx, `SELECT hash FROM exec.audit_event ORDER BY id DESC LIMIT 1`).Scan(&prev); err != nil {
		t.Fatal(err)
	}
	e := audit.Event{TS: time.Now().UTC().Truncate(time.Microsecond), Action: action, Result: audit.OK}
	payload, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := env.Pool("postgres").QueryRow(ctx, `INSERT INTO exec.audit_event (ts, action, result, payload, prev_hash, hash)
		VALUES ($1, $2, 'ok', $3, $4, $5) RETURNING id`, e.TS, action, payload, prev, sum(prev, payload)).Scan(&id); err != nil {
		t.Fatal(err)
	}
	attacktest.Tamper(t, env, `UPDATE exec.audit_head SET (last_id, hash) = (SELECT id, hash FROM exec.audit_event ORDER BY id DESC LIMIT 1)`)
	return id
}

func appendRows(t *testing.T, r *registry.Registry, actions ...string) []state.AuditHead {
	t.Helper()
	var heads []state.AuditHead
	for _, a := range actions {
		if err := r.Append(context.Background(), audit.Append(ev(a, nil))); err != nil {
			t.Fatal(err)
		}
		heads = append(heads, anchorOf(t, r))
	}
	return heads
}

func plan(t *testing.T, r *registry.Registry, c state.Chain, known bool) audit.Plan {
	t.Helper()
	var p audit.Plan
	if err := r.Read(context.Background(), time.Minute, func(ctx context.Context, tx pgx.Tx) error {
		var tail state.AuditHead
		if err := tx.QueryRow(ctx, `SELECT id, hash FROM exec.audit_event ORDER BY id DESC LIMIT 1`).Scan(&tail.LastID, &tail.Hash); err != nil {
			return err
		}
		var err error
		p, err = audit.PlanReset(ctx, tx, c, known, tail)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return p
}

/*
Review I1 PoC: the whole history rewritten with recomputed hashes and the
head moved to match is consistent in itself; Verify and PlanReset both see
that the row at the anchor id no longer has the anchored hash. With the
trusted end row wrong, nothing is vouched: no forged row is sealed.
*/
func TestRewrittenHistoryIsNotIntact(t *testing.T) {
	env, r := setup(t)
	heads := appendRows(t, r, "a.one", "a.two", "a.three")
	anchor := heads[2]
	rewrite(t, env, 0, func(p []byte) []byte { return bytes.ReplaceAll(p, []byte(`"v"`), []byte(`"w"`)) })
	if res := verify(t, r, anchor); res.Break == nil || res.Break.ID != anchor.LastID || res.Break.Reason != audit.ReasonAnchorMissing {
		t.Fatalf("verify: %+v", res)
	}
	c, _ := r.AuditChain()
	p := plan(t, r, c, true)
	if p.Intact || p.Break == nil || p.Break.ID != anchor.LastID || len(p.Vouched) != 0 ||
		len(p.Suspect) != 1 || p.Suspect[0] != (audit.Range{From: 0, To: anchor.LastID}) {
		t.Fatalf("plan %+v", p)
	}
	if p.Chain.Base.LastID != anchor.LastID || len(p.Chain.Sealed) != 0 {
		t.Fatalf("plan chain %+v", p.Chain)
	}
}

/* The anchor row removed and forged rows appended after its id: the first forged row is the break; nothing is vouched. */
func TestForgedRowsPastTheAnchor(t *testing.T) {
	env, r := setup(t)
	heads := appendRows(t, r, "a.one", "a.two", "a.three")
	anchor := heads[2]
	attacktest.Tamper(t, env, `ALTER TABLE exec.audit_event DISABLE TRIGGER audit_event_append_only;
		DELETE FROM exec.audit_event WHERE action = 'a.three';
		ALTER TABLE exec.audit_event ENABLE TRIGGER audit_event_append_only`)
	first := forge(t, env, "a.forged")
	forge(t, env, "a.forged")
	if first <= anchor.LastID {
		t.Fatalf("forged id %d not after the anchor %d", first, anchor.LastID)
	}
	if res := verify(t, r, anchor); res.Break == nil || res.Break.ID != first || res.Break.Reason != audit.ReasonAnchorMissing {
		t.Fatalf("verify: %+v", res)
	}
	c, _ := r.AuditChain()
	if p := plan(t, r, c, true); p.Intact || len(p.Vouched) != 0 || len(p.Chain.Sealed) != 0 || p.Unanchored != 2 {
		t.Fatalf("plan %+v", p)
	}
}

/* Rows after the anchor (a change in flight, or forged) are reported as unanchored, not as verified; a reset plan does not call that intact. */
func TestUnanchoredRowsAreReported(t *testing.T) {
	env, r := setup(t)
	heads := appendRows(t, r, "a.one", "a.two")
	forge(t, env, "a.after")
	res := verify(t, r, heads[1])
	if res.Break != nil || res.Count != 2 || res.Unanchored != 1 {
		t.Fatalf("verify: %+v", res)
	}
	c, _ := r.AuditChain()
	if p := plan(t, r, c, true); p.Intact || p.Unanchored != 1 || len(p.Chain.Sealed) != 1 || !sameHead(p.Chain.Sealed[0].To, heads[1]) {
		t.Fatalf("plan %+v", p)
	}
}

func sameHead(a, b state.AuditHead) bool { return a.LastID == b.LastID && bytes.Equal(a.Hash, b.Hash) }

/* A sealed segment is checked on every verification: rewriting it, even consistently, is a break. */
func TestSealedSegmentsStayChecked(t *testing.T) {
	env, r := setup(t)
	heads := appendRows(t, r, "a.one", "a.two", "a.three")
	genesis := state.AuditHead{Hash: make([]byte, sha256.Size)}
	c := state.Chain{Sealed: []state.Segment{{From: genesis, To: heads[1]}}, Base: heads[1], Anchor: heads[2]}
	if res := verifyChain(t, r, c); res.Break != nil || res.Count != 3 {
		t.Fatalf("intact: %+v", res)
	}
	rewrite(t, env, heads[1].LastID, func(p []byte) []byte { return bytes.ReplaceAll(p, []byte(`"v"`), []byte(`"x"`)) })
	if res := verifyChain(t, r, c); res.Break == nil || res.Break.Reason != audit.ReasonSealedMismatch {
		t.Fatalf("rewritten sealed segment: %+v", res)
	}
	/* Unreadable state file: nothing is anchored, the plan vouches for nothing. */
	if p := plan(t, r, c, false); p.Intact || p.Unanchored != 3 || len(p.Chain.Sealed) != 0 || p.Chain.Base.LastID != heads[2].LastID {
		t.Fatalf("unknown plan %+v", p)
	}
}

/*
Re-review PoC B: rows 1-3 rewritten with recomputed hashes, row 4's
prev_hash left as it was, so the chain breaks at #4. Only the anchor
vouches, backward: rows 4-6 are proven and sealed, rows 1-3 (the forged
ones, consistent among themselves from the start hash) may be forged and
are never sealed; verification then counts only rows 4-6.
*/
func TestOnlyTheAnchorVouchesBackward(t *testing.T) {
	env, r := setup(t)
	heads := appendRows(t, r, "a.1", "a.2", "a.3", "a.4", "a.5", "a.6")
	rewrite(t, env, heads[2].LastID, func(p []byte) []byte { return bytes.ReplaceAll(p, []byte(`"v"`), []byte(`"forged"`)) })
	c, _ := r.AuditChain()
	p := plan(t, r, c, true)
	if p.Intact || len(p.Vouched) != 1 || p.Vouched[0].From.LastID != heads[2].LastID || !sameHead(p.Vouched[0].To, heads[5]) {
		t.Fatalf("vouched %+v", p.Vouched)
	}
	if len(p.Suspect) != 1 || p.Suspect[0] != (audit.Range{From: 0, To: heads[2].LastID}) {
		t.Fatalf("suspect %+v", p.Suspect)
	}
	if len(p.Chain.Sealed) != 1 || p.Chain.Sealed[0].From.LastID != heads[2].LastID {
		t.Fatalf("sealed %+v", p.Chain.Sealed)
	}
	p.Chain.Anchor = p.Chain.Base
	if res := verifyChain(t, r, p.Chain); res.Break != nil || res.Count != 3 || res.Unverified != 3 {
		t.Fatalf("verify after the plan: %+v", res)
	}
}

/*
Re-review PoC C: a sealed segment rewritten including its end row. Its
trusted end hash no longer matches, so nothing in its range is vouched any
more: a second reset never seals the forged segment again.
*/
func TestRewrittenSealedEndVouchesNothing(t *testing.T) {
	env, r := setup(t)
	heads := appendRows(t, r, "a.1", "a.2", "a.3", "a.4", "a.5", "a.6")
	genesis := state.AuditHead{Hash: make([]byte, sha256.Size)}
	c := state.Chain{Sealed: []state.Segment{{From: genesis, To: heads[2]}}, Base: heads[2], Anchor: heads[5]}
	rewrite(t, env, heads[2].LastID, func(p []byte) []byte { return bytes.ReplaceAll(p, []byte(`"v"`), []byte(`"eve"`)) })
	p := plan(t, r, c, true)
	for _, g := range p.Chain.Sealed {
		if g.To.LastID <= heads[2].LastID {
			t.Fatalf("forged segment sealed again: %+v", p.Chain.Sealed)
		}
	}
	if p.Intact || p.Break == nil || p.Break.Reason != audit.ReasonSealedMismatch || len(p.Suspect) != 1 ||
		p.Suspect[0] != (audit.Range{From: 0, To: heads[2].LastID}) || len(p.Vouched) != 1 || !sameHead(p.Vouched[0].To, heads[5]) {
		t.Fatalf("plan %+v", p)
	}
}
