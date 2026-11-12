package changeset_test

import (
	"context"
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/changeset"
	"github.com/beekamai/network-scheme/cmd/executor/internal/confirm"
)

/*
C2k (K4, security.md 5.4): the content an approval executes is the one its
H covers, whoever holds the api.

  - the api (nms_api and the ticket key) has no right on any changeset row,
    nor on the panel's summary but SELECT;
  - a database superuser who swaps the approved revision's content (and its
    hash) or rewrites the dry-run's plan cannot recompute the row MACs: the
    approval and the run refuse, with executor_changeset_tamper, and
    nothing starts;
  - a summary rewritten in execpub decides nothing: the state is the
    verified events'.
*/
func TestC2kChangesetContent(t *testing.T) {
	f := newFx(t, "mes6")
	ctx := context.Background()
	api := attacktest.NewAttacker(f.env, ticketKey)
	alice := f.user(t, "core")
	tok, id := f.ready(t, alice, f.devs[0])
	for _, sql := range []string{
		`SELECT content FROM exec.changeset_revision`,
		`INSERT INTO exec.changeset_event (changeset_id, rev, at, kind, payload, mac) SELECT changeset_id, 1, now(), 'run_started', '{}', mac FROM exec.changeset_event`,
		`UPDATE execpub.changeset_summary SET status = 'dry_run_ok'`,
		`INSERT INTO execpub.changeset_summary (changeset_id, author_id, kind, title, status, device_count, device_ids, created_at, updated_at)
			VALUES (gen_random_uuid(), 1, 'lines', 't', 'approved', 1, '{1}', now(), now())`,
	} {
		if err := api.Exec(ctx, sql); err == nil {
			t.Errorf("the api ran %q", sql)
		}
	}
	tampers := func() int {
		return f.count(t, `SELECT count(*) FROM execpub.alert WHERE kind = $1`, changeset.KindTamper)
	}

	/* the content swapped after the challenge: H's revision now holds other lines */
	cs := confirm.New(f.az, f.now)
	ch, err := f.challenge(t, cs, alice, id)
	if err != nil {
		t.Fatal(err)
	}
	evil := f.lines("approve me", f.devs[0])
	evil.Steps[2].Line = "description owned"
	attacktest.Tamper(t, f.env, `ALTER TABLE exec.changeset_revision DISABLE TRIGGER changeset_revision_append_only`)
	attacktest.Tamper(t, f.env, `UPDATE exec.changeset_revision SET content = $1, content_sha256 = sha256($1)`, evil.Canonical())
	attacktest.Tamper(t, f.env, `ALTER TABLE exec.changeset_revision ENABLE TRIGGER changeset_revision_append_only`)
	if _, err := f.approve(t, cs, alice, ch, id, 1); code(err) != changeset.CodeTampered || tampers() == 0 {
		t.Fatalf("swapped content: %v, %d alerts", err, tampers())
	}
	if len(f.runs()) != 0 {
		t.Fatal("a run started")
	}

	/* a second changeset: its dry-run's plan rewritten (another plan_sha256, the H the attacker would like) */
	_, id2 := f.ready(t, alice, f.devs[0])
	n := tampers()
	attacktest.Tamper(t, f.env, `ALTER TABLE exec.changeset_event DISABLE TRIGGER changeset_event_append_only`)
	attacktest.Tamper(t, f.env, `UPDATE exec.changeset_event SET payload = jsonb_set(payload, '{plan_sha256}', '"0000"') WHERE changeset_id = $1`, id2)
	attacktest.Tamper(t, f.env, `ALTER TABLE exec.changeset_event ENABLE TRIGGER changeset_event_append_only`)
	if _, err := f.challenge(t, cs, alice, id2); code(err) != changeset.CodeTampered || tampers() == n {
		t.Fatalf("rewritten plan: %v", err)
	}

	/* a third: a draft whose panel summary claims dry_run_ok is still a draft to the executor */
	s := f.save(t, tok, "", 0, f.lines("draft", f.devs[0]))
	attacktest.Tamper(t, f.env, `UPDATE execpub.changeset_summary SET status = 'dry_run_ok' WHERE changeset_id = $1`, s.ID)
	if _, err := f.challenge(t, cs, alice, s.ID); code(err) != changeset.CodeState {
		t.Fatalf("summary says dry_run_ok: %v", err)
	}
	if len(f.runs()) != 0 {
		t.Fatal("a run started")
	}
}
