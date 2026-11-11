package changeset_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/approval"
	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/changeset"
	"github.com/beekamai/network-scheme/cmd/executor/internal/confirm"
	"github.com/beekamai/network-scheme/cmd/executor/internal/session"
)

/* challenge is u's confirm(H) challenge of approving changeset id (/x/confirm/issue: Describe, then Issue). */
func (f *fx) challenge(t *testing.T, cs *confirm.Store, u who, id string) (confirm.Challenge, error) {
	t.Helper()
	need, d, err := f.m.Describe(context.Background(), authz.Decision{UserID: u.id, Username: u.name}, json.RawMessage(`{"changeset_id":"`+id+`"}`))
	if err != nil {
		return confirm.Challenge{}, err
	}
	ch, err := cs.Issue(u.id, need, d)
	if err != nil {
		t.Fatal(err)
	}
	return ch, nil
}

/* approve confirms ch as u with a fresh change TOTP code (as the approve route does) and runs it with the typed count. */
func (f *fx) approve(t *testing.T, cs *confirm.Store, u who, ch confirm.Challenge, id string, count int) (any, error) {
	t.Helper()
	c, by, err := cs.Confirm(context.Background(), ch.ID, ch.H[:], f.req(t, u))
	if err != nil {
		return nil, err
	}
	return f.m.RunApprove(context.Background(), c, by, []string{id, strconv.Itoa(count)})
}

/* ready is a changeset of u over devs that passed its dry-run. */
func (f *fx) ready(t *testing.T, u who, devs ...*dev) (tok, id string) {
	t.Helper()
	tok = f.open(t, u)
	s := f.save(t, tok, "", 0, f.lines("approve me", devs...))
	if d := f.dryRun(t, tok, s.ID, 1); !d.DryRun.Result.OK {
		t.Fatalf("dry-run failed: %+v", d.DryRun.Result)
	}
	return tok, s.ID
}

func (f *fx) runs() []changeset.Started {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]changeset.Started{}, f.started...)
}

func (f *fx) status(t *testing.T, tok, id string) string {
	t.Helper()
	res, err := f.op(t, tok, "get", map[string]any{"changeset_id": id})
	if err != nil {
		t.Fatal(err)
	}
	return res.(changeset.Detail).Status
}

/*
K6 and the plain approval: the description is D3's; a typed device count
off by one refuses and spends the challenge; the right count starts the run
with the dry-run's plan, recorded and audited.
*/
func TestApproveDeviceCountAndStart(t *testing.T) {
	f := newFx(t, "mes6", "mes10")
	alice := f.user(t, "core")
	tok, id := f.ready(t, alice, f.devs...)
	cs := confirm.New(f.az, f.now)
	ch, err := f.challenge(t, cs, alice, id)
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{}
	for _, fl := range ch.Description.Fields {
		keys = append(keys, fl.Key)
	}
	if strings.Join(keys, ",") != "author,batch_size,canary,changeset,groups,kind,plan_sha256,revision,settle_s,title" {
		t.Fatalf("description keys %v", keys)
	}
	for _, n := range []int{1, 3} {
		ch, _ := f.challenge(t, cs, alice, id)
		if _, err := f.approve(t, cs, alice, ch, id, n); code(err) != "device_count" {
			t.Fatalf("count %d: %v", n, err)
		}
		if _, err := f.approve(t, cs, alice, ch, id, 2); !errors.Is(err, authz.ErrDenied) {
			t.Fatalf("the challenge of a wrong count was not spent: %v", err)
		}
	}
	if len(f.runs()) != 0 || f.audits(t, changeset.ApproveAction, "denied") != 2 {
		t.Fatalf("runs %d, denied rows %d", len(f.runs()), f.audits(t, changeset.ApproveAction, "denied"))
	}
	ch, _ = f.challenge(t, cs, alice, id) /* the first one expired meanwhile (2 minutes; every code moves the clock 30 s) */
	res, err := f.approve(t, cs, alice, ch, id, 2)
	if err != nil {
		t.Fatal(err)
	}
	runs := f.runs()
	if res.(changeset.Approved).Status != "running" || len(runs) != 1 || runs[0].Second != 0 || len(runs[0].Plan) != 2 ||
		runs[0].Plan[0].ID != f.devs[0].id || len(runs[0].Plan[0].Pre) != 64 || runs[0].H != ch.H {
		t.Fatalf("started %+v / %+v", res, runs)
	}
	if st := f.status(t, tok, id); st != changeset.StatusRunning {
		t.Fatalf("status %s", st)
	}
	if n := f.audits(t, "confirm."+changeset.ApproveAction, "ok"); n != 3 { /* the two with a wrong count passed authz too */
		t.Errorf("%d audit rows of the confirmations", n)
	}
	/* a running changeset is not approved again */
	if _, err := f.challenge(t, cs, alice, id); code(err) != changeset.CodeState {
		t.Fatalf("approve a running one: %v", err)
	}
}

/*
K4 primitives: after the challenge was issued, a new revision, a changed
registry row or a dry_run event changed under the executor's MAC each stop
the approval; nothing starts.
*/
func TestApproveRefusesWhatChangedAfterTheChallenge(t *testing.T) {
	for name, change := range map[string]func(t *testing.T, f *fx, tok, id string){
		"new revision": func(t *testing.T, f *fx, tok, id string) {
			f.save(t, tok, id, 1, f.lines("approve me, changed", f.devs[0]))
		},
		"registry address": func(t *testing.T, f *fx, _, _ string) {
			row := f.devs[0].row
			row["address"] = netip.MustParseAddr("192.0.2.99")
			f.put(t, "write_device", row)
		},
		"registry group": func(t *testing.T, f *fx, _, _ string) {
			row := f.devs[0].row
			row["write_group"] = "core2"
			f.put(t, "write_device", row)
		},
		"dry_run event": func(t *testing.T, f *fx, _, _ string) {
			attacktest.Tamper(t, f.env, `ALTER TABLE exec.changeset_event DISABLE TRIGGER changeset_event_append_only`)
			attacktest.Tamper(t, f.env, `UPDATE exec.changeset_event SET payload = jsonb_set(payload, '{plan_sha256}', '"00"')`)
			attacktest.Tamper(t, f.env, `ALTER TABLE exec.changeset_event ENABLE TRIGGER changeset_event_append_only`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFx(t, "mes6")
			alice := f.user(t, "core", "core2")
			tok, id := f.ready(t, alice, f.devs[0])
			cs := confirm.New(f.az, f.now)
			ch, err := f.challenge(t, cs, alice, id)
			if err != nil {
				t.Fatal(err)
			}
			change(t, f, tok, id)
			if _, err := f.approve(t, cs, alice, ch, id, 1); err == nil {
				t.Fatal("approved")
			}
			if len(f.runs()) != 0 {
				t.Fatal("a run started")
			}
		})
	}
}

/*
K5: in a two-person group the author's confirmation only records the
author's approval; the author confirming again is same_person; a user
without the grant on a group gets no description; another user with the
grant starts the run.
*/
func TestTwoPersonAuthorCannotApprove(t *testing.T) {
	f := newFx(t, "mes6")
	f.policy(t, "two_person_groups: [core]\n")
	alice, bob, eve := f.user(t, "core"), f.user(t, "core"), f.user(t, "edge")
	tok, id := f.ready(t, alice, f.devs[0])
	cs := confirm.New(f.az, f.now)
	ch, _ := f.challenge(t, cs, alice, id)
	res, err := f.approve(t, cs, alice, ch, id, 1)
	if err != nil || res.(changeset.Approved).Status != "awaiting_second_person" || len(f.runs()) != 0 {
		t.Fatalf("author: %+v %v", res, err)
	}
	if st := f.status(t, tok, id); st != changeset.StatusApproved {
		t.Fatalf("status %s", st)
	}
	ch, _ = f.challenge(t, cs, alice, id)
	if _, err := f.approve(t, cs, alice, ch, id, 1); !errors.Is(err, approval.ErrSamePerson) {
		t.Fatalf("author twice: %v", err)
	}
	if _, err := f.challenge(t, cs, eve, id); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("a user without the group's grant describes: %v", err)
	}
	bch, err := f.challenge(t, cs, bob, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.approve(t, cs, bob, bch, id, 1); err != nil {
		t.Fatalf("bob: %v", err)
	}
	runs := f.runs()
	if len(runs) != 1 || runs[0].Second != bob.id || runs[0].Author != alice.id {
		t.Fatalf("runs %+v", runs)
	}
	if f.audits(t, changeset.ApproveAction, "ok") != 2 || f.audits(t, changeset.ApproveAction, "denied") != 1 {
		t.Errorf("audit rows: ok %d, denied %d", f.audits(t, changeset.ApproveAction, "ok"), f.audits(t, changeset.ApproveAction, "denied"))
	}
}

/*
The author's approval does not outlive second_person_minutes, a restart of
the executor (memory only) or a new plan: a second person then finds no
approval, or confirms another H (h_mismatch); nothing starts.
*/
func TestSecondPersonNeedsALiveApprovalOfTheSameH(t *testing.T) {
	f := newFx(t, "mes6")
	f.policy(t, "two_person_groups: [core]\nsecond_person_minutes: 5\n")
	alice, bob := f.user(t, "core"), f.user(t, "core")
	cs := confirm.New(f.az, f.now)
	authorApproves := func(id string) {
		ch, _ := f.challenge(t, cs, alice, id)
		if res, err := f.approve(t, cs, alice, ch, id, 1); err != nil || res.(changeset.Approved).Status != "awaiting_second_person" {
			t.Fatalf("author: %+v %v", res, err)
		}
	}
	bobApproves := func(id string) error {
		ch, err := f.challenge(t, cs, bob, id)
		if err != nil {
			return err
		}
		_, err = f.approve(t, cs, bob, ch, id, 1)
		return err
	}
	/* expired */
	_, id := f.ready(t, alice, f.devs[0])
	authorApproves(id)
	f.offset.Add(int64(6 * time.Minute))
	if err := bobApproves(id); code(err) != "author_approval_required" {
		t.Fatalf("after expiry: %v", err)
	}
	/* a new plan: the device changed, a new dry-run passed, bob confirms its H; the author approved the old one */
	tok, id := f.ready(t, alice, f.devs[0])
	authorApproves(id)
	c := f.devs[0].d.Dial("admin")
	for _, l := range []string{"configure", "hostname changed-meanwhile", "end"} {
		c.Do(l)
	}
	f.dryRun(t, tok, id, 1)
	if err := bobApproves(id); !errors.Is(err, approval.ErrH) {
		t.Fatalf("another H: %v", err)
	}
	/* a restart forgets every approval */
	_, id = f.ready(t, alice, f.devs[0])
	authorApproves(id)
	cfg := f.cfg
	cfg.Approvals = approval.New(f.now)
	f.m = changeset.New(cfg)
	if err := bobApproves(id); code(err) != "author_approval_required" {
		t.Fatalf("after a restart: %v", err)
	}
	if len(f.runs()) != 0 {
		t.Fatal("a run started")
	}
}

/* Outside every window: deny refuses (with the warning alert), second_person needs the second person. */
func TestApproveOutsideWindow(t *testing.T) {
	f := newFx(t, "mes6")
	alice := f.user(t, "core")
	_, id := f.ready(t, alice, f.devs[0])
	h := (f.now().UTC().Hour() + 12) % 24
	window := "windows: [{days: [mon, tue, wed, thu, fri, sat, sun], start: \"" + twoDigits(h) + ":00\", end: \"" + twoDigits(h) + ":30\"}]\n"
	f.policy(t, window)
	cs := confirm.New(f.az, f.now)
	ch, _ := f.challenge(t, cs, alice, id)
	if _, err := f.approve(t, cs, alice, ch, id, 1); code(err) != "outside_window" {
		t.Fatalf("deny: %v", err)
	}
	if f.count(t, `SELECT count(*) FROM execpub.alert WHERE kind = $1`, session.KindOutsideWindow) != 1 {
		t.Fatal("no outside-window alert")
	}
	f.policy(t, window+"outside_window: second_person\n")
	ch, _ = f.challenge(t, cs, alice, id)
	if res, err := f.approve(t, cs, alice, ch, id, 1); err != nil || res.(changeset.Approved).Status != "awaiting_second_person" {
		t.Fatalf("second_person: %+v %v", res, err)
	}
	if len(f.runs()) != 0 {
		t.Fatal("a run started")
	}
}

func twoDigits(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}
