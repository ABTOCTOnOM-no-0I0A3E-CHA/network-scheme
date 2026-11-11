package session_test

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/approval"
	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/confirm"
	"github.com/beekamai/network-scheme/cmd/executor/internal/session"
)

/* withApprovals rebuilds the manager with an approval store (main shares one with the changesets). */
func (f *fx) withApprovals() {
	f.cfg.Approvals = approval.New(f.now)
	f.m = session.New(f.cfg)
}

/* secondApproves is u's session.approve of request id: Describe, Issue, Confirm with a new code, Run (as /x/confirm does). */
func (f *fx) secondApproves(t *testing.T, u who, id string) error {
	t.Helper()
	cs := confirm.New(f.az, f.now)
	need, d, err := f.m.DescribeApprove(ctx(t), authz.Decision{UserID: u.id, Username: u.name}, json.RawMessage(`{"request_id":"`+id+`"}`))
	if err != nil {
		return err
	}
	ch, err := cs.Issue(u.id, need, d)
	if err != nil {
		t.Fatal(err)
	}
	c, by, err := cs.Confirm(ctx(t), ch.ID, ch.H[:], f.req(t, u))
	if err != nil {
		return err
	}
	_, err = f.m.RunApprove(ctx(t), c, by)
	return err
}

func (f *fx) request(t *testing.T, u who, ids ...int64) session.Requested {
	t.Helper()
	r, err := f.m.Request(ctx(t), f.req(t, u), ids)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return r
}

/*
D5: a session in a two-person group opens only with a second person's
approval: requested by the author, approved by another user (not the
author) with write on the group through confirm(H), then spent once by the
author for the same devices.
*/
func TestTwoPersonSessionNeedsApproval(t *testing.T) {
	f := newFx(t)
	f.withApprovals()
	alice, bob := f.user(t, "core"), f.user(t, "core")
	f.policy(t, "two_person_groups: [core]\n")
	ids := []int64{f.id}
	f.refused(t, "no approval", alice, ids, session.ErrTwoPerson)
	r := f.request(t, alice, f.id)
	if len(r.ID) < 20 || !hasField(r.Fields, "reason", "two_person") || !hasField(r.Fields, "author", "") {
		t.Fatalf("request %+v", r)
	}
	if err := f.secondApproves(t, alice, r.ID); !errors.Is(err, approval.ErrSamePerson) {
		t.Fatalf("approved by the author: %v", err)
	}
	if _, err := f.m.OpenApproved(ctx(t), f.req(t, alice), ids, r.ID); !errors.Is(err, approval.ErrSecondPerson) {
		t.Fatalf("not approved yet: %v", err)
	}
	/* that spent it: a request is used once, whatever the outcome */
	r = f.request(t, alice, f.id)
	if err := f.secondApproves(t, bob, r.ID); err != nil {
		t.Fatalf("bob approves: %v", err)
	}
	second := f.panelDevice(t, "10.251.0.7")
	row2 := maps.Clone(f.row)
	row2["device_id"], row2["address"] = second, netip.MustParseAddr("192.0.2.11")
	f.put(t, "write_device", row2)
	if _, err := f.m.OpenApproved(ctx(t), f.req(t, alice), []int64{f.id, second}, r.ID); !errors.Is(err, approval.ErrMismatch) {
		t.Fatalf("other devices: %v", err)
	}
	if _, err := f.m.OpenApproved(ctx(t), f.req(t, alice), ids, r.ID); !errors.Is(err, approval.ErrExpired) {
		t.Fatalf("the approval used twice: %v", err)
	}
	r = f.request(t, alice, f.id)
	if err := f.secondApproves(t, bob, r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.OpenApproved(ctx(t), f.req(t, bob), ids, r.ID); !errors.Is(err, approval.ErrMismatch) {
		t.Fatalf("someone else's approval: %v", err)
	}
	r = f.request(t, alice, f.id)
	if err := f.secondApproves(t, bob, r.ID); err != nil {
		t.Fatal(err)
	}
	o, err := f.m.OpenApproved(ctx(t), f.req(t, alice), ids, r.ID)
	if err != nil {
		t.Fatalf("approved open: %v", err)
	}
	if n := f.count(t, `SELECT count(*) FROM exec.session_event WHERE session_id = $1 AND kind = 'approved' AND (payload->>'by')::bigint = $2`,
		o.ID, bob.id); n != 1 {
		t.Fatalf("approved events %d", n)
	}
	if err := f.m.Close(context.Background(), o.ID, o.Token); err != nil {
		t.Fatal(err)
	}
	for _, a := range [][2]string{{"session.request", "ok"}, {"session.approve", "ok"}, {"confirm.session.approve", "ok"}, {"session.approve", "denied"}} {
		if f.count(t, `SELECT count(*) FROM exec.audit_event WHERE action = $1 AND result = $2`, a[0], a[1]) == 0 {
			t.Errorf("no audit row %s %s", a[0], a[1])
		}
	}
	if f.count(t, `SELECT count(*) FROM exec.audit_event WHERE action = 'session.open' AND result = 'denied' AND convert_from(payload, 'UTF8')::jsonb #>> '{details,class}' = 'approval_mismatch'`) == 0 {
		t.Error("no denied open with approval_mismatch")
	}
	/* an approval of a restarted executor is gone */
	r = f.request(t, alice, f.id)
	if err := f.secondApproves(t, bob, r.ID); err != nil {
		t.Fatal(err)
	}
	f.withApprovals()
	if _, err := f.m.OpenApproved(ctx(t), f.req(t, alice), ids, r.ID); !errors.Is(err, approval.ErrExpired) {
		t.Fatalf("after a restart: %v", err)
	}
	/* a session that needs no second person takes no request */
	f.policy(t, "")
	if _, err := f.m.Request(ctx(t), f.req(t, alice), ids); !errors.Is(err, session.ErrNotNeeded) {
		t.Fatalf("not needed: %v", err)
	}
}

/* outside_window: second_person opens a session outside the windows only with a second person's approval. */
func TestOutsideWindowNeedsSecondPerson(t *testing.T) {
	f := newFx(t)
	f.withApprovals()
	alice, bob := f.user(t, "core"), f.user(t, "core")
	day := strings.ToLower(f.now().UTC().Add(48 * time.Hour).Weekday().String()[:3])
	f.policy(t, "windows:\n  - days: ["+day+"]\n    start: \"00:00\"\n    end: \"24:00\"\noutside_window: second_person\n")
	ids := []int64{f.id}
	f.refused(t, "outside the window, no approval", alice, ids, session.ErrTwoPerson)
	r := f.request(t, alice, f.id)
	if !hasField(r.Fields, "reason", "outside_window") {
		t.Fatalf("request %+v", r)
	}
	if err := f.secondApproves(t, bob, r.ID); err != nil {
		t.Fatal(err)
	}
	o, err := f.m.OpenApproved(ctx(t), f.req(t, alice), ids, r.ID)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := f.m.Close(context.Background(), o.ID, o.Token); err != nil {
		t.Fatal(err)
	}
}

/* hasField reports whether fields hold key (with value, unless value is empty). */
func hasField(fields []confirm.Field, key, value string) bool {
	for _, f := range fields {
		if f.Key == key && (value == "" || f.Value == value) {
			return true
		}
	}
	return false
}
