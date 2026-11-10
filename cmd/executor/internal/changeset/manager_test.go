package changeset_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/changeset"
	"github.com/beekamai/network-scheme/internal/execadmin"
)

/*
The workspace: only ticket + change TOTP of a user with a write grant opens
one; every route needs its token, which ends idle or expired; a token
grants nothing by itself (a changeset of a group the user has no grant on
is denied, and a revoked grant counts at once, for the author too).
*/
func TestWorkspaceTokenAndGrants(t *testing.T) {
	f := newFx(t, "mes6")
	ctx := context.Background()
	if _, err := f.m.Open(ctx, f.req(t, f.user(t))); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("no write grant: %v", err)
	}
	bad := f.req(t, f.user(t, "core"))
	bad.Code = "000000"
	if _, err := f.m.Open(ctx, bad); err == nil {
		t.Fatal("wrong TOTP opened a workspace")
	}
	alice := f.user(t, "core")
	tok := f.open(t, alice)
	if _, err := f.op(t, "", "list", nil); code(err) != changeset.CodeNoWorkspace {
		t.Fatalf("no token: %v", err)
	}
	if _, err := f.op(t, tok+"x", "list", nil); code(err) != changeset.CodeNoWorkspace {
		t.Fatalf("wrong token: %v", err)
	}
	s := f.save(t, tok, "", 0, f.lines("first", f.devs[0]))

	/* another user with write on another group only: denied, the changeset stays unknown to them */
	bob := f.user(t, "edge")
	btok := f.open(t, bob)
	if _, err := f.op(t, btok, "get", map[string]any{"changeset_id": s.ID}); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("other group: %v", err)
	}
	if res, err := f.op(t, btok, "list", nil); err != nil || len(res.([]changeset.Item)) != 0 {
		t.Fatalf("other group lists: %v %v", res, err)
	}

	/* revoking the author's grant counts at once */
	f.adminDo(t, execadmin.Request{Cmd: execadmin.CmdRevoke, User: alice.name, Kind: execadmin.KindWrite, Group: "core"}, nil)
	if _, err := f.op(t, tok, "get", map[string]any{"changeset_id": s.ID}); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("after revoke: %v", err)
	}
	if _, err := f.op(t, tok, "save", map[string]any{"content": f.lines("again", f.devs[0])}); code(err) != "no_grant" {
		t.Fatalf("save after revoke: %v", err)
	}

	/* idle and lifetime end the token */
	carol := f.user(t, "core")
	ctok := f.open(t, carol)
	f.offset.Add(int64(11 * time.Minute))
	if _, err := f.op(t, ctok, "list", nil); code(err) != changeset.CodeNoWorkspace {
		t.Fatalf("idle token: %v", err)
	}
	ctok = f.open(t, carol)
	for range 4 {
		f.offset.Add(int64(9 * time.Minute))
		if _, err := f.op(t, ctok, "list", nil); err != nil && f.now().Sub(f.start) < 30*time.Minute {
			t.Fatalf("token in use: %v", err)
		}
	}
	if _, err := f.op(t, ctok, "list", nil); code(err) != changeset.CodeNoWorkspace {
		t.Fatalf("expired token: %v", err)
	}
	/* a frozen executor answers nothing */
	ctok = f.open(t, carol)
	f.adminDo(t, execadmin.Request{Cmd: execadmin.CmdFreezeOn}, nil)
	if _, err := f.op(t, ctok, "list", nil); !errors.Is(err, authz.ErrFrozen) {
		t.Fatalf("frozen: %v", err)
	}
}

/*
Authoring: the author creates and revises (with the revision edited from),
nobody else does; the devices come from the write registry only; the
policy's limits hold; every change is audited and published to the panel's
summary.
*/
func TestSaveReviseDiscard(t *testing.T) {
	f := newFx(t, "mes6", "mes10")
	alice, bob := f.user(t, "core"), f.user(t, "core")
	tok, btok := f.open(t, alice), f.open(t, bob)
	s := f.save(t, tok, "", 0, f.lines("vlan descr", f.devs...))
	if s.Rev != 1 {
		t.Fatalf("saved %+v", s)
	}
	var st string
	var n int
	if err := f.env.Pool("nms_api").QueryRow(context.Background(), `SELECT status, device_count FROM execpub.changeset_summary WHERE changeset_id = $1`,
		s.ID).Scan(&st, &n); err != nil || st != "draft" || n != 2 {
		t.Fatalf("summary %s %d %v", st, n, err)
	}
	/* bob may read it (write on its group), not change or discard it */
	if _, err := f.op(t, btok, "get", map[string]any{"changeset_id": s.ID}); err != nil {
		t.Fatalf("bob reads: %v", err)
	}
	if _, err := f.op(t, btok, "save", map[string]any{"changeset_id": s.ID, "revision": 1, "content": f.lines("bob's", f.devs...)}); code(err) != changeset.CodeNotAuthor {
		t.Fatalf("bob revises: %v", err)
	}
	if _, err := f.op(t, btok, "discard", map[string]any{"changeset_id": s.ID}); code(err) != changeset.CodeNotAuthor {
		t.Fatalf("bob discards: %v", err)
	}
	if r := f.save(t, tok, s.ID, 1, f.lines("vlan descr 2", f.devs...)); r.Rev != 2 {
		t.Fatalf("revise: %+v", r)
	}
	if _, err := f.op(t, tok, "save", map[string]any{"changeset_id": s.ID, "revision": 1, "content": f.lines("stale", f.devs...)}); code(err) != changeset.CodeConflict {
		t.Fatalf("stale revision: %v", err)
	}
	res, err := f.op(t, tok, "get", map[string]any{"changeset_id": s.ID})
	if err != nil {
		t.Fatal(err)
	}
	if d := res.(changeset.Detail); d.Rev != 2 || d.Content.Title != "vlan descr 2" || d.Status != changeset.StatusDraft {
		t.Fatalf("detail %+v", d)
	}
	if _, err := f.op(t, tok, "discard", map[string]any{"changeset_id": s.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.op(t, tok, "save", map[string]any{"changeset_id": s.ID, "revision": 2, "content": f.lines("after", f.devs...)}); code(err) != changeset.CodeState {
		t.Fatalf("revise a discarded one: %v", err)
	}
	if err := f.env.Pool("nms_api").QueryRow(context.Background(), `SELECT status FROM execpub.changeset_summary WHERE changeset_id = $1`, s.ID).Scan(&st); err != nil || st != "discarded" {
		t.Fatalf("summary after discard %s %v", st, err)
	}
	for _, a := range []string{"changeset.create", "changeset.revise", "changeset.discard", "changeset.view", "changeset.open"} {
		if f.audits(t, a, "ok") == 0 {
			t.Errorf("no audit row %s", a)
		}
	}
}

/*
Devices are only what the write registry allows now: an id the registry
does not have (the api may add any core.device), writes off, a model not
confirmed; and a content over the policy's limits or with a line the
device's grammar refuses is refused before it is stored.
*/
func TestSaveRefusals(t *testing.T) {
	f := newFx(t, "mes6", "esr")
	alice := f.user(t, "core")
	tok := f.open(t, alice)
	stranger := f.panelDevice(t) /* in core.device, not in the write registry */
	c := f.lines("x", f.devs[0])
	c.Devices = append(c.Devices, stranger)
	c.Vars[stranger] = c.Vars[f.devs[0].id]
	if _, err := f.op(t, tok, "save", map[string]any{"content": c}); code(err) != "device_unknown" {
		t.Fatalf("device outside the registry: %v", err)
	}
	off := f.devs[1].row
	off["writes_enabled"] = false
	f.put(t, "write_device", off)
	if _, err := f.op(t, tok, "save", map[string]any{"content": f.lines("x", f.devs[1])}); code(err) != "writes_disabled" {
		t.Fatalf("writes off: %v", err)
	}
	f.policy(t, "changeset_max_devices: 1\n")
	if _, err := f.op(t, tok, "save", map[string]any{"content": f.lines("x", f.devs...)}); code(err) != changeset.CodeBadContent {
		t.Fatalf("over changeset_max_devices: %v", err)
	}
	f.policy(t, "")
	c = f.lines("x", f.devs[0])
	c.Steps = append(c.Steps, changeset.Step{Line: "hostname a;reload"})
	_, err := f.op(t, tok, "save", map[string]any{"content": c})
	var r *changeset.Refusal
	if !errors.As(err, &r) || r.Code != changeset.CodeBadLine || r.Device != f.devs[0].id || r.Step != 5 || !strings.Contains(r.Reason, "line 5") {
		t.Fatalf("impure line: %v", err)
	}
	if n := f.count(t, `SELECT count(*) FROM exec.changeset`); n != 0 {
		t.Fatalf("%d changesets stored", n)
	}
}
