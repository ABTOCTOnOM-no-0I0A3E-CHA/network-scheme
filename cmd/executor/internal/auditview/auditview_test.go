package auditview_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/beekamai/network-scheme/cmd/executor/internal/admin"
	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/audit"
	"github.com/beekamai/network-scheme/cmd/executor/internal/auditview"
	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/cmd/executor/internal/policy"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/terminal"
	"github.com/beekamai/network-scheme/internal/execadmin"
	"github.com/beekamai/network-scheme/internal/testdb"
	"github.com/beekamai/network-scheme/internal/ticket"
)

func TestMain(m *testing.M) { testdb.Main(m) }

var ticketKey = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

type fx struct {
	env    *testdb.Env
	v      *auditview.View
	az     *authz.Authorizer
	adm    *admin.Admin
	start  time.Time
	offset atomic.Int64
}

func (f *fx) now() time.Time { return f.start.Add(time.Duration(f.offset.Load())) }

func newFx(t *testing.T) *fx {
	t.Helper()
	env := testdb.New(t)
	attacktest.Reset(t, env)
	ctx := context.Background()
	keys, err := seal.Derive(&[32]byte{11})
	if err != nil {
		t.Fatal(err)
	}
	f := &fx{env: env, start: time.Now()}
	pool := env.Pool("nms_executor")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()
	reg := registry.New(pool, keys, filepath.Join(dir, "state"))
	guard := freeze.New(reg, pool, log)
	if err := guard.Start(ctx); err != nil {
		t.Fatal(err)
	}
	polF := filepath.Join(dir, "executor.yaml")
	if err := os.WriteFile(polF, []byte("enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pol := policy.New(polF)
	pol.Reload(true)
	if f.az, err = authz.New(authz.Config{Guard: guard, Reg: reg, Keys: keys, Policy: pol, Log: log, Now: f.now,
		TicketKey: ticketKey.Public().(ed25519.PublicKey), Started: f.start, GuardsFile: filepath.Join(dir, "guards")}); err != nil {
		t.Fatal(err)
	}
	f.adm = &admin.Admin{Guard: guard, Reg: reg, Keys: keys, Policy: pol, Log: log, Lockouts: f.az}
	if f.v, err = auditview.New(auditview.Config{Reg: reg, Clean: terminal.Clean, Audit: f.az.Record, Now: f.now}); err != nil {
		t.Fatal(err)
	}
	return f
}

type who struct {
	id         int64
	name, totp string
}

func (f *fx) user(t *testing.T, grants ...string) who {
	t.Helper()
	name := fmt.Sprintf("av-%d", time.Now().UnixNano()%1e9)
	var u who
	if err := f.env.Pool("postgres").QueryRow(context.Background(),
		`INSERT INTO core."user" (username, password_phc) VALUES ($1, 'x') RETURNING id`, name).Scan(&u.id); err != nil {
		t.Fatal(err)
	}
	u.name = name
	reqs := []execadmin.Request{{Cmd: execadmin.CmdEnroll}}
	for _, g := range grants {
		kind, group, _ := strings.Cut(g, ":")
		reqs = append(reqs, execadmin.Request{Cmd: execadmin.CmdGrant, Kind: kind, Group: group})
	}
	for _, req := range reqs {
		req.User, req.V, req.Operator = name, execadmin.Version, "tester"
		resp := f.adm.Handle(context.Background(), req)
		if resp.OK && resp.Confirm != nil {
			req.UserID, req.UserCreated = resp.Confirm.ID, resp.Confirm.CreatedAt
			resp = f.adm.Handle(context.Background(), req)
		}
		if !resp.OK {
			t.Fatalf("%s %s: %s", req.Cmd, req.Kind, resp.Error)
		}
		if resp.Enrollment != nil {
			u.totp = resp.Enrollment.Secret
		}
	}
	return u
}

func (f *fx) code(t *testing.T, u who) string {
	t.Helper()
	f.offset.Add(int64(30 * time.Second))
	c, err := totp.GenerateCodeCustom(u.totp, f.now(), totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

/* read is web's authorized read of /x/audit: authz with the read's Need (ticket, code), then Run. */
func (f *fx) read(t *testing.T, u who, code string, params any) (auditview.Page, error) {
	t.Helper()
	tok, _, err := ticket.Issue(ticketKey, u.id, u.name, f.now())
	if err != nil {
		t.Fatal(err)
	}
	by, err := f.az.Authorize(context.Background(), authz.Request{Ticket: tok, Code: code, Need: auditview.Need(), Action: auditview.ActionRead, Object: "/x/audit"})
	if err != nil {
		return auditview.Page{}, err
	}
	b, _ := json.Marshal(params)
	res, err := f.v.Run(context.Background(), by, b)
	p, _ := res.(auditview.Page)
	return p, err
}

func (f *fx) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := f.env.Pool("postgres").QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

/*
4d.2: the audit view needs the audit-read grant and the user's change TOTP
code (every other grant, no code, a wrong code: refused); each view is
itself an audit row (audit.view, with its filter and the rows shown) beside
authz's (audit.read).
*/
func TestAuditViewNeedsAuditReadAndTOTP(t *testing.T) {
	f := newFx(t)
	others := f.user(t, "write:core", execadmin.KindWriteAdmin, execadmin.KindUnmask)
	if _, err := f.read(t, others, f.code(t, others), map[string]any{}); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("without audit-read: %v", err)
	}
	auditor := f.user(t, execadmin.KindAuditRead)
	for _, code := range []string{"", "000000"} {
		if _, err := f.read(t, auditor, code, map[string]any{}); err == nil {
			t.Fatalf("code %q accepted", code)
		}
	}
	f.az.ResetUser(auditor.id)
	p, err := f.read(t, auditor, f.code(t, auditor), map[string]any{"limit": 5})
	if err != nil || len(p.Rows) != 5 {
		t.Fatalf("read: %v, %d rows", err, len(p.Rows))
	}
	if n := f.count(t, `SELECT count(*) FROM exec.audit_event WHERE action = 'audit.view' AND result = 'ok' AND user_id = $1
		AND convert_from(payload, 'UTF8')::jsonb #>> '{details,rows}' = '5'`, auditor.id); n != 1 {
		t.Fatalf("%d audit.view rows", n)
	}
	if n := f.count(t, `SELECT count(*) FROM exec.audit_event WHERE action = 'audit.read' AND result = 'ok' AND user_id = $1`, auditor.id); n != 1 {
		t.Fatalf("%d audit.read rows", n)
	}
}

/*
Filters (time range, user, action exact or prefix, device by object or
details, result) and paging are bounded: newest first, at most the page
size, the cursor continues without overlap; a page size above the bound, a
malformed action or result, an empty time range are refused.
*/
func TestAuditViewFiltersAndPages(t *testing.T) {
	f := newFx(t)
	auditor := f.user(t, execadmin.KindAuditRead)
	ctx := context.Background()
	t0 := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	mark := func(sec int, user int64, action, object, result string, details map[string]any) {
		u := user
		f.az.Record(ctx, audit.Event{TS: t0.Add(time.Duration(sec) * time.Second), UserID: &u, Action: action, Object: object, Result: result, Details: details})
	}
	mark(1, 4242, "session.command", "session:x", audit.OK, map[string]any{"device_id": 77, "class": "safe"})
	mark(2, 4242, "session.command", "session:x", audit.Denied, map[string]any{"device_id": 78, "class": "denied"})
	mark(3, 4243, "session.open", "devices:5,77,9", audit.OK, nil)
	mark(4, 4243, "config.view", "device:77", audit.OK, nil)
	mark(5, 4243, "config.view", "device:177", audit.OK, nil)
	params := func(m map[string]any) map[string]any {
		m["from"], m["to"] = t0, t0.Add(time.Minute)
		return m
	}
	ids := func(p auditview.Page) string {
		var s []string
		for _, r := range p.Rows {
			s = append(s, r.Action+"/"+r.Result+"/"+r.Object)
		}
		return strings.Join(s, " ")
	}
	for name, c := range map[string]struct {
		filter map[string]any
		want   string
	}{
		"time range":    {params(map[string]any{}), "config.view/ok/device:177 config.view/ok/device:77 session.open/ok/devices:5,77,9 session.command/denied/session:x session.command/ok/session:x"},
		"user":          {params(map[string]any{"user_id": 4242}), "session.command/denied/session:x session.command/ok/session:x"},
		"action exact":  {params(map[string]any{"action": "session.open"}), "session.open/ok/devices:5,77,9"},
		"action prefix": {params(map[string]any{"action": "session.*"}), "session.open/ok/devices:5,77,9 session.command/denied/session:x session.command/ok/session:x"},
		"device":        {params(map[string]any{"device_id": 77}), "config.view/ok/device:77 session.open/ok/devices:5,77,9 session.command/ok/session:x"},
		"result":        {params(map[string]any{"result": "denied"}), "session.command/denied/session:x"},
	} {
		p, err := f.read(t, auditor, f.code(t, auditor), c.filter)
		if err != nil || ids(p) != c.want {
			t.Errorf("%s: %v\n got %s\nwant %s", name, err, ids(p), c.want)
		}
	}
	/* paging: 2 + 2 + 1, the cursor continues where the last page ended */
	var all []string
	before := int64(0)
	for range 3 {
		filter := params(map[string]any{"limit": 2})
		if before != 0 {
			filter["before"] = before
		}
		p, err := f.read(t, auditor, f.code(t, auditor), filter)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range p.Rows {
			all = append(all, r.Object)
		}
		before = p.Next
	}
	if strings.Join(all, " ") != "device:177 device:77 devices:5,77,9 session:x session:x" || before != 0 {
		t.Fatalf("pages %v, last cursor %d", all, before)
	}
	for name, bad := range map[string]map[string]any{
		"page above the bound": {"limit": 101},
		"action":               {"action": "session.*.x"},
		"result":               {"result": "fine"},
		"empty range":          {"from": t0, "to": t0},
		"unknown field":        {"sql": "1"},
	} {
		if _, err := f.read(t, auditor, f.code(t, auditor), bad); !errors.Is(err, auditview.ErrParams) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

/* What a device or a client wrote reaches the view as text: escapes, controls and format characters cleaned, details bounded. */
func TestAuditViewCleansText(t *testing.T) {
	f := newFx(t)
	auditor := f.user(t, execadmin.KindAuditRead)
	u := int64(4244)
	f.az.Record(context.Background(), audit.Event{UserID: &u, UA: "evil\x1b]52;c;ZXZpbA==\x07agent", Action: "session.command", Object: "session:\x1b[31mx",
		Result: audit.OK, Details: map[string]any{"line": "show \xe2\x80\xaeevil\x07 " + strings.Repeat("y", 10000)}})
	p, err := f.read(t, auditor, f.code(t, auditor), map[string]any{"user_id": u})
	if err != nil || len(p.Rows) != 1 {
		t.Fatalf("%v %+v", err, p)
	}
	r := p.Rows[0]
	if r.UA != "evilagent" || r.Object != "session:x" || strings.ContainsAny(r.Details, "\x1b\x07\u202e") || len(r.Details) > 4<<10+8 ||
		!strings.HasSuffix(r.Details, " …") {
		t.Fatalf("row %+v", r)
	}
}

/* Views per user and hour are bounded: past the bound refused, and the refusal is audited. */
func TestAuditViewLimit(t *testing.T) {
	f := newFx(t)
	t.Cleanup(auditview.SetViewsPerHour(2))
	auditor := f.user(t, execadmin.KindAuditRead)
	for range 2 {
		if _, err := f.read(t, auditor, f.code(t, auditor), map[string]any{}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.read(t, auditor, f.code(t, auditor), map[string]any{}); !errors.Is(err, auditview.ErrViewLimit) {
		t.Fatalf("past the limit: %v", err)
	}
	if n := f.count(t, `SELECT count(*) FROM exec.audit_event WHERE action = 'audit.view' AND result = 'denied'`); n != 1 {
		t.Fatalf("%d refusals audited", n)
	}
}
