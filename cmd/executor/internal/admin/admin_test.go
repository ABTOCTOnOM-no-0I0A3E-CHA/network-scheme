package admin_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
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
	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/cmd/executor/internal/policy"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/state"
	"github.com/beekamai/network-scheme/internal/auth"
	"github.com/beekamai/network-scheme/internal/execadmin"
	"github.com/beekamai/network-scheme/internal/secret"
	"github.com/beekamai/network-scheme/internal/testdb"
)

func TestMain(m *testing.M) { testdb.Main(m) }

/* fixture is one executor with its administration over the test database. */
type fixture struct {
	env    *testdb.Env
	keys   *seal.Keys
	dir    string
	reg    *registry.Registry
	guard  *freeze.Guard
	admin  *admin.Admin
	policy string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	env := testdb.New(t)
	attacktest.Reset(t, env)
	k, err := seal.Derive(&[32]byte{9})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir() /* the state directory; the policy lives apart, as on the host */
	f := &fixture{env: env, keys: k, dir: dir, policy: filepath.Join(t.TempDir(), "executor.yaml")}
	f.writePolicy(t, "enabled: false\n")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	f.reg = registry.New(env.Pool("nms_executor"), k, filepath.Join(dir, "state"))
	f.guard = freeze.New(f.reg, env.Pool("nms_executor"), log)
	if err := f.guard.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	pol := policy.New(f.policy)
	pol.Reload(true)
	f.admin = &admin.Admin{Guard: f.guard, Reg: f.reg, Keys: k, Policy: pol, Log: log}
	return f
}

func (f *fixture) writePolicy(t *testing.T, body string) {
	t.Helper()
	if err := os.WriteFile(f.policy, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	/* A later mtime than the last read, whatever the file system's resolution. */
	_ = os.Chtimes(f.policy, time.Now(), time.Now().Add(time.Duration(seq.Add(1))*time.Second))
}

var seq atomic.Int64

func (f *fixture) do(req execadmin.Request) execadmin.Response {
	req.V, req.Operator = execadmin.Version, "tester"
	return f.admin.Handle(context.Background(), req)
}

/* user creates a panel user with a unique name. */
func (f *fixture) user(t *testing.T, prefix string) (int64, string) {
	t.Helper()
	name := fmt.Sprintf("%s%d", prefix, seq.Add(1))
	var id int64
	if err := f.env.Pool("postgres").QueryRow(context.Background(),
		`INSERT INTO core."user" (username, password_phc) VALUES ($1, 'x') RETURNING id`, name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id, name
}

/* bind runs a two-step command: preview, then the confirmation with the user it showed. */
func (f *fixture) bind(t *testing.T, req execadmin.Request) execadmin.Response {
	t.Helper()
	resp := f.do(req)
	if !resp.OK || resp.Confirm == nil {
		return resp
	}
	req.User, req.UserID, req.UserCreated = resp.Confirm.Username, resp.Confirm.ID, resp.Confirm.CreatedAt
	return f.do(req)
}

type auditRow struct {
	action, result string
	details        map[string]any
}

func (f *fixture) lastAudit(t *testing.T) auditRow {
	t.Helper()
	var r auditRow
	var payload []byte
	if err := f.env.Pool("postgres").QueryRow(context.Background(),
		`SELECT action, result, payload FROM exec.audit_event ORDER BY id DESC LIMIT 1`).Scan(&r.action, &r.result, &payload); err != nil {
		t.Fatal(err)
	}
	var e struct {
		Details map[string]any `json:"details"`
	}
	if err := json.Unmarshal(payload, &e); err != nil {
		t.Fatal(err)
	}
	r.details = e.Details
	return r
}

func (f *fixture) auditCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.env.Pool("postgres").QueryRow(context.Background(), `SELECT count(*) FROM exec.audit_event`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (f *fixture) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := f.env.Pool("postgres").QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (f *fixture) chainIntact(t *testing.T) {
	t.Helper()
	if resp := f.do(execadmin.Request{Cmd: execadmin.CmdAuditVerify}); !resp.OK {
		t.Fatalf("audit chain: %s", resp.Error)
	}
}

/* Every command, also a refused, invalid or not yet implemented one, writes one audit row with its action and result. */
func TestEveryCommandIsAudited(t *testing.T) {
	f := newFixture(t)
	_, alice := f.user(t, "alice")
	steps := []struct {
		req            execadmin.Request
		action, result string
	}{
		{execadmin.Request{Cmd: "policy-show"}, "admin.policy-show", "ok"},
		{execadmin.Request{Cmd: "policy-check"}, "admin.policy-check", "ok"},
		{execadmin.Request{Cmd: "policy-reload", Action: "enable"}, "admin.policy-reload.enable", "error"}, /* the file still says false */
		{execadmin.Request{Cmd: "enroll", User: alice}, "admin.enroll", "ok"},
		{execadmin.Request{Cmd: "grant", User: alice, Kind: "unmask"}, "admin.grant", "ok"},
		{execadmin.Request{Cmd: "grant", User: "nobody-here", Kind: "unmask"}, "admin.grant", "denied"},
		{execadmin.Request{Cmd: "revoke", User: alice, Kind: "audit-read"}, "admin.revoke", "denied"},
		{execadmin.Request{Cmd: "unlock", Global: true}, "admin.unlock", "ok"},
		{execadmin.Request{Cmd: "unlock", User: alice}, "admin.unlock", "denied"}, /* not enrolled */
		{execadmin.Request{Cmd: "model-verify", Driver: "esr", Model: "^ESR", Firmware: ".", Note: "stand"}, "admin.model-verify", "ok"},
		{execadmin.Request{Cmd: "model-verify", Driver: "esr", Model: "(", Firmware: ".", Note: "stand"}, "admin.model-verify", "denied"},
		{execadmin.Request{Cmd: "registry-verify"}, "admin.registry-verify", "ok"},
		{execadmin.Request{Cmd: "audit-verify"}, "admin.audit-verify", "ok"},
		{execadmin.Request{Cmd: "freeze-on", Reason: "drill"}, "admin.freeze-on", "ok"},
		{execadmin.Request{Cmd: "freeze-off"}, "admin.freeze-off", "ok"},
		{execadmin.Request{Cmd: "registry-reset"}, "admin.registry-reset", "denied"},
		{execadmin.Request{Cmd: "device", Action: "add"}, "admin.device.add", "denied"},
		{execadmin.Request{Cmd: "no-such-command"}, "admin.request", "denied"},
		{execadmin.Request{Cmd: "grant", User: alice, Kind: "write"}, "admin.request", "denied"},
	}
	for _, s := range steps {
		before := f.auditCount(t)
		resp := f.do(s.req)
		if s.result == "ok" && !resp.OK {
			t.Fatalf("%+v: %s", s.req, resp.Error)
		}
		if s.result != "ok" && resp.OK {
			t.Fatalf("%+v: accepted", s.req)
		}
		if n := f.auditCount(t); n != before+1 {
			t.Fatalf("%+v: %d audit rows, want 1", s.req, n-before)
		}
		if r := f.lastAudit(t); r.action != s.action || r.result != s.result || r.details["operator"] != "tester" {
			t.Fatalf("%+v: audit %+v, want %s %s", s.req, r, s.action, s.result)
		}
	}
	/* The two-step commands: the confirmation writes its own row, in the change's transaction. */
	before := f.auditCount(t)
	if resp := f.bind(t, execadmin.Request{Cmd: "grant", User: alice, Kind: "write", Group: "core"}); !resp.OK {
		t.Fatal(resp.Error)
	}
	if n := f.auditCount(t); n != before+2 {
		t.Fatalf("grant: %d audit rows", n-before)
	}
	if resp := f.do(execadmin.Request{Cmd: "revoke", User: alice, All: true}); !resp.OK {
		t.Fatal(resp.Error)
	}
	if r := f.lastAudit(t); r.action != "admin.revoke" || r.result != "ok" {
		t.Fatalf("revoke audit %+v", r)
	}
	f.chainIntact(t)
	/* The head is anchored in the state file at the chain's last row. */
	var last int64
	if err := f.env.Pool("postgres").QueryRow(context.Background(), `SELECT max(id) FROM exec.audit_event`).Scan(&last); err != nil {
		t.Fatal(err)
	}
	if _, a, err := f.reg.AuditBounds(); err != nil || a.LastID != last {
		t.Fatalf("anchor %+v %v, last row %d", a, err, last)
	}
}

/* enroll seals a fresh secret bound to the user; a second enroll needs --replace, and both are audited. */
func TestEnrollReplacesOnlyWithReplace(t *testing.T) {
	f := newFixture(t)
	id, name := f.user(t, "erin")
	open := func() string {
		var ct []byte
		if err := f.env.Pool("postgres").QueryRow(context.Background(), `SELECT ciphertext FROM exec.change_totp WHERE user_id = $1`, id).Scan(&ct); err != nil {
			t.Fatal(err)
		}
		pt, err := f.keys.OpenTOTP(id, seal.KeyVersion, ct)
		if err != nil {
			t.Fatal(err)
		}
		return string(pt)
	}
	resp := f.bind(t, execadmin.Request{Cmd: "enroll", User: name})
	if !resp.OK || resp.Enrollment == nil || !strings.HasPrefix(resp.Enrollment.URI, "otpauth://totp/") {
		t.Fatalf("enroll: %+v", resp)
	}
	first := open()
	if first != resp.Enrollment.Secret {
		t.Fatal("stored secret differs from the one shown")
	}
	/* The sealed secret validates codes as the change TOTP will (4a.5). */
	now := time.Now()
	code, _ := totpCode(first, now)
	if _, ok := auth.ValidateTOTP(code, secret.New(first), 0, now); !ok {
		t.Fatal("enrolled secret does not validate a code")
	}
	if resp := f.do(execadmin.Request{Cmd: "enroll", User: name}); resp.OK {
		t.Fatal("second enroll without --replace accepted")
	}
	if r := f.lastAudit(t); r.action != "admin.enroll" || r.result != "denied" {
		t.Fatalf("refusal audit %+v", r)
	}
	if open() != first {
		t.Fatal("secret overwritten without --replace")
	}
	resp = f.bind(t, execadmin.Request{Cmd: "enroll", User: name, Replace: true})
	if !resp.OK || open() == first || open() != resp.Enrollment.Secret {
		t.Fatalf("replace: %+v", resp)
	}
	if r := f.lastAudit(t); r.action != "admin.enroll" || r.result != "ok" || r.details["replace"] != true || r.details["existed"] != true {
		t.Fatalf("replace audit %+v", r)
	}
	if strings.Contains(fmt.Sprint(f.lastAudit(t).details), resp.Enrollment.Secret) {
		t.Fatal("secret in the audit")
	}
}

/*
D10 (api attacker): between the preview the host confirmed and the
confirmation, the api renames users so that the confirmed name now belongs
to another id, or disables the user. The confirmation binds nobody.
*/
func TestBindingRefusesWhatTheAPIChanged(t *testing.T) {
	f := newFixture(t)
	api := f.env.Pool("nms_api")
	ctx := context.Background()
	id, name := f.user(t, "vic")
	preview := f.do(execadmin.Request{Cmd: "grant", User: name, Kind: "write-admin"})
	if !preview.OK || preview.Confirm == nil || preview.Confirm.ID != id {
		t.Fatalf("preview %+v", preview)
	}
	if _, err := api.Exec(ctx, `UPDATE core."user" SET username = username || 'x' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	mal, _ := f.user(t, "mal")
	if _, err := api.Exec(ctx, `UPDATE core."user" SET username = $1 WHERE id = $2`, name, mal); err != nil {
		t.Fatal(err)
	}
	confirm := execadmin.Request{Cmd: "grant", User: name, UserID: id, UserCreated: preview.Confirm.CreatedAt, Kind: "write-admin"}
	if resp := f.do(confirm); resp.OK {
		t.Fatal("grant bound after a rename")
	}
	if n := f.count(t, `SELECT count(*) FROM exec.write_grant`); n != 0 {
		t.Fatalf("grants %d", n)
	}
	/* A disabled user is refused at either step. */
	did, dname := f.user(t, "dis")
	if _, err := api.Exec(ctx, `UPDATE core."user" SET disabled = true WHERE id = $1`, did); err != nil {
		t.Fatal(err)
	}
	if resp := f.do(execadmin.Request{Cmd: "enroll", User: dname}); resp.OK {
		t.Fatal("disabled user enrolled")
	}
	if resp := f.do(execadmin.Request{Cmd: "enroll", User: dname, UserID: did}); resp.OK {
		t.Fatal("disabled user enrolled on confirmation")
	}
}

/* revoke by a name that two ids carried is ambiguous and needs #id; by #id it removes exactly that user's grant. */
func TestRevokeIsUnambiguous(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	id1, name := f.user(t, "amb")
	if resp := f.bind(t, execadmin.Request{Cmd: "grant", User: name, Kind: "unmask"}); !resp.OK {
		t.Fatal(resp.Error)
	}
	if _, err := f.env.Pool("nms_api").Exec(ctx, `UPDATE core."user" SET username = username || '-old' WHERE id = $1`, id1); err != nil {
		t.Fatal(err)
	}
	id2, _ := f.user(t, "x")
	if _, err := f.env.Pool("nms_api").Exec(ctx, `UPDATE core."user" SET username = $1 WHERE id = $2`, name, id2); err != nil {
		t.Fatal(err)
	}
	if resp := f.bind(t, execadmin.Request{Cmd: "grant", User: name, Kind: "unmask"}); !resp.OK {
		t.Fatal(resp.Error)
	}
	if resp := f.do(execadmin.Request{Cmd: "revoke", User: name, Kind: "unmask"}); resp.OK || !strings.Contains(resp.Error, "#id") {
		t.Fatalf("ambiguous revoke: %+v", resp)
	}
	if resp := f.do(execadmin.Request{Cmd: "revoke", User: fmt.Sprintf("#%d", id1), Kind: "unmask"}); !resp.OK {
		t.Fatal(resp.Error)
	}
	if n := f.count(t, `SELECT count(*) FROM exec.write_grant WHERE user_id = $1`, id2); n != 1 {
		t.Fatalf("other user's grant: %d", n)
	}
	if n := f.count(t, `SELECT count(*) FROM exec.write_grant WHERE user_id = $1`, id1); n != 0 {
		t.Fatalf("revoked grant: %d", n)
	}
}

/* The host can still revoke and unlock while frozen (incident response); decisions stay refused. */
func TestHostCommandsWorkWhileFrozen(t *testing.T) {
	f := newFixture(t)
	_, name := f.user(t, "fz")
	if resp := f.bind(t, execadmin.Request{Cmd: "grant", User: name, Kind: "write", Group: "core"}); !resp.OK {
		t.Fatal(resp.Error)
	}
	if resp := f.do(execadmin.Request{Cmd: "freeze-on", Reason: "incident"}); !resp.OK {
		t.Fatal(resp.Error)
	}
	if resp := f.do(execadmin.Request{Cmd: "revoke", User: name, All: true}); !resp.OK {
		t.Fatalf("revoke while frozen: %s", resp.Error)
	}
	if err := f.guard.Check(context.Background()); err == nil {
		t.Fatal("decisions allowed while frozen")
	}
}

/* unlock clears one user's failures and lockouts (keeping the secret and the last step), --global the failure window. */
func TestUnlock(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	id, name := f.user(t, "lock")
	if resp := f.bind(t, execadmin.Request{Cmd: "enroll", User: name}); !resp.OK {
		t.Fatal(resp.Error)
	}
	var ct []byte
	if err := f.guard.HostWrite(ctx, func(_ context.Context, s *registry.Snapshot, tx *registry.Tx) error {
		r, _ := s.Get("change_totp", id)
		ct, _ = r.Get("ciphertext").([]byte)
		return tx.Put("change_totp", map[string]any{"user_id": id, "username_snapshot": name, "ciphertext": ct, "key_version": 1,
			"last_step": 77, "failures": 5, "lock_until": time.Now().Add(time.Hour), "lock_count": 3})
	}); err != nil {
		t.Fatal(err)
	}
	if resp := f.do(execadmin.Request{Cmd: "unlock", User: name}); !resp.OK {
		t.Fatal(resp.Error)
	}
	if n := f.count(t, `SELECT count(*) FROM exec.change_totp WHERE user_id = $1 AND failures = 0 AND lock_count = 0
		AND lock_until IS NULL AND last_step = 77 AND ciphertext = $2`, id, ct); n != 1 {
		t.Fatal("not unlocked as expected")
	}
	if err := f.guard.HostWrite(ctx, func(_ context.Context, _ *registry.Snapshot, tx *registry.Tx) error {
		return tx.Put("exec_state", map[string]any{"singleton": true, "freeze": false, "freeze_reason": nil,
			"global_fail_window": json.RawMessage(`[{"u":1,"at":1}]`)})
	}); err != nil {
		t.Fatal(err)
	}
	if resp := f.do(execadmin.Request{Cmd: "unlock", Global: true}); !resp.OK {
		t.Fatal(resp.Error)
	}
	if n := f.count(t, `SELECT count(*) FROM exec.exec_state WHERE global_fail_window = '[]' AND NOT "freeze"`); n != 1 {
		t.Fatal("window not cleared")
	}
}

/* model-verify records a profile; the same driver and patterns update it in place. */
func TestModelVerify(t *testing.T) {
	f := newFixture(t)
	req := execadmin.Request{Cmd: "model-verify", Driver: "mes10", Model: "^MES2424", Firmware: `^10\.`, Note: "stand 1",
		Strategies: map[string]string{"terminal": "set-cli-pagination-off"}}
	for range 2 {
		if resp := f.do(req); !resp.OK {
			t.Fatal(resp.Error)
		}
		req.Note = "stand 2"
	}
	if n := f.count(t, `SELECT count(*) FROM exec.model_profile WHERE note = 'stand 2' AND strategies = '{"terminal": "set-cli-pagination-off"}'`); n != 1 {
		t.Fatalf("profiles %d", n)
	}
	req.Firmware = `^10\.4`
	if resp := f.do(req); !resp.OK {
		t.Fatal(resp.Error)
	}
	if n := f.count(t, `SELECT count(*) FROM exec.model_profile`); n != 2 {
		t.Fatalf("profiles %d", n)
	}
}

/* freeze off is refused while the registry does not verify: the executor stays frozen (and the refusal is audited). */
func TestFreezeOffRefusedWithFailedVerify(t *testing.T) {
	f := newFixture(t)
	_, name := f.user(t, "fo")
	if resp := f.bind(t, execadmin.Request{Cmd: "grant", User: name, Kind: "unmask"}); !resp.OK {
		t.Fatal(resp.Error)
	}
	attacktest.Tamper(t, f.env, `UPDATE exec.write_grant SET username_snapshot = 'evil'`)
	if resp := f.do(execadmin.Request{Cmd: "freeze-off"}); resp.OK {
		t.Fatal("freeze off over a tampered registry")
	}
	if r := f.lastAudit(t); r.action != "admin.freeze-off" || r.result != "denied" {
		t.Fatalf("audit %+v", r)
	}
	if frozen, _ := f.guard.Frozen(); !frozen {
		t.Fatal("not frozen")
	}
	if st, err := state.Load(filepath.Join(f.dir, "state"), f.keys.State()); err != nil || !st.Frozen {
		t.Fatalf("state file %+v %v", st, err)
	}
}

/*
registry reset after real tampering: refused without --i-understand; then
every grant revoked, writes disabled and host keys cleared on every device,
model profiles removed, TOTP secrets kept; the registry verifies, the freeze
is lifted and the audit chain continues intact.
*/
func TestRegistryResetRevokesEverything(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, name := f.user(t, "rs")
	for _, r := range []execadmin.Request{
		{Cmd: "grant", User: name, Kind: "write", Group: "core"}, {Cmd: "grant", User: name, Kind: "write-admin"}, {Cmd: "enroll", User: name},
	} {
		if resp := f.bind(t, r); !resp.OK {
			t.Fatal(resp.Error)
		}
	}
	if resp := f.do(execadmin.Request{Cmd: "model-verify", Driver: "esr", Model: "^ESR", Firmware: ".", Note: "n"}); !resp.OK {
		t.Fatal(resp.Error)
	}
	if err := f.guard.HostWrite(ctx, func(_ context.Context, _ *registry.Snapshot, tx *registry.Tx) error {
		return tx.Put("write_device", map[string]any{"device_id": 1, "address": mustAddr("10.0.0.1"), "port": 22, "protocol": "ssh",
			"write_group": "core", "write_driver": "esr", "hostkey_algo": "ssh-ed25519",
			"hostkey_fp": "SHA256:" + strings.Repeat("A", 43), "allow_ssh_rsa_sha1": true, "writes_enabled": true, "backup_via_executor": true})
	}); err != nil {
		t.Fatal(err)
	}
	/* Tampering: a planted grant, and the audit head rewound. */
	attacktest.Tamper(t, f.env, `INSERT INTO exec.write_grant (user_id, kind, username_snapshot, version, mac)
		VALUES (66, 'unmask', 'evil', 1, decode(repeat('00', 32), 'hex'))`)
	attacktest.Tamper(t, f.env, `UPDATE exec.audit_head SET last_id = last_id - 1`)
	if err := f.guard.Check(ctx); err == nil {
		t.Fatal("tampering not seen")
	}
	if resp := f.do(execadmin.Request{Cmd: "freeze-off"}); resp.OK {
		t.Fatal("freeze off after tampering")
	}
	if resp := f.do(execadmin.Request{Cmd: "registry-reset"}); resp.OK {
		t.Fatal("reset without --i-understand")
	}
	resp := f.do(execadmin.Request{Cmd: "registry-reset", IUnderstand: true})
	if !resp.OK {
		t.Fatalf("reset: %s", resp.Error)
	}
	for sql, want := range map[string]int{
		`SELECT count(*) FROM exec.write_grant`:   0,
		`SELECT count(*) FROM exec.model_profile`: 0,
		`SELECT count(*) FROM exec.change_totp`:   0,
		`SELECT count(*) FROM exec.write_device WHERE NOT writes_enabled AND NOT allow_ssh_rsa_sha1 AND NOT backup_via_executor
			AND hostkey_fp IS NULL AND hostkey_algo IS NULL AND address = '10.0.0.1'`: 1,
		`SELECT count(*) FROM exec.exec_state WHERE NOT "freeze"`: 1,
	} {
		if n := f.count(t, sql); n != want {
			t.Errorf("%s = %d, want %d", sql, n, want)
		}
	}
	if err := f.guard.Check(ctx); err != nil {
		t.Fatalf("after reset: %v", err)
	}
	if r := f.lastAudit(t); r.action != "admin.registry-reset" || r.result != "ok" || r.details["grants_revoked"] != float64(3) ||
		r.details["totp_removed"] != float64(1) {
		t.Fatalf("reset audit %+v", r)
	}
	if !strings.Contains(resp.Text, "device 1  10.0.0.1") {
		t.Fatalf("reset report does not list the device: %s", resp.Text)
	}
	f.chainIntact(t)
	/* A restart over the reset registry comes up unfrozen. */
	g := freeze.New(registry.New(f.env.Pool("nms_executor"), f.keys, filepath.Join(f.dir, "state")), f.env.Pool("nms_executor"),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := g.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := g.Check(ctx); err != nil {
		t.Fatalf("restart after reset: %v", err)
	}
}

/*
audit verify catches a rewritten row (break) and a truncated tail whose
exec.audit_head was rewound to match: only the anchor in the state file
shows the truncation. Both freeze; the O(1) head check of every
verification catches the truncation too.
*/
func TestAuditVerifyCatchesBreakAndTruncation(t *testing.T) {
	for name, attack := range map[string]string{
		"break": `ALTER TABLE exec.audit_event DISABLE TRIGGER audit_event_append_only;
			UPDATE exec.audit_event SET payload = convert_to(replace(convert_from(payload, 'UTF8'), 'tester', 'mallory'), 'UTF8')
				WHERE id = (SELECT min(id) + 1 FROM exec.audit_event);
			ALTER TABLE exec.audit_event ENABLE TRIGGER audit_event_append_only`,
		"truncation": `ALTER TABLE exec.audit_event DISABLE TRIGGER audit_event_append_only;
			DELETE FROM exec.audit_event WHERE id > (SELECT max(id) - 2 FROM exec.audit_event);
			ALTER TABLE exec.audit_event ENABLE TRIGGER audit_event_append_only;
			UPDATE exec.audit_head SET (last_id, hash) = (SELECT id, hash FROM exec.audit_event ORDER BY id DESC LIMIT 1)`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			for range 4 {
				if resp := f.do(execadmin.Request{Cmd: "registry-verify"}); !resp.OK {
					t.Fatal(resp.Error)
				}
			}
			f.chainIntact(t)
			attacktest.Tamper(t, f.env, attack)
			resp := f.do(execadmin.Request{Cmd: "audit-verify"})
			if resp.OK {
				t.Fatal("tampered chain verified")
			}
			if frozen, _ := f.guard.Frozen(); !frozen {
				t.Fatal("not frozen")
			}
			if f.count(t, `SELECT count(*) FROM execpub.alert WHERE kind = 'executor_tamper' AND severity = 'disaster'`) == 0 {
				t.Fatal("no disaster alert")
			}
			if name == "truncation" {
				if _, err := f.reg.Verify(context.Background()); err == nil {
					t.Fatal("registry verification missed the truncated chain")
				}
			}
		})
	}
}

/*
Policy file tampering fails closed: an invalid or missing file disables the
executor, raises the alert and is audited; enable needs the executor to read
enabled=true itself.
*/
func TestPolicyFailsClosed(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.writePolicy(t, "enabled: true\n")
	if resp := f.do(execadmin.Request{Cmd: "policy-reload", Action: "enable"}); !resp.OK || !f.admin.Policy.Current().Enabled() {
		t.Fatalf("enable: %+v", resp)
	}
	for name, body := range map[string]string{
		"garbage":      "enabled: true\n\x00",
		"unknown key":  "enabled: true\nallow_everything: true\n",
		"out of range": "enabled: true\nesr_commit_timer_s: 5\n",
		"missing":      "",
	} {
		t.Run(name, func(t *testing.T) {
			if body == "" {
				if err := os.Remove(f.policy); err != nil {
					t.Fatal(err)
				}
			} else {
				f.writePolicy(t, body)
			}
			old, cur, changed := f.admin.Policy.Reload(false)
			if !changed || cur.Enabled() || cur.Err == nil {
				t.Fatalf("still enabled: %+v", cur)
			}
			before := f.count(t, `SELECT count(*) FROM execpub.alert WHERE kind = 'executor_policy_invalid' AND severity = 'high'`)
			f.admin.PolicyChanged(ctx, "reload", old, cur)
			if f.count(t, `SELECT count(*) FROM execpub.alert WHERE kind = 'executor_policy_invalid' AND severity = 'high'`) != before+1 {
				t.Fatal("no alert")
			}
			if r := f.lastAudit(t); r.action != "executor.policy" || r.result != "error" || r.details["enabled"] != false {
				t.Fatalf("audit %+v", r)
			}
			if resp := f.do(execadmin.Request{Cmd: "policy-check"}); resp.OK {
				t.Fatal("check passed")
			}
			f.writePolicy(t, "enabled: true\n")
			if _, cur, _ := f.admin.Policy.Reload(false); !cur.Enabled() {
				t.Fatalf("valid again: %+v", cur)
			}
		})
	}
}

func totpCode(sec string, now time.Time) (string, error) {
	return totp.GenerateCodeCustom(sec, now, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

/* D10: a user re-created under the confirmed id and name (another creation date) is not the one the host confirmed. */
func TestBindingChecksTheCreationDate(t *testing.T) {
	f := newFixture(t)
	_, name := f.user(t, "cd")
	preview := f.do(execadmin.Request{Cmd: "enroll", User: name})
	if !preview.OK || preview.Confirm == nil {
		t.Fatalf("preview %+v", preview)
	}
	u := preview.Confirm
	if resp := f.do(execadmin.Request{Cmd: "enroll", User: u.Username, UserID: u.ID, UserCreated: u.CreatedAt.Add(-time.Hour)}); resp.OK {
		t.Fatal("enrolled with another creation date")
	}
	if resp := f.do(execadmin.Request{Cmd: "enroll", User: u.Username, UserID: u.ID, UserCreated: u.CreatedAt}); !resp.OK {
		t.Fatal(resp.Error)
	}
}

/*
Review H1/M2: a row rewritten below the anchor (the head still matches)
freezes on audit verify, and freeze off refuses (the chain can never be
repaired); registry reset continues the chain and verifies it from its tail
on, after which audit verify, freeze on/off work again.
*/
func TestBrokenAuditChainNeedsAReset(t *testing.T) {
	f := newFixture(t)
	for range 3 {
		if resp := f.do(execadmin.Request{Cmd: "registry-verify"}); !resp.OK {
			t.Fatal(resp.Error)
		}
	}
	attacktest.Tamper(t, f.env, `ALTER TABLE exec.audit_event DISABLE TRIGGER audit_event_append_only;
		UPDATE exec.audit_event SET payload = convert_to(replace(convert_from(payload, 'UTF8'), 'tester', 'mallory'), 'UTF8')
			WHERE id = (SELECT min(id) FROM exec.audit_event);
		ALTER TABLE exec.audit_event ENABLE TRIGGER audit_event_append_only`)
	if resp := f.do(execadmin.Request{Cmd: "audit-verify"}); resp.OK {
		t.Fatal("broken chain verified")
	}
	if resp := f.do(execadmin.Request{Cmd: "freeze-off"}); resp.OK || !strings.Contains(resp.Error, "registry reset") {
		t.Fatalf("freeze off over a broken chain: %+v", resp)
	}
	if frozen, _ := f.guard.Frozen(); !frozen {
		t.Fatal("not frozen")
	}
	resp := f.do(execadmin.Request{Cmd: "registry-reset", IUnderstand: true})
	if !resp.OK {
		t.Fatalf("reset: %s", resp.Error)
	}
	if r := f.lastAudit(t); r.details["audit_base"] != r.details["audit_tail"] {
		t.Fatalf("base not moved to the tail: %+v", r)
	}
	f.chainIntact(t)
	for _, c := range []string{"freeze-on", "freeze-off"} {
		if resp := f.do(execadmin.Request{Cmd: c}); !resp.OK {
			t.Fatalf("%s after reset: %s", c, resp.Error)
		}
	}
	if err := f.guard.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
}

/* Review L2: unlock never takes the id from core.user (the api's names): a user without a change TOTP is unknown to it. */
func TestUnlockIgnoresPanelNames(t *testing.T) {
	f := newFixture(t)
	id, name := f.user(t, "ul")
	if resp := f.bind(t, execadmin.Request{Cmd: "enroll", User: name}); !resp.OK {
		t.Fatal(resp.Error)
	}
	other, _ := f.user(t, "ot")
	ctx := context.Background()
	if _, err := f.env.Pool("nms_api").Exec(ctx, `UPDATE core."user" SET username = username || '-x' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.env.Pool("nms_api").Exec(ctx, `UPDATE core."user" SET username = $1 WHERE id = $2`, name, other); err != nil {
		t.Fatal(err)
	}
	if resp := f.do(execadmin.Request{Cmd: "unlock", User: name}); !resp.OK || !strings.Contains(resp.Text, fmt.Sprintf("#%d", id)) {
		t.Fatalf("unlock by snapshot: %+v", resp)
	}
}
