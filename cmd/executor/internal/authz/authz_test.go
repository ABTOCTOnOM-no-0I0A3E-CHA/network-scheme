package authz_test

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
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/beekamai/network-scheme/cmd/executor/internal/admin"
	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/cmd/executor/internal/policy"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/internal/execadmin"
	"github.com/beekamai/network-scheme/internal/store"
	"github.com/beekamai/network-scheme/internal/testdb"
	"github.com/beekamai/network-scheme/internal/ticket"
)

func TestMain(m *testing.M) { testdb.Main(m) }

/* The api's ticket key (the attacker of these tests holds it: a ticket alone must open nothing). */
var (
	ticketPriv = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	ticketPub  = ticketPriv.Public().(ed25519.PublicKey)
	otherPriv  = ed25519.NewKeyFromSeed(append(make([]byte, ed25519.SeedSize-1), 1))
	seq        atomic.Int64
)

/* WriteCore is the grant most tests need: write on group core. */
var writeCore = authz.Need{Kind: "write", Groups: []string{"core"}}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

/* fixture is one executor: registry, freeze, host administration and the authorizer, over the test database. */
type fixture struct {
	env    *testdb.Env
	pool   *pgxpool.Pool /* nms_executor, bounded and pinned as in main */
	dir    string        /* the state directory */
	keys   *seal.Keys
	reg    *registry.Registry
	guard  *freeze.Guard
	pol    *policy.Holder
	policy string
	adm    *admin.Admin
	az     *authz.Authorizer
	clk    *clock
	log    *slog.Logger
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	env := testdb.New(t)
	attacktest.Reset(t, env)
	k, err := seal.Derive(&[32]byte{7})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{env: env, keys: k, clk: &clock{t: time.Now().UTC().Truncate(time.Second)}, dir: t.TempDir(),
		policy: filepath.Join(t.TempDir(), "executor.yaml"), log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	cfg, pw := env.Config("nms_executor")
	pool, err := store.Open(context.Background(), cfg, pw, registry.PinSession, registry.BoundMessages)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	f.pool = pool
	f.reg = registry.New(pool, k, filepath.Join(f.dir, "state"))
	f.guard = freeze.New(f.reg, pool, f.log)
	if err := f.guard.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.pol = policy.New(f.policy)
	f.setPolicy(t, "enabled: true\n")
	f.az = f.authorizer(t)
	f.adm = &admin.Admin{Guard: f.guard, Reg: f.reg, Keys: k, Policy: f.pol, Log: f.log, Lockouts: f.az}
	return f
}

/* authorizer is a new process's authorizer (started now) over the same registry. */
func (f *fixture) authorizer(t *testing.T) *authz.Authorizer {
	t.Helper()
	a, err := authz.New(authz.Config{Guard: f.guard, Reg: f.reg, Keys: f.keys, Policy: f.pol, Log: f.log,
		TicketKey: ticketPub, Started: f.clk.Now(), Now: f.clk.Now, GuardsFile: filepath.Join(f.dir, "guards")})
	if err != nil {
		t.Fatal(err)
	}
	if f.adm != nil {
		f.adm.Lockouts = a
	}
	return a
}

func (f *fixture) setPolicy(t *testing.T, body string) {
	t.Helper()
	if err := os.WriteFile(f.policy, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	f.pol.Reload(true)
}

func (f *fixture) host(t *testing.T, req execadmin.Request) execadmin.Response {
	t.Helper()
	req.V, req.Operator = execadmin.Version, "tester"
	resp := f.adm.Handle(context.Background(), req)
	if resp.OK && resp.Confirm != nil {
		req.User, req.UserID, req.UserCreated = resp.Confirm.Username, resp.Confirm.ID, resp.Confirm.CreatedAt
		resp = f.adm.Handle(context.Background(), req)
	}
	if !resp.OK {
		t.Fatalf("%s: %s", req.Cmd, resp.Error)
	}
	return resp
}

type user struct {
	id           int64
	name, secret string
}

/* panelUser creates a panel user (the api's data). */
func (f *fixture) panelUser(t *testing.T, prefix string) user {
	t.Helper()
	u := user{name: fmt.Sprintf("%s%d", prefix, seq.Add(1))}
	if err := f.env.Pool("postgres").QueryRow(context.Background(),
		`INSERT INTO core."user" (username, password_phc) VALUES ($1, 'x') RETURNING id`, u.name).Scan(&u.id); err != nil {
		t.Fatal(err)
	}
	return u
}

/* enrolled creates a panel user, enrolls its change TOTP and gives it write on core. */
func (f *fixture) enrolled(t *testing.T, prefix string) user {
	t.Helper()
	u := f.panelUser(t, prefix)
	u.secret = f.host(t, execadmin.Request{Cmd: execadmin.CmdEnroll, User: u.name}).Enrollment.Secret
	f.host(t, execadmin.Request{Cmd: execadmin.CmdGrant, User: u.name, Kind: "write", Group: "core"})
	return u
}

func codeAt(t *testing.T, sec string, at time.Time) string {
	t.Helper()
	c, err := totp.GenerateCodeCustom(sec, at, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *fixture) code(t *testing.T, u user) string { return codeAt(t, u.secret, f.clk.Now()) }

/* wrong is a code valid at none of the steps the executor accepts now. */
func (f *fixture) wrong(t *testing.T, u user) string {
	t.Helper()
	now := f.clk.Now()
	valid := []string{codeAt(t, u.secret, now.Add(-30*time.Second)), codeAt(t, u.secret, now), codeAt(t, u.secret, now.Add(30*time.Second))}
	for i := 0; ; i++ {
		c := fmt.Sprintf("%06d", (i*7919+12345)%1000000)
		if !slices.Contains(valid, c) {
			return c
		}
	}
}

func (f *fixture) ticketFor(t *testing.T, u user) string {
	t.Helper()
	tok, _, err := ticket.Issue(ticketPriv, u.id, u.name, f.clk.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (f *fixture) ask(tok, code string, need authz.Need) error {
	_, err := f.az.Authorize(context.Background(), authz.Request{Ticket: tok, Code: code, Need: need, Action: "test.action",
		Object: "test", IP: "192.0.2.1", UA: "tester"})
	return err
}

/* try authorizes write on core for u with code and a fresh ticket. */
func (f *fixture) try(t *testing.T, u user, code string) error {
	t.Helper()
	return f.ask(f.ticketFor(t, u), code, writeCore)
}

type totpRow struct {
	failures, lockCount, lastStep int64
	lockUntil                     *time.Time
}

func (f *fixture) row(t *testing.T, id int64) totpRow {
	t.Helper()
	var r totpRow
	if err := f.env.Pool("postgres").QueryRow(context.Background(),
		`SELECT failures, lock_count, last_step, lock_until FROM exec.change_totp WHERE user_id = $1`, id).
		Scan(&r.failures, &r.lockCount, &r.lastStep, &r.lockUntil); err != nil {
		t.Fatal(err)
	}
	return r
}

type auditRow struct {
	action, result string
	userID         *int64
	details        map[string]any
}

func (f *fixture) audits(t *testing.T, after int64) []auditRow {
	t.Helper()
	rows, err := f.env.Pool("postgres").Query(context.Background(),
		`SELECT action, result, user_id, payload FROM exec.audit_event WHERE id > $1 ORDER BY id`, after)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		var payload []byte
		if err := rows.Scan(&r.action, &r.result, &r.userID, &payload); err != nil {
			t.Fatal(err)
		}
		var e struct {
			Details map[string]any `json:"details"`
		}
		if err := json.Unmarshal(payload, &e); err != nil {
			t.Fatal(err)
		}
		r.details = e.Details
		out = append(out, r)
	}
	return out
}

func (f *fixture) lastAuditID(t *testing.T) int64 {
	t.Helper()
	var id int64
	if err := f.env.Pool("postgres").QueryRow(context.Background(), `SELECT coalesce(max(id), 0) FROM exec.audit_event`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *fixture) alerts(t *testing.T, kind, severity string) int {
	t.Helper()
	var n int
	if err := f.env.Pool("postgres").QueryRow(context.Background(),
		`SELECT count(*) FROM execpub.alert WHERE kind = $1 AND severity = $2`, kind, severity).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

/* oneAudit runs fn and insists it wrote exactly one audit row with result and class; it returns the row. */
func (f *fixture) oneAudit(t *testing.T, result, class string, fn func()) auditRow {
	t.Helper()
	before := f.lastAuditID(t)
	fn()
	rows := f.audits(t, before)
	if len(rows) != 1 {
		t.Fatalf("%d audit rows, want 1: %+v", len(rows), rows)
	}
	r := rows[0]
	if r.result != result || r.details["class"] != class {
		t.Fatalf("audit %s %s %v, want %s class %s", r.action, r.result, r.details, result, class)
	}
	for k := range r.details {
		if !slices.Contains([]string{"class", "need", "groups", "ticket"}, k) {
			t.Fatalf("audit detail %q: decisions record only class, need, groups and ticket", k)
		}
	}
	return r
}

/* A valid ticket, a grant and the user's code open the action once; the audit row says who and why, never the code. */
func TestAcceptOnceAndAudit(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	tok := f.ticketFor(t, u)
	c, _ := ticket.Verify(ticketPub, tok, f.clk.Now())
	var dec authz.Decision
	r := f.oneAudit(t, "ok", "accepted", func() {
		var err error
		dec, err = f.az.Authorize(context.Background(), authz.Request{Ticket: tok, Code: f.code(t, u), Need: writeCore,
			Action: "test.action", Object: "test", IP: "192.0.2.1", UA: "tester"})
		if err != nil {
			t.Fatal(err)
		}
	})
	if dec.UserID != u.id || dec.Username != u.name || dec.Ticket != c.ID() || r.action != "test.action" || *r.userID != u.id ||
		r.details["ticket"] != c.ID() || r.details["need"] != "write" {
		t.Fatalf("decision %+v, audit %+v", dec, r)
	}
	if got := f.row(t, u.id); got.lastStep != f.clk.Now().Unix()/30 || got.failures != 0 {
		t.Fatalf("row %+v", got)
	}
	/* The same ticket again: refused before any code is looked at. */
	f.oneAudit(t, "denied", "ticket_replayed", func() {
		if err := f.ask(tok, f.code(t, u), writeCore); !errors.Is(err, authz.ErrDenied) {
			t.Fatalf("replayed ticket: %v", err)
		}
	})
	/* The same code with a fresh ticket: a replay of the code, counted as a failure (C3). */
	f.oneAudit(t, "denied", "replayed", func() {
		if err := f.try(t, u, f.code(t, u)); !errors.Is(err, authz.ErrDenied) {
			t.Fatalf("replayed code: %v", err)
		}
	})
	if got := f.row(t, u.id); got.failures != 1 {
		t.Fatalf("a replayed code is a failure: %+v", got)
	}
	/* The next step's code is accepted (and resets the failures). */
	f.clk.Advance(30 * time.Second)
	if err := f.try(t, u, f.code(t, u)); err != nil {
		t.Fatal(err)
	}
	if got := f.row(t, u.id); got.failures != 0 {
		t.Fatalf("row %+v", got)
	}
}

/* C2a: no code, a wrong code, another user's code: refused alike, each counted as a failure of the ticket's user. */
func TestC2aNoOrWrongTOTP(t *testing.T) {
	f := newFixture(t)
	alice, bob := f.enrolled(t, "alice"), f.enrolled(t, "bob")
	for _, code := range []string{"", f.wrong(t, alice), "1234567", "abcdef"} {
		f.oneAudit(t, "denied", "wrong_code", func() {
			if err := f.try(t, alice, code); err != authz.ErrDenied {
				t.Fatalf("code %q: %v", code, err)
			}
		})
	}
	/* A ticket for alice (the api can sign any) with bob's own valid code: alice's secret decides; the 5th failure locks. */
	if err := f.try(t, alice, f.code(t, bob)); !errors.Is(err, authz.ErrLocked) {
		t.Fatalf("bob's code for alice: %v", err)
	}
	if got := f.row(t, bob.id); got.failures != 0 || got.lastStep != 0 {
		t.Fatalf("bob's row was touched: %+v", got)
	}
}

/* FirstLockPlus lets a lock of the first length end. */
const FirstLockPlus = authz.FirstLock + time.Second

/* C2b: a valid ticket and code without the grant the action needs is refused, before the code is checked. */
func TestC2bTicketWithoutGrant(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	for _, need := range []authz.Need{
		{Kind: "write", Groups: []string{"edge"}},
		{Kind: "write", Groups: []string{"core", "edge"}},
		{Kind: "write-admin"}, {Kind: "unmask"}, {Kind: "audit-read"},
	} {
		f.oneAudit(t, "denied", "no_grant", func() {
			if err := f.ask(f.ticketFor(t, u), f.code(t, u), need); err != authz.ErrDenied {
				t.Fatalf("%+v: %v", need, err)
			}
		})
	}
	for _, need := range []authz.Need{{Kind: "write"}, {Kind: "unmask", Groups: []string{"core"}}, {Kind: "root"}} {
		f.oneAudit(t, "denied", "bad_need", func() {
			if err := f.ask(f.ticketFor(t, u), f.code(t, u), need); err != authz.ErrDenied {
				t.Fatalf("%+v: %v", need, err)
			}
		})
	}
	/* Nothing was evaluated: no failure, no step used; the grant then opens it with the very same code. */
	if got := f.row(t, u.id); got.failures != 0 || got.lastStep != 0 {
		t.Fatalf("row %+v", got)
	}
	f.host(t, execadmin.Request{Cmd: execadmin.CmdGrant, User: u.name, Kind: "unmask"})
	if err := f.ask(f.ticketFor(t, u), f.code(t, u), authz.Need{Kind: "unmask"}); err != nil {
		t.Fatal(err)
	}
	/* A revoked grant refuses again. */
	f.clk.Advance(30 * time.Second)
	f.host(t, execadmin.Request{Cmd: execadmin.CmdRevoke, User: u.name, Kind: "write", Group: "core"})
	if err := f.try(t, u, f.code(t, u)); err != authz.ErrDenied {
		t.Fatalf("revoked: %v", err)
	}
}

/*
C2g: change TOTP secrets swapped between two users, each row with a valid
recomputed MAC (written through the registry with the sealing key, as an
attacker holding the MAC key would): the secret does not open under the
user's AAD. The executor refuses and freezes (disaster): nobody without the
key can produce such a row.
*/
func TestC2gSwappedSecretsWithValidMAC(t *testing.T) {
	f := newFixture(t)
	alice, bob := f.enrolled(t, "alice"), f.enrolled(t, "bob")
	ctx := context.Background()
	if err := f.guard.HostWrite(ctx, func(_ context.Context, s *registry.Snapshot, tx *registry.Tx) error {
		a, _ := s.Get("change_totp", alice.id)
		b, _ := s.Get("change_totp", bob.id)
		for _, p := range [][2]registry.Row{{a, b}, {b, a}} {
			if err := tx.Put("change_totp", map[string]any{"user_id": p[0].Get("user_id"), "username_snapshot": p[0].Get("username_snapshot"),
				"ciphertext": p[1].Get("ciphertext"), "key_version": int32(1), "last_step": 0, "failures": 0, "lock_until": nil, "lock_count": 0}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.reg.Verify(ctx); err != nil {
		t.Fatalf("the swapped rows must verify (valid MACs): %v", err)
	}
	for _, code := range []string{f.code(t, alice), f.code(t, bob)} {
		if err := f.try(t, alice, code); !errors.Is(err, authz.ErrFrozen) {
			t.Fatalf("swapped secret: %v", err)
		}
	}
	if frozen, _ := f.guard.Frozen(); !frozen {
		t.Fatal("not frozen")
	}
	if f.alerts(t, freeze.KindTamper, "disaster") != 1 {
		t.Fatal("no disaster alert")
	}
}

/* D10: the api's data only refuses: an unknown, disabled or renamed user, a ticket for another name or another user. */
func TestPanelUserDenyOnly(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	u := f.enrolled(t, "alice")
	ghost := user{id: u.id + 100000, name: "ghost"}
	f.oneAudit(t, "denied", "unknown_user", func() {
		if err := f.try(t, ghost, "123456"); err != authz.ErrDenied {
			t.Fatal(err)
		}
	})
	/* The api renames the user: the ticket must carry the panel's current name and the snapshot of enroll and grant. */
	if _, err := f.env.Pool("nms_api").Exec(ctx, `UPDATE core."user" SET username = $1 WHERE id = $2`, u.name+"x", u.id); err != nil {
		t.Fatal(err)
	}
	f.oneAudit(t, "denied", "panel_name_mismatch", func() {
		if err := f.try(t, u, f.code(t, u)); err != authz.ErrDenied {
			t.Fatal(err)
		}
	})
	renamed := user{id: u.id, name: u.name + "x", secret: u.secret}
	f.oneAudit(t, "denied", "snapshot_mismatch", func() {
		if err := f.try(t, renamed, f.code(t, u)); err != authz.ErrDenied {
			t.Fatal(err)
		}
	})
	if _, err := f.env.Pool("nms_api").Exec(ctx, `UPDATE core."user" SET username = $1, disabled = true WHERE id = $2`, u.name, u.id); err != nil {
		t.Fatal(err)
	}
	f.oneAudit(t, "denied", "disabled_user", func() {
		if err := f.try(t, u, f.code(t, u)); err != authz.ErrDenied {
			t.Fatal(err)
		}
	})
	if _, err := f.env.Pool("nms_api").Exec(ctx, `UPDATE core."user" SET disabled = false WHERE id = $1`, u.id); err != nil {
		t.Fatal(err)
	}
	/* A grant whose snapshot is another name (granted before a rename and back) refuses too. */
	f.host(t, execadmin.Request{Cmd: execadmin.CmdGrant, User: u.name, Kind: "unmask"})
	if err := f.guard.HostWrite(ctx, func(_ context.Context, _ *registry.Snapshot, tx *registry.Tx) error {
		return tx.Put("write_grant", map[string]any{"user_id": u.id, "kind": "unmask", "write_group": nil, "username_snapshot": "someone"})
	}); err != nil {
		t.Fatal(err)
	}
	f.oneAudit(t, "denied", "grant_snapshot_mismatch", func() {
		if err := f.ask(f.ticketFor(t, u), f.code(t, u), authz.Need{Kind: "unmask"}); err != authz.ErrDenied {
			t.Fatal(err)
		}
	})
	/* A ticket for another user than the one the caller requires (a challenge's). */
	other := f.enrolled(t, "bob")
	f.oneAudit(t, "denied", "wrong_user", func() {
		_, err := f.az.Authorize(ctx, authz.Request{Ticket: f.ticketFor(t, other), Code: f.code(t, other), Need: writeCore,
			Action: "test.action", User: u.id})
		if err != authz.ErrDenied {
			t.Fatal(err)
		}
	})
	/* A panel user without a change TOTP. */
	plain := f.panelUser(t, "plain")
	f.host(t, execadmin.Request{Cmd: execadmin.CmdGrant, User: plain.name, Kind: "write", Group: "core"})
	f.oneAudit(t, "denied", "not_enrolled", func() {
		if err := f.try(t, plain, "123456"); err != authz.ErrDenied {
			t.Fatal(err)
		}
	})
	if got := f.row(t, u.id); got.failures != 0 {
		t.Fatalf("refusals before the code counted as failures: %+v", got)
	}
}

/* Tickets: forged, expired, replayed, another audience, tampered, oversize, issued before the executor started. */
func TestTicketRefusals(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	now := f.clk.Now()
	sign := func(key ed25519.PrivateKey, mut func(*ticket.Claims)) string {
		c := ticket.Claims{V: 1, Aud: "executor", UserID: u.id, Username: u.name, IssuedAt: now.Unix(), Expires: now.Unix() + 60,
			Nonce: [16]byte{byte(seq.Add(1)), byte(seq.Add(1) >> 8), 7}}
		mut(&c)
		tok, err := ticket.Sign(key, c)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	none := func(*ticket.Claims) {}
	expired := sign(ticketPriv, none)
	for name, tc := range map[string]struct{ tok, class string }{
		"forged":        {sign(otherPriv, none), "ticket_signature"},
		"wrong aud":     {sign(ticketPriv, func(c *ticket.Claims) { c.Aud = "api" }), "ticket_audience"},
		"long lifetime": {sign(ticketPriv, func(c *ticket.Claims) { c.Expires += 600 }), "ticket_lifetime"},
		"tampered":      {"x" + sign(ticketPriv, none)[1:], "ticket_signature"},
		"oversize":      {string(make([]byte, ticket.MaxLen+1)), "ticket_oversize"},
		"empty":         {"", "ticket_malformed"},
	} {
		f.oneAudit(t, "denied", tc.class, func() {
			if err := f.ask(tc.tok, f.code(t, u), writeCore); err != authz.ErrDenied {
				t.Fatalf("%s: %v", name, err)
			}
		})
	}
	f.clk.Advance(ticket.TTL)
	f.oneAudit(t, "denied", "ticket_expired", func() {
		if err := f.ask(expired, f.code(t, u), writeCore); err != authz.ErrDenied {
			t.Fatal(err)
		}
	})
	/* Restart: a ticket issued more than 5 s before the new process started is refused, one within the skew is not. */
	old := f.ticketFor(t, u)
	f.clk.Advance(2 * time.Second)
	recent := f.ticketFor(t, u)
	f.clk.Advance(4 * time.Second)
	f.az = f.authorizer(t)
	f.oneAudit(t, "denied", "ticket_before_start", func() {
		if err := f.ask(old, f.code(t, u), writeCore); err != authz.ErrDenied {
			t.Fatal(err)
		}
	})
	if err := f.ask(recent, f.code(t, u), writeCore); err != nil {
		t.Fatalf("within the skew: %v", err)
	}
	if got := f.row(t, u.id); got.failures != 0 {
		t.Fatalf("ticket refusals counted as TOTP failures: %+v", got)
	}
}

/* C1 groundwork and D9: a disabled executor, fido2 mode and a freeze refuse before the ticket is even spent. */
func TestPolicyAndFreezeGate(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	tok := f.ticketFor(t, u)
	for body, class := range map[string]string{"enabled: false\n": "disabled", "enabled: true\nconfirm_mode: fido2\n": "confirm_mode", "enabled: [\n": "disabled"} {
		f.setPolicy(t, body)
		f.oneAudit(t, "denied", class, func() {
			if err := f.ask(tok, f.code(t, u), writeCore); err != authz.ErrDisabled {
				t.Fatalf("%q: %v", body, err)
			}
		})
	}
	f.setPolicy(t, "enabled: true\n")
	f.host(t, execadmin.Request{Cmd: execadmin.CmdFreezeOn, Reason: "drill"})
	f.oneAudit(t, "denied", "frozen", func() {
		if err := f.ask(tok, f.code(t, u), writeCore); err != authz.ErrFrozen {
			t.Fatal(err)
		}
	})
	f.host(t, execadmin.Request{Cmd: execadmin.CmdFreezeOff})
	if err := f.ask(tok, f.code(t, u), writeCore); err != nil {
		t.Fatalf("the ticket was spent by a refusal before it: %v", err)
	}
}

/* fail5 makes 5 failed attempts of u, the last of which locks. */
func (f *fixture) fail5(t *testing.T, u user) authz.LockedError {
	t.Helper()
	for i := 0; i < authz.MaxFailures-1; i++ {
		if err := f.try(t, u, f.wrong(t, u)); err != authz.ErrDenied {
			t.Fatalf("failure %d: %v", i+1, err)
		}
	}
	var le *authz.LockedError
	if err := f.try(t, u, f.wrong(t, u)); !errors.As(err, &le) {
		t.Fatalf("5th failure: %v", err)
	}
	return *le
}

/* C3: 5 failures lock 15 min, the next lock in a row 30 min, the third only nmsctl executor unlock lifts. */
func TestC3LockGrowthAndUnlock(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	if le := f.fail5(t, u); le.Permanent || !le.Until.Equal(f.clk.Now().Add(15*time.Minute)) {
		t.Fatalf("first lock %+v", le)
	}
	/* While locked even the right code is refused, and not counted. */
	f.oneAudit(t, "denied", "locked", func() {
		if err := f.try(t, u, f.code(t, u)); !errors.Is(err, authz.ErrLocked) {
			t.Fatal(err)
		}
	})
	if got := f.row(t, u.id); got.lockCount != 1 || got.failures != 0 || got.lastStep != 0 {
		t.Fatalf("row %+v", got)
	}
	f.clk.Advance(15*time.Minute - time.Second)
	if err := f.try(t, u, f.code(t, u)); !errors.Is(err, authz.ErrLocked) {
		t.Fatalf("a second before the end: %v", err)
	}
	f.clk.Advance(time.Second)
	if le := f.fail5(t, u); le.Permanent || !le.Until.Equal(f.clk.Now().Add(30*time.Minute)) {
		t.Fatalf("second lock %+v", le)
	}
	f.clk.Advance(30 * time.Minute)
	if le := f.fail5(t, u); !le.Permanent {
		t.Fatalf("third lock %+v", le)
	}
	f.clk.Advance(48 * time.Hour)
	if err := f.try(t, u, f.code(t, u)); !errors.Is(err, authz.ErrLocked) {
		t.Fatalf("third lock lifted by time: %v", err)
	}
	/* A new process (restart) still sees the lock: it lives in the registry. */
	f.az = f.authorizer(t)
	if err := f.try(t, u, f.code(t, u)); !errors.Is(err, authz.ErrLocked) {
		t.Fatalf("after a restart: %v", err)
	}
	f.host(t, execadmin.Request{Cmd: execadmin.CmdUnlock, User: u.name})
	if err := f.try(t, u, f.code(t, u)); err != nil {
		t.Fatalf("after unlock: %v", err)
	}
}

/* A success between locks starts the count of locks in a row again. */
func TestC3SuccessResetsLocksInARow(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	f.fail5(t, u)
	f.clk.Advance(15 * time.Minute)
	f.fail5(t, u)
	f.clk.Advance(30 * time.Minute)
	if err := f.try(t, u, f.code(t, u)); err != nil {
		t.Fatal(err)
	}
	if got := f.row(t, u.id); got.lockCount != 0 || got.failures != 0 || got.lockUntil != nil {
		t.Fatalf("row %+v", got)
	}
	f.clk.Advance(30 * time.Second)
	if le := f.fail5(t, u); le.Permanent || !le.Until.Equal(f.clk.Now().Add(15*time.Minute)) {
		t.Fatalf("lock after a success %+v", le)
	}
}

/* The step used survives a restart: the same code is refused by a new process. */
func TestC3StepSurvivesRestart(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	code := f.code(t, u)
	if err := f.try(t, u, code); err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(6 * time.Second)
	f.az = f.authorizer(t)
	if err := f.try(t, u, code); err != authz.ErrDenied {
		t.Fatalf("replay after a restart: %v", err)
	}
}

/* C3 global: failures of 3 or more users over 20 within an hour freeze the executor (disaster); two users never do. */
func TestC3GlobalFreeze(t *testing.T) {
	f := newFixture(t)
	a, b := f.enrolled(t, "a"), f.enrolled(t, "b")
	for range 3 {
		f.fail5(t, a)
		f.fail5(t, b)
		f.clk.Advance(30*time.Minute + time.Second)
	}
	if frozen, _ := f.guard.Frozen(); frozen {
		t.Fatal("two users froze the executor")
	}
	f2 := newFixture(t)
	var us []user
	for i := range 5 {
		us = append(us, f2.enrolled(t, fmt.Sprintf("u%d-", i)))
	}
	n := 0
	for _, u := range us[:4] {
		f2.fail5(t, u)
		n += 5
	}
	if frozen, _ := f2.guard.Frozen(); frozen || n != 20 {
		t.Fatalf("frozen at %d failures", n)
	}
	if err := f2.try(t, us[4], f2.wrong(t, us[4])); err != authz.ErrDenied {
		t.Fatal(err)
	}
	if frozen, reason := f2.guard.Frozen(); !frozen {
		t.Fatal("21 failures of 5 users did not freeze")
	} else if reason == "" {
		t.Fatal("no reason")
	}
	if f2.alerts(t, freeze.KindBruteforce, "disaster") != 1 {
		t.Fatal("no disaster alert")
	}
	if err := f2.try(t, us[4], f2.code(t, us[4])); err != authz.ErrFrozen {
		t.Fatalf("after the freeze: %v", err)
	}
	/* The host clears the window and lifts the freeze: decisions are taken again. */
	f2.host(t, execadmin.Request{Cmd: execadmin.CmdUnlock, Global: true})
	f2.host(t, execadmin.Request{Cmd: execadmin.CmdFreezeOff})
	if err := f2.try(t, us[4], f2.code(t, us[4])); err != nil {
		t.Fatal(err)
	}
}

/*
The failure-recording write fails (not committed, as a superuser can make it
fail): the in-memory guards still count every failure and lock the user, and
a correct code whose use could not be recorded is refused and never accepted
later. Nothing that was evaluated is forgotten in this process.
*/
func TestFailClosedWhenRecordingFails(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	injected := errors.New("injected: lock_timeout")
	authz.SetAbortWrite(f.az, func() error { return injected })
	for i := 0; i < authz.MaxFailures; i++ {
		f.oneAudit(t, "denied", "wrong_code_unrecorded", func() {
			if err := f.try(t, u, f.wrong(t, u)); err != authz.ErrUnavailable {
				t.Fatalf("failure %d: %v", i+1, err)
			}
		})
	}
	if got := f.row(t, u.id); got.failures != 0 || got.lockCount != 0 {
		t.Fatalf("the injected failure committed: %+v", got)
	}
	/* Locked in memory although the registry knows nothing: the right code is refused. */
	authz.SetAbortWrite(f.az, nil)
	if err := f.try(t, u, f.code(t, u)); !errors.Is(err, authz.ErrLocked) {
		t.Fatalf("in-memory lock: %v", err)
	}
	/* The next write records the merged state: the lock reaches the registry. */
	f.clk.Advance(FirstLockPlus)
	authz.SetAbortWrite(f.az, func() error { return injected })
	code := f.code(t, u)
	if err := f.try(t, u, code); err != authz.ErrUnavailable {
		t.Fatalf("right code, unrecorded: %v", err)
	}
	authz.SetAbortWrite(f.az, nil)
	if err := f.try(t, u, code); err != authz.ErrDenied {
		t.Fatalf("a code whose use was not recorded was accepted later: %v", err)
	}
	if got := f.row(t, u.id); got.lockCount != 1 || got.failures != 1 {
		t.Fatalf("merged state not written: %+v", got)
	}
}

/* The write committed but reported an error (an ambiguous COMMIT): refused, and the step stays used. */
func TestFailClosedOnUnknownOutcome(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	authz.SetAfterWrite(f.az, func(err error) error {
		if err == nil {
			return errors.New("injected: commit outcome unknown")
		}
		return err
	})
	code := f.code(t, u)
	if err := f.try(t, u, code); err != authz.ErrUnavailable {
		t.Fatalf("unknown outcome: %v", err)
	}
	authz.SetAfterWrite(f.az, nil)
	if err := f.try(t, u, code); err != authz.ErrDenied {
		t.Fatalf("replay after an unknown outcome: %v", err)
	}
}

/* Global freeze from the in-memory window alone, when no failure reached the registry. */
func TestGlobalFreezeFromMemory(t *testing.T) {
	f := newFixture(t)
	var us []user
	for i := range 5 {
		us = append(us, f.enrolled(t, fmt.Sprintf("m%d-", i)))
	}
	authz.SetAbortWrite(f.az, func() error { return errors.New("injected") })
	for i := range 21 {
		u := us[i%5]
		if err := f.try(t, u, f.wrong(t, u)); err != authz.ErrUnavailable && err != authz.ErrFrozen {
			t.Fatalf("failure %d: %v", i+1, err)
		}
	}
	if frozen, _ := f.guard.Frozen(); !frozen {
		t.Fatal("not frozen")
	}
	if f.alerts(t, freeze.KindBruteforce, "disaster") != 1 {
		t.Fatal("no disaster alert")
	}
}

/*
A lock held on the registry (a superuser's open transaction) makes the
decision's write fail before any code is looked at: refused, nothing counted,
nothing consumed; the same code works once the lock is gone.
*/
func TestLockHeldRefusesWithoutEvaluating(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	ctx := context.Background()
	tx, err := f.env.Pool("postgres").Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `LOCK TABLE exec.change_totp IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	code := f.code(t, u)
	err = f.try(t, u, code)
	_ = tx.Rollback(ctx)
	if err != authz.ErrUnavailable {
		t.Fatalf("lock held: %v", err)
	}
	if err := f.try(t, u, code); err != nil {
		t.Fatalf("after the lock: %v", err)
	}
}

/* Re-enrollment and unlock reset the in-memory guards too (the host's word), but never a used step. */
func TestHostResetsInMemoryGuards(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	authz.SetAbortWrite(f.az, func() error { return errors.New("injected") })
	for range authz.MaxFailures {
		_ = f.try(t, u, f.wrong(t, u))
	}
	authz.SetAbortWrite(f.az, nil)
	if err := f.try(t, u, f.code(t, u)); !errors.Is(err, authz.ErrLocked) {
		t.Fatalf("in-memory lock: %v", err)
	}
	u.secret = f.host(t, execadmin.Request{Cmd: execadmin.CmdEnroll, User: u.name, Replace: true}).Enrollment.Secret
	if err := f.try(t, u, f.code(t, u)); err != nil {
		t.Fatalf("after re-enroll: %v", err)
	}
	if err := f.try(t, u, f.code(t, u)); err != authz.ErrDenied {
		t.Fatalf("the step used before is used: %v", err)
	}
}

/* Uniform refusals: every per-user reason is the same error value. */
func TestRefusalsAreUniform(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	plain := f.panelUser(t, "plain")
	ghost := user{id: plain.id + 100000, name: "ghost"}
	for _, err := range []error{
		f.try(t, ghost, "123456"),
		f.try(t, plain, "123456"),
		f.ask(f.ticketFor(t, u), f.code(t, u), authz.Need{Kind: "unmask"}),
		f.try(t, u, f.wrong(t, u)),
		f.ask("garbage", f.code(t, u), writeCore),
	} {
		if err != authz.ErrDenied || err.Error() != authz.ErrDenied.Error() {
			t.Fatalf("refusal %v is not the uniform ErrDenied", err)
		}
	}
}

/*
Identify (the gate of a confirmation challenge) checks policy, freeze,
ticket and core.user like Authorize, spends the ticket's nonce, writes one
audit row, and never looks at a code or touches the user's TOTP state.
*/
func TestIdentifyTicketOnly(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	tok := f.ticketFor(t, u)
	ident := func(tok string, user int64) (authz.Decision, error) {
		return f.az.Identify(context.Background(), authz.Request{Ticket: tok, Code: "000000", Need: authz.Need{Kind: "unmask"},
			Action: "confirm.issue", Object: "x", User: user, IP: "192.0.2.1", UA: "tester"})
	}
	before := f.row(t, u.id)
	f.oneAudit(t, "ok", "identified", func() {
		if d, err := ident(tok, 0); err != nil || d.UserID != u.id || d.Username != u.name {
			t.Fatalf("%+v %v", d, err)
		}
	})
	if got := f.row(t, u.id); got != before {
		t.Fatalf("Identify changed the TOTP row: %+v -> %+v", before, got)
	}
	f.oneAudit(t, "denied", "ticket_replayed", func() {
		if _, err := ident(tok, 0); err != authz.ErrDenied {
			t.Fatal(err)
		}
	})
	f.oneAudit(t, "denied", "wrong_user", func() {
		if _, err := ident(f.ticketFor(t, u), u.id+1); err != authz.ErrDenied {
			t.Fatal(err)
		}
	})
	ghost := user{id: 990001, name: "ghost"}
	f.oneAudit(t, "denied", "unknown_user", func() {
		if _, err := ident(f.ticketFor(t, ghost), 0); err != authz.ErrDenied {
			t.Fatal(err)
		}
	})
	f.oneAudit(t, "denied", "ticket_signature", func() {
		forged, _, _ := ticket.Issue(otherPriv, u.id, u.name, f.clk.Now())
		if _, err := ident(forged, 0); err != authz.ErrDenied {
			t.Fatal(err)
		}
	})
	f.setPolicy(t, "enabled: false\n")
	f.oneAudit(t, "denied", "disabled", func() {
		if _, err := ident(f.ticketFor(t, u), 0); err != authz.ErrDisabled {
			t.Fatal(err)
		}
	})
	f.setPolicy(t, "enabled: true\n")
	f.host(t, execadmin.Request{Cmd: execadmin.CmdFreezeOn, Reason: "drill"})
	f.oneAudit(t, "denied", "frozen", func() {
		if _, err := ident(f.ticketFor(t, u), 0); err != authz.ErrFrozen {
			t.Fatal(err)
		}
	})
}

/* TicketUser reads a ticket that verifies without spending it; a forged or expired one gives no user. */
func TestTicketUserSpendsNothing(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	tok := f.ticketFor(t, u)
	before := f.lastAuditID(t)
	if id, ok := f.az.TicketUser(tok); !ok || id != u.id {
		t.Fatalf("TicketUser = %d %v", id, ok)
	}
	if f.lastAuditID(t) != before {
		t.Fatal("TicketUser wrote an audit row")
	}
	forged, _, _ := ticket.Issue(otherPriv, u.id, u.name, f.clk.Now())
	if _, ok := f.az.TicketUser(forged); ok {
		t.Fatal("a forged ticket gave a user")
	}
	if err := f.ask(tok, f.code(t, u), writeCore); err != nil {
		t.Fatalf("the nonce was spent: %v", err)
	}
	old := f.ticketFor(t, u)
	f.clk.Advance(2 * time.Minute)
	if _, ok := f.az.TicketUser(old); ok {
		t.Fatal("an expired ticket gave a user")
	}
}

/* Identify accepts nobody whose accepting audit row cannot be written (a superuser's lock blocks the append). */
func TestIdentifyFailsClosedWithoutAudit(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	ctx := context.Background()
	tx, err := f.env.Pool("postgres").Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `LOCK TABLE exec.audit_event IN SHARE MODE`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.az.Identify(ctx, authz.Request{Ticket: f.ticketFor(t, u), Action: "confirm.issue", Object: "x"}); err != authz.ErrUnavailable {
		t.Fatalf("Identify without its audit row: %v", err)
	}
}
