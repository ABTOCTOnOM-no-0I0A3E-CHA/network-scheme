package confirm_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/beekamai/network-scheme/cmd/executor/internal/admin"
	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/confirm"
	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/cmd/executor/internal/policy"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/internal/execadmin"
	"github.com/beekamai/network-scheme/internal/testdb"
	"github.com/beekamai/network-scheme/internal/ticket"
)

func TestMain(m *testing.M) { testdb.Main(m) }

var (
	ticketPriv = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	seq        atomic.Int64
	writeCore  = authz.Need{Kind: "write", Groups: []string{"core"}}
	hostkey    = confirm.Description{Action: "hostkey.accept", Fields: []confirm.Field{
		{Key: "address", Value: "192.0.2.7"}, {Key: "device", Value: "12"}, {Key: "fingerprint", Value: "SHA256:abc"}}}
)

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

type fixture struct {
	env   *testdb.Env
	adm   *admin.Admin
	store *confirm.Store
	clk   *clock
}

type user struct {
	id           int64
	name, secret string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	env := testdb.New(t)
	attacktest.Reset(t, env)
	k, err := seal.Derive(&[32]byte{5})
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := registry.New(env.Pool("nms_executor"), k, filepath.Join(t.TempDir(), "state"))
	guard := freeze.New(reg, env.Pool("nms_executor"), log)
	if err := guard.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	pfile := filepath.Join(t.TempDir(), "executor.yaml")
	if err := os.WriteFile(pfile, []byte("enabled: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pol := policy.New(pfile)
	pol.Reload(true)
	clk := &clock{t: time.Now().UTC().Truncate(time.Second)}
	az, err := authz.New(authz.Config{Guard: guard, Reg: reg, Keys: k, Policy: pol, Log: log,
		TicketKey: ticketPriv.Public().(ed25519.PublicKey), Started: clk.Now(), Now: clk.Now, GuardsFile: filepath.Join(t.TempDir(), "guards")})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{env: env, clk: clk, store: confirm.New(az, clk.Now),
		adm: &admin.Admin{Guard: guard, Reg: reg, Keys: k, Policy: pol, Log: log, Lockouts: az}}
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

func (f *fixture) enrolled(t *testing.T, prefix string) user {
	t.Helper()
	u := user{name: fmt.Sprintf("%s%d", prefix, seq.Add(1))}
	if err := f.env.Pool("postgres").QueryRow(context.Background(),
		`INSERT INTO core."user" (username, password_phc) VALUES ($1, 'x') RETURNING id`, u.name).Scan(&u.id); err != nil {
		t.Fatal(err)
	}
	u.secret = f.host(t, execadmin.Request{Cmd: execadmin.CmdEnroll, User: u.name}).Enrollment.Secret
	f.host(t, execadmin.Request{Cmd: execadmin.CmdGrant, User: u.name, Kind: "write", Group: "core"})
	return u
}

/* req is a confirmation request of u: a fresh ticket and the current code. */
func (f *fixture) req(t *testing.T, u user) authz.Request {
	t.Helper()
	tok, _, err := ticket.Issue(ticketPriv, u.id, u.name, f.clk.Now())
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCodeCustom(u.secret, f.clk.Now(), totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return authz.Request{Ticket: tok, Code: code, IP: "192.0.2.1", UA: "tester"}
}

func (f *fixture) issue(t *testing.T, u user, need authz.Need, d confirm.Description) confirm.Challenge {
	t.Helper()
	c, err := f.store.Issue(u.id, need, d)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type auditRow struct {
	action, result string
	userID         *int64
	details        map[string]any
}

func (f *fixture) lastAudit(t *testing.T) auditRow {
	t.Helper()
	var r auditRow
	var payload []byte
	if err := f.env.Pool("postgres").QueryRow(context.Background(),
		`SELECT action, result, user_id, payload FROM exec.audit_event ORDER BY id DESC LIMIT 1`).Scan(&r.action, &r.result, &r.userID, &payload); err != nil {
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

func (f *fixture) failures(t *testing.T, id int64) int64 {
	t.Helper()
	var n int64
	if err := f.env.Pool("postgres").QueryRow(context.Background(), `SELECT failures FROM exec.change_totp WHERE user_id = $1`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

/* The challenge carries H of its description; the same H, ticket and code confirm it once, audited with challenge and H. */
func TestConfirmOnce(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	c := f.issue(t, u, writeCore, hostkey)
	if h, _ := hostkey.Hash(); c.H != h || c.Action != "hostkey.accept" || c.User != u.id || !c.Expires.Equal(f.clk.Now().Add(confirm.TTL)) || len(c.ID) != 22 {
		t.Fatalf("challenge %+v", c)
	}
	got, dec, err := f.store.Confirm(context.Background(), c.ID, c.H[:], f.req(t, u))
	if err != nil || dec.UserID != u.id || got.ID != c.ID {
		t.Fatalf("confirm: %+v %+v %v", got, dec, err)
	}
	r := f.lastAudit(t)
	if r.action != "confirm.hostkey.accept" || r.result != "ok" || *r.userID != u.id || r.details["challenge"] != c.ID ||
		r.details["h"] != hex.EncodeToString(c.H[:]) || r.details["class"] != "accepted" {
		t.Fatalf("audit %+v", r)
	}
	/* One-time: the same challenge again (next step's code, fresh ticket) is unknown. */
	f.clk.Advance(30 * time.Second)
	if _, _, err := f.store.Confirm(context.Background(), c.ID, c.H[:], f.req(t, u)); err != authz.ErrDenied {
		t.Fatalf("second use: %v", err)
	}
	if r := f.lastAudit(t); r.details["class"] != "unknown_challenge" || r.result != "denied" {
		t.Fatalf("audit %+v", r)
	}
}

/*
C2k (primitive): the description changed after it was shown (another
address, another field order, one more field) gives another H; the
challenge refuses it and is spent, so the original H no longer works
either. No code was evaluated and the ticket was not spent.
*/
func TestC2kChangedDescription(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	changed := []confirm.Description{
		{Action: hostkey.Action, Fields: []confirm.Field{{Key: "address", Value: "198.51.100.7"}, hostkey.Fields[1], hostkey.Fields[2]}},
		{Action: "hostkey.accepted", Fields: hostkey.Fields},
		{Action: hostkey.Action, Fields: append(append([]confirm.Field(nil), hostkey.Fields...), confirm.Field{Key: "port", Value: "22"})},
		{Action: hostkey.Action, Fields: hostkey.Fields[:2]},
	}
	for _, d := range changed {
		c := f.issue(t, u, writeCore, hostkey)
		h, err := d.Hash()
		if err != nil {
			t.Fatal(err)
		}
		req := f.req(t, u)
		if _, _, err := f.store.Confirm(context.Background(), c.ID, h[:], req); err != authz.ErrDenied {
			t.Fatalf("%+v: %v", d, err)
		}
		if r := f.lastAudit(t); r.details["class"] != "h_mismatch" || *r.userID != u.id || r.action != "confirm.hostkey.accept" {
			t.Fatalf("audit %+v", r)
		}
		if _, _, err := f.store.Confirm(context.Background(), c.ID, c.H[:], req); err != authz.ErrDenied {
			t.Fatalf("the spent challenge with its own H: %v", err)
		}
		/* The ticket and the code were never looked at: they confirm a fresh challenge. */
		c2 := f.issue(t, u, writeCore, hostkey)
		if _, _, err := f.store.Confirm(context.Background(), c2.ID, c2.H[:], req); err != nil {
			t.Fatalf("fresh challenge: %v", err)
		}
		f.clk.Advance(30 * time.Second)
	}
	if n := f.failures(t, u.id); n != 0 {
		t.Fatalf("%d TOTP failures from H mismatches", n)
	}
	/* H of another length, or none. */
	for _, h := range [][]byte{nil, {1, 2}, make([]byte, 33)} {
		c := f.issue(t, u, writeCore, hostkey)
		if _, _, err := f.store.Confirm(context.Background(), c.ID, h, f.req(t, u)); err != authz.ErrDenied {
			t.Fatalf("H %x: %v", h, err)
		}
	}
}

/* A challenge lives 2 minutes. */
func TestChallengeExpires(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	c := f.issue(t, u, writeCore, hostkey)
	f.clk.Advance(confirm.TTL)
	if _, _, err := f.store.Confirm(context.Background(), c.ID, c.H[:], f.req(t, u)); err != authz.ErrDenied {
		t.Fatalf("expired: %v", err)
	}
	if r := f.lastAudit(t); r.details["class"] != "challenge_expired" {
		t.Fatalf("audit %+v", r)
	}
}

/* The challenge decides the user and the grant: another user's ticket, or a request naming another grant, change nothing. */
func TestChallengeBindsUserAndGrant(t *testing.T) {
	f := newFixture(t)
	alice, bob := f.enrolled(t, "alice"), f.enrolled(t, "bob")
	c := f.issue(t, alice, writeCore, hostkey)
	if _, _, err := f.store.Confirm(context.Background(), c.ID, c.H[:], f.req(t, bob)); err != authz.ErrDenied {
		t.Fatalf("bob confirms alice's challenge: %v", err)
	}
	if r := f.lastAudit(t); r.details["class"] != "wrong_user" {
		t.Fatalf("audit %+v", r)
	}
	/* The action needs unmask, which alice lacks: a request claiming write does not help. */
	c = f.issue(t, alice, authz.Need{Kind: "unmask"}, hostkey)
	req := f.req(t, alice)
	req.Need = writeCore
	if _, _, err := f.store.Confirm(context.Background(), c.ID, c.H[:], req); err != authz.ErrDenied {
		t.Fatalf("grant from the request: %v", err)
	}
	if r := f.lastAudit(t); r.details["class"] != "no_grant" {
		t.Fatalf("audit %+v", r)
	}
	if _, err := f.store.Issue(alice.id, authz.Need{Kind: "write"}, hostkey); err == nil {
		t.Fatal("a challenge without a valid grant was issued")
	}
	if _, err := f.store.Issue(alice.id, writeCore, confirm.Description{Action: "x", Fields: []confirm.Field{{Key: "b"}, {Key: "a"}}}); err == nil {
		t.Fatal("a non-canonical description was issued")
	}
}

/* At most 16 pending challenges per user: issuing more is refused until some are spent or expire. */
func TestPendingLimit(t *testing.T) {
	f := newFixture(t)
	alice, bob := f.enrolled(t, "alice"), f.enrolled(t, "bob")
	for range 16 {
		f.issue(t, alice, writeCore, hostkey)
	}
	if _, err := f.store.Issue(alice.id, writeCore, hostkey); !errors.Is(err, confirm.ErrTooMany) {
		t.Fatalf("17th: %v", err)
	}
	f.issue(t, bob, writeCore, hostkey)
	f.clk.Advance(confirm.TTL)
	f.issue(t, alice, writeCore, hostkey)
}
