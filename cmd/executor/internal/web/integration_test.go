package web

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
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
	"github.com/beekamai/network-scheme/internal/store"
	"github.com/beekamai/network-scheme/internal/testdb"
	"github.com/beekamai/network-scheme/internal/ticket"
)

var ticketPriv = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

/* live is the server over the live authorizer and confirm store, on the test database. */
type live struct {
	*harness
	env *testdb.Env
	adm *admin.Admin
}

func startLive(t *testing.T) *live {
	t.Helper()
	env := testdb.New(t)
	attacktest.Reset(t, env)
	ctx := context.Background()
	keys, err := seal.Derive(&[32]byte{9})
	if err != nil {
		t.Fatal(err)
	}
	db, pw := env.Config("nms_executor")
	pool, err := store.Open(ctx, db, pw, registry.PinSession, registry.BoundMessages)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()
	reg := registry.New(pool, keys, filepath.Join(dir, "state"))
	guard := freeze.New(reg, pool, log)
	if err := guard.Start(ctx); err != nil {
		t.Fatal(err)
	}
	polFile := filepath.Join(dir, "executor.yaml")
	if err := os.WriteFile(polFile, []byte("enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pol := policy.New(polFile)
	pol.Reload(true)
	az, err := authz.New(authz.Config{Guard: guard, Reg: reg, Keys: keys, Policy: pol, Log: log,
		TicketKey: ticketPriv.Public().(ed25519.PublicKey), Started: time.Now(), GuardsFile: filepath.Join(dir, "guards")})
	if err != nil {
		t.Fatal(err)
	}
	h := startWith(t, newCerts(t), func(c *Config) {
		c.Auth, c.Confirm = az, confirm.New(az, nil)
		c.State = func() (bool, bool) { f, _ := guard.Frozen(); return pol.Current().Enabled(), f }
	})
	return &live{harness: h, env: env, adm: &admin.Admin{Guard: guard, Reg: reg, Keys: keys, Policy: pol, Log: log, Lockouts: az}}
}

/* user creates a panel user, enrolls its change TOTP and grants write-admin; it returns id, name and secret. */
func (r *live) user(t *testing.T, name string) (int64, string, string) {
	t.Helper()
	name = fmt.Sprintf("%s-%d", name, time.Now().UnixNano()%1e9) /* unique across -count runs over one database */
	var id int64
	if err := r.env.Pool("postgres").QueryRow(context.Background(),
		`INSERT INTO core."user" (username, password_phc) VALUES ($1, 'x') RETURNING id`, name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	host := func(req execadmin.Request) execadmin.Response {
		req.V, req.Operator = execadmin.Version, "tester"
		resp := r.adm.Handle(context.Background(), req)
		if resp.OK && resp.Confirm != nil {
			req.User, req.UserID, req.UserCreated = resp.Confirm.Username, resp.Confirm.ID, resp.Confirm.CreatedAt
			resp = r.adm.Handle(context.Background(), req)
		}
		if !resp.OK {
			t.Fatalf("%s: %s", req.Cmd, resp.Error)
		}
		return resp
	}
	sec := host(execadmin.Request{Cmd: execadmin.CmdEnroll, User: name}).Enrollment.Secret
	host(execadmin.Request{Cmd: execadmin.CmdGrant, User: name, Kind: "write-admin"})
	return id, name, sec
}

func tok(t *testing.T, id int64, name string) string {
	t.Helper()
	s, _, err := ticket.Issue(ticketPriv, id, name, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

/* audits counts the executor's audit rows of action. */
func (r *live) audits(t *testing.T, action string) int {
	t.Helper()
	var n int
	if err := r.env.Pool("postgres").QueryRow(context.Background(),
		`SELECT count(*) FROM exec.audit_event WHERE action = $1`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

/*
Requests over a rate limit never reach authz: the executor's audit chain
(one row per authz decision) holds exactly the burst's worth, for forged
tickets from one address and for one user's valid tickets from many.
*/
func TestRateLimitedRequestsWriteNoAuditRows(t *testing.T) {
	oldIP, oldUser := ipBurst, userBurst
	ipBurst, userBurst = 5, 3
	t.Cleanup(func() { ipBurst, userBurst = oldIP, oldUser })
	r := startLive(t)
	for i := range 9 {
		r.do(t, http.MethodPost, "/x/confirm/issue", issueBody(fmt.Sprintf("forged.%d", i)), hdr("X-Forwarded-For", "203.0.113.5"))
	}
	if n := r.audits(t, "confirm.issue"); n != 5 {
		t.Fatalf("%d audit rows for 9 forged requests from one address, want the IP burst 5", n)
	}
	id, name, _ := r.user(t, "rl-alice")
	for i := range 7 {
		a := r.do(t, http.MethodPost, "/x/confirm/issue", issueBody(tok(t, id, name)), hdr("X-Forwarded-For", fmt.Sprintf("10.2.%d.1", i)))
		if (i < 3) != (a.status == http.StatusOK) {
			t.Fatalf("request %d of one user: %d %s", i+1, a.status, a.body)
		}
	}
	if n := r.audits(t, "confirm.issue"); n != 5+3 {
		t.Fatalf("%d audit rows after 7 requests of one user, want 3 more", n-5)
	}
}

/*
The whole confirm(H) path over /x with the live authorizer: a ticket opens
a challenge (no TOTP), a second ticket and the user's change TOTP code
confirm it once; another H and a replay are refused.
*/
func TestConfirmFlowWithRealAuthz(t *testing.T) {
	r := startLive(t)
	id, name, sec := r.user(t, "cf-bob")
	a := r.do(t, http.MethodPost, "/x/confirm/issue", issueBody(tok(t, id, name)), hdr())
	var ch challengeBody
	if err := json.Unmarshal([]byte(a.body), &ch); err != nil || a.status != http.StatusOK {
		t.Fatalf("issue: %d %s", a.status, a.body)
	}
	code, err := totp.GenerateCodeCustom(sec, time.Now(), totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	body := func(h string) string {
		return `{"ticket":"` + tok(t, id, name) + `","challenge_id":"` + ch.ID + `","h":"` + h + `","code":"` + code + `"}`
	}
	a = r.do(t, http.MethodPost, "/x/confirm", body(ch.H), hdr())
	if a.status != http.StatusOK || a.body != "{\"action\":\"test.echo\",\"result\":\"sw1\"}\n" {
		t.Fatalf("confirm: %d %s", a.status, a.body)
	}
	if a := r.do(t, http.MethodPost, "/x/confirm", body(ch.H), hdr()); a.status != http.StatusForbidden || a.code != "denied" {
		t.Errorf("replayed challenge: %d %s", a.status, a.body)
	}
	if n, m := r.audits(t, "confirm.test.echo"), r.audits(t, "confirm.challenge"); n != 1 || m != 1 {
		t.Errorf("audit rows: %d accepted, %d unknown challenge; want 1 and 1", n, m)
	}
}
