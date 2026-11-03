package attacktest_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
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
)

func TestMain(m *testing.M) { testdb.Main(m) }

/* stack is one enabled executor over the test database (registry, freeze guard, authz, host administration) and the api attacking it. */
type stack struct {
	env *testdb.Env
	az  *authz.Authorizer
	adm *admin.Admin
	api *attacktest.Attacker
	log *bytes.Buffer /* everything the executor logged */
}

func newStack(t *testing.T) *stack {
	t.Helper()
	env := testdb.New(t)
	attacktest.Reset(t, env)
	ctx := context.Background()
	keys, err := seal.Derive(&[32]byte{4, 9})
	if err != nil {
		t.Fatal(err)
	}
	db, pw := env.Config("nms_executor")
	pool, err := store.Open(ctx, db, pw, registry.PinSession, registry.BoundMessages)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	var out bytes.Buffer
	log := slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug}))
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
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	az, err := authz.New(authz.Config{Guard: guard, Reg: reg, Keys: keys, Policy: pol, Log: log,
		TicketKey: key.Public().(ed25519.PublicKey), Started: time.Now(), GuardsFile: filepath.Join(dir, "guards")})
	if err != nil {
		t.Fatal(err)
	}
	return &stack{env: env, az: az, adm: &admin.Admin{Guard: guard, Reg: reg, Keys: keys, Policy: pol, Log: log, Lockouts: az},
		api: attacktest.NewAttacker(env, key), log: &out}
}

/* host runs an nmsctl executor command, confirming the user binding as nmsctl does. */
func (s *stack) host(t *testing.T, req execadmin.Request) execadmin.Response {
	t.Helper()
	req.V, req.Operator = execadmin.Version, "tester"
	resp := s.adm.Handle(context.Background(), req)
	if resp.OK && resp.Confirm != nil {
		req.User, req.UserID, req.UserCreated = resp.Confirm.Username, resp.Confirm.ID, resp.Confirm.CreatedAt
		resp = s.adm.Handle(context.Background(), req)
	}
	if !resp.OK {
		t.Fatalf("%s: %s", req.Cmd, resp.Error)
	}
	return resp
}

/* enrolled creates a panel user (as the api would), enrolls its change TOTP and grants write-admin; it returns id, name and secret. */
func (s *stack) enrolled(t *testing.T, name string) (int64, string, string) {
	t.Helper()
	name = fmt.Sprintf("%s-%d", name, time.Now().UnixNano()%1e9)
	var id int64
	if err := s.env.Pool("postgres").QueryRow(context.Background(),
		`INSERT INTO core."user" (username, password_phc) VALUES ($1, 'x') RETURNING id`, name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	sec := s.host(t, execadmin.Request{Cmd: execadmin.CmdEnroll, User: name}).Enrollment.Secret
	s.host(t, execadmin.Request{Cmd: execadmin.CmdGrant, User: name, Kind: "write-admin"})
	return id, name, sec
}

/*
Review Focus 4a (2), "learn a TOTP secret": with the ticket key and its role
the api drives the victim's change TOTP through every path it can reach (a
wrong code, the right one, a replay, a code for a grant the victim lacks),
and the secret is then in no form (base32 in either case, the raw bytes in
hex or base64) in any row of any table of the database — read as the
superuser, so exec's own tables and audit rows count too — nor in the
executor's logs. The api cannot read exec at all.
*/
func TestAPICannotLearnTheChangeTOTPSecret(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	id, name, sec := s.enrolled(t, "victim")
	code, err := totp.GenerateCodeCustom(sec, time.Now(), totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	wrong := code[:5] + string(rune('0'+(code[5]-'0'+1)%10))
	ask := func(c string, need authz.Need) error {
		_, err := s.az.Authorize(ctx, authz.Request{Ticket: s.api.Ticket(t, id, name), Code: c, Need: need, Action: "attack.probe", Object: "secret"})
		return err
	}
	granted := authz.Need{Kind: "write-admin"}
	if err := ask(wrong, granted); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("wrong code: %v", err)
	}
	if err := ask(code, granted); err != nil {
		t.Fatalf("the victim's code: %v", err)
	}
	if err := ask(code, granted); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("replayed code: %v", err)
	}
	if err := ask(code, authz.Need{Kind: "unmask"}); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("grant the victim lacks: %v", err)
	}

	var pgErr *pgconn.PgError
	if err := s.api.Exec(ctx, `SELECT ciphertext FROM exec.change_totp`); !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("the api read exec.change_totp: %v", err)
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(sec))
	if err != nil || len(raw) < 10 {
		t.Fatalf("secret %d bytes: %v", len(raw), err)
	}
	needles := []string{strings.ToUpper(sec), strings.ToLower(sec), hex.EncodeToString(raw), base64.StdEncoding.EncodeToString(raw),
		base64.RawStdEncoding.EncodeToString(raw), base64.RawURLEncoding.EncodeToString(raw)}
	found := func(where, text string) {
		t.Helper()
		lower := strings.ToLower(text)
		for _, n := range needles {
			if strings.Contains(text, n) || strings.Contains(lower, strings.ToLower(n)) {
				t.Errorf("the change TOTP secret is in %s", where)
			}
		}
	}
	found("the executor's log", s.log.String())
	su := s.env.Pool("postgres")
	rows, err := su.Query(ctx, `SELECT format('%I.%I', n.nspname, c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind IN ('r', 'p', 'm') AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_%'`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var tbl string
		if err := rows.Scan(&tbl); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, tbl)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	scanned := map[string]bool{}
	for _, tbl := range tables {
		var text string
		if err := su.QueryRow(ctx, `SELECT coalesce(string_agg(t::text, E'\n'), '') FROM `+tbl+` t`).Scan(&text); err != nil {
			t.Fatalf("%s: %v", tbl, err)
		}
		scanned[tbl] = true
		found(tbl, text)
	}
	for _, must := range []string{"exec.change_totp", "exec.audit_event", "execpub.alert", "audit.event", "core.\"user\""} {
		if !scanned[must] {
			t.Fatalf("%s not scanned (%d tables): the scan proves nothing", must, len(tables))
		}
	}
	if s.count(t, `SELECT count(*) FROM exec.audit_event WHERE action = 'attack.probe'`) != 4 {
		t.Fatal("the probes left no audit rows to scan")
	}
}

func (s *stack) count(t *testing.T, sql string) int {
	t.Helper()
	var n int
	if err := s.env.Pool("postgres").QueryRow(context.Background(), sql).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
