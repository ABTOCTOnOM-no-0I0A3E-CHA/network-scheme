package attacktest_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/nacl/box"

	"github.com/beekamai/network-scheme/cmd/executor/internal/admin"
	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/confirm"
	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/cmd/executor/internal/policy"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/wcreds"
	"github.com/beekamai/network-scheme/cmd/executor/internal/web"
	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/creds/credstest"
	"github.com/beekamai/network-scheme/internal/devices"
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
	s.scan(t, "the change TOTP secret", needles, "exec.change_totp")
	if s.count(t, `SELECT count(*) FROM exec.audit_event WHERE action = 'attack.probe'`) != 4 {
		t.Fatal("the probes left no audit rows to scan")
	}
}

/*
scan fails the test if any needle (case-insensitive) is in the executor's
log or in any row of any table of the database, read as the superuser, so
exec's own tables and audit rows count too; must lists tables that have to
be among those scanned (beyond the audit and user tables).
*/
func (s *stack) scan(t *testing.T, what string, needles []string, must ...string) {
	t.Helper()
	ctx := context.Background()
	found := func(where, text string) {
		t.Helper()
		lower := strings.ToLower(text)
		for _, n := range needles {
			if strings.Contains(text, n) || strings.Contains(lower, strings.ToLower(n)) {
				t.Errorf("%s is in %s", what, where)
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
	for _, m := range append(must, "exec.audit_event", "execpub.alert", "audit.event", "core.\"user\"") {
		if !scanned[m] {
			t.Fatalf("%s not scanned (%d tables): the scan proves nothing", m, len(tables))
		}
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

/*
Task 4b.4: a write credential with a known password goes through the whole
/x path over HTTP (web.Server with the live authorizer and confirm store:
issue, then the write-admin's change TOTP and confirm), next to refused
submissions carrying the same password (weak, sealed for another device).
The password is then in no form in any row of any table (the superuser's
view: whatever the api or the poller can read is a subset), in the
executor's log (authz, wcreds and web log to it) or in any HTTP answer; the
api and the poller cannot read exec.write_credential.
*/
func TestAPICannotLearnTheWriteCredential(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	const pw = "Kn0wn-Write-Pass-4b4"
	type writeAdmin struct {
		id        int64
		name, sec string
	}
	var admins []writeAdmin /* one write-admin per submission: a TOTP step is accepted once per user */
	for range 3 {
		id, name, sec := s.enrolled(t, "wadmin")
		admins = append(admins, writeAdmin{id, name, sec})
	}
	if err := s.adm.Reg.Write(ctx, func(_ context.Context, _ *registry.Snapshot, tx *registry.Tx) error {
		for d := int64(1); d <= 2; d++ {
			if err := tx.Put("write_device", map[string]any{"device_id": d, "address": netip.AddrFrom4([4]byte{10, 8, 0, byte(d)}), "port": 22,
				"protocol": "ssh", "write_group": "core", "write_driver": "esr", "hostkey_algo": nil, "hostkey_fp": nil,
				"allow_ssh_rsa_sha1": false, "writes_enabled": false, "backup_via_executor": false}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	wpub, wpriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wc := &wcreds.Store{Gate: s.adm.Guard, Priv: wpriv, Pub: wpub, Record: s.az.Record, Log: s.adm.Log}
	const origin = "https://nms.example.test:8443"
	cert, key := selfSigned(t)
	srv, err := web.New(web.Config{CertFile: cert, KeyFile: key, ClientCAFile: cert, ExecutorOrigin: origin,
		PanelOrigin: "https://nms.example.test", Auth: s.az, Confirm: confirm.New(s.az, nil), Log: s.adm.Log,
		Actions: map[string]web.Action{wcreds.Action: {Describe: wc.Describe, Run: wc.Run}},
		State:   func() (bool, bool) { return true, false }})
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(srv)
	t.Cleanup(hs.Close)
	var answers strings.Builder
	post := func(path string, body any) (int, map[string]any) {
		t.Helper()
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, hs.URL+path, bytes.NewReader(b))
		req.Host = "nms.example.test:8443"
		req.Header.Set("Origin", origin)
		req.Header.Set("X-Forwarded-For", "192.0.2.44")
		req.Header.Set("Content-Type", "application/json")
		resp, err := hs.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		answers.Write(raw)
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		return resp.StatusCode, out
	}
	at := time.Now().UTC().Truncate(time.Second)
	sealed := func(owner int64, pass string) string {
		return base64.StdEncoding.EncodeToString(credstest.Seal(wpub, devices.Owner{Kind: devices.OwnerDevice, ID: owner}, creds.KindSSHWrite,
			map[string]string{"username": "netadmin", "password": pass}, at))
	}
	code := func(sec string) string {
		c, err := totp.GenerateCodeCustom(sec, time.Now(), totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	/* each submission: issue, then confirm with the code; the refused ones are refused only after the code */
	n := 0
	submit := func(device int64, ct string) (int, map[string]any) {
		u := admins[n]
		n++
		st, ch := post("/x/confirm/issue", map[string]any{"ticket": s.api.Ticket(t, u.id, u.name), "action": wcreds.Action,
			"params": map[string]any{"device_id": device, "ciphertext": ct}})
		if st != http.StatusOK {
			t.Fatalf("issue: %d %v", st, ch)
		}
		for _, f := range ch["fields"].([]any) {
			if k := f.(map[string]any)["key"]; k != "address" && k != "ciphertext" && k != "device_id" && k != "write_key" {
				t.Fatalf("the challenge shows %v before the code", k)
			}
		}
		return post("/x/confirm", map[string]any{"ticket": s.api.Ticket(t, u.id, u.name), "challenge_id": ch["challenge_id"], "h": ch["h"],
			"code": code(u.sec)})
	}
	if st, out := submit(2, sealed(1, pw)); st != http.StatusUnprocessableEntity || out["error"].(map[string]any)["code"] != "mismatch" {
		t.Fatalf("another device: %d %v", st, out)
	}
	if st, out := submit(1, sealed(1, pw[:11])); st != http.StatusUnprocessableEntity || out["error"].(map[string]any)["code"] != "weak" {
		t.Fatalf("weak: %d %v", st, out)
	}
	if st, out := submit(1, sealed(1, pw)); st != http.StatusOK {
		t.Fatalf("store: %d %v", st, out)
	}
	if s.count(t, `SELECT count(*) FROM exec.write_credential WHERE device_id = 1`) != 1 ||
		s.count(t, `SELECT count(*) FROM exec.audit_event WHERE action = 'confirm.credential.set'`) != 3 ||
		s.count(t, `SELECT count(*) FROM exec.audit_event WHERE action = 'credential.set'`) != 3 {
		t.Fatal("the credential or its audit rows are missing: the scan proves nothing")
	}
	var pgErr *pgconn.PgError
	for _, role := range []string{"nms_api", "nms_poller"} {
		if _, err := s.env.Pool(role).Exec(ctx, `SELECT ciphertext FROM exec.write_credential`); !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Fatalf("%s read exec.write_credential: %v", role, err)
		}
	}
	raw := []byte(pw)
	needles := []string{pw, pw[:11], hex.EncodeToString(raw), base64.StdEncoding.EncodeToString(raw),
		base64.RawStdEncoding.EncodeToString(raw), base64.RawURLEncoding.EncodeToString(raw)}
	for _, n := range needles {
		if strings.Contains(answers.String(), n) {
			t.Fatal("an HTTP answer holds the write password")
		}
	}
	s.scan(t, "the write password", needles, "exec.write_credential")
}

/* selfSigned writes a self-signed certificate and key (the server only loads them: the test speaks plain HTTP to its handler). */
func selfSigned(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "executor"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "x.crt"), filepath.Join(dir, "x.key")
	if err := errors.Join(os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600),
		os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600)); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}
