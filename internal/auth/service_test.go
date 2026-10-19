package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/beekamai/network-scheme/internal/auth"
	nmscrypto "github.com/beekamai/network-scheme/internal/crypto"
	"github.com/beekamai/network-scheme/internal/testdb"
)

func TestMain(m *testing.M) { testdb.Main(m) }

const goodPW = "Tangerine-Lighthouse-Quorum-81"

/* fakeClock is a manually advanced clock shared by the service and the test. */
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

var seq atomic.Int64

/* fixture is one service over the shared database, with a unique client IP. */
type fixture struct {
	t     *testing.T
	env   *testdb.Env
	svc   *auth.Service
	users *auth.UserStore
	clk   *fakeClock
	key   *[32]byte
	ip    string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	env := testdb.New(t)
	key := new([32]byte)
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	clk := &fakeClock{t: time.Now().UTC().Truncate(time.Second)}
	n := seq.Add(1)
	return &fixture{
		t: t, env: env, clk: clk, key: key,
		/* The service runs as the api role, user management as the nmsctl role. */
		svc:   auth.NewService(env.Pool("nms_api"), key, clk.Now),
		users: auth.NewUserStore(env.Pool("nms_cli")),
		ip:    fmt.Sprintf("198.51.%d.%d", n/250, n%250+1),
	}
}

func uniqueName(prefix string) string { return fmt.Sprintf("%s%d", prefix, seq.Add(1)) }

/* inCLITx runs fn in a transaction of the nms_cli pool. */
func (f *fixture) inCLITx(fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(context.Background(), f.env.Pool("nms_cli"), fn)
}

func (f *fixture) createUser(name string) int64 {
	f.t.Helper()
	var id int64
	err := f.inCLITx(func(tx pgx.Tx) error {
		var err error
		id, err = f.users.Create(context.Background(), tx, name, goodPW)
		return err
	})
	if err != nil {
		f.t.Fatalf("create %q: %v", name, err)
	}
	return id
}

func code(t *testing.T, sec string, at time.Time) string {
	t.Helper()
	c, err := totp.GenerateCodeCustom(sec, at, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func secretFromURI(t *testing.T, uri string) string {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "otpauth" || u.Host != "totp" {
		t.Fatalf("bad otpauth URI %q: %v", uri, err)
	}
	s := u.Query().Get("secret")
	if s == "" {
		t.Fatalf("no secret in %q", uri)
	}
	return s
}

/* enroll performs the first login of name and returns its TOTP secret and backup codes. */
func (f *fixture) enroll(name string) (sec string, codes []string, ns auth.NewSession) {
	f.t.Helper()
	ctx := context.Background()
	step, err := f.svc.BeginLogin(ctx, name, goodPW, f.ip)
	if err != nil {
		f.t.Fatalf("BeginLogin: %v", err)
	}
	if step.Kind != "enroll" {
		f.t.Fatalf("Kind = %q, want enroll", step.Kind)
	}
	sec = secretFromURI(f.t, step.OTPAuthURI)
	ns, codes, err = f.svc.CompleteEnroll(ctx, step.ChallengeID, code(f.t, sec, f.clk.Now()), f.ip, "test-agent")
	if err != nil {
		f.t.Fatalf("CompleteEnroll: %v", err)
	}
	return sec, codes, ns
}

/* login moves to the next TOTP step and performs a full login. */
func (f *fixture) login(name, sec string) auth.NewSession {
	f.t.Helper()
	ctx := context.Background()
	f.clk.Advance(30 * time.Second)
	step, err := f.svc.BeginLogin(ctx, name, goodPW, f.ip)
	if err != nil {
		f.t.Fatalf("BeginLogin: %v", err)
	}
	if step.Kind != "totp" || step.OTPAuthURI != "" {
		f.t.Fatalf("step = %+v, want totp without URI", step)
	}
	ns, err := f.svc.CompleteTOTP(ctx, step.ChallengeID, code(f.t, sec, f.clk.Now()), f.ip, "test-agent")
	if err != nil {
		f.t.Fatalf("CompleteTOTP: %v", err)
	}
	return ns
}

func (f *fixture) begin(name, pw string) error {
	_, err := f.svc.BeginLogin(context.Background(), name, pw, f.ip)
	return err
}

func wantErr(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("err = %v, want %v", got, want)
	}
}

func (f *fixture) auditCount(action string, uid *int64, ip string) int {
	f.t.Helper()
	var n int
	err := f.env.Pool("nms_api").QueryRow(context.Background(),
		`SELECT count(*) FROM audit.event
		 WHERE action = $1 AND ($2::bigint IS NULL OR user_id = $2)
		   AND ($3 = '' OR convert_from(payload, 'UTF8')::jsonb->>'ip' = $3)`,
		action, uid, ip).Scan(&n)
	if err != nil {
		f.t.Fatal(err)
	}
	return n
}

func TestLoginHappyPath(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	name := uniqueName("happy")
	uid := f.createUser(name)
	sec, _, _ := f.enroll(name)

	ns := f.login(name, sec)
	if ns.Token == "" || ns.CSRF == "" || ns.Token == ns.CSRF {
		t.Fatalf("bad session %+v", ns)
	}
	if want := f.clk.Now().Add(12 * time.Hour); !ns.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want %v", ns.ExpiresAt, want)
	}
	if raw, err := base64.RawURLEncoding.DecodeString(ns.Token); err != nil || len(raw) != 32 {
		t.Fatalf("token is not 32 bytes base64url: %v", err)
	}
	s, err := f.svc.Authenticate(ctx, ns.Token)
	if err != nil {
		t.Fatal(err)
	}
	if s.UserID != uid || s.Username != name || s.CSRF != ns.CSRF || s.StepUpValid {
		t.Fatalf("session = %+v", s)
	}
	if f.auditCount("auth.login.success", &uid, f.ip) < 2 {
		t.Fatal("auth.login.success not audited")
	}

	/* A challenge is single-use and expires after 5 minutes. */
	f.clk.Advance(30 * time.Second)
	step, err := f.svc.BeginLogin(ctx, name, goodPW, f.ip)
	if err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(5*time.Minute + time.Second)
	_, err = f.svc.CompleteTOTP(ctx, step.ChallengeID, code(t, sec, f.clk.Now()), f.ip, "ua")
	wantErr(t, err, auth.ErrChallengeExpired)
	_, err = f.svc.CompleteTOTP(ctx, step.ChallengeID, code(t, sec, f.clk.Now()), f.ip, "ua")
	wantErr(t, err, auth.ErrInvalidCredentials)

	if err := f.svc.Logout(ctx, ns.Token); err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.Authenticate(ctx, ns.Token)
	wantErr(t, err, auth.ErrSessionExpired)
	if f.auditCount("auth.logout", &uid, "") != 1 {
		t.Fatal("auth.logout not audited")
	}
}

func TestEnrollFlow(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	name := uniqueName("enroll")
	uid := f.createUser(name)

	step, err := f.svc.BeginLogin(ctx, name, goodPW, f.ip)
	if err != nil {
		t.Fatal(err)
	}
	if step.Kind != "enroll" || !strings.HasPrefix(step.OTPAuthURI, "otpauth://totp/") {
		t.Fatalf("step = %+v", step)
	}
	_, _, err = f.svc.CompleteEnroll(ctx, step.ChallengeID, "000000", f.ip, "ua")
	wantErr(t, err, auth.ErrInvalidCredentials)

	/* A TOTP challenge cannot complete an enrollment and vice versa. */
	step, err = f.svc.BeginLogin(ctx, name, goodPW, f.ip)
	if err != nil {
		t.Fatal(err)
	}
	sec := secretFromURI(t, step.OTPAuthURI)
	_, err = f.svc.CompleteTOTP(ctx, step.ChallengeID, code(t, sec, f.clk.Now()), f.ip, "ua")
	wantErr(t, err, auth.ErrInvalidCredentials)

	sec, codes, ns := f.enroll(name)
	if len(codes) != 10 {
		t.Fatalf("got %d backup codes, want 10", len(codes))
	}
	if _, err := f.svc.Authenticate(ctx, ns.Token); err != nil {
		t.Fatal(err)
	}
	if f.auditCount("auth.enroll", &uid, f.ip) != 1 {
		t.Fatal("auth.enroll not audited")
	}
	list, err := f.users.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, u := range list {
		if u.ID == uid {
			found = u.TOTPEnrolled && u.Username == name && !u.Disabled
		}
	}
	if !found {
		t.Fatal("List does not show the user as enrolled")
	}
	f.login(name, sec)
}

func TestUniformErrors(t *testing.T) {
	f := newFixture(t)
	name := uniqueName("uniform")
	f.createUser(name)
	off := uniqueName("disabled")
	offID := f.createUser(off)
	if err := f.inCLITx(func(tx pgx.Tx) error {
		return f.users.SetDisabled(context.Background(), tx, offID, true)
	}); err != nil {
		t.Fatal(err)
	}

	errs := []error{
		f.begin(uniqueName("nosuch"), goodPW),
		f.begin(name, goodPW+"x"),
		f.begin(off, goodPW),
		f.begin("", goodPW),
		f.begin("bad name!", goodPW),
	}
	for i, err := range errs {
		if err != auth.ErrInvalidCredentials { //nolint:errorlint // identity is the point
			t.Fatalf("case %d: err = %v, want exactly ErrInvalidCredentials", i, err)
		}
	}
}

func TestTOTPReplayRejected(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	name := uniqueName("replay")
	f.createUser(name)
	sec, _, _ := f.enroll(name)

	f.clk.Advance(30 * time.Second)
	c := code(t, sec, f.clk.Now())
	for i, want := range []error{nil, auth.ErrInvalidCredentials} {
		step, err := f.svc.BeginLogin(ctx, name, goodPW, f.ip)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.svc.CompleteTOTP(ctx, step.ChallengeID, c, f.ip, "ua")
		if !errors.Is(err, want) { /* errors.Is(nil, nil) is true */
			t.Fatalf("attempt %d: err = %v, want %v", i, err, want)
		}
	}
	/* The previous step is inside the ±1 window but not newer than the last used one. */
	step, err := f.svc.BeginLogin(ctx, name, goodPW, f.ip)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.CompleteTOTP(ctx, step.ChallengeID, code(t, sec, f.clk.Now().Add(-30*time.Second)), f.ip, "ua")
	wantErr(t, err, auth.ErrInvalidCredentials)
}

func TestBackupCodeSingleUse(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	name := uniqueName("backup")
	uid := f.createUser(name)
	_, codes, _ := f.enroll(name)

	try := func(c string) error {
		step, err := f.svc.BeginLogin(ctx, name, goodPW, f.ip)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.svc.CompleteTOTP(ctx, step.ChallengeID, c, f.ip, "ua")
		return err
	}
	if err := try(codes[0]); err != nil {
		t.Fatal(err)
	}
	wantErr(t, try(codes[0]), auth.ErrInvalidCredentials)
	if err := try(" " + strings.ToLower(codes[1]) + " "); err != nil {
		t.Fatalf("lower-case backup code: %v", err)
	}
	var left int
	if err := f.env.Pool("postgres").QueryRow(ctx,
		`SELECT cardinality(backup_hashes) FROM core."user" WHERE id = $1`, uid).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 8 {
		t.Fatalf("%d backup hashes left, want 8", left)
	}
}

func TestAccountLockoutEscalates(t *testing.T) {
	f := newFixture(t)
	name := uniqueName("lock")
	uid := f.createUser(name)
	sec, _, _ := f.enroll(name)

	/* A successful login resets the counter. */
	for range 4 {
		wantErr(t, f.begin(name, "wrong-password-123"), auth.ErrInvalidCredentials)
	}
	f.login(name, sec)

	for range 5 {
		wantErr(t, f.begin(name, "wrong-password-123"), auth.ErrInvalidCredentials)
	}
	wantErr(t, f.begin(name, goodPW), auth.ErrLocked)
	f.clk.Advance(59 * time.Second)
	wantErr(t, f.begin(name, goodPW), auth.ErrLocked)
	f.clk.Advance(2 * time.Second)

	/* One more failure after the lock ends doubles it. */
	wantErr(t, f.begin(name, "wrong-password-123"), auth.ErrInvalidCredentials)
	f.clk.Advance(119 * time.Second)
	wantErr(t, f.begin(name, goodPW), auth.ErrLocked)
	f.clk.Advance(2 * time.Second)
	if err := f.begin(name, goodPW); err != nil {
		t.Fatalf("after 2 min: %v", err)
	}
	if n := f.auditCount("auth.lockout", &uid, ""); n != 2 {
		t.Fatalf("%d auth.lockout events, want 2", n)
	}
	if n := f.auditCount("auth.login.failure", &uid, f.ip); n != 10 {
		t.Fatalf("%d auth.login.failure events, want 10", n)
	}
}

func TestAccountLockoutConcurrent(t *testing.T) {
	f := newFixture(t)
	name := uniqueName("race")
	uid := f.createUser(name)

	const n = 8
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() { errs <- f.begin(name, "wrong-password-123") })
	}
	wg.Wait()
	close(errs)
	var invalid, locked int
	for err := range errs {
		switch {
		case errors.Is(err, auth.ErrInvalidCredentials):
			invalid++
		case errors.Is(err, auth.ErrLocked):
			locked++
		default:
			t.Fatalf("unexpected err %v", err)
		}
	}
	if invalid != 5 || locked != n-5 {
		t.Fatalf("invalid=%d locked=%d, want 5 and %d", invalid, locked, n-5)
	}
	var failures int
	if err := f.env.Pool("postgres").QueryRow(context.Background(),
		`SELECT failures FROM core.account_lock WHERE user_id = $1`, uid).Scan(&failures); err != nil {
		t.Fatal(err)
	}
	if failures != 5 {
		t.Fatalf("failures = %d, want 5", failures)
	}
}

func TestIPRateLimit(t *testing.T) {
	f := newFixture(t)
	name := uniqueName("iprl")
	f.createUser(name)

	for i := range 21 {
		err := f.begin(uniqueName("ghost"), goodPW)
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	wantErr(t, f.begin(name, goodPW), auth.ErrRateLimited)
	_, err := f.svc.CompleteTOTP(context.Background(), "whatever", "123456", f.ip, "ua")
	wantErr(t, err, auth.ErrRateLimited)
	if f.auditCount("auth.lockout", nil, f.ip) != 1 {
		t.Fatal("IP lockout not audited")
	}

	other := *f
	other.ip = "203.0.113.77"
	if err := other.begin(name, goodPW); err != nil {
		t.Fatalf("other IP: %v", err)
	}
	f.clk.Advance(9 * time.Minute)
	wantErr(t, f.begin(name, goodPW), auth.ErrRateLimited)
	f.clk.Advance(time.Minute + time.Second)
	if err := f.begin(name, goodPW); err != nil {
		t.Fatalf("after 10 min: %v", err)
	}
}

func TestSessionIdleAndAbsoluteExpiry(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	name := uniqueName("expiry")
	f.createUser(name)
	sec, _, _ := f.enroll(name)

	ns := f.login(name, sec)
	f.clk.Advance(29 * time.Minute)
	if _, err := f.svc.Authenticate(ctx, ns.Token); err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(31 * time.Minute)
	_, err := f.svc.Authenticate(ctx, ns.Token)
	wantErr(t, err, auth.ErrSessionExpired)

	ns = f.login(name, sec)
	for i := range 35 {
		f.clk.Advance(20 * time.Minute)
		if _, err := f.svc.Authenticate(ctx, ns.Token); err != nil {
			t.Fatalf("tick %d: %v", i, err)
		}
	}
	f.clk.Advance(19 * time.Minute) /* 11 h 59 min */
	if _, err := f.svc.Authenticate(ctx, ns.Token); err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(2 * time.Minute) /* 12 h 1 min */
	_, err = f.svc.Authenticate(ctx, ns.Token)
	wantErr(t, err, auth.ErrSessionExpired)
	_, err = f.svc.Authenticate(ctx, "not-a-token")
	wantErr(t, err, auth.ErrSessionExpired)
}

func TestStepUpRotatesTokenAndExpires(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	name := uniqueName("stepup")
	uid := f.createUser(name)
	sec, codes, _ := f.enroll(name)
	ns := f.login(name, sec)

	_, err := f.svc.StepUp(ctx, ns.Token, "000000")
	wantErr(t, err, auth.ErrInvalidCredentials)
	_, err = f.svc.StepUp(ctx, ns.Token, codes[0])
	wantErr(t, err, auth.ErrInvalidCredentials)
	/* The code of the login step is a replay. */
	_, err = f.svc.StepUp(ctx, ns.Token, code(t, sec, f.clk.Now()))
	wantErr(t, err, auth.ErrInvalidCredentials)

	f.clk.Advance(30 * time.Second)
	tok, err := f.svc.StepUp(ctx, ns.Token, code(t, sec, f.clk.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if tok == ns.Token {
		t.Fatal("token not rotated")
	}
	_, err = f.svc.Authenticate(ctx, ns.Token)
	wantErr(t, err, auth.ErrSessionExpired)
	s, err := f.svc.Authenticate(ctx, tok)
	if err != nil || !s.StepUpValid || s.CSRF != ns.CSRF {
		t.Fatalf("after step-up: %+v, %v", s, err)
	}
	f.clk.Advance(5*time.Minute + time.Second)
	if s, err = f.svc.Authenticate(ctx, tok); err != nil || s.StepUpValid {
		t.Fatalf("after 5 min 1 s: %+v, %v", s, err)
	}
	if f.auditCount("auth.stepup", &uid, "") != 4 {
		t.Fatal("auth.stepup not audited for every attempt")
	}
	_, err = f.svc.StepUp(ctx, ns.Token, code(t, sec, f.clk.Now()))
	wantErr(t, err, auth.ErrSessionExpired)
}

func TestTokenStoredHashed(t *testing.T) {
	f := newFixture(t)
	name := uniqueName("hashed")
	f.createUser(name)
	sec, _, _ := f.enroll(name)
	ns := f.login(name, sec)
	raw, err := base64.RawURLEncoding.DecodeString(ns.Token)
	if err != nil {
		t.Fatal(err)
	}

	rows, err := f.env.Pool("postgres").Query(context.Background(), `SELECT s::text FROM core.session s`)
	if err != nil {
		t.Fatal(err)
	}
	all, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(ns.Token))
	hashSeen := false
	for _, r := range all {
		if strings.Contains(r, ns.Token) || strings.Contains(r, hex.EncodeToString(raw)) {
			t.Fatalf("plain token stored: %s", r)
		}
		hashSeen = hashSeen || strings.Contains(r, hex.EncodeToString(h[:]))
	}
	if !hashSeen {
		t.Fatal("SHA-256 of the token not found: test is not looking at the right rows")
	}
}

func TestTOTPSecretEncryptedAtRest(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	name := uniqueName("atrest")
	uid := f.createUser(name)
	pg := f.env.Pool("postgres")

	/* The pending secret of an enrollment challenge is sealed too. */
	step, err := f.svc.BeginLogin(ctx, name, goodPW, f.ip)
	if err != nil {
		t.Fatal(err)
	}
	pending := secretFromURI(t, step.OTPAuthURI)
	var chRow string
	if err := pg.QueryRow(ctx, `SELECT c::text FROM core.login_challenge c WHERE user_id = $1`, uid).Scan(&chRow); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToUpper(chRow), pending) || strings.Contains(chRow, step.ChallengeID) {
		t.Fatal("challenge row holds the plain secret or challenge id")
	}

	sec, _, _ := f.enroll(name)
	var row string
	var enc []byte
	if err := pg.QueryRow(ctx, `SELECT u::text, u.totp_secret_enc FROM core."user" u WHERE id = $1`, uid).Scan(&row, &enc); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToUpper(row), sec) || strings.Contains(row, hex.EncodeToString([]byte(sec))) {
		t.Fatal("user row holds the plain TOTP secret")
	}
	pt, err := nmscrypto.Open(f.key, enc, []byte("totp-login:"+strconv.FormatInt(uid, 10)))
	if err != nil || string(pt) != sec {
		t.Fatalf("open with the right AAD: %v", err)
	}
	if _, err := nmscrypto.Open(f.key, enc, []byte("totp-login:"+strconv.FormatInt(uid+1, 10))); !errors.Is(err, nmscrypto.ErrOpen) {
		t.Fatalf("open with another user id in AAD: %v", err)
	}
}

func TestUsernameCaseAndUnicodeDuplicates(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.createUser("admin")
	f.createUser("caf\u00e9") /* NFC */
	for _, dup := range []string{"Admin", " ADMIN ", "cafe\u0301" /* NFD */, "CAFE\u0301"} {
		err := f.inCLITx(func(tx pgx.Tx) error {
			_, err := f.users.Create(ctx, tx, dup, goodPW)
			return err
		})
		wantErr(t, err, auth.ErrUserExists)
	}
	step, err := f.svc.BeginLogin(ctx, "ADMIN", goodPW, f.ip)
	if err != nil || step.Kind != "enroll" {
		t.Fatalf("login as ADMIN: %+v, %v", step, err)
	}

	for in, want := range map[string]string{
		" Bob ": "bob", "Иван.Петров": "иван.петров", "a_b-c.9": "a_b-c.9", "cafe\u0301": "caf\u00e9",
	} {
		got, err := auth.NormalizeUsername(in)
		if err != nil || got != want {
			t.Fatalf("NormalizeUsername(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "ab", "a b c", "bob@example", strings.Repeat("x", 65), "x\u0301yz" /* x-acute has no precomposed form */, "日本語"} {
		if _, err := auth.NormalizeUsername(bad); !errors.Is(err, auth.ErrBadUsername) {
			t.Fatalf("NormalizeUsername(%q) err = %v", bad, err)
		}
	}
	err = f.inCLITx(func(tx pgx.Tx) error {
		_, err := f.users.Create(ctx, tx, uniqueName("short"), "short")
		return err
	})
	wantErr(t, err, auth.ErrPasswordTooShort)
}

func TestDisableAndResetKillSessions(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	name := uniqueName("kill")
	uid := f.createUser(name)
	sec, _, _ := f.enroll(name)
	cli := func(fn func(context.Context, pgx.Tx, int64) error) {
		t.Helper()
		if err := f.inCLITx(func(tx pgx.Tx) error { return fn(ctx, tx, uid) }); err != nil {
			t.Fatal(err)
		}
	}

	ns := f.login(name, sec)
	cli(func(ctx context.Context, tx pgx.Tx, id int64) error { return f.users.SetDisabled(ctx, tx, id, true) })
	_, err := f.svc.Authenticate(ctx, ns.Token)
	wantErr(t, err, auth.ErrSessionExpired)
	wantErr(t, f.begin(name, goodPW), auth.ErrInvalidCredentials)
	cli(func(ctx context.Context, tx pgx.Tx, id int64) error { return f.users.SetDisabled(ctx, tx, id, false) })

	ns = f.login(name, sec)
	cli(f.users.ResetTOTP)
	_, err = f.svc.Authenticate(ctx, ns.Token)
	wantErr(t, err, auth.ErrSessionExpired)
	step, err := f.svc.BeginLogin(ctx, name, goodPW, f.ip)
	if err != nil || step.Kind != "enroll" {
		t.Fatalf("after ResetTOTP: %+v, %v", step, err)
	}
	var codes int
	if err := f.env.Pool("postgres").QueryRow(ctx,
		`SELECT cardinality(backup_hashes) FROM core."user" WHERE id = $1`, uid).Scan(&codes); err != nil {
		t.Fatal(err)
	}
	if codes != 0 {
		t.Fatalf("%d backup codes left after ResetTOTP", codes)
	}

	sec, _, ns = f.enroll(name)
	const newPW = "Marmalade-Sextant-Orbit-77"
	cli(func(ctx context.Context, tx pgx.Tx, id int64) error { return f.users.SetPassword(ctx, tx, id, newPW) })
	_, err = f.svc.Authenticate(ctx, ns.Token)
	wantErr(t, err, auth.ErrSessionExpired)
	wantErr(t, f.begin(name, goodPW), auth.ErrInvalidCredentials)
	if _, err := f.svc.BeginLogin(ctx, name, newPW, f.ip); err != nil {
		t.Fatalf("login with new password: %v", err)
	}
	err = f.inCLITx(func(tx pgx.Tx) error { return f.users.SetDisabled(ctx, tx, uid+1_000_000, true) })
	wantErr(t, err, auth.ErrUserNotFound)
	_ = sec
}
