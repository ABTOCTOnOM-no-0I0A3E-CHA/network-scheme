package httpapi_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/beekamai/network-scheme/internal/auth"
	"github.com/beekamai/network-scheme/internal/config"
	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/httpapi"
	"github.com/beekamai/network-scheme/internal/rbac"
	"github.com/beekamai/network-scheme/internal/testdb"
)

func TestMain(m *testing.M) { testdb.Main(m) }

const (
	goodPW     = "Tangerine-Lighthouse-Quorum-81"
	cookieName = "__Host-nms_session"
)

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

/* fixture is a router over the shared database with a unique client address. */
type fixture struct {
	t    *testing.T
	env  *testdb.Env
	clk  *fakeClock
	h    http.Handler
	ip   string
	logs *bytes.Buffer
	jobs *fakeJobs
}

func newFixture(t *testing.T, mutate func(*httpapi.Deps)) *fixture {
	t.Helper()
	env := testdb.New(t)
	key := new([32]byte)
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	clk := &fakeClock{t: time.Now().UTC().Truncate(time.Second)}
	logs := &bytes.Buffer{}
	pool := env.Pool("nms_api")
	jobs := &fakeJobs{}
	d := httpapi.Deps{
		Auth:    auth.NewService(pool, key, clk.Now),
		Users:   auth.NewUserStore(pool),
		RBAC:    rbac.NewStore(pool),
		Pool:    pool,
		Devices: devices.NewStore(pool),
		Jobs:    jobs,
		Cfg: config.API{PublicOrigin: publicOrigin, TrustedProxyCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			ReadKeyVersion: 1},
		Clock:         clk.Now,
		Logger:        slog.New(slog.NewJSONHandler(&lockedWriter{w: logs}, nil)),
		AuthRateLimit: 1000,
	}
	if mutate != nil {
		mutate(&d)
	}
	n := seq.Add(1)
	return &fixture{
		t: t, env: env, clk: clk, h: httpapi.NewRouter(d), logs: logs, jobs: jobs,
		ip: fmt.Sprintf("192.0.%d.%d", 2+n/250, n%250+1),
	}
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func uniqueName(prefix string) string { return fmt.Sprintf("%s%d", prefix, seq.Add(1)) }

func (f *fixture) createUser(name string) int64 {
	f.t.Helper()
	var id int64
	err := pgx.BeginFunc(context.Background(), f.env.Pool("nms_cli"), func(tx pgx.Tx) error {
		var err error
		id, err = auth.NewUserStore(f.env.Pool("nms_cli")).Create(context.Background(), tx, name, goodPW)
		return err
	})
	if err != nil {
		f.t.Fatalf("create %q: %v", name, err)
	}
	return id
}

/* req describes one request; zero fields take defaults. */
type req struct {
	method, path string
	body         any
	raw          []byte
	cookie       string
	csrf         string
	origin       string
	remote       string
	xff          string
}

func (f *fixture) do(r req) *http.Response {
	f.t.Helper()
	var body io.Reader
	switch {
	case r.raw != nil:
		body = bytes.NewReader(r.raw)
	case r.body != nil:
		b, err := json.Marshal(r.body)
		if err != nil {
			f.t.Fatal(err)
		}
		body = bytes.NewReader(b)
	}
	hr := httptest.NewRequest(r.method, r.path, body)
	if body != nil {
		hr.Header.Set("Content-Type", "application/json")
	}
	hr.RemoteAddr = f.ip + ":40000"
	if r.remote != "" {
		hr.RemoteAddr = r.remote
	}
	if r.xff != "" {
		hr.Header.Set("X-Forwarded-For", r.xff)
	}
	if r.cookie != "" {
		hr.AddCookie(&http.Cookie{Name: cookieName, Value: r.cookie})
	}
	if r.csrf != "" {
		hr.Header.Set("X-CSRF-Token", r.csrf)
	}
	if r.origin != "" {
		hr.Header.Set("Origin", r.origin)
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, hr)
	return rec.Result()
}

func decode[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	var v T
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatalf("decode %d response: %v", resp.StatusCode, err)
	}
	return v
}

type errBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func wantError(t *testing.T, resp *http.Response, status int, code string) {
	t.Helper()
	if resp.StatusCode != status {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d; body %s", resp.StatusCode, status, b)
	}
	e := decode[errBody](t, resp)
	if e.Error.Code != code || e.Error.Message == "" {
		t.Fatalf("error = %+v, want code %q with a message", e.Error, code)
	}
}

func totpCode(t *testing.T, sec string, at time.Time) string {
	t.Helper()
	c, err := totp.GenerateCodeCustom(sec, at, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type loginResp struct {
	Stage      string `json:"stage"`
	Challenge  string `json:"challenge"`
	OTPAuthURI string `json:"otpauth_uri"`
}

func sessionCookie(t *testing.T, resp *http.Response) (value, raw string) {
	t.Helper()
	for _, h := range resp.Header.Values("Set-Cookie") {
		if strings.HasPrefix(h, cookieName+"=") {
			c, err := http.ParseSetCookie(h)
			if err != nil {
				t.Fatal(err)
			}
			return c.Value, h
		}
	}
	t.Fatalf("no %s cookie in %v", cookieName, resp.Header.Values("Set-Cookie"))
	return "", ""
}

func wantCookieAttrs(t *testing.T, raw string) {
	t.Helper()
	for _, a := range []string{"Path=/", "Secure", "HttpOnly", "SameSite=Strict"} {
		if !strings.Contains(raw, "; "+a) {
			t.Fatalf("cookie %q lacks %s", raw, a)
		}
	}
	if strings.Contains(strings.ToLower(raw), "domain=") {
		t.Fatalf("cookie %q must not carry Domain", raw)
	}
}

/* enroll performs the first login of a new user over HTTP and returns its secret and cookie. */
func (f *fixture) enroll(name string) (sec, cookie string) {
	f.t.Helper()
	sec, cookie, _ = f.enrollCodes(name)
	return sec, cookie
}

/* enrollCodes is enroll that also returns the backup codes. */
func (f *fixture) enrollCodes(name string) (sec, cookie string, backup []string) {
	f.t.Helper()
	resp := f.do(req{method: "POST", path: "/api/auth/login", body: map[string]string{"username": name, "password": goodPW}})
	if resp.StatusCode != http.StatusOK {
		f.t.Fatalf("login status %d", resp.StatusCode)
	}
	lr := decode[loginResp](f.t, resp)
	if lr.Stage != "enroll" || lr.Challenge == "" || lr.OTPAuthURI == "" {
		f.t.Fatalf("login = %+v, want enroll", lr)
	}
	u, err := url.Parse(lr.OTPAuthURI)
	if err != nil {
		f.t.Fatal(err)
	}
	sec = u.Query().Get("secret")
	resp = f.do(req{method: "POST", path: "/api/auth/enroll", body: map[string]string{"challenge": lr.Challenge, "code": totpCode(f.t, sec, f.clk.Now())}})
	if resp.StatusCode != http.StatusOK {
		f.t.Fatalf("enroll status %d", resp.StatusCode)
	}
	codes := decode[struct {
		BackupCodes []string `json:"backup_codes"`
	}](f.t, resp)
	if len(codes.BackupCodes) != 10 {
		f.t.Fatalf("backup codes = %v", codes.BackupCodes)
	}
	cookie, raw := sessionCookie(f.t, resp)
	wantCookieAttrs(f.t, raw)
	return sec, cookie, codes.BackupCodes
}

type meResp struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Roles    []struct {
		Role    string `json:"role"`
		GroupID *int64 `json:"group_id"`
	} `json:"roles"`
	CSRFToken string `json:"csrf_token"`
}

func (f *fixture) me(cookie string) meResp {
	f.t.Helper()
	resp := f.do(req{method: "GET", path: "/api/auth/me", cookie: cookie})
	if resp.StatusCode != http.StatusOK {
		f.t.Fatalf("me status %d", resp.StatusCode)
	}
	return decode[meResp](f.t, resp)
}

func TestLoginEndToEndOverHTTP(t *testing.T) {
	f := newFixture(t, nil)
	name := uniqueName("http")
	uid := f.createUser(name)
	sec, first := f.enroll(name)

	f.clk.Advance(30 * time.Second)
	resp := f.do(req{method: "POST", path: "/api/auth/login", body: map[string]string{"username": name, "password": goodPW}})
	lr := decode[loginResp](t, resp)
	if lr.Stage != "totp" || lr.OTPAuthURI != "" {
		t.Fatalf("login = %+v, want totp without URI", lr)
	}
	/* A stale cookie is replaced, not cleared after the new one is set. */
	resp = f.do(req{method: "POST", path: "/api/auth/totp", cookie: "stale-token",
		body: map[string]string{"challenge": lr.Challenge, "code": totpCode(t, sec, f.clk.Now())}})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("totp status %d", resp.StatusCode)
	}
	if n := len(resp.Header.Values("Set-Cookie")); n != 1 {
		t.Fatalf("%d Set-Cookie headers: %v", n, resp.Header.Values("Set-Cookie"))
	}
	cookie, raw := sessionCookie(t, resp)
	wantCookieAttrs(t, raw)
	if cookie == first {
		t.Fatal("second login reused the session token")
	}

	me := f.me(cookie)
	if me.ID != uid || me.Username != name || me.CSRFToken == "" || me.Roles == nil {
		t.Fatalf("me = %+v", me)
	}

	resp = f.do(req{method: "POST", path: "/api/auth/logout", cookie: cookie, csrf: me.CSRFToken})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout status %d", resp.StatusCode)
	}
	if _, raw := sessionCookie(t, resp); !strings.Contains(raw, "Max-Age=0") {
		t.Fatalf("logout cookie %q not cleared", raw)
	}
	wantError(t, f.do(req{method: "GET", path: "/api/auth/me", cookie: cookie}), http.StatusUnauthorized, "session_expired")
	wantError(t, f.do(req{method: "GET", path: "/api/auth/me"}), http.StatusUnauthorized, "unauthenticated")
}

func TestLoginRejectsBadPassword(t *testing.T) {
	f := newFixture(t, nil)
	name := uniqueName("bad")
	f.createUser(name)
	wantError(t, f.do(req{method: "POST", path: "/api/auth/login", body: map[string]string{"username": name, "password": "wrong-password-123"}}),
		http.StatusUnauthorized, "invalid_credentials")
	wantError(t, f.do(req{method: "POST", path: "/api/auth/totp", body: map[string]string{"challenge": "nope", "code": "123456"}}),
		http.StatusUnauthorized, "invalid_credentials")
}

func TestStepUpRotatesCookie(t *testing.T) {
	f := newFixture(t, nil)
	name := uniqueName("step")
	f.createUser(name)
	sec, cookie := f.enroll(name)
	csrf := f.me(cookie).CSRFToken

	f.clk.Advance(30 * time.Second)
	wantError(t, f.do(req{method: "POST", path: "/api/auth/stepup", cookie: cookie, csrf: csrf, body: map[string]string{"code": "000000"}}),
		http.StatusUnauthorized, "invalid_credentials")
	resp := f.do(req{method: "POST", path: "/api/auth/stepup", cookie: cookie, csrf: csrf, body: map[string]string{"code": totpCode(t, sec, f.clk.Now())}})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("stepup status %d", resp.StatusCode)
	}
	fresh, raw := sessionCookie(t, resp)
	wantCookieAttrs(t, raw)
	if fresh == cookie {
		t.Fatal("step-up did not rotate the token")
	}
	wantError(t, f.do(req{method: "GET", path: "/api/auth/me", cookie: cookie}), http.StatusUnauthorized, "session_expired")
	f.me(fresh)
}

func TestCSRFRequiredForMutations(t *testing.T) {
	f := newFixture(t, nil)
	name := uniqueName("csrf")
	f.createUser(name)
	_, cookie := f.enroll(name)

	wantError(t, f.do(req{method: "POST", path: "/api/auth/logout", cookie: cookie}), http.StatusForbidden, "csrf")
	wantError(t, f.do(req{method: "POST", path: "/api/auth/logout", cookie: cookie, csrf: "forged"}), http.StatusForbidden, "csrf")
	f.me(cookie) /* the session survived the rejected logouts */
}

const publicOrigin = "https://nms.test"

func TestForeignOriginRejectedOnMutations(t *testing.T) {
	f := newFixture(t, nil)
	name := uniqueName("origin")
	f.createUser(name)
	bad := map[string]string{"username": name, "password": "wrong-password-123"}

	/* Without a session: a foreign Origin is refused before the credentials are checked. */
	for _, o := range []string{"https://evil.test", "null", "https://nms.test:8443", "http://nms.test"} {
		wantError(t, f.do(req{method: "POST", path: "/api/auth/login", body: bad, origin: o}), http.StatusForbidden, "csrf")
	}
	wantError(t, f.do(req{method: "POST", path: "/api/auth/login", body: bad, origin: publicOrigin}), http.StatusUnauthorized, "invalid_credentials")
	wantError(t, f.do(req{method: "POST", path: "/api/auth/login", body: bad}), http.StatusUnauthorized, "invalid_credentials")

	/* With a session and the right token, a foreign Origin is still refused. */
	_, cookie := f.enroll(name)
	csrf := f.me(cookie).CSRFToken
	wantError(t, f.do(req{method: "POST", path: "/api/auth/logout", cookie: cookie, csrf: csrf, origin: "https://evil.test"}), http.StatusForbidden, "csrf")
	f.me(cookie)
	/* Safe methods do not check Origin. */
	if resp := f.do(req{method: "GET", path: "/api/auth/me", cookie: cookie, origin: "https://evil.test"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET with a foreign Origin: %d", resp.StatusCode)
	}
	if resp := f.do(req{method: "POST", path: "/api/auth/logout", cookie: cookie, csrf: csrf, origin: publicOrigin}); resp.StatusCode/100 != 2 {
		t.Fatalf("logout from the public origin: %d", resp.StatusCode)
	}
}

func TestOriginComparedNormalised(t *testing.T) {
	f := newFixture(t, func(d *httpapi.Deps) { d.Cfg.PublicOrigin = "https://NMS.Corp.example" })
	name := uniqueName("originnorm")
	f.createUser(name)
	bad := map[string]string{"username": name, "password": "wrong-password-123"}
	for _, o := range []string{"https://nms.corp.example", "https://nms.corp.example:443", "HTTPS://NMS.corp.example"} {
		wantError(t, f.do(req{method: "POST", path: "/api/auth/login", body: bad, origin: o}), http.StatusUnauthorized, "invalid_credentials")
	}
	for _, o := range []string{"https://evil.example", "http://nms.corp.example", "null", "https://nms.corp.example:8443", "https://nms.corp.example/x"} {
		wantError(t, f.do(req{method: "POST", path: "/api/auth/login", body: bad, origin: o}), http.StatusForbidden, "csrf")
	}
	g := newFixture(t, func(d *httpapi.Deps) { d.Cfg.PublicOrigin = "https://nms.corp.example:8443" })
	wantError(t, g.do(req{method: "POST", path: "/api/auth/login", body: bad, origin: "https://nms.corp.example"}), http.StatusForbidden, "csrf")
	wantError(t, g.do(req{method: "POST", path: "/api/auth/login", body: bad, origin: "https://nms.corp.example:8443"}), http.StatusUnauthorized, "invalid_credentials")
}

func TestXFFIgnoredFromUntrustedPeer(t *testing.T) {
	f := newFixture(t, nil)
	bad := map[string]string{"username": uniqueName("ghost"), "password": "wrong-password-123"}
	for i := range 21 {
		resp := f.do(req{method: "POST", path: "/api/auth/login", body: bad, xff: fmt.Sprintf("1.2.3.%d", i+1)})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d", i+1, resp.StatusCode)
		}
	}
	/* The real address is now blocked whatever the spoofed header says. */
	wantError(t, f.do(req{method: "POST", path: "/api/auth/login", body: bad, xff: "1.2.3.200"}), http.StatusTooManyRequests, "rate_limited")
	/* A trusted proxy forwarding a different client is unaffected. */
	wantError(t, f.do(req{method: "POST", path: "/api/auth/login", body: bad, remote: "10.0.0.5:5000", xff: "1.2.3.4, " + fmt.Sprintf("203.0.113.%d", seq.Add(1)%250+1)}),
		http.StatusUnauthorized, "invalid_credentials")
	/* ...while a trusted proxy forwarding the blocked client is refused. */
	wantError(t, f.do(req{method: "POST", path: "/api/auth/login", body: bad, remote: "10.0.0.5:5000", xff: "9.9.9.9, " + f.ip}),
		http.StatusTooManyRequests, "rate_limited")
}

func TestErrorsHaveNoInternals(t *testing.T) {
	f := newFixture(t, func(d *httpapi.Deps) {
		cfg := d.Pool.Config()
		/* Every write fails with SQLSTATE 25006 (read-only transaction). */
		cfg.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
		pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		d.Auth = auth.NewService(pool, new([32]byte), nil)
	})
	resp := f.do(req{method: "POST", path: "/api/auth/login", body: map[string]string{"username": uniqueName("ro"), "password": goodPW}})
	reqID := resp.Header.Get("X-Request-ID")
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, body %s", resp.StatusCode, body)
	}
	for _, leak := range []string{"pgx", "SQLSTATE", "goroutine", "read-only", "auth:", ".go:"} {
		if strings.Contains(string(body), leak) {
			t.Fatalf("body %s leaks %q", body, leak)
		}
	}
	var e errBody
	if err := json.Unmarshal(body, &e); err != nil || e.Error.Code != "internal" {
		t.Fatalf("body = %s", body)
	}
	if reqID == "" || !strings.Contains(f.logs.String(), reqID) || !strings.Contains(f.logs.String(), "SQLSTATE") {
		t.Fatalf("500 not logged with request id %q: %s", reqID, f.logs.String())
	}
}

func TestBodyLimit(t *testing.T) {
	f := newFixture(t, nil)
	big := []byte(`{"username":"x","password":"` + strings.Repeat("a", 2<<20) + `"}`)
	wantError(t, f.do(req{method: "POST", path: "/api/auth/login", raw: big}), http.StatusRequestEntityTooLarge, "payload_too_large")

	/* Unknown length (chunked): cut off by the reader limit instead. */
	hr := httptest.NewRequest("POST", "/api/auth/login", io.MultiReader(bytes.NewReader(big)))
	hr.Header.Set("Content-Type", "application/json")
	hr.RemoteAddr = f.ip + ":1"
	if hr.ContentLength > 0 {
		t.Fatalf("ContentLength = %d, want unknown", hr.ContentLength)
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, hr)
	wantError(t, rec.Result(), http.StatusRequestEntityTooLarge, "payload_too_large")
}

func TestAuthRateLimit(t *testing.T) {
	f := newFixture(t, func(d *httpapi.Deps) { d.AuthRateLimit = 0 })
	bad := map[string]string{"username": uniqueName("rl"), "password": "wrong-password-123"}
	for i := range 10 {
		if resp := f.do(req{method: "POST", path: "/api/auth/login", body: bad}); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d", i+1, resp.StatusCode)
		}
	}
	wantError(t, f.do(req{method: "POST", path: "/api/auth/login", body: bad}), http.StatusTooManyRequests, "rate_limited")
	/* Other clients keep their own budget. */
	wantError(t, f.do(req{method: "POST", path: "/api/auth/login", body: bad, remote: "198.18.0.1:1"}), http.StatusUnauthorized, "invalid_credentials")
}

func TestRequestValidation(t *testing.T) {
	f := newFixture(t, nil)
	resp := f.do(req{method: "GET", path: "/api/health"})
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("health: %d %v", resp.StatusCode, resp.Header)
	}
	wantError(t, f.do(req{method: "GET", path: "/api/nope"}), http.StatusNotFound, "not_found")
	wantError(t, f.do(req{method: "GET", path: "/api/auth/login"}), http.StatusMethodNotAllowed, "method_not_allowed")
	wantError(t, f.do(req{method: "POST", path: "/api/auth/login", raw: []byte(`{"username":"a","password":"b","extra":1}`)}), http.StatusBadRequest, "bad_request")
	wantError(t, f.do(req{method: "POST", path: "/api/auth/login", raw: []byte(`{"username":"a"} {}`)}), http.StatusBadRequest, "bad_request")

	hr := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"a","password":"b"}`))
	hr.Header.Set("Content-Type", "text/plain")
	hr.RemoteAddr = f.ip + ":1"
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, hr)
	wantError(t, rec.Result(), http.StatusUnsupportedMediaType, "unsupported_media_type")
}

func TestRoutesRegistry(t *testing.T) {
	want := map[string]httpapi.Policy{
		"GET /api/health":       {Public: true},
		"POST /api/auth/login":  {Public: true},
		"POST /api/auth/totp":   {Public: true},
		"POST /api/auth/enroll": {Public: true},
		"POST /api/auth/stepup": {Perm: rbac.PermSelf},
		"POST /api/auth/logout": {Perm: rbac.PermSelf},
		"GET /api/auth/me":      {Perm: rbac.PermSelf},
	}
	got := map[string]httpapi.Policy{}
	for _, r := range httpapi.Routes() {
		got[r.Method+" "+r.Pattern] = r.Policy
	}
	for k, p := range want {
		if g, ok := got[k]; !ok || g != p {
			t.Errorf("route %s: got %+v (present %v), want %+v", k, g, ok, p)
		}
	}
}
