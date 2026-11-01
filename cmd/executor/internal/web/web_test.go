package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/config"
	"github.com/beekamai/network-scheme/cmd/executor/internal/confirm"
	"github.com/beekamai/network-scheme/internal/install"
	"github.com/beekamai/network-scheme/internal/pki"
	"github.com/beekamai/network-scheme/internal/testdb"
)

func TestMain(m *testing.M) { testdb.Main(m) }

const (
	executorOrigin = "https://nms.test:8443"
	panelOrigin    = "https://nms.test"
	wantCSP        = "default-src 'self'; script-src https://nms.test:8443/assets/; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
		"frame-ancestors https://nms.test; frame-src 'none'; form-action 'none'; base-uri 'none'; object-src 'none'"
)

/* certs are the files of one test PKI: the internal CA, the executor's server certificate and client certificates. */
type certs struct {
	dir     string
	roots   *x509.CertPool
	clients map[string]tls.Certificate /* gateway, api (same CA, CN api), foreign (other CA, CN gateway), server (same CA, CN gateway, serverAuth) */
}

func newCerts(t *testing.T) *certs {
	t.Helper()
	dir := t.TempDir()
	ca, caKey, err := pki.NewCA("test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	other, otherKey, err := pki.NewCA("other CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv, srvKey, err := pki.IssueServerCert(ca, caKey, []string{"executor"}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"ca.crt": ca, "executor.crt": srv, "executor.key": srvKey} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c := &certs{dir: dir, roots: x509.NewCertPool(), clients: map[string]tls.Certificate{}}
	c.roots.AppendCertsFromPEM(ca)
	issue := func(name string, crt, key []byte, err error) {
		if err != nil {
			t.Fatal(err)
		}
		pair, err := tls.X509KeyPair(crt, key)
		if err != nil {
			t.Fatal(err)
		}
		c.clients[name] = pair
	}
	crt, key, err := pki.IssueClientCert(ca, caKey, "gateway", time.Hour)
	issue("gateway", crt, key, err)
	crt, key, err = pki.IssueClientCert(ca, caKey, "api", time.Hour)
	issue("api", crt, key, err)
	crt, key, err = pki.IssueClientCert(other, otherKey, "gateway", time.Hour)
	issue("foreign", crt, key, err)
	crt, key, err = pki.IssueServerCert(ca, caKey, []string{"gateway"}, nil, time.Hour)
	issue("server", crt, key, err)
	return c
}

func (c *certs) file(name string) string { return filepath.Join(c.dir, name) }

/* spki is the pin of a client certificate. */
func spki(t *testing.T, cert tls.Certificate) []byte {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return s[:]
}

/* fakeAuth records what reaches authz and answers with err (nil: the user of the ticket "user-<id>"). */
type fakeAuth struct {
	mu    sync.Mutex
	calls []authz.Request
	err   error
}

func (f *fakeAuth) TicketUser(tok string) (int64, bool) {
	var id int64
	_, err := fmt.Sscanf(tok, "user-%d", &id)
	return id, err == nil
}

func (f *fakeAuth) Identify(_ context.Context, req authz.Request) (authz.Decision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, req)
	if f.err != nil {
		return authz.Decision{}, f.err
	}
	id, _ := f.TicketUser(req.Ticket)
	return authz.Decision{UserID: id, Username: "u"}, nil
}

func (f *fakeAuth) n() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeAuth) set(err error) {
	f.mu.Lock()
	f.err = err
	f.mu.Unlock()
}

func (f *fakeAuth) call(i int) authz.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[i]
}

/* fixedNow is the limiters' clock in the tests. */
var fixedNow = time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)

/* fakeConfirm issues and confirms in memory; Confirm answers with err when set. */
type fakeConfirm struct {
	mu     sync.Mutex
	issued []confirm.Challenge
	calls  []authz.Request
	err    error
}

func (f *fakeConfirm) Issue(user int64, _ authz.Need, d confirm.Description) (confirm.Challenge, error) {
	h, err := d.Hash()
	if err != nil {
		return confirm.Challenge{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	c := confirm.Challenge{ID: fmt.Sprintf("c%d", len(f.issued)), Action: d.Action, H: h, Description: d, User: user, Expires: time.Now().Add(time.Minute)}
	f.issued = append(f.issued, c)
	return c, nil
}

/* counts returns how many challenges were issued and how many confirmations asked. */
func (f *fakeConfirm) counts() (issued, calls int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.issued), len(f.calls)
}

func (f *fakeConfirm) call(i int) authz.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[i]
}

func (f *fakeConfirm) Confirm(_ context.Context, id string, h []byte, req authz.Request) (confirm.Challenge, authz.Decision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, req)
	if f.err != nil {
		return confirm.Challenge{}, authz.Decision{}, f.err
	}
	for _, c := range f.issued {
		if c.ID == id && bytes.Equal(c.H[:], h) {
			return c, authz.Decision{UserID: c.User}, nil
		}
	}
	return confirm.Challenge{}, authz.Decision{}, authz.ErrDenied
}

/* testAction is the one action of the tests: its description repeats the "device" param. */
var testAction = Action{
	Describe: func(_ context.Context, _ authz.Decision, params json.RawMessage) (authz.Need, confirm.Description, error) {
		var p struct{ Device string }
		if err := json.Unmarshal(params, &p); err != nil || p.Device == "" {
			return authz.Need{}, confirm.Description{}, errors.New("no device")
		}
		return authz.Need{Kind: "write-admin"}, confirm.Description{Action: "test.echo", Fields: []confirm.Field{{Key: "device", Value: p.Device}}}, nil
	},
	Run: func(_ context.Context, c confirm.Challenge, _ authz.Decision) (any, error) {
		return c.Description.Fields[0].Value, nil
	},
}

type harness struct {
	certs   *certs
	srv     *Server
	auth    *fakeAuth
	conf    *fakeConfirm
	addr    string
	enabled bool
	mu      sync.Mutex
}

func (h *harness) state() (bool, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.enabled, false
}

func (h *harness) setEnabled(on bool) {
	h.mu.Lock()
	h.enabled = on
	h.mu.Unlock()
}

/* start serves a Server with fakes on a loopback listener until the test ends; mod adjusts the configuration first. */
func start(t *testing.T, mod func(*Config)) *harness {
	t.Helper()
	return startWith(t, newCerts(t), mod)
}

/* startWith is start over given certificates. */
func startWith(t *testing.T, c *certs, mod func(*Config)) *harness {
	t.Helper()
	h := &harness{certs: c, auth: &fakeAuth{}, conf: &fakeConfirm{}, enabled: true}
	cfg := Config{CertFile: h.certs.file("executor.crt"), KeyFile: h.certs.file("executor.key"), ClientCAFile: h.certs.file("ca.crt"),
		ExecutorOrigin: executorOrigin, PanelOrigin: panelOrigin, Auth: h.auth, Confirm: h.conf, State: h.state,
		Actions: map[string]Action{"test.echo": testAction, "test.liar": liarAction}, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return fixedNow }} /* a stopped clock: no bucket refills during a test */
	if mod != nil {
		mod(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.srv = srv
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.addr = ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	return h
}

/* client is an HTTP client presenting the named client certificate ("" none). */
func (h *harness) client(name string) *http.Client {
	cfg := &tls.Config{RootCAs: h.certs.roots, ServerName: "executor", MinVersion: tls.VersionTLS12}
	if name != "" {
		cfg.Certificates = []tls.Certificate{h.certs.clients[name]}
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", h.addr)
		},
		TLSClientConfig: cfg, DisableKeepAlives: true,
		/* An oversized body waits for the answer instead of racing the server closing the connection. */
		ExpectContinueTimeout: 5 * time.Second,
	}}
}

/* hdr are the headers the gateway adds to every request; tests change them per call. */
func hdr(kv ...string) map[string][]string {
	m := map[string][]string{"X-Forwarded-For": {"192.0.2.10"}, "Origin": {executorOrigin}, "Content-Type": {"application/json"}}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			delete(m, kv[i])
		} else {
			m[kv[i]] = []string{kv[i+1]}
		}
	}
	return m
}

type answer struct {
	status int
	header http.Header
	body   string
	code   string
}

func (h *harness) do(t *testing.T, method, path, body string, headers map[string][]string) answer {
	t.Helper()
	req, err := http.NewRequest(method, "https://executor"+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "nms.test:8443" /* what the gateway passes on: the browser's Host */
	for k, v := range headers {
		req.Header[k] = v
	}
	if len(body) > int(maxBody) {
		req.Header.Set("Expect", "100-continue")
	}
	resp, err := h.client("gateway").Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	var e errorBody
	_ = json.Unmarshal(b, &e)
	return answer{resp.StatusCode, resp.Header, string(b), e.Error.Code}
}

func issueBody(tok string) string {
	return `{"ticket":"` + tok + `","action":"test.echo","params":{"device":"sw1"}}`
}

/* Only the gateway's certificate opens a session: none, another CN, another CA, a serverAuth one, TLS 1.2 — refused. */
func TestOnlyTheGatewayCertificate(t *testing.T) {
	h := start(t, nil)
	get := func(c *http.Client) error {
		req, _ := http.NewRequest(http.MethodGet, "https://executor/x/status", nil)
		req.Host = "nms.test:8443"
		req.Header.Set("X-Forwarded-For", "192.0.2.10")
		resp, err := c.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}
	for _, name := range []string{"", "api", "foreign", "server"} {
		if err := get(h.client(name)); err == nil {
			t.Errorf("client certificate %q was served", name)
		}
	}
	tls12 := h.client("gateway")
	tls12.Transport.(*http.Transport).TLSClientConfig.MaxVersion = tls.VersionTLS12
	if err := get(tls12); err == nil {
		t.Error("TLS 1.2 was served")
	}
	if err := get(h.client("gateway")); err != nil {
		t.Fatalf("the gateway: %v", err)
	}

	/* With a pin, only the pinned key: the same CA and CN with another key is refused. */
	if err := get(start(t, func(c *Config) { c.GatewaySPKI = make([]byte, 32) }).client("gateway")); err == nil {
		t.Error("a gateway certificate off the pin was served")
	}
	c := newCerts(t)
	pinned := startWith(t, c, func(cfg *Config) { cfg.GatewaySPKI = spki(t, c.clients["gateway"]) })
	if err := get(pinned.client("gateway")); err != nil {
		t.Errorf("the pinned gateway: %v", err)
	}
}

/* The server does not start without its certificate, key or client CA, or with a CA file holding no certificate. */
func TestNewRefusesMissingFiles(t *testing.T) {
	c := newCerts(t)
	notPEM := filepath.Join(c.dir, "garbage")
	if err := os.WriteFile(notPEM, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := Config{CertFile: c.file("executor.crt"), KeyFile: c.file("executor.key"), ClientCAFile: c.file("ca.crt"),
		ExecutorOrigin: executorOrigin, PanelOrigin: panelOrigin, Auth: &fakeAuth{}, Confirm: &fakeConfirm{},
		State: func() (bool, bool) { return true, false }, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if _, err := New(base); err != nil {
		t.Fatalf("complete configuration: %v", err)
	}
	for name, mod := range map[string]func(*Config){
		"no certificate": func(c *Config) { c.CertFile = filepath.Join(c.CertFile, "missing") },
		"no key":         func(c *Config) { c.KeyFile = notPEM },
		"no client CA":   func(c *Config) { c.ClientCAFile = filepath.Join(filepath.Dir(c.ClientCAFile), "missing") },
		"CA not PEM":     func(c *Config) { c.ClientCAFile = notPEM },
		"short pin":      func(c *Config) { c.GatewaySPKI = []byte{1} },
		"no origin":      func(c *Config) { c.ExecutorOrigin = "" },
		"no authorizer":  func(c *Config) { c.Auth = nil },
	} {
		cfg := base
		mod(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: started", name)
		}
	}
}

/* The route table is exactly status and the two confirmation routes: no host-only operation exists on :8443. */
func TestRouteTableHasNoHostOnlyRoutes(t *testing.T) {
	h := start(t, nil)
	got := h.srv.Routes()
	want := []string{"GET /x/status", "POST /x/confirm/issue", "POST /x/confirm"}
	if !slices.Equal(got, want) {
		t.Fatalf("routes = %v, want %v", got, want)
	}
	for _, r := range got {
		for _, word := range []string{"enroll", "grant", "revoke", "unlock", "freeze", "policy", "reset", "enable", "disable", "model", "registry", "audit"} {
			if strings.Contains(strings.ToLower(r), word) {
				t.Errorf("route %q looks like a host-only operation (%s)", r, word)
			}
		}
	}
	for _, p := range []string{"/x/freeze", "/x/unlock", "/x/enroll", "/x/grant", "/x/policy", "/x/registry/reset", "/api/auth/login", "/"} {
		for _, m := range []string{http.MethodGet, http.MethodPost} {
			if a := h.do(t, m, p, "{}", hdr()); a.status != http.StatusNotFound {
				t.Errorf("%s %s = %d, want 404", m, p, a.status)
			}
		}
	}
}

/* checkHeaders insists the security headers are on an answer, once each, and no cookie is set. */
func checkHeaders(t *testing.T, what string, h http.Header) {
	t.Helper()
	for k, v := range map[string]string{
		"Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
		"Content-Security-Policy": wantCSP, "Referrer-Policy": "no-referrer", "Cross-Origin-Resource-Policy": "same-origin",
		"Cross-Origin-Opener-Policy": "same-origin",
	} {
		if got := h.Values(k); len(got) != 1 || got[0] != v {
			t.Errorf("%s: %s = %q, want %q", what, k, got, v)
		}
	}
	for _, k := range []string{"Set-Cookie", "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"} {
		if v := h.Values(k); len(v) != 0 {
			t.Errorf("%s: %s = %q", what, k, v)
		}
	}
}

/* Every answer, errors included (400, 403, 404, 405, 413, 415, 423, 429, 503), carries the headers. */
func TestHeadersOnEveryAnswer(t *testing.T) {
	h := start(t, nil)
	big := `{"ticket":"` + strings.Repeat("a", int(maxBody)) + `"}`
	for _, c := range []struct {
		what, method, path, body string
		headers                  map[string][]string
		status                   int
	}{
		{"status", http.MethodGet, "/x/status", "", hdr("Origin", ""), 200},
		{"bad client ip", http.MethodGet, "/x/status", "", hdr("X-Forwarded-For", "nope"), 400},
		{"origin", http.MethodPost, "/x/confirm", "{}", hdr("Origin", panelOrigin), 403},
		{"not found", http.MethodGet, "/x/nope", "", hdr(), 404},
		{"method", http.MethodGet, "/x/confirm", "", hdr(), 405},
		{"too large", http.MethodPost, "/x/confirm/issue", big, hdr(), 413},
		{"media type", http.MethodPost, "/x/confirm/issue", issueBody("user-1"), hdr("Content-Type", "text/plain"), 415},
		{"denied", http.MethodPost, "/x/confirm/issue", issueBody("user-1"), hdr(), 403},
	} {
		if c.what == "denied" {
			h.auth.set(authz.ErrDenied)
		}
		a := h.do(t, c.method, c.path, c.body, c.headers)
		if a.status != c.status {
			t.Errorf("%s: %d %s, want %d", c.what, a.status, a.body, c.status)
		}
		checkHeaders(t, c.what, a.header)
	}
	h.auth.set(&authz.LockedError{Until: time.Now()})
	a := h.do(t, http.MethodPost, "/x/confirm/issue", issueBody("user-2"), hdr())
	if a.status != http.StatusLocked {
		t.Errorf("locked: %d", a.status)
	}
	checkHeaders(t, "locked", a.header)
	for range int(ipBurst) + 1 {
		a = h.do(t, http.MethodGet, "/x/status", "", hdr("X-Forwarded-For", "192.0.2.99"))
	}
	if a.status != http.StatusTooManyRequests || a.header.Get("Retry-After") == "" {
		t.Errorf("rate limited: %d %q", a.status, a.header.Get("Retry-After"))
	}
	checkHeaders(t, "rate limited", a.header)
	h.setEnabled(false)
	a = h.do(t, http.MethodPost, "/x/confirm", "{}", hdr())
	if a.status != http.StatusServiceUnavailable || a.code != "executor_disabled" {
		t.Errorf("disabled: %d %s", a.status, a.body)
	}
	checkHeaders(t, "disabled", a.header)
}

/*
The Cookie header is never read: the handler removes it before anything
else, and requests that differ only in their cookies reach authz the same
and get the same answer.
*/
func TestCookieIgnored(t *testing.T) {
	h := start(t, nil)
	r := httptest.NewRequest(http.MethodGet, "/x/status", nil)
	r.Host = "nms.test"
	r.Header.Set("Cookie", "nms_session=forged; x=1")
	r.Header.Set("X-Forwarded-For", "192.0.2.1")
	w := httptest.NewRecorder()
	h.srv.ServeHTTP(w, r)
	if r.Header.Get("Cookie") != "" || w.Code != http.StatusOK {
		t.Fatalf("Cookie left on the request (%q), status %d", r.Header.Get("Cookie"), w.Code)
	}
	var answers []string
	for _, cookie := range []string{"", "nms_session=forged", "__Host-nms_session=x; csrf=y"} {
		hd := hdr()
		if cookie != "" {
			hd["Cookie"] = []string{cookie}
		}
		a := h.do(t, http.MethodPost, "/x/confirm/issue", issueBody("user-7"), hd)
		var ch challengeBody
		_ = json.Unmarshal([]byte(a.body), &ch)
		ch.ID, ch.Expires = "", time.Time{} /* fresh per challenge */
		answers = append(answers, fmt.Sprint(a.status, ch))
	}
	if answers[0] != answers[1] || answers[0] != answers[2] {
		t.Errorf("answers differ by cookie: %q", answers)
	}
	h.auth.mu.Lock()
	defer h.auth.mu.Unlock()
	for _, c := range h.auth.calls[1:] {
		if fmt.Sprint(c) != fmt.Sprint(h.auth.calls[0]) {
			t.Errorf("authz saw different requests: %+v vs %+v", c, h.auth.calls[0])
		}
	}
}

/* An Origin other than the executor's is refused, and a POST must carry one; a GET from the same origin may omit it. */
func TestOriginChecked(t *testing.T) {
	h := start(t, nil)
	for name, hd := range map[string]map[string][]string{
		"panel origin": hdr("Origin", panelOrigin),
		"null origin":  hdr("Origin", "null"),
		"other port":   hdr("Origin", "https://nms.test:9443"),
		"http":         hdr("Origin", "http://nms.test:8443"),
		"no origin":    hdr("Origin", ""),
		"two origins": func() map[string][]string {
			m := hdr()
			m["Origin"] = []string{executorOrigin, executorOrigin}
			return m
		}(),
		"trailing slash":  hdr("Origin", executorOrigin+"/"),
		"case difference": hdr("Origin", "https://NMS.test:8443"),
	} {
		if a := h.do(t, http.MethodPost, "/x/confirm/issue", issueBody("user-1"), hd); a.status != http.StatusForbidden || a.code != "origin" {
			t.Errorf("%s: %d %s", name, a.status, a.body)
		}
	}
	if n := h.auth.n(); n != 0 {
		t.Errorf("%d refused-origin requests reached authz", n)
	}
	if a := h.do(t, http.MethodGet, "/x/status", "", hdr("Origin", panelOrigin)); a.status != http.StatusForbidden {
		t.Errorf("GET with a foreign Origin: %d", a.status)
	}
	if a := h.do(t, http.MethodGet, "/x/status", "", hdr("Origin", "")); a.status != http.StatusOK {
		t.Errorf("GET without Origin: %d", a.status)
	}
	if a := h.do(t, http.MethodPost, "/x/confirm/issue", issueBody("user-1"), hdr()); a.status != http.StatusOK {
		t.Errorf("the executor origin: %d %s", a.status, a.body)
	}
}

/* The client's address is the one X-Forwarded-For value the gateway wrote; anything else is refused before authz. */
func TestClientIPFromGatewayHeaderOnly(t *testing.T) {
	h := start(t, nil)
	for name, hd := range map[string]map[string][]string{
		"missing": hdr("X-Forwarded-For", ""),
		"a list":  hdr("X-Forwarded-For", "6.6.6.6, 192.0.2.10"),
		"two lines": func() map[string][]string {
			m := hdr()
			m["X-Forwarded-For"] = []string{"6.6.6.6", "192.0.2.10"}
			return m
		}(),
		"with port": hdr("X-Forwarded-For", "192.0.2.10:443"),
		"a name":    hdr("X-Forwarded-For", "evil.example"),
		"zone":      hdr("X-Forwarded-For", "fe80::1%eth0"),
	} {
		if a := h.do(t, http.MethodPost, "/x/confirm/issue", issueBody("user-1"), hd); a.status != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, a.status, a.body)
		}
	}
	if n := h.auth.n(); n != 0 {
		t.Fatalf("%d requests without a gateway address reached authz", n)
	}
	hd := hdr("X-Forwarded-For", "::ffff:198.51.100.4", "User-Agent", "test-agent/1")
	hd["X-Real-Ip"] = []string{"6.6.6.6"}
	if a := h.do(t, http.MethodPost, "/x/confirm/issue", issueBody("user-1"), hd); a.status != http.StatusOK {
		t.Fatalf("%d %s", a.status, a.body)
	}
	if c := h.auth.call(0); c.IP != "198.51.100.4" || c.UA != "test-agent/1" {
		t.Errorf("authz got IP %q UA %q", c.IP, c.UA)
	}
}

/* Bodies: JSON only, at most maxBody bytes, no unknown fields, nothing after the value. */
func TestBodyChecks(t *testing.T) {
	h := start(t, nil)
	for name, c := range map[string]struct {
		body, ctype string
		status      int
	}{
		"form":          {"ticket=user-1", "application/x-www-form-urlencoded", 415},
		"no type":       {issueBody("user-1"), "", 415},
		"unknown field": {`{"ticket":"user-1","action":"test.echo","params":{"device":"sw1"},"user":1}`, "application/json", 400},
		"trailing":      {issueBody("user-1") + `{}`, "application/json", 400},
		"not json":      {`{"ticket":`, "application/json", 400},
		"too large":     {`{"ticket":"` + strings.Repeat("a", int(maxBody)) + `"}`, "application/json", 413},
		"long ticket":   {issueBody(strings.Repeat("a", 2000)), "application/json", 400},
		"bad params":    {`{"ticket":"user-1","action":"test.echo","params":{}}`, "application/json", 400},
		"bad h":         {`{"ticket":"user-1","challenge_id":"c0","h":"zz","code":"1"}`, "application/json", 400},
	} {
		path := "/x/confirm/issue"
		if name == "bad h" {
			path = "/x/confirm"
		}
		if a := h.do(t, http.MethodPost, path, c.body, hdr("Content-Type", c.ctype)); a.status != c.status {
			t.Errorf("%s: %d %s, want %d", name, a.status, a.body, c.status)
		}
	}
	/* A body sent in chunks (no Content-Length) over the bound is cut off too (handler called directly: no write race). */
	req := httptest.NewRequest(http.MethodPost, "/x/confirm/issue", io.MultiReader(strings.NewReader(`{"ticket":"`),
		strings.NewReader(strings.Repeat("a", int(maxBody))), strings.NewReader(`"}`)))
	for k, v := range hdr() {
		req.Header[k] = v
	}
	req.ContentLength = -1
	req.Host = "nms.test:8443"
	w := httptest.NewRecorder()
	h.srv.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("chunked body over the bound: %d", w.Code)
	}
}

/*
The per-IP, per-user and global limits refuse before authz: a refused
request never reaches it (each that does writes an audit row and may take
the registry lock).
*/
func TestRateLimitsBeforeAuthz(t *testing.T) {
	h := start(t, nil)
	/* One user from many addresses: the user's burst, then 429 without authz. */
	for i := range int(userBurst) + 5 {
		a := h.do(t, http.MethodPost, "/x/confirm/issue", issueBody("user-42"), hdr("X-Forwarded-For", fmt.Sprintf("10.0.%d.1", i)))
		if (i < int(userBurst)) != (a.status == http.StatusOK) {
			t.Fatalf("request %d of one user: %d %s", i+1, a.status, a.body)
		}
	}
	if n := h.auth.n(); n != int(userBurst) {
		t.Fatalf("authz saw %d requests of one user, want %d", n, int(userBurst))
	}
	/* One address, unverifiable tickets (no user to key on): the IP burst, then 429 without authz. */
	before := h.auth.n()
	for i := range int(ipBurst) + 5 {
		a := h.do(t, http.MethodPost, "/x/confirm/issue", issueBody(fmt.Sprintf("forged-%d", i)), hdr("X-Forwarded-For", "203.0.113.9"))
		if (i < int(ipBurst)) != (a.status != http.StatusTooManyRequests) {
			t.Fatalf("request %d of one address: %d", i+1, a.status)
		}
	}
	if n := h.auth.n() - before; n != int(ipBurst) {
		t.Fatalf("authz saw %d requests of one address, want %d", n, int(ipBurst))
	}
}

/* The global limit bounds what reaches authz from many addresses and users. */
func TestGlobalLimitBeforeAuthz(t *testing.T) {
	old := globalBurst
	globalBurst = 3
	t.Cleanup(func() { globalBurst = old })
	h := start(t, nil)
	for i := range 6 {
		h.do(t, http.MethodPost, "/x/confirm/issue", issueBody(fmt.Sprintf("user-%d", 100+i)), hdr("X-Forwarded-For", fmt.Sprintf("10.1.%d.1", i)))
	}
	if n := h.auth.n(); n != 3 {
		t.Fatalf("authz saw %d requests, want the global burst 3", n)
	}
}

/* Refusals map to HTTP answers: disabled and frozen 503, locked 423 with its end, unavailable 503, too many 429, denied 403. */
func TestRefusalMapping(t *testing.T) {
	until := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		err    error
		status int
		body   string
	}{
		{authz.ErrDisabled, 503, `{"error":{"code":"executor_disabled"}}`},
		{authz.ErrFrozen, 503, `{"error":{"code":"frozen"}}`},
		{&authz.LockedError{Until: until}, 423, `{"error":{"code":"locked","until":"2026-11-01T12:00:00Z"}}`},
		{&authz.LockedError{Permanent: true}, 423, `{"error":{"code":"locked","permanent":true}}`},
		{authz.ErrUnavailable, 503, `{"error":{"code":"unavailable"}}`},
		{confirm.ErrTooMany, 429, `{"error":{"code":"too_many_challenges"}}`},
		{authz.ErrDenied, 403, `{"error":{"code":"denied"}}`},
		{errors.New("something else"), 403, `{"error":{"code":"denied"}}`},
	} {
		w := httptest.NewRecorder()
		refused(w, c.err)
		if w.Code != c.status || strings.TrimSpace(w.Body.String()) != c.body {
			t.Errorf("%v: %d %s, want %d %s", c.err, w.Code, w.Body.String(), c.status, c.body)
		}
	}
}

/* Disabled by the host's policy, everything under /x/ but the status answers 503 executor_disabled before authz. */
func TestDisabledAnswers503(t *testing.T) {
	h := start(t, nil)
	h.setEnabled(false)
	for _, p := range []string{"/x/confirm/issue", "/x/confirm", "/x/sessions", "/x/anything"} {
		if a := h.do(t, http.MethodPost, p, issueBody("user-1"), hdr()); a.status != http.StatusServiceUnavailable || a.code != "executor_disabled" {
			t.Errorf("POST %s: %d %s", p, a.status, a.body)
		}
	}
	if n := h.auth.n(); n != 0 {
		t.Errorf("%d requests reached authz while disabled", n)
	}
	if a := h.do(t, http.MethodGet, "/x/status", "", hdr()); a.status != http.StatusOK || strings.TrimSpace(a.body) != `{"enabled":false,"frozen":false}` {
		t.Errorf("status while disabled: %d %s", a.status, a.body)
	}
}

/* Issue goes through Identify and the action's own description; confirm runs the action on what H covers. */
func TestIssueAndConfirm(t *testing.T) {
	h := start(t, nil)
	if a := h.do(t, http.MethodPost, "/x/confirm/issue", `{"ticket":"user-5","action":"device.delete","params":{}}`, hdr()); a.status != http.StatusNotFound || h.auth.n() != 0 {
		t.Fatalf("an action outside the table: %d %s (authz calls %d)", a.status, a.body, h.auth.n())
	}
	a := h.do(t, http.MethodPost, "/x/confirm/issue", issueBody("user-5"), hdr())
	var ch challengeBody
	if err := json.Unmarshal([]byte(a.body), &ch); err != nil || a.status != http.StatusOK {
		t.Fatalf("issue: %d %s", a.status, a.body)
	}
	want, _ := confirm.Description{Action: "test.echo", Fields: []confirm.Field{{Key: "device", Value: "sw1"}}}.Hash()
	if ch.H != hex.EncodeToString(want[:]) || ch.Action != "test.echo" || len(ch.Fields) != 1 || ch.Fields[0] != (field{"device", "sw1"}) {
		t.Fatalf("challenge: %+v", ch)
	}
	if c := h.auth.call(0); c.Action != "confirm.issue" || c.Object != "test.echo" || c.Code != "" {
		t.Errorf("Identify got %+v", c)
	}
	wrong := strings.Repeat("00", 32)
	if a := h.do(t, http.MethodPost, "/x/confirm", `{"ticket":"user-5","challenge_id":"`+ch.ID+`","h":"`+wrong+`","code":"123456"}`, hdr()); a.status != http.StatusForbidden {
		t.Errorf("another H: %d %s", a.status, a.body)
	}
	a = h.do(t, http.MethodPost, "/x/confirm", `{"ticket":"user-5","challenge_id":"`+ch.ID+`","h":"`+ch.H+`","code":"123456"}`, hdr())
	if a.status != http.StatusOK || strings.TrimSpace(a.body) != `{"action":"test.echo","result":"sw1"}` {
		t.Errorf("confirm: %d %s", a.status, a.body)
	}
	if c := h.conf.call(1); c.Ticket != "user-5" || c.Code != "123456" || c.IP != "192.0.2.10" {
		t.Errorf("Confirm got %+v", c)
	}
}

/* A client that sends its headers slowly (or no TLS handshake at all) is cut off after the header timeout. */
func TestSlowClientsCutOff(t *testing.T) {
	old := readHeaderTimeout
	readHeaderTimeout = 300 * time.Millisecond
	t.Cleanup(func() { readHeaderTimeout = old })
	h := start(t, nil)
	closed := func(c net.Conn) bool {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err := io.ReadAll(c)
		var ne net.Error
		return !errors.As(err, &ne) || !ne.Timeout()
	}
	raw, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	if !closed(raw) {
		t.Error("a connection without a handshake was kept open")
	}
	c, err := tls.Dial("tcp", h.addr, &tls.Config{RootCAs: h.certs.roots, ServerName: "executor", MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{h.certs.clients["gateway"]}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("GET /x/status HTTP/1.1\r\nHost: executor\r\nX-Forwarded-For: 192.0.2.1\r\n")); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	if !closed(c) || time.Since(t0) > 3*time.Second {
		t.Error("a request whose headers never end was kept open")
	}
}

/*
The executor's own CSP is exactly the gateway's for the executor origin, for
the origins nmsctl install renders (whichever header wins, they agree), and
neither allows unsafe-inline or unsafe-eval.
*/
func TestCSPMatchesTheGateway(t *testing.T) {
	out, err := install.Render(install.RenderInput{PublicHost: "nms.example.org", ExecutorPort: 9000, ImageTag: "1", APIImage: "a", GatewayImage: "g"})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "executor.yaml")
	if err := os.WriteFile(p, out["config/executor.yaml"], 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	c := newCerts(t)
	s, err := New(Config{CertFile: c.file("executor.crt"), KeyFile: c.file("executor.key"), ClientCAFile: c.file("ca.crt"),
		ExecutorOrigin: cfg.ExecutorOrigin, PanelOrigin: cfg.PanelOrigin, Auth: &fakeAuth{}, Confirm: &fakeConfirm{},
		State: func() (bool, bool) { return true, false }, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	_, snippet, _ := strings.Cut(string(out["Caddyfile"]), "(executor_headers) {")
	if !strings.Contains(snippet, `Content-Security-Policy "`+s.csp+`"`) {
		t.Errorf("the executor's CSP %q is not the gateway's", s.csp)
	}
	if strings.Contains(s.csp, "unsafe-") || !strings.Contains(s.csp, "frame-ancestors https://nms.example.org;") {
		t.Errorf("CSP %q", s.csp)
	}
}

/* The TLS settings themselves (each layer is also covered by a handshake test; this catches one weakened alone). */
func TestTLSSettings(t *testing.T) {
	h := start(t, nil)
	c := h.srv.TLSConfig()
	if c.MinVersion != tls.VersionTLS13 || c.MaxVersion != tls.VersionTLS13 || c.ClientAuth != tls.RequireAndVerifyClientCert ||
		!c.SessionTicketsDisabled || !slices.Equal(c.NextProtos, []string{"http/1.1"}) || c.ClientCAs == nil || c.InsecureSkipVerify {
		t.Errorf("TLS config: min %x max %x client auth %v tickets off %v protos %v", c.MinVersion, c.MaxVersion, c.ClientAuth,
			c.SessionTicketsDisabled, c.NextProtos)
	}
	leaf, err := x509.ParseCertificate(h.certs.clients["gateway"].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	/* A gateway leaf the handshake did not verify against the CA is refused all the same. */
	if err := gatewayOnly(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}, nil); err == nil {
		t.Error("an unverified chain was accepted")
	}
	if err := gatewayOnly(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}, nil); err != nil {
		t.Errorf("the verified gateway leaf: %v", err)
	}
}

/* IPv6 clients share one per-IP bucket per /64; IPv4 clients have one each. */
func TestIPv6LimitedPerPrefix(t *testing.T) {
	h := start(t, nil)
	for i := range int(ipBurst) + 1 {
		a := h.do(t, http.MethodGet, "/x/status", "", hdr("X-Forwarded-For", fmt.Sprintf("2001:db8:1:2::%x", i+1)))
		if (i < int(ipBurst)) != (a.status == http.StatusOK) {
			t.Fatalf("request %d from one /64: %d", i+1, a.status)
		}
	}
	if a := h.do(t, http.MethodGet, "/x/status", "", hdr("X-Forwarded-For", "2001:db8:1:3::1")); a.status != http.StatusOK {
		t.Errorf("another /64: %d", a.status)
	}
	if ipKey("192.0.2.1") != "192.0.2.1" || ipKey("2001:db8::1") != "2001:db8::/64" {
		t.Errorf("keys %q %q", ipKey("192.0.2.1"), ipKey("2001:db8::1"))
	}
}

/* liarAction describes another action than its own name: issuing must refuse it. */
var liarAction = Action{
	Describe: func(context.Context, authz.Decision, json.RawMessage) (authz.Need, confirm.Description, error) {
		return authz.Need{Kind: "write-admin"}, confirm.Description{Action: "test.echo", Fields: []confirm.Field{{Key: "device", Value: "x"}}}, nil
	},
	Run: testAction.Run,
}

/* An action whose description names another action gets no challenge (confirm would run the other one). */
func TestIssueRefusesMislabelledDescription(t *testing.T) {
	h := start(t, nil)
	a := h.do(t, http.MethodPost, "/x/confirm/issue", `{"ticket":"user-1","action":"test.liar","params":{}}`, hdr())
	if n, _ := h.conf.counts(); a.status != http.StatusInternalServerError || n != 0 {
		t.Fatalf("mislabelled description: %d %s, %d challenges", a.status, a.body, n)
	}
}

/* A challenge id longer than any issued one is refused before confirm. */
func TestConfirmBoundsChallengeID(t *testing.T) {
	h := start(t, nil)
	body := `{"ticket":"user-1","challenge_id":"` + strings.Repeat("c", 65) + `","h":"` + strings.Repeat("00", 32) + `","code":"1"}`
	a := h.do(t, http.MethodPost, "/x/confirm", body, hdr())
	if _, n := h.conf.counts(); a.status != http.StatusBadRequest || n != 0 {
		t.Fatalf("65-character challenge id: %d %s, %d confirm calls", a.status, a.body, n)
	}
}

/* A Host other than the executor origin's is refused (421) before anything else; the port and case do not matter. */
func TestHostChecked(t *testing.T) {
	h := start(t, nil)
	for _, host := range []string{"executor", "10.0.0.1:8443", "nms.test.evil:8443", "api:8080", "",
		"[nms.test", "nms.test]", "[[nms.test]]", "]nms.test[", "[]nms.test"} {
		r := httptest.NewRequest(http.MethodGet, "/x/status", nil)
		r.Host = host
		r.Header.Set("X-Forwarded-For", "192.0.2.1")
		w := httptest.NewRecorder()
		h.srv.ServeHTTP(w, r)
		if w.Code != http.StatusMisdirectedRequest {
			t.Errorf("Host %q: %d", host, w.Code)
		}
		checkHeaders(t, "host "+host, w.Result().Header)
	}
	for _, host := range []string{"nms.test", "NMS.test:8443", "nms.test:9000", "[nms.test]"} {
		r := httptest.NewRequest(http.MethodGet, "/x/status", nil)
		r.Host = host
		r.Header.Set("X-Forwarded-For", "192.0.2.1")
		w := httptest.NewRecorder()
		h.srv.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("Host %q: %d", host, w.Code)
		}
	}
}

/* A body that never arrives is cut off by the read timeout; headers over the bound get 431. */
func TestSlowBodyAndLargeHeaders(t *testing.T) {
	old := readTimeout
	readTimeout = 500 * time.Millisecond
	t.Cleanup(func() { readTimeout = old })
	h := start(t, nil)
	c, err := tls.Dial("tcp", h.addr, &tls.Config{RootCAs: h.certs.roots, ServerName: "executor", MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{h.certs.clients["gateway"]}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("POST /x/confirm/issue HTTP/1.1\r\nHost: nms.test:8443\r\nX-Forwarded-For: 192.0.2.1\r\n" +
		"Origin: " + executorOrigin + "\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
	if _, err := io.ReadAll(c); err != nil {
		t.Fatalf("a body that never arrived kept the request open: %v", err)
	}
	hd := hdr()
	hd["X-Padding"] = []string{strings.Repeat("a", 2*maxHeader)}
	if a := h.do(t, http.MethodGet, "/x/status", "", hd); a.status != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("headers of %d bytes: %d", 2*maxHeader, a.status)
	}
}
