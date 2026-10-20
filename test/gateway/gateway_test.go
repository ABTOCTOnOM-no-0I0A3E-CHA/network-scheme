/*
Package gateway_test runs the rendered Caddyfile in an official Caddy
container in front of an "evil" upstream that impersonates a compromised api
and checks what reaches the browser.
*/
package gateway_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/beekamai/network-scheme/internal/install"
	"github.com/beekamai/network-scheme/internal/pki"
)

/* caddyImage is the same Caddy release the gateway image is built from. */
const caddyImage = "caddy:2.11.7-alpine@sha256:d8542f48d34a9cf4e4c11a478865229840e87e4c96ea3f439101f31a5d35f75f"

const publicHost = "nms.test"

/* evilCaddyfile answers every path like a compromised api trying to own the panel origin. */
const evilCaddyfile = `{
	admin off
	auto_https off
}
:8080 {
	header Content-Type "text/html"
	header Service-Worker-Allowed "/"
	header Set-Cookie "x=1"
	header Content-Security-Policy "script-src *"
	# Read the whole request body like the real api does, so gateway body limits trigger.
	@post method POST
	respond @post "{http.request.body}" 200
	respond "<script>navigator.serviceWorker.register('/api/evil')</script>" 200
}
`

var panelHeaders = map[string]string{
	"Content-Security-Policy": "default-src 'self'; script-src https://" + publicHost + "/assets/; style-src 'self'; img-src 'self' data:; " +
		"font-src 'self'; connect-src 'self'; frame-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'",
	"Strict-Transport-Security":    "max-age=31536000",
	"X-Content-Type-Options":       "nosniff",
	"Referrer-Policy":              "no-referrer",
	"Permissions-Policy":           "camera=(), microphone=(), geolocation=()",
	"Cross-Origin-Opener-Policy":   "same-origin",
	"Cross-Origin-Resource-Policy": "same-origin",
}

type stack struct {
	client *http.Client
	base   string
	bare   *stack /* same gateway without a reachable upstream */
}

var (
	once       sync.Once
	shared     *stack
	startErr   error
	containers []testcontainers.Container
	nw         *testcontainers.DockerNetwork
)

var errNoDocker = errors.New("docker daemon not reachable")

func TestMain(m *testing.M) {
	code := m.Run()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	for _, c := range containers {
		_ = c.Terminate(ctx)
	}
	if nw != nil {
		_ = nw.Remove(ctx)
	}
	cancel()
	os.Exit(code)
}

func gateway(t *testing.T) *stack {
	t.Helper()
	if testing.Short() {
		t.Skip("gateway: skipped in -short mode (needs Docker)")
	}
	once.Do(func() { shared, startErr = start() })
	if startErr != nil {
		if errors.Is(startErr, errNoDocker) {
			t.Skipf("gateway: Docker is unavailable: %v", startErr)
		}
		t.Fatalf("gateway: %v", startErr)
	}
	return shared
}

func start() (*stack, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	p, err := testcontainers.NewDockerProvider()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errNoDocker, err)
	}
	healthErr := p.Health(ctx)
	_ = p.Close()
	if healthErr != nil {
		return nil, fmt.Errorf("%w: %v", errNoDocker, healthErr)
	}

	caCert, caKey, err := pki.NewCA("nms gateway test CA", time.Hour)
	if err != nil {
		return nil, err
	}
	webCert, webKey, err := pki.IssueServerCert(caCert, caKey, []string{publicHost}, nil, time.Hour)
	if err != nil {
		return nil, err
	}
	rendered, err := install.Render(install.RenderInput{
		PublicHost: publicHost, ImageTag: "test", APIImage: "nms/api", GatewayImage: "nms/gateway",
	})
	if err != nil {
		return nil, err
	}

	nw, err = network.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("network: %w", err)
	}
	evil, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          caddyImage,
			Networks:       []string{nw.Name},
			NetworkAliases: map[string][]string{nw.Name: {"api"}},
			Files:          []testcontainers.ContainerFile{file("/etc/caddy/Caddyfile", []byte(evilCaddyfile))},
			WaitingFor:     wait.ForLog("serving initial configuration").WithStartupTimeout(time.Minute),
		},
		Started: true,
	})
	if evil != nil {
		containers = append(containers, evil)
	}
	if err != nil {
		return nil, fmt.Errorf("evil upstream: %w", err)
	}

	/* Fresh readers per container: a ContainerFile reader is consumed by the copy. */
	files := func() []testcontainers.ContainerFile {
		return []testcontainers.ContainerFile{
			file("/etc/caddy/Caddyfile", rendered["Caddyfile"]),
			file("/certs/web.crt", webCert),
			file("/certs/web.key", webKey),
			file("/srv/app/index.html", []byte("<!doctype html><title>nms</title>")),
			file("/srv/app/assets/app.js", []byte("console.log(1)")),
			file("/srv/keys/keys.json", []byte(`{"domains":[]}`)),
		}
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caCert) {
		return nil, errors.New("bad test CA")
	}
	s, err := startGateway(ctx, []string{nw.Name}, files(), roots)
	if err != nil {
		return nil, err
	}
	/* A second gateway on the default bridge, where the name "api" does not resolve. */
	if s.bare, err = startGateway(ctx, nil, files(), roots); err != nil {
		return nil, err
	}
	return s, nil
}

func startGateway(ctx context.Context, networks []string, files []testcontainers.ContainerFile, roots *x509.CertPool) (*stack, error) {
	gw, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        caddyImage,
			ExposedPorts: []string{"8443/tcp"},
			Networks:     networks,
			Files:        files,
			/* Log-based: the port probe dials the IPv6 loopback, which Docker Desktop on Windows may refuse. */
			WaitingFor: wait.ForLog("serving initial configuration").WithStartupTimeout(time.Minute),
		},
		Started: true,
	})
	if gw != nil {
		containers = append(containers, gw)
	}
	if err != nil {
		return nil, fmt.Errorf("gateway: %w", err)
	}

	host, err := gw.Host(ctx)
	if err != nil {
		return nil, err
	}
	if host == "localhost" {
		host = "127.0.0.1" /* avoid the IPv6 loopback, which Docker Desktop on Windows may not publish */
	}
	port, err := gw.MappedPort(ctx, "8443/tcp")
	if err != nil {
		return nil, err
	}
	target := net.JoinHostPort(host, port.Port())
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			/* The URL names publicHost for SNI and verification; the socket goes to the mapped port. */
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, "tcp", target)
			},
			TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &stack{client: client, base: "https://" + publicHost}, nil
}

func file(path string, content []byte) testcontainers.ContainerFile {
	return testcontainers.ContainerFile{Reader: strings.NewReader(string(content)), ContainerFilePath: path, FileMode: 0o644}
}

func (s *stack) get(t *testing.T, path string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	return s.do(t, http.MethodGet, path, nil, hdr)
}

func (s *stack) do(t *testing.T, method, path string, payload io.Reader, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, s.base+path, payload)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(body)
}

/* only asserts that header k is present exactly once with value want. */
func only(t *testing.T, h http.Header, k, want string) {
	t.Helper()
	if got := h.Values(k); len(got) != 1 || got[0] != want {
		t.Errorf("%s = %q, want exactly [%q]", k, got, want)
	}
}

func TestAPIResponsesForcedJSON(t *testing.T) {
	s := gateway(t)
	resp, _ := s.get(t, "/api/evil", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 from the upstream", resp.StatusCode)
	}
	only(t, resp.Header, "Content-Type", "application/json; charset=utf-8")
	only(t, resp.Header, "Content-Security-Policy", panelHeaders["Content-Security-Policy"])
	only(t, resp.Header, "X-Content-Type-Options", "nosniff")
	for _, h := range []string{"Service-Worker-Allowed", "Set-Cookie"} {
		if v := resp.Header.Values(h); len(v) > 0 {
			t.Errorf("%s leaked: %q", h, v)
		}
	}
}

func TestServiceWorkerRequestRejected(t *testing.T) {
	s := gateway(t)
	for _, path := range []string{"/", "/api/evil", "/api/auth/totp", "/assets/app.js", "/keys.json", "/sw.js"} {
		resp, _ := s.get(t, path, map[string]string{"Service-Worker": "script"})
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s with Service-Worker: script → %d, want 403", path, resp.StatusCode)
		}
	}
}

func TestPanelHeaders(t *testing.T) {
	s := gateway(t)
	resp, body := s.get(t, "/", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "<title>nms</title>") {
		t.Fatalf("GET / → %d %q, want index.html", resp.StatusCode, body)
	}
	for k, v := range panelHeaders {
		only(t, resp.Header, k, v)
	}
	var scriptSrc string
	for _, d := range strings.Split(resp.Header.Get("Content-Security-Policy"), ";") {
		if f := strings.Fields(d); len(f) > 0 && f[0] == "script-src" {
			scriptSrc = strings.Join(f[1:], " ")
		}
	}
	if scriptSrc != "https://"+publicHost+"/assets/" {
		t.Errorf("script-src = %q", scriptSrc)
	}

	/* SPA fallback and long-lived caching of hashed assets. */
	if resp, body := s.get(t, "/devices/42", nil); resp.StatusCode != http.StatusOK || !strings.Contains(body, "<title>nms</title>") {
		t.Errorf("SPA fallback → %d %q", resp.StatusCode, body)
	}
	resp, _ = s.get(t, "/assets/app.js", nil)
	only(t, resp.Header, "Cache-Control", "public, max-age=31536000, immutable")
	if resp, body := s.get(t, "/keys.json", nil); resp.StatusCode != http.StatusOK || body != `{"domains":[]}` {
		t.Errorf("/keys.json → %d %q", resp.StatusCode, body)
	}
}

func TestSetCookieAllowedOnlyForAuth(t *testing.T) {
	s := gateway(t)
	resp, _ := s.get(t, "/api/auth/totp", nil)
	only(t, resp.Header, "Set-Cookie", "x=1")
	only(t, resp.Header, "Content-Type", "application/json; charset=utf-8")
	for _, path := range []string{"/api/users", "/api/authx", "/api/auth"} {
		resp, _ := s.get(t, path, nil)
		if v := resp.Header.Values("Set-Cookie"); len(v) > 0 {
			t.Errorf("%s: Set-Cookie leaked: %q", path, v)
		}
	}
}

func panelHeadersOnce(t *testing.T, h http.Header) {
	t.Helper()
	for k, v := range panelHeaders {
		only(t, h, k, v)
	}
}

/* Errors raised by Caddy itself must carry the panel headers too. */
func TestErrorResponsesKeepPanelHeaders(t *testing.T) {
	s := gateway(t)

	t.Run("missing asset", func(t *testing.T) {
		resp, _ := s.get(t, "/assets/missing.js", nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", resp.StatusCode)
		}
		panelHeadersOnce(t, resp.Header)
	})

	t.Run("upstream unreachable", func(t *testing.T) {
		resp, body := s.bare.get(t, "/api/users", nil)
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("status = %d, want 502", resp.StatusCode)
		}
		panelHeadersOnce(t, resp.Header)
		only(t, resp.Header, "Content-Type", "application/json; charset=utf-8")
		if body != `{"error":{"code":"gateway_error","message":"Ошибка шлюза панели"}}` {
			t.Errorf("body = %q", body)
		}
	})

	t.Run("body over 1MB", func(t *testing.T) {
		big := strings.NewReader(strings.Repeat("a", 2<<20))
		resp, _ := s.do(t, http.MethodPost, "/api/users", big, map[string]string{"Content-Type": "application/json"})
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413", resp.StatusCode)
		}
		panelHeadersOnce(t, resp.Header)
		only(t, resp.Header, "Content-Type", "application/json; charset=utf-8")
	})
}
