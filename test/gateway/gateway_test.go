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
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	mobynet "github.com/moby/moby/api/types/network"
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
		"font-src 'self'; connect-src 'self'; frame-src https://" + publicHost + ":8443; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'",
	"Strict-Transport-Security":    "max-age=31536000",
	"X-Content-Type-Options":       "nosniff",
	"Referrer-Policy":              "no-referrer",
	"Permissions-Policy":           "camera=(), microphone=(), geolocation=()",
	"Cross-Origin-Opener-Policy":   "same-origin",
	"Cross-Origin-Resource-Policy": "same-origin",
}

type stack struct {
	client  *http.Client /* the panel origin (:443, the container's 8443) */
	xclient *http.Client /* the executor origin (:8443, the container's 9443) */
	base    string
	bare    *stack            /* same gateway without a reachable upstream */
	inner   map[string]string /* the gateway's address in each internal network, by network name */
}

var (
	once       sync.Once
	shared     *stack
	startErr   error
	containers []testcontainers.Container
	nw         *testcontainers.DockerNetwork
	edges      []*testcontainers.DockerNetwork
)

var errNoDocker = errors.New("docker daemon not reachable")

func TestMain(m *testing.M) {
	code := m.Run()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	for _, c := range containers {
		_ = c.Terminate(ctx)
	}
	for _, n := range append([]*testcontainers.DockerNetwork{nw, xnw}, edges...) {
		if n != nil {
			_ = n.Remove(ctx)
		}
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
		/* in CI a missing Docker fails, as in testdb: a skipped attack test proves nothing */
		if _, ci := os.LookupEnv("CI"); errors.Is(startErr, errNoDocker) && !ci {
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
	/* Each gateway has an edge of its own (the executor origin binds to the gateway's address there). */
	render := func(edge string) ([]byte, error) {
		out, err := install.Render(install.RenderInput{PublicHost: publicHost, ImageTag: "test", APIImage: "nms/api",
			GatewayImage: "nms/gateway", XnetSubnet: xnetSubnet, EdgeSubnet: edge})
		return out["Caddyfile"], err
	}
	caddyfile, err := render(edgeSubnet)
	if err != nil {
		return nil, err
	}
	bareCaddyfile, err := render(bareEdgeSubnet)
	if err != nil {
		return nil, err
	}

	/* core, as in the deployment: internal (no route anywhere, Docker publishes nothing there). */
	nw, err = network.New(ctx, network.WithInternal())
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
	/* The executor (a stub around its real /x server) on xnet at its static address, and in core like the real one. */
	executorFiles, err := startExecutor(ctx, caCert, caKey)
	if err != nil {
		return nil, err
	}

	/* Fresh readers per container: a ContainerFile reader is consumed by the copy. */
	files := func(caddyfile []byte) []testcontainers.ContainerFile {
		return append([]testcontainers.ContainerFile{
			file("/etc/caddy/Caddyfile", caddyfile),
			file("/certs/web.crt", webCert),
			file("/certs/web.key", webKey),
			file("/srv/app/index.html", []byte("<!doctype html><title>nms</title>")),
			file("/srv/app/assets/app.js", []byte("console.log(1)")),
			file("/srv/keys/keys.json", []byte(`{"domains":[]}`)),
			file("/srv/executor/index.html", []byte("<!doctype html><title>nms executor</title>")),
			file("/srv/executor/assets/x.js", []byte("console.log(2)")),
		}, executorFiles()...)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caCert) {
		return nil, errors.New("bad test CA")
	}
	s, err := startGateway(ctx, edgeSubnet, []string{nw.Name, xnw.Name}, files(caddyfile), roots)
	if err != nil {
		return nil, err
	}
	/* A second gateway on its edge only, where the name "api" does not resolve and the executor is not reachable. */
	if s.bare, err = startGateway(ctx, bareEdgeSubnet, nil, files(bareCaddyfile), roots); err != nil {
		return nil, err
	}
	return s, nil
}

/*
startGateway starts a gateway on a new edge network of subnet edge (routed,
the only one Docker can publish its ports on), at its second host address
as rendered, and on the internal networks.
*/
func startGateway(ctx context.Context, edge string, networks []string, files []testcontainers.ContainerFile, roots *x509.CertPool) (*stack, error) {
	en, err := network.New(ctx, network.WithIPAM(&mobynet.IPAM{Config: []mobynet.IPAMConfig{{Subnet: netip.MustParsePrefix(edge)}}}))
	if err != nil {
		return nil, fmt.Errorf("edge network: %w", err)
	}
	edges = append(edges, en)
	edgeIP := netip.MustParsePrefix(edge).Addr().Next().Next()
	gw, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        caddyImage,
			ExposedPorts: []string{"8443/tcp", "9443/tcp"},
			Networks:     append([]string{en.Name}, networks...),
			Files:        files,
			EndpointSettingsModifier: func(es map[string]*mobynet.EndpointSettings) {
				if es[en.Name] == nil {
					es[en.Name] = &mobynet.EndpointSettings{}
				}
				es[en.Name].IPAMConfig = &mobynet.EndpointIPAMConfig{IPv4Address: edgeIP}
			},
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
	ins, err := gw.Inspect(ctx)
	if err != nil {
		return nil, err
	}
	inner := map[string]string{}
	for _, n := range networks {
		if ep, ok := ins.NetworkSettings.Networks[n]; ok {
			inner[n] = fmt.Sprint(ep.IPAddress)
		}
	}

	host, err := gw.Host(ctx)
	if err != nil {
		return nil, err
	}
	if host == "localhost" {
		host = "127.0.0.1" /* avoid the IPv6 loopback, which Docker Desktop on Windows may not publish */
	}
	client := func(containerPort string) (*http.Client, error) {
		port, err := gw.MappedPort(ctx, containerPort)
		if err != nil {
			return nil, err
		}
		return httpsClient(net.JoinHostPort(host, port.Port()), roots), nil
	}
	panel, err := client("8443/tcp")
	if err != nil {
		return nil, err
	}
	x, err := client("9443/tcp")
	if err != nil {
		return nil, err
	}
	return &stack{client: panel, xclient: x, base: "https://" + publicHost, inner: inner}, nil
}

/* httpsClient dials target whatever the URL says: the URL names publicHost for SNI and verification. */
func httpsClient(target string, roots *x509.CertPool) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, "tcp", target)
			},
			TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
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

	t.Run("body over 1MiB", func(t *testing.T) {
		/* The gateway limit equals the api's 1 MiB: exactly 1 MiB passes, one byte more does not. */
		limit := strings.NewReader(strings.Repeat("a", 1<<20))
		resp, _ := s.do(t, http.MethodPost, "/api/users", limit, map[string]string{"Content-Type": "application/json"})
		if resp.StatusCode == http.StatusRequestEntityTooLarge {
			t.Fatal("1 MiB body rejected by the gateway")
		}
		big := strings.NewReader(strings.Repeat("a", 1<<20+1))
		resp, _ = s.do(t, http.MethodPost, "/api/users", big, map[string]string{"Content-Type": "application/json"})
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413", resp.StatusCode)
		}
		panelHeadersOnce(t, resp.Header)
		only(t, resp.Header, "Content-Type", "application/json; charset=utf-8")
	})
}

const imageCSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; sandbox"

/*
Map background images keep their own sandboxing CSP, chosen by the gateway:
neither the panel CSP nor whatever a compromised api sends. Everything else
about the panel headers stays, and the body is not forced to JSON.
*/
func TestBackgroundImageHeaders(t *testing.T) {
	s := gateway(t)
	resp, _ := s.get(t, "/api/map/backgrounds/1", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 from the upstream", resp.StatusCode)
	}
	only(t, resp.Header, "Content-Security-Policy", imageCSP)
	only(t, resp.Header, "X-Content-Type-Options", "nosniff")
	only(t, resp.Header, "Content-Type", "text/html") /* the api's type passes; the CSP sandbox is what confines it */
	only(t, resp.Header, "Cross-Origin-Resource-Policy", "same-origin")
	if v := resp.Header.Values("Set-Cookie"); len(v) != 0 {
		t.Errorf("Set-Cookie = %q", v)
	}
	if v := resp.Header.Values("Service-Worker-Allowed"); len(v) != 0 {
		t.Errorf("Service-Worker-Allowed = %q", v)
	}

	/* neighbouring paths keep the panel CSP and forced JSON */
	for _, p := range []string{"/api/map/backgrounds", "/api/map/views", "/api/map/backgroundsx/1"} {
		resp, _ := s.get(t, p, nil)
		only(t, resp.Header, "Content-Security-Policy", panelHeaders["Content-Security-Policy"])
		only(t, resp.Header, "Content-Type", "application/json; charset=utf-8")
	}
}

/* Only the background upload may carry more than 1 MiB: up to 21 MiB (20 MiB image plus multipart framing). */
func TestUploadBodyLimit(t *testing.T) {
	/* A rejected body is left unread: never reuse that connection for the next request. */
	closing := map[string]string{"Content-Type": "multipart/form-data; boundary=x", "Connection": "close"}
	s := gateway(t)
	post := func(path string, n int) int {
		resp, _ := s.do(t, http.MethodPost, path, strings.NewReader(strings.Repeat("a", n)), closing)
		return resp.StatusCode
	}
	if c := post("/api/map/backgrounds", 21<<20); c == http.StatusRequestEntityTooLarge {
		t.Errorf("21 MiB upload rejected by the gateway (%d)", c)
	}
	resp, _ := s.do(t, http.MethodPost, "/api/map/backgrounds", strings.NewReader(strings.Repeat("a", 21<<20+1)), closing)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("21 MiB + 1 upload = %d, want 413", resp.StatusCode)
	}
	only(t, resp.Header, "Content-Security-Policy", panelHeaders["Content-Security-Policy"])
	for _, p := range []string{"/api/users", "/api/map/views", "/api/map/backgrounds/1", "/api/map/backgrounds/"} {
		if c := post(p, 2<<20); c != http.StatusRequestEntityTooLarge {
			t.Errorf("2 MiB body to %s = %d, want 413", p, c)
		}
	}
}

/*
Caddy matches paths case-insensitively while the api router does not: a differently cased path reaches the
api as a 404 JSON error and still gets the image CSP from the gateway (the safe side), never the panel CSP
with an upstream-chosen body type for an image path.
*/
func TestBackgroundPathCaseInsensitive(t *testing.T) {
	s := gateway(t)
	resp, _ := s.get(t, "/API/map/Backgrounds/1", nil)
	only(t, resp.Header, "Content-Security-Policy", imageCSP)
	only(t, resp.Header, "X-Content-Type-Options", "nosniff")
	resp, _ = s.get(t, "/API/map/views", nil)
	only(t, resp.Header, "Content-Security-Policy", panelHeaders["Content-Security-Policy"])
	only(t, resp.Header, "Content-Type", "application/json; charset=utf-8")
}
