package gateway_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	mobynet "github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/beekamai/network-scheme/internal/pki"
)

/*
The executor origin (:9443 in the gateway container, :8443 on the host) in
front of a stub executor (cmd/executor/internal/web/webstub: the real /x
server with an authorizer that refuses everything, plus /x/evil/* playing a
compromised answer). xnet uses a subnet outside Docker's default address
pools, so it never collides with a network Docker allocated itself.
*/
const (
	xnetSubnet = "10.213.47.0/24"
	executorIP = "10.213.47.2" /* the rendered static address: the second host address of xnetSubnet */
	/* The gateways' edges (the routed network of the published ports), one per gateway. */
	edgeSubnet     = "10.213.48.0/24"
	bareEdgeSubnet = "10.213.49.0/24"
)

var executorHeaders = map[string]string{
	"Content-Security-Policy": "default-src 'self'; script-src https://" + publicHost + ":8443/assets/; style-src 'self'; img-src 'self' data:; " +
		"connect-src 'self'; frame-ancestors https://" + publicHost + "; frame-src 'none'; form-action 'none'; base-uri 'none'; object-src 'none'",
	"Strict-Transport-Security":    "max-age=31536000",
	"X-Content-Type-Options":       "nosniff",
	"Referrer-Policy":              "no-referrer",
	"Permissions-Policy":           "camera=(), microphone=(), geolocation=()",
	"Cross-Origin-Opener-Policy":   "same-origin",
	"Cross-Origin-Resource-Policy": "same-origin",
}

var (
	xnw *testcontainers.DockerNetwork
	/* stubCoreAddr is the stub executor's address in the core network, where nothing may listen. */
	stubCoreAddr string
	/* probeFiles are the probe's binary, CA and client certificates (fresh readers per container). */
	probeFiles func() []testcontainers.ContainerFile
)

/* pemPair is one certificate and its key. */
type pemPair struct{ crt, key []byte }

/*
startExecutor creates xnet, builds the stub for Linux, starts it at the
executor's static address (and in core) and returns the gateway's files:
its client certificate (CN gateway) and the CA.
*/
func startExecutor(ctx context.Context, caCert, caKey []byte) (func() []testcontainers.ContainerFile, error) {
	var err error
	xnw, err = network.New(ctx, network.WithInternal(), network.WithIPAM(&mobynet.IPAM{
		Config: []mobynet.IPAMConfig{{Subnet: netip.MustParsePrefix(xnetSubnet)}},
	}))
	if err != nil {
		return nil, fmt.Errorf("xnet: %w", err)
	}
	bin, err := buildStub()
	if err != nil {
		return nil, err
	}
	pairs := map[string]pemPair{}
	srv, srvKey, err := pki.IssueServerCert(caCert, caKey, []string{"executor"}, nil, time.Hour)
	if err != nil {
		return nil, err
	}
	pairs["executor"] = pemPair{srv, srvKey}
	for _, c := range []struct{ name, cn string }{{"gateway", "gateway"}, {"api", "api"}} {
		crt, key, err := pki.IssueClientCert(caCert, caKey, c.cn, time.Hour)
		if err != nil {
			return nil, err
		}
		pairs[c.name] = pemPair{crt, key}
	}
	otherCA, otherKey, err := pki.NewCA("another CA", time.Hour)
	if err != nil {
		return nil, err
	}
	if crt, key, err := pki.IssueClientCert(otherCA, otherKey, "gateway", time.Hour); err == nil {
		pairs["foreign"] = pemPair{crt, key}
	} else {
		return nil, err
	}
	probeFiles = func() []testcontainers.ContainerFile {
		fs := []testcontainers.ContainerFile{exe("/webstub", bin), file("/p/ca.crt", caCert)}
		for _, n := range []string{"gateway", "api", "foreign"} {
			fs = append(fs, file("/p/"+n+".crt", pairs[n].crt), file("/p/"+n+".key", pairs[n].key))
		}
		return fs
	}

	stub, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: caddyImage,
			Entrypoint: []string{"/webstub", "serve", "-listen", executorIP + ":8444", "-cert", "/p/executor.crt", "-key", "/p/executor.key",
				"-ca", "/p/ca.crt", "-executor-origin", "https://" + publicHost + ":8443", "-panel-origin", "https://" + publicHost},
			Networks: []string{nw.Name, xnw.Name},
			Files: []testcontainers.ContainerFile{exe("/webstub", bin), file("/p/ca.crt", caCert),
				file("/p/executor.crt", srv), file("/p/executor.key", srvKey)},
			EndpointSettingsModifier: func(es map[string]*mobynet.EndpointSettings) {
				if es[xnw.Name] == nil {
					es[xnw.Name] = &mobynet.EndpointSettings{}
				}
				es[xnw.Name].IPAMConfig = &mobynet.EndpointIPAMConfig{IPv4Address: netip.MustParseAddr(executorIP)}
			},
			WaitingFor: wait.ForLog("webstub serving").WithStartupTimeout(time.Minute),
		},
		Started: true,
	})
	if stub != nil {
		containers = append(containers, stub)
	}
	if err != nil {
		return nil, fmt.Errorf("stub executor: %w", err)
	}
	ins, err := stub.Inspect(ctx)
	if err != nil {
		return nil, err
	}
	core, ok := ins.NetworkSettings.Networks[nw.Name]
	if !ok {
		return nil, fmt.Errorf("stub executor not in %s", nw.Name)
	}
	stubCoreAddr = net.JoinHostPort(fmt.Sprint(core.IPAddress), "8444")
	return func() []testcontainers.ContainerFile {
		return []testcontainers.ContainerFile{file("/certs/ca.crt", caCert),
			file("/certs/gateway_client.crt", pairs["gateway"].crt), file("/certs/gateway_client.key", pairs["gateway"].key)}
	}, nil
}

/* buildStub cross-compiles the stub for the Docker daemon's Linux (same architecture as this machine). */
func buildStub() ([]byte, error) {
	dir, err := os.MkdirTemp("", "webstub")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	out := filepath.Join(dir, "webstub")
	cmd := exec.Command("go", "build", "-trimpath", "-o", out, "./cmd/executor/internal/web/webstub") // #nosec G204 -- fixed arguments
	cmd.Dir = filepath.Join("..", "..")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if b, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("build webstub: %v: %s", err, b)
	}
	return os.ReadFile(out) // #nosec G304 -- our own build output
}

func exe(path string, content []byte) testcontainers.ContainerFile {
	return testcontainers.ContainerFile{Reader: strings.NewReader(string(content)), ContainerFilePath: path, FileMode: 0o755}
}

/*
probe runs the stub's probe mode in a container on networks: each case is
name, address, client certificate (gateway, api, foreign or - for none). It
returns each case's line ("OK 200", "ERR tls ...").
*/
func probe(t *testing.T, networks []string, cases ...string) map[string]string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	args := []string{"/webstub", "probe", "-ca", "/p/ca.crt", "-host", publicHost + ":8443"}
	for i := 0; i+2 < len(cases); i += 3 {
		cert := cases[i+2]
		if cert != "-" {
			cert = "/p/" + cert
		}
		args = append(args, cases[i], cases[i+1], cert)
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: caddyImage, Entrypoint: args, Networks: networks, Files: probeFiles(),
			WaitingFor: wait.ForExit().WithExitTimeout(time.Minute),
		},
		Started: true,
	})
	if c != nil {
		containers = append(containers, c)
	}
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	logs, err := c.Logs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logs.Close() }()
	got := map[string]string{}
	sc := bufio.NewScanner(logs)
	for sc.Scan() {
		if name, rest, ok := strings.Cut(sc.Text(), " "); ok {
			got[name] = rest
		}
	}
	return got
}

/*
From xnet, only the gateway's certificate opens a TLS session to the
executor: none, CN api (same CA) and CN gateway from another CA are refused.
From core (where the api lives) the executor's core address has no listener
and its xnet address is unreachable.
*/
func TestExecutorReachableOnlyByTheGatewayCertificate(t *testing.T) {
	gateway(t)
	x := executorIP + ":8444"
	onXnet := probe(t, []string{xnw.Name}, "nocert", x, "-", "api", x, "api", "foreign", x, "foreign", "gateway", x, "gateway")
	for _, name := range []string{"nocert", "api", "foreign"} {
		if !strings.HasPrefix(onXnet[name], "ERR tls") {
			t.Errorf("from xnet, client %s: %q, want a TLS refusal", name, onXnet[name])
		}
	}
	if onXnet["gateway"] != "OK 200" {
		t.Fatalf("from xnet, the gateway certificate: %q (the refusals above prove nothing without it)", onXnet["gateway"])
	}
	onCore := probe(t, []string{nw.Name}, "core-address", stubCoreAddr, "gateway", "xnet-address", x, "gateway")
	if !strings.HasPrefix(onCore["core-address"], "ERR refused") {
		t.Errorf("from core, the executor's core address: %q, want connection refused (it listens only in xnet)", onCore["core-address"])
	}
	if !strings.HasPrefix(onCore["xnet-address"], "ERR timeout") && !strings.HasPrefix(onCore["xnet-address"], "ERR refused") {
		t.Errorf("from core, the executor's xnet address: %q, want unreachable", onCore["xnet-address"])
	}
}

/* xdo sends a request to the executor origin. */
func (s *stack) xdo(t *testing.T, method, path, body string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	var payload io.Reader
	if body != "" {
		payload = strings.NewReader(body)
	}
	return (&stack{client: s.xclient, base: s.base}).do(t, method, path, payload, hdr)
}

func executorHeadersOnce(t *testing.T, what string, h http.Header) {
	t.Helper()
	for k, v := range executorHeaders {
		if got := h.Values(k); len(got) != 1 || got[0] != v {
			t.Errorf("%s: %s = %q, want exactly [%q]", what, k, got, v)
		}
	}
	for _, k := range []string{"Set-Cookie", "Service-Worker-Allowed", "Server"} {
		if v := h.Values(k); len(v) != 0 {
			t.Errorf("%s: %s leaked: %q", what, k, v)
		}
	}
}

/* /x/status through the gateway: the executor's answer, JSON, with the executor origin's headers. */
func TestExecutorStatusThroughGateway(t *testing.T) {
	s := gateway(t)
	resp, body := s.xdo(t, http.MethodGet, "/x/status", "", nil)
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(body) != `{"enabled":true,"frozen":false}` {
		t.Fatalf("GET /x/status = %d %q", resp.StatusCode, body)
	}
	executorHeadersOnce(t, "status", resp.Header)
	only(t, resp.Header, "Content-Type", "application/json; charset=utf-8")
	only(t, resp.Header, "Cache-Control", "no-store")
}

/* The executor origin serves nothing of the api: /api/* is 404 there, with the executor headers. */
func TestExecutorOriginHasNoAPI(t *testing.T) {
	s := gateway(t)
	for _, p := range []string{"/api/users", "/api/auth/login", "/api/ws", "/API/users", "/api/executor/ticket"} {
		for _, m := range []string{http.MethodGet, http.MethodPost} {
			resp, body := s.xdo(t, m, p, "{}", map[string]string{"Content-Type": "application/json"})
			if resp.StatusCode != http.StatusNotFound || strings.Contains(body, "script") {
				t.Errorf("%s %s on the executor origin = %d %q, want 404", m, p, resp.StatusCode, body)
			}
			executorHeadersOnce(t, m+" "+p, resp.Header)
		}
	}
}

/*
What a compromised executor answer would set never reaches the browser
(Set-Cookie, Service-Worker-Allowed, its own CSP and type); what the browser
sends that the executor must not trust never reaches it: the Cookie header
is dropped and X-Forwarded-For is the gateway's own, one address, not the
browser's.
*/
func TestExecutorHeadersFilteredBothWays(t *testing.T) {
	s := gateway(t)
	resp, body := s.xdo(t, http.MethodGet, "/x/evil/echo", "", map[string]string{
		"Cookie": "nms_session=tossed-from-443; __Host-nms=x", "X-Forwarded-For": "6.6.6.6", "X-Real-Ip": "6.6.6.6",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("evil route = %d %q", resp.StatusCode, body)
	}
	executorHeadersOnce(t, "evil answer", resp.Header)
	only(t, resp.Header, "Content-Type", "application/json; charset=utf-8")
	var seen map[string][]string
	if err := json.Unmarshal([]byte(body), &seen); err != nil {
		t.Fatalf("echo %q: %v", body, err)
	}
	if v, ok := seen["Cookie"]; ok {
		t.Errorf("the executor received Cookie %q", v)
	}
	if h := seen["Host"]; len(h) != 1 || h[0] != publicHost {
		t.Errorf("Host at the executor = %q, want the browser's %q (the executor checks it)", h, publicHost)
	}
	xff := seen["X-Forwarded-For"]
	if len(xff) != 1 {
		t.Fatalf("X-Forwarded-For at the executor = %q, want one value", xff)
	}
	if a, err := netip.ParseAddr(xff[0]); err != nil || a.String() == "6.6.6.6" {
		t.Errorf("X-Forwarded-For at the executor = %q: the browser's value survived or it is not one address", xff[0])
	}
}

/* An Origin other than the executor's is refused by the executor (403) through the gateway; its own passes on. */
func TestExecutorOriginEnforcedThroughGateway(t *testing.T) {
	s := gateway(t)
	body := `{"ticket":"t","action":"none","params":{}}`
	for _, origin := range []string{"https://" + publicHost, "https://evil.example", ""} {
		resp, b := s.xdo(t, http.MethodPost, "/x/confirm/issue", body, map[string]string{"Origin": origin, "Content-Type": "application/json"})
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(b, `"origin"`) {
			t.Errorf("Origin %q: %d %q, want 403 origin", origin, resp.StatusCode, b)
		}
		executorHeadersOnce(t, "origin "+origin, resp.Header)
	}
	resp, b := s.xdo(t, http.MethodPost, "/x/confirm/issue", body, map[string]string{"Origin": "https://" + publicHost + ":8443", "Content-Type": "application/json"})
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(b, "unknown_action") {
		t.Errorf("the executor origin: %d %q, want the handler's 404 unknown_action", resp.StatusCode, b)
	}
}

/* Only the panel may frame the executor origin, and the panel frames only it. */
func TestExecutorFramedOnlyByThePanel(t *testing.T) {
	s := gateway(t)
	resp, body := s.xdo(t, http.MethodGet, "/", "", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "nms executor") {
		t.Fatalf("GET / on the executor origin = %d %q, want the bundle from the gateway", resp.StatusCode, body)
	}
	executorHeadersOnce(t, "bundle", resp.Header)
	var ancestors, frames string
	for _, d := range strings.Split(resp.Header.Get("Content-Security-Policy"), ";") {
		if f := strings.Fields(d); len(f) > 0 && f[0] == "frame-ancestors" {
			ancestors = strings.Join(f[1:], " ")
		}
	}
	if ancestors != "https://"+publicHost {
		t.Errorf("frame-ancestors = %q, want only the panel origin", ancestors)
	}
	resp, _ = s.get(t, "/", nil)
	for _, d := range strings.Split(resp.Header.Get("Content-Security-Policy"), ";") {
		if f := strings.Fields(d); len(f) > 0 && f[0] == "frame-src" {
			frames = strings.Join(f[1:], " ")
		}
	}
	if frames != "https://"+publicHost+":8443" {
		t.Errorf("panel frame-src = %q, want only the executor origin", frames)
	}
	if resp, _ := s.xdo(t, http.MethodGet, "/assets/x.js", "", nil); resp.StatusCode != http.StatusOK {
		t.Errorf("executor asset = %d", resp.StatusCode)
	}
}

/* A service worker registration request is refused on the executor origin, whatever the path. */
func TestExecutorServiceWorkerRefused(t *testing.T) {
	s := gateway(t)
	for _, p := range []string{"/", "/x/status", "/assets/x.js", "/keys.json", "/sw.js"} {
		resp, _ := s.xdo(t, http.MethodGet, p, "", map[string]string{"Service-Worker": "script"})
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s with Service-Worker: script = %d, want 403", p, resp.StatusCode)
		}
		executorHeadersOnce(t, "sw "+p, resp.Header)
	}
}

/* Errors of the gateway itself (404, 413, 502) and of the executor (404, 405) carry the executor headers; under /x/* they are JSON. */
func TestExecutorErrorsKeepHeaders(t *testing.T) {
	s := gateway(t)
	hd := map[string]string{"Content-Type": "application/json", "Origin": "https://" + publicHost + ":8443"}
	cases := []struct {
		what   string
		s      *stack
		method string
		path   string
		body   string
		status int
		isJSON bool
	}{
		{"missing asset", s, http.MethodGet, "/assets/missing.js", "", 404, false},
		{"executor 404", s, http.MethodGet, "/x/nope", "", 404, true},
		{"executor 405", s, http.MethodGet, "/x/confirm", "", 405, true},
		{"body over 64 KiB", s, http.MethodPost, "/x/confirm", strings.Repeat("a", 64<<10+1), 413, true},
		{"executor unreachable", s.bare, http.MethodGet, "/x/status", "", 502, true},
	}
	for _, c := range cases {
		resp, body := c.s.xdo(t, c.method, c.path, c.body, hd)
		if resp.StatusCode != c.status {
			t.Errorf("%s: %d %q, want %d", c.what, resp.StatusCode, body, c.status)
		}
		executorHeadersOnce(t, c.what, resp.Header)
		if c.isJSON {
			only(t, resp.Header, "Content-Type", "application/json; charset=utf-8")
		}
	}
}

/*
I1: the api (core) cannot use the gateway as a door to the executor. The
executor origin listens only on the gateway's address in edge, so from core
(and from xnet) the gateway's own address refuses port 9443 before any TLS
(no /x/status, no /x/confirm/issue, no handshake), while the panel port of
the same address answers (core reaches the gateway at all) and the
published port still serves the executor origin (TestExecutorStatusThroughGateway).
*/
func TestExecutorOriginNotReachableFromInternalNetworks(t *testing.T) {
	s := gateway(t)
	core, xn := s.inner[nw.Name], s.inner[xnw.Name]
	if core == "" || xn == "" {
		t.Fatalf("gateway addresses: %v", s.inner)
	}
	got := probe(t, []string{nw.Name}, "core-9443", core+":9443", "gateway", "core-8443", core+":8443", "gateway")
	if !strings.HasPrefix(got["core-9443"], "ERR refused") {
		t.Errorf("from core, the gateway's executor origin: %q, want connection refused", got["core-9443"])
	}
	if !strings.HasPrefix(got["core-8443"], "ERR tls") && !strings.HasPrefix(got["core-8443"], "OK") {
		t.Fatalf("from core, the gateway's panel port: %q, want a TLS session (the refusal above proves nothing without it)", got["core-8443"])
	}
	if got := probe(t, []string{xnw.Name}, "xnet-9443", xn+":9443", "gateway"); !strings.HasPrefix(got["xnet-9443"], "ERR refused") {
		t.Errorf("from xnet, the gateway's executor origin: %q, want connection refused", got["xnet-9443"])
	}
}

/* A request for another host on the executor origin is refused by the gateway (421) with the headers. */
func TestExecutorOriginRefusesForeignHost(t *testing.T) {
	s := gateway(t)
	/* / is the gateway's own file: only its matcher can refuse it; /x/status is refused by both. */
	for _, p := range []string{"/", "/x/status"} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, s.base+p, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "api"
		resp, err := s.xclient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMisdirectedRequest {
			t.Errorf("Host api, %s on the executor origin = %d, want 421", p, resp.StatusCode)
		}
		executorHeadersOnce(t, "foreign host "+p, resp.Header)
	}
}

/*
The executor's own 429 passes the gateway with the headers. Last of the /x
tests in this package (source order): it spends this client address's
budget at the executor.
*/
func TestExecutorRateLimitKeepsHeaders(t *testing.T) {
	s := gateway(t)
	for i := range 200 {
		resp, _ := s.xdo(t, http.MethodGet, "/x/status", "", nil)
		if resp.StatusCode == http.StatusTooManyRequests {
			executorHeadersOnce(t, "429", resp.Header)
			if resp.Header.Get("Retry-After") == "" {
				t.Error("429 without Retry-After")
			}
			return
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: %d", i+1, resp.StatusCode)
		}
	}
	t.Fatal("no 429 after 200 requests from one address")
}
