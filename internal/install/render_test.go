package install_test

import (
	"bytes"
	"flag"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/beekamai/network-scheme/deploy"
	"github.com/beekamai/network-scheme/internal/config"
	"github.com/beekamai/network-scheme/internal/install"
	"github.com/beekamai/network-scheme/internal/poller"
	"github.com/beekamai/network-scheme/internal/testdb"
)

var update = flag.Bool("update", false, "rewrite testdata/*.golden")

func sampleInput() install.RenderInput {
	return install.RenderInput{
		PublicHost:   "nms.example.org",
		ImageTag:     "1.0.0",
		APIImage:     "nms/api",
		GatewayImage: "nms/gateway",
	}
}

func render(t *testing.T, in install.RenderInput) map[string][]byte {
	t.Helper()
	out, err := install.Render(in)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	return out
}

/* goldenFiles maps rendered keys to their golden files. */
var goldenFiles = map[string]string{
	"compose.yaml":       "compose.yaml.golden",
	"Caddyfile":          "Caddyfile.golden",
	"config/api.yaml":    "api.yaml.golden",
	"config/poller.yaml": "poller.yaml.golden",
	"config/eventd.yaml": "eventd.yaml.golden",

	"config/executor.yaml":   "executor.yaml.golden",
	"policies/executor.yaml": "executor-policy.yaml.golden",
}

func TestRenderGolden(t *testing.T) {
	out := render(t, sampleInput())
	for key, name := range goldenFiles {
		got, ok := out[key]
		if !ok {
			t.Fatalf("missing key %q", key)
		}
		path := filepath.Join("testdata", name)
		if *update {
			if err := os.WriteFile(path, got, 0o600); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path) // #nosec G304 -- fixed test path
		if err != nil {
			t.Fatal(err)
		}
		want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from %s (run with -update)\n--- got ---\n%s", key, path, got)
		}
	}
	/* Deterministic: a second render is byte-identical. */
	again := render(t, sampleInput())
	for key := range out {
		if !bytes.Equal(out[key], again[key]) {
			t.Errorf("%s: render is not deterministic", key)
		}
	}
}

func TestRenderShipsInitDBScript(t *testing.T) {
	want, err := deploy.FS.ReadFile("postgres/initdb/10-roles.sh")
	if err != nil {
		t.Fatal(err)
	}
	if got := render(t, sampleInput())["postgres/initdb/10-roles.sh"]; !bytes.Equal(got, want) {
		t.Error("postgres/initdb/10-roles.sh differs from deploy/postgres/initdb/10-roles.sh")
	}
}

func TestDefaultDBImageMatchesTests(t *testing.T) {
	if install.DefaultDBImage != testdb.Image {
		t.Errorf("DefaultDBImage = %q, testdb.Image = %q", install.DefaultDBImage, testdb.Image)
	}
}

func TestRenderedAPIConfigLoads(t *testing.T) {
	p := filepath.Join(t.TempDir(), "api.yaml")
	if err := os.WriteFile(p, render(t, sampleInput())["config/api.yaml"], 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := config.LoadAPI(p)
	if err != nil {
		t.Fatal(err)
	}
	if want := []netip.Prefix{netip.MustParsePrefix("172.30.0.2/32")}; !slices.Equal(c.TrustedProxyCIDRs, want) {
		t.Errorf("trusted_proxy_cidrs = %v, want %v", c.TrustedProxyCIDRs, want)
	}
	if c.PublicOrigin != "https://nms.example.org" || c.ListenAddr != ":8080" || c.DB.User != "nms_api" || c.DB.Name != "nms" {
		t.Errorf("unexpected config: %+v", c)
	}
}

func TestRenderedPollerConfigLoads(t *testing.T) {
	p := filepath.Join(t.TempDir(), "poller.yaml")
	if err := os.WriteFile(p, render(t, sampleInput())["config/poller.yaml"], 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := poller.LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.PollerID != "local" || c.DB.User != "nms_poller" || c.DB.Name != "nms" || c.DB.Host != "postgres" ||
		c.DB.PasswordFile != "/run/secrets/db_poller_password" || c.ReadKeyFile != "/run/secrets/domain_read_key" ||
		c.ReadPubKeyFile != "/etc/nms/domain_read.pub" || c.BackupPubKeyFile != "/etc/nms/domain_backup.pub" {
		t.Errorf("unexpected config: %+v", c)
	}
}

func TestRenderNonDefaultPortAndSubnet(t *testing.T) {
	in := sampleInput()
	in.HTTPSPort = 8443
	in.ExecutorPort = 9443
	in.CoreSubnet = "10.99.0.0/24"
	in.DevicesSubnet = "10.99.8.0/22"
	out := render(t, in)
	if !bytes.Contains(out["compose.yaml"], []byte(`- subnet: "10.99.8.0/22"`)) {
		t.Error("devices network must use DevicesSubnet")
	}
	if !bytes.Contains(out["config/api.yaml"], []byte(`"https://nms.example.org:8443"`)) {
		t.Errorf("public_origin must carry the port:\n%s", out["config/api.yaml"])
	}
	if !bytes.Contains(out["Caddyfile"], []byte("script-src https://nms.example.org:8443/assets/;")) {
		t.Error("CSP script-src must carry the port")
	}
	if !bytes.Contains(out["config/api.yaml"], []byte(`"10.99.0.2/32"`)) {
		t.Error("default gateway IP must be derived from CoreSubnet")
	}
	if ex := out["config/executor.yaml"]; !bytes.Contains(ex, []byte(`executor_origin: "https://nms.example.org:9443"`)) ||
		!bytes.Contains(ex, []byte(`panel_origin: "https://nms.example.org:8443"`)) {
		t.Errorf("executor origins must carry the ports: %s", ex)
	}
	if !bytes.Contains(out["compose.yaml"], []byte(`ports: ["8443:8443", "9443:9443"]`)) {
		t.Error("gateway must publish both ports")
	}
}

/*
caddySite returns the block of the Caddyfile that starts with the line
header (a site or snippet), up to its closing brace at column 0.
*/
func caddySite(t *testing.T, caddyfile []byte, header string) string {
	t.Helper()
	_, rest, ok := strings.Cut(string(caddyfile), "\n"+header+" {\n")
	if !ok {
		t.Fatalf("no %q block", header)
	}
	block, _, ok := strings.Cut(rest, "\n}\n")
	if !ok {
		t.Fatalf("%q block not closed", header)
	}
	return block
}

/*
The executor origin (:9443) proxies only /x/* to the executor's static xnet
address with the gateway's client certificate, trusting only the internal
CA and naming the server executor; the api is never proxied there, cookies
are dropped both ways and the client address is overwritten. The panel
frames only the executor origin and never proxies to the executor.
*/
func TestCaddyExecutorSite(t *testing.T) {
	in := sampleInput()
	in.XnetSubnet = "10.77.3.0/24"
	in.ExecutorPort = 9000
	in.EdgeSubnet = "10.77.4.0/24"
	out := render(t, in)
	site := caddySite(t, out["Caddyfile"], ":9443")
	for _, want := range []string{
		"reverse_proxy https://10.77.3.2:8444 {", "tls_client_auth /certs/gateway_client.crt /certs/gateway_client.key",
		"tls_trust_pool file /certs/ca.crt", "tls_server_name executor", "header_up -Cookie", "header_up X-Forwarded-For {remote_host}", "header_up Host {http.request.hostport}",
		"header_down -Set-Cookie", "header_down -Service-Worker-Allowed", "respond @sw 403", "handle /api/* {\n\t\t\terror 404",
		"import executor_headers", "max_size 64KiB", "handle /x/* {", "\tbind 10.77.4.2\n",
		"@foreign_host not host nms.example.org", "route {\n\t\terror @foreign_host 421\n\t\trespond @sw 403",
	} {
		if !strings.Contains(site, want) {
			t.Errorf("executor site lacks %q", want)
		}
	}
	if n := strings.Count(site, "reverse_proxy"); n != 1 || strings.Contains(site, "api:") {
		t.Errorf("executor site: %d reverse_proxy, api mentioned %v; want only the executor", n, strings.Contains(site, "api:"))
	}
	if strings.Contains(site, "tls_insecure_skip_verify") {
		t.Error("executor upstream verification is off")
	}
	headers := caddySite(t, out["Caddyfile"], "(executor_headers)")
	for _, want := range []string{"frame-ancestors https://nms.example.org;", "script-src https://nms.example.org:9000/assets/;", "-Set-Cookie", "defer"} {
		if !strings.Contains(headers, want) {
			t.Errorf("executor headers lack %q", want)
		}
	}
	for _, bad := range []string{"unsafe-inline", "unsafe-eval"} {
		if strings.Contains(headers, bad) || strings.Contains(caddySite(t, out["Caddyfile"], "(panel_headers)"), "script-src "+bad) {
			t.Errorf("CSP allows %s", bad)
		}
	}
	panel := caddySite(t, out["Caddyfile"], ":8443")
	if strings.Contains(panel, "10.77.3.2") || strings.Contains(panel, "gateway_client") {
		t.Error("the panel site reaches the executor")
	}
	if !strings.Contains(caddySite(t, out["Caddyfile"], "(panel_headers)"), "frame-src https://nms.example.org:9000;") {
		t.Error("the panel CSP must frame only the executor origin")
	}
}

func TestRenderRejectsBadInput(t *testing.T) {
	cases := map[string]func(*install.RenderInput){
		"empty host":           func(in *install.RenderInput) { in.PublicHost = "" },
		"host injection":       func(in *install.RenderInput) { in.PublicHost = "a.example; respond 200" },
		"host with newline":    func(in *install.RenderInput) { in.PublicHost = "a.example\n" },
		"empty tag":            func(in *install.RenderInput) { in.ImageTag = "" },
		"bad tag":              func(in *install.RenderInput) { in.ImageTag = "1.0\"x" },
		"bad image":            func(in *install.RenderInput) { in.APIImage = "nms/api\ncommand: sh" },
		"api image with tag":   func(in *install.RenderInput) { in.APIImage = "nms/api:latest" },
		"port out of range":    func(in *install.RenderInput) { in.HTTPSPort = 70000 },
		"ipv6 subnet":          func(in *install.RenderInput) { in.CoreSubnet = "fd00::/64" },
		"subnet too small":     func(in *install.RenderInput) { in.CoreSubnet = "172.30.0.0/30" },
		"gateway outside":      func(in *install.RenderInput) { in.GatewayIP = "10.0.0.2" },
		"gateway is docker gw": func(in *install.RenderInput) { in.GatewayIP = "172.30.0.1" },
		"gateway in ip_range":  func(in *install.RenderInput) { in.GatewayIP = "172.30.0.200" },
		"relative etc path":    func(in *install.RenderInput) { in.Paths.Etc = "etc/nms" },
		"path with quote":      func(in *install.RenderInput) { in.Paths.Var = "/var/lib/n\"ms" },
		"devices overlap core": func(in *install.RenderInput) { in.DevicesSubnet = "172.30.0.0/16" },
		"devices same as core": func(in *install.RenderInput) { in.DevicesSubnet = "172.30.0.0/24" },
		"devices ipv6":         func(in *install.RenderInput) { in.DevicesSubnet = "fd00::/64" },
		"devices host bits":    func(in *install.RenderInput) { in.DevicesSubnet = "172.30.1.1/24" },
		"devices too small":    func(in *install.RenderInput) { in.DevicesSubnet = "172.30.1.0/30" },
		"exec port = https":    func(in *install.RenderInput) { in.ExecutorPort = 443 },
		"exec port range":      func(in *install.RenderInput) { in.ExecutorPort = 70000 },
		"exec image tag":       func(in *install.RenderInput) { in.ExecutorImage = "nms/executor:latest" },
		"xnet overlaps core":   func(in *install.RenderInput) { in.XnetSubnet = "172.30.0.0/24" },
		"xnet overlaps devs":   func(in *install.RenderInput) { in.XnetSubnet = "172.30.1.0/25" },
		"edge overlaps core":   func(in *install.RenderInput) { in.EdgeSubnet = "172.30.0.128/25" },
		"edge overlaps xnet":   func(in *install.RenderInput) { in.EdgeSubnet = "172.30.2.0/24" },
		"edge overlaps devs":   func(in *install.RenderInput) { in.EdgeSubnet = "172.30.0.0/16" },
		"edge not network":     func(in *install.RenderInput) { in.EdgeSubnet = "172.30.3.1/24" },
		"xnet ipv6":            func(in *install.RenderInput) { in.XnetSubnet = "fd00::/64" },
		"xnet host bits":       func(in *install.RenderInput) { in.XnetSubnet = "172.30.2.1/24" },
		"host executor":        func(in *install.RenderInput) { in.PublicHost = "executor" },
		"host gateway":         func(in *install.RenderInput) { in.PublicHost = "GATEWAY" },
		"devices injection":    func(in *install.RenderInput) { in.DevicesSubnet = "172.30.1.0/24\"\n  x: y" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := sampleInput()
			mutate(&in)
			if _, err := install.Render(in); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

/* compose is the subset of the compose file the hardening test inspects. */
type compose struct {
	Services map[string]struct {
		Image       string            `yaml:"image"`
		Entrypoint  []string          `yaml:"entrypoint"`
		Command     []string          `yaml:"command"`
		Sysctls     map[string]string `yaml:"sysctls"`
		Secrets     []any             `yaml:"secrets"`
		Healthcheck struct {
			Test []string `yaml:"test"`
		} `yaml:"healthcheck"`
		User        string            `yaml:"user"`
		CapDrop     []string          `yaml:"cap_drop"`
		SecurityOpt []string          `yaml:"security_opt"`
		ReadOnly    bool              `yaml:"read_only"`
		Ports       []string          `yaml:"ports"`
		Environment map[string]string `yaml:"environment"`
		CPUs        string            `yaml:"cpus"`
		MemLimit    string            `yaml:"mem_limit"`
		Volumes     []string          `yaml:"volumes"`
		Networks    map[string]any    `yaml:"networks"`
		Tmpfs       []string          `yaml:"tmpfs"`
	} `yaml:"services"`
	Networks map[string]struct {
		Internal   bool  `yaml:"internal"`
		EnableIPv6 *bool `yaml:"enable_ipv6"`
		IPAM       struct {
			Config []struct {
				Subnet string `yaml:"subnet"`
			} `yaml:"config"`
		} `yaml:"ipam"`
	} `yaml:"networks"`
	Secrets map[string]struct {
		File string `yaml:"file"`
	} `yaml:"secrets"`
}

var sensitive = regexp.MustCompile(`(?i)PASSWORD|SECRET|KEY`)

/* executorSecret matches the secrets that belong to the executor. */
var executorSecret = regexp.MustCompile(`backup|write|sealing|executor|ticket_pub`)

func TestComposeHardening(t *testing.T) {
	var c compose
	if err := yaml.Unmarshal(render(t, sampleInput())["compose.yaml"], &c); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"postgres", "migrate", "api", "poller", "eventd", "executor", "gateway", "nmsctl"} {
		if _, ok := c.Services[want]; !ok {
			t.Errorf("service %s missing", want)
		}
	}
	for name, s := range c.Services {
		if !slices.Equal(s.CapDrop, []string{"ALL"}) {
			t.Errorf("%s: cap_drop = %v, want [ALL]", name, s.CapDrop)
		}
		if !slices.Contains(s.SecurityOpt, "no-new-privileges:true") {
			t.Errorf("%s: no-new-privileges missing", name)
		}
		if name != "postgres" {
			if !s.ReadOnly {
				t.Errorf("%s: read_only must be true", name)
			}
			if s.User == "" || strings.HasPrefix(s.User, "0") || strings.HasPrefix(s.User, "root") {
				t.Errorf("%s: must run as a non-root user, got %q", name, s.User)
			}
		}
		if name != "gateway" && name != "eventd" && len(s.Ports) > 0 {
			t.Errorf("%s: must not publish ports, got %v", name, s.Ports)
		}
		if s.CPUs == "" || s.MemLimit == "" {
			t.Errorf("%s: cpus/mem_limit required", name)
		}
		for k, v := range s.Environment {
			/* A *_FILE variable holding a /run/secrets path names a secret, it is not one. */
			if strings.HasSuffix(k, "_FILE") && strings.HasPrefix(v, "/run/secrets/") && !strings.Contains(v, "..") {
				continue
			}
			if sensitive.MatchString(k) || sensitive.MatchString(v) {
				t.Errorf("%s: environment %s looks like a secret value", name, k)
			}
		}
		for _, v := range s.Volumes {
			if strings.Contains(v, "/secrets") {
				t.Errorf("%s: secrets must be mounted via secrets:, not volume %q", name, v)
			}
		}
	}
	if !slices.Equal(c.Services["gateway"].Ports, []string{"443:8443", "8443:9443"}) {
		t.Errorf("gateway ports = %v", c.Services["gateway"].Ports)
	}
	if _, ok := c.Services["postgres"].Networks["edge"]; ok {
		t.Error("postgres must not join edge")
	}
	if !c.Networks["core"].Internal {
		t.Error("network core must be internal")
	}
	if c.Networks["edge"].Internal {
		t.Error("network edge must not be internal")
	}
	if len(c.Secrets) == 0 {
		t.Error("no secrets declared")
	}

	/* poller: api image as /poller, unprivileged ICMP via sysctl, only core + devices, only its secrets. */
	p := c.Services["poller"]
	if p.Image != "nms/api:1.0.0" || !slices.Equal(p.Entrypoint, []string{"/poller"}) || !slices.Equal(p.Command, []string{"run"}) {
		t.Errorf("poller image/entrypoint/command = %q %v %v", p.Image, p.Entrypoint, p.Command)
	}
	if p.User != "65532:65532" {
		t.Errorf("poller user = %q", p.User)
	}
	if p.Sysctls["net.ipv4.ping_group_range"] != "0 2147483647" {
		t.Errorf("poller sysctls = %v", p.Sysctls)
	}
	if !slices.Equal(p.Healthcheck.Test, []string{"CMD", "/poller", "healthcheck"}) {
		t.Errorf("poller healthcheck = %v", p.Healthcheck.Test)
	}
	if !slices.Equal(p.Secrets, []any{"db_poller_password", "domain_read_key"}) {
		t.Errorf("poller secrets = %v", p.Secrets)
	}
	if got := slices.Sorted(maps.Keys(p.Networks)); !slices.Equal(got, []string{"core", "devices"}) {
		t.Errorf("poller networks = %v", got)
	}
	for name, s := range c.Services {
		if _, ok := s.Networks["devices"]; ok && name != "poller" && name != "eventd" && name != "executor" {
			t.Errorf("%s must not join devices", name)
		}
		/* The write and backup private keys, the sealing key and the executor's TLS key reach the executor only; the poller gets the public backup key. */
		for _, sec := range s.Secrets {
			if executorSecret.MatchString(fmt.Sprint(sec)) && name != "executor" && (name != "postgres" || sec != "db_executor_password") {
				t.Errorf("%s gets secret %v: it belongs to the executor", name, sec)
			}
		}
		if name == "poller" != slices.ContainsFunc(s.Volumes, func(v string) bool { return strings.Contains(v, "domain_backup.pub") }) {
			t.Errorf("%s volumes %v: only the poller mounts domain_backup.pub", name, s.Volumes)
		}
		if name != "poller" && name != "eventd" && slices.Contains(s.Secrets, any("domain_read_key")) {
			t.Errorf("%s must not get the read domain key", name)
		}
	}

	/*
		eventd: api image as /eventd, core + devices, unprivileged container ports (so cap_drop ALL stays
		complete) published on the standard ports, only its own secrets, no database or api secrets.
	*/
	e := c.Services["eventd"]
	if e.Image != "nms/api:1.0.0" || !slices.Equal(e.Entrypoint, []string{"/eventd"}) || !slices.Equal(e.Command, []string{"run"}) || e.User != "65532:65532" {
		t.Errorf("eventd image/entrypoint/command/user = %q %v %v %q", e.Image, e.Entrypoint, e.Command, e.User)
	}
	if !slices.Equal(e.Healthcheck.Test, []string{"CMD", "/eventd", "healthcheck"}) {
		t.Errorf("eventd healthcheck = %v", e.Healthcheck.Test)
	}
	if want := []string{"514:1514/udp", "514:1514/tcp", "6514:6514/tcp", "162:1162/udp"}; !slices.Equal(e.Ports, want) {
		t.Errorf("eventd ports = %v, want %v", e.Ports, want)
	}
	if !slices.Equal(e.Secrets, []any{"db_eventd_password", "domain_read_key", "syslog_crt", "syslog_key"}) {
		t.Errorf("eventd secrets = %v", e.Secrets)
	}
	if got := slices.Sorted(maps.Keys(e.Networks)); !slices.Equal(got, []string{"core", "devices"}) {
		t.Errorf("eventd networks = %v", got)
	}
	/*
		executor: its own image and user, a tmpfs only it can enter, its own state volume, a static
		address in the internal xnet, exactly its secrets; the ticket signing key goes to the api only.
	*/
	x := c.Services["executor"]
	if x.Image != "nms/executor:1.0.0" || x.User != "65533:65533" || len(x.Entrypoint) != 0 || !slices.Equal(x.Healthcheck.Test, []string{"CMD", "/executor", "healthcheck"}) {
		t.Errorf("executor image/user/entrypoint/healthcheck = %q %q %v %v", x.Image, x.User, x.Entrypoint, x.Healthcheck.Test)
	}
	if !slices.Equal(x.Tmpfs, []string{"/run/executor:mode=0700,uid=65533,gid=65533,size=1m"}) {
		t.Errorf("executor tmpfs = %v", x.Tmpfs)
	}
	/* The administration socket lives in the executor's own tmpfs: no other service mounts /run/executor. */
	for name, s := range c.Services {
		if name == "executor" {
			continue
		}
		for _, m := range append(slices.Clone(s.Volumes), s.Tmpfs...) {
			if strings.Contains(m, "/run/executor") {
				t.Errorf("%s mounts %s", name, m)
			}
		}
	}
	if want := []any{"db_executor_password", "executor_sealing_key", "domain_write_key", "domain_backup_key", "ticket_pub", "executor_tls_crt", "executor_tls_key", "ca_crt"}; !slices.Equal(x.Secrets, want) {
		t.Errorf("executor secrets = %v, want %v", x.Secrets, want)
	}
	if want := []string{
		"executor-state:/var/lib/executor", "/etc/nms/config/executor.yaml:/etc/nms/executor.yaml:ro",
		"/etc/nms/config/egress.yaml:/etc/nms/egress.yaml:ro", "/etc/nms/policies:/etc/nms/policies:ro",
	}; !slices.Equal(x.Volumes, want) {
		t.Errorf("executor volumes = %v", x.Volumes)
	}
	if got := slices.Sorted(maps.Keys(x.Networks)); !slices.Equal(got, []string{"core", "devices", "xnet"}) {
		t.Errorf("executor networks = %v", got)
	}
	if xn, _ := x.Networks["xnet"].(map[string]any); xn["ipv4_address"] != "172.30.2.2" {
		t.Errorf("executor xnet = %v, want the static address 172.30.2.2", x.Networks["xnet"])
	}
	xnet := c.Networks["xnet"]
	if !xnet.Internal || len(xnet.IPAM.Config) != 1 || xnet.IPAM.Config[0].Subnet != install.DefaultXnetSubnet {
		t.Errorf("xnet = %+v, want internal with subnet %s", xnet, install.DefaultXnetSubnet)
	}
	for name, s := range c.Services {
		if _, ok := s.Networks["xnet"]; ok != (name == "executor" || name == "gateway") {
			t.Errorf("%s: xnet membership %v, want only executor and gateway", name, ok)
		}
		if slices.ContainsFunc(s.Volumes, func(v string) bool { return strings.HasPrefix(v, "executor-state:") }) != (name == "executor") {
			t.Errorf("%s volumes %v: only the executor mounts executor-state", name, s.Volumes)
		}
		if slices.Contains(s.Secrets, any("ticket_key")) != (name == "api") {
			t.Errorf("%s: only the api gets ticket_key", name)
		}
	}
	/* The gateway's client identity towards the executor and its web key exist only in the gateway. */
	for name, s := range c.Services {
		for _, sec := range []string{"gateway_client_crt", "gateway_client_key", "web_key", "ca_crt"} {
			has := slices.ContainsFunc(s.Secrets, func(v any) bool {
				m, _ := v.(map[string]any)
				return v == sec || m["source"] == sec
			})
			if want := name == "gateway" || (sec == "ca_crt" && name == "executor"); has != want {
				t.Errorf("%s: secret %s present = %v, want %v", name, sec, has, want)
			}
		}
	}

	dev := c.Networks["devices"]
	if dev.Internal || len(dev.IPAM.Config) != 1 || dev.IPAM.Config[0].Subnet != install.DefaultDevicesSubnet {
		t.Errorf("devices network = %+v, want routed with subnet %s", dev, install.DefaultDevicesSubnet)
	}
	/* The egress rules are IPv4 only: IPv6 must be off explicitly, not by daemon default. */
	if dev.EnableIPv6 == nil || *dev.EnableIPv6 {
		t.Errorf("devices network enable_ipv6 = %v, want explicit false", dev.EnableIPv6)
	}
	if !slices.Equal(c.Services["postgres"].Command, []string{"postgres", "-c", "timescaledb.telemetry_level=off"}) {
		t.Errorf("postgres command = %v, want telemetry off", c.Services["postgres"].Command)
	}
	for name, s := range c.Secrets {
		if !strings.HasPrefix(s.File, "/etc/nms/secrets/") || strings.Contains(s.File, "..") {
			t.Errorf("secret %s: file = %q, want a file under /etc/nms/secrets/", name, s.File)
		}
	}
}

func TestRenderLowercasesPublicHost(t *testing.T) {
	in := sampleInput()
	in.PublicHost = "NMS.Corp.Example"
	for key, got := range render(t, in) {
		if bytes.Contains(got, []byte("Corp")) || bytes.Contains(got, []byte("NMS.")) {
			t.Errorf("%s still contains the uppercase host", key)
		}
	}
	p := filepath.Join(t.TempDir(), "api.yaml")
	if err := os.WriteFile(p, render(t, in)["config/api.yaml"], 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := config.LoadAPI(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicOrigin != "https://nms.corp.example" {
		t.Errorf("public_origin = %q", c.PublicOrigin)
	}
	if !bytes.Contains(render(t, in)["Caddyfile"], []byte("https://nms.corp.example/assets/")) {
		t.Error("Caddyfile CSP does not carry the lowercase host")
	}
}

func TestRenderedEventdConfigLoads(t *testing.T) {
	p := filepath.Join(t.TempDir(), "eventd.yaml")
	if err := os.WriteFile(p, render(t, sampleInput())["config/eventd.yaml"], 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := config.LoadEventD(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.DB.User != "nms_eventd" || c.DB.Name != "nms" || c.DB.PasswordFile != "/run/secrets/db_eventd_password" ||
		c.ReadKeyFile != "/run/secrets/domain_read_key" || c.TLSCertFile != "/run/secrets/syslog_crt" || c.TLSKeyFile != "/run/secrets/syslog_key" || c.SyslogUDP != "0.0.0.0:1514" || c.TrapUDP != "0.0.0.0:1162" {
		t.Errorf("unexpected config: %+v", c)
	}
}

/*
The executor origin listens only on the gateway's static address in edge, the
gateway's only routed network (where Docker publishes the ports): edge has a
fixed subnet, the gateway its second host address there, and the :9443 site
binds to exactly that address; the panel site does not bind.
*/
func TestExecutorOriginBoundToEdge(t *testing.T) {
	in := sampleInput()
	in.EdgeSubnet = "10.66.5.0/24"
	out := render(t, in)
	var c compose
	if err := yaml.Unmarshal(out["compose.yaml"], &c); err != nil {
		t.Fatal(err)
	}
	edge := c.Networks["edge"]
	if edge.Internal || len(edge.IPAM.Config) != 1 || edge.IPAM.Config[0].Subnet != "10.66.5.0/24" {
		t.Errorf("edge = %+v, want routed with subnet 10.66.5.0/24", edge)
	}
	if e, _ := c.Services["gateway"].Networks["edge"].(map[string]any); e["ipv4_address"] != "10.66.5.2" {
		t.Errorf("gateway edge = %v, want the static address 10.66.5.2", c.Services["gateway"].Networks["edge"])
	}
	for name, s := range c.Services {
		if _, ok := s.Networks["edge"]; ok != (name == "gateway") {
			t.Errorf("%s: edge membership %v, want only the gateway", name, ok)
		}
	}
	/* Only edge may be routed for the gateway, or Docker could publish its ports on another network. */
	for n := range c.Services["gateway"].Networks {
		if n != "edge" && !c.Networks[n].Internal {
			t.Errorf("gateway network %s is routed", n)
		}
	}
	if site := caddySite(t, out["Caddyfile"], ":9443"); !strings.Contains(site, "\n\tbind 10.66.5.2\n") {
		t.Errorf("the executor origin is not bound to the gateway's edge address:\n%s", site)
	}
	if strings.Contains(caddySite(t, out["Caddyfile"], ":8443"), "bind ") {
		t.Error("the panel site binds")
	}
}
