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

func TestComposeHardening(t *testing.T) {
	var c compose
	if err := yaml.Unmarshal(render(t, sampleInput())["compose.yaml"], &c); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"postgres", "migrate", "api", "poller", "eventd", "gateway", "nmsctl"} {
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
	if !slices.Equal(c.Services["gateway"].Ports, []string{"443:8443"}) {
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
		if _, ok := s.Networks["devices"]; ok && name != "poller" && name != "eventd" {
			t.Errorf("%s must not join devices", name)
		}
		/* The backup-domain private key reaches no service (only the future executor); the poller gets the public key. */
		for _, sec := range s.Secrets {
			if strings.Contains(fmt.Sprint(sec), "backup") {
				t.Errorf("%s gets secret %v: the backup domain key must stay on the host", name, sec)
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
