package install_test

import (
	"bytes"
	"flag"
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
	"compose.yaml":    "compose.yaml.golden",
	"Caddyfile":       "Caddyfile.golden",
	"config/api.yaml": "api.yaml.golden",
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

func TestRenderNonDefaultPortAndSubnet(t *testing.T) {
	in := sampleInput()
	in.HTTPSPort = 8443
	in.CoreSubnet = "10.99.0.0/24"
	out := render(t, in)
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
		Internal bool `yaml:"internal"`
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
	for _, want := range []string{"postgres", "migrate", "api", "gateway", "nmsctl"} {
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
		if name != "gateway" && len(s.Ports) > 0 {
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
	for name, s := range c.Secrets {
		if !strings.HasPrefix(s.File, "/etc/nms/secrets/") || strings.Contains(s.File, "..") {
			t.Errorf("secret %s: file = %q, want a file under /etc/nms/secrets/", name, s.File)
		}
	}
}
