package config_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/beekamai/network-scheme/internal/config"
)

func write(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadAPIParses(t *testing.T) {
	p := write(t, "api.yaml", `
listen_addr: 0.0.0.0:8080
public_origin: https://nms.example.org
trusted_proxy_cidrs: [172.30.0.2/32]
db: {host: postgres, name: nms, user: nms_api, password_file: /run/secrets/db_api_password}
data_key_file: /run/secrets/data_key
read_key_version: 3
`)
	c, err := config.LoadAPI(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.ReadKeyVersion != 3 {
		t.Errorf("read_key_version = %d, want 3", c.ReadKeyVersion)
	}
	if c.DB.Port != 5432 {
		t.Errorf("default port = %d, want 5432", c.DB.Port)
	}
	if len(c.TrustedProxyCIDRs) != 1 || c.TrustedProxyCIDRs[0] != netip.MustParsePrefix("172.30.0.2/32") {
		t.Errorf("cidrs = %v", c.TrustedProxyCIDRs)
	}
	if c.PublicOrigin != "https://nms.example.org" || c.DB.User != "nms_api" {
		t.Errorf("unexpected config: %+v", c)
	}
}

/* db.max_conns defaults to max(16, 4 x CPUs) for the api; an explicit value wins. */
func TestLoadAPIDefaultsMaxConns(t *testing.T) {
	load := func(db string) int {
		t.Helper()
		c, err := config.LoadAPI(write(t, "api.yaml", "db: {host: postgres, name: nms, user: nms_api, password_file: /p"+db+"}\n"))
		if err != nil {
			t.Fatal(err)
		}
		return c.DB.MaxConns
	}
	if got, want := load(""), max(16, 4*runtime.NumCPU()); got != want {
		t.Errorf("default max_conns = %d, want %d", got, want)
	}
	if got := load(", max_conns: 7"); got != 7 {
		t.Errorf("explicit max_conns = %d, want 7", got)
	}
}

func TestLoadAPIRejectsUnknownFields(t *testing.T) {
	p := write(t, "api.yaml", "listen_addr: :8080\ndb_password: hunter2\n")
	if _, err := config.LoadAPI(p); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestLoadAPIRejectsNegativeReadKeyVersion(t *testing.T) {
	p := write(t, "api.yaml", "read_key_version: -1\ndb: {host: h, name: n, user: u, password_file: /p}\n")
	if _, err := config.LoadAPI(p); err == nil {
		t.Fatal("expected error for a negative read_key_version")
	}
}

func TestLoadAPIRejectsMissingDB(t *testing.T) {
	p := write(t, "api.yaml", "listen_addr: :8080\n")
	if _, err := config.LoadAPI(p); err == nil {
		t.Fatal("expected error for missing db section")
	}
}

func TestReadSecretFileTrimsNewlineRejectsEmpty(t *testing.T) {
	s, err := config.ReadSecretFile(write(t, "s", "pw\r\n"))
	if err != nil || s.Reveal() != "pw" {
		t.Fatalf("got %q, %v", s.Reveal(), err)
	}
	s, err = config.ReadSecretFile(write(t, "s2", "a\nb\n"))
	if err != nil || s.Reveal() != "a\nb" {
		t.Fatalf("only one trailing newline must be trimmed, got %q, %v", s.Reveal(), err)
	}
	for _, content := range []string{"", "\n"} {
		if _, err := config.ReadSecretFile(write(t, "e", content)); err == nil {
			t.Fatalf("expected error for %q", content)
		}
	}
	if _, err := config.ReadSecretFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestReadKeyFile(t *testing.T) {
	want := bytes.Repeat([]byte{0xAB}, 32)
	cases := map[string][]byte{
		"raw":       want,
		"raw-nl":    append(bytes.Clone(want), '\n'), /* 33 bytes: neither raw nor base64 */
		"b64":       []byte(base64.StdEncoding.EncodeToString(want) + "\n"),
		"b64url":    []byte(base64.RawURLEncoding.EncodeToString(want)),
		"short-b64": []byte(base64.StdEncoding.EncodeToString(want[:16])),
	}
	for name, content := range cases {
		key, err := config.ReadKeyFile(write(t, name, string(content)))
		ok := name == "raw" || name == "b64" || name == "b64url"
		if ok != (err == nil) {
			t.Fatalf("%s: err = %v", name, err)
		}
		if ok && !bytes.Equal(key[:], want) {
			t.Fatalf("%s: wrong key", name)
		}
	}
}

func TestNormalizeOrigin(t *testing.T) {
	ok := map[string]string{
		"https://NMS.Corp.example":      "https://nms.corp.example",
		"HTTPS://nms.corp.example:443":  "https://nms.corp.example",
		"https://nms.corp.example/":     "https://nms.corp.example",
		"https://nms.corp.example:8443": "https://nms.corp.example:8443",
		"http://nms.corp.example:80":    "http://nms.corp.example",
		"https://10.0.0.5:8443":         "https://10.0.0.5:8443",
	}
	for in, want := range ok {
		if got, err := config.NormalizeOrigin(in); err != nil || got != want {
			t.Errorf("NormalizeOrigin(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "null", "nms.corp.example", "ftp://nms.corp.example", "https://nms.corp.example/path", "https://nms.corp.example?x=1", "https://u@nms.corp.example", "https://nms.corp.example#f"} {
		if got, err := config.NormalizeOrigin(in); err == nil {
			t.Errorf("NormalizeOrigin(%q) = %q, want error", in, got)
		}
	}
}

func TestLoadAPINormalizesPublicOrigin(t *testing.T) {
	body := `
listen_addr: 0.0.0.0:8080
public_origin: %s
db: {host: postgres, name: nms, user: nms_api, password_file: /run/secrets/db_api_password}
data_key_file: /run/secrets/data_key
`
	c, err := config.LoadAPI(write(t, "ok.yaml", fmt.Sprintf(body, "https://NMS.Corp.example:443")))
	if err != nil || c.PublicOrigin != "https://nms.corp.example" {
		t.Fatalf("origin = %q, err = %v", c.PublicOrigin, err)
	}
	if _, err := config.LoadAPI(write(t, "bad.yaml", fmt.Sprintf(body, "https://nms.corp.example/panel"))); err == nil {
		t.Error("a public_origin with a path must be rejected")
	}
}
