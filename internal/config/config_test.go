package config_test

import (
	"net/netip"
	"os"
	"path/filepath"
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
`)
	c, err := config.LoadAPI(p)
	if err != nil {
		t.Fatal(err)
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

func TestLoadAPIRejectsUnknownFields(t *testing.T) {
	p := write(t, "api.yaml", "listen_addr: :8080\ndb_password: hunter2\n")
	if _, err := config.LoadAPI(p); err == nil {
		t.Fatal("expected error for unknown field")
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
