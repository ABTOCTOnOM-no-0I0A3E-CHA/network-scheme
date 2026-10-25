package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/install"
	"github.com/beekamai/network-scheme/internal/testdb"
)

func TestMain(m *testing.M) { testdb.Main(m) }

/* writeConfig writes executor.yaml over a fresh secrets directory and the nms_executor role of the test database. */
func writeConfig(t *testing.T) (cfgPath, secrets string) {
	t.Helper()
	env := testdb.New(t)
	dir := t.TempDir()
	secrets = filepath.Join(dir, "secrets")
	if err := install.WriteSecrets(secrets, install.SecretsInput{PublicHost: "nms.example.org", Chown: func(string, int, int) error { return nil }}); err != nil {
		t.Fatal(err)
	}
	db, pw := env.Config("nms_executor")
	state := filepath.Join(dir, "state")
	for p, body := range map[string]string{
		filepath.Join(dir, "db_password"): pw.Reveal(),
		filepath.Join(dir, "policy.yaml"): "enabled: false\n",
		filepath.Join(dir, "egress.yaml"): "mgmt_subnets: []\n",
	} {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	f := func(name string) string { return filepath.ToSlash(filepath.Join(secrets, name)) }
	cfg := fmt.Sprintf(`db: {host: %q, port: %d, name: %q, user: nms_executor, password_file: %q}
sealing_key_file: %q
write_key_file: %q
backup_key_file: %q
ticket_pub_key_file: %q
tls_cert_file: %q
tls_key_file: %q
client_ca_file: %q
listen_xnet: "172.30.2.2:8444"
core_subnet: "172.30.0.0/24"
xnet_subnet: "172.30.2.0/24"
panel_origin: "https://nms.example.org"
executor_origin: "https://nms.example.org:8443"
state_dir: %q
policy_file: %q
egress_file: %q
`, db.Host, db.Port, db.Name, filepath.ToSlash(filepath.Join(dir, "db_password")),
		f("executor_sealing_key"), f("domain_write.key"), f("domain_backup.key"), f("ticket.pub"),
		f("executor_tls.crt"), f("executor_tls.key"), f("ca.crt"), filepath.ToSlash(state),
		filepath.ToSlash(filepath.Join(dir, "policy.yaml")), filepath.ToSlash(filepath.Join(dir, "egress.yaml")))
	cfgPath = filepath.Join(dir, "executor.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, secrets
}

/* run connects as nms_executor with the installer's secrets, is healthy while up and stops on cancel. */
func TestRunStaysUpAndIsHealthy(t *testing.T) {
	cfgPath, _ := writeConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"run", "--config", cfgPath}) }()
	if err := run(context.Background(), []string{"healthcheck", "--config", cfgPath}); err != nil {
		t.Fatalf("healthcheck: %v", err)
	}
	select {
	case err := <-done:
		t.Fatalf("run returned while up: %v", err)
	case <-time.After(2 * time.Second):
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run after cancel: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not stop")
	}
}

/* replace swaps a read-only secret for garbage. */
func replace(p string) error {
	if err := os.Remove(p); err != nil {
		return err
	}
	return os.WriteFile(p, []byte("x"), 0o600)
}

/* A missing or malformed key stops the daemon before it connects; admin is not there yet. */
func TestRunRefusesBadFilesAndAdminIsAStub(t *testing.T) {
	for name, mutate := range map[string]func(secrets string) error{
		"write key missing":  func(s string) error { return os.Remove(filepath.Join(s, "domain_write.key")) },
		"ticket.pub garbage": func(s string) error { return replace(filepath.Join(s, "ticket.pub")) },
		"ca not PEM":         func(s string) error { return replace(filepath.Join(s, "ca.crt")) },
	} {
		cfgPath, secrets := writeConfig(t)
		if err := mutate(secrets); err != nil {
			t.Fatal(err)
		}
		if err := run(context.Background(), []string{"run", "--config", cfgPath}); err == nil {
			t.Errorf("%s: run started", name)
		}
	}
	cfgPath, _ := writeConfig(t)
	if err := run(context.Background(), []string{"admin", "status"}); err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Errorf("admin = %v", err)
	}
	if err := run(context.Background(), []string{"serve", "--config", cfgPath}); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("unknown command: %v", err)
	}
}
