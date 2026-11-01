package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/internal/install"
	"github.com/beekamai/network-scheme/internal/store"
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
	/* Unix socket paths are short (sun_path): a directory of its own under the system temp directory. */
	sock, err := os.MkdirTemp("", "exa")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sock) })
	old := adminSocket
	adminSocket = filepath.Join(sock, "admin.sock")
	t.Cleanup(func() { adminSocket = old })
	return cfgPath, secrets
}

/* run connects as nms_executor with the installer's secrets, bootstraps the registry, is healthy while up and stops on cancel. */
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
	if _, err := os.Stat(filepath.Join(filepath.Dir(cfgPath), "state", "state")); err != nil {
		t.Fatalf("state file: %v", err)
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

/*
The healthcheck's connections carry the same message bound as the daemon's:
a superuser's login trigger that sends nms_executor a 2 MiB notice fails the
healthcheck instead of being read into memory (a connection without the
bound reads it and succeeds, so the trigger does fire).
*/
func TestHealthcheckBoundsMessages(t *testing.T) {
	cfgPath, _ := writeConfig(t)
	env := testdb.New(t)
	ctx := context.Background()
	su := env.Pool("postgres")
	for _, q := range []string{
		`CREATE SCHEMA hc_test`,
		`GRANT USAGE ON SCHEMA hc_test TO nms_executor`,
		`CREATE FUNCTION hc_test.big() RETURNS event_trigger LANGUAGE plpgsql AS $$
		BEGIN IF session_user = 'nms_executor' THEN RAISE NOTICE '%', repeat('a', 2097152); END IF; END $$`,
		`CREATE EVENT TRIGGER hc_test_big ON login EXECUTE FUNCTION hc_test.big()`,
	} {
		if _, err := su.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = su.Exec(ctx, `DROP EVENT TRIGGER IF EXISTS hc_test_big`)
		_, _ = su.Exec(ctx, `DROP SCHEMA IF EXISTS hc_test CASCADE`)
	})
	db, pw := env.Config("nms_executor")
	unbounded, err := store.Open(ctx, db, pw, registry.PinSession)
	if err != nil {
		t.Fatalf("without the bound the notice is read: %v", err)
	}
	unbounded.Close()
	if err := run(ctx, []string{"healthcheck", "--config", cfgPath}); err == nil {
		t.Fatal("the healthcheck read a 2 MiB message")
	}
}

/* replace swaps a read-only secret for garbage. */
func replace(p string) error {
	if err := os.Remove(p); err != nil {
		return err
	}
	return os.WriteFile(p, []byte("x"), 0o600)
}

/* A missing or malformed key stops the daemon before it connects; admin takes no arguments and needs a request on stdin. */
func TestRunRefusesBadFilesAndAdminUsage(t *testing.T) {
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
	if err := run(context.Background(), []string{"admin", "status"}); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Errorf("admin with arguments = %v", err)
	}
	if err := relay(context.Background(), strings.NewReader(""), io.Discard); err == nil {
		t.Error("relay without a request line")
	}
	if err := run(context.Background(), []string{"serve", "--config", cfgPath}); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("unknown command: %v", err)
	}
}
