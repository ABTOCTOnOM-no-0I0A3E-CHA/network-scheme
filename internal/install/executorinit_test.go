package install_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/internal/install"
)

/* executorOnly are the secrets an installation made before the executor (Phases 0-3) does not have. */
var executorOnly = []string{"db_executor_password", "ticket.key", "ticket.pub", "executor_tls.crt", "executor_tls.key", "gateway_client.crt", "gateway_client.key"}

/* preExecutorCompose is the shape of a Phase 3 compose.yaml as far as init reads it: no executor, edge without a subnet. */
const preExecutorCompose = `name: nms
services:
  api: {image: "nms/api:0.3.0"}
networks:
  edge: {}
  core: {internal: true, ipam: {config: [{subnet: "172.30.0.0/24", ip_range: "172.30.0.128/25"}]}}
  devices: {enable_ipv6: false, ipam: {config: [{subnet: "172.30.1.0/24"}]}}
`

/*
preExecutorInstall installs with the fake system, keeps what install
rendered for the executor (want), then takes the installation back to
Phases 0-3: no executor secrets, executor.yaml or policy, a compose.yaml
without the executor and api.yaml without ticket_key_file.
*/
func preExecutorInstall(t *testing.T) (o install.Options, etc string, want map[string][]byte) {
	t.Helper()
	o, root, _ := installOptions(t)
	if err := install.Run(context.Background(), o, newFakeSys()); err != nil {
		t.Fatalf("install: %v", err)
	}
	etc = filepath.Join(root, "etc", "nms")
	want = map[string][]byte{}
	for _, f := range []string{"compose.yaml", "Caddyfile", "config/api.yaml", "config/executor.yaml", "policies/executor.yaml"} {
		want[f] = readFile(t, filepath.Join(etc, f))
	}
	for _, f := range executorOnly {
		if err := os.Remove(filepath.Join(etc, "secrets", f)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(filepath.Join(etc, "config", "executor.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(etc, "policies")); err != nil {
		t.Fatal(err)
	}
	api := strings.ReplaceAll(string(want["config/api.yaml"]), "ticket_key_file: \"/run/secrets/ticket_key\"\n", "")
	writeFile(t, filepath.Join(etc, "config", "api.yaml"), api)
	writeFile(t, filepath.Join(etc, "compose.yaml"), preExecutorCompose)
	o.ImageTag, o.Out = "1.0.0", &bytes.Buffer{}
	return o, etc, want
}

func TestInitExecutorUpgradesAndRefusesTwice(t *testing.T) {
	o, etc, want := preExecutorInstall(t)
	secrets := filepath.Join(etc, "secrets")
	kept := snapshot(t, secrets)
	oldAPI := readFile(t, filepath.Join(etc, "config", "api.yaml"))

	sys := newFakeSys()
	if err := install.InitExecutor(context.Background(), o, sys); err != nil {
		t.Fatalf("InitExecutor: %v\n%s", err, o.Out)
	}
	/* Existing secrets keep their content; the missing ones are issued by the installation's CA. */
	for p, st := range kept {
		if !bytes.Equal(readFile(t, p), st.data) {
			t.Errorf("%s changed", p)
		}
	}
	if got := listDir(t, secrets); !slices.Equal(got, secretNames) {
		t.Fatalf("secrets = %v, want %v", got, secretNames)
	}
	verifyXnetAndTicketKeys(t, secrets)
	for _, n := range []string{"executor_sealing_key", "domain_write.key", "domain_backup.key", "ticket.pub", "db_executor_password"} {
		w := wantOwner[n]
		if got := sys.chowns[filepath.Join(secrets, n)]; got != [2]int{w.uid, w.gid} {
			if n == "ticket.pub" || n == "db_executor_password" { /* chowned as the temporary file */
				got = sys.chowns[filepath.Join(secrets, ".init-"+n)]
			}
			if got != [2]int{w.uid, w.gid} {
				t.Errorf("%s: owner %v, want %d:%d", n, got, w.uid, w.gid)
			}
		}
	}

	/* The project is what a new installation renders; replaced files keep their old content beside them. */
	for f, w := range want {
		if !bytes.Equal(readFile(t, filepath.Join(etc, f)), w) {
			t.Errorf("%s differs from a new installation's", f)
		}
	}
	if !bytes.Equal(readFile(t, filepath.Join(etc, "compose.yaml.pre-executor")), []byte(preExecutorCompose)) ||
		!bytes.Equal(readFile(t, filepath.Join(etc, "config", "api.yaml.pre-executor")), oldAPI) {
		t.Error("previous compose.yaml or api.yaml not kept")
	}
	if _, err := os.Stat(filepath.Join(etc, "Caddyfile.pre-executor")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("unchanged Caddyfile backed up: %v", err)
	}
	if _, err := os.Stat(filepath.Join(etc, ".executor-init-pending")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("pending marker left: %v", err)
	}

	/* down, postgres with the new secret, the role (password read in the container), then the stack. */
	var got []string
	for _, c := range sys.cmds {
		got = append(got, strings.TrimPrefix(cmdline(c), "docker compose -f /etc/nms/compose.yaml "))
	}
	wantCmds := []string{
		"down",
		"up -d --wait --wait-timeout 600 postgres",
		"exec -T postgres psql -q -v ON_ERROR_STOP=1 -U postgres -d nms",
		"up -d --wait --wait-timeout 600",
	}
	if !slices.Equal(got, wantCmds) {
		t.Fatalf("commands:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wantCmds, "\n"))
	}
	sql := sys.stdins[2]
	pw := string(readFile(t, filepath.Join(secrets, "db_executor_password")))
	if !strings.Contains(sql, "CREATE ROLE nms_executor") || !strings.Contains(sql, "/run/secrets/db_executor_password") ||
		!strings.Contains(sql, "GRANT CONNECT ON DATABASE nms TO nms_executor") || strings.Contains(sql, pw) {
		t.Fatalf("role SQL:\n%s", sql)
	}

	/* Again: refused, nothing touched. */
	before := snapshot(t, etc)
	sys2 := newFakeSys()
	if err := install.InitExecutor(context.Background(), o, sys2); !errors.Is(err, install.ErrExecutorInitialised) {
		t.Fatalf("second InitExecutor = %v, want ErrExecutorInitialised", err)
	}
	assertSnapshot(t, etc, before)
	if len(sys2.cmds) != 0 || len(sys2.chowns) != 0 {
		t.Fatalf("second InitExecutor acted: %v %v", sys2.cmds, sys2.chowns)
	}
}

/* An interrupted init is finished by running it again, without regenerating what it wrote or losing the first backups. */
func TestInitExecutorResumes(t *testing.T) {
	o, etc, want := preExecutorInstall(t)
	sys := newFakeSys()
	sys.onRun = func(c install.Cmd) {
		sys.runErr = nil
		if slices.Contains(c.Args, "exec") {
			sys.runErr = errors.New("exit status 2")
		}
	}
	if err := install.InitExecutor(context.Background(), o, sys); err == nil {
		t.Fatal("InitExecutor succeeded with a failing psql")
	}
	issued := snapshot(t, filepath.Join(etc, "secrets"))
	if err := install.InitExecutor(context.Background(), o, newFakeSys()); err != nil {
		t.Fatalf("resumed InitExecutor: %v", err)
	}
	for p, st := range issued {
		if !bytes.Equal(readFile(t, p), st.data) {
			t.Errorf("%s regenerated on resume", p)
		}
	}
	if !bytes.Equal(readFile(t, filepath.Join(etc, "compose.yaml.pre-executor")), []byte(preExecutorCompose)) {
		t.Error("the first backup of compose.yaml was overwritten")
	}
	if !bytes.Equal(readFile(t, filepath.Join(etc, "compose.yaml")), want["compose.yaml"]) {
		t.Error("compose.yaml not rendered")
	}
	if err := install.InitExecutor(context.Background(), o, newFakeSys()); !errors.Is(err, install.ErrExecutorInitialised) {
		t.Fatalf("third InitExecutor = %v", err)
	}
}

func TestInitExecutorRefusals(t *testing.T) {
	/* A new installation has the executor. */
	o, _, _ := installOptions(t)
	if err := install.Run(context.Background(), o, newFakeSys()); err != nil {
		t.Fatal(err)
	}
	if err := install.InitExecutor(context.Background(), o, newFakeSys()); !errors.Is(err, install.ErrExecutorInitialised) {
		t.Fatalf("on a new installation: %v", err)
	}
	/* No installation. */
	o2, _, _ := installOptions(t)
	if err := install.InitExecutor(context.Background(), o2, newFakeSys()); !errors.Is(err, install.ErrNotInstalled) {
		t.Fatalf("without an installation: %v", err)
	}
	/* The executor port is taken: nothing written. */
	o3, etc, _ := preExecutorInstall(t)
	o3.PortFree = func(string, int) error { return errors.New("in use") }
	before := snapshot(t, etc)
	if err := install.InitExecutor(context.Background(), o3, newFakeSys()); !errors.Is(err, install.ErrPortInUse) {
		t.Fatalf("port taken: %v", err)
	}
	assertSnapshot(t, etc, before)
}
