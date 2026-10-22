package install_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/config"
	"github.com/beekamai/network-scheme/internal/install"
	"github.com/beekamai/network-scheme/internal/keys"
	"github.com/beekamai/network-scheme/internal/pki"
	"github.com/beekamai/network-scheme/internal/secret"
)

/* fakeSys records every OS interaction instead of performing it. */
type fakeSys struct {
	goos    string
	docker  string
	cmds    []install.Cmd
	stdins  []string
	chowns  map[string][2]int /* path -> uid, gid */
	runErr  error
	inCtner bool
	exe     string                    /* the running nmsctl; default: the test binary */
	run     func(c install.Cmd) error /* optional: result of iptables commands (default runErr) */
	onRun   func(c install.Cmd)       /* optional: observes every command before it is recorded */
}

func newFakeSys() *fakeSys {
	exe, _ := os.Executable()
	return &fakeSys{goos: "linux", docker: "24.0.7", chowns: map[string][2]int{}, exe: exe}
}

func (f *fakeSys) Executable() (string, error) { return f.exe, nil }

func (f *fakeSys) GOOS() string                         { return f.goos }
func (f *fakeSys) InContainer() bool                    { return f.inCtner }
func (f *fakeSys) DockerServerVersion() (string, error) { return f.docker, nil }

func (f *fakeSys) Chown(path string, uid, gid int) error {
	f.chowns[path] = [2]int{uid, gid}
	return nil
}

func (f *fakeSys) Run(_ context.Context, c install.Cmd) error {
	if f.onRun != nil {
		f.onRun(c)
	}
	f.cmds = append(f.cmds, c)
	in := ""
	if c.Stdin != nil {
		b, _ := io.ReadAll(c.Stdin)
		in = string(b)
	}
	f.stdins = append(f.stdins, in)
	if f.run != nil && c.Name == "iptables" {
		return f.run(c)
	}
	if slices.Contains(c.Args, "admin") && c.Stdout != nil {
		_, _ = io.WriteString(c.Stdout, "QR...\n"+install.TOTPSecretLinePrefix+"JBSWY3DPEHPK3PXP\n")
	}
	return f.runErr
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

const goodDaemonJSON = `{"log-driver": "json-file", "userland-proxy": false}`

func TestPreflightErrors(t *testing.T) {
	cases := []struct {
		name   string
		goos   string
		docker string
		daemon string /* "" = file absent */
		marker bool
		want   error
	}{
		{"ok", "linux", "24.0.7", goodDaemonJSON, false, nil},
		{"ok newer docker", "linux", "28.1.1", goodDaemonJSON, false, nil},
		{"not linux", "windows", "24.0.7", goodDaemonJSON, false, install.ErrNotLinux},
		{"docker 23", "linux", "23.0.6", goodDaemonJSON, false, install.ErrDockerTooOld},
		{"docker version garbage", "linux", "unknown", goodDaemonJSON, false, install.ErrDockerTooOld},
		{"no daemon.json", "linux", "24.0.7", "", false, install.ErrUserlandProxy},
		{"userland-proxy missing", "linux", "24.0.7", `{"log-driver": "json-file"}`, false, install.ErrUserlandProxy},
		{"userland-proxy true", "linux", "24.0.7", `{"userland-proxy": true}`, false, install.ErrUserlandProxy},
		{"daemon.json invalid", "linux", "24.0.7", `{`, false, install.ErrUserlandProxy},
		{"already installed", "linux", "24.0.7", goodDaemonJSON, true, install.ErrAlreadyInstalled},
		{"iptables explicitly on", "linux", "29.1.3", `{"userland-proxy": false, "iptables": true, "firewall-backend": "iptables"}`, false, nil},
		{"iptables off", "linux", "29.1.3", `{"userland-proxy": false, "iptables": false}`, false, install.ErrDockerFirewall},
		{"iptables not a bool", "linux", "29.1.3", `{"userland-proxy": false, "iptables": "false"}`, false, install.ErrDockerFirewall},
		{"nftables backend", "linux", "29.1.3", `{"userland-proxy": false, "firewall-backend": "nftables"}`, false, install.ErrDockerFirewall},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			if c.daemon != "" {
				writeFile(t, filepath.Join(root, "etc", "docker", "daemon.json"), c.daemon)
			}
			if c.marker {
				writeFile(t, filepath.Join(root, "etc", "nms", "installed"), "")
			}
			sys := newFakeSys()
			sys.goos, sys.docker = c.goos, c.docker
			err := install.Preflight(install.Options{Root: root}, sys)
			if !errors.Is(err, c.want) || (c.want == nil) != (err == nil) {
				t.Fatalf("Preflight = %v, want %v", err, c.want)
			}
			if errors.Is(err, install.ErrUserlandProxy) && !strings.Contains(err.Error(), `"userland-proxy": false`) {
				t.Fatalf("error lacks the JSON fragment to paste: %v", err)
			}
			if errors.Is(err, install.ErrDockerFirewall) && !strings.Contains(err.Error(), `"iptables"`) {
				t.Fatalf("error lacks the JSON fragment to set: %v", err)
			}
		})
	}
}

/* secretNames is the exact set WriteSecrets must create. */
var secretNames = []string{
	"api_data_key", "ca.crt", "ca.key",
	"db_api_password", "db_cli_password", "db_eventd_password", "db_migrator_password", "db_poller_password", "db_postgres_password",
	"domain_backup.key", "domain_read.key", "domain_write.key",
	"executor_sealing_key", "syslog.crt", "syslog.key", "web.crt", "web.key",
}

/* wantOwner is the owner table: consumer container uid/gid and mode. */
var wantOwner = map[string]struct {
	uid, gid int
	mode     os.FileMode
}{
	"db_postgres_password": {install.PostgresUID, install.PostgresUID, 0o400},
	"db_migrator_password": {install.ContainerUID, install.PostgresUID, 0o440},
	"db_api_password":      {install.ContainerUID, install.PostgresUID, 0o440},
	"db_cli_password":      {install.ContainerUID, install.PostgresUID, 0o440},
	"db_poller_password":   {install.ContainerUID, install.PostgresUID, 0o440},
	"db_eventd_password":   {install.ContainerUID, install.PostgresUID, 0o440},
	"api_data_key":         {install.ContainerUID, install.ContainerUID, 0o400},
	"syslog.crt":           {install.ContainerUID, install.ContainerUID, 0o400},
	"syslog.key":           {install.ContainerUID, install.ContainerUID, 0o400},
	"web.crt":              {install.ContainerUID, install.ContainerUID, 0o400},
	"web.key":              {install.ContainerUID, install.ContainerUID, 0o400},
	"ca.crt":               {0, 0, 0o400},
	"ca.key":               {0, 0, 0o400},
	"domain_read.key":      {install.ContainerUID, install.ContainerUID, 0o400},
	"domain_write.key":     {0, 0, 0o400},
	"domain_backup.key":    {0, 0, 0o400},
	"executor_sealing_key": {0, 0, 0o400},
}

func listDir(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- test path
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestWriteSecretsPermsAndNoOverwrite(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "secrets")
	sys := newFakeSys()
	if err := install.WriteSecrets(dir, install.SecretsInput{PublicHost: "nms.example.org", Chown: sys.Chown}); err != nil {
		t.Fatalf("WriteSecrets: %v", err)
	}
	if got := listDir(t, dir); !slices.Equal(got, secretNames) {
		t.Fatalf("files = %v, want %v", got, secretNames)
	}
	if got := listDir(t, parent); !slices.Equal(got, []string{"secrets"}) {
		t.Fatalf("parent = %v: temporary directory left behind", got)
	}

	/* Owners (set in the temporary directory, before the rename) and modes. */
	owners := map[string][2]int{}
	for p, o := range sys.chowns {
		if strings.HasPrefix(filepath.Base(filepath.Dir(p)), ".secrets-tmp-") {
			owners[filepath.Base(p)] = o
		}
	}
	for name, w := range wantOwner {
		p := filepath.Join(dir, name)
		if got, ok := owners[name]; !ok || got != [2]int{w.uid, w.gid} {
			t.Errorf("%s: chown = %v (recorded %v), want %d:%d", name, got, ok, w.uid, w.gid)
		}
		if runtime.GOOS == "linux" {
			st, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if st.Mode().Perm() != w.mode {
				t.Errorf("%s: mode %o, want %o", name, st.Mode().Perm(), w.mode)
			}
		}
	}
	if runtime.GOOS == "linux" {
		st, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o700 {
			t.Errorf("dir mode %o, want 700", st.Mode().Perm())
		}
	}

	/* Contents. */
	for _, n := range []string{"db_postgres_password", "db_migrator_password", "db_api_password", "db_cli_password", "db_poller_password", "db_eventd_password"} {
		raw := readFile(t, filepath.Join(dir, n))
		b, err := base64.RawURLEncoding.DecodeString(string(raw))
		if err != nil || len(b) != 32 {
			t.Errorf("%s: want base64url of 32 bytes, got %q", n, raw)
		}
	}
	if _, err := config.ReadKeyFile(filepath.Join(dir, "api_data_key")); err != nil {
		t.Errorf("api_data_key: %v", err)
	}
	for _, n := range []string{"domain_read.key", "domain_write.key", "domain_backup.key", "executor_sealing_key"} {
		if _, err := config.ReadKeyFile(filepath.Join(dir, n)); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
	seen := map[string]bool{}
	for _, n := range []string{"db_api_password", "db_cli_password", "domain_read.key", "domain_write.key"} {
		v := string(readFile(t, filepath.Join(dir, n)))
		if seen[v] {
			t.Errorf("%s repeats another secret", n)
		}
		seen[v] = true
	}
	verifyCert(t, dir, "web.crt", "nms.example.org")
	verifyCert(t, dir, "syslog.crt", "nms.example.org")

	/* Second call: refused, nothing changed. */
	before := snapshot(t, dir)
	if err := install.WriteSecrets(dir, install.SecretsInput{PublicHost: "nms.example.org", Chown: sys.Chown}); !errors.Is(err, install.ErrSecretsExist) {
		t.Fatalf("second WriteSecrets = %v, want ErrSecretsExist", err)
	}
	assertSnapshot(t, dir, before)

	/* A directory holding one pre-existing secret: error, nothing else created. */
	dir2 := filepath.Join(parent, "secrets2")
	writeFile(t, filepath.Join(dir2, "db_api_password"), "keep-me")
	if err := install.WriteSecrets(dir2, install.SecretsInput{PublicHost: "nms.example.org", Chown: sys.Chown}); !errors.Is(err, install.ErrSecretsExist) {
		t.Fatalf("WriteSecrets over existing file = %v, want ErrSecretsExist", err)
	}
	if got := listDir(t, dir2); !slices.Equal(got, []string{"db_api_password"}) {
		t.Fatalf("partial secrets created: %v", got)
	}
	if string(readFile(t, filepath.Join(dir2, "db_api_password"))) != "keep-me" {
		t.Fatal("existing secret overwritten")
	}
	if got := listDir(t, parent); !slices.Equal(got, []string{"secrets", "secrets2"}) {
		t.Fatalf("parent = %v: temporary directory left behind", got)
	}
}

func TestWriteSecretsUsesSuppliedWebCert(t *testing.T) {
	caCrt, caKey, err := pki.NewCA("corp", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	crt, key, err := pki.IssueServerCert(caCrt, caKey, []string{"nms.corp.example"}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "secrets")
	err = install.WriteSecrets(dir, install.SecretsInput{
		PublicHost: "nms.corp.example", WebCertPEM: crt, WebKeyPEM: key, Chown: newFakeSys().Chown,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFile(t, filepath.Join(dir, "web.crt")), crt) || !bytes.Equal(readFile(t, filepath.Join(dir, "web.key")), key) {
		t.Fatal("supplied web certificate not used verbatim")
	}

	/* A mismatched pair is rejected before anything is written. */
	_, otherKey, err := pki.IssueServerCert(caCrt, caKey, []string{"x.example"}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir2 := filepath.Join(t.TempDir(), "secrets")
	err = install.WriteSecrets(dir2, install.SecretsInput{PublicHost: "x.example", WebCertPEM: crt, WebKeyPEM: otherKey, Chown: newFakeSys().Chown})
	if err == nil {
		t.Fatal("mismatched web cert/key accepted")
	}
	if _, err := os.Stat(dir2); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("secrets dir created on error: %v", err)
	}
}

func verifyCert(t *testing.T, dir, file, host string) {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(readFile(t, filepath.Join(dir, "ca.crt"))) {
		t.Fatal("ca.crt is not PEM")
	}
	b, _ := pem.Decode(readFile(t, filepath.Join(dir, file)))
	if b == nil {
		t.Fatal(file + " is not PEM")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Verify(x509.VerifyOptions{DNSName: host, Roots: pool}); err != nil {
		t.Fatalf("%s does not verify for %s against ca.crt: %v", file, host, err)
	}
}

type fileState struct {
	data  []byte
	mtime time.Time
}

func snapshot(t *testing.T, dir string) map[string]fileState {
	t.Helper()
	out := map[string]fileState{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		st, err := d.Info()
		if err != nil {
			return err
		}
		out[p] = fileState{readFile(t, p), st.ModTime()}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func assertSnapshot(t *testing.T, dir string, want map[string]fileState) {
	t.Helper()
	got := snapshot(t, dir)
	if len(got) != len(want) {
		t.Fatalf("%s: %d files, want %d", dir, len(got), len(want))
	}
	for p, w := range want {
		g, ok := got[p]
		if !ok || !bytes.Equal(g.data, w.data) || !g.mtime.Equal(w.mtime) {
			t.Fatalf("%s changed", p)
		}
	}
}

const adminPassword = "Plume-harbor-Quartz-71"

func installOptions(t *testing.T) (install.Options, string, *bytes.Buffer) {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "etc", "docker", "daemon.json"), goodDaemonJSON)
	pwFile := filepath.Join(t.TempDir(), "pw")
	writeFile(t, pwFile, adminPassword+"\n")
	out := &bytes.Buffer{}
	return install.Options{
		PublicHost:        "nms.example.org",
		InfraNTP:          []string{"10.0.0.1"},
		InfraDNS:          []string{"10.0.0.2", "dns.corp.example"},
		MgmtSubnets:       []string{"10.0.0.0/8"},
		AdminUser:         "admin",
		AdminPasswordFile: pwFile,
		TOTPSecretOut:     filepath.Join(t.TempDir(), "totp"),
		NonInteractive:    true,
		ImageTag:          "1.0.0",
		Paths:             install.Paths{Etc: "/etc/nms", Var: "/var/lib/nms"},
		Root:              root,
		Out:               out,
	}, root, out
}

func cmdline(c install.Cmd) string { return c.Name + " " + strings.Join(c.Args, " ") }

func TestRunInstalls(t *testing.T) {
	o, root, out := installOptions(t)
	sys := newFakeSys()
	if err := install.Run(context.Background(), o, sys); err != nil {
		t.Fatalf("Run: %v\n%s", err, out)
	}
	etc, vr := filepath.Join(root, "etc", "nms"), filepath.Join(root, "var", "lib", "nms")
	for _, p := range []string{
		"compose.yaml", "Caddyfile", "config/api.yaml", "config/poller.yaml", "config/eventd.yaml", "config/infra.yaml", "config/egress.yaml",
		"config/domain_read.pub", "postgres/initdb/10-roles.sh", "installed",
	} {
		if _, err := os.Stat(filepath.Join(etc, p)); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	if runtime.GOOS == "linux" {
		st, err := os.Stat(filepath.Join(etc, "postgres", "initdb", "10-roles.sh"))
		if err != nil || st.Mode().Perm() != 0o755 {
			t.Errorf("10-roles.sh mode: %v %v", st, err)
		}
		st, err = os.Stat(filepath.Join(etc, "postgres", "initdb"))
		if err != nil || st.Mode().Perm() != 0o755 {
			t.Errorf("initdb dir mode: %v %v", st, err)
		}
	}
	if got := sys.chowns[filepath.Join(vr, "anchors")]; got != [2]int{install.ContainerUID, install.ContainerUID} {
		t.Errorf("anchors dir owner = %v", got)
	}

	/* keys.json carries the public halves of the domain keys on disk. */
	var kj keys.KeysJSON
	if err := json.Unmarshal(readFile(t, filepath.Join(vr, "gateway", "keys.json")), &kj); err != nil {
		t.Fatal(err)
	}
	if len(kj.Domains) != 3 || !strings.Contains(out.String(), kj.Domains["read"].Fingerprint) {
		t.Fatalf("keys.json %+v / fingerprint not printed:\n%s", kj, out)
	}
	/* The poller's public read key is the one keys.json publishes. */
	if got := strings.TrimSpace(string(readFile(t, filepath.Join(etc, "config", "domain_read.pub")))); got != kj.Domains["read"].PublicKey {
		t.Errorf("domain_read.pub = %q, keys.json read key = %q", got, kj.Domains["read"].PublicKey)
	}
	eg, err := install.LoadEgress(filepath.Join(etc, "config", "egress.yaml"))
	if err != nil || eg.DevicesSubnet.String() != install.DefaultDevicesSubnet || len(eg.MgmtSubnets) != 1 || eg.MgmtSubnets[0].String() != "10.0.0.0/8" {
		t.Errorf("egress.yaml = %+v, %v", eg, err)
	}
	if !strings.Contains(out.String(), "SHA-256") {
		t.Errorf("web certificate fingerprint not printed:\n%s", out)
	}

	/* Commands: egress rules before any container, compose up, admin create in the tools container, units. */
	var lines []string
	for _, c := range sys.cmds {
		lines = append(lines, cmdline(c))
	}
	want := []string{"iptables -w -n -L DOCKER-USER"}
	/* The eventd ports (published on every host interface) accept only the management subnet. */
	for _, pp := range [][2]string{{"udp", "1514"}, {"tcp", "1514"}, {"tcp", "6514"}, {"udp", "1162"}} {
		m := "iptables -w -C DOCKER-USER -d 172.30.1.0/24 -p " + pp[0] + " -m " + pp[0] + " --dport " + pp[1] + " -m comment --comment nms-ingress-" + pp[0] + "-" + pp[1]
		want = append(want, m+" -j DROP", m+" -s 10.0.0.0/8 -j RETURN")
	}
	want = append(want,
		"iptables -w -C DOCKER-USER -s 172.30.1.0/24 -j DROP",
		"iptables -w -C DOCKER-USER -s 172.30.1.0/24 -d 10.0.0.0/8 -j RETURN",
		"iptables -w -C DOCKER-USER -s 172.30.1.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
		"iptables -w -C FORWARD -j DOCKER-USER",
		"systemctl daemon-reload",
		"docker compose -f /etc/nms/compose.yaml up -d --wait --wait-timeout 600",
		"docker compose -f /etc/nms/compose.yaml --profile tools run --rm --no-deps -T nmsctl admin create --user admin --password-file -",
		"systemctl daemon-reload",
		"systemctl enable --now nms-audit-anchor.timer",
	)
	if !slices.Equal(lines, want) {
		t.Fatalf("commands:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	if sys.stdins[slices.IndexFunc(lines, func(l string) bool { return strings.Contains(l, " admin create ") })] != adminPassword+"\n" {
		t.Fatalf("admin create stdin = %q", sys.stdins)
	}
	for _, u := range []string{"nms-audit-anchor.service", "nms-audit-anchor.timer"} {
		if _, err := os.Stat(filepath.Join(root, "etc", "systemd", "system", u)); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	/* Docker starts only after the egress rules are applied; a failing apply keeps it down. */
	dropIn := string(readFile(t, filepath.Join(root, "etc", "systemd", "system", "docker.service.d", "nms-egress.conf")))
	if !strings.Contains(dropIn, "[Service]\nExecStartPre=/usr/local/bin/nmsctl egress apply\nExecStartPost=/usr/local/bin/nmsctl egress check\n") ||
		strings.Contains(dropIn, "=-") {
		t.Errorf("docker drop-in:\n%s", dropIn)
	}
	if got := strings.TrimSpace(string(readFile(t, o.TOTPSecretOut))); got != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("totp secret out = %q", got)
	}
	if !strings.Contains(out.String(), "WARNING") {
		t.Errorf("no warning about --totp-secret-out:\n%s", out)
	}

	/* The running binary is copied to /usr/local/bin/nmsctl for the anchor timer, owned by root. */
	dst := filepath.Join(root, "usr", "local", "bin", "nmsctl")
	if !bytes.Equal(readFile(t, dst), readFile(t, sys.exe)) {
		t.Fatal("nmsctl not copied to the host binary path")
	}
	if runtime.GOOS == "linux" {
		if st, err := os.Stat(dst); err != nil || st.Mode().Perm() != 0o755 {
			t.Errorf("nmsctl mode: %v %v", st, err)
		}
	}
	var rootOwned bool
	for p, owner := range sys.chowns {
		rootOwned = rootOwned || (filepath.Dir(p) == filepath.Dir(dst) && owner == [2]int{0, 0})
	}
	if !rootOwned {
		t.Errorf("nmsctl not chowned to root: %v", sys.chowns)
	}
	if entries, _ := os.ReadDir(filepath.Dir(dst)); len(entries) != 1 {
		t.Errorf("leftover temp files: %v", entries)
	}
}

func TestEgressDropInBeforeContainers(t *testing.T) {
	o, root, out := installOptions(t)
	dropIn := filepath.Join(root, "etc", "systemd", "system", "docker.service.d", "nms-egress.conf")
	sys := newFakeSys()
	reloaded, checked := false, false
	sys.onRun = func(c install.Cmd) {
		if c.Name == "systemctl" && cmdline(c) == "systemctl daemon-reload" {
			_, err := os.Stat(dropIn)
			reloaded = reloaded || err == nil
		}
		if c.Name == "docker" && !checked {
			checked = true
			if !reloaded {
				t.Errorf("first docker command %q ran before the drop-in was written and systemd reloaded", cmdline(c))
			}
		}
	}
	if err := install.Run(context.Background(), o, sys); err != nil {
		t.Fatalf("Run: %v\n%s", err, out)
	}
	if !checked {
		t.Fatal("no docker command ran")
	}
}

func TestRunFailsWhenDockerBypassesDockerUser(t *testing.T) {
	o, _, out := installOptions(t)
	sys := newFakeSys()
	sys.run = func(c install.Cmd) error {
		if cmdline(c) == "iptables -w -C FORWARD -j DOCKER-USER" {
			return errors.New("iptables: Bad rule")
		}
		return nil
	}
	err := install.Run(context.Background(), o, sys)
	if !errors.Is(err, install.ErrEgressBypassed) {
		t.Fatalf("Run = %v, want ErrEgressBypassed\n%s", err, out)
	}
	for _, c := range sys.cmds {
		if c.Name == "docker" {
			t.Fatalf("containers started without effective egress rules: %s", cmdline(c))
		}
	}
}

func TestRunKeepsHostBinaryWhenRunFromIt(t *testing.T) {
	o, root, out := installOptions(t)
	dst := filepath.Join(root, "usr", "local", "bin", "nmsctl")
	writeFile(t, dst, "the installed nmsctl")
	sys := newFakeSys()
	sys.exe = dst
	if err := install.Run(context.Background(), o, sys); err != nil {
		t.Fatalf("Run: %v\n%s", err, out)
	}
	if got := string(readFile(t, dst)); got != "the installed nmsctl" {
		t.Fatalf("host binary rewritten: %q", got)
	}
	for p := range sys.chowns {
		if filepath.Dir(p) == filepath.Dir(dst) {
			t.Fatalf("chowned %s", p)
		}
	}
	if strings.Contains(out.String(), "Installed nmsctl") {
		t.Fatalf("reported a copy:\n%s", out)
	}
}

func TestReinstallRefusedAndSecretsUntouched(t *testing.T) {
	o, root, _ := installOptions(t)
	if err := install.Run(context.Background(), o, newFakeSys()); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	etc, vr := filepath.Join(root, "etc", "nms"), filepath.Join(root, "var", "lib", "nms")
	secrets, gw := snapshot(t, filepath.Join(etc, "secrets")), snapshot(t, filepath.Join(vr, "gateway"))
	if len(secrets) != len(secretNames) {
		t.Fatalf("secrets: %d files", len(secrets))
	}
	time.Sleep(20 * time.Millisecond) /* a rewrite would show in mtime */

	sys := newFakeSys()
	o.TOTPSecretOut = filepath.Join(t.TempDir(), "totp")
	if err := install.Run(context.Background(), o, sys); !errors.Is(err, install.ErrAlreadyInstalled) {
		t.Fatalf("second Run = %v, want ErrAlreadyInstalled", err)
	}
	assertSnapshot(t, filepath.Join(etc, "secrets"), secrets)
	assertSnapshot(t, filepath.Join(vr, "gateway"), gw)
	if len(sys.cmds) != 0 || len(sys.chowns) != 0 {
		t.Fatalf("second Run acted: cmds=%v chowns=%v", sys.cmds, sys.chowns)
	}
}

func TestRunRejectsBadInputBeforeWriting(t *testing.T) {
	cases := map[string]func(o *install.Options){
		"bad host":          func(o *install.Options) { o.PublicHost = "bad host" },
		"weak password":     func(o *install.Options) { writeFile(t, o.AdminPasswordFile, "short") },
		"no password":       func(o *install.Options) { o.AdminPasswordFile = "" },
		"bad infra":         func(o *install.Options) { o.InfraNTP = []string{"ntp;rm -rf /"} },
		"cert without key":  func(o *install.Options) { o.WebCertFile = o.AdminPasswordFile },
		"missing image tag": func(o *install.Options) { o.ImageTag = "" },
		"totp out exists":   func(o *install.Options) { writeFile(t, o.TOTPSecretOut, "old") },
		"totp out no dir":   func(o *install.Options) { o.TOTPSecretOut = filepath.Join(t.TempDir(), "missing", "totp") },
		"no mgmt subnet":    func(o *install.Options) { o.MgmtSubnets = nil },
		"reserved mgmt":     func(o *install.Options) { o.MgmtSubnets = []string{"10.0.0.0/8", "127.0.0.0/8"} },
		"bad devices":       func(o *install.Options) { o.DevicesSubnet = "172.30.0.0/24" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o, root, _ := installOptions(t)
			mutate(&o)
			sys := newFakeSys()
			if err := install.Run(context.Background(), o, sys); err == nil {
				t.Fatal("Run succeeded")
			}
			if _, err := os.Stat(filepath.Join(root, "etc", "nms")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s created on bad input (%v)", filepath.Join(root, "etc", "nms"), err)
			}
			if len(sys.cmds) != 0 {
				t.Fatalf("commands ran: %v", sys.cmds)
			}
		})
	}
}

func TestRunKeepsForeignSecretsWithoutMarker(t *testing.T) {
	o, root, _ := installOptions(t)
	key := filepath.Join(root, "etc", "nms", "secrets", "api_data_key")
	writeFile(t, key, "existing")
	sys := newFakeSys()
	err := install.Run(context.Background(), o, sys)
	if !errors.Is(err, install.ErrSecretsExist) || strings.Contains(err.Error(), "remove") {
		t.Fatalf("Run = %v, want ErrSecretsExist without a removal hint", err)
	}
	if string(readFile(t, key)) != "existing" || len(sys.cmds) != 0 {
		t.Fatal("existing secrets touched or commands ran")
	}
}

func TestRunInToolsArgv(t *testing.T) {
	sys := newFakeSys()
	var out bytes.Buffer
	err := install.RunInTools(context.Background(), sys, "/etc/nms", []string{"audit", "verify"}, nil, &out, &out)
	if err != nil {
		t.Fatal(err)
	}
	want := "docker compose -f /etc/nms/compose.yaml --profile tools run --rm --no-deps -T nmsctl audit verify"
	if len(sys.cmds) != 1 || cmdline(sys.cmds[0]) != want {
		t.Fatalf("argv = %v, want %q", sys.cmds, want)
	}
}

func TestAdminCreateRejectsBadTOTPOutBeforeRunning(t *testing.T) {
	existing := filepath.Join(t.TempDir(), "totp")
	writeFile(t, existing, "old")
	for _, out := range []string{existing, filepath.Join(t.TempDir(), "missing", "totp")} {
		sys := newFakeSys()
		var buf bytes.Buffer
		err := install.AdminCreate(context.Background(), sys, "/etc/nms", "admin", secret.New(adminPassword), out, &buf, &buf)
		if err == nil || len(sys.cmds) != 0 {
			t.Fatalf("%s: err=%v cmds=%v, want an error before any command", out, err, sys.cmds)
		}
	}
}

/* The TLS syslog certificate is signed by the internal CA also when the panel uses a corporate certificate, and it matches the public host. */
func TestSyslogCertSignedByInternalCA(t *testing.T) {
	corpCrt, corpCA, err := pki.NewCA("corp", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	crt, key, err := pki.IssueServerCert(corpCrt, corpCA, []string{"nms.corp.example"}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "secrets")
	if err := install.WriteSecrets(dir, install.SecretsInput{PublicHost: "NMS.corp.example", WebCertPEM: crt, WebKeyPEM: key, Chown: newFakeSys().Chown}); err != nil {
		t.Fatal(err)
	}
	verifyCert(t, dir, "syslog.crt", "nms.corp.example")
	if _, err := tls.X509KeyPair(readFile(t, filepath.Join(dir, "syslog.crt")), readFile(t, filepath.Join(dir, "syslog.key"))); err != nil {
		t.Fatalf("syslog certificate and key do not form a pair: %v", err)
	}

	/* An IPv4 public host becomes an IP SAN. */
	dir2 := filepath.Join(t.TempDir(), "secrets")
	if err := install.WriteSecrets(dir2, install.SecretsInput{PublicHost: "192.0.2.10", Chown: newFakeSys().Chown}); err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(readFile(t, filepath.Join(dir2, "syslog.crt")))
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil || len(c.IPAddresses) != 1 || c.IPAddresses[0].String() != "192.0.2.10" {
		t.Fatalf("syslog certificate SANs = %v %v (%v)", c.DNSNames, c.IPAddresses, err)
	}
}

/* A published port that is taken stops the install before anything is written, naming the port and the likely culprit. */
func TestPreflightHostPorts(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "etc", "docker", "daemon.json"), goodDaemonJSON)
	sys := newFakeSys()
	sys.goos, sys.docker = "linux", "28.1.1"
	for _, c := range []struct {
		proto   string
		port    int
		culprit string
	}{{"udp", 514, "rsyslog"}, {"tcp", 514, "rsyslog"}, {"tcp", 6514, "rsyslog"}, {"udp", 162, "snmptrapd"}, {"tcp", 443, "web server"}} {
		busy := errors.New("address already in use")
		err := install.Preflight(install.Options{Root: root, PortFree: func(proto string, port int) error {
			if proto == c.proto && port == c.port {
				return busy
			}
			return nil
		}}, sys)
		if !errors.Is(err, install.ErrPortInUse) || !strings.Contains(err.Error(), fmt.Sprintf("%d/%s", c.port, c.proto)) || !strings.Contains(err.Error(), c.culprit) {
			t.Errorf("%s/%d: %v", c.proto, c.port, err)
		}
	}
	if err := install.Preflight(install.Options{Root: root, PortFree: func(string, int) error { return nil }}, sys); err != nil {
		t.Errorf("all ports free: %v", err)
	}

	/* The real check sees a bound port. */
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Skip(err)
	}
	defer func() { _ = l.Close() }()
	if install.ListenFree("tcp", l.Addr().(*net.TCPAddr).Port) == nil {
		t.Error("ListenFree accepted a port in use")
	}
}
