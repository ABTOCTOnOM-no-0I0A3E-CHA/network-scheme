package main

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/install"
	"github.com/beekamai/network-scheme/internal/secret"
	"github.com/beekamai/network-scheme/internal/sysbackup"
)

const (
	testCID  = "0123456789ab"
	testPass = "correct horse battery"
)

/* stackFake answers the docker commands of backup and restore. */
type stackFake struct {
	fakeSys
	state []byte
}

func (f *stackFake) Run(ctx context.Context, c install.Cmd) error {
	if err := f.fakeSys.Run(ctx, c); err != nil {
		return err
	}
	a, w := strings.Join(c.Args, " "), c.Stdout
	if w == nil {
		w = io.Discard
	}
	var out string
	switch {
	case strings.HasSuffix(a, " ps -aq executor"), strings.HasSuffix(a, " ps -q --status running executor"):
		out = testCID
	case strings.Contains(a, "server_version_num"):
		out = "170006 2.30.2\n"
	case strings.Contains(a, "pg_dump"):
		out = "PGDMP a dump"
	case a == "cp "+testCID+":/var/lib/executor -":
		out = string(f.state)
	case strings.HasSuffix(a, "/executor admin"):
		out = `{"ok":true,"text":"registry verified at counter 5; not frozen"}` + "\n"
	}
	_, err := io.WriteString(w, out)
	return err
}

/* argv lists the recorded commands as strings. */
func (f *stackFake) argv() []string {
	var out []string
	for _, c := range f.cmds {
		out = append(out, strings.Join(c.Args, " "))
	}
	return out
}

/* index is the position of the first command containing s, or -1. */
func (f *stackFake) index(s string) int {
	return slices.IndexFunc(f.argv(), func(a string) bool { return strings.Contains(a, s) })
}

func stateTar(t *testing.T, body string) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	file := "0011\n" + body
	for _, h := range []*tar.Header{
		{Name: "executor/", Typeflag: tar.TypeDir, Mode: 0o700},
		{Name: "executor/state", Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(file))},
	} {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tw.Write([]byte(file)); err != nil || tw.Close() != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

/* host points the install paths into a new root and returns it. */
func host(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	oldEtc, oldVar, oldRoot := etcDir, varDir, hostRoot
	t.Cleanup(func() { etcDir, varDir, hostRoot = oldEtc, oldVar, oldRoot })
	etcDir, varDir, hostRoot = filepath.Join(root, "etc", "nms"), filepath.Join(root, "var", "lib", "nms"), root
	return root
}

func write(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func runWith(sys install.System, stdin string, args ...string) (int, string) {
	var out bytes.Buffer
	d := deps{in: strings.NewReader(stdin), out: &out, errw: &out, sys: sys, now: func() time.Time { return time.Date(2026, 11, 13, 1, 2, 3, 0, time.UTC) }}
	return run(context.Background(), args, d), out.String()
}

/* backupFixture makes an install with a running executor and backs it up into a new directory. */
func backupFixture(t *testing.T) (data, keys string) {
	t.Helper()
	host(t)
	write(t, filepath.Join(etcDir, "secrets", "db_cli_password"), "pw")
	write(t, filepath.Join(etcDir, install.EgressFile), "devices_subnet: 172.30.0.0/24\nmgmt_subnets: [10.20.0.0/24]\n")
	write(t, filepath.Join(etcDir, "compose.yaml"), "name: nms\n")
	write(t, filepath.Join(etcDir, "installed"), "")
	write(t, filepath.Join(varDir, "anchors", "anchors.log"), "anchor\n")
	sys := &stackFake{state: stateTar(t, `{"v":1,"committed":{"hwm":5},"pending":null,"frozen":false}`)}
	out := t.TempDir()
	if code, msg := runWith(sys, testPass+"\n", "backup", "--out", out, "--passphrase-file", "-"); code != 0 {
		t.Fatalf("backup: %s", msg)
	}
	stop, cp, dump, start := sys.index(" stop executor"), sys.index("cp "+testCID), sys.index("pg_dump"), sys.index(" start executor")
	if stop < 0 || stop > cp || cp > dump || dump > start {
		t.Fatalf("not stop, copy, dump, start: %q", sys.argv())
	}
	return filepath.Join(out, "nms-backup-20261113T010203Z.age"), filepath.Join(out, "nms-keys-20261113T010203Z.age")
}

func TestBackupWritesBothArchivesAroundAStoppedExecutor(t *testing.T) {
	data, keys := backupFixture(t)
	entries, id, err := readKeysFile(keys, secret.New(testPass))
	if err != nil || len(entries) == 0 {
		t.Fatal(err)
	}
	df, err := os.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = df.Close() }()
	m, err := sysbackup.VerifyData(df, id)
	if err != nil || m.ExecutorHWM != 5 || string(m.Files["anchors/anchors.log"]) != "anchor\n" || m.TimescaleDB != "2.30.2" {
		t.Fatalf("manifest %+v: %v", m, err)
	}
}

func TestBackupRefusesAChangeInFlightAndRestartsTheExecutor(t *testing.T) {
	host(t)
	write(t, filepath.Join(etcDir, "secrets", "db_cli_password"), "pw")
	sys := &stackFake{state: stateTar(t, `{"v":1,"committed":{"hwm":5},"pending":{"hwm":6},"pending_xid":9}`)}
	out := t.TempDir()
	code, msg := runWith(sys, testPass+"\n", "backup", "--out", out, "--passphrase-file", "-")
	if code == 0 || !strings.Contains(msg, "in flight") || sys.index(" start executor") < 0 || sys.index("pg_dump") >= 0 {
		t.Fatalf("code %d %s %q", code, msg, sys.argv())
	}
	if ents, _ := os.ReadDir(out); len(ents) != 0 {
		t.Fatalf("left %v", ents)
	}
}

func TestBackupRefusesAShortPassphrase(t *testing.T) {
	host(t)
	if code, msg := runWith(&stackFake{}, "short\n", "backup", "--passphrase-file", "-"); code == 0 || !strings.Contains(msg, "at least") {
		t.Fatalf("code %d %s", code, msg)
	}
}

/* A wrong passphrase or a tampered data archive fails before anything is written or started. */
func TestRestoreRefusesBadArchivesWithoutChanges(t *testing.T) {
	data, keys := backupFixture(t)
	raw, err := os.ReadFile(data)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-20] ^= 1
	tampered := filepath.Join(t.TempDir(), "tampered.age")
	write(t, tampered, string(raw))
	for _, c := range []struct{ pass, data string }{{"wrong passphrase here", data}, {testPass, tampered}} {
		host(t)
		sys := &stackFake{}
		code, msg := runWith(sys, c.pass+"\n", "restore", "--data", c.data, "--keys", keys, "--passphrase-file", "-")
		if code == 0 {
			t.Fatalf("restore succeeded: %s", msg)
		}
		if a := sys.argv(); len(a) != 1 || !strings.HasPrefix(a[0], "volume ls") {
			t.Fatalf("ran %q", a)
		}
		if _, err := os.Stat(etcDir); !os.IsNotExist(err) {
			t.Fatalf("%s written", etcDir)
		}
	}
}

func TestRestoreRefusesAServerInUse(t *testing.T) {
	_, keys := backupFixture(t)
	write(t, filepath.Join(etcDir, "x"), "")
	if code, msg := runWith(&stackFake{}, testPass+"\n", "restore", "--data", keys, "--keys", keys, "--passphrase-file", "-"); code == 0 || !strings.Contains(msg, "clean server") {
		t.Fatalf("code %d %s", code, msg)
	}
}

func TestRestorePutsTheInstallBack(t *testing.T) {
	data, keys := backupFixture(t)
	host(t)
	sys := &stackFake{}
	if code, msg := runWith(sys, testPass+"\n", "restore", "--data", data, "--keys", keys, "--passphrase-file", "-"); code != 0 {
		t.Fatalf("restore: %s\n%q", msg, sys.argv())
	}
	order := []string{"-C FORWARD -j DOCKER-USER", "up -d --wait postgres", "pg_restore", "up --no-start executor", "cp -a - " + testCID + ":/var/lib",
		"up -d --wait --wait-timeout", "nmsctl restore record", "nmsctl audit anchor", "nms-audit-anchor.timer", "/executor admin"}
	last := -1
	for _, s := range order {
		i := sys.index(s)
		if i <= last {
			t.Fatalf("%q out of order in %q", s, sys.argv())
		}
		last = i
	}
	if got := sys.stdins[sys.index("cp -a")]; !strings.Contains(got, `"hwm":5`) {
		t.Fatalf("state %q", got)
	}
	if got := sys.stdins[sys.index("pg_restore")]; got != "PGDMP a dump" {
		t.Fatalf("dump %q", got)
	}
	for _, p := range []string{filepath.Join(etcDir, "secrets", "db_cli_password"), filepath.Join(etcDir, "secrets", "backup_age.key"),
		filepath.Join(etcDir, "installed"), filepath.Join(varDir, "anchors", "anchors.log")} {
		if _, err := os.Stat(p); err != nil {
			t.Fatal(err)
		}
	}
}
