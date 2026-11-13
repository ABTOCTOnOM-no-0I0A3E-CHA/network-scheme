package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/install"
)

/* rotator is the host: docker calls are recorded; the one-shot rotate-key answers with result (or fails with fail). */
type rotator struct {
	fakeSys
	result string
	fail   error
}

func (f *rotator) Run(ctx context.Context, c install.Cmd) error {
	if err := f.fakeSys.Run(ctx, c); err != nil {
		return err
	}
	if a := strings.Join(c.Args, " "); strings.Contains(a, "rotate-key") || strings.Contains(a, "reseal-backup") {
		if f.fail != nil {
			return f.fail
		}
		_, _ = c.Stdout.Write([]byte(f.result))
	}
	return nil
}

func (f *rotator) argv() []string {
	var out []string
	for _, c := range f.cmds {
		out = append(out, c.Name+" "+strings.Join(c.Args, " "))
	}
	return out
}

func withSecrets(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(b), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	old := secretsDir
	secretsDir = dir
	t.Cleanup(func() { secretsDir = old })
	return dir
}

func hostRun(t *testing.T, sys install.System, args ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	d := deps{in: strings.NewReader(""), out: &out, errw: &out, sys: sys, now: time.Now}
	return run(context.Background(), args, d), out.String()
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

/*
The sealing key rotation stops the executor, hands the staged key to the
one-shot rotate-key on stdin (never argv), and only after it succeeded
replaces the key file and starts the executor. A failed run leaves the key
file, the staged key and a stopped executor; the next run resumes with the
same staged key.
*/
func TestSealingKeyRotation(t *testing.T) {
	dir := withSecrets(t, map[string]string{"executor_sealing_key": "old"})
	p := filepath.Join(dir, "executor_sealing_key")
	sys := &rotator{fail: errors.New("exit status 1")}
	if code, out := hostRun(t, sys, "executor", "key", "rotate", "--yes"); code == 0 || !strings.Contains(out, "resume") {
		t.Fatalf("failed run: %d %s", code, out)
	}
	staged := read(t, p+".next")
	if read(t, p) != "old" || len(staged) != 44 {
		t.Fatalf("after a failed run: key %q staged %q", read(t, p), staged)
	}
	for _, a := range sys.argv() {
		if strings.Contains(a, staged) || strings.Contains(a, "up -d") {
			t.Fatalf("argv %q", a)
		}
	}
	sys = &rotator{result: `{"version":2,"rows":5,"totps":1,"resumed":true,"already":false}` + "\n"}
	code, out := hostRun(t, sys, "executor", "key", "rotate", "--yes")
	if code != 0 || !strings.Contains(out, "version 2") {
		t.Fatalf("resumed run: %d %s", code, out)
	}
	want := []string{
		"docker compose -f /etc/nms/compose.yaml stop executor",
		"docker compose -f /etc/nms/compose.yaml run --rm --no-deps -T executor rotate-key",
		"docker compose -f /etc/nms/compose.yaml up -d executor",
	}
	if got := sys.argv(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("commands:\n%s", strings.Join(got, "\n"))
	}
	if !strings.HasPrefix(sys.stdins[1], staged+"\n") {
		t.Fatalf("stdin %q", sys.stdins[1])
	}
	if read(t, p) != staged {
		t.Fatal("the key file is not the staged key")
	}
	if _, err := os.Stat(p + ".next"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged key left: %v", err)
	}
}

/* An executor that answers nonsense is not taken for a finished rotation: the key file stays. */
func TestSealingKeyRotationNeedsAResult(t *testing.T) {
	dir := withSecrets(t, map[string]string{"executor_sealing_key": "old"})
	sys := &rotator{result: "{}\n"}
	if code, _ := hostRun(t, sys, "executor", "key", "rotate", "--yes"); code == 0 {
		t.Fatal("accepted")
	}
	if read(t, filepath.Join(dir, "executor_sealing_key")) != "old" {
		t.Fatal("key file replaced")
	}
}

/* The ticket rotation installs a matching pair (pub first) and restarts api and executor; a run interrupted after the pub resumes with the staged key. */
func TestTicketKeyRotation(t *testing.T) {
	dir := withSecrets(t, map[string]string{"ticket.key": "oldkey", "ticket.pub": "oldpub"})
	sys := &rotator{}
	if code, out := hostRun(t, sys, "keys", "rotate", "ticket"); code != 0 {
		t.Fatalf("%d %s", code, out)
	}
	seed, err := base64.StdEncoding.DecodeString(read(t, filepath.Join(dir, "ticket.key")))
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("ticket.key %v", err)
	}
	pub := base64.StdEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	if read(t, filepath.Join(dir, "ticket.pub")) != pub {
		t.Fatal("ticket.pub does not match ticket.key")
	}
	if got := strings.Join(sys.argv(), "\n"); got != "docker compose -f /etc/nms/compose.yaml restart api executor" {
		t.Fatalf("commands %s", got)
	}
	/* Interrupted after ticket.pub was replaced: only ticket.key.next is left. */
	if err := os.WriteFile(filepath.Join(dir, "ticket.key.next"), []byte(base64.StdEncoding.EncodeToString(seed)), 0o400); err != nil {
		t.Fatal(err)
	}
	if code, out := hostRun(t, &rotator{}, "keys", "rotate", "ticket"); code != 0 || !strings.Contains(out, "resuming") {
		t.Fatalf("resume: %d %s", code, out)
	}
	if read(t, filepath.Join(dir, "ticket.pub")) != pub {
		t.Fatal("resume changed ticket.pub")
	}
	if code, _ := hostRun(t, &rotator{fakeSys: fakeSys{inContainer: true}}, "keys", "rotate", "ticket"); code == 0 {
		t.Fatal("ran inside a container")
	}
}
