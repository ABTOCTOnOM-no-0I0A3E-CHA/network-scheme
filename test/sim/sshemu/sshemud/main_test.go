package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/beekamai/network-scheme/test/sim/sshemu"
)

func TestLookup(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "show running-config"), []byte("hostname sw1\r\n exit\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".next"), []byte("hidden"), 0o600); err != nil {
		t.Fatal(err)
	}
	for cmd, want := range map[string]struct {
		out string
		ok  bool
	}{
		"show running-config":          {"hostname sw1\n exit", true},
		"show version":                 {"", false},
		".next":                        {"", false},
		"../main.go":                   {"", false},
		"show interfaces status 1/0/1": {"", false},
	} {
		out, ok := lookup(dir, cmd)
		if out != want.out || ok != want.ok {
			t.Errorf("lookup(%q) = %q, %v; want %q, %v", cmd, out, ok, want.out, want.ok)
		}
	}
}

/* TestServe logs in with the password and reads a served command through a shell, as the poller does. */
func TestServe(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "show version"), []byte("v1.2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = sshemu.Serve(ln, sshemu.Config{HostKey: signer, Prompt: "sw1#", Username: "u", Password: "twelve-chars",
			Lookup: func(cmd string) (string, bool) { return lookup(dir, cmd) }}, nil)
	}()
	c, err := gossh.Dial("tcp", ln.Addr().String(), &gossh.ClientConfig{User: "u", Auth: []gossh.AuthMethod{gossh.Password("twelve-chars")},
		HostKeyCallback: gossh.FixedHostKey(signer.PublicKey()), Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	in, err := s.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	s.Stdout = &out
	if err := s.Shell(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(in, "show version\n"); err != nil {
		t.Fatal(err)
	}
	_ = in.Close()
	_ = s.Wait()
	if !strings.Contains(out.String(), "v1.2\r\nsw1#") {
		t.Fatalf("shell output %q", out.String())
	}
}

/*
TestProfileParity: the poller's dialogue (pager off, running-config, a show
from -dir) gives the same outputs from the stateless emulator and from
-profile, once each side's echo and prompt are stripped as internal/ssh does.
*/
func TestProfileParity(t *testing.T) {
	dir := t.TempDir()
	for name, out := range map[string]string{"show running-config": "hostname e2e\n exit\n", "terminal datadump": "", "show version": "v-e2e\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(out), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	plain := sshemu.Config{HostKey: sshemu.NewHostKey(t), Prompt: "esr-lab-01#", Username: "u", Password: "twelve-chars",
		Lookup: func(cmd string) (string, bool) { return lookup(dir, cmd) }}
	prof, line, err := profileConfig("esr", "u", "twelve-chars", dir)
	if err != nil || line != "esr" {
		t.Fatal(line, err)
	}
	cmds := []string{"terminal datadump", "show running-config", "show version"}
	a, b := dialogue(t, plain, cmds), dialogue(t, prof, cmds)
	if !slices.Equal(a, b) || a[1] != "hostname e2e\n exit" || a[2] != "v-e2e" {
		t.Fatalf("stateless %q\nprofile   %q", a, b)
	}
}

/* dialogue serves cfg, runs cmds in one shell and returns each output without echo and prompt. */
func dialogue(t *testing.T, cfg sshemu.Config, cmds []string) []string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = sshemu.Serve(ln, cfg, nil) }()
	c, err := gossh.Dial("tcp", ln.Addr().String(), &gossh.ClientConfig{User: "u", Auth: []gossh.AuthMethod{gossh.Password("twelve-chars")},
		HostKeyCallback: gossh.FixedHostKey(cfg.HostKey.PublicKey()), Timeout: 10 * time.Second,
		Config: gossh.Config{KeyExchanges: []string{gossh.KeyExchangeECDHP256}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	in, err := s.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	s.Stdout = &out
	if err := s.Shell(); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range append(cmds, "exit") {
		if _, err := io.WriteString(in, cmd+"\r"); err != nil {
			t.Fatal(err)
		}
	}
	_ = in.Close()
	_ = s.Wait()
	/* split at the prompt; drop the banner and the echo of each command */
	parts := strings.Split(strings.ReplaceAll(out.String(), "\r\n", "\n"), "esr-lab-01#")[1:]
	if len(parts) < len(cmds) {
		t.Fatalf("output %q", out.String())
	}
	var got []string
	for i, cmd := range cmds {
		got = append(got, strings.Trim(strings.TrimPrefix(parts[i], cmd), "\n"))
	}
	return got
}
