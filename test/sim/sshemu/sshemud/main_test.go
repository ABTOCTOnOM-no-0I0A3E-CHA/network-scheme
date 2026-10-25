package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
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
