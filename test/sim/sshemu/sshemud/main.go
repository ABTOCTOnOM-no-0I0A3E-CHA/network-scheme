/*
Command sshemud is the SSH device emulator of the e2e stack: package sshemu as
a standalone server. Every command line is answered from a file of -dir named
exactly as the line ("show running-config", "terminal datadump", ...), read
again at every command, so a test changes the device's output by rewriting
the file. A line with no file (or one that cannot name a file) answers
"% Unrecognized command". Every line received is logged, for the job log.
The host key is generated at start. Test-only: the password is a flag.
*/
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"

	gossh "golang.org/x/crypto/ssh"

	"github.com/beekamai/network-scheme/test/sim/sshemu"
)

/* log writes to stdout without timestamps, so the job can count identical lines. */
var log = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
	if a.Key == slog.TimeKey {
		return slog.Attr{}
	}
	return a
}}))

func main() {
	listen := flag.String("listen", ":22", "listen address")
	prompt := flag.String("prompt", "sw1#", "privileged EXEC prompt")
	user := flag.String("user", "", "accepted user (empty: any)")
	password := flag.String("password", "", "accepted password")
	dir := flag.String("dir", "", "directory of command outputs")
	flag.Parse()
	log.Error("sshemud stopped", "err", run(*listen, *prompt, *user, *password, *dir))
	os.Exit(1)
}

/* run serves until the listener fails; it never returns nil. */
func run(listen, prompt, user, password, dir string) error {
	if dir == "" || password == "" {
		return errors.New("-dir and -password are required")
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	signer, err := gossh.NewSignerFromKey(key)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	log.Info("sshemud listening", "addr", ln.Addr().String())
	return sshemu.Serve(ln, sshemu.Config{
		HostKey:  signer,
		Prompt:   prompt,
		Username: user,
		Password: password,
		Lookup:   func(cmd string) (string, bool) { return lookup(dir, cmd) },
	}, nil)
}

/* lookup reads the output of cmd from dir; lines that are not a plain file name are unknown. */
func lookup(dir, cmd string) (string, bool) {
	ok := !strings.ContainsAny(cmd, "/\\\x00") && !strings.HasPrefix(cmd, ".")
	var out []byte
	if ok {
		var err error
		out, err = os.ReadFile(filepath.Join(dir, cmd)) // #nosec G304 -- test emulator; cmd cannot leave dir
		ok = err == nil
	}
	log.Info("command", "cmd", cmd, "known", ok)
	return strings.TrimRight(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n"), ok
}
