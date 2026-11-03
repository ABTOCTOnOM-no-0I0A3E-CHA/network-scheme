/*
Command sshemud is the SSH device emulator of the e2e stack: package sshemu as
a standalone server. Every command line is answered from a file of -dir named
exactly as the line ("show running-config", "terminal datadump", ...), read
again at every command, so a test changes the device's output by rewriting
the file. A line with no file (or one that cannot name a file) answers
"% Unrecognized command". Every line received is logged, for the job log.
The host key is generated at start. Test-only: the password is a flag.

With -profile (a line of test/fixtures/devices, e.g. "esr", or a fixture
directory) the stateful emulator of package devemu serves the shell instead:
modes, prompts from the fixture (-prompt is ignored), echo, pager,
confirmations, commit timers on the wall clock, and the profile's SSH
algorithms and host-key type. -dir, when given, still overrides outputs: a
command line with a file there is answered from it. Every line received is
logged as "command" with the mode it was typed in.
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

	"github.com/beekamai/network-scheme/test/sim/devemu"
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
	profile := flag.String("profile", "", "devemu fixture line or directory (empty: the stateless emulator)")
	flag.Parse()
	var err error
	if *profile != "" {
		err = runProfile(*listen, *profile, *user, *password, *dir)
	} else {
		err = run(*listen, *prompt, *user, *password, *dir)
	}
	log.Error("sshemud stopped", "err", err)
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

/* lookup reads the output of cmd from dir and logs the command. */
func lookup(dir, cmd string) (string, bool) {
	out, ok := readOutput(dir, cmd)
	log.Info("command", "cmd", cmd, "known", ok)
	return out, ok
}

/* readOutput reads the output of cmd from dir; lines that are not a plain file name are unknown. */
func readOutput(dir, cmd string) (string, bool) {
	ok := !strings.ContainsAny(cmd, "/\\\x00") && !strings.HasPrefix(cmd, ".")
	var out []byte
	if ok {
		var err error
		out, err = os.ReadFile(filepath.Join(dir, cmd)) // #nosec G304 -- test emulator; cmd cannot leave dir
		ok = err == nil
	}
	return strings.TrimRight(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n"), ok
}

/* runProfile serves the stateful emulator of a fixture until the listener fails; it never returns nil. */
func runProfile(listen, profile, user, password, dir string) error {
	cfg, line, err := profileConfig(profile, user, password, dir)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	log.Info("sshemud listening", "addr", ln.Addr().String(), "profile", line)
	return sshemu.Serve(ln, cfg, nil)
}

/* profileConfig loads the fixture and returns the transport serving its device, and the device's line. */
func profileConfig(profile, user, password, dir string) (sshemu.Config, string, error) {
	if password == "" {
		return sshemu.Config{}, "", errors.New("-password is required")
	}
	if !strings.ContainsAny(profile, "/\\") {
		profile = filepath.Join(devemu.FixturesDir(), profile)
	}
	fx, err := devemu.Load(profile)
	if err != nil {
		return sshemu.Config{}, "", err
	}
	d := devemu.New(fx, devemu.Options{})
	if dir != "" {
		d.SetShowLookup(func(cmd string) (string, bool) { return readOutput(dir, cmd) })
	}
	d.OnInput(func(e devemu.Entry) {
		if e.Kind == "line" {
			log.Info("command", "cmd", e.Input, "mode", e.Mode)
		}
	})
	go d.RunClock(nil)
	cfg, err := d.SSHConfig()
	if err != nil {
		return sshemu.Config{}, "", err
	}
	cfg.Username, cfg.Password = user, password
	return cfg, fx.Profile.Line, nil
}
