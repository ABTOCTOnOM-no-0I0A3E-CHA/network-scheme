package transport

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/beekamai/network-scheme/cmd/executor/internal/identify"
	"github.com/beekamai/network-scheme/cmd/executor/internal/strategy"
	"github.com/beekamai/network-scheme/internal/secret"
	"github.com/beekamai/network-scheme/test/sim/devemu"
	"github.com/beekamai/network-scheme/test/sim/sshemu"
)

/*
An async line and the prompt redrawn behind it, before a slow device's
reply: the read must not end at the redrawn prompt and report the error as
success (nor leave the reply for the next command).
*/
func TestStrayPromptAfterAsyncDoesNotEndTheRead(t *testing.T) {
	for _, line := range []string{"esr", "mes6", "mes10"} {
		r := start(t, line, devemu.Options{}, nil)
		r.src.profiles = verified(strategy.Line(line), map[string]string{"concurrency": "trust"})
		if line != "esr" {
			r.src.profiles = verified(strategy.Line(line), nil)
		}
		sh := r.mustDial(t)
		r.d.BeforeReply(func(l string) (string, time.Duration) {
			if l == "bogus command" {
				return "%SYS-I-TEST: async before the reply", 500 * time.Millisecond
			}
			return "", 0
		})
		out, err := sh.Send(ctx(t), "bogus command")
		if !errors.Is(err, ErrDevice) || out.Error == "" {
			t.Fatalf("%s: the error came back as success: %+v %v", line, out, err)
		}
		if len(out.Async) != 1 || strings.Contains(out.Text(), "%SYS") {
			t.Errorf("%s: async %q lines %q", line, out.Async, out.Lines)
		}
		if _, err := sh.Run(ctx(t), showVersion); err != nil {
			t.Errorf("%s: next command: %v", line, err)
		}
	}
}

/* rawDevice is an ESR-like shell on sshemu whose replies the test writes itself: reply gets each line and the channel. */
func rawDevice(t *testing.T, r *rig, reply func(line string, w io.Writer)) {
	t.Helper()
	key := sshemu.NewHostKey(t)
	fx, _ := devemu.LoadLine("esr")
	addr, _ := sshemu.Start(t, sshemu.Config{HostKey: key, Username: "admin", Password: pw,
		Shell: func(_ string, ch io.ReadWriteCloser) {
			_, _ = io.WriteString(ch, "esr# ")
			buf, line := make([]byte, 256), ""
			for {
				n, err := ch.Read(buf)
				if err != nil {
					return
				}
				line += string(buf[:n])
				for {
					l, rest, ok := strings.Cut(line, "\n")
					if !ok {
						break
					}
					line, l = rest, strings.TrimSpace(l)
					if out := fx.Show[l]; out != "" {
						_, _ = io.WriteString(ch, l+"\r\n"+strings.ReplaceAll(out, "\n", "\r\n")+"\r\nesr# ")
						continue
					}
					reply(l, ch)
				}
			}
		}})
	r.src.t.addr, r.src.t.hostFP, r.src.t.hostAlgo = addr, gossh.FingerprintSHA256(key.PublicKey()), key.PublicKey().Type()
	r.src.profiles = verified(strategy.ESR, map[string]string{"concurrency": "trust", "terminal": "none"})
}

/* A prompt redrawn before the echo of the line is not its reply. */
func TestPromptBeforeTheEchoIsIgnored(t *testing.T) {
	r := start(t, "esr", devemu.Options{}, nil)
	rawDevice(t, r, func(l string, w io.Writer) {
		_, _ = io.WriteString(w, "\r\nesr# ")
		time.Sleep(400 * time.Millisecond)
		_, _ = io.WriteString(w, l+"\r\n% Unrecognized command\r\nesr# ")
	})
	sh := r.mustDial(t)
	out, err := sh.Send(ctx(t), "configure")
	if !errors.Is(err, ErrDevice) || out.Error != "% Unrecognized command" {
		t.Fatalf("the reply behind the echo was lost: %+v %v", out, err)
	}
}

/* Output that arrives after a command's prompt (anything but async lines and the prompt) closes the shell before the next line. */
func TestLateOutputFailsClosed(t *testing.T) {
	r := start(t, "esr", devemu.Options{}, nil)
	rawDevice(t, r, func(l string, w io.Writer) {
		_, _ = io.WriteString(w, l+"\r\nesr# ")
		if l == "configure" {
			time.Sleep(300 * time.Millisecond)
			_, _ = io.WriteString(w, "\r\n% Late error\r\nesr# ")
		}
	})
	sh := r.mustDial(t)
	if _, err := sh.Send(ctx(t), "configure"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(600 * time.Millisecond)
	if _, err := sh.Send(ctx(t), "end"); !errors.Is(err, ErrUnexpectedPrompt) {
		t.Fatalf("late output: %v", err)
	}
	select {
	case <-sh.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("not closed")
	}
}

/* Keyboard-interactive: password, then an info round saying expired, then password again: only the first is answered. */
func TestKeyboardInteractiveRounds(t *testing.T) {
	set := strategy.Defaults(strategy.MES6)
	c := Credential{Password: secret.New(pw)}
	var exp atomic.Bool
	ki := kiChallenge(set, c, &exp)
	if ans, err := ki("", "", []string{"Password:"}, []bool{false}); err != nil || !slices.Equal(ans, []string{pw}) {
		t.Fatalf("round 1: %q %v", ans, err)
	}
	if ans, err := ki("", "Your password has expired", nil, nil); !errors.Is(err, ErrPasswordExpired) || ans != nil || !exp.Load() {
		t.Fatalf("round 2: %q %v", ans, err)
	}
	if ans, err := ki("", "", []string{"Password:"}, []bool{false}); err == nil || ans != nil {
		t.Fatalf("round 3 answered: %q", ans)
	}

	/* without an expired round: still only one password round */
	exp.Store(false)
	ki = kiChallenge(set, c, &exp)
	if _, err := ki("", "", nil, nil); err != nil {
		t.Fatalf("empty info round: %v", err)
	}
	if _, err := ki("", "", []string{"Password:"}, []bool{false}); err != nil {
		t.Fatal(err)
	}
	if ans, err := ki("", "", []string{"Password:"}, []bool{false}); !errors.Is(err, ErrLoginFailed) || ans != nil {
		t.Fatalf("second password round: %q %v", ans, err)
	}
	/* a change flow named in the name or instruction is seen before any question is answered */
	for _, nameInstr := range [][2]string{{"Password change", ""}, {"", "You must change your password"}, {"", "Password aging: expires today"}} {
		exp.Store(false)
		ki = kiChallenge(set, c, &exp)
		if ans, err := ki(nameInstr[0], nameInstr[1], []string{"Password:"}, []bool{false}); !errors.Is(err, ErrPasswordExpired) || ans != nil {
			t.Errorf("%q: %q %v", nameInstr, ans, err)
		}
	}
}

/*
Pre-login strategies of the profiles apply before connecting: a device that
refuses the password method is reached with auth=keyboard-interactive, when
the profiles agree, and also when they do not (defaults first, then each).
*/
func TestPreLoginOverridesApply(t *testing.T) {
	kiOnly := func(c *sshemu.Config) { c.KeyboardInteractive, c.NoPasswordAuth = true, true }
	ki := map[string]string{"auth": "keyboard-interactive"}

	r := start(t, "mes10", devemu.Options{}, kiOnly)
	if _, err := r.dial(t); !errors.Is(err, ErrHandshake) {
		t.Fatalf("defaults on a keyboard-interactive device: %v", err)
	}

	r = start(t, "mes10", devemu.Options{}, kiOnly)
	r.src.profiles = verified(strategy.MES10, ki)
	sh := r.mustDial(t)
	if got := r.log.AuthAttempts(); slices.ContainsFunc(got, func(a string) bool { return strings.HasPrefix(a, "password:") }) || !slices.Contains(got, "keyboard-interactive:"+pw) {
		t.Errorf("agreeing profiles: %q", got)
	}
	if !sh.Decision().Write || sh.Strategies().Auth != "keyboard-interactive" {
		t.Errorf("decision %+v", sh.Decision())
	}

	r = start(t, "mes10", devemu.Options{}, kiOnly)
	r.src.profiles = []identify.Profile{
		{ID: 1, WriteDriver: strategy.MES10, ModelRe: "^(?:.*)$", FirmwareRe: `^(?:10\..*)$`, Strategies: ki},
		{ID: 2, WriteDriver: strategy.MES10, ModelRe: "^(?:.*)$", FirmwareRe: `^(?:9\..*)$`},
	}
	sh = r.mustDial(t)
	if sh.Decision().Profile != 1 || sh.Strategies().Auth != "keyboard-interactive" {
		t.Errorf("disagreeing profiles: %+v", sh.Decision())
	}
	/* the defaults' password method is not even offered by the server ("none" probe only), then keyboard-interactive */
	got := r.log.AuthAttempts()
	if n := len(slices.DeleteFunc(slices.Clone(got), func(a string) bool { return a != "none" })); n != 2 || !slices.Contains(got, "keyboard-interactive:"+pw) {
		t.Errorf("defaults first, then the profile's: %q", got)
	}
}

/* ESR exclusive: every row but the header and separators is a session; exactly one, marked "*". */
func TestESRExclusiveRows(t *testing.T) {
	for name, c := range map[string]struct {
		rows []string
		ok   bool
	}{
		"only this one":    {[]string{"-----", "*  1  admin  00:29:59  15  ssh  192.0.2.10"}, true},
		"not marked":       {[]string{"   1  admin  00:29:59  15  ssh  192.0.2.10"}, false},
		"unparsable other": {[]string{"*  1  admin  00:29:59  15  ssh  192.0.2.10", "console  bob"}, false},
		"none":             {nil, false},
	} {
		r := start(t, "esr", devemu.Options{}, nil)
		r.src.profiles = verified(strategy.ESR, nil)
		exclusiveESR(r.d, c.rows...)
		if c.rows == nil {
			r.d.SetShowLookup(func(cmd string) (string, bool) { return "SID  User", cmd == "show users" })
		}
		_, err := r.dial(t)
		if (err == nil) != c.ok || err != nil && !errors.Is(err, ErrNotExclusive) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

/* The in-band password is one line of text: any control byte refuses the login before anything of it is sent. */
func TestInbandPasswordRefusesControls(t *testing.T) {
	for _, p := range []string{"a\x1bb", "a\x7fb", "a\tb", "a\rshow"} {
		r := start(t, "mes6", devemu.Options{InbandLogin: true}, nil)
		r.cfg.Credential.Password = secret.New(p)
		if _, err := r.dial(t); !errors.Is(err, ErrLoginFailed) {
			t.Errorf("%q: %v", p, err)
		}
		r.d.ExpectNone(t, "password", "line")
	}
}

/* An RSA user key signs with SHA-2 (ssh-rsa only with the registry flag). */
func TestRSAUserKey(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	pub, _ := gossh.NewPublicKey(&k.PublicKey)
	r := start(t, "mes10", devemu.Options{}, func(c *sshemu.Config) { c.Password, c.AuthorizedKey = "", pub })
	r.cfg.Credential = Credential{Username: "admin", PrivateKey: secret.New(string(pemKey))}
	r.src.profiles = verified(strategy.MES10, nil)
	r.mustDial(t)
	var exp atomic.Bool
	if _, err := authMethod(strategy.Defaults(strategy.MES10), r.cfg.Credential, false, &exp); err != nil {
		t.Fatal(err)
	}
}
