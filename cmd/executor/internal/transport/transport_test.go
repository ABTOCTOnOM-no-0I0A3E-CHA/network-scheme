package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/beekamai/network-scheme/cmd/executor/internal/identify"
	"github.com/beekamai/network-scheme/cmd/executor/internal/strategy"
	"github.com/beekamai/network-scheme/internal/secret"
	"github.com/beekamai/network-scheme/internal/ssh"
	"github.com/beekamai/network-scheme/test/sim/devemu"
	"github.com/beekamai/network-scheme/test/sim/sshemu"
)

const pw = "transport-test-pw-1"

/* fakeSource is the registry for the tests of this file: a fixed row and model profiles, the gate as in registrySource. */
type fakeSource struct {
	t        target
	profiles []identify.Profile
	decided  atomic.Int32
}

func (f *fakeSource) target(context.Context) (target, error) { return f.t, nil }
func (f *fakeSource) decide(_ context.Context, t target, id identify.Identity) (identify.Decision, error) {
	f.decided.Add(1)
	return identify.Decide(t.line, f.profiles, id)
}

type plainDialer struct{}

func (plainDialer) Dial(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", ap.String())
}

/* alerts records published alerts. */
type alerts struct {
	mu    sync.Mutex
	kinds []string
}

func (a *alerts) add(_ context.Context, kind, severity string, _ int64, _ string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.kinds = append(a.kinds, kind+"/"+severity)
	return nil
}

func (a *alerts) list() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.kinds)
}

/* verified is a model profile of line for any model and firmware with the strategies st. */
func verified(line strategy.Line, st map[string]string) []identify.Profile {
	return []identify.Profile{{ID: 1, WriteDriver: line, ModelRe: "^(?:.*)$", FirmwareRe: "^(?:.*)$", Strategies: st}}
}

type rig struct {
	d   *devemu.Device
	src *fakeSource
	log *sshemu.Log
	al  *alerts
	cfg Config
}

/* start runs an emulated device of line over SSH with user admin; the row is registered as line with the host key pinned. */
func start(t *testing.T, line string, opt devemu.Options, edit func(*sshemu.Config)) *rig {
	t.Helper()
	d := devemu.NewLine(t, line, opt)
	addr, key, log := devemu.StartSSH(t, d, func(c *sshemu.Config) {
		c.Username, c.Password = "admin", pw
		if edit != nil {
			edit(c)
		}
	})
	r := &rig{d: d, log: log, al: &alerts{}}
	r.src = &fakeSource{t: target{deviceID: 7, addr: addr, line: strategy.Line(line), hostAlgo: key.Type(),
		hostFP: gossh.FingerprintSHA256(key), rsaSHA1: line == "mes6", writesEnabled: true}}
	r.cfg = Config{DeviceID: 7, Access: Write, Credential: Credential{Username: "admin", Password: secret.New(pw)},
		Net: plainDialer{}, Alert: r.al.add, CommandTimeout: 5 * time.Second}
	return r
}

func (r *rig) dial(t *testing.T) (*Shell, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sh, err := dial(ctx, r.cfg, r.src)
	if sh != nil {
		t.Cleanup(func() { _ = sh.Close() })
	}
	return sh, err
}

func (r *rig) mustDial(t *testing.T) *Shell {
	t.Helper()
	sh, err := r.dial(t)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return sh
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return c
}

/* exclusiveESR makes "show users" list only this session (the ESR default concurrency is exclusive). */
func exclusiveESR(d *devemu.Device, rows ...string) {
	if len(rows) == 0 {
		rows = []string{"*  1  admin  00:29:59  15  ssh  192.0.2.10"}
	}
	d.SetShowLookup(func(cmd string) (string, bool) {
		if cmd == "show users" {
			return "SID  User  Timeout  Level  Protocol  Host\n" + strings.Join(rows, "\n"), true
		}
		return "", false
	})
}

/* Terminal and confirmation strategies, per line, and their variants: exactly these lines reach the device. */
func TestTerminalAndConfirmationStrategies(t *testing.T) {
	id := []string{"show version", "show system"}
	for _, c := range []struct {
		line string
		st   map[string]string
		want []string
	}{
		{"esr", nil, append(slices.Clone(id), "terminal datadump", "terminal mode machine", "show users", "show configuration changes")},
		{"esr", map[string]string{"terminal": "datadump", "concurrency": "trust"}, append(slices.Clone(id), "terminal datadump")},
		{"esr", map[string]string{"terminal": "none", "concurrency": "trust"}, id},
		{"mes6", nil, append(slices.Clone(id), "terminal datadump", "terminal no prompt")},
		{"mes6", map[string]string{"confirmations": "table"}, append(slices.Clone(id), "terminal datadump")},
		{"mes10", nil, append(slices.Clone(id), "set cli pagination off", "set cli prompt off")},
		{"mes10", map[string]string{"confirmations": "table", "terminal": "none"}, id},
	} {
		t.Run(fmt.Sprintf("%s/%v", c.line, c.st), func(t *testing.T) {
			r := start(t, c.line, devemu.Options{}, nil)
			exclusiveESR(r.d)
			r.src.profiles = verified(strategy.Line(c.line), c.st)
			sh := r.mustDial(t)
			r.d.ExpectLines(t, c.want...)
			if st := sh.State(); st.Mode != ModePrivileged {
				t.Errorf("state after setup: %+v", st)
			}
			if !sh.Decision().Write || sh.Access() != Write {
				t.Errorf("decision %+v", sh.Decision())
			}
		})
	}
}

/* Mode and prompt tracking: privileged, configuration, sub-modes and back; a question is a mode of its own. */
func TestModeTracking(t *testing.T) {
	r := start(t, "esr", devemu.Options{}, nil)
	r.src.profiles = verified(strategy.ESR, map[string]string{"concurrency": "trust"})
	sh := r.mustDial(t)
	c := ctx(t)
	steps := []struct {
		line string
		mode Mode
		sub  string
	}{
		{"configure", ModeConfig, "config"},
		{"interface gigabitethernet 1/0/1", ModeSub, "config-if-gi"},
		{"description uplink", ModeSub, "config-if-gi"},
		{"exit", ModeConfig, "config"},
		{"end", ModePrivileged, ""},
	}
	for _, s := range steps {
		out, err := sh.Send(c, s.line)
		if err != nil || out.State.Mode != s.mode || out.State.Context != s.sub || out.State.Host != "esr-lab-01" {
			t.Fatalf("%q: %+v %v", s.line, out.State, err)
		}
	}
	out, err := sh.Send(c, "reload system")
	if err != nil || out.State.Mode != ModeConfirm || !strings.Contains(out.State.Question, "reload system") {
		t.Fatalf("question: %+v %v", out.State, err)
	}
	if _, err := sh.Send(c, "show version"); !errors.Is(err, ErrQuestionPending) {
		t.Errorf("send while a question waits: %v", err)
	}
	if _, err := sh.Run(c, ssh.ShowCommand{Name: "show version"}); !errors.Is(err, ErrUnexpectedPrompt) {
		t.Errorf("run while a question waits: %v", err)
	}
	if _, err := sh.Answer(c, "y\nreload"); !errors.Is(err, ErrBadLine) {
		t.Errorf("answer with a newline: %v", err)
	}
	if out, err = sh.Answer(c, "n"); err != nil || out.State.Mode != ModePrivileged || r.d.Reboots() != 0 {
		t.Fatalf("answer n: %+v %v reboots %d", out.State, err, r.d.Reboots())
	}
	if _, err := sh.Answer(c, "y"); !errors.Is(err, ErrNoQuestion) {
		t.Errorf("answer without a question: %v", err)
	}
	for _, bad := range []string{"", "show version\nreload system", "show\tversion", "a\x1b[2J", "a\x00", "крипто", strings.Repeat("a", MaxLine+1)} {
		if _, err := sh.Send(c, bad); !errors.Is(err, ErrBadLine) {
			t.Errorf("Send(%q): %v", bad, err)
		}
	}
	if slices.Contains(r.d.Lines(), "reload") || strings.Contains(strings.Join(r.d.Lines(), "|"), "\x1b") {
		t.Errorf("a refused line reached the device: %q", r.d.Lines())
	}
}

/* Pager: answered with the line's key (pager=answer), or the shell closes (pager=fail). */
func TestPagerStrategy(t *testing.T) {
	for _, line := range []string{"esr", "mes6"} {
		r := start(t, line, devemu.Options{}, nil)
		r.src.profiles = verified(strategy.Line(line), map[string]string{"terminal": "none", "concurrency": "trust"})
		sh := r.mustDial(t)
		out, err := sh.Send(ctx(t), "show long")
		if err != nil || len(out.Lines) != 30 || out.Lines[0] != "line 1" || out.Lines[29] != "line 30" {
			t.Fatalf("%s paged: %d lines %q %v", line, len(out.Lines), out.Lines, err)
		}
		if out.State.Mode != ModePrivileged {
			t.Errorf("%s: %+v", line, out.State)
		}
		r2 := start(t, line, devemu.Options{}, nil)
		r2.src.profiles = verified(strategy.Line(line), map[string]string{"terminal": "none", "concurrency": "trust", "pager": "fail"})
		sh2 := r2.mustDial(t)
		if _, err := sh2.Send(ctx(t), "show long"); !errors.Is(err, ErrPager) {
			t.Fatalf("%s pager=fail: %v", line, err)
		}
		<-sh2.Done()
	}
}

/* Async syslog lines: filtered out of the output (async=filter) or kept (async=keep); MES 6.x write prints two. */
func TestAsyncStrategy(t *testing.T) {
	for variant, inLines := range map[string]bool{"filter": false, "keep": true} {
		r := start(t, "mes6", devemu.Options{}, nil)
		r.src.profiles = verified(strategy.MES6, map[string]string{"async": variant})
		sh := r.mustDial(t)
		out, err := sh.System(ctx(t), "write")
		if err != nil {
			t.Fatalf("%s: %v", variant, err)
		}
		has := strings.Contains(out.Text(), "%COPY-I-FILECPY")
		if has != inLines || !inLines && len(out.Async) != 2 {
			t.Errorf("async=%s: lines %q async %q", variant, out.Lines, out.Async)
		}
		if !strings.Contains(out.Text(), "Copy succeeded") {
			t.Errorf("async=%s: output %q", variant, out.Lines)
		}
	}
	/* a line logged between commands surfaces with the next command, never as its output */
	r := start(t, "esr", devemu.Options{}, nil)
	r.src.profiles = verified(strategy.ESR, map[string]string{"concurrency": "trust"})
	sh := r.mustDial(t)
	r.d.Syslog("%SYS-I-TEST: hello")
	time.Sleep(200 * time.Millisecond)
	out, err := sh.Run(ctx(t), ssh.ShowCommand{Name: "show version"})
	if err != nil || strings.Contains(out.Text(), "%SYS") || len(out.Async) != 1 || !strings.HasPrefix(out.Lines[0], "Boot version") {
		t.Fatalf("between commands: %q %q %v", out.Lines, out.Async, err)
	}
}

/* Confirmations: off (the device asks nothing) or the table, which answers system commands only. */
func TestConfirmationTable(t *testing.T) {
	r := start(t, "mes6", devemu.Options{}, nil)
	r.src.profiles = verified(strategy.MES6, map[string]string{"confirmations": "table"})
	sh := r.mustDial(t)
	c := ctx(t)
	if _, err := sh.System(c, "write"); err != nil {
		t.Fatal(err)
	}
	if j := r.d.Journal(); j[len(j)-1].Kind != "answer" || j[len(j)-1].Input != "Y" {
		t.Errorf("write not answered Y: %+v", j[len(j)-1])
	}
	/* a question after a line outside the table is left to the user */
	if _, err := sh.System(c, "delete startup-config"); !errors.Is(err, ErrUnansweredQuestion) || sh.State().Mode != ModeConfirm {
		t.Fatalf("delete: %v %+v", err, sh.State())
	}
	if out, err := sh.Send(c, "write"); err == nil || out.State.Mode == ModeConfirm {
		t.Fatal("Send went past a pending question")
	}
	if _, err := sh.Answer(c, "n"); err != nil {
		t.Fatal(err)
	}
	for _, e := range r.d.Journal() {
		if e.Kind == "answer" && e.Input != "Y" && e.Input != "n" {
			t.Errorf("answered %q", e.Input)
		}
	}
}

/* Errors: the line's markers (an ErrDevice with the line), and strict (any output to a configuration line). */
func TestErrorStrategy(t *testing.T) {
	for variant, strictErr := range map[string]bool{"markers": false, "strict": true} {
		r := start(t, "mes10", devemu.Options{}, nil)
		r.src.profiles = verified(strategy.MES10, map[string]string{"errors": variant})
		r.d.Reject(`^hostname bad$`, "Hostname rejected by the device")
		sh := r.mustDial(t)
		c := ctx(t)
		out, err := sh.Send(c, "bogus command")
		if !errors.Is(err, ErrDevice) || out.Error != "% Invalid Command" {
			t.Errorf("%s unknown command: %+v %v", variant, out, err)
		}
		if _, err := sh.Send(c, "configure terminal"); err != nil {
			t.Fatal(err)
		}
		_, err = sh.Send(c, "hostname bad")
		if errors.Is(err, ErrDevice) != strictErr {
			t.Errorf("errors=%s: unmarked output to a config line: %v", variant, err)
		}
		if _, err := sh.Send(c, "hostname sw1"); err != nil {
			t.Errorf("errors=%s: silent config line: %v", variant, err)
		}
		if sh.State().Host != "sw1" {
			t.Errorf("the prompt does not follow the hostname: %+v", sh.State())
		}
	}
}

/* PTY: width 511; a line wrapped at exactly that width is joined (pty=wide-join), not with pty=wide. */
func TestPTYStrategy(t *testing.T) {
	long := strings.Repeat("x", 511)
	for variant, joined := range map[string]bool{"wide-join": true, "wide": false} {
		r := start(t, "esr", devemu.Options{}, nil)
		r.src.profiles = verified(strategy.ESR, map[string]string{"pty": variant, "concurrency": "trust"})
		r.d.SetShowLookup(func(cmd string) (string, bool) {
			if cmd == "show interfaces status" {
				return long + "\ntail\nnext", true
			}
			return "", false
		})
		sh := r.mustDial(t)
		if sh.Strategies().Width != 511 {
			t.Fatal("width")
		}
		out, err := sh.Run(ctx(t), ssh.ShowCommand{Name: "show interfaces status"})
		want := []string{long, "tail", "next"}
		if joined {
			want = []string{long + "tail", "next"}
		}
		if err != nil || !slices.Equal(out.Lines, want) {
			t.Errorf("pty=%s: %d lines %v", variant, len(out.Lines), err)
		}
	}
}

/* ESR concurrency: exclusive refuses another session or a non-empty candidate; trust does not look. */
func TestESRConcurrency(t *testing.T) {
	r := start(t, "esr", devemu.Options{}, nil)
	r.src.profiles = verified(strategy.ESR, nil)
	exclusiveESR(r.d, "*  1  admin  00:29:59  15  ssh  192.0.2.10", "   2  bob    00:10:00  15  ssh  192.0.2.11")
	if _, err := r.dial(t); !errors.Is(err, ErrNotExclusive) {
		t.Fatalf("two sessions: %v", err)
	}
	exclusiveESR(r.d)
	other := r.mustDial(t)
	c := ctx(t)
	for _, l := range []string{"configure", "hostname changed"} {
		if _, err := other.Send(c, l); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.dial(t); !errors.Is(err, ErrNotExclusive) {
		t.Fatalf("non-empty candidate: %v", err)
	}
	r.src.profiles = verified(strategy.ESR, map[string]string{"concurrency": "trust"})
	if _, err := r.dial(t); err != nil {
		t.Fatalf("trust: %v", err)
	}
}

/* Auth: password; keyboard-interactive with the same password; publickey for a key credential. */
func TestAuthStrategies(t *testing.T) {
	r := start(t, "mes10", devemu.Options{}, func(c *sshemu.Config) { c.KeyboardInteractive = true })
	r.src.profiles = verified(strategy.MES10, nil)
	r.mustDial(t)
	if got := r.log.AuthAttempts(); !slices.Contains(got, "password:"+pw) {
		t.Errorf("password: %q", got)
	}
	r = start(t, "mes10", devemu.Options{}, func(c *sshemu.Config) { c.KeyboardInteractive = true })
	r.src.profiles = verified(strategy.MES10, map[string]string{"auth": "keyboard-interactive"})
	sh := r.mustDial(t)
	if got := r.log.AuthAttempts(); !slices.Contains(got, "keyboard-interactive:"+pw) || !sh.Decision().Write {
		t.Errorf("keyboard-interactive (after reconnecting with the profile): %q", got)
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	spub, _ := gossh.NewPublicKey(pub)
	r = start(t, "mes10", devemu.Options{}, func(c *sshemu.Config) { c.Password, c.AuthorizedKey = "", spub })
	r.cfg.Credential = Credential{Username: "admin", PrivateKey: secret.New(string(pem.EncodeToMemory(block)))}
	r.src.profiles = verified(strategy.MES10, nil)
	r.mustDial(t)
	if got := r.log.AuthAttempts(); !slices.Contains(got, "publickey") || slices.ContainsFunc(got, func(s string) bool { return strings.HasPrefix(s, "password") }) {
		t.Errorf("publickey: %q", got)
	}
	/* auth=publickey with a password credential sends nothing */
	r = start(t, "mes10", devemu.Options{}, nil)
	r.src.profiles = verified(strategy.MES10, map[string]string{"auth": "publickey"})
	if _, err := r.dial(t); !errors.Is(err, ErrCredential) {
		t.Errorf("publickey without a key: %v", err)
	}
}

/* In-band login on MES 6.x (auto): User Name:/Password: inside the channel, once; off or on ESR: refused before sending anything. */
func TestInbandLogin(t *testing.T) {
	r := start(t, "mes6", devemu.Options{InbandLogin: true, Users: map[string]devemu.User{"admin": {Password: pw, Privilege: 15}}}, nil)
	r.src.profiles = verified(strategy.MES6, nil)
	r.mustDial(t)
	j := r.d.Journal()
	if j[0].Kind != "user" || j[0].Input != "admin" || j[1].Kind != "password" || j[1].Input != pw {
		t.Fatalf("in-band login: %+v", j[:2])
	}

	r = start(t, "mes6", devemu.Options{InbandLogin: true, Users: map[string]devemu.User{"admin": {Password: "other", Privilege: 15}}}, nil)
	if _, err := r.dial(t); !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("wrong password: %v", err)
	}
	if n := len(r.d.Journal()); n != 2 {
		t.Errorf("the login was tried %d entries, want once (user, password)", n)
	}

	r = start(t, "mes6", devemu.Options{InbandLogin: true}, nil)
	r.src.profiles = verified(strategy.MES6, map[string]string{"inband_login": "off"})
	if _, err := r.dial(t); !errors.Is(err, ErrInbandLogin) {
		t.Fatalf("inband_login=off: %v", err)
	}

	r = start(t, "esr", devemu.Options{InbandLogin: true}, nil)
	if _, err := r.dial(t); !errors.Is(err, ErrInbandLogin) {
		t.Fatalf("ESR in-band: %v", err)
	}
	if len(r.d.Journal()) != 0 {
		t.Errorf("ESR in-band sent %+v", r.d.Journal())
	}
}

/* An expired password stops the connection: nothing but the login reaches the device, never a new password; an alert is raised. */
func TestExpiredPasswordStops(t *testing.T) {
	expired := map[string]devemu.User{"admin": {Password: pw, Privilege: 15, Expired: true}}
	for _, c := range []struct {
		line   string
		inband bool
	}{{"esr", false}, {"mes6", false}, {"mes6", true}, {"mes10", false}} {
		r := start(t, c.line, devemu.Options{Users: expired, InbandLogin: c.inband}, nil)
		r.src.profiles = verified(strategy.Line(c.line), nil)
		if _, err := r.dial(t); !errors.Is(err, ErrPasswordExpired) {
			t.Fatalf("%s inband=%v: %v", c.line, c.inband, err)
		}
		time.Sleep(300 * time.Millisecond) /* anything sent after the stop would be in the journal by now */
		r.d.ExpectNone(t, "new-password", "line", "answer", "key")
		if got := r.al.list(); !slices.Equal(got, []string{KindPasswordExpired + "/high"}) {
			t.Errorf("%s: alerts %q", c.line, got)
		}
		if r.src.decided.Load() != 0 {
			t.Errorf("%s: the gate ran after a password change request", c.line)
		}
	}
	/* keyboard-interactive asking for a new password: nothing is answered */
	var exp atomic.Bool
	set := strategy.Defaults(strategy.MES6)
	ans, err := kiChallenge(set, Credential{Password: secret.New(pw)}, &exp)("", "", []string{"New password:"}, []bool{false})
	if !errors.Is(err, ErrPasswordExpired) || ans != nil || !exp.Load() {
		t.Errorf("keyboard-interactive new password: %q %v", ans, err)
	}
	if ans, err := kiChallenge(set, Credential{Password: secret.New(pw)}, &exp)("", "", []string{"OTP code:"}, []bool{true}); err == nil || ans != nil {
		t.Errorf("keyboard-interactive other question answered: %q", ans)
	}
}

/* An unverified model refuses a write session (ReadOnly is allowed); MES 10.x registered as mes6 refuses any session. */
func TestModelGate(t *testing.T) {
	r := start(t, "mes6", devemu.Options{}, nil)
	if _, err := r.dial(t); !errors.Is(err, ErrModelUnverified) {
		t.Fatalf("unverified write: %v", err)
	}
	r.d.ExpectLines(t, "show version", "show system")
	r.cfg.Access = ReadOnly
	sh := r.mustDial(t)
	if sh.Decision().Write || sh.Access() != ReadOnly {
		t.Errorf("read-only decision %+v", sh.Decision())
	}
	if _, err := sh.Send(ctx(t), "configure"); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Send on ReadOnly: %v", err)
	}

	for _, access := range []Access{Write, ReadOnly} {
		r := start(t, "mes10", devemu.Options{}, nil)
		r.src.t.line = strategy.MES6 /* registered as mes6 */
		r.src.profiles = append(verified(strategy.MES6, nil), verified(strategy.MES10, nil)...)
		r.cfg.Access = access
		if _, err := r.dial(t); !errors.Is(err, identify.ErrLineMismatch) {
			t.Fatalf("mes10 as mes6 (%d): %v", access, err)
		}
		r.d.ExpectLines(t, "show version", "show system")
		if got := r.al.list(); !slices.Equal(got, []string{KindLineMismatch + "/high"}) {
			t.Errorf("alerts %q", got)
		}
	}

	r = start(t, "esr", devemu.Options{}, nil)
	r.src.t.writesEnabled = false
	r.src.profiles = verified(strategy.ESR, nil)
	if _, err := r.dial(t); !errors.Is(err, ErrWritesDisabled) {
		t.Fatalf("writes disabled: %v", err)
	}
	if len(r.log.AuthAttempts()) != 0 {
		t.Error("connected although writes are disabled")
	}
}

/* ReadOnly sends not one command outside the read dialect: whatever the caller tries. */
func TestReadOnlySendsOnlyTheAllowlist(t *testing.T) {
	for _, line := range strategy.Lines() {
		r := start(t, string(line), devemu.Options{}, nil)
		r.cfg.Access = ReadOnly
		r.src.profiles = verified(line, nil) /* even on a verified model */
		sh := r.mustDial(t)
		c := ctx(t)
		ifArg, _ := ssh.IfName("1/0/1")
		for _, cmd := range []ssh.ShowCommand{{Name: "show version"}, {Name: "show running-config", LongOutput: true},
			{Name: "show interfaces status", Args: []ssh.Arg{ifArg}}, {Name: "configure"}, {Name: "show version; reload"},
			{Name: "copy running-config tftp://192.0.2.1/x"}, {Name: "show interfaces status", Args: []ssh.Arg{{}}}} {
			_, _ = sh.Run(c, cmd)
		}
		for _, f := range []func() error{
			func() error { _, err := sh.Send(c, "configure"); return err },
			func() error { _, err := sh.System(c, "write"); return err },
			func() error { _, err := sh.Answer(c, "y"); return err },
		} {
			if err := f(); !errors.Is(err, ErrReadOnly) {
				t.Errorf("%s: %v", line, err)
			}
		}
		d := readDialect(line)
		for _, l := range r.d.Lines() {
			name, _, _ := strings.Cut(l, " 1/0/1")
			if !slices.Contains(d.PagerOff, l) && !slices.ContainsFunc(d.Allowlist, func(c ssh.ShowCommand) bool { return c.Name == name }) {
				t.Errorf("%s: %q reached the device outside the read allowlist", line, l)
			}
		}
		if !slices.Contains(r.d.Lines(), "show running-config") {
			t.Errorf("%s: the allowed long command was not sent: %q", line, r.d.Lines())
		}
	}
}

/* ESC, OSC, CSI, C0, C1 and bidi controls in device output never reach the client of the transport. */
func TestEscapesNeverReachTheClient(t *testing.T) {
	evil := "a\x1b[31mred\x1b[0m \x1b]52;c;cm0gLXJmIC8=\x07osc \x1b]0;title\x1b\\t2 \x1bPq#0;1\x1b\\dcs \x9b2J\u009b1m" + string(rune(0x202e)) + "abc" + string(rune(0x2066)) + " b\x08c\x07\x00\x7fd\r\nline2\x1b[\n\x1b]8;;http://x\x07link"
	r := start(t, "esr", devemu.Options{}, nil)
	r.src.profiles = verified(strategy.ESR, map[string]string{"concurrency": "trust"})
	r.d.SetShowLookup(func(cmd string) (string, bool) {
		if cmd == "show interfaces status" || cmd == "show system" {
			return evil, true
		}
		return "", false
	})
	sh := r.mustDial(t)
	out, err := sh.Run(ctx(t), ssh.ShowCommand{Name: "show interfaces status"})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range append(append(slices.Clone(out.Lines), out.Async...), out.State.Prompt, out.Error) {
		for _, r := range s {
			if dropped(r) || r == 0x1b {
				t.Fatalf("control %U reached the client in %q", r, s)
			}
		}
		if strings.Contains(s, "52;") || strings.Contains(s, "title") || strings.Contains(s, "http://x") {
			t.Fatalf("an escape payload reached the client: %q", s)
		}
	}
	if !strings.HasPrefix(out.Lines[0], "ared osc t2 dcs") {
		t.Errorf("visible text lost: %q", out.Lines)
	}
}

/* A disconnect closes the shell: the next command fails, Done is closed. */
func TestDisconnect(t *testing.T) {
	r := start(t, "mes10", devemu.Options{}, func(c *sshemu.Config) { c.DisconnectAfter = 5 })
	r.src.profiles = verified(strategy.MES10, nil)
	sh := r.mustDial(t)
	if _, err := sh.Send(ctx(t), "configure terminal"); !errors.Is(err, ErrClosed) {
		t.Fatalf("after disconnect: %v; device got %q", err, r.d.Lines())
	}
	select {
	case <-sh.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done not closed")
	}
	if _, err := sh.Send(ctx(t), "end"); !errors.Is(err, ErrClosed) {
		t.Errorf("closed shell: %v", err)
	}
}

/* Output is bounded in size and time; both close the shell. */
func TestBounds(t *testing.T) {
	r := start(t, "esr", devemu.Options{}, nil)
	r.src.profiles = verified(strategy.ESR, map[string]string{"concurrency": "trust"})
	r.d.SetShowLookup(func(cmd string) (string, bool) {
		if cmd == "show arp" {
			return strings.Repeat(strings.Repeat("y", 400)+"\n", maxOutput/400+10), true
		}
		return "", false
	})
	sh := r.mustDial(t)
	if _, err := sh.Run(ctx(t), ssh.ShowCommand{Name: "show arp"}); !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("large output: %v", err)
	}

	/* a device that stops answering after login */
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
					line = rest
					switch l = strings.TrimSpace(l); {
					case l == "configure": /* silent from here on */
					case fx.Show[l] != "":
						_, _ = io.WriteString(ch, l+"\r\n"+strings.ReplaceAll(fx.Show[l], "\n", "\r\n")+"\r\nesr# ")
					default:
						_, _ = io.WriteString(ch, l+"\r\nesr# ")
					}
				}
			}
		}})
	r.src.t.addr, r.src.t.hostFP, r.src.t.hostAlgo = addr, gossh.FingerprintSHA256(key.PublicKey()), key.PublicKey().Type()
	r.cfg.CommandTimeout = time.Second
	sh = r.mustDial(t)
	if _, err := sh.Send(ctx(t), "configure"); !errors.Is(err, ErrTimeout) {
		t.Fatalf("silent device: %v", err)
	}
}

/* Host key: only the pinned type is offered; a different key sends no credential (alert); ssh-rsa SHA-1 only by the flag. */
func TestHostKeyStrategy(t *testing.T) {
	r := start(t, "esr", devemu.Options{}, nil)
	r.src.t.hostFP = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err := r.dial(t); !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("other key: %v", err)
	}
	if len(r.log.AuthAttempts()) != 0 {
		t.Errorf("credential sent to an unpinned key: %q", r.log.AuthAttempts())
	}
	if got := r.al.list(); !slices.Equal(got, []string{KindHostKeyMismatch + "/high"}) {
		t.Errorf("alerts %q", got)
	}

	r = start(t, "mes6", devemu.Options{}, nil) /* the MES 6.x profile signs with ssh-rsa (SHA-1) only */
	r.src.t.rsaSHA1 = false
	if _, err := r.dial(t); !errors.Is(err, ErrHandshake) || len(r.log.AuthAttempts()) != 0 {
		t.Fatalf("ssh-rsa without the flag: %v %q", err, r.log.AuthAttempts())
	}
	r.src.t.rsaSHA1 = true
	r.src.profiles = verified(strategy.MES6, nil)
	r.mustDial(t)

	if got := hostKeyAlgorithms(gossh.KeyAlgoRSA, false); slices.Contains(got, gossh.KeyAlgoRSA) {
		t.Errorf("rsa without the flag: %q", got)
	}
	if got := hostKeyAlgorithms(gossh.KeyAlgoED25519, true); !slices.Equal(got, []string{gossh.KeyAlgoED25519}) {
		t.Errorf("ed25519: %q", got)
	}
}

/* KEX: ESR is offered no curve25519 (no-curve25519); a curve25519-only device then fails, with modern it works. */
func TestKEXStrategy(t *testing.T) {
	for _, k := range kexAlgorithms("no-curve25519") {
		if strings.Contains(k, "25519") {
			t.Errorf("no-curve25519 offers %s", k)
		}
	}
	curveOnly := func(c *sshemu.Config) { c.KeyExchanges = []string{gossh.KeyExchangeCurve25519} }
	r := start(t, "esr", devemu.Options{}, curveOnly)
	if _, err := r.dial(t); !errors.Is(err, ErrHandshake) {
		t.Fatalf("ESR default with a curve25519-only server: %v", err)
	}
	r = start(t, "mes10", devemu.Options{}, curveOnly)
	r.src.profiles = verified(strategy.MES10, nil)
	r.mustDial(t)
	/* the ESR fixture's documented KEX list works with the ESR default */
	r = start(t, "esr", devemu.Options{}, nil)
	r.src.profiles = verified(strategy.ESR, map[string]string{"concurrency": "trust"})
	r.mustDial(t)
}

func FuzzCleanLines(f *testing.F) {
	f.Add([]byte("a\x1b]52;c;x\x07b\x1b[2Jc\x9bd" + string(rune(0x202e))))
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, l := range cleanLines(b) {
			for _, r := range l {
				if dropped(r) || r == 0x1b || r == '\n' {
					t.Fatalf("%U in %q", r, l)
				}
			}
		}
	})
}
