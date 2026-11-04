/*
Package transport is the executor's SSH transport to a write device
(security.md 5.3, architecture.md 5): an interactive shell that tracks the
CLI mode and prompt (exec, privileged, configuration and its sub-modes, a
pending confirmation question, the pager, the in-band login), strips ANSI,
OSC and C0 from device output before anything reaches a client, detects
errors per line and bounds output size and time.

A connection uses only the address, port, firmware line and pinned host key
of the device's verified registry row (registry table write_device through
registry.View), dials through the network guard, and checks the host key
before any credential is sent. After login the executor reads show version
itself and applies the model gate (package identify): another firmware line
than the registered one refuses the session; an unverified (model,
firmware) allows only ReadOnly, which sends nothing but the read dialect of
the line (internal/ssh allowlist). A forced password change stops the
connection: nothing but the login is ever sent.
*/
package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/beekamai/network-scheme/cmd/executor/internal/identify"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/strategy"
	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/drivers/eltexesr"
	"github.com/beekamai/network-scheme/internal/drivers/eltexmes"
	"github.com/beekamai/network-scheme/internal/secret"
	"github.com/beekamai/network-scheme/internal/ssh"
)

/* Access is what a connection may send. */
type Access int

const (
	/* Write sends configuration lines; it needs writes_enabled and a verified model. */
	Write Access = iota + 1
	/* ReadOnly sends only the read dialect of the line: its session commands and allowlist (ssh.Dialect.Allows). */
	ReadOnly
)

/* Alert kinds raised by the transport (execpub.alert; internal/triggers). */
const (
	KindHostKeyMismatch = "hostkey_mismatch_write"    /* high */
	KindPasswordExpired = "executor_password_expired" /* high: the device asks for a new password; the executor stopped */
	KindLineMismatch    = "executor_line_mismatch"    /* high: show version names another firmware line than the registry */
)

/* Errors of the connection. Errors of an open shell are in shell.go. */
var (
	ErrNotRegistered   = errors.New("transport: device not in the write registry")
	ErrNoHostKey       = errors.New("transport: no accepted host key for the device")
	ErrProtocol        = errors.New("transport: only SSH is supported")
	ErrWritesDisabled  = errors.New("transport: writes are not enabled for the device")
	ErrHostKeyMismatch = errors.New("transport: host key does not match the pinned key")
	ErrHandshake       = errors.New("transport: SSH handshake failed")
	ErrPasswordExpired = errors.New("transport: the device demands a password change; stopped without changing it")
	ErrInbandLogin     = errors.New("transport: in-band login asked but not allowed by the strategy")
	ErrLoginFailed     = errors.New("transport: login failed")
	ErrUnprivileged    = errors.New("transport: not at the privileged prompt after login")
	ErrModelUnverified = errors.New("transport: model and firmware not verified, writes refused")
	ErrRegistryChanged = errors.New("transport: the device's registry row changed during the connection")
	ErrIdentityChanged = errors.New("transport: the device identified differently on reconnect")
	ErrNotExclusive    = errors.New("transport: another session or a non-empty candidate on the device")
	ErrSetup           = errors.New("transport: terminal setup failed")
	ErrCredential      = errors.New("transport: the credential does not fit the authentication strategy")
)

/* Credential is a write credential opened by the executor (wcreds). The caller wipes it after Dial. */
type Credential struct {
	Username   string
	Password   secret.Secret
	PrivateKey secret.Secret
}

/* Viewer is the gate of every decision: *freeze.Guard (registry.View under the freeze latch). */
type Viewer interface {
	View(ctx context.Context, fn func(*registry.Snapshot) error) error
}

/* Dialer opens the TCP connection after the address check: *netguard.Guard (security.md 5.1a, SSRF). */
type Dialer interface {
	Dial(ctx context.Context, ap netip.AddrPort) (net.Conn, error)
}

/* Config of one connection. Every field but CommandTimeout is required. */
type Config struct {
	DeviceID   int64
	Access     Access
	Credential Credential
	Registry   Viewer
	Net        Dialer
	/* Alert publishes an alert (pub.Publisher.Alert); its failure does not change the outcome. */
	Alert func(ctx context.Context, kind, severity string, deviceID int64, text string) error
	/* CommandTimeout bounds each command until the next prompt; 0: 60 s (3 min for long output). */
	CommandTimeout time.Duration
}

/* keyTypes are the host key types the registry may pin. */
var keyTypes = []string{gossh.KeyAlgoED25519, gossh.KeyAlgoECDSA256, gossh.KeyAlgoECDSA384, gossh.KeyAlgoECDSA521, gossh.KeyAlgoRSA}

/* target is what a connection may use of a verified write_device row, and nothing else. */
type target struct {
	deviceID      int64
	addr          netip.AddrPort
	line          strategy.Line
	hostAlgo      string
	hostFP        string
	rsaSHA1       bool
	writesEnabled bool
	version       int64
}

/* targetOf reads a verified registry table write_device row. */
func targetOf(r registry.Row) (target, error) {
	if r.Table() != "write_device" {
		return target{}, ErrNotRegistered
	}
	t := target{version: r.Version()}
	t.deviceID, _ = r.Get("device_id").(int64)
	addr, _ := r.Get("address").(netip.Addr)
	port, _ := r.Get("port").(int64)
	if !addr.IsValid() || port < 1 || port > 65535 {
		return target{}, fmt.Errorf("%w: bad address %v port %d", ErrNotRegistered, addr, port)
	}
	t.addr = netip.AddrPortFrom(addr, uint16(port))
	if p, _ := r.Get("protocol").(string); p != "ssh" {
		return target{}, fmt.Errorf("%w: %q", ErrProtocol, p)
	}
	drv, _ := r.Get("write_driver").(string)
	if t.line = strategy.Line(drv); !t.line.Valid() {
		return target{}, fmt.Errorf("%w: write driver %q", ErrNotRegistered, drv)
	}
	t.hostAlgo, _ = r.Get("hostkey_algo").(string)
	t.hostFP, _ = r.Get("hostkey_fp").(string)
	if !slices.Contains(keyTypes, t.hostAlgo) || !strings.HasPrefix(t.hostFP, "SHA256:") {
		return target{}, ErrNoHostKey
	}
	t.rsaSHA1, _ = r.Get("allow_ssh_rsa_sha1").(bool)
	t.writesEnabled, _ = r.Get("writes_enabled").(bool)
	return t, nil
}

/* source is where a connection's decisions come from: the verified registry (registrySource); tests use a fake. */
type source interface {
	target(ctx context.Context) (target, error)
	modelProfiles(ctx context.Context, t target) ([]identify.Profile, error)
	decide(ctx context.Context, t target, id identify.Identity) (identify.Decision, error)
}

type registrySource struct {
	v  Viewer
	id int64
}

func (r registrySource) row(s *registry.Snapshot) (target, error) {
	row, ok := s.Get("write_device", r.id)
	if !ok {
		return target{}, ErrNotRegistered
	}
	return targetOf(row)
}

func (r registrySource) target(ctx context.Context) (target, error) {
	var t target
	err := r.v.View(ctx, func(s *registry.Snapshot) error {
		var err error
		t, err = r.row(s)
		return err
	})
	return t, err
}

/* modelProfiles reads the model profiles on a verified snapshot in which the device row is still the one to dial. */
func (r registrySource) modelProfiles(ctx context.Context, t target) ([]identify.Profile, error) {
	var ps []identify.Profile
	err := r.v.View(ctx, func(s *registry.Snapshot) error {
		now, err := r.row(s)
		if err != nil {
			return err
		}
		if now != t {
			return ErrRegistryChanged
		}
		ps = identify.ProfilesOf(s)
		return nil
	})
	return ps, err
}

/* decide takes the gate on a fresh verified snapshot, in which the device row must be the one dialled. */
func (r registrySource) decide(ctx context.Context, t target, id identify.Identity) (identify.Decision, error) {
	var d identify.Decision
	err := r.v.View(ctx, func(s *registry.Snapshot) error {
		now, err := r.row(s)
		if err != nil {
			return err
		}
		if now != t {
			return ErrRegistryChanged
		}
		d, err = identify.Decide(t.line, identify.ProfilesOf(s), id)
		return err
	})
	return d, err
}

/*
Dial connects to the registered device cfg.DeviceID: the target comes from
the verified registry, the TCP connection from cfg.Net, then host key,
authentication, login, identification and the model gate, then the
terminal setup of the access. Any refusal closes the connection.
*/
func Dial(ctx context.Context, cfg Config) (*Shell, error) {
	if cfg.Registry == nil {
		return nil, errors.New("transport: no registry")
	}
	return dial(ctx, cfg, registrySource{v: cfg.Registry, id: cfg.DeviceID})
}

/* alertTimeout bounds publishing one alert; a cancelled caller does not cancel it. */
const alertTimeout = 5 * time.Second

func (c Config) alert(ctx context.Context, kind, text string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), alertTimeout)
	defer cancel()
	_ = c.Alert(ctx, kind, "high", c.DeviceID, text)
}

/*
preLogins are the ways to connect before the device is identified (auth,
in-band login, KEX): the pre-login values of the line's usable profiles if
they all agree, otherwise the defaults first and then each distinct set of
the profiles. The model gate after login decides which profile applies.
*/
func preLogins(line strategy.Line, ps []identify.Profile) []strategy.Set {
	def := strategy.Defaults(line)
	var sets []strategy.Set
	for _, p := range ps {
		if p.WriteDriver != line || p.Err != nil {
			continue
		}
		set, err := def.Override(p.Strategies)
		if err != nil {
			continue
		}
		if !slices.ContainsFunc(sets, func(x strategy.Set) bool { return x.PreLogin() == set.PreLogin() }) {
			sets = append(sets, preLogin(def, set))
		}
	}
	if len(sets) == 1 {
		return sets
	}
	out := []strategy.Set{def}
	for _, x := range sets {
		if x.PreLogin() != def.PreLogin() {
			out = append(out, x)
		}
	}
	return out
}

/* preLogin is def with the pre-login values of set. */
func preLogin(def, set strategy.Set) strategy.Set {
	def.Auth, def.InbandLogin, def.KEX = set.Auth, set.InbandLogin, set.KEX
	return def
}

/*
retryable reports whether the next pre-login set may be tried after err: only
a refused authentication or key exchange, or a credential the method cannot
use. A host key mismatch, a password change, a failed in-band login and every
later stage stop.
*/
func retryable(err error) bool {
	return errors.Is(err, ErrHandshake) || errors.Is(err, ErrCredential) || errors.Is(err, ErrInbandLogin)
}

func dial(ctx context.Context, cfg Config, src source) (*Shell, error) {
	if cfg.Access != Write && cfg.Access != ReadOnly {
		return nil, errors.New("transport: no access")
	}
	if cfg.Net == nil || cfg.Alert == nil {
		return nil, errors.New("transport: no network guard or alert sink")
	}
	t, err := src.target(ctx)
	if err != nil {
		return nil, err
	}
	if t.deviceID != cfg.DeviceID {
		return nil, ErrNotRegistered
	}
	if cfg.Access == Write && !t.writesEnabled {
		return nil, ErrWritesDisabled
	}
	ps, err := src.modelProfiles(ctx, t)
	if err != nil {
		return nil, err
	}
	var (
		sh  *Shell
		id  identify.Identity
		set strategy.Set
	)
	for _, set = range preLogins(t.line, ps) {
		if sh, id, err = connect(ctx, cfg, t, set); err == nil || !retryable(err) {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	dec, err := gate(ctx, cfg, src, t, id)
	if err != nil {
		_ = sh.Close()
		return nil, err
	}
	if !dec.Write {
		/* no profile applies: reading keeps the way it connected (pre-login values say nothing about what is sent) */
		dec.Set = preLogin(dec.Set, set)
	}
	if dec.Write && dec.Set.PreLogin() != set.PreLogin() {
		/* the matching profile connects otherwise: connect again with it, and it must come out the same */
		_ = sh.Close()
		sh2, id2, err := connect(ctx, cfg, t, dec.Set)
		if err != nil {
			return nil, err
		}
		dec2, err := gate(ctx, cfg, src, t, id2)
		if err != nil {
			_ = sh2.Close()
			return nil, err
		}
		if id2 != id || dec2.Profile != dec.Profile || dec2.Set.PreLogin() != dec.Set.PreLogin() {
			_ = sh2.Close()
			return nil, ErrIdentityChanged
		}
		sh, dec = sh2, dec2
	}
	if cfg.Access == Write && !dec.Write {
		_ = sh.Close()
		return nil, fmt.Errorf("%w: %s", ErrModelUnverified, dec.Reason)
	}
	sh.access, sh.set, sh.ident, sh.decision = cfg.Access, dec.Set, id, dec
	if err := sh.setup(ctx); err != nil {
		_ = sh.Close()
		return nil, err
	}
	return sh, nil
}

func gate(ctx context.Context, cfg Config, src source, t target, id identify.Identity) (identify.Decision, error) {
	d, err := src.decide(ctx, t, id)
	if errors.Is(err, identify.ErrLineMismatch) {
		cfg.alert(ctx, KindLineMismatch, fmt.Sprintf("device %d is registered as %s, show version says %s %s %s",
			t.deviceID, t.line, id.Line, id.Model, id.Firmware))
	}
	return d, err
}

/* hostKeyAlgorithms offers only the pinned key type; RSA with SHA-2, ssh-rsa (SHA-1) only by the registry's flag [R §9.10]. */
func hostKeyAlgorithms(pinned string, sha1 bool) []string {
	if pinned != gossh.KeyAlgoRSA {
		return []string{pinned}
	}
	out := []string{gossh.KeyAlgoRSASHA512, gossh.KeyAlgoRSASHA256}
	if sha1 {
		out = append(out, gossh.KeyAlgoRSA)
	}
	return out
}

/* kexAlgorithms is the x/crypto secure set, without anything on X25519 for no-curve25519 (ESR [R §4]). */
func kexAlgorithms(variant string) []string {
	all := gossh.SupportedAlgorithms().KeyExchanges
	if variant == "no-curve25519" {
		all = slices.DeleteFunc(all, func(k string) bool { return strings.Contains(k, "25519") })
	}
	return all
}

/*
authMethod is the one SSH authentication of the strategy: a key credential
authenticates with its key (auth password or publickey); a password
credential with password, or keyboard-interactive answered with the same
password; publickey requires a key credential.
*/
func authMethod(set strategy.Set, c Credential, rsaSHA1 bool, expired *atomic.Bool) (gossh.AuthMethod, error) {
	auth := set.Auth
	if !c.PrivateKey.IsZero() && auth == "password" {
		auth = "publickey"
	}
	switch auth {
	case "password":
		if c.Password.IsZero() {
			return nil, ErrCredential
		}
		return gossh.Password(c.Password.Reveal()), nil
	case "keyboard-interactive":
		if c.Password.IsZero() {
			return nil, ErrCredential
		}
		return gossh.KeyboardInteractive(kiChallenge(set, c, expired)), nil
	case "publickey":
		if c.PrivateKey.IsZero() {
			return nil, ErrCredential
		}
		signer, err := gossh.ParsePrivateKey([]byte(c.PrivateKey.Reveal()))
		if err != nil {
			return nil, fmt.Errorf("%w: unusable private key", ErrCredential)
		}
		if signer.PublicKey().Type() == gossh.KeyAlgoRSA {
			/* RSA user keys sign with SHA-2; ssh-rsa (SHA-1) only with the registry's flag, as for the host key [R §9.10] */
			as, ok := signer.(gossh.AlgorithmSigner)
			if !ok {
				return nil, fmt.Errorf("%w: RSA key without algorithm choice", ErrCredential)
			}
			if signer, err = gossh.NewSignerWithAlgorithms(as, hostKeyAlgorithms(gossh.KeyAlgoRSA, rsaSHA1)); err != nil {
				return nil, fmt.Errorf("%w: %w", ErrCredential, err)
			}
		}
		return gossh.PublicKeys(signer), nil
	}
	return nil, fmt.Errorf("%w: auth %q", ErrCredential, auth)
}

/*
kiChallenge answers keyboard-interactive rounds [R §9.9]: a name,
instruction or question about an expired or new password sets expired (it
stays set: every later round fails) and fails; a round without questions
gets no answer; exactly one round with password questions is answered, with
the password; any other question, and any later password round, fails.
*/
func kiChallenge(set strategy.Set, c Credential, expired *atomic.Bool) gossh.KeyboardInteractiveChallenge {
	answered := false
	return func(name, instruction string, questions []string, _ []bool) ([]string, error) {
		if expired.Load() {
			return nil, ErrPasswordExpired
		}
		if set.Expired.MatchString(strings.TrimSpace(name)) || set.Expired.MatchString(strings.TrimSpace(instruction)) {
			expired.Store(true)
			return nil, ErrPasswordExpired
		}
		for _, q := range questions {
			if set.Expired.MatchString(strings.TrimSpace(q)) {
				expired.Store(true)
				return nil, ErrPasswordExpired
			}
		}
		if len(questions) == 0 {
			return nil, nil
		}
		if answered {
			return nil, ErrLoginFailed
		}
		answers := make([]string, len(questions))
		for i, q := range questions {
			if !set.LoginPassword.MatchString(strings.TrimSpace(q)) {
				return nil, fmt.Errorf("%w: unexpected keyboard-interactive question %q", ErrLoginFailed, sanitizeLine([]byte(q)))
			}
			answers[i] = c.Password.Reveal()
		}
		answered = true
		return answers, nil
	}
}

/* readDialect is the read side's dialect of the line (internal/drivers), its exec prompt anchored to the whole line. */
func readDialect(l strategy.Line) ssh.Dialect {
	var d ssh.Dialect
	switch l {
	case strategy.ESR:
		d = eltexesr.New().Dialect()
	case strategy.MES6:
		d = eltexmes.New().ForIdentity(drivers.Identity{Firmware: "6.0"}).Dialect()
	default:
		d = eltexmes.New().ForIdentity(drivers.Identity{Firmware: "10.0"}).Dialect()
	}
	d.ExecPrompt = anchored(d.ExecPrompt.String())
	return d
}

/* connect dials, authenticates, logs in and identifies the device with set (nothing but the read allowlist is sent). */
func connect(ctx context.Context, cfg Config, t target, set strategy.Set) (*Shell, identify.Identity, error) {
	var expired, mismatch atomic.Bool
	auth, err := authMethod(set, cfg.Credential, t.rsaSHA1, &expired)
	if err != nil {
		return nil, identify.Identity{}, err
	}
	cc := &gossh.ClientConfig{
		Config: gossh.Config{KeyExchanges: kexAlgorithms(set.KEX)},
		User:   cfg.Credential.Username,
		Auth:   []gossh.AuthMethod{auth},
		HostKeyCallback: func(_ string, _ net.Addr, key gossh.PublicKey) error {
			if key.Type() != t.hostAlgo || gossh.FingerprintSHA256(key) != t.hostFP {
				mismatch.Store(true)
				return ErrHostKeyMismatch
			}
			return nil
		},
		HostKeyAlgorithms: hostKeyAlgorithms(t.hostAlgo, t.rsaSHA1),
	}
	conn, err := cfg.Net.Dial(ctx, t.addr)
	if err != nil {
		return nil, identify.Identity{}, fmt.Errorf("transport: connect: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	sc, chans, reqs, err := gossh.NewClientConn(conn, t.addr.String(), cc)
	if err != nil {
		_ = conn.Close()
		switch {
		case mismatch.Load():
			cfg.alert(ctx, KindHostKeyMismatch, fmt.Sprintf("device %d at %s presented another host key than the pinned %s", t.deviceID, t.addr, t.hostFP))
			return nil, identify.Identity{}, ErrHostKeyMismatch
		case expired.Load():
			cfg.alert(ctx, KindPasswordExpired, fmt.Sprintf("device %d demands a password change; the executor stopped", t.deviceID))
			return nil, identify.Identity{}, ErrPasswordExpired
		}
		return nil, identify.Identity{}, fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	/* the deadline holds until the shell is open: a device stalling the session, PTY or shell request cannot hang the dial */
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	sh, err := open(gossh.NewClient(sc, chans, reqs), t, set, cfg.CommandTimeout)
	if err != nil {
		return nil, identify.Identity{}, err
	}
	_ = conn.SetDeadline(time.Time{})
	if err := sh.login(ctx, cfg.Credential); err != nil {
		_ = sh.Close()
		if errors.Is(err, ErrPasswordExpired) {
			cfg.alert(ctx, KindPasswordExpired, fmt.Sprintf("device %d demands a password change; the executor stopped", t.deviceID))
		}
		return nil, identify.Identity{}, err
	}
	id, err := sh.identify(ctx)
	if err != nil {
		_ = sh.Close()
		return nil, identify.Identity{}, err
	}
	return sh, id, nil
}

/* open requests a PTY of the strategy's width (no forwarding of any kind) and a shell. */
func open(client *gossh.Client, t target, set strategy.Set, timeout time.Duration) (*Shell, error) {
	fail := func(what string, err error) (*Shell, error) {
		_ = client.Close()
		return nil, fmt.Errorf("transport: %s: %w", what, err)
	}
	sess, err := client.NewSession()
	if err != nil {
		return fail("session", err)
	}
	if err := sess.RequestPty("vt100", ptyHeight, set.Width, gossh.TerminalModes{gossh.ECHO: 0}); err != nil {
		return fail("pty", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		return fail("stdin", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return fail("stdout", err)
	}
	if err := sess.Shell(); err != nil {
		return fail("shell", err)
	}
	if timeout <= 0 {
		timeout = commandTimeout
	}
	sh := &Shell{client: client, stdin: stdin, chunks: make(chan []byte, 16), done: make(chan struct{}), gone: make(chan struct{}),
		deviceID: t.deviceID, line: t.line, set: set, dialect: readDialect(t.line), timeout: timeout}
	go sh.pump(stdout)
	return sh, nil
}

/* pump is the only sender on chunks; it closes chunks (a read sees the disconnect at once) and then gone. */
func (s *Shell) pump(out io.Reader) {
	defer close(s.gone)
	defer close(s.chunks)
	for {
		buf := make([]byte, 32<<10)
		n, err := out.Read(buf)
		if n > 0 {
			select {
			case s.chunks <- buf[:n]:
			case <-s.done:
				return
			}
		}
		if err != nil {
			return
		}
	}
}
