/*
Package ssh runs read-only CLI commands on network devices. Only commands
from the driver's allowlist reach the device (exact name, typed arguments),
the exec-mode prompt is checked before every command, and each device's host
key is pinned on first use.
*/
package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/beekamai/network-scheme/internal/creds"
)

var (
	// ErrNotAllowed means the command is not in the dialect's allowlist or has invalid arguments.
	ErrNotAllowed = errors.New("ssh: command not allowed")
	// ErrUnexpectedPrompt means the device is not at its exec-mode prompt; the session is closed.
	ErrUnexpectedPrompt = errors.New("ssh: unexpected prompt")
	// ErrClosed means the session is closed.
	ErrClosed = errors.New("ssh: session closed")
	// ErrOutputTooLarge means a command produced more than the output cap; the session is closed.
	ErrOutputTooLarge = errors.New("ssh: command output too large")
	// ErrTimeout means the device did not return to a prompt in time; the session is closed.
	ErrTimeout = errors.New("ssh: command timed out")
)

const (
	handshakeTimeout = 15 * time.Second
	commandTimeout   = 60 * time.Second
	maxOutput        = 4 << 20
	maxPromptLen     = 256
	/* A prompt is accepted only once the device has been quiet this long after it. */
	promptSettle = 150 * time.Millisecond
)

type argKind uint8

const (
	kindInvalid argKind = iota
	kindIfName
	kindVLANID
)

/*
Arg is a typed command argument. Values are built only by IfName and VLANID;
the zero Arg and the Any* placeholders are rejected by Run.
*/
type Arg struct {
	kind argKind
	val  string
}

var (
	// AnyIfName marks an interface-name argument in an allowlist entry.
	AnyIfName = Arg{kind: kindIfName}
	// AnyVLANID marks a VLAN-ID argument in an allowlist entry.
	AnyVLANID = Arg{kind: kindVLANID}
)

var ifNameRe = regexp.MustCompile(`^[A-Za-z0-9/.:-]{1,64}$`)

// IfName returns an interface-name argument; s must match ^[A-Za-z0-9/.:-]{1,64}$.
func IfName(s string) (Arg, error) {
	a := Arg{kind: kindIfName, val: s}
	if !a.valid() {
		return Arg{}, fmt.Errorf("ssh: invalid interface name %q", s)
	}
	return a, nil
}

// VLANID returns a VLAN-ID argument in 1..4094.
func VLANID(v int) (Arg, error) {
	if v < 1 || v > 4094 {
		return Arg{}, fmt.Errorf("ssh: invalid VLAN ID %d", v)
	}
	return Arg{kind: kindVLANID, val: strconv.Itoa(v)}, nil
}

func (a Arg) valid() bool {
	switch a.kind {
	case kindIfName:
		return ifNameRe.MatchString(a.val)
	case kindVLANID:
		n, err := strconv.Atoi(a.val)
		return err == nil && n >= 1 && n <= 4094 && strconv.Itoa(n) == a.val
	}
	return false
}

// ShowCommand is a read-only command: a fixed name followed by typed arguments.
type ShowCommand struct {
	Name string
	Args []Arg
}

func (c ShowCommand) line() string {
	parts := []string{c.Name}
	for _, a := range c.Args {
		parts = append(parts, a.val)
	}
	return strings.Join(parts, " ")
}

/*
Dialect describes a vendor CLI. ExecPrompt is matched against the last line
of output with trailing spaces removed. PagerOff holds session-level commands
sent once after login. Allowlist entries use AnyIfName/AnyVLANID to state the
argument kinds a command accepts.
*/
type Dialect struct {
	ExecPrompt *regexp.Regexp
	PagerOff   []string
	Allowlist  []ShowCommand
}

func (d Dialect) validate() error {
	if d.ExecPrompt == nil {
		return errors.New("ssh: dialect has no exec prompt")
	}
	for _, p := range d.PagerOff {
		if !printable(p) {
			return fmt.Errorf("ssh: dialect pager command %q is not printable ASCII", p)
		}
	}
	for _, c := range d.Allowlist {
		if !printable(c.Name) {
			return fmt.Errorf("ssh: dialect command %q is not printable ASCII", c.Name)
		}
		for _, a := range c.Args {
			if a.kind == kindInvalid {
				return fmt.Errorf("ssh: dialect command %q has an untyped argument", c.Name)
			}
		}
	}
	return nil
}

func printable(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

/* allows reports whether c matches an allowlist entry by exact name and argument kinds, with valid values. */
func (d Dialect) allows(c ShowCommand) bool {
	for _, a := range c.Args {
		if !a.valid() {
			return false
		}
	}
	for _, e := range d.Allowlist {
		if e.Name == c.Name && slices.EqualFunc(e.Args, c.Args, func(x, y Arg) bool { return x.kind == y.kind }) {
			return true
		}
	}
	return false
}

/*
Runner is an interactive read-only CLI session on one device. It runs one
command at a time; any protocol surprise closes it.
*/
type Runner struct {
	mu        sync.Mutex
	client    *gossh.Client
	stdin     io.Writer
	chunks    chan []byte
	done      chan struct{}
	closeOnce sync.Once
	d         Dialect
	prompt    string
}

/*
Dial connects to the device at addr, verifies its host key against the pin
for deviceID (pinning it on first use) before authenticating with c (kind
ssh_read), waits for the exec prompt and sends the dialect's PagerOff commands.
*/
func Dial(ctx context.Context, addr netip.AddrPort, deviceID int64, c creds.Credential, hk *HostKeys, d Dialect) (*Runner, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	auth, err := authMethod(c)
	if err != nil {
		return nil, err
	}
	if hk == nil {
		return nil, errors.New("ssh: no host key store")
	}
	pinned, err := hk.pinnedAlgorithm(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	var mismatch atomic.Bool
	verify := hk.callback(ctx, deviceID, addr.Addr())
	cfg := &gossh.ClientConfig{
		User: c.Username,
		Auth: []gossh.AuthMethod{auth},
		HostKeyCallback: func(host string, remote net.Addr, key gossh.PublicKey) error {
			err := verify(host, remote, key)
			if errors.Is(err, ErrHostKeyMismatch) {
				mismatch.Store(true)
			}
			return err
		},
		HostKeyAlgorithms: hostKeyAlgorithms(pinned),
		Timeout:           handshakeTimeout,
	}

	nd := net.Dialer{Timeout: handshakeTimeout}
	conn, err := nd.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		return nil, fmt.Errorf("ssh: connect: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	sc, chans, reqs, err := gossh.NewClientConn(conn, addr.String(), cfg)
	if err != nil {
		_ = conn.Close()
		if mismatch.Load() {
			return nil, ErrHostKeyMismatch
		}
		return nil, fmt.Errorf("ssh: handshake: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	client := gossh.NewClient(sc, chans, reqs)

	r, err := startShell(client, d)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err := r.readPrompt(ctx); err != nil {
		_ = r.Close()
		return nil, err
	}
	for _, p := range d.PagerOff {
		if _, err := r.exec(ctx, p); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func authMethod(c creds.Credential) (gossh.AuthMethod, error) {
	if c.Kind != creds.KindSSHRead {
		return nil, fmt.Errorf("ssh: credential kind %q is not %s", c.Kind, creds.KindSSHRead)
	}
	if c.Username == "" {
		return nil, errors.New("ssh: credential has no username")
	}
	switch {
	case !c.PrivateKey.IsZero():
		signer, err := gossh.ParsePrivateKey([]byte(c.PrivateKey.Reveal()))
		if err != nil {
			return nil, errors.New("ssh: unusable private key")
		}
		return gossh.PublicKeys(signer), nil
	case !c.Password.IsZero():
		return gossh.Password(c.Password.Reveal()), nil
	}
	return nil, errors.New("ssh: credential has no password or key")
}

/* startShell opens one session with a PTY (no X11 or agent forwarding) and a shell. */
func startShell(client *gossh.Client, d Dialect) (*Runner, error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("ssh: session: %w", err)
	}
	if err := sess.RequestPty("vt100", 200, 512, gossh.TerminalModes{gossh.ECHO: 0}); err != nil {
		return nil, fmt.Errorf("ssh: pty: %w", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("ssh: stdin: %w", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("ssh: stdout: %w", err)
	}
	if err := sess.Shell(); err != nil {
		return nil, fmt.Errorf("ssh: shell: %w", err)
	}
	r := &Runner{client: client, stdin: stdin, chunks: make(chan []byte, 16), done: make(chan struct{}), d: d}
	go r.pump(stdout)
	return r, nil
}

func (r *Runner) pump(out io.Reader) {
	defer close(r.chunks)
	for {
		buf := make([]byte, 32<<10)
		n, err := out.Read(buf)
		if n > 0 {
			select {
			case r.chunks <- buf[:n]:
			case <-r.done:
				return
			}
		}
		if err != nil {
			return
		}
	}
}

/*
Run sends cmd if the dialect allows it and the device is at its exec prompt,
and returns the output up to the next prompt (CRLF normalised, without the
echoed command and the prompt). Device output is untrusted text.
*/
func (r *Runner) Run(ctx context.Context, cmd ShowCommand) (string, error) {
	if !r.d.allows(cmd) {
		return "", ErrNotAllowed
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.exec(ctx, cmd.line())
}

/* exec sends one line; any failure closes the session, since the CLI state is then unknown. */
func (r *Runner) exec(ctx context.Context, line string) (string, error) {
	select {
	case <-r.done:
		return "", ErrClosed
	default:
	}
	if !r.d.ExecPrompt.MatchString(r.prompt) {
		_ = r.Close()
		return "", ErrUnexpectedPrompt
	}
	if _, err := io.WriteString(r.stdin, line+"\n"); err != nil {
		_ = r.Close()
		return "", fmt.Errorf("%w: %w", ErrClosed, err)
	}
	raw, err := r.readPrompt(ctx)
	if err != nil {
		_ = r.Close()
		return "", err
	}
	return clean(raw, line), nil
}

/*
readPrompt reads until the device has printed a prompt-like last line and
gone quiet, records that prompt and returns the output before it. A prompt
other than the exec prompt yields ErrUnexpectedPrompt.
*/
func (r *Runner) readPrompt(ctx context.Context) (string, error) {
	deadline := time.NewTimer(commandTimeout)
	defer deadline.Stop()
	var (
		buf    []byte
		settle <-chan time.Time
	)
	for {
		select {
		case b, ok := <-r.chunks:
			if !ok {
				return "", ErrClosed
			}
			buf = append(buf, b...)
			if len(buf) > maxOutput {
				return "", ErrOutputTooLarge
			}
			settle = nil
			if r.promptLike(lastLine(buf)) {
				settle = time.After(promptSettle)
			}
		case <-settle:
			last := lastLine(buf)
			r.prompt = strings.TrimRight(last, " ")
			if !r.d.ExecPrompt.MatchString(r.prompt) {
				return "", ErrUnexpectedPrompt
			}
			return string(buf[:len(buf)-len(last)]), nil
		case <-deadline.C:
			return "", ErrTimeout
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
}

/* promptLike reports whether an unterminated last line looks like a CLI prompt. */
func (r *Runner) promptLike(line string) bool {
	l := strings.TrimRight(line, " ")
	if l == "" || len(l) > maxPromptLen {
		return false
	}
	return strings.HasSuffix(l, "#") || strings.HasSuffix(l, ">") || r.d.ExecPrompt.MatchString(l)
}

func lastLine(b []byte) string {
	return string(b[bytes.LastIndexAny(b, "\r\n")+1:])
}

func clean(raw, cmd string) string {
	s := strings.ReplaceAll(raw, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "")
	if first, rest, ok := strings.Cut(s, "\n"); ok && strings.TrimSpace(first) == cmd {
		s = rest
	}
	return strings.TrimSuffix(s, "\n")
}

// Close ends the session; it is safe to call more than once and concurrently with Run.
func (r *Runner) Close() error {
	var err error
	r.closeOnce.Do(func() {
		close(r.done)
		err = r.client.Close()
	})
	return err
}
