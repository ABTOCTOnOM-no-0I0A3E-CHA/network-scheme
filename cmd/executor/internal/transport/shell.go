package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/beekamai/network-scheme/cmd/executor/internal/identify"
	"github.com/beekamai/network-scheme/cmd/executor/internal/strategy"
	"github.com/beekamai/network-scheme/internal/ssh"
)

/* Errors of an open shell. The ones marked "closes" leave the CLI state unknown: the shell is closed. */
var (
	ErrReadOnly           = errors.New("transport: read-only connection")
	ErrNotAllowed         = errors.New("transport: command not in the read allowlist")
	ErrBadLine            = errors.New("transport: line is empty, too long or has control characters")
	ErrQuestionPending    = errors.New("transport: the device waits for an answer")
	ErrNoQuestion         = errors.New("transport: no question to answer")
	ErrUnansweredQuestion = errors.New("transport: the device asked a question the table does not answer")
	ErrDevice             = errors.New("transport: the device reported an error")
	ErrUnexpectedPrompt   = errors.New("transport: unexpected prompt")                  /* closes */
	ErrClosed             = errors.New("transport: connection closed")                  /* closes */
	ErrTimeout            = errors.New("transport: no prompt in time")                  /* closes */
	ErrOutputTooLarge     = errors.New("transport: command output too large")           /* closes */
	ErrPager              = errors.New("transport: pager prompt (pager strategy fail)") /* closes */
)

const (
	handshakeTimeout   = 15 * time.Second
	commandTimeout     = 60 * time.Second
	longCommandTimeout = 3 * time.Minute
	/* maxOutput bounds one command's output; maxPages its pager presses. */
	maxOutput = 4 << 20
	maxPages  = 4096
	/* MaxLine bounds a line sent; the PTY is 511 wide, so a line and its prompt never wrap. */
	MaxLine   = 400
	ptyHeight = 200
	/* a prompt or question counts only once the device has been quiet this long behind it */
	promptSettle     = 150 * time.Millisecond
	longPromptSettle = time.Second
)

/* Mode is where the CLI is. */
type Mode int

// The CLI modes; ModeUnknown is a prompt the transport does not recognise.
const (
	ModeUnknown    Mode = iota
	ModeExec            /* host> */
	ModePrivileged      /* host# */
	ModeConfig          /* host(config)# */
	ModeSub             /* host(config-if)# and other configuration sub-modes */
	ModeConfirm         /* a confirmation question waits for an answer */
)

/* State is the CLI state after the last read. */
type State struct {
	Mode     Mode
	Prompt   string /* the prompt line, or the question line in ModeConfirm */
	Host     string
	Context  string /* the sub-mode, e.g. "config-if" */
	Question string
}

/*
Output is one command's result as clean text: no escapes or control
characters, without the echo of the line and the next prompt, async log
lines moved to Async (strategy async=filter), lines the device wrapped at
the PTY width joined (pty=wide-join). Error is the line that reported an
error (or, strict, the first output line of a configuration line).
*/
type Output struct {
	Lines []string
	Async []string
	State State
	Error string
}

/* Text is the output lines joined by "\n". */
func (o Output) Text() string { return strings.Join(o.Lines, "\n") }

/* Shell is one open connection; it runs one command at a time. */
type Shell struct {
	mu        sync.Mutex
	client    *gossh.Client
	stdin     io.Writer
	chunks    chan []byte
	done      chan struct{}
	gone      chan struct{}
	closeOnce sync.Once

	deviceID int64
	line     strategy.Line
	access   Access
	set      strategy.Set
	dialect  ssh.Dialect
	ident    identify.Identity
	decision identify.Decision
	timeout  time.Duration

	buf   []byte   /* raw output not yet consumed */
	async []string /* async lines drained between commands */
	st    State
}

func anchored(re string) *regexp.Regexp { return regexp.MustCompile(`^(?:` + re + `)$`) }

// Line is the registered firmware line.
func (s *Shell) Line() strategy.Line { return s.line }

// Identity is what show version and show system said.
func (s *Shell) Identity() identify.Identity { return s.ident }

// Decision is the model gate's verdict.
func (s *Shell) Decision() identify.Decision { return s.decision }

// Access is what the connection may send.
func (s *Shell) Access() Access { return s.access }

// Strategies are the line's defaults, overridden by the matching model profile.
func (s *Shell) Strategies() strategy.Set { return s.set }

// DeviceID is the registry's device id.
func (s *Shell) DeviceID() int64 { return s.deviceID }

/* State returns the CLI state after the last command. */
func (s *Shell) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st
}

/* Done is closed once the connection is gone (closed here or by the device). */
func (s *Shell) Done() <-chan struct{} { return s.gone }

/* Close ends the connection; safe to call more than once and concurrently. */
func (s *Shell) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.done)
		err = s.client.Close()
	})
	return err
}

/* what the last line of the output is */
type kind int

const (
	kNone kind = iota
	kPrompt
	kQuestion
	kUser
	kPassword
	kExpired
)

func (s *Shell) classify(last string, login bool) kind {
	switch {
	case login && s.set.Expired.MatchString(last):
		return kExpired
	case login && s.set.LoginUser.MatchString(last):
		return kUser
	case login && s.set.LoginPassword.MatchString(last):
		return kPassword
	case s.set.Question.MatchString(last):
		return kQuestion
	case s.set.Prompt.MatchString(last):
		return kPrompt
	}
	return kNone
}

func (s *Shell) stateOf(last string, k kind) State {
	if k == kQuestion {
		return State{Mode: ModeConfirm, Prompt: last, Question: last}
	}
	m := s.set.Prompt.FindStringSubmatch(last)
	if m == nil {
		return State{Prompt: last}
	}
	st := State{Prompt: last, Host: m[s.set.Prompt.SubexpIndex("host")], Context: m[s.set.Prompt.SubexpIndex("ctx")]}
	switch {
	case m[s.set.Prompt.SubexpIndex("end")] == ">":
		st.Mode = ModeExec
	case st.Context == "":
		st.Mode = ModePrivileged
	case st.Context == "config":
		st.Mode = ModeConfig
	default:
		st.Mode = ModeSub
	}
	return st
}

func (s *Shell) write(p string) error {
	if _, err := io.WriteString(s.stdin, p); err != nil {
		_ = s.Close()
		return fmt.Errorf("%w: %w", ErrClosed, err)
	}
	return nil
}

/*
read collects output until its last line is a prompt or a question (in
login also a login or password-change prompt) and the device stayed quiet
behind it. A pager prompt is answered with the line's key (pager=answer)
and removed. It returns the clean lines before the last one, the last line
and its kind. Every error closes the shell.
*/
func (s *Shell) read(ctx context.Context, long, login bool) ([]string, string, kind, error) {
	timeout, idle := s.timeout, promptSettle
	if long {
		timeout, idle = max(s.timeout, longCommandTimeout), longPromptSettle
	}
	fail := func(err error) ([]string, string, kind, error) {
		_ = s.Close()
		return nil, "", kNone, err
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	var settle <-chan time.Time
	pages := 0
	for {
		select {
		case b, ok := <-s.chunks:
			if !ok {
				return fail(ErrClosed)
			}
			if s.buf = append(s.buf, b...); len(s.buf) > maxOutput {
				return fail(ErrOutputTooLarge)
			}
			start := lastRaw(s.buf)
			last := cleanLines(s.buf[start:])[0]
			if s.set.PagerPrompt.MatchString(last) {
				if s.set.Pager != "answer" || pages >= maxPages {
					return fail(ErrPager)
				}
				pages++
				s.buf = s.buf[:start]
				if err := s.write(s.set.PagerKey); err != nil {
					return fail(err)
				}
				settle = nil
				continue
			}
			settle = nil
			if s.classify(last, login) != kNone {
				settle = time.After(idle)
			}
		case <-settle:
			start := lastRaw(s.buf)
			last := cleanLines(s.buf[start:])[0]
			k := s.classify(last, login)
			lines := cleanLines(s.buf[:start])
			s.buf = nil
			return lines[:len(lines)-1], last, k, nil /* the text before the last line ends with "\n": drop the empty tail */
		case <-deadline.C:
			return fail(ErrTimeout)
		case <-ctx.Done():
			return fail(ctx.Err())
		case <-s.done:
			return fail(ErrClosed)
		}
	}
}

/* drain consumes what arrived between commands (async log lines and a repeated prompt); only the log lines are kept. */
func (s *Shell) drain() {
	for {
		select {
		case b, ok := <-s.chunks:
			if !ok {
				return
			}
			s.buf = append(s.buf, b...)
			continue
		default:
		}
		break
	}
	if len(s.buf) == 0 {
		return
	}
	for _, l := range cleanLines(s.buf) {
		if s.set.Syslog.MatchString(l) {
			s.async = append(s.async, l)
		}
	}
	s.buf = nil
}

/* login waits for the prompt, doing the in-band login once if the strategy allows it. A password change stops it. */
func (s *Shell) login(ctx context.Context, c Credential) error {
	sentUser, sentPass := false, false
	for {
		lines, last, k, err := s.read(ctx, false, true)
		if err != nil {
			return err
		}
		for _, l := range lines {
			if s.set.Expired.MatchString(l) {
				return ErrPasswordExpired
			}
		}
		switch k {
		case kExpired:
			return ErrPasswordExpired
		case kPrompt:
			if s.st = s.stateOf(last, k); s.st.Mode != ModePrivileged {
				return fmt.Errorf("%w: %q", ErrUnprivileged, last)
			}
			return nil
		case kUser, kPassword:
			if s.set.InbandLogin != "auto" {
				return ErrInbandLogin
			}
			if k == kUser && sentUser || k == kPassword && sentPass || c.Password.IsZero() && k == kPassword {
				return ErrLoginFailed
			}
			sentUser, sentPass = sentUser || k == kUser, sentPass || k == kPassword
			if k == kUser && !printable(c.Username) {
				return ErrLoginFailed
			}
			v := c.Username
			if k == kPassword {
				/* a password is one line: a CR or LF in it would send what follows as a command */
				if v = c.Password.Reveal(); strings.ContainsAny(v, "\r\n\x00") {
					return ErrLoginFailed
				}
			}
			if err := s.write(v + "\n"); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: %q during login", ErrUnexpectedPrompt, last)
		}
	}
}

/* identify reads show version and show system (read allowlist) and parses them; a show system the device lacks gives no model. */
func (s *Shell) identify(ctx context.Context) (identify.Identity, error) {
	ver, err := s.run(ctx, ssh.ShowCommand{Name: "show version"})
	if err != nil {
		return identify.Identity{}, err
	}
	sys, err := s.run(ctx, ssh.ShowCommand{Name: "show system"})
	if err != nil && !errors.Is(err, ErrDevice) {
		return identify.Identity{}, err
	}
	if err != nil {
		sys = Output{}
	}
	return identify.Parse(ver.Text(), sys.Text())
}

/* setup sends the access's session commands: Write the terminal and confirmation strategies (and ESR exclusivity), ReadOnly the read dialect's. */
func (s *Shell) setup(ctx context.Context) error {
	var cmds []string
	if s.access == ReadOnly {
		cmds = s.dialect.PagerOff
	} else {
		cmds = append(cmds, s.set.TerminalCommands[s.set.Terminal]...)
		if s.set.Confirmations == "off" {
			cmds = append(cmds, s.set.ConfirmOff...)
		}
	}
	for _, c := range cmds {
		if _, err := s.exec(ctx, c, false); err != nil {
			return fmt.Errorf("%w: %s: %w", ErrSetup, c, err)
		}
		if s.st.Mode != ModePrivileged {
			return fmt.Errorf("%w: %s: left the privileged prompt", ErrSetup, c)
		}
	}
	if s.access == Write && s.line == strategy.ESR && s.set.Concurrency == "exclusive" {
		return s.exclusive(ctx)
	}
	return nil
}

/* exclusive: this must be the only session on the ESR, and the shared candidate empty [R §8, §9.11]. */
func (s *Shell) exclusive(ctx context.Context) error {
	users, err := s.exec(ctx, "show users", false)
	if err != nil {
		return fmt.Errorf("%w: show users: %w", ErrNotExclusive, err)
	}
	rows, mine := 0, 0
	for _, l := range users.Lines {
		if m := s.set.UsersRow.FindStringSubmatch(l); m != nil {
			rows++
			if m[1] == "*" {
				mine++
			}
		}
	}
	if rows != 1 || mine != 1 {
		return fmt.Errorf("%w: %d sessions in show users", ErrNotExclusive, rows)
	}
	ch, err := s.exec(ctx, "show configuration changes", false)
	if err != nil {
		return fmt.Errorf("%w: show configuration changes: %w", ErrNotExclusive, err)
	}
	if strings.TrimSpace(ch.Text()) != "" {
		return fmt.Errorf("%w: the candidate has uncommitted changes", ErrNotExclusive)
	}
	return nil
}

func printable(l string) bool {
	if l == "" || len(l) > MaxLine {
		return false
	}
	for i := range len(l) {
		if l[i] < 0x20 || l[i] > 0x7e {
			return false
		}
	}
	return true
}

/*
exec sends one line (or answer) and reads up to the next prompt or
question; s.st follows. The output is processed per the strategies; a line
reporting an error gives ErrDevice with the output (the shell stays open).
*/
func (s *Shell) exec(ctx context.Context, line string, long bool) (Output, error) {
	select {
	case <-s.done:
		return Output{}, ErrClosed
	default:
	}
	s.drain()
	before := s.st
	if err := s.write(line + "\n"); err != nil {
		return Output{}, err
	}
	lines, last, k, err := s.read(ctx, long, false)
	if err != nil {
		return Output{}, err
	}
	st := s.stateOf(last, k)
	if long && st.Prompt != before.Prompt {
		_ = s.Close()
		return Output{}, fmt.Errorf("%w: %q after a long output", ErrUnexpectedPrompt, last)
	}
	s.st = st
	out := s.process(line, lines, before)
	if out.Error != "" {
		return out, fmt.Errorf("%w: %s", ErrDevice, out.Error)
	}
	return out, nil
}

/* process turns the clean lines of one command into its Output. */
func (s *Shell) process(sent string, lines []string, before State) Output {
	out := Output{State: s.st, Async: s.async}
	s.async = nil
	/* the echo, maybe behind async lines and the prompt the device repeated after them */
	for i, l := range lines {
		if l == sent || strings.HasSuffix(l, sent) && s.set.Prompt.MatchString(strings.TrimSuffix(l, sent)) {
			lines = append(lines[:i:i], lines[i+1:]...)
			break
		}
		if l != "" && !s.set.Syslog.MatchString(l) && !s.set.Prompt.MatchString(l) {
			break
		}
	}
	for _, l := range lines {
		if s.set.Async == "filter" && s.set.Syslog.MatchString(l) {
			out.Async = append(out.Async, l)
			continue
		}
		if s.set.PTY == "wide-join" && len(out.Lines) > 0 && len([]rune(out.Lines[len(out.Lines)-1])) == s.set.Width {
			out.Lines[len(out.Lines)-1] += l
			continue
		}
		out.Lines = append(out.Lines, l)
	}
	for len(out.Lines) > 0 && out.Lines[0] == "" {
		out.Lines = out.Lines[1:]
	}
	for len(out.Lines) > 0 && out.Lines[len(out.Lines)-1] == "" {
		out.Lines = out.Lines[:len(out.Lines)-1]
	}
	for _, l := range out.Lines {
		if s.set.ErrorMarkers.MatchString(l) {
			out.Error = l
			break
		}
	}
	if out.Error == "" && s.set.Errors == "strict" && (before.Mode == ModeConfig || before.Mode == ModeSub) && len(out.Lines) > 0 {
		out.Error = out.Lines[0]
	}
	return out
}

func (s *Shell) writable() error {
	if s.access != Write {
		return ErrReadOnly
	}
	return nil
}

/*
Send sends one configuration or command line (Write only): printable ASCII,
at most MaxLine bytes, no control characters. The CLI must be at a
privileged or configuration prompt, not waiting for an answer. A question
the device then asks is returned in the state (ModeConfirm) for Answer; it
is never answered here.
*/
func (s *Shell) Send(ctx context.Context, line string) (Output, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writable(); err != nil {
		return Output{}, err
	}
	return s.send(ctx, line)
}

func (s *Shell) send(ctx context.Context, line string) (Output, error) {
	if !printable(line) {
		return Output{}, ErrBadLine
	}
	switch s.st.Mode {
	case ModePrivileged, ModeConfig, ModeSub:
	case ModeConfirm:
		return Output{}, ErrQuestionPending
	default:
		return Output{}, fmt.Errorf("%w: %q", ErrUnexpectedPrompt, s.st.Prompt)
	}
	return s.exec(ctx, line, false)
}

var answerRe = regexp.MustCompile(`^[A-Za-z]{0,8}$`)

/* Answer answers the pending question (Write only) with a short word (letters only; "" takes the device's default). */
func (s *Shell) Answer(ctx context.Context, answer string) (Output, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writable(); err != nil {
		return Output{}, err
	}
	if s.st.Mode != ModeConfirm {
		return Output{}, ErrNoQuestion
	}
	if !answerRe.MatchString(answer) {
		return Output{}, ErrBadLine
	}
	return s.exec(ctx, answer, false)
}

/*
System sends a system command of a driver (save, snapshot, reload timer;
Write only) and answers its questions from the confirmation table of the
strategies, only where both the command and the question match an entry. Any
other question is left pending (ErrUnansweredQuestion).
*/
func (s *Shell) System(ctx context.Context, line string) (Output, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writable(); err != nil {
		return Output{}, err
	}
	out, err := s.send(ctx, line)
	for range 3 {
		if err != nil || out.State.Mode != ModeConfirm {
			return out, err
		}
		reply, ok := "", false
		for _, a := range s.set.Answers {
			if a.Command.MatchString(line) && a.Question.MatchString(out.State.Question) {
				reply, ok = a.Reply, true
				break
			}
		}
		if !ok {
			return out, fmt.Errorf("%w: %q", ErrUnansweredQuestion, out.State.Question)
		}
		prev := out
		out, err = s.exec(ctx, reply, false)
		out.Async = append(prev.Async, out.Async...)
		out.Lines = append(prev.Lines, out.Lines...)
	}
	if out.State.Mode == ModeConfirm {
		return out, fmt.Errorf("%w: %q", ErrUnansweredQuestion, out.State.Question)
	}
	return out, err
}

/*
Run runs a read command (both accesses): it must be in the read dialect's
allowlist (ssh.Dialect.Allows: exact name, typed arguments) and the CLI at
the dialect's exec prompt. LongOutput commands end only behind the same
prompt as before and a one-second pause.
*/
func (s *Shell) Run(ctx context.Context, cmd ssh.ShowCommand) (Output, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.run(ctx, cmd)
}

func (s *Shell) run(ctx context.Context, cmd ssh.ShowCommand) (Output, error) {
	if !s.dialect.Allows(cmd) {
		return Output{}, ErrNotAllowed
	}
	if s.st.Mode != ModePrivileged || !s.dialect.ExecPrompt.MatchString(s.st.Prompt) {
		return Output{}, fmt.Errorf("%w: %q", ErrUnexpectedPrompt, s.st.Prompt)
	}
	out, err := s.exec(ctx, cmd.String(), cmd.LongOutput)
	if err == nil && s.st.Mode != ModePrivileged {
		_ = s.Close()
		return Output{}, fmt.Errorf("%w: %q after %s", ErrUnexpectedPrompt, s.st.Prompt, cmd.Name)
	}
	return out, err
}
