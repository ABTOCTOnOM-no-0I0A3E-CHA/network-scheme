package devemu

import (
	"io"
	"strings"
)

const (
	stUser = iota
	stPass
	stExpired
	stCLI
	stConfirm
	stPager
)

/* question is a pending confirmation; yes/no return the command's output. */
type question struct {
	text string
	def  bool /* the answer an empty line gives */
	yes  func() string
	no   func() string
}

type ctxStep struct{ text, mode string }

/*
Session is one CLI session on a Device. It works on bytes as a terminal does:
it echoes what is typed (not passwords, not pager keys), pages long output,
asks confirmations and tracks the mode. Every method runs under the device lock.
*/
type Session struct {
	d      *Device
	id     int
	out    io.WriteCloser
	closed bool
	state  int
	line   []byte
	lastCR bool
	user   string
	inUser string
	priv   bool
	config bool
	ctx    []ctxStep
	conf   *question
	rest   []string /* lines the pager still holds */
	busy   bool     /* a command runs: async lines wait in queued */
	queued []string

	datadump bool /* paging off */
	noPrompt bool /* confirmations answered "yes" without asking */
}

func (s *Session) write(str string) {
	if s.closed || str == "" {
		return
	}
	_, _ = io.WriteString(s.out, strings.ReplaceAll(str, "\n", "\r\n"))
}

func (s *Session) close() {
	if s.closed {
		return
	}
	s.closed = true
	_ = s.out.Close()
	delete(s.d.sess, s.id)
}

func (s *Session) start(user string) {
	if b := s.d.P.Banner.Text; b != "" {
		s.write(strings.TrimRight(b, "\n") + "\n")
	}
	if s.d.opt.InbandLogin {
		s.state = stUser
		s.write(s.d.P.Login["user"].Text)
		return
	}
	s.login(user)
}

/* login enters the CLI as user, or the password-change dialogue when the user's password has expired [R §4]. */
func (s *Session) login(user string) {
	s.user = user
	u, ok := s.d.opt.Users[user]
	if !ok {
		u = User{Privilege: 15}
	}
	if u.Expired {
		s.state = stExpired
		s.write(s.d.P.Login["expired"].Text + "\n" + s.d.P.Login["new_password"].Text)
		return
	}
	s.priv, s.state = u.Privilege >= 15, stCLI
	s.write(s.prompt())
}

/* promptKey names the current mode. */
func (s *Session) promptKey() string {
	switch {
	case !s.priv:
		return "exec"
	case !s.config:
		return "privileged"
	case len(s.ctx) == 0:
		return "config"
	}
	return s.ctx[len(s.ctx)-1].mode
}

func (s *Session) prompt() string {
	k, ctx := s.promptKey(), ""
	if len(s.ctx) > 0 {
		k, ctx = "context", s.ctx[len(s.ctx)-1].mode
	}
	return s.d.P.prompt(k, s.d.hostname(), ctx)
}

/* waiting is what the device shows while it waits for input. */
func (s *Session) waiting() string {
	switch s.state {
	case stUser:
		return s.d.P.Login["user"].Text
	case stPass:
		return s.d.P.Login["password"].Text
	case stExpired:
		return s.d.P.Login["new_password"].Text
	case stConfirm:
		return s.conf.text
	case stPager:
		return s.d.P.Pager.Prompt.Text
	}
	return s.prompt()
}

func (s *Session) mode() string {
	switch s.state {
	case stUser, stPass:
		return "login"
	case stExpired:
		return "expired"
	case stConfirm:
		return "confirm"
	case stPager:
		return "pager"
	}
	return s.promptKey()
}

func (s *Session) record(kind, in string) {
	s.d.record(Entry{Session: s.id, Mode: s.mode(), Kind: kind, Input: in})
}

/* input feeds typed bytes; it reports false once the session is closed. */
func (s *Session) input(p []byte) bool {
	s.d.mu.Lock()
	defer s.d.mu.Unlock()
	s.d.fire()
	for _, b := range p {
		if s.closed {
			return false
		}
		cr := s.lastCR
		s.lastCR = b == '\r'
		if b == '\n' && cr {
			continue
		}
		if s.state == stPager {
			s.pagerKey(b)
			continue
		}
		hidden := s.state == stPass || s.state == stExpired
		switch {
		case b == '\r' || b == '\n':
			s.write("\n")
			s.lineDone(string(s.line))
			s.line = s.line[:0]
		case b == 0x08 || b == 0x7f:
			if len(s.line) > 0 {
				s.line = s.line[:len(s.line)-1]
				if !hidden {
					s.write("\b \b")
				}
			}
		case b == 0x1a && s.state == stCLI && s.config: /* Ctrl+Z: to privileged EXEC [R §5] */
			s.record("key", "ctrl-z")
			s.line = s.line[:0]
			s.config, s.ctx = false, nil
			s.write("^Z\n" + s.prompt())
		case b < 0x20 && b != '\t':
		default:
			s.line = append(s.line, b)
			if !hidden {
				s.write(string(b))
			}
		}
	}
	return !s.closed
}

func (s *Session) lineDone(text string) {
	P := s.d.P
	switch s.state {
	case stUser:
		s.record("user", text)
		s.inUser, s.state = text, stPass
		s.write(P.Login["password"].Text)
	case stPass:
		s.record("password", text)
		u, ok := s.d.opt.Users[s.inUser]
		if len(s.d.opt.Users) > 0 && (!ok || u.Password != text) {
			s.state = stUser
			s.write(P.Login["failed"].Text + "\n" + P.Login["user"].Text)
			return
		}
		s.login(s.inUser)
	case stExpired:
		/* recorded so tests can prove that a client never sent a new password [R §9.9] */
		s.record("new-password", text)
		s.write(P.Login["new_password"].Text)
	case stConfirm:
		s.record("answer", text)
		q := s.conf
		s.conf, s.state = nil, stCLI
		a := strings.TrimSpace(text)
		yes := a == "" && q.def || strings.HasPrefix(strings.ToLower(a), "y")
		s.busy = true
		out := ""
		switch {
		case yes:
			out = q.yes()
		case q.no != nil:
			out = q.no()
		}
		s.emit(out)
	case stCLI:
		s.record("line", text)
		s.busy = true
		s.emit(s.exec(text))
	}
}

/* ask raises a confirmation; with confirmations off it answers yes at once. */
func (s *Session) ask(text string, def bool, yes, no func() string) string {
	if s.noPrompt {
		return yes()
	}
	s.conf = &question{text: text, def: def, yes: yes, no: no}
	return ""
}

/* emit prints a command's output through the pager, then what the device waits for. */
func (s *Session) emit(out string) {
	s.busy = false
	if s.closed {
		return
	}
	if len(s.queued) > 0 {
		s.write(strings.Join(s.queued, "\n") + "\n")
		s.queued = nil
	}
	if out != "" {
		lines := strings.Split(out, "\n")
		if n := s.d.P.Pager.Lines; !s.datadump && len(lines) > n {
			s.write(strings.Join(lines[:n], "\n") + "\n" + s.d.P.Pager.Prompt.Text)
			s.rest, s.state = lines[n:], stPager
			return
		}
		s.write(out + "\n")
	}
	if s.conf != nil {
		s.state = stConfirm
	}
	s.write(s.waiting())
}

/* pagerKey handles one key at the pager prompt: space a page, Enter a line, q/Ctrl+Z quit, r the rest [R §5]. */
func (s *Session) pagerKey(b byte) {
	s.record("key", string(b))
	n := 0
	switch b {
	case ' ':
		n = s.d.P.Pager.Lines
	case '\r', '\n':
		n = 1
	case 'q', 'Q', 0x1a:
		s.rest = nil
	case 'r', 'R':
		n = len(s.rest)
	default:
		return
	}
	s.write(s.d.P.Pager.Erase.Text)
	n = min(n, len(s.rest))
	if n > 0 {
		s.write(strings.Join(s.rest[:n], "\n") + "\n")
		s.rest = s.rest[n:]
	}
	if len(s.rest) > 0 {
		s.write(s.d.P.Pager.Prompt.Text)
		return
	}
	s.state = stCLI
	if s.conf != nil {
		s.state = stConfirm
	}
	s.write(s.waiting())
}

/* async prints a syslog line in the middle of the session and repeats what the user sees [R §5]. */
func (s *Session) async(line string) {
	if s.busy {
		s.queued = append(s.queued, line)
		return
	}
	typed := string(s.line)
	if s.state == stPass || s.state == stExpired {
		typed = ""
	}
	s.write("\n" + line + "\n" + s.waiting() + typed)
}
