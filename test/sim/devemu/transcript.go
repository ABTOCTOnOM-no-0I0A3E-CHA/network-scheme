package devemu

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

/*
Transcript is a CLI dialogue. In the marker format every line is one of:

	<<< TEXT       what the device shows while it waits (prompt, question, pager, User Name:)
	>>> TEXT       a line typed and Enter
	>>| KEY        one key without Enter: a character or <space>, <enter>, <ctrl-z>
	## key: value  metadata before the first <<< (user, password, privilege, source)
	## advance 10m moves the device's clock before the next input
	anything else  output, exactly as printed

A file with no "<<< " line is a raw capture (script, console log): a line that
starts with a prompt of the profile is the prompt and the typed command, a
line containing a confirmation or login question is that question and the
answer, everything else is output. ANSI sequences, backspaces, carriage-return
overprints and pager prompts are cleaned first; a password (never echoed) is
taken from "## password:".
*/
type Transcript struct {
	Name  string
	Meta  map[string]string
	Start string /* what the device shows first */
	Steps []Step
}

/* Step is one input and the device's answer. */
type Step struct {
	Input   string
	Key     bool /* one key without Enter */
	Hidden  bool /* not echoed (passwords) */
	Output  string
	Prompt  string /* what the device shows next; "" at the end of the file */
	Advance time.Duration
}

var keyNames = map[string]string{"<space>": " ", "<enter>": "\r", "<ctrl-z>": "\x1a"}

/* ParseTranscript parses a transcript of the profile's device in either format. */
func ParseTranscript(p *Profile, name, text string) (*Transcript, error) {
	text = normalizeNL(text)
	tr := &Transcript{Name: name, Meta: map[string]string{}}
	var err error
	if regexp.MustCompile(`(?m)^<<< `).MatchString(text) {
		err = tr.parseMarked(p, text)
	} else {
		err = tr.parseRaw(p, text)
	}
	if err != nil {
		return nil, err
	}
	if tr.Start == "" {
		return nil, errors.New("no prompt: a transcript starts with what the device shows")
	}
	return tr, nil
}

/* directive handles a "## " line; it returns a clock advance, if any. */
func (tr *Transcript) directive(l string, started bool) (time.Duration, error) {
	body := strings.TrimSpace(strings.TrimPrefix(l, "##"))
	if v, ok := strings.CutPrefix(body, "advance "); ok {
		return time.ParseDuration(strings.TrimSpace(v))
	}
	if k, v, ok := strings.Cut(body, ":"); ok && !started {
		tr.Meta[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return 0, nil
}

func (tr *Transcript) last() *Step { return &tr.Steps[len(tr.Steps)-1] }

/* shown sets what the device shows next. */
func (tr *Transcript) shown(text string) error {
	switch {
	case len(tr.Steps) == 0 && tr.Start == "":
		tr.Start = text
	case len(tr.Steps) == 0 || tr.last().Prompt != "":
		return fmt.Errorf("%q: two prompts without input between them", text)
	default:
		tr.last().Prompt = text
	}
	return nil
}

func (tr *Transcript) waitingNow() string {
	if len(tr.Steps) == 0 {
		return tr.Start
	}
	return tr.last().Prompt
}

func (tr *Transcript) typed(p *Profile, st Step) error {
	w := tr.waitingNow()
	if w == "" {
		return fmt.Errorf("input %q before any prompt", st.Input)
	}
	st.Hidden = st.Hidden || w == p.Login["password"].Text || w == p.Login["new_password"].Text
	tr.Steps = append(tr.Steps, st)
	return nil
}

func (tr *Transcript) parseMarked(p *Profile, text string) error {
	var adv time.Duration
	for i, l := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		fail := func(err error) error { return fmt.Errorf("line %d: %w", i+1, err) }
		switch {
		case strings.HasPrefix(l, "## "):
			d, err := tr.directive(l, tr.Start != "")
			if err != nil {
				return fail(err)
			}
			adv += d
		case strings.HasPrefix(l, "<<< "):
			if err := tr.shown(strings.TrimRight(l[4:], " ")); err != nil {
				return fail(err)
			}
		case strings.HasPrefix(l, ">>> "), strings.HasPrefix(l, ">>| "):
			st := Step{Input: l[4:], Advance: adv}
			if l[2] == '|' {
				k, ok := keyNames[st.Input]
				if !ok && len(st.Input) != 1 {
					return fail(fmt.Errorf("key %q: want one character or %v", st.Input, keyNames))
				}
				if ok {
					st.Input = k
				}
				st.Key = true
			}
			adv = 0
			if err := tr.typed(p, st); err != nil {
				return fail(err)
			}
		case tr.Start == "":
			/* banner and login text before the first prompt */
		case len(tr.Steps) == 0 || tr.last().Prompt != "":
			if !p.syslogRe.MatchString(l) && strings.TrimSpace(l) != "" {
				return fail(fmt.Errorf("output %q after a prompt and before input", l))
			}
		default:
			s := tr.last()
			if s.Output != "" || l != "" {
				s.Output += l + "\n"
			}
		}
	}
	return nil
}

func (tr *Transcript) parseRaw(p *Profile, text string) error {
	promptRe := p.promptRe()
	var questions []string
	for _, m := range []map[string]Text{p.Confirm, p.Login} {
		for k, t := range m {
			if k != "failed" && k != "expired" && t.Text != "" {
				questions = append(questions, strings.NewReplacer("{file}", "").Replace(t.Text))
			}
		}
	}
	lines := strings.Split(strings.TrimRight(p.clean(text, false), "\n"), "\n")
	var adv time.Duration
	for i, l := range lines {
		waiting, input, ok := "", "", false
		if m := promptRe.FindString(l); m != "" {
			waiting, input, ok = m, strings.TrimLeft(l[len(m):], " "), true
		} else {
			for _, q := range questions {
				if j := strings.Index(l, q); j >= 0 && q != "" {
					if j > 0 && len(tr.Steps) > 0 {
						tr.last().Output += l[:j] + "\n"
					}
					waiting, input, ok = q, strings.TrimSpace(l[j+len(q):]), true
					break
				}
			}
		}
		switch {
		case strings.HasPrefix(l, "## "):
			d, err := tr.directive(l, tr.Start != "")
			if err != nil {
				return fmt.Errorf("line %d: %w", i+1, err)
			}
			adv += d
		case !ok:
			if len(tr.Steps) > 0 && tr.last().Prompt == "" {
				s := tr.last()
				if s.Output != "" || l != "" {
					s.Output += l + "\n"
				}
			}
		default:
			if err := tr.shown(strings.TrimRight(waiting, " ")); err != nil {
				return fmt.Errorf("line %d: %w", i+1, err)
			}
			if i == len(lines)-1 && input == "" {
				break /* the final prompt */
			}
			st := Step{Input: input, Advance: adv}
			if waiting == p.Login["password"].Text {
				st.Input, st.Hidden = tr.Meta["password"], true
			}
			adv = 0
			if err := tr.typed(p, st); err != nil {
				return fmt.Errorf("line %d: %w", i+1, err)
			}
		}
	}
	return nil
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Z0-9]|\x1b[=>]`)

/*
clean turns terminal output into the lines a reader sees: CRLF, ANSI
sequences, backspaces and carriage-return overprints resolved, pager prompts
removed; with dropSyslog also async log lines; trailing spaces and leading and
trailing blank lines dropped.
*/
func (p *Profile) clean(s string, dropSyslog bool) string {
	s = ansiRe.ReplaceAllString(normalizeNL(s), "")
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, "\b") {
			var b []byte
			for i := 0; i < len(l); i++ {
				if l[i] == '\b' {
					if len(b) > 0 {
						b = b[:len(b)-1]
					}
					continue
				}
				b = append(b, l[i])
			}
			l = string(b)
		}
		l = strings.ReplaceAll(l, p.Pager.Prompt.Text, "")
		if strings.Contains(l, "\r") { /* overprint: the last segment with text wins */
			segs, last := strings.Split(l, "\r"), ""
			for _, seg := range segs {
				if strings.TrimSpace(seg) != "" {
					last = seg
				}
			}
			l = last
		}
		l = strings.TrimRight(l, " \t")
		if dropSyslog && p.syslogRe.MatchString(l) {
			continue
		}
		out = append(out, l)
	}
	return strings.Trim(strings.Join(out, "\n"), "\n")
}

/* Conn is an in-memory terminal on a Device session, for tests and transcript replay. */
type Conn struct {
	d   *Device
	s   *Session
	buf *memOut
}

type memOut struct {
	bytes.Buffer
	closed bool
}

func (m *memOut) Close() error { m.closed = true; return nil }

/* Dial opens a session as an SSH-authenticated user (with Options.InbandLogin it starts at User Name:). */
func (d *Device) Dial(user string) *Conn {
	buf := &memOut{}
	return &Conn{d: d, s: d.open(user, buf), buf: buf}
}

/* Read returns everything the device printed since the last read. */
func (c *Conn) Read() string {
	c.d.mu.Lock()
	defer c.d.mu.Unlock()
	s := c.buf.String()
	c.buf.Reset()
	return s
}

/* Type types text and Enter and returns the raw output (echo included). */
func (c *Conn) Type(text string) string {
	c.s.input([]byte(text + "\r"))
	return c.Read()
}

/* Key presses one key and returns the raw output. */
func (c *Conn) Key(b byte) string {
	c.s.input([]byte{b})
	return c.Read()
}

/* Waiting returns what the device shows while it waits for input ("" once closed). */
func (c *Conn) Waiting() string {
	c.d.mu.Lock()
	defer c.d.mu.Unlock()
	if c.s.closed {
		return ""
	}
	return c.s.waiting()
}

/* Closed reports whether the device closed the session. */
func (c *Conn) Closed() bool {
	c.d.mu.Lock()
	defer c.d.mu.Unlock()
	return c.s.closed
}

/* Do drops unread output, types a line and returns its output without the echo and the next prompt, pages joined, CRLF as "\n". */
func (c *Conn) Do(line string) string {
	_ = c.Read() /* what came before: banner, prompt, async lines */
	return c.body(line, false, c.Type(line))
}

func (c *Conn) body(input string, noEcho bool, raw string) string {
	if !noEcho {
		raw = strings.TrimPrefix(raw, input)
	}
	raw = strings.TrimPrefix(raw, "\r\n")
	for c.Waiting() == c.d.P.Pager.Prompt.Text {
		raw += c.Key(' ')
	}
	return c.d.P.clean(strings.TrimSuffix(raw, c.Waiting()), false)
}

/* Replay runs a transcript against a fresh device of the fixture and returns the first difference. */
func Replay(fx *Fixture, tr *Transcript) error {
	p := fx.Profile
	user, pass := tr.Meta["user"], tr.Meta["password"]
	if user == "" {
		user = "admin"
	}
	priv := 15
	if v := tr.Meta["privilege"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("## privilege: %w", err)
		}
		priv = n
	}
	norm := func(s string) string { return p.clean(s, true) }
	opt := Options{
		InbandLogin: norm(tr.Start) == norm(p.Login["user"].Text),
		Users: map[string]User{user: {Password: pass, Privilege: priv,
			Expired: tr.Meta["password-expired"] == "yes" || strings.Contains(tr.Start, p.Login["new_password"].Text)}},
	}
	d := New(fx, opt)
	c := d.Dial(user)
	_ = c.Read() /* banner */
	if got := c.Waiting(); norm(got) != norm(tr.Start) {
		return fmt.Errorf("start: device shows %q, transcript %q", got, tr.Start)
	}
	for i, st := range tr.Steps {
		if st.Advance > 0 {
			d.Advance(st.Advance)
		}
		var raw string
		if st.Key {
			raw = c.Key(st.Input[0])
		} else {
			raw = c.Type(st.Input)
		}
		if norm(st.Prompt) == norm(p.Pager.Prompt.Text) || st.Key {
			raw = strings.TrimSuffix(raw, c.Waiting())
			if !st.Key && !st.Hidden {
				raw = strings.TrimPrefix(raw, st.Input)
			}
		} else {
			raw = c.body(st.Input, st.Key || st.Hidden, raw)
		}
		where := fmt.Sprintf("step %d (%q)", i+1, st.Input)
		if got, want := norm(raw), norm(st.Output); got != want {
			return fmt.Errorf("%s: output\n--- device\n%s\n--- transcript\n%s", where, got, want)
		}
		if st.Prompt == "" {
			continue
		}
		if got := c.Waiting(); norm(got) != norm(st.Prompt) {
			return fmt.Errorf("%s: device then shows %q, transcript %q", where, got, st.Prompt)
		}
	}
	return nil
}
