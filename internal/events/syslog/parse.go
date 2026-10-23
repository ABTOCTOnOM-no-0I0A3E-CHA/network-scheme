/*
Package syslog parses untrusted syslog datagrams (RFC 3164, RFC 5424 and the
Eltex MES/ESR flavours) into a normalized Message.

The parser is pure (no I/O) and strict: limits are enforced, text is
sanitized to valid UTF-8 without control characters, and fields are only
extracted from the header when the layout is unambiguous. Message text is
never dropped, only the recognised header parts are split off it. A malformed
RFC 5424 header therefore keeps the whole remainder as Text (TS=now, no
Host/App); only a bad PRI or an oversized message is rejected.

Host and App are text claimed by the device: for display only. They must never
be used to identify the source (eventd identifies it by IP address alone).
*/
package syslog

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// MaxMessage is the largest accepted datagram/frame, in bytes.
	MaxMessage = 8 << 10
	// MaxHost is the largest Host length (RFC 5424 HOSTNAME limit).
	MaxHost = 255
	// MaxApp is the largest App length (RFC 5424 APP-NAME limit).
	MaxApp = 48
	// maxFuture is how far ahead of now a device timestamp may be.
	maxFuture = time.Hour
	// maxPast is how far behind now a device timestamp may be; the timestamp
	// is a hypertable partition key, so claimed days must not create chunks.
	maxPast = 24 * time.Hour
)

var (
	// ErrTooLarge is returned for input longer than MaxMessage.
	ErrTooLarge = errors.New("syslog: message too large")
	// ErrMalformed is returned when the PRI or a mandatory header part is invalid.
	ErrMalformed = errors.New("syslog: malformed message")
)

/*
Message is a normalized syslog message. TS is always UTC and within
[now-24h, now+1h]. Host and App are device-claimed text, display only, never
used for source identification.
*/
type Message struct {
	TS       time.Time
	Facility uint8
	Severity uint8
	Host     string
	App      string
	Text     string
}

/*
Parse parses one syslog message. Timestamps without a zone are taken as UTC;
a missing timestamp, or one outside [now-24h, now+1h], becomes now.
*/
func Parse(b []byte, now time.Time) (Message, error) {
	if len(b) > MaxMessage {
		return Message{}, ErrTooLarge
	}
	b = trimTail(b)
	pri, rest, ok := parsePRI(string(b))
	if !ok {
		return Message{}, ErrMalformed
	}
	m := Message{Facility: uint8(pri >> 3), Severity: uint8(pri & 7)} //nolint:gosec // pri <= 191
	if isV1(rest) {
		if err := parse5424(&m, rest); err != nil {
			/* keep the text: reset the header fields and use the whole remainder */
			m.TS, m.Host, m.App, m.Text = time.Time{}, "", "", rest
		}
	} else {
		parse3164(&m, rest, now)
	}
	if m.TS.IsZero() || m.TS.After(now.Add(maxFuture)) || m.TS.Before(now.Add(-maxPast)) {
		m.TS = now
	}
	m.TS = m.TS.UTC()
	/* Clone: a clean field is a substring of the whole raw message and would keep all of it alive. */
	m.Host = strings.Clone(clip(sanitize(m.Host), MaxHost))
	m.App = strings.Clone(clip(sanitize(m.App), MaxApp))
	m.Text = strings.Clone(clip(sanitize(m.Text), MaxMessage))
	return m, nil
}

func trimTail(b []byte) []byte {
	for len(b) > 0 {
		switch b[len(b)-1] {
		case '\n', '\r', 0:
			b = b[:len(b)-1]
		default:
			return b
		}
	}
	return b
}

/* parsePRI reads "<N>" with N in 0..191 and no leading zeros. */
func parsePRI(s string) (pri int, rest string, ok bool) {
	if len(s) < 3 || s[0] != '<' {
		return 0, "", false
	}
	i := 1
	for i < len(s) && i <= 3 && isDigit(s[i]) {
		pri = pri*10 + int(s[i]-'0')
		i++
	}
	if i == 1 || i >= len(s) || s[i] != '>' || (i > 2 && s[1] == '0') || pri > 191 {
		return 0, "", false
	}
	return pri, s[i+1:], true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

/* sanitize makes s valid UTF-8 and replaces what badRune lists (C0 controls except \t, DEL, C1 controls, bidi controls, U+2028/2029) with U+FFFD. */
func sanitize(s string) string {
	clean := true
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= utf8.RuneSelf || (c < 0x20 && c != '\t') || c == 0x7f {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if (r == utf8.RuneError && n <= 1) || badRune(r) {
			sb.WriteRune(utf8.RuneError)
		} else {
			sb.WriteString(s[i : i+n])
		}
		i += n
	}
	return sb.String()
}

/*
badRune: C0 controls except \t, DEL, C1 controls, bidi embedding/override/isolate
controls and the line/paragraph separators (log-line display spoofing).
*/
func badRune(r rune) bool {
	return (r < 0x20 && r != '\t') || (r >= 0x7f && r <= 0x9f) ||
		(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || r == 0x2028 || r == 0x2029
}

/* clip cuts s to at most n bytes on a rune boundary. */
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

/* token splits s at the first space; ok is false when there is no space. */
func token(s string) (tok, rest string, ok bool) {
	i := strings.IndexByte(s, ' ')
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+1:], true
}

/* isV1 reports whether rest starts an RFC 5424 header: "1 " followed by "-" or a year. */
func isV1(s string) bool {
	if len(s) < 3 || s[0] != '1' || s[1] != ' ' {
		return false
	}
	return s[2] == '-' || (len(s) >= 6 && isDigit(s[2]) && isDigit(s[3]) && isDigit(s[4]) && isDigit(s[5]))
}

/* headerField validates an RFC 5424 header token: 1..max printable ASCII, "-" means nil. */
func headerField(tok string, limit int) (string, bool) {
	if tok == "-" {
		return "", true
	}
	if len(tok) == 0 || len(tok) > limit {
		return "", false
	}
	for i := 0; i < len(tok); i++ {
		if tok[i] < 33 || tok[i] > 126 {
			return "", false
		}
	}
	return tok, true
}

func parse5424(m *Message, s string) error {
	s = s[2:] /* version and its space */
	var toks [5]string
	for i := range toks {
		t, r, ok := token(s)
		if !ok {
			return ErrMalformed
		}
		toks[i], s = t, r
	}
	if toks[0] != "-" {
		ts, err := time.Parse(time.RFC3339Nano, toks[0])
		if err != nil {
			return ErrMalformed
		}
		m.TS = ts
	}
	var ok bool
	if m.Host, ok = headerField(toks[1], MaxHost); !ok {
		return ErrMalformed
	}
	if m.App, ok = headerField(toks[2], MaxApp); !ok {
		return ErrMalformed
	}
	if _, ok = headerField(toks[3], 128); !ok { /* PROCID */
		return ErrMalformed
	}
	if _, ok = headerField(toks[4], 32); !ok { /* MSGID */
		return ErrMalformed
	}
	n, ok := sdLen(s)
	if !ok {
		return ErrMalformed
	}
	s = s[n:]
	if s != "" {
		if s[0] != ' ' {
			return ErrMalformed
		}
		s = s[1:]
	}
	m.Text = strings.TrimPrefix(s, "\xef\xbb\xbf")
	return nil
}

/*
sdLen returns the length of the STRUCTURED-DATA at the start of s: "-" or one
or more bracketed elements. Inside quoted parameter values a backslash escapes
the next byte, so an escaped quote or bracket does not end the value/element.
*/
func sdLen(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	if s[0] == '-' {
		return 1, true
	}
	i := 0
	for i < len(s) && s[i] == '[' {
		inQuote := false
		i++
		for ; i < len(s); i++ {
			c := s[i]
			if inQuote && c == '\\' {
				i++
			} else if c == '"' {
				inQuote = !inQuote
			} else if c == ']' && !inQuote {
				break
			}
		}
		if i >= len(s) {
			return 0, false
		}
		i++ /* closing bracket */
	}
	return i, i > 0
}

var months = map[string]time.Month{
	"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
	"Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

func parse3164(m *Message, s string, now time.Time) {
	ts, rest, ok := timestamp3164(s, now)
	if ok {
		m.TS = ts
		s = rest
		if tok, after, found := token(s); found && hostLike(tok) {
			m.Host = tok
			s = after
		}
		if app, after, found := tag3164(s); found {
			m.App = app
			s = after
		}
	}
	m.Text = s
	eltex(m)
}

/*
timestamp3164 recognises "Mmm dd hh:mm:ss", "Mmm dd yyyy hh:mm:ss" (Eltex) and
an RFC 3339 timestamp. Without a year the latest candidate year (now-1..now+1) not more than an
hour ahead of now wins, which handles the new-year rollover. An out-of-range date yields a zero time.
*/
func timestamp3164(s string, now time.Time) (ts time.Time, rest string, ok bool) {
	if len(s) >= 20 && isDigit(s[0]) && isDigit(s[1]) && isDigit(s[2]) && isDigit(s[3]) && s[4] == '-' {
		tok, after, _ := token(s)
		if len(tok) > 40 {
			return
		}
		t, err := time.Parse(time.RFC3339Nano, tok)
		if err != nil {
			return
		}
		return t, after, true
	}
	if len(s) < 15 {
		return
	}
	mon, found := months[s[:3]]
	if !found || s[3] != ' ' {
		return
	}
	i := 4
	if s[i] == ' ' {
		i++
	}
	day, n := num(s[i:], 2)
	if n == 0 || i+n >= len(s) || s[i+n] != ' ' {
		return
	}
	i += n + 1
	year := 0
	if len(s) >= i+5 && s[i+4] == ' ' {
		if y, yn := num(s[i:], 4); yn == 4 {
			year = y
			i += 5
		}
	}
	if len(s) < i+8 || s[i+2] != ':' || s[i+5] != ':' {
		return
	}
	hh, n1 := num(s[i:], 2)
	mm, n2 := num(s[i+3:], 2)
	ss, n3 := num(s[i+6:], 2)
	if n1 != 2 || n2 != 2 || n3 != 2 {
		return
	}
	i += 8
	if i < len(s) && s[i] == '.' { /* fractional seconds, ignored */
		j := i + 1
		for j < len(s) && j-i <= 9 && isDigit(s[j]) {
			j++
		}
		if j > i+1 {
			i = j
		}
	}
	if i < len(s) && s[i] == ':' {
		i++
	}
	if i < len(s) {
		if s[i] != ' ' {
			return
		}
		i++
	}
	rest, ok = s[i:], true
	if hh > 23 || mm > 59 || ss > 59 || day < 1 {
		return
	}
	build := func(y int) (time.Time, bool) {
		t := time.Date(y, mon, day, hh, mm, ss, 0, time.UTC)
		return t, t.Day() == day
	}
	if year != 0 {
		if t, v := build(year); v {
			ts = t
		}
		return
	}
	for y := now.Year() - 1; y <= now.Year()+1; y++ {
		if t, v := build(y); v && !t.After(now.Add(maxFuture)) {
			ts = t /* years ascend: the latest candidate not in the future wins */
		}
	}
	return
}

/* num reads up to max leading digits of s. */
func num(s string, limit int) (v, n int) {
	for n < len(s) && n < limit && isDigit(s[n]) {
		v = v*10 + int(s[n]-'0')
		n++
	}
	return
}

/* hostLike: a plausible hostname or IP literal, not a tag ("x:", "x[1]:") nor an Eltex "%..." token. */
func hostLike(t string) bool {
	if len(t) == 0 || len(t) > MaxHost || t[len(t)-1] == ':' {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || isDigit(c)
		if !alnum && c != '.' && c != '-' && c != '_' && c != ':' {
			return false
		}
	}
	return true
}

/* tag3164 splits a leading "tag:" or "tag[pid]:" off s. */
func tag3164(s string) (app, rest string, ok bool) {
	i := 0
	for i < len(s) && i <= MaxApp {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || isDigit(c) || c == '.' || c == '_' || c == '-' || c == '/' {
			i++
			continue
		}
		break
	}
	if i == 0 || i > MaxApp || i >= len(s) {
		return
	}
	app = s[:i]
	if s[i] == '[' {
		j := i + 1
		for j < len(s) && isDigit(s[j]) {
			j++
		}
		if j == i+1 || j >= len(s) || s[j] != ']' {
			return "", s, false
		}
		i = j + 1
	}
	if i >= len(s) || s[i] != ':' {
		return "", s, false
	}
	i++
	return app, strings.TrimPrefix(s[i:], " "), true
}
