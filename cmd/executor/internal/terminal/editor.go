package terminal

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
)

/* event is what stopped feed: a key the session acts on. */
type event uint8

const (
	evNone     event = iota
	evEnter          /* the line is complete */
	evComplete       /* Tab: complete the word through the grammar */
	evHelp           /* '?': list what may follow through the grammar */
	evCancel         /* Ctrl-C: drop the line (and a pending confirmation) */
)

/* History bounds: entries kept per device. */
const maxHistory = 100

/*
editor is the line being typed on one device: its runes, the cursor and
the device's history. It knows only the keys of the line editor (arrows,
Backspace, Delete, Home/End, Ctrl-A/E/U/W/C, Enter, Tab, '?'); every other
control or escape sequence is dropped whole, and so are format characters
(bidirectional overrides, zero-width) and invalid UTF-8. Nothing it holds
reaches the device until Enter hands the whole line to the session.
*/
type editor struct {
	buf   []rune
	cur   int
	hist  []string
	hpos  int    /* len(hist): the line being typed */
	saved []rune /* the line being typed while the history is browsed */
	size  int    /* bytes of buf in UTF-8: at most core.MaxLine */
}

func (e *editor) text() string { return string(e.buf) }

/* prefix is the line up to the cursor: what Tab and '?' complete. */
func (e *editor) prefix() string { return string(e.buf[:e.cur]) }

func (e *editor) set(r []rune) {
	e.buf, e.cur, e.size = append([]rune(nil), r...), len(r), len(string(r))
}

func (e *editor) insert(r rune) {
	n := utf8.RuneLen(r)
	if n < 0 || e.size+n > core.MaxLine {
		return
	}
	e.buf = append(e.buf, 0)
	copy(e.buf[e.cur+1:], e.buf[e.cur:])
	e.buf[e.cur] = r
	e.cur++
	e.size += n
}

/* cut removes buf[from:to] and leaves the cursor at from. */
func (e *editor) cut(from, to int) {
	if from < 0 || to > len(e.buf) || from >= to {
		return
	}
	e.size -= len(string(e.buf[from:to]))
	e.buf = append(e.buf[:from], e.buf[to:]...)
	e.cur = from
}

/* take ends the line: it returns the text, keeps it in the history (not a blank one or a repeat) and starts an empty one. */
func (e *editor) take() string {
	line := e.text()
	if strings.TrimSpace(line) != "" && (len(e.hist) == 0 || e.hist[len(e.hist)-1] != line) {
		if len(e.hist) == maxHistory {
			e.hist = append(e.hist[:0], e.hist[1:]...)
		}
		e.hist = append(e.hist, line)
	}
	e.clear()
	return line
}

func (e *editor) clear() {
	e.buf, e.cur, e.size, e.saved = nil, 0, 0, nil
	e.hpos = len(e.hist)
}

func (e *editor) up() {
	if e.hpos == 0 {
		return
	}
	if e.hpos == len(e.hist) {
		e.saved = append([]rune(nil), e.buf...)
	}
	e.hpos--
	e.set([]rune(e.hist[e.hpos]))
}

func (e *editor) down() {
	if e.hpos >= len(e.hist) {
		return
	}
	e.hpos++
	if e.hpos == len(e.hist) {
		e.set(e.saved)
		return
	}
	e.set([]rune(e.hist[e.hpos]))
}

/* killWord is Ctrl-W: the spaces before the cursor, then the word before them. */
func (e *editor) killWord() {
	i := e.cur
	for i > 0 && e.buf[i-1] == ' ' {
		i--
	}
	for i > 0 && e.buf[i-1] != ' ' {
		i--
	}
	e.cut(i, e.cur)
}

/*
complete applies the grammar's completions of the prefix: one keyword
replaces the partial word before the cursor (with a space after it);
anything else changes nothing (the caller shows the list). The words come
from the grammar only, never from the line or the device.
*/
func (e *editor) complete(words []string) bool {
	if len(words) != 1 || strings.HasPrefix(words[0], "<") {
		return false
	}
	i := e.cur
	for i > 0 && e.buf[i-1] != ' ' {
		i--
	}
	e.cut(i, e.cur)
	for _, r := range words[0] + " " {
		e.insert(r)
	}
	return true
}

/* dropRune: control (C0, DEL, C1) and format characters, and invalid UTF-8, never enter the line. */
func dropRune(r rune, size int) bool {
	return r == utf8.RuneError && size <= 1 || unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
}

/*
feed applies data, a keys frame (paste false) or a confirmed paste, and
stops at the first key the session acts on (Enter, and for keys Tab, '?'
and Ctrl-C), returning it with the data not yet read. In a paste Tab is a
space, '?' a character (the grammar refuses the line), and escape
sequences are dropped like any control. "\r\n" is one Enter.
*/
func (e *editor) feed(data string, paste bool) (event, string) {
	for len(data) > 0 {
		r, size := utf8.DecodeRuneInString(data)
		rest := data[size:]
		switch {
		case r == '\r' || r == '\n':
			if r == '\r' && strings.HasPrefix(rest, "\n") {
				rest = rest[1:]
			}
			return evEnter, rest
		case r == '\t' && paste:
			e.insert(' ')
		case r == '\t':
			return evComplete, rest
		case r == '?' && !paste:
			return evHelp, rest
		case r == 0x1b:
			var key string
			key, rest = escape(rest)
			if !paste {
				e.key(key)
			}
		case paste && (r < 0x20 || r == 0x7f):
			/* no editing keys in a paste: dropped */
		case r == 0x03:
			return evCancel, rest
		case r == 0x7f || r == 0x08:
			e.cut(e.cur-1, e.cur)
		case r == 0x01:
			e.cur = 0
		case r == 0x05:
			e.cur = len(e.buf)
		case r == 0x15:
			e.cut(0, e.cur)
		case r == 0x17:
			e.killWord()
		case dropRune(r, size):
		default:
			e.insert(r)
		}
		data = rest
	}
	return evNone, ""
}

/* key applies a recognized escape key. */
func (e *editor) key(k string) {
	switch k {
	case "up":
		e.up()
	case "down":
		e.down()
	case "left":
		e.cur = max(0, e.cur-1)
	case "right":
		e.cur = min(len(e.buf), e.cur+1)
	case "home":
		e.cur = 0
	case "end":
		e.cur = len(e.buf)
	case "delete":
		e.cut(e.cur, e.cur+1)
	}
}

/* keys are the CSI and SS3 sequences of the editing keys. */
var keys = map[string]string{
	"[A": "up", "[B": "down", "[C": "right", "[D": "left", "[H": "home", "[F": "end",
	"[1~": "home", "[7~": "home", "[4~": "end", "[8~": "end", "[3~": "delete",
	"OA": "up", "OB": "down", "OC": "right", "OD": "left", "OH": "home", "OF": "end",
}

/*
escape reads the sequence after an ESC whole and returns the editing key it
names ("" for any other) and the data after it: CSI (ESC [ parameters,
intermediates, a final byte), SS3 (ESC O and one byte), the string
sequences OSC, DCS, SOS, PM, APC (up to BEL or ST; unterminated: the rest
of the frame), or ESC, intermediates and a final byte. A sequence cut by a control or a
non-ASCII byte ends there, the byte read again as data.
*/
func escape(s string) (string, string) {
	if s == "" {
		return "", ""
	}
	switch c := s[0]; {
	case c == '[':
		i := 1
		for i < len(s) && s[i] >= 0x20 && s[i] <= 0x3f {
			i++
		}
		for i < len(s) && s[i] >= 0x20 && s[i] <= 0x2f {
			i++
		}
		if i < len(s) && s[i] >= 0x40 && s[i] <= 0x7e {
			return keys[s[:i+1]], s[i+1:]
		}
		return "", s[i:]
	case c == 'O':
		if len(s) > 1 && s[1] >= 0x20 && s[1] <= 0x7e {
			return keys[s[:2]], s[2:]
		}
		return "", s[1:]
	case c == ']' || c == 'P' || c == 'X' || c == '^' || c == '_':
		return "", stringEnd(s[1:])
	case c >= 0x20 && c <= 0x2f: /* intermediates, then a final byte (ESC ( B) */
		i := 1
		for i < len(s) && s[i] >= 0x20 && s[i] <= 0x2f {
			i++
		}
		if i < len(s) && s[i] >= 0x30 && s[i] <= 0x7e {
			i++
		}
		return "", s[i:]
	case c >= 0x30 && c <= 0x7e:
		return "", s[1:]
	}
	return "", s /* a control or non-ASCII after ESC: read again */
}

/* stringEnd skips a string sequence's payload to after its BEL, ESC \ or 8-bit ST; unterminated: everything. */
func stringEnd(s string) string {
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == 0x07:
			return s[i+1:]
		case s[i] == 0x1b && i+1 < len(s) && s[i+1] == '\\':
			return s[i+2:]
		case s[i] == 0xc2 && i+1 < len(s) && s[i+1] == 0x9c:
			return s[i+2:]
		}
	}
	return ""
}
