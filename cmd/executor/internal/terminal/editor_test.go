package terminal

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
)

/* feedAll feeds data and returns the events it stopped at. */
func feedAll(e *editor, data string, paste bool) []event {
	var evs []event
	for data != "" {
		var ev event
		ev, data = e.feed(data, paste)
		if ev != evNone {
			evs = append(evs, ev)
		}
	}
	return evs
}

/* The editing keys of the plan: arrows, Backspace, Delete, Home/End, Ctrl-A/E/U/W/C; other escape sequences are dropped whole. */
func TestEditorKeys(t *testing.T) {
	cases := []struct{ keys, want string }{
		{"show vlan", "show vlan"},
		{"shw\x1b[Do", "show"},
		{"show\x1bOD\x1bOD\x7f", "sow"},
		{"show\x1b[H\x1b[3~", "how"},
		{"how\x01s\x05!", "show!"},
		{"how\x1b[1~s\x1b[4~!", "show!"},
		{"show ip route\x17\x17", "show "},
		{"show ip\x1b[D\x1b[D\x15", "ip"},
		{"sh\x08ow", "sow"},
		{"a\x1b[1;5Cb", "ab"},                      /* an unknown CSI key: dropped whole */
		{"a\x1b]52;c;ZXZpbA==\x07b", "ab"},         /* OSC 52 typed: dropped, payload included */
		{"a\x1b]0;title\x1b\\b", "ab"},             /* OSC with ST */
		{"a\x1bPq#0;2;0;0;0\x1b\\b", "ab"},         /* DCS */
		{"a\x1b[200~b\x1b[201~", "ab"},             /* bracketed paste markers */
		{"a\x1b(Bb\x1bcc", "abc"},                  /* charset and RIS */
		{"a\x00\x02\x04\x0b\x0c\x0e\x1f\x7f", ""},  /* other controls dropped, DEL deletes */
		{"a\u0085\u009b\u202e\u200b\ufeffb", "ab"}, /* C1, bidi, zero-width, BOM */
		{"a" + string([]byte{0xff, 0xc0}) + "b", "ab"},
		{"vlan 10\x1b", "vlan 10"},
	}
	for _, c := range cases {
		var e editor
		if evs := feedAll(&e, c.keys, false); len(evs) != 0 {
			t.Errorf("%q: events %v", c.keys, evs)
		}
		if e.text() != c.want {
			t.Errorf("%q: line %q, want %q", c.keys, e.text(), c.want)
		}
	}
}

func TestEditorEvents(t *testing.T) {
	var e editor
	ev, rest := e.feed("conf\tig", false)
	if ev != evComplete || rest != "ig" || e.prefix() != "conf" {
		t.Fatalf("tab: %v %q %q", ev, rest, e.prefix())
	}
	if !e.complete([]string{"configure"}) || e.text() != "configure " {
		t.Fatalf("complete: %q", e.text())
	}
	if e.complete([]string{"<vlan>"}) || e.complete([]string{"a", "b"}) || e.text() != "configure " {
		t.Fatalf("an argument or a choice changed the line: %q", e.text())
	}
	if ev, _ := e.feed("?", false); ev != evHelp {
		t.Fatalf("? = %v", ev)
	}
	if ev, rest := e.feed("\r\nx", false); ev != evEnter || rest != "x" {
		t.Fatalf("CRLF = %v %q", ev, rest)
	}
	if ev, _ := e.feed("\x03", false); ev != evCancel {
		t.Fatalf("Ctrl-C = %v", ev)
	}
	/* in a paste: tab is a space, '?' a character, escapes and editing keys dropped */
	var p editor
	if evs := feedAll(&p, "int\tgi1/0/1 ?\x1b[D\x15\x7f", true); len(evs) != 0 || p.text() != "int gi1/0/1 ?" {
		t.Fatalf("paste: %v %q", evs, p.text())
	}
}

func TestEditorHistory(t *testing.T) {
	var e editor
	for _, l := range []string{"show vlan\r", "show vlan\r", "   \r", "show clock\r"} {
		e.feed(l, false)
		e.take()
	}
	if len(e.hist) != 2 {
		t.Fatalf("history %q: repeats and blanks kept", e.hist)
	}
	feedAll(&e, "sh\x1b[A", false)
	if e.text() != "show clock" {
		t.Fatalf("up: %q", e.text())
	}
	feedAll(&e, "\x1b[A\x1b[A", false)
	if e.text() != "show vlan" {
		t.Fatalf("up up: %q", e.text())
	}
	feedAll(&e, "\x1b[B\x1b[B", false)
	if e.text() != "sh" {
		t.Fatalf("back to the typed line: %q", e.text())
	}
	for i := range maxHistory + 10 {
		feedAll(&e, "x"+strings.Repeat("y", i), false)
		e.take()
	}
	if len(e.hist) != maxHistory {
		t.Fatalf("history %d entries", len(e.hist))
	}
	feedAll(&e, strings.Repeat("é", core.MaxLine), false)
	if len(e.text()) > core.MaxLine || e.size != len(e.text()) {
		t.Fatalf("line of %d bytes (size %d)", len(e.text()), e.size)
	}
}

/* Device output: no escape sequence (OSC 52 included), control or format character reaches the browser. */
func TestCleanStripsEscapes(t *testing.T) {
	cases := map[string]string{
		"a\x1b]52;c;ZXZpbA==\x07b":               "ab",
		"a\x1b]52;c;ZXZpbA==\x1b\\b":             "ab",
		"a\u009d52;c;ZXZpbA==\u009cb":            "ab",
		"a\x1b]8;;http://x/\x07link\x1b]8;;\x07": "alink",
		"\x1b[31mred\x1b[0m\r\n":                 "red\n",
		"a\u009b31mb":                            "ab",
		"a\x1bPtmux;\x1b\x1b]52;c;x\x07\x1b\\b":  "ab",
		"a\x1b_apc\x1b\\b\x1b^pm\x1b\\c":         "abc",
		"t\tab\x08\x07\x00\x7f\u202e\u200bx":     "t\tabx",
		"bad" + string([]byte{0xff}):             "bad\ufffd",
		"cut\x1b]52;c;never ends":                "cut",
		"кириллица ok":                           "кириллица ok",
	}
	for in, want := range cases {
		if got := clean(in); got != want {
			t.Errorf("clean(%q) = %q, want %q", in, got, want)
		}
	}
}

func checkClean(t *testing.T, in string) {
	out := clean(in)
	if !utf8.ValidString(out) {
		t.Fatalf("clean(%q) = %q: invalid UTF-8", in, out)
	}
	for _, r := range out {
		if r != '\n' && r != '\t' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) {
			t.Fatalf("clean(%q) = %q: control %U", in, out, r)
		}
	}
	if again := clean(out); again != out {
		t.Fatalf("clean is not idempotent on %q: %q", out, again)
	}
}

/* FuzzClean: whatever a device sends, the browser gets text without controls (but \n, \t) or format characters. */
func FuzzClean(f *testing.F) {
	for _, s := range []string{"\x1b]52;c;ZXZpbA==\x07", "\x1b[31m", "\u009d52;c;x\u009c", "\x1bP\x1b\\", "a\r\nb"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		checkClean(t, s)
		/* a paste is shown as typed: no control but the line breaks */
		var e editor
		p := pasted(s)
		for _, r := range p {
			if r != '\n' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) {
				t.Fatalf("pasted(%q) = %q: control %U", s, p, r)
			}
		}
		if breaks(s) != strings.Count(p, "\n") {
			t.Fatalf("breaks(%q) = %d, the shown text has %d", s, breaks(s), strings.Count(p, "\n"))
		}
		/* the line editor never holds a control or format character, nor more than core.MaxLine bytes */
		for _, paste := range []bool{false, true} {
			feedAll(&e, s, paste)
			l := e.text()
			if len(l) > core.MaxLine || e.cur < 0 || e.cur > len(e.buf) {
				t.Fatalf("feed(%q): line of %d bytes, cursor %d", s, len(l), e.cur)
			}
			for _, r := range l {
				if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
					t.Fatalf("feed(%q) = %q: control %U", s, l, r)
				}
			}
		}
	})
}
