package terminal

import (
	"strings"
	"unicode/utf8"
)

/*
clean turns device output into plain text for the browser: escape
sequences (CSI, SS3, OSC with OSC 52 among them, DCS, SOS, PM, APC, any
ESC and one byte, and their 8-bit C1 forms) are removed whole, every other
control (C0 but '\n' and '\t', DEL, C1) and format character is dropped,
and invalid UTF-8 becomes U+FFFD. The UI renders the result as text only;
this keeps the device from driving the terminal or the clipboard at all.
*/
func clean(s string) string { return Clean(s) }

/* Clean is clean for the session recording (it records and replays what the browser would get). */
func Clean(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		s = s[size:]
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r == 0x1b:
			_, s = escape(s)
		case r == 0x9b: /* 8-bit CSI */
			_, s = escape("[" + s)
		case r == 0x90 || r == 0x98 || r == 0x9d || r == 0x9e || r == 0x9f: /* 8-bit DCS, SOS, OSC, PM, APC */
			s = stringEnd(s)
		case r == utf8.RuneError && size <= 1:
			b.WriteRune(utf8.RuneError)
		case dropRune(r, size):
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
