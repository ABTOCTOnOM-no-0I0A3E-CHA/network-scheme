package drivers

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

/* MaxTextLen bounds every string taken from a device, in bytes. */
const MaxTextLen = 1024

/*
CleanText turns untrusted device bytes into display text: invalid UTF-8 is
replaced, control and format characters (including bidi overrides) are
removed, surrounding space is trimmed and the result is cut to MaxTextLen
bytes on a rune boundary.
*/
func CleanText(b []byte) string {
	s := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(string(b), string(utf8.RuneError)))
	s = strings.TrimSpace(s)
	if len(s) > MaxTextLen {
		cut := MaxTextLen
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut]
	}
	return s
}

/* FormatMAC formats a 6-byte MAC address as "aa:bb:cc:dd:ee:ff". */
func FormatMAC(b []byte) (string, bool) {
	if len(b) != 6 {
		return "", false
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5]), true
}
