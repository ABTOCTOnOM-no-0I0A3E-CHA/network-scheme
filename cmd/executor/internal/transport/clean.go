package transport

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

/*
stripEscapes removes terminal escape sequences from device output: CSI
(ESC [ … final), the string sequences OSC, DCS, SOS, PM and APC (ESC ] P X ^
_ up to BEL or ESC \), and every other ESC sequence (intermediates and a
final byte). An unfinished sequence at the end is dropped with the rest of
the input: nothing of it reaches a client.
*/
func stripEscapes(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); {
		if b[i] != 0x1b {
			out = append(out, b[i])
			i++
			continue
		}
		j := i + 1
		if j >= len(b) {
			break
		}
		switch b[j] {
		case '[':
			j++
			for j < len(b) && b[j] >= 0x20 && b[j] <= 0x3f {
				j++
			}
			if j < len(b) && b[j] >= 0x40 && b[j] <= 0x7e {
				j++
			}
		case ']', 'P', 'X', '^', '_':
			j++
			for j < len(b) {
				if b[j] == 0x07 {
					j++
					break
				}
				if b[j] == 0x1b && j+1 < len(b) && b[j+1] == '\\' {
					j += 2
					break
				}
				j++
			}
		default:
			for j < len(b) && b[j] >= 0x20 && b[j] <= 0x2f {
				j++
			}
			if j < len(b) {
				j++
			}
		}
		i = j
	}
	return out
}

/* dropped are runes no client ever gets: C0 but tab, DEL, C1, and the bidirectional controls. */
func dropped(r rune) bool {
	switch {
	case r == '\t':
		return false
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
		return true
	case r == 0x200e, r == 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}

/*
sanitizeLine renders one line (no '\n') as a terminal would show it, as
plain text: CR returns to column 0 and later text overwrites, backspace
moves left, invalid UTF-8 becomes U+FFFD, and every dropped rune goes.
Trailing blanks are removed. Input must already be free of escapes.
*/
func sanitizeLine(raw []byte) string {
	var cells []rune
	col := 0
	for len(raw) > 0 {
		r, n := utf8.DecodeRune(raw)
		raw = raw[n:]
		switch {
		case r == '\r':
			col = 0
			continue
		case r == '\b':
			col = max(col-1, 0)
			continue
		case dropped(r):
			continue
		}
		if col < len(cells) {
			cells[col] = r
		} else {
			cells = append(cells, r)
		}
		col++
	}
	return strings.TrimRight(string(cells), " \t")
}

/* cleanLines strips escapes from raw device output and splits it into sanitized lines. */
func cleanLines(raw []byte) []string {
	parts := bytes.Split(stripEscapes(raw), []byte("\n"))
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = sanitizeLine(p)
	}
	return out
}

/* lastRaw returns the start of the last (unterminated) line of b. */
func lastRaw(b []byte) int { return bytes.LastIndexByte(b, '\n') + 1 }
