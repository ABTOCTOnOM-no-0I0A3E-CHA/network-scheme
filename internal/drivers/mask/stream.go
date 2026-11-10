package mask

import (
	"regexp"
	"strings"
)

/* Block states of a Stream: outside a block, inside a PEM block, inside a "crypto ... import" block. */
const (
	outside = iota
	inPEM
	inImport
)

var (
	/* keyRe: a line of key material (base64 or hex), no space; KeyMaterial adds what tells it from a word. */
	keyRe = regexp.MustCompile(`^[A-Za-z0-9+/=]{1,128}$`)
	/* pemHeaderRe: an RFC 1421 header line inside a PEM block (Proc-Type, DEK-Info). */
	pemHeaderRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,63}: \S`)
)

/*
KeyMaterial reports whether a line (trimmed) looks like a line of key
material: base64/hex characters only, no space, at most 128, and a digit,
'+', '/' or '=' or at least 20 characters (a word such as "shutdown" or
"exit" is not). Such a line is masked whole wherever it is: no command
reads like that, so nothing an operator types can be hidden by it.
*/
func KeyMaterial(t string) bool {
	return keyRe.MatchString(t) && (len(t) >= 20 || strings.ContainsAny(t, "0123456789+/="))
}

/*
Stream follows PEM and "crypto ... import" blocks across the lines of a
session's device output, which arrives in pieces: Block reports, line by
line, whether a line is inside a block and must be masked whole. Inside a
block only lines that look like key material (KeyMaterial, PEM markers and
headers, empty lines) stay in it; any other line, a prompt or a command's
answer, ends the block and is masked as usual, so an opener the device did
not take cannot hide what follows. The zero value is outside any block.
*/
type Stream struct{ mode int }

/* Block advances the state over line and reports whether the line must be masked whole. */
func (s *Stream) Block(line string) bool {
	t := strings.TrimSpace(line)
	switch s.mode {
	case inPEM:
		switch {
		case strings.HasPrefix(t, "-----END "):
			s.mode = outside
			return false
		case t == "":
			return false
		case KeyMaterial(t), pemHeaderRe.MatchString(t):
			return true
		}
		s.mode = outside
	case inImport:
		switch {
		case t == "." || t == "!" || t == "exit" || t == "end":
			s.mode = outside
			return false
		case t == "":
			return false
		case KeyMaterial(t), strings.HasPrefix(t, "-----BEGIN ") || strings.HasPrefix(t, "-----END "), pemHeaderRe.MatchString(t):
			return true
		}
		s.mode = outside
	}
	switch {
	case strings.HasPrefix(t, "-----BEGIN ") && !strings.Contains(t, "-----END "):
		s.mode = inPEM
	case certRe.MatchString(line):
		s.mode = inImport
	}
	return KeyMaterial(t)
}
