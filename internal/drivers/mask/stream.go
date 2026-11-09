package mask

import "strings"

/* Block states of a Stream: outside a block, inside a PEM block, inside a "crypto ... import" block. */
const (
	outside = iota
	inPEM
	inImport
)

/*
Stream masks a text that arrives in pieces of whole lines, as a change
session's input and output do: a PEM block or a "crypto ... import" block
that one piece leaves open goes on being masked in the next pieces (Secrets
alone would see their lines without the line that opened the block). The
zero value is outside any block.
*/
type Stream struct{ mode int }

/* Secrets masks the next piece of whole lines (its final line break is not a line of its own). */
func (s *Stream) Secrets(text string) string {
	text, nl := strings.CutSuffix(text, "\n")
	opener := [...]string{outside: "", inPEM: "-----BEGIN STREAM-----", inImport: "crypto certificate stream import"}[s.mode]
	s.mode = endMode(s.mode, text)
	out := Secrets(text)
	if opener != "" {
		_, out, _ = strings.Cut(Secrets(opener+"\n"+text), "\n")
	}
	if nl {
		out += "\n"
	}
	return out
}

/* endMode is the block state after text, from mode (the transitions of pass). */
func endMode(mode int, text string) int {
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case mode == inPEM:
			if strings.HasPrefix(t, "-----END ") {
				mode = outside
			}
		case mode == inImport:
			if t == "." || t == "!" || t == "exit" || t == "end" {
				mode = outside
			}
		case strings.HasPrefix(t, "-----BEGIN ") && !strings.Contains(t, "-----END "):
			mode = inPEM
		case certRe.MatchString(line):
			mode = inImport
		}
	}
	return mode
}
