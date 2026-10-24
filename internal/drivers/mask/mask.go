/*
Package mask removes secrets from device configuration text. It is shared by
the read drivers: dialect-independent keyword rules plus a heuristic for
unknown lines. A masked value becomes "***", the structure of the line is
kept, and when in doubt the value is masked (over-masking is the safe side).
Secrets covers Eltex MES (RADLAN) and ESR syntax; both use the same rules.
*/
package mask

import (
	"regexp"
	"strings"
)

/* Mark replaces every masked value. */
const Mark = "***"

const maxPasses = 8

var (
	tokenRe  = regexp.MustCompile(`"[^"]*"|\S+`)
	hashRe   = regexp.MustCompile(`^\$[0-9][a-z0-9]*\$`)
	b64Re    = regexp.MustCompile(`^[A-Za-z0-9+/=_.$:-]+$`)
	hexRe    = regexp.MustCompile(`^[0-9A-Fa-f]+$`)
	certRe   = regexp.MustCompile(`(?i)^\s*crypto\s+(certificate|key)\s.*\bimport\b`)
	hintSubs = []string{"password", "secret", "key", "community", "hash", "md5", "sha", "psk", "token"}
)

/* keywords whose next value is a secret; suffix forms ("-key", ...) are matched in isKeyword. */
var (
	keywords = map[string]bool{
		"password": true, "passwd": true, "secret": true, "key": true, "community": true,
		"passphrase": true, "psk": true, "key-string": true, "token": true,
	}
	keywordSuffixes = []string{"-password", "-passwd", "-secret", "-key", "-community", "-passphrase", "-psk", "-token"}
	/* keyIDKeywords may be followed by a numeric key id before the secret. */
	keyIDKeywords = map[string]bool{"authentication-key": true, "message-digest-key": true, "trusted-key": true}
	/* qualifiers sit between a keyword and its value ("password encrypted <hash>"). */
	qualifiers = map[string]bool{
		"encrypted": true, "unencrypted": true, "plaintext": true, "ascii-text": true, "hexadecimal": true,
		"hex": true, "text": true, "md5": true, "sha": true, "sha1": true, "sha256": true, "sha384": true,
		"sha512": true, "des": true, "aes": true, "aes128": true, "aes192": true, "aes256": true, "3des": true,
		"clear": true, "cleartext": true,
	}
	/* stops are words that follow a value and are never the value themselves. */
	stops = map[string]bool{
		"privilege": true, "level": true, "role": true, "ro": true, "rw": true, "view": true,
		"address": true, "vrf": true, "group": true,
	}
	hexLens = map[int]bool{32: true, 40: true, 56: true, 64: true, 96: true, 128: true}
)

/*
Secrets returns text with secret values replaced by "***". It is idempotent:
it repeats until the text no longer changes.
*/
func Secrets(text string) string {
	for range maxPasses {
		next := pass(text)
		if next == text {
			return next
		}
		text = next
	}
	return text
}

func pass(text string) string {
	lines := strings.Split(text, "\n")
	out := make([]string, 0, len(lines))
	const (
		none = iota
		pem
		cert
	)
	mode, starred := none, false
	for _, line := range lines {
		t := strings.TrimSpace(line)
		switch mode {
		case pem:
			if strings.HasPrefix(t, "-----END ") {
				out = append(out, line)
				mode = none
			} else if !starred {
				out, starred = append(out, Mark), true
			}
			continue
		case cert:
			if t == "." || t == "!" || t == "exit" || t == "end" {
				out = append(out, line)
				mode = none
			} else if !starred {
				out, starred = append(out, Mark), true
			}
			continue
		}
		switch {
		case strings.HasPrefix(t, "-----BEGIN "):
			if strings.Contains(t, "-----END ") {
				out = append(out, Mark)
			} else {
				out, mode, starred = append(out, line), pem, false
			}
		case certRe.MatchString(line):
			out, mode, starred = append(out, maskLine(line)), cert, false
		default:
			out = append(out, maskLine(line))
		}
	}
	return strings.Join(out, "\n")
}

type tok struct {
	start, end int
	text       string /* without quotes, lower case */
	raw        string
	masked     bool
}

func maskLine(line string) string {
	spans := tokenRe.FindAllStringIndex(line, -1)
	if len(spans) == 0 {
		return line
	}
	ts := make([]tok, len(spans))
	for i, s := range spans {
		raw := line[s[0]:s[1]]
		ts[i] = tok{start: s[0], end: s[1], raw: raw, text: strings.ToLower(strings.Trim(raw, `"`))}
	}
	n := len(ts)
	snmp := ts[0].text == "snmp-server"
	if snmp && n > 3 && ts[1].text == "host" {
		j := 3
		for j < n && (ts[j].text == "traps" || ts[j].text == "informs") {
			j++
		}
		if j+1 < n && ts[j].text == "version" {
			j += 2
		}
		if j < n {
			ts[j].masked = true
		}
	}
	for i := range ts {
		t := ts[i].text
		switch {
		case t == Mark:
		case t == "encrypted":
			markValue(ts, i, false)
		case keyIDKeywords[t]:
			markValue(ts, i, true)
		case isKeyword(t), snmp && (t == "auth" || t == "priv" || t == "privacy"):
			markValue(ts, i, false)
		}
	}
	/* Hash-looking tokens and, on lines with a secret-ish keyword, long base64/hex tokens. */
	lower := strings.ToLower(line)
	hint := false
	for _, h := range hintSubs {
		if strings.Contains(lower, h) {
			hint = true
			break
		}
	}
	for i := range ts {
		raw := strings.Trim(ts[i].raw, `"`)
		switch {
		case hashRe.MatchString(raw), isDigest(raw):
			ts[i].masked = true
		case hint && looksSecret(raw):
			ts[i].masked = true
		case n == 1 && len(raw) >= 32 && looksSecret(raw):
			ts[i].masked = true
		}
	}
	var b strings.Builder
	prev := 0
	for _, t := range ts {
		if !t.masked {
			continue
		}
		b.WriteString(line[prev:t.start])
		b.WriteString(Mark)
		prev = t.end
	}
	b.WriteString(line[prev:])
	return b.String()
}

func isKeyword(t string) bool {
	if keywords[t] {
		return true
	}
	for _, s := range keywordSuffixes {
		if strings.HasSuffix(t, s) {
			return true
		}
	}
	return false
}

/* markValue masks the value that follows the keyword at i, skipping qualifiers and key ids. */
func markValue(ts []tok, i int, anyNumber bool) {
	n := len(ts)
	j := i + 1
	for j < n {
		t := ts[j].text
		switch {
		case qualifiers[t]:
			j++
			continue
		case t == "level" && j+2 < n:
			j += 2
			continue
		case isNumber(t) && j+1 < n && !stops[ts[j+1].text] && (anyNumber || len(t) == 1):
			j++
			continue
		}
		break
	}
	if j < n && !stops[ts[j].text] {
		ts[j].masked = true
	}
}

func isNumber(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isDigest(s string) bool { return hexLens[len(s)] && hexRe.MatchString(s) }

/* looksSecret: a long base64/hex/hash-like token that is not a plain hyphenated word. */
func looksSecret(s string) bool {
	if len(s) < 16 || !b64Re.MatchString(s) {
		return false
	}
	var digit, upper, lower, sym bool
	for i := range len(s) {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			digit = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= 'a' && c <= 'z':
			lower = true
		case c == '+' || c == '/' || c == '=' || c == '$':
			sym = true
		}
	}
	return digit || sym || (upper && lower)
}
