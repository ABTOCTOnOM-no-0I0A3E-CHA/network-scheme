/*
Package mask removes secrets from device configuration text. It is shared by
the read drivers. Strategy: after a secret keyword every remaining token of
the line is masked, except a few known qualifiers that precede the value
("encrypted", "md5", ...) and a small set of structural words that follow it
("privilege 15", "ro", "auth-port 1812"). A masked value becomes "***" and the
structure of the line is kept. When in doubt the token is masked: over-masking
is the safe side. Secrets covers Eltex MES (RADLAN) and ESR syntax.
*/
package mask

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

/* Mark replaces every masked value. */
const Mark = "***"

const maxPasses = 8

var (
	hashRe = regexp.MustCompile(`^\$[0-9][a-z0-9]*\$`)
	hexRe  = regexp.MustCompile(`^[0-9A-Fa-f]+$`)
	certRe = regexp.MustCompile(`(?i)^\s*crypto\s+(certificate|key)\s.*\bimport\b`)
)

/* keywordSubstrings: a token containing one of them is a secret keyword (also password-hash, wpa-psk, community-group, ...). */
var keywordSubstrings = []string{"password", "passwd", "secret", "passphrase", "community", "psk", "token", "cipher", "hash", "key"}

var (
	/* keyIDKeywords may be followed by a numeric key id before the secret. */
	keyIDKeywords = map[string]bool{"authentication-key": true, "message-digest-key": true, "trusted-key": true, "key-id": true}
	/* contextKeywords are secret keywords only on lines of the listed protocols/commands. */
	authContexts = map[string]bool{"vrrp": true, "ospf": true, "ospfv3": true, "isis": true, "bgp": true, "rip": true, "ripng": true, "hsrp": true, "glbp": true, "eigrp": true, "ntp": true, "snmp-server": true}
	snmpKeywords = map[string]bool{"auth": true, "priv": true, "privacy": true, "encryption": true}
	/* qualifiers sit between a keyword and its value ("password encrypted <hash>") and are kept. */
	qualifiers = map[string]bool{
		"encrypted": true, "unencrypted": true, "plaintext": true, "ascii": true, "ascii-text": true, "hexadecimal": true,
		"hex": true, "text": true, "md5": true, "sha": true, "sha1": true, "sha256": true, "sha384": true,
		"sha512": true, "hmac-sha-256": true, "des": true, "aes": true, "aes128": true, "aes192": true, "aes256": true,
		"3des": true, "clear": true, "cleartext": true, "simple": true, "message-digest": true, "null": true, "algorithm": true,
	}
	/* structural words that may follow a value and are kept: 0 no argument, 1 any argument, 2 numeric argument. */
	structural = map[string]int{
		"ro": 0, "rw": 0, "privilege": 2, "role": 1, "view": 1, "group": 1, "vrf": 1, "filter": 1, "access-list": 1,
		"auth-port": 2, "acct-port": 2, "port": 2, "udp-port": 2, "timeout": 2, "retries": 2, "retransmit": 2, "priority": 2, "usage": 1,
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
	raw        string
	text       string /* unquoted, lower case */
	quoted     bool
	masked     bool
}

/* tokenize splits on Unicode space; a double-quoted token may contain spaces and backslash escapes. */
func tokenize(line string) []tok {
	var ts []tok
	for i := 0; i < len(line); {
		r, size := utf8.DecodeRuneInString(line[i:])
		if unicode.IsSpace(r) {
			i += size
			continue
		}
		start, quoted := i, r == '"'
		if quoted {
			i += size
			for i < len(line) {
				c := line[i]
				if c == '\\' && i+1 < len(line) {
					i += 2
					continue
				}
				i++
				if c == '"' {
					break
				}
			}
		} else {
			for i < len(line) {
				r, size = utf8.DecodeRuneInString(line[i:])
				if unicode.IsSpace(r) {
					break
				}
				i += size
			}
		}
		raw := line[start:i]
		ts = append(ts, tok{start: start, end: i, raw: raw, quoted: quoted, text: strings.ToLower(strings.Trim(raw, `"`))})
	}
	return ts
}

func hasKeywordSub(s string) bool {
	for _, k := range keywordSubstrings {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

/* plainWord: only lower-case letters and hyphens, so a mixed-case or digit-bearing value is never taken for a keyword. */
func plainWord(s string) bool {
	for i := range len(s) {
		if c := s[i]; c != '-' && (c < 'a' || c > 'z') {
			return false
		}
	}
	return s != ""
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] < 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

func maskLine(line string) string {
	ts := tokenize(line)
	if len(ts) == 0 {
		return line
	}
	n := len(ts)
	first := ts[0].text
	ctx := false
	for _, t := range ts {
		if authContexts[t.text] {
			ctx = true
		}
	}

	/* snmp-server host: everything after the address, vrf, traps|informs and version is community or user. */
	valueFrom := -1
	if first == "snmp-server" && n > 2 && ts[1].text == "host" {
		j := 2
		if ts[j].text == "ipv6" {
			j++
		}
		j++
		for j < n {
			switch ts[j].text {
			case "vrf":
				j += 2
			case "traps", "informs":
				j++
			case "version":
				j += 2
				if j < n && (ts[j].text == "auth" || ts[j].text == "noauth" || ts[j].text == "priv") {
					j++
				}
			default:
				valueFrom = j
				j = n
			}
		}
	}

	inValue, leading, keyID := false, false, false
	keep := 0 /* structural argument tokens still to keep: 0 none, else numeric flag below */
	keepNum := false
	for i := range ts {
		t := &ts[i]
		if valueFrom >= 0 && i == valueFrom {
			inValue, leading, keyID = true, true, false
		}
		if keep > 0 {
			keep--
			if !keepNum || isNumber(t.text) {
				continue
			}
		}
		kw := !t.quoted && isKeyword(t.text, first == "snmp-server", ctx)
		switch {
		case !inValue && kw:
			inValue, leading, keyID = true, true, keyIDKeywords[t.text]
			if strings.Contains(t.text, "=") || !isASCII(t.text) { /* key=value in one token, or a disguised keyword */
				t.masked = true
			}
		case !inValue:
			if !isASCII(t.text) && hasKeywordSub(t.text) {
				t.masked = true
			}
		case leading:
			switch {
			case t.text == "level" && i+1 < n && isNumber(ts[i+1].text):
				keep, keepNum = 1, true
			case qualifiers[t.text] && !t.quoted:
			case keyID && isNumber(t.text):
			default:
				t.masked, leading = true, false
			}
		default: /* value phase */
			if arg, ok := structural[t.text]; ok && !t.quoted {
				if arg > 0 {
					keep, keepNum = 1, arg == 2
				}
			} else if kw && plainWord(t.raw) {
				leading, keyID = true, keyIDKeywords[t.text]
			} else {
				t.masked = true
			}
		}
	}

	/* Hash-looking tokens and, on lines with a secret-ish keyword, long secret-like tokens. */
	hint := hasKeywordSub(strings.ToLower(line)) || strings.Contains(strings.ToLower(line), "md5") || strings.Contains(strings.ToLower(line), "sha")
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

func isKeyword(t string, snmp, ctx bool) bool {
	switch {
	case t == Mark:
		return false
	case hasKeywordSub(t):
		return true
	case snmp && snmpKeywords[t]:
		return true
	case ctx && t == "authentication":
		return true
	}
	return false
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

/* looksSecret: a long printable token with a digit, a symbol or mixed case; plain lower-case words are not. */
func looksSecret(s string) bool {
	if len(s) < 16 || !isASCII(s) || strings.Trim(s, "*") == "" {
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
		case c != '-' && c != '_' && c != '.':
			sym = true
		}
	}
	return digit || sym || (upper && lower)
}
