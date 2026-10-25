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

/* authFamily words are keywords when a value token follows (snmp user "auth"/"priv", block lines "auth K"). */
var authFamily = map[string]bool{"auth": true, "priv": true, "privacy": true, "encryption": true}

/* authExcluded words after an authFamily word mean it is not a secret keyword ("auth login ..."). */
var authExcluded = map[string]bool{"login": true, "enable": true, "default": true, "none": true, "local": true, "radius": true, "tacacs": true, "ldap": true}

/* hostWords introduce the notification receiver of "snmp-server host" and its variants. */
var hostWords = map[string]bool{"host": true, "trap-host": true, "trap-hosts": true}

type scan struct {
	ts  []tok
	ctx bool
}

/* kwAt reports whether token i starts a secret value. */
func (s *scan) kwAt(i int) bool {
	t := s.ts[i].text
	if t == Mark || t == "" {
		return false
	}
	if !plainWord(t) {
		return hasKeywordSub(t) /* glued or disguised keyword: the token itself is masked too */
	}
	switch {
	case hasKeywordSub(t), pwForm(t):
		return true
	case authFamily[t]:
		return i+1 < len(s.ts) && !authExcluded[s.ts[i+1].text]
	case s.ctx && t == "authentication":
		return true
	}
	return false
}

/* pwForm: short password spellings (pw, pwd, pass, bind-pw, auth-pass). */
func pwForm(t string) bool {
	switch t {
	case "pw", "pwd", "pass":
		return true
	}
	for _, p := range []string{"-pw", "-pwd", "-pass"} {
		if strings.HasSuffix(t, p) {
			return true
		}
	}
	return strings.HasPrefix(t, "pw-") || strings.HasPrefix(t, "pass-")
}

/*
region masks from index j to the end of the line: the first token when first
is set, then every token except structural words (with their argument when it
is harmless). It returns the index of an auth/priv keyword that starts a new
value, or len(ts).
*/
func (s *scan) region(j int, first bool) int {
	n := len(s.ts)
	for k := j; k < n; k++ {
		t := &s.ts[k]
		if k == j && first {
			t.masked = true
			continue
		}
		if arg, ok := structural[t.text]; ok && !t.quoted && plainWord(t.text) {
			if arg > 0 && k+1 < n {
				a := s.ts[k+1]
				if (arg == 2 && isNumber(a.text)) || (arg == 1 && !a.quoted && plainWord(a.text) && !looksSecret(a.raw)) {
					k++
				}
			}
			continue
		}
		if plainWord(t.text) && authFamily[t.text] && s.kwAt(k) {
			return k
		}
		t.masked = true
	}
	return n
}

/* value handles the secret keyword at i and returns the index where scanning resumes. */
func (s *scan) value(i int) int {
	ts, n := s.ts, len(s.ts)
	kw := ts[i].text
	if !plainWord(kw) || strings.Contains(ts[i].raw, "=") {
		ts[i].masked = true
	}
	keyID := keyIDKeywords[kw]
	var cands []int
	idSeen, typeSeen := false, false
	j := i + 1
loop:
	for j < n {
		t := ts[j]
		switch {
		case t.quoted:
			break loop
		case qualifiers[t.text]:
			cands = append(cands, j)
		case t.text == "level" && j+1 < n && isNumber(ts[j+1].text):
			cands = append(cands, j, j+1)
			j++
		case keyID && !idSeen && isNumber(t.text) && len(t.text) <= 3:
			idSeen = true
			cands = append(cands, j)
		case isNumber(t.text) && len(t.text) == 1 && !typeSeen:
			typeSeen = true
			cands = append(cands, j)
		default:
			break loop
		}
		j++
	}
	maskCands := func() {
		for _, c := range cands {
			ts[c].masked = true
		}
	}
	if j >= n {
		if kw != "authentication" {
			maskCands() /* no value follows: what looked like a qualifier is the value */
		}
		return n
	}
	if _, ok := structural[ts[j].text]; ok && len(cands) > 0 && plainWord(ts[j].text) {
		maskCands()
		return s.region(j, false)
	}
	return s.region(j, true)
}

func maskLine(line string) string {
	ts := tokenize(line)
	if len(ts) == 0 {
		return line
	}
	n := len(ts)
	s := &scan{ts: ts}
	for _, t := range ts {
		if authContexts[t.text] {
			s.ctx = true
		}
	}

	/* snmp host variants: everything after the address, vrf, traps|informs and version is community or user. */
	end := n
	if strings.HasPrefix(ts[0].text, "snmp") && n > 2 {
		h := -1
		for _, c := range []int{1, 2} {
			if h < 0 && c < n && hostWords[ts[c].text] {
				h = c
			}
		}
		if h >= 0 {
			j := h + 1
			if j < n && ts[j].text == "ipv6" {
				j++
			}
			j++
		scanHost:
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
					break scanHost
				}
			}
			if j < n {
				end = j
				s.region(j, true)
			}
		}
	}
	for i := 0; i < end; {
		if s.kwAt(i) {
			i = s.value(i)
			continue
		}
		i++
	}

	/* Hash-looking tokens and, on lines with a secret-ish keyword, long secret-like tokens. */
	low := strings.ToLower(line)
	hint := hasKeywordSub(low) || strings.Contains(low, "md5") || strings.Contains(low, "sha")
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
