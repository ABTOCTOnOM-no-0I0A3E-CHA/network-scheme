package drivers

import (
	"regexp"
	"strings"

	"github.com/beekamai/network-scheme/internal/drivers/mask"
)

/*
Mask removes secrets from session input and output before anything is
recorded [R §7], for every firmware line (the "always" variant of [R §9.14]:
every encrypted form is masked, never only the clear text). It runs the read
drivers' mask.Secrets (values after secret keywords, encrypted and hashed
forms, PEM and "crypto ... import" blocks) and then:
  - userinfo in a URL ("sftp://user:pass@host") becomes "***@";
  - a secret-bearing command (families: username, enable, radius-server,
    snmp, encrypted, ...; also abbreviated) keeps only its first words;
  - an abbreviation of ascii-text or hexadecimal masks the rest of the line;
  - the token after "encrypted" (or an abbreviation of it) is masked;
  - an abbreviated secret keyword as an operator types it ("pas", "sec",
    "com", "key-str") masks the rest of the line.

Over-masking is the safe side. Mask is idempotent.
*/
func Mask(text string) string {
	lines := strings.Split(mask.Secrets(text), "\n")
	for i, l := range lines {
		lines[i] = maskWords(urlInfoRe.ReplaceAllString(l, "${1}"+mask.Mark+"@"))
	}
	return strings.Join(lines, "\n")
}

/* urlInfoRe: the userinfo runs to the last '@' before a space or '/' (a password may hold '@'). */
var urlInfoRe = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^\s/]*@`)

/* abbrevKeywords: an operator's abbreviation (3 letters or more, not ending a hyphen part) of one of them starts a secret. */
var abbrevKeywords = []string{"password", "secret", "community", "key-string", "pre-shared-key", "authpassword",
	"privpassword", "root-password", "passphrase", "authentication-key"}

func abbreviates(t string, kws ...string) bool {
	if len(t) < 3 {
		return false
	}
	for _, k := range kws {
		if len(t) < len(k) && strings.HasPrefix(k, t) && k[len(t)] != '-' {
			return true
		}
	}
	return false
}

func isEncrypted(t string) bool { return t == "encrypted" || abbreviates(t, "encrypted") }

/* field is a space-separated word of a line and where it is. */
type field struct{ start, end int }

func fields(l string) []field {
	var out []field
	for i := 0; i < len(l); {
		for i < len(l) && (l[i] == ' ' || l[i] == '\t') {
			i++
		}
		j := i
		for j < len(l) && l[j] != ' ' && l[j] != '\t' {
			j++
		}
		if j > i {
			out = append(out, field{i, j})
		}
		i = j
	}
	return out
}

func maskWords(l string) string {
	fs := fields(l)
	masked := make([]bool, len(fs))
	ws := make([]string, len(fs))
	for i, f := range fs {
		ws[i] = strings.ToLower(strings.Trim(l[f.start:f.end], `"'`))
	}
	for k := familyKeep(ws); k < len(fs); k++ {
		masked[k] = true
	}
	for i, w := range ws {
		switch {
		case isEncrypted(w) && i+1 < len(fs):
			masked[i+1] = true
		case abbreviates(w, abbrevKeywords...), len(w) >= 3 && (strings.HasPrefix("ascii-text", w) || strings.HasPrefix("hexadecimal", w)):
			for k := i + 1; k < len(fs); k++ {
				masked[k] = true
			}
		}
	}
	var b strings.Builder
	prev := 0
	for i, f := range fs {
		if !masked[i] || l[f.start:f.end] == mask.Mark {
			continue
		}
		b.WriteString(l[prev:f.start])
		b.WriteString(mask.Mark)
		prev = f.end
	}
	b.WriteString(l[prev:])
	return b.String()
}

/*
family is a secret-bearing command: its first words (each also as an
abbreviation of 2 letters or more, "key" also as the start of a word:
key-string, key-chain) and how many words stay; everything after them is
masked [R §7]. The first word may follow "no" or "do".
*/
type family struct {
	words []string
	keep  int
}

var families = []family{
	{[]string{"username"}, 2}, {[]string{"enable"}, 1}, {[]string{"radius-server"}, 1}, {[]string{"tacacs-server"}, 1},
	{[]string{"snmp-server"}, 1}, {[]string{"snmp"}, 1}, {[]string{"aaa"}, 1}, {[]string{"encrypted"}, 2},
	{[]string{"crypto"}, 2}, {[]string{"key"}, 1}, {[]string{"line"}, 2},
	{[]string{"ip", "ssh-client"}, 2}, {[]string{"ip", "ssh", "client"}, 3},
	{[]string{"ip", "ftp", "client"}, 3}, {[]string{"ip", "sftp", "client"}, 3},
}

/* famWord: t is w or an abbreviation of it (2 letters or more); for "key" also any word starting with it. */
func famWord(t, w string) bool {
	return t == w || len(t) >= 2 && strings.HasPrefix(w, t) || w == "key" && strings.HasPrefix(t, "key")
}

/* familyKeep returns the index from which a secret-bearing command's line is masked (len(ws): none). */
func familyKeep(ws []string) int {
	off := 0
	for off < len(ws)-1 && (ws[off] == "no" || ws[off] == "do") {
		off++
	}
	best := len(ws)
next:
	for _, f := range families {
		if off+len(f.words) > len(ws) {
			continue
		}
		for i, w := range f.words {
			if !famWord(ws[off+i], w) {
				continue next
			}
		}
		best = min(best, off+f.keep)
	}
	return best
}
