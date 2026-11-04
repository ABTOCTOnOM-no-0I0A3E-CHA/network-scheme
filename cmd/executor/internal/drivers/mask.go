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
  - a line starting with "encrypted" (MES 6.x: "encrypted radius-server host
    ... key ...") keeps only its first two words;
  - the token after "encrypted" (or an abbreviation of it) is masked;
  - an abbreviated secret keyword as an operator types it ("passw", "secr",
    "commu", "key-str") masks the rest of the line.

Over-masking is the safe side. Mask is idempotent.
*/
func Mask(text string) string {
	lines := strings.Split(mask.Secrets(text), "\n")
	for i, l := range lines {
		lines[i] = maskWords(urlInfoRe.ReplaceAllString(l, "${1}"+mask.Mark+"@"))
	}
	return strings.Join(lines, "\n")
}

var urlInfoRe = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^\s/@]*@`)

/* abbrevKeywords: an operator's abbreviation (4 letters or more, not ending a hyphen part) of one of them starts a secret. */
var abbrevKeywords = []string{"password", "secret", "community", "key-string", "pre-shared-key", "authpassword",
	"privpassword", "root-password", "passphrase", "authentication-key"}

func abbreviates(t string, kws ...string) bool {
	if len(t) < 4 {
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
	word := func(i int) string { return strings.ToLower(strings.Trim(l[fs[i].start:fs[i].end], `"'`)) }
	for i := range fs {
		w := word(i)
		switch {
		case i == 0 && isEncrypted(w):
			for k := 2; k < len(fs); k++ {
				masked[k] = true
			}
		case isEncrypted(w) && i+1 < len(fs):
			masked[i+1] = true
		case abbreviates(w, abbrevKeywords...):
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
