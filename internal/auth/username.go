package auth

import (
	"errors"
	"regexp"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// ErrBadUsername is returned for a username outside the allowed form.
var ErrBadUsername = errors.New("auth: invalid username")

var usernameRe = regexp.MustCompile(`^[\p{Ll}\p{Nd}._-]{3,64}$`)

/*
NormalizeUsername trims s, applies NFC and lower-cases it, so that names
differing only in case or Unicode composition map to one account. The result
must be 3-64 lower-case letters, digits, '.', '_' or '-'.
*/
func NormalizeUsername(s string) (string, error) {
	n := strings.ToLower(norm.NFC.String(strings.TrimSpace(s)))
	if !usernameRe.MatchString(n) {
		return "", ErrBadUsername
	}
	return n, nil
}
