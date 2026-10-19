// Package auth implements password, TOTP and backup-code primitives.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

/* Password validation errors. */
var (
	ErrPasswordTooShort    = errors.New("auth: password shorter than 12 characters")
	ErrPasswordCompromised = errors.New("auth: password is in the compromised list")
	errBadPHC              = errors.New("auth: malformed password hash")
)

const minPasswordRunes = 12

/* Argon2Params are the Argon2id cost parameters (Memory in KiB). */
type Argon2Params struct {
	Memory, Time uint32
	Threads      uint8
	KeyLen       uint32
	SaltLen      uint32
}

/* DefaultArgon2 is the production parameter set. */
var DefaultArgon2 = Argon2Params{Memory: 65536, Time: 3, Threads: 1, KeyLen: 32, SaltLen: 16}

var b64 = base64.RawStdEncoding

/* HashPassword returns a PHC-encoded Argon2id hash with a fresh random salt. */
func HashPassword(pw string, p Argon2Params) (string, error) {
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

/*
VerifyPassword checks pw against a PHC hash in constant time. needsRehash is
true when the stored parameters differ from DefaultArgon2.
*/
func VerifyPassword(pw, phc string) (ok, needsRehash bool, err error) {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return false, false, errBadPHC
	}
	var ver int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &ver); err != nil || ver != argon2.Version {
		return false, false, errBadPHC
	}
	var p Argon2Params
	var th uint32
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &th); err != nil || th == 0 || th > 255 {
		return false, false, errBadPHC
	}
	p.Threads = uint8(th)
	salt, err1 := b64.DecodeString(parts[4])
	want, err2 := b64.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(salt) == 0 || len(want) == 0 {
		return false, false, errBadPHC
	}
	/* Bound attacker-influenced cost from a corrupted/forged hash. */
	if p.Memory > 1<<20 || p.Time > 20 {
		return false, false, errBadPHC
	}
	p.KeyLen, p.SaltLen = uint32(len(want)), uint32(len(salt)) //nolint:gosec // decoded slice lengths
	got := argon2.IDKey([]byte(pw), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	ok = subtle.ConstantTimeCompare(got, want) == 1
	return ok, ok && p != DefaultArgon2, nil
}

/*
ValidateNewPassword enforces length (in runes) and the compromised list.
The password is neither trimmed nor normalized.
*/
func ValidateNewPassword(pw string) error {
	if utf8.RuneCountInString(pw) < minPasswordRunes {
		return ErrPasswordTooShort
	}
	if isCompromised(pw) {
		return ErrPasswordCompromised
	}
	return nil
}
