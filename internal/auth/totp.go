package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/beekamai/network-scheme/internal/secret"
)

const (
	totpPeriod  = 30
	backupCount = 10
	backupLen   = 16
)

/* NewTOTPSecret generates a TOTP secret (RFC 6238, SHA-1, 6 digits, 30 s) and its otpauth URI. */
func NewTOTPSecret(issuer, account string) (sec secret.Secret, otpauthURI string, err error) {
	k, err := totp.Generate(totp.GenerateOpts{
		Issuer: issuer, AccountName: account,
		Period: totpPeriod, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return secret.Secret{}, "", err
	}
	return secret.New(k.Secret()), k.URL(), nil
}

/*
ValidateTOTP accepts the current step and one step either side. ok is true only
when the matched step is greater than lastStep (replay protection). The code is
compared in constant time.
*/
func ValidateTOTP(code string, sec secret.Secret, lastStep int64, now time.Time) (step int64, ok bool) {
	cur := now.Unix() / totpPeriod
	opts := totp.ValidateOpts{Period: totpPeriod, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
	for _, d := range []int64{-1, 0, 1} {
		s := cur + d
		want, err := totp.GenerateCodeCustom(sec.Reveal(), time.Unix(s*totpPeriod, 0), opts)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(code), []byte(want)) == 1 && s > lastStep {
			return s, true
		}
	}
	return 0, false
}

/* GenerateBackupCodes returns 10 random 16-char base32 codes and their SHA-256 hashes. */
func GenerateBackupCodes() (codes []string, hashes [][]byte) {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	for i := 0; i < backupCount; i++ {
		b := make([]byte, 10) /* 80 bits -> exactly 16 base32 chars */
		if _, err := rand.Read(b); err != nil {
			panic("auth: entropy source failed: " + err.Error())
		}
		c := enc.EncodeToString(b)
		h := sha256.Sum256([]byte(c))
		codes, hashes = append(codes, c), append(hashes, h[:])
	}
	return codes, hashes
}
