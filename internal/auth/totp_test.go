package auth

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func TestTOTPWindowAndReplay(t *testing.T) {
	sec, uri, err := NewTOTPSecret("NMS", "alice")
	if err != nil || sec.IsZero() || uri == "" {
		t.Fatalf("new: %v", err)
	}
	now := time.Unix(1_700_000_000, 0)
	step := now.Unix() / 30
	code := func(s int64) string {
		c, err := totp.GenerateCodeCustom(sec.Reveal(), time.Unix(s*30, 0), totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	for _, d := range []int64{0, -1, 1} {
		if got, ok := ValidateTOTP(code(step+d), sec, 0, now); !ok || got != step+d {
			t.Fatalf("delta %d: %d %v", d, got, ok)
		}
	}
	for _, d := range []int64{-2, 2} {
		if _, ok := ValidateTOTP(code(step+d), sec, 0, now); ok {
			t.Fatalf("delta %d must fail", d)
		}
	}
	if _, ok := ValidateTOTP(code(step), sec, step, now); ok {
		t.Fatal("replay must fail")
	}
	if _, ok := ValidateTOTP("abc", sec, 0, now); ok {
		t.Fatal("garbage must fail")
	}
}

func TestBackupCodes(t *testing.T) {
	codes, hashes := GenerateBackupCodes()
	if len(codes) != 10 || len(hashes) != 10 {
		t.Fatal("want 10")
	}
	seen := map[string]bool{}
	for i, c := range codes {
		if len(c) != 16 || seen[c] {
			t.Fatalf("bad code %q", c)
		}
		seen[c] = true
		h := sha256.Sum256([]byte(c))
		if string(hashes[i]) != string(h[:]) {
			t.Fatal("hash mismatch")
		}
	}
}
