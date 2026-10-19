package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestHashVerify(t *testing.T) {
	phc, err := HashPassword("correct horse battery", DefaultArgon2)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(phc, "$argon2id$v=19$m=65536,t=3,p=1$") {
		t.Fatalf("bad PHC prefix: %s", phc)
	}
	ok, rehash, err := VerifyPassword("correct horse battery", phc)
	if err != nil || !ok || rehash {
		t.Fatalf("verify: %v %v %v", ok, rehash, err)
	}
	ok, _, err = VerifyPassword("wrong", phc)
	if err != nil || ok {
		t.Fatalf("wrong password: %v %v", ok, err)
	}
	if _, _, err := VerifyPassword("x", "garbage"); err == nil {
		t.Fatal("malformed PHC must error")
	}
}

func TestNeedsRehash(t *testing.T) {
	p := DefaultArgon2
	p.Time = 2
	phc, err := HashPassword("correct horse battery", p)
	if err != nil {
		t.Fatal(err)
	}
	ok, rehash, err := VerifyPassword("correct horse battery", phc)
	if err != nil || !ok || !rehash {
		t.Fatalf("got %v %v %v", ok, rehash, err)
	}
}

func TestValidateNewPassword(t *testing.T) {
	if err := ValidateNewPassword("short"); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("short: %v", err)
	}
	if err := ValidateNewPassword("Password1234"); !errors.Is(err, ErrPasswordCompromised) {
		t.Fatalf("compromised: %v", err)
	}
	if err := ValidateNewPassword("  correct horse battery  "); err != nil {
		t.Fatalf("spaces significant: %v", err)
	}
}
