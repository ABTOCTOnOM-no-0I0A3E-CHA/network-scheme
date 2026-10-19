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

func TestVerifyMalformedPHC(t *testing.T) {
	cases := map[string]string{
		"t=0":          "$argon2id$v=19$m=65536,t=0,p=1$c2FsdA$aGFzaA",
		"p=0":          "$argon2id$v=19$m=65536,t=3,p=0$c2FsdA$aGFzaA",
		"p>255":        "$argon2id$v=19$m=65536,t=3,p=256$c2FsdA$aGFzaA",
		"m too small":  "$argon2id$v=19$m=7,t=3,p=1$c2FsdA$aGFzaA",
		"m above cap":  "$argon2id$v=19$m=1048577,t=3,p=1$c2FsdA$aGFzaA",
		"t above cap":  "$argon2id$v=19$m=65536,t=21,p=1$c2FsdA$aGFzaA",
		"bad version":  "$argon2id$v=18$m=65536,t=3,p=1$c2FsdA$aGFzaA",
		"version junk": "$argon2id$v=19x$m=65536,t=3,p=1$c2FsdA$aGFzaA",
		"trailing":     "$argon2id$v=19$m=65536,t=3,p=1junk$c2FsdA$aGFzaA",
		"wrong order":  "$argon2id$v=19$t=3,m=65536,p=1$c2FsdA$aGFzaA",
		"extra param":  "$argon2id$v=19$m=65536,t=3,p=1,x=1$c2FsdA$aGFzaA",
		"bad salt b64": "$argon2id$v=19$m=65536,t=3,p=1$!!!$aGFzaA",
		"bad hash b64": "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$!!!",
		"empty salt":   "$argon2id$v=19$m=65536,t=3,p=1$$aGFzaA",
		"missing hash": "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA",
		"wrong alg":    "$argon2i$v=19$m=65536,t=3,p=1$c2FsdA$aGFzaA",
		"empty":        "",
	}
	for name, phc := range cases {
		t.Run(name, func(t *testing.T) {
			ok, rehash, err := VerifyPassword("pw", phc)
			if err == nil || ok || rehash {
				t.Fatalf("want error, got ok=%v rehash=%v err=%v", ok, rehash, err)
			}
		})
	}
}
