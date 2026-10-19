package crypto

import (
	"bytes"
	"testing"
)

func TestAEADRoundTripAndAADBinding(t *testing.T) {
	var key [32]byte
	key[0] = 1
	box, err := Seal(&key, []byte("hello"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Open(&key, box, []byte("aad"))
	if err != nil || !bytes.Equal(pt, []byte("hello")) {
		t.Fatalf("round trip: %q %v", pt, err)
	}
	if _, err := Open(&key, box, []byte("other")); err == nil {
		t.Fatal("different aad must fail")
	}
	box[len(box)-1] ^= 1
	if _, err := Open(&key, box, []byte("aad")); err == nil {
		t.Fatal("tampered box must fail")
	}
	if _, err := Open(&key, []byte("x"), nil); err == nil {
		t.Fatal("short box must fail")
	}
}
