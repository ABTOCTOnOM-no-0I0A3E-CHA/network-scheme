package keys

import (
	"crypto/rand"
	"errors"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

/* A rotation bumps only the rotated domain's version and key; Published finds the new key at that version and not the old one. */
func TestRotateKeysJSON(t *testing.T) {
	var pubs = map[string][32]byte{}
	for _, d := range domains {
		k, err := NewDomainKey()
		if err != nil {
			t.Fatal(err)
		}
		pubs[d] = k.Public
	}
	doc, err := BuildKeysJSON(pubs)
	if err != nil {
		t.Fatal(err)
	}
	next, err := NewDomainKey()
	if err != nil {
		t.Fatal(err)
	}
	out, v, err := Rotate(doc, "read", next.Public)
	if err != nil || v != 2 {
		t.Fatalf("rotate: %d %v", v, err)
	}
	if Published(out, "read", next.Public) != 2 || Published(out, "read", pubs["read"]) != 0 || Published(out, "write", pubs["write"]) != 1 {
		t.Fatalf("published: %s", out)
	}
	if again, v, err := Rotate(out, "read", pubs["read"]); err != nil || v != 3 || Published(again, "read", pubs["read"]) != 3 {
		t.Fatalf("second rotation: %d %v", v, err)
	}
	for _, bad := range []string{`{}`, `{"version":2,"domains":{}}`, `{"version":1,"domains":{"read":{"key_version":1}},"x":1}`} {
		if _, _, err := Rotate([]byte(bad), "read", next.Public); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

/* Reseal moves a sealed box from one key to another unchanged; a box of another key is refused. */
func TestReseal(t *testing.T) {
	old, _ := NewDomainKey()
	next, _ := NewDomainKey()
	ct, err := box.SealAnonymous(nil, []byte("secret"), &old.Public, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nct, err := Reseal(ct, &old.Private, &next.Public)
	if err != nil {
		t.Fatal(err)
	}
	if pt, ok := box.OpenAnonymous(nil, nct, &next.Public, &next.Private); !ok || string(pt) != "secret" {
		t.Fatalf("re-sealed box: %q %v", pt, ok)
	}
	if _, ok := box.OpenAnonymous(nil, nct, &old.Public, &old.Private); ok {
		t.Fatal("the re-sealed box opens under the retired key")
	}
	if _, err := Reseal(nct, &old.Private, &next.Public); !errors.Is(err, ErrNotSealedToKey) {
		t.Fatalf("a box of another key: %v", err)
	}
}
