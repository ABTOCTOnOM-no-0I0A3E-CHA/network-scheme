package keys

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestDomainKeySealOpen(t *testing.T) {
	k, err := NewDomainKey()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := box.SealAnonymous(nil, []byte("secret"), &k.Public, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	out, ok := box.OpenAnonymous(nil, sealed, &k.Public, &k.Private)
	if !ok || string(out) != "secret" {
		t.Fatal("open failed")
	}
}

func TestKeysJSONHasNoPrivate(t *testing.T) {
	pubs := map[string][32]byte{}
	var privs []DomainKey
	for _, d := range []string{"read", "write", "backup"} {
		k, err := NewDomainKey()
		if err != nil {
			t.Fatal(err)
		}
		pubs[d] = k.Public
		privs = append(privs, k)
	}
	b, err := BuildKeysJSON(pubs)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range privs {
		if strings.Contains(string(b), base64.StdEncoding.EncodeToString(k.Private[:])) {
			t.Fatal("private key leaked")
		}
	}
	var kj KeysJSON
	if err := json.Unmarshal(b, &kj); err != nil {
		t.Fatal(err)
	}
	if kj.Version != 1 || len(kj.Domains) != 3 {
		t.Fatalf("bad doc: %+v", kj)
	}
	for _, d := range []string{"read", "write", "backup"} {
		pd, ok := kj.Domains[d]
		if !ok || pd.KeyVersion != 1 || pd.Fingerprint != Fingerprint(pubs[d]) {
			t.Fatalf("bad domain %s: %+v", d, pd)
		}
	}
	b2, _ := BuildKeysJSON(pubs)
	if string(b) != string(b2) {
		t.Fatal("not deterministic")
	}
}

func TestBuildKeysJSONValidation(t *testing.T) {
	k, _ := NewDomainKey()
	cases := map[string]map[string][32]byte{
		"missing": {"read": k.Public, "write": k.Public},
		"extra":   {"read": k.Public, "write": k.Public, "backup": k.Public, "x": k.Public},
		"zero":    {"read": k.Public, "write": k.Public, "backup": {}},
	}
	for name, m := range cases {
		if _, err := BuildKeysJSON(m); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestFingerprintFormat(t *testing.T) {
	fp := Fingerprint([32]byte{1, 2, 3})
	if !regexp.MustCompile(`^([0-9a-f]{4}:){7}[0-9a-f]{4}$`).MatchString(fp) {
		t.Fatalf("bad format %q", fp)
	}
	if fp != Fingerprint([32]byte{1, 2, 3}) || fp == Fingerprint([32]byte{4}) {
		t.Fatal("not stable/unique")
	}
}

func TestNewSymmetricKey(t *testing.T) {
	a, err := NewSymmetricKey()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewSymmetricKey()
	if a == b || a == ([32]byte{}) {
		t.Fatal("bad key")
	}
}
