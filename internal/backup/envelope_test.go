package backup_test

import (
	"bytes"
	"crypto/rand"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"

	"github.com/beekamai/network-scheme/internal/backup"
	"github.com/beekamai/network-scheme/internal/backup/open"
)

func keys(t *testing.T) (pub, priv *[32]byte) {
	t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestSealOpenRoundTrip(t *testing.T) {
	pub, priv := keys(t)
	want := []byte("hostname sw1\nusername admin password Sup3rSecret\n")
	aad := backup.AAD(7, "ab12")
	pt := bytes.Clone(want)
	ct, dekCT, err := backup.Seal(pub, pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, make([]byte, len(pt))) {
		t.Error("plaintext buffer was not wiped")
	}
	if bytes.Contains(ct, []byte("Sup3rSecret")) || bytes.Contains(dekCT, []byte("Sup3rSecret")) {
		t.Fatal("secret visible in ciphertext")
	}
	got, err := open.Open(priv, pub, ct, dekCT, aad)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("Open = %q, %v", got, err)
	}
	/* Two seals of one text differ (random key and nonce). */
	ct2, dek2, _ := backup.Seal(pub, bytes.Clone(want), aad)
	if bytes.Equal(ct, ct2) || bytes.Equal(dekCT, dek2) {
		t.Error("sealing is deterministic")
	}
}

func TestOpenFailures(t *testing.T) {
	pub, priv := keys(t)
	otherPub, otherPriv := keys(t)
	ct, dekCT, err := backup.Seal(pub, []byte("config"), backup.AAD(1, "aa"))
	if err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]func() error{
		"wrong private key": func() error { _, err := open.Open(otherPriv, otherPub, ct, dekCT, backup.AAD(1, "aa")); return err },
		"public key only":   func() error { _, err := open.Open(pub, pub, ct, dekCT, backup.AAD(1, "aa")); return err },
		"other device":      func() error { _, err := open.Open(priv, pub, ct, dekCT, backup.AAD(2, "aa")); return err },
		"other sha":         func() error { _, err := open.Open(priv, pub, ct, dekCT, backup.AAD(1, "bb")); return err },
		"no aad":            func() error { _, err := open.Open(priv, pub, ct, dekCT, nil); return err },
		"short":             func() error { _, err := open.Open(priv, pub, ct[:10], dekCT, backup.AAD(1, "aa")); return err },
		"tampered": func() error {
			c := bytes.Clone(ct)
			c[len(c)-1] ^= 1
			_, err := open.Open(priv, pub, c, dekCT, backup.AAD(1, "aa"))
			return err
		},
	} {
		if f() == nil {
			t.Errorf("%s: opened", name)
		}
	}
	/* A data key from another version does not open this ciphertext. */
	_, dek2, _ := backup.Seal(pub, []byte("x"), backup.AAD(1, "aa"))
	if _, err := open.Open(priv, pub, ct, dek2, backup.AAD(1, "aa")); err == nil {
		t.Error("foreign data key opened the ciphertext")
	}
}

/* The opening package, which needs the private key, is linked into no service but the executor. */
func TestOpenNotLinkedIntoServices(t *testing.T) {
	for _, cmd := range []string{"poller", "api", "eventd", "nmsctl"} {
		out, err := exec.Command("go", "list", "-deps", "github.com/beekamai/network-scheme/cmd/"+cmd).CombinedOutput()
		if err != nil {
			t.Fatalf("go list %s: %v\n%s", cmd, err, out)
		}
		if strings.Contains(string(out), "internal/backup/open") {
			t.Errorf("cmd/%s depends on internal/backup/open", cmd)
		}
	}
}
