package seal

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func master(b byte) *[32]byte {
	var m [32]byte
	for i := range m {
		m[i] = b + byte(i)
	}
	return &m
}

/* Subkeys are pairwise distinct, differ from the master, and are the same for the same master. */
func TestDeriveDistinctAndDeterministic(t *testing.T) {
	m := master(1)
	a, err := Derive(m)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Derive(m)
	if err != nil {
		t.Fatal(err)
	}
	subs := [][]byte{a.Enc()[:], a.MAC()[:], a.State()[:], m[:]}
	for i := range subs {
		for j := i + 1; j < len(subs); j++ {
			if bytes.Equal(subs[i], subs[j]) {
				t.Fatalf("keys %d and %d are equal", i, j)
			}
		}
	}
	if *a != *b {
		t.Fatal("derivation is not deterministic")
	}
	c, err := Derive(master(2))
	if err != nil {
		t.Fatal(err)
	}
	if *c.MAC() == *a.MAC() || *c.State() == *a.State() || *c.Enc() == *a.Enc() {
		t.Fatal("another master gives the same subkeys")
	}
}

/* The labels are pinned: changing one would silently invalidate every MAC and state file. */
const deriveVector = "7eda6a669fa9978cce538070"

func TestDeriveVector(t *testing.T) {
	k, err := Derive(new([32]byte))
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(k.MAC()[:4]) + hex.EncodeToString(k.State()[:4]) + hex.EncodeToString(k.Enc()[:4])
	if got != deriveVector {
		t.Fatalf("vector = %s, want %s", got, deriveVector)
	}
}

func TestWipeZeroesAndLoadWipesMaster(t *testing.T) {
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, master(7)[:], 0o600); err != nil {
		t.Fatal(err)
	}
	k, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := Derive(master(7))
	if *k != *want {
		t.Fatal("Load differs from Derive")
	}
	k.Wipe()
	if *k != (Keys{}) {
		t.Fatal("Wipe left key bytes")
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing key file accepted")
	}
}

/* Keys never render their bytes through fmt or slog. */
func TestKeysAreMasked(t *testing.T) {
	k, err := Derive(master(3))
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	slog.New(slog.NewTextHandler(&b, nil)).Info("x", slog.Any("keys", k))
	for _, s := range []string{fmt.Sprint(k), fmt.Sprintf("%v %+v %#v %s", k, k, k, k), b.String()} {
		if strings.Contains(s, hex.EncodeToString(k.MAC()[:4])) || strings.Contains(s, "["+fmt.Sprint(k.Enc()[0])) {
			t.Fatalf("leak: %s", s)
		}
		if !strings.Contains(s, "***") {
			t.Fatalf("not masked: %s", s)
		}
	}
}

/* C2g primitive: a sealed change TOTP secret opens only for its user and key version, and not under another sealing key. */
func TestTOTPSealIsBoundToTheUser(t *testing.T) {
	k, _ := Derive(master(1))
	other, _ := Derive(master(2))
	secret := []byte("12345678901234567890")
	ct, err := k.SealTOTP(5, KeyVersion, secret)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := k.OpenTOTP(5, KeyVersion, ct)
	if err != nil || !bytes.Equal(pt, secret) {
		t.Fatalf("open: %q %v", pt, err)
	}
	ct2, _ := k.SealTOTP(5, KeyVersion, secret)
	if bytes.Equal(ct, ct2) {
		t.Fatal("nonce reused")
	}
	for name, open := range map[string]func() ([]byte, error){
		"other user":        func() ([]byte, error) { return k.OpenTOTP(6, KeyVersion, ct) },
		"other key version": func() ([]byte, error) { return k.OpenTOTP(5, KeyVersion+1, ct) },
		"other sealing key": func() ([]byte, error) { return other.OpenTOTP(5, KeyVersion, ct) },
		"flipped bit": func() ([]byte, error) {
			bad := bytes.Clone(ct)
			bad[len(bad)-1] ^= 1
			return k.OpenTOTP(5, KeyVersion, bad)
		},
		"truncated": func() ([]byte, error) { return k.OpenTOTP(5, KeyVersion, ct[:10]) },
	} {
		if pt, err := open(); err == nil {
			t.Errorf("%s: opened %q", name, pt)
		}
	}
}
