package seal

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
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
