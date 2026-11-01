package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

/*
A sealed file opens only with its key and its label, and is neither a state
file nor the other way round: valid JSON re-MACed with another key or under
another label is refused by the MAC, not by parsing.
*/
func TestSealedFileBinding(t *testing.T) {
	dir := t.TempDir()
	key, other := &[32]byte{1}, &[32]byte{2}
	path := filepath.Join(dir, "guards")
	body := []byte(`{"v":1,"users":[],"window":[]}`)
	if err := SaveSealed(path, key, "authz-guards", body); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSealed(path, key, "authz-guards", 1<<20)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("round trip: %q %v", got, err)
	}
	for name, p := range map[string]string{
		"other key":   save(t, dir, "k", func(p string) error { return SaveSealed(p, other, "authz-guards", body) }),
		"other label": save(t, dir, "l", func(p string) error { return SaveSealed(p, key, "authz-guardz", body) }),
		"state file":  save(t, dir, "s", func(p string) error { return Save(p, key, File{Committed: rec(1, 1)}) }),
	} {
		if _, err := LoadSealed(p, key, "authz-guards", 1<<20); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	/* And a sealed file is not a state file. */
	if _, err := Load(path, key); !errors.Is(err, ErrInvalid) {
		t.Errorf("sealed file as a state file: %v", err)
	}
	/* A file over the bound is refused before its MAC is computed. */
	if _, err := LoadSealed(path, key, "authz-guards", 10); !errors.Is(err, ErrInvalid) {
		t.Errorf("over the bound: %v", err)
	}
	/* The MAC is checked: an untouched body with a MAC over another body is refused. */
	h := sha256.Sum256(nil)
	raw, _ := os.ReadFile(path)
	_, b, _ := bytes.Cut(raw, []byte("\n"))
	forged := filepath.Join(dir, "forged")
	if err := os.WriteFile(forged, append(append([]byte(nil), []byte(hex.EncodeToString(h[:]))...), append([]byte("\n"), b...)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSealed(forged, key, "authz-guards", 1<<20); !errors.Is(err, ErrInvalid) {
		t.Errorf("forged MAC: %v", err)
	}
}

func save(t *testing.T, dir, name string, fn func(string) error) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := fn(p); err != nil {
		t.Fatal(err)
	}
	return p
}
