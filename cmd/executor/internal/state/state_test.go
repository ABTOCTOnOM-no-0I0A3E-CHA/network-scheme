package state

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func rec(hwm int64, b byte) Record {
	return Record{HWM: hwm, StateHash: bytes.Repeat([]byte{b}, 32), AuditHead: AuditHead{Hash: make([]byte, 32)}}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	key := &[32]byte{1}
	p := filepath.Join(t.TempDir(), "state")
	if _, err := Load(p, key); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	pend := rec(8, 2)
	in := File{Committed: rec(7, 1), Pending: &pend, Frozen: true, FreezeReason: "x"}
	if err := Save(p, key, in); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p, key)
	if err != nil {
		t.Fatal(err)
	}
	if got.V != Version || !got.Committed.Equal(in.Committed) || !got.Pending.Equal(pend) || !got.Frozen || got.FreezeReason != "x" {
		t.Fatalf("got %+v", got)
	}
	if ents, _ := os.ReadDir(filepath.Dir(p)); len(ents) != 1 {
		t.Fatalf("temporary files left: %v", ents)
	}
}

/* Another key (another install), a flipped byte, another version or a malformed body: ErrInvalid. */
func TestLoadRefusesForeignOrTampered(t *testing.T) {
	key := &[32]byte{1}
	p := filepath.Join(t.TempDir(), "state")
	if err := Save(p, key, File{Committed: rec(3, 1)}); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p, &[32]byte{2}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("foreign key: %v", err)
	}
	good, _ := os.ReadFile(p)
	write := func(b []byte) {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, b := range map[string][]byte{
		"flipped": bytes.Replace(good, []byte(`"hwm":3`), []byte(`"hwm":4`), 1),
		"no mac":  good[bytes.IndexByte(good, '\n')+1:],
		"empty":   {},
	} {
		write(b)
		if _, err := Load(p, key); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	/* Validly MACed but of another version, with a short hash, or with extra fields. */
	for name, body := range map[string]string{
		"version":    `{"v":2,"committed":{"hwm":1,"state_hash":"` + b64(32) + `","audit_head":{"last_id":0,"hash":"` + b64(32) + `"}},"pending":null,"frozen":false,"freeze_reason":""}`,
		"short hash": `{"v":1,"committed":{"hwm":1,"state_hash":"` + b64(31) + `","audit_head":{"last_id":0,"hash":"` + b64(32) + `"}},"pending":null,"frozen":false,"freeze_reason":""}`,
		"unknown":    `{"v":1,"x":1,"committed":{"hwm":1,"state_hash":"` + b64(32) + `","audit_head":{"last_id":0,"hash":"` + b64(32) + `"}},"pending":null,"frozen":false,"freeze_reason":""}`,
	} {
		write(append([]byte(hexMAC(key, body)+"\n"), body...))
		if _, err := Load(p, key); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func b64(n int) string { return base64.StdEncoding.EncodeToString(make([]byte, n)) }

func hexMAC(key *[32]byte, body string) string { return hex.EncodeToString(mac(key, []byte(body))) }

func TestReasonIsBoundedUTF8(t *testing.T) {
	r := Reason(strings.Repeat("ж", MaxReason) + "\xff")
	if len(r) > MaxReason || !utf8.ValidString(r) {
		t.Fatalf("len %d valid %v", len(r), utf8.ValidString(r))
	}
	if Reason("a\xffb") != "a?b" {
		t.Fatal("invalid UTF-8 kept")
	}
}
