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
	in := File{Committed: rec(7, 1), Pending: &pend, PendingXID: 991, Frozen: true, FreezeReason: "x"}
	if err := Save(p, key, in); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p, key)
	if err != nil {
		t.Fatal(err)
	}
	if got.V != Version || !got.Committed.Equal(in.Committed) || !got.Pending.Equal(pend) || got.PendingXID != 991 || !got.Frozen || got.FreezeReason != "x" {
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

/* A pending record without its transaction id (or an id without a record) is refused. */
func TestPendingNeedsItsTransaction(t *testing.T) {
	key := &[32]byte{1}
	p := filepath.Join(t.TempDir(), "state")
	pend := rec(2, 2)
	for _, f := range []File{{Committed: rec(1, 1), Pending: &pend}, {Committed: rec(1, 1), PendingXID: 5}} {
		if err := Save(p, key, f); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p, key); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%+v: %v", f, err)
		}
	}
}

/* Sealed audit segments must be well formed, in order, apart and before the live base: anything else is an invalid file. */
func TestSealedSegmentsAreChecked(t *testing.T) {
	key := &[32]byte{1}
	p := filepath.Join(t.TempDir(), "state")
	h := func(id int64, b byte) AuditHead { return AuditHead{LastID: id, Hash: bytes.Repeat([]byte{b}, 32)} }
	base := h(20, 9)
	ok := File{Committed: rec(3, 1), AuditBase: &base, AuditSealed: []Segment{{h(0, 0), h(5, 1)}, {h(5, 2), h(10, 3)}}}
	if err := Save(p, key, ok); err != nil {
		t.Fatal(err)
	}
	if f, err := Load(p, key); err != nil || len(f.Chain().Sealed) != 2 || f.Chain().Base.LastID != 20 {
		t.Fatalf("valid segments: %+v %v", f, err)
	}
	many := make([]Segment, MaxSealed+1)
	for i := range many {
		many[i] = Segment{h(int64(i), 0), h(int64(i)+1, 1)}
	}
	big := h(int64(MaxSealed)+1, 9)
	for name, f := range map[string]File{
		"empty segment": {AuditBase: &base, AuditSealed: []Segment{{h(5, 0), h(5, 1)}}},
		"backward":      {AuditBase: &base, AuditSealed: []Segment{{h(6, 0), h(5, 1)}}},
		"overlapping":   {AuditBase: &base, AuditSealed: []Segment{{h(0, 0), h(8, 1)}, {h(5, 2), h(10, 3)}}},
		"past the base": {AuditBase: &base, AuditSealed: []Segment{{h(0, 0), h(21, 1)}}},
		"no base":       {AuditSealed: []Segment{{h(0, 0), h(1, 1)}}},
		"short hash":    {AuditBase: &base, AuditSealed: []Segment{{AuditHead{LastID: 0, Hash: []byte{1}}, h(1, 1)}}},
		"too many":      {AuditBase: &big, AuditSealed: many},
		"negative base": {AuditBase: &AuditHead{LastID: -1, Hash: make([]byte, 32)}},
	} {
		f.Committed = rec(3, 1)
		if err := Save(p, key, f); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p, key); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
