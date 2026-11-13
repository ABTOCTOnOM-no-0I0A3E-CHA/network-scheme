package sysbackup

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/beekamai/network-scheme/internal/secret"
)

var pass = secret.New("correct horse battery")

type hdr struct {
	name string
	typ  byte
	body string
}

func tarOf(t *testing.T, hs ...hdr) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, h := range hs {
		if err := tw.WriteHeader(&tar.Header{Name: h.name, Typeflag: h.typ, Mode: 0o600, Size: int64(len(h.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(h.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestKeysRoundTrip(t *testing.T) {
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "secrets"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "secrets", "k"), []byte("key"), 0o400); err != nil {
		t.Fatal(err)
	}
	var arc bytes.Buffer
	if err := WriteKeys(&arc, pass, src); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKeys(bytes.NewReader(arc.Bytes()), secret.New("another passphrase")); err == nil {
		t.Fatal("a wrong passphrase opened the keys archive")
	}
	es, err := ReadKeys(bytes.NewReader(arc.Bytes()), pass)
	if err != nil || len(es) != 2 || es[0].Name != "secrets" || !es[0].Dir || es[1].Name != "secrets/k" || string(es[1].Data) != "key" {
		t.Fatalf("%+v %v", es, err)
	}
	dst := filepath.Join(t.TempDir(), "etc")
	var owned []string
	if err := WriteEntries(dst, es, func(p string, _, _ int) error { owned = append(owned, p); return nil }); err != nil || len(owned) != 2 {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dst, "secrets", "k")); err != nil || string(b) != "key" {
		t.Fatal(err)
	}
	if err := WriteEntries(dst, es, func(string, int, int) error { return nil }); err == nil {
		t.Fatal("WriteEntries wrote over existing files")
	}
}

func TestReadKeysRefusesUnsafeEntries(t *testing.T) {
	for _, hs := range [][]hdr{
		{{"../x", tar.TypeReg, ""}},
		{{"/etc/x", tar.TypeReg, ""}},
		{{"a", tar.TypeSymlink, ""}},
		{{"d/x", tar.TypeReg, ""}},
		{{"x", tar.TypeReg, ""}, {"x", tar.TypeReg, ""}},
	} {
		rcpt, _ := age.NewScryptRecipient(pass.Reveal())
		var arc bytes.Buffer
		w, _ := age.Encrypt(&arc, rcpt)
		_, _ = w.Write(tarOf(t, hs...))
		_ = w.Close()
		if _, err := ReadKeys(&arc, pass); err == nil {
			t.Errorf("%v accepted", hs)
		}
	}
}

func TestCheckState(t *testing.T) {
	ok := `{"v":1,"committed":{"hwm":5},"pending":null}`
	if hwm, err := CheckState(tarOf(t, hdr{"executor/", tar.TypeDir, ""}, hdr{"executor/state", tar.TypeReg, "ab\n" + ok}, hdr{"executor/initialized", tar.TypeReg, ""})); err != nil || hwm != 5 {
		t.Fatalf("%d %v", hwm, err)
	}
	for name, tb := range map[string][]byte{
		"pending":    tarOf(t, hdr{"executor/state", tar.TypeReg, "ab\n" + `{"committed":{"hwm":5},"pending":{"hwm":6}}`}),
		"no state":   tarOf(t, hdr{"executor/guards", tar.TypeReg, "x"}),
		"outside":    tarOf(t, hdr{"executor/state", tar.TypeReg, "ab\n" + ok}, hdr{"other/x", tar.TypeReg, ""}),
		"symlink":    tarOf(t, hdr{"executor/state", tar.TypeReg, "ab\n" + ok}, hdr{"executor/l", tar.TypeSymlink, ""}),
		"traversal":  tarOf(t, hdr{"executor/state", tar.TypeReg, "ab\n" + ok}, hdr{"executor/../x", tar.TypeReg, ""}),
		"not a body": tarOf(t, hdr{"executor/state", tar.TypeReg, ok}),
	} {
		if _, err := CheckState(tb); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

/* fakeDB answers the versions query and the dump; it records the restore's stdin. */
type fakeDB struct{ restored string }

func (f *fakeDB) exec(_ context.Context, script string, stdin io.Reader, stdout io.Writer) error {
	switch {
	case strings.Contains(script, "server_version_num"):
		_, err := io.WriteString(stdout, "170006 2.30.2\n")
		return err
	case strings.Contains(script, "pg_dump"):
		_, err := io.WriteString(stdout, "PGDMP"+strings.Repeat("x", 200000))
		return err
	}
	b, err := io.ReadAll(stdin)
	f.restored = string(b)
	return err
}

func TestDataRoundTrip(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	db := &fakeDB{}
	m := Manifest{ID: "b", Server: "170006", TimescaleDB: "2.30.2", Files: map[string][]byte{"anchors/anchors.log": []byte("a")},
		ExecutorState: tarOf(t, hdr{"executor/state", tar.TypeReg, "ab\n" + `{"committed":{"hwm":3}}`})}
	var arc bytes.Buffer
	if err := WriteData(context.Background(), &arc, id.Recipient(), m, db.exec); err != nil {
		t.Fatal(err)
	}
	got, err := VerifyData(bytes.NewReader(arc.Bytes()), id)
	if err != nil || got.ID != "b" || string(got.Files["anchors/anchors.log"]) != "a" {
		t.Fatalf("%+v %v", got, err)
	}
	if err := RestoreDB(context.Background(), bytes.NewReader(arc.Bytes()), id, db.exec); err != nil || len(db.restored) != 200005 {
		t.Fatalf("restored %d bytes: %v", len(db.restored), err)
	}
	m.Server = "160000"
	arc.Reset()
	if err := WriteData(context.Background(), &arc, id.Recipient(), m, db.exec); err != nil {
		t.Fatal(err)
	}
	db.restored = ""
	if err := RestoreDB(context.Background(), &arc, id, db.exec); err == nil || db.restored != "" {
		t.Fatal("restored into another PostgreSQL version")
	}
}

func TestIdentityIsCreatedOnce(t *testing.T) {
	p := filepath.Join(t.TempDir(), "backup_age.key")
	a, err := Identity(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Identity(p)
	if err != nil || a.String() != b.String() {
		t.Fatal("identity changed", err)
	}
}
