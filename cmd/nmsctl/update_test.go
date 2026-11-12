package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aead.dev/minisign"

	"github.com/beekamai/network-scheme/internal/install"
	"github.com/beekamai/network-scheme/internal/testdb"
)

const oldCompose = `name: nms
services:
  migrate:
    image: "nms/api:0.9.0"
  api:
    image: "nms/api:0.9.0"
  executor:
    image: "nms/executor:0.9.0"
  gateway:
    image: "nms/gateway:0.9.0"
`

/* updateFake answers backup's commands, the schema version, and fails the first command containing fail. */
type updateFake struct {
	stackFake
	fail   string
	schema string
}

func (f *updateFake) Run(ctx context.Context, c install.Cmd) error {
	a := strings.Join(c.Args, " ")
	if f.fail != "" && strings.Contains(a, f.fail) {
		f.fail = ""
		f.cmds, f.stdins = append(f.cmds, c), append(f.stdins, "")
		return errors.New("simulated failure")
	}
	if err := f.stackFake.Run(ctx, c); err != nil {
		return err
	}
	switch {
	case strings.Contains(a, "run --rm migrate"):
		f.schema = "31"
	case strings.Contains(a, "volume rm"):
		f.schema = "30"
	case strings.Contains(a, "goose_db_version"):
		_, err := io.WriteString(c.Stdout, f.schema+"\n")
		return err
	}
	return nil
}

/* signer sets releaseKey to a new key for the test and returns its private half. */
func signer(t *testing.T) minisign.PrivateKey {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	text, _ := pub.MarshalText()
	old := releaseKey
	t.Cleanup(func() { releaseKey = old })
	releaseKey = string(text)
	return priv
}

type bundleEntry struct{ name, body string }

/* makeBundle writes a bundle of entries (manifest first) and, with priv, its signature; it returns the bundle's path. */
func makeBundle(t *testing.T, priv *minisign.PrivateKey, entries ...bundleEntry) string {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(e.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "nms-1.0.0.tar")
	write(t, p, b.String())
	if priv != nil {
		r := minisign.NewReader(bytes.NewReader(b.Bytes()))
		_, _ = io.Copy(io.Discard, r)
		write(t, p+".minisig", string(r.Sign(*priv)))
	}
	return p
}

/* goodEntries is a consistent bundle of version 1.0.0; edit adjusts the manifest before it is encoded. */
func goodEntries(t *testing.T, edit func(*bundleManifest)) []bundleEntry {
	t.Helper()
	m := bundleManifest{Format: 1, Version: "1.0.0", ImageTag: "1.0.0"}
	m.Schema.From, m.Schema.To = 1, 31
	images := []bundleEntry{{"images/api.tar", "api image"}, {"images/gateway.tar", "gateway image"}, {"images/executor.tar", "executor image"}}
	for i, repo := range bundleRepos {
		sum := sha256.Sum256([]byte(images[i].body))
		m.Images = append(m.Images, bundleImage{Ref: repo + ":1.0.0", File: images[i].name, SHA256: hex.EncodeToString(sum[:])})
	}
	if edit != nil {
		edit(&m)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return append([]bundleEntry{{"manifest.json", string(raw)}}, images...)
}

/* updateHost makes an install at 0.9.0 with schema 30 and a running executor. */
func updateHost(t *testing.T) *updateFake {
	t.Helper()
	host(t)
	write(t, filepath.Join(etcDir, "secrets", "db_cli_password"), "pw")
	write(t, filepath.Join(etcDir, "compose.yaml"), oldCompose)
	return &updateFake{stackFake: stackFake{state: stateTar(t, `{"v":1,"committed":{"hwm":5},"pending":null,"frozen":false}`)}, schema: "30"}
}

func compose(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(etcDir, "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

/* inOrder fails unless each of want is in the commands after the previous one. */
func inOrder(t *testing.T, f *updateFake, want ...string) {
	t.Helper()
	last := -1
	for _, s := range want {
		i := -1
		for j, a := range f.argv() {
			if j > last && strings.Contains(a, s) {
				i = j
				break
			}
		}
		if i < 0 {
			t.Fatalf("%q missing or out of order in %q", s, f.argv())
		}
		last = i
	}
}

/* A missing or bad signature, a tampered bundle or no release key: refused before any command, nothing left behind. */
func TestUpdateRefusesUnverifiedBundlesWithoutChanges(t *testing.T) {
	priv := signer(t)
	other := func() minisign.PrivateKey { _, k, _ := minisign.GenerateKey(rand.Reader); return k }()
	cases := map[string]func(t *testing.T) string{
		"no signature": func(t *testing.T) string { return makeBundle(t, nil, goodEntries(t, nil)...) },
		"foreign key":  func(t *testing.T) string { return makeBundle(t, &other, goodEntries(t, nil)...) },
		"tampered image": func(t *testing.T) string {
			p := makeBundle(t, &priv, goodEntries(t, nil)...)
			raw, _ := os.ReadFile(p)
			write(t, p, strings.Replace(string(raw), "gateway image", "gateway imagX", 1))
			return p
		},
		"tampered manifest": func(t *testing.T) string {
			p := makeBundle(t, &priv, goodEntries(t, nil)...)
			raw, _ := os.ReadFile(p)
			write(t, p, strings.Replace(string(raw), `"to":31`, `"to":99`, 1))
			return p
		},
		"no release key": func(t *testing.T) string {
			p := makeBundle(t, &priv, goodEntries(t, nil)...)
			k := releaseKey
			releaseKey = ""
			t.Cleanup(func() { releaseKey = k })
			return p
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			sys := updateHost(t)
			p := mk(t)
			code, msg := runWith(sys, "", "update", p)
			if code == 0 || !strings.Contains(msg, "nothing was changed") {
				t.Fatalf("code %d %s", code, msg)
			}
			if len(sys.cmds) != 0 || compose(t) != oldCompose {
				t.Fatalf("ran %q", sys.argv())
			}
			if ents, _ := os.ReadDir(filepath.Join(varDir, "updates")); len(ents) != 0 {
				t.Fatalf("left %v", ents)
			}
		})
	}
}

/* A correctly signed bundle inconsistent with its own manifest is refused before any command too. */
func TestUpdateRefusesABundleThatDoesNotMatchItsManifest(t *testing.T) {
	priv := signer(t)
	cases := map[string][]bundleEntry{
		"image hash": func() []bundleEntry {
			e := goodEntries(t, nil)
			e[2].body = "other image"
			return e
		}(),
		"foreign repository": goodEntries(t, func(m *bundleManifest) { m.Images[0].Ref = "evil/api:1.0.0" }),
		"extra entry":        append(goodEntries(t, nil), bundleEntry{"images/x.tar", "x"}),
		"manifest not first": func() []bundleEntry { e := goodEntries(t, nil); e[0], e[1] = e[1], e[0]; return e }(),
		"missing image":      goodEntries(t, nil)[:3],
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			sys := updateHost(t)
			code, msg := runWith(sys, "", "update", makeBundle(t, &priv, entries...))
			if code == 0 || len(sys.cmds) != 0 || compose(t) != oldCompose {
				t.Fatalf("code %d %s %q", code, msg, sys.argv())
			}
		})
	}
}

func TestUpdateRefusesASchemaOutsideTheBundlesRange(t *testing.T) {
	priv := signer(t)
	sys := updateHost(t)
	sys.schema = "32"
	code, msg := runWith(sys, "", "update", makeBundle(t, &priv, goodEntries(t, nil)...))
	if code == 0 || !strings.Contains(msg, "schema is at version 32") || sys.index("pg_dump") >= 0 || compose(t) != oldCompose {
		t.Fatalf("code %d %s %q", code, msg, sys.argv())
	}
}

func TestUpdateBacksUpLoadsMigratesAndRecords(t *testing.T) {
	priv := signer(t)
	sys := updateHost(t)
	if code, msg := runWith(sys, "", "update", makeBundle(t, &priv, goodEntries(t, nil)...)); code != 0 {
		t.Fatalf("update: %s\n%q", msg, sys.argv())
	}
	inOrder(t, sys, "goose_db_version", " stop executor", "pg_dump", " start executor", "load", "load", "load",
		"image inspect --format {{.Id}} nms/executor:1.0.0", "run --rm migrate", "goose_db_version", "up -d --wait --wait-timeout 600", "nmsctl update record")
	if sys.index("volume rm") >= 0 {
		t.Fatalf("rolled back: %q", sys.argv())
	}
	if got := compose(t); got != strings.ReplaceAll(oldCompose, "0.9.0", "1.0.0") {
		t.Fatalf("compose %s", got)
	}
	if got := sys.stdins[sys.index("load")]; got != "api image" {
		t.Fatalf("load got %q", got)
	}
	if got := sys.stdins[sys.index("update record")]; !strings.Contains(got, `"result":"success"`) || !strings.Contains(got, `"from":"0.9.0"`) {
		t.Fatalf("record %s", got)
	}
	ents, _ := os.ReadDir(filepath.Join(varDir, "updates", "20261113T010203Z"))
	if len(ents) != 2 { /* backup.age and compose.yaml; the bundle copy is removed */
		t.Fatalf("left %v", ents)
	}
}

/* A failing migration or health check rolls back to the previous images and the backup's database and executor state. */
func TestUpdateRollsBackABrokenUpdate(t *testing.T) {
	for _, fail := range []string{"run --rm migrate", "up -d --wait --wait-timeout 600"} {
		t.Run(fail, func(t *testing.T) {
			priv := signer(t)
			sys := updateHost(t)
			sys.fail = fail
			code, msg := runWith(sys, "", "update", makeBundle(t, &priv, goodEntries(t, nil)...))
			if code == 0 || !strings.Contains(msg, "rolled back to 0.9.0") {
				t.Fatalf("code %d %s", code, msg)
			}
			inOrder(t, sys, fail, " stop", "rm -f postgres executor", "volume rm nms_pgdata nms_executor-state", "up -d --wait postgres",
				"pg_restore", "up --no-start executor", "cp -a - "+testCID+":/var/lib", "up -d --wait --wait-timeout 600", "nmsctl update record")
			if compose(t) != oldCompose {
				t.Fatalf("compose not rolled back: %s", compose(t))
			}
			if got := sys.stdins[sys.index("pg_restore")]; got != "PGDMP a dump" {
				t.Fatalf("dump %q", got)
			}
			if got := sys.stdins[sys.index("cp -a")]; !strings.Contains(got, `"hwm":5`) {
				t.Fatalf("state %q", got)
			}
			if got := sys.stdins[sys.index("update record")]; !strings.Contains(got, `"result":"failure"`) {
				t.Fatalf("record %s", got)
			}
		})
	}
}

/* A load failure changes nothing that runs: no retag, no migration, no rollback. */
func TestUpdateStopsOnALoadFailure(t *testing.T) {
	priv := signer(t)
	sys := updateHost(t)
	sys.fail = "image inspect"
	code, msg := runWith(sys, "", "update", makeBundle(t, &priv, goodEntries(t, nil)...))
	if code == 0 || !strings.Contains(msg, "not changed") || sys.index("migrate") >= 0 || sys.index("volume rm") >= 0 || compose(t) != oldCompose {
		t.Fatalf("code %d %s %q", code, msg, sys.argv())
	}
}

func TestUpdateRecordAppendsToTheAudit(t *testing.T) {
	env := testdb.New(t)
	for _, in := range []string{`{"from":"0.9.0","to":"1.0.0","backup":"ab","result":"success"}`,
		`{"from":"0.9.0","to":"1.0.0","backup":"ab","result":"failure","error":"migrations: boom"}`} {
		if code, out := cli(t, env, in, "update", "record"); code != 0 {
			t.Fatalf("update record: %s", out)
		}
	}
	if n := auditCount(t, env, "cli.update"); n != 2 {
		t.Fatalf("%d cli.update records", n)
	}
	if code, _ := cli(t, env, `{"to":"1.0.0","result":"maybe"}`, "update", "record"); code == 0 {
		t.Fatal("bad summary accepted")
	}
}
