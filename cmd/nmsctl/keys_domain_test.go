package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"

	"github.com/beekamai/network-scheme/internal/keys"
	"github.com/beekamai/network-scheme/internal/testdb"
)

var errExit = errors.New("exit status 1")

func domainKey(t *testing.T) keys.DomainKey {
	t.Helper()
	k, err := keys.NewDomainKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

/*
The tools container re-seals every read credential from the retired key to
the next one at the next version, in one audited transaction; a credential
that does not open under the retired key is marked invalid; run again it
changes nothing more.
*/
func TestReencryptRead(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	root := env.Pool("postgres")
	old, next, other := domainKey(t), domainKey(t), domainKey(t)
	seal := func(k keys.DomainKey, pt string) []byte {
		ct, err := box.SealAnonymous(nil, []byte(pt), &k.Public, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return ct
	}
	if _, err := root.Exec(ctx, `DELETE FROM core.access_profile`); err != nil {
		t.Fatal(err)
	}
	for i, ct := range [][]byte{seal(old, "a"), seal(old, "b"), seal(other, "planted")} {
		if _, err := root.Exec(ctx, `INSERT INTO core.access_profile (owner_kind, owner_id, kind, ciphertext, key_version, status)
			VALUES ('device', $1, 'snmp2c', $2, 1, 'ok')`, 900+i, ct); err != nil {
			t.Fatal(err)
		}
	}
	stdin := base64.StdEncoding.EncodeToString(old.Private[:]) + "\n" + base64.StdEncoding.EncodeToString(next.Private[:]) + "\n"
	if code, out := cli(t, env, stdin, "keys", "reencrypt", "read", "--version", "2"); code != 0 || !strings.Contains(out, ": 2;") {
		t.Fatalf("%d %s", code, out)
	}
	rows, err := root.Query(ctx, `SELECT owner_id, ciphertext, key_version, status FROM core.access_profile ORDER BY owner_id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var (
			id     int64
			ct     []byte
			v      int
			status string
		)
		if err := rows.Scan(&id, &ct, &v, &status); err != nil {
			t.Fatal(err)
		}
		_, okNx := box.OpenAnonymous(nil, ct, &next.Public, &next.Private)
		_, okOld := box.OpenAnonymous(nil, ct, &old.Public, &old.Private)
		switch {
		case id < 902 && (!okNx || okOld || v != 2 || status != "ok"):
			t.Errorf("credential %d: next %v old %v version %d status %s", id, okNx, okOld, v, status)
		case id == 902 && (v != 1 || status != "invalid"):
			t.Errorf("planted credential: version %d status %s", v, status)
		}
	}
	rows.Close()
	var audits int
	if err := root.QueryRow(ctx, `SELECT count(*) FROM audit.event WHERE action = 'cli.keys_rotate'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("audit rows %d %v", audits, err)
	}
	if code, out := cli(t, env, stdin, "keys", "reencrypt", "read", "--version", "2"); code != 0 || !strings.Contains(out, ": 0;") {
		t.Fatalf("second run: %d %s", code, out)
	}
	if code, _ := cli(t, env, "", "keys", "reencrypt", "read", "--version", "2"); code == 0 {
		t.Fatal("ran without keys on stdin")
	}
}

/*
On the host the read rotation stages the key, moves api.yaml and keys.json
to the next version, restarts the api, re-seals in the tools container
(keys on stdin, never argv), then replaces the key file and restarts the
readers. Run again after a crash before the key file was replaced, it does
not bump the version twice.
*/
func TestReadDomainRotation(t *testing.T) {
	cur := domainKey(t)
	dir := withSecrets(t, map[string]string{"domain_read.key": base64.StdEncoding.EncodeToString(cur.Private[:])})
	pubs := map[string][32]byte{"read": cur.Public, "write": domainKey(t).Public, "backup": domainKey(t).Public}
	doc, err := keys.BuildKeysJSON(pubs)
	if err != nil {
		t.Fatal(err)
	}
	etc := t.TempDir()
	kj, api := filepath.Join(etc, "keys.json"), filepath.Join(etc, "api.yaml")
	for p, b := range map[string][]byte{kj: doc, api: []byte("listen_addr: \":8080\"\nread_key_version: 1\n")} {
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	oldKJ, oldAPI := keysJSONPath, apiYAMLPath
	keysJSONPath, apiYAMLPath = kj, api
	t.Cleanup(func() { keysJSONPath, apiYAMLPath = oldKJ, oldAPI })

	sys := &rotator{fakeSys: fakeSys{err: errExit, failMatch: "reencrypt"}}
	if code, _ := hostRun(t, sys, "keys", "rotate", "read"); code == 0 {
		t.Fatal("a failed re-seal passed")
	}
	staged := read(t, filepath.Join(dir, "domain_read.key.next"))
	if read(t, api) != "listen_addr: \":8080\"\nread_key_version: 2\n" {
		t.Fatalf("api.yaml %q", read(t, api))
	}
	sys = &rotator{}
	if code, out := hostRun(t, sys, "keys", "rotate", "read"); code != 0 || !strings.Contains(out, "version 2") {
		t.Fatalf("resumed: %d %s", code, out)
	}
	want := []string{
		"docker compose -f /etc/nms/compose.yaml restart api",
		"docker compose -f /etc/nms/compose.yaml --profile tools run --rm --no-deps -T nmsctl keys reencrypt read --version 2",
		"docker compose -f /etc/nms/compose.yaml restart poller eventd",
	}
	if got := strings.Join(sys.argv(), "\n"); got != strings.Join(want, "\n") {
		t.Fatalf("commands:\n%s", got)
	}
	if !strings.HasPrefix(sys.stdins[1], base64.StdEncoding.EncodeToString(cur.Private[:])+"\n"+staged+"\n") {
		t.Fatal("the tools container did not get the retired and the next key on stdin")
	}
	if read(t, filepath.Join(dir, "domain_read.key")) != staged {
		t.Fatal("key file not replaced")
	}
	var priv [32]byte
	b, _ := base64.StdEncoding.DecodeString(staged)
	copy(priv[:], b)
	pub, _ := keys.PublicOf(&priv)
	if v := keys.Published([]byte(read(t, kj)), "read", pub); v != 2 {
		t.Fatalf("keys.json publishes the next key at %d", v)
	}
}

/*
The backup rotation stages the key, publishes the next public key to the
poller and keys.json and restarts the poller before the executor is
stopped and the one-shot reseal-backup gets the next key on stdin; only
after it succeeded is the key file replaced and the executor started. A
failed re-seal leaves the key file and the executor stopped; run again it
resumes with the staged key and does not bump the version twice.
*/
func TestBackupDomainRotation(t *testing.T) {
	cur := domainKey(t)
	dir := withSecrets(t, map[string]string{"domain_backup.key": base64.StdEncoding.EncodeToString(cur.Private[:])})
	doc, err := keys.BuildKeysJSON(map[string][32]byte{"read": domainKey(t).Public, "write": domainKey(t).Public, "backup": cur.Public})
	if err != nil {
		t.Fatal(err)
	}
	etc := t.TempDir()
	kj, bp := filepath.Join(etc, "keys.json"), filepath.Join(etc, "domain_backup.pub")
	for p, b := range map[string][]byte{kj: doc, bp: []byte(base64.StdEncoding.EncodeToString(cur.Public[:]) + "\n")} {
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	oldKJ, oldBP := keysJSONPath, backupPubPath
	keysJSONPath, backupPubPath = kj, bp
	t.Cleanup(func() { keysJSONPath, backupPubPath = oldKJ, oldBP })

	sys := &rotator{fail: errExit}
	if code, _ := hostRun(t, sys, "keys", "rotate", "backup"); code == 0 {
		t.Fatal("a failed re-seal passed")
	}
	staged := read(t, filepath.Join(dir, "domain_backup.key.next"))
	if read(t, filepath.Join(dir, "domain_backup.key")) != base64.StdEncoding.EncodeToString(cur.Private[:]) {
		t.Fatal("the key file was replaced after a failed re-seal")
	}
	if strings.Contains(strings.Join(sys.argv(), "\n"), "up -d executor") {
		t.Fatal("the executor started after a failed re-seal")
	}
	sys = &rotator{result: `{"backups":3,"unreadable":1,"sessions":1,"chunks":4,"manifests":1}`}
	if code, out := hostRun(t, sys, "keys", "rotate", "backup"); code != 0 || !strings.Contains(out, "version 2") || !strings.Contains(out, "re-sealed 3 config versions") {
		t.Fatalf("resumed: %d %s", code, out)
	}
	want := []string{
		"docker compose -f /etc/nms/compose.yaml restart poller",
		"docker compose -f /etc/nms/compose.yaml stop executor",
		"docker compose -f /etc/nms/compose.yaml run --rm --no-deps -T executor reseal-backup",
		"docker compose -f /etc/nms/compose.yaml up -d executor",
	}
	if got := strings.Join(sys.argv(), "\n"); got != strings.Join(want, "\n") {
		t.Fatalf("commands:\n%s", got)
	}
	if !strings.HasPrefix(sys.stdins[2], staged+"\n") {
		t.Fatal("reseal-backup did not get the next key on stdin")
	}
	if read(t, filepath.Join(dir, "domain_backup.key")) != staged {
		t.Fatal("key file not replaced")
	}
	var priv [32]byte
	b, _ := base64.StdEncoding.DecodeString(staged)
	copy(priv[:], b)
	pub, _ := keys.PublicOf(&priv)
	if v := keys.Published([]byte(read(t, kj)), "backup", pub); v != 2 {
		t.Fatalf("keys.json publishes the next key at %d", v)
	}
	if read(t, bp) != base64.StdEncoding.EncodeToString(pub[:])+"\n" {
		t.Fatal("the poller's backup public key was not replaced")
	}
}
