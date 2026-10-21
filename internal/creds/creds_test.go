package creds_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/ssh"

	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/creds/credstest"
	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/secret"
)

var (
	dev1 = devices.Owner{Kind: devices.OwnerDevice, ID: 1}
	dev2 = devices.Owner{Kind: devices.OwnerDevice, ID: 2}
	t0   = time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
)

const k16 = "0123456789abcdef"

var testPEM = func() string {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	b, err := ssh.MarshalPrivateKey(k, "")
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(b))
}()

func keys(t *testing.T) (pub, priv *[32]byte) {
	t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func snmp3(auth, priv string) map[string]string {
	return map[string]string{"user": "mon", "auth_proto": "SHA256", "auth_key": auth, "priv_proto": "AES", "priv_key": priv}
}

func TestOpenRoundTrip(t *testing.T) {
	pub, priv := keys(t)
	cases := []struct {
		kind   string
		secret any
		check  func(*testing.T, creds.Credential)
	}{
		{"snmp2c", map[string]string{"community": k16}, func(t *testing.T, c creds.Credential) {
			if c.Community.Reveal() != k16 {
				t.Fatal("community")
			}
		}},
		{"snmp3", snmp3(k16, k16+"x"), func(t *testing.T, c creds.Credential) {
			if c.User != "mon" || c.AuthProto != "SHA256" || c.PrivProto != "AES" ||
				c.AuthKey.Reveal() != k16 || c.PrivKey.Reveal() != k16+"x" {
				t.Fatalf("snmp3 fields: %+v", c)
			}
		}},
		{"ssh_read", map[string]string{"username": "u", "password": "twelve-chars"}, func(t *testing.T, c creds.Credential) {
			if c.Username != "u" || c.Password.Reveal() != "twelve-chars" || !c.PrivateKey.IsZero() {
				t.Fatalf("ssh pw: %+v", c)
			}
		}},
		{"ssh_read", map[string]string{"username": "u", "private_key": testPEM}, func(t *testing.T, c creds.Credential) {
			if c.PrivateKey.Reveal() != testPEM || !c.Password.IsZero() {
				t.Fatalf("ssh key: %+v", c)
			}
		}},
		{"telnet_read", map[string]string{"username": "u", "password": "twelve-chars"}, func(t *testing.T, c creds.Credential) {
			if c.Password.Reveal() != "twelve-chars" {
				t.Fatal("telnet")
			}
		}},
	}
	for _, tc := range cases {
		ct := credstest.Seal(pub, dev1, tc.kind, tc.secret, t0)
		c, err := creds.Open(priv, pub, ct, dev1, tc.kind, time.Time{}, t0)
		if err != nil {
			t.Fatalf("%s: %v", tc.kind, err)
		}
		if c.Kind != tc.kind || c.Owner != dev1 || !c.CreatedAt.Equal(t0) {
			t.Fatalf("%s meta: %+v", tc.kind, c)
		}
		tc.check(t, c)
	}
}

func TestOwnerSwapRejected(t *testing.T) {
	pub, priv := keys(t)
	ct := credstest.Seal(pub, dev1, "snmp2c", map[string]string{"community": k16}, t0)
	if _, err := creds.Open(priv, pub, ct, dev2, "snmp2c", time.Time{}, t0); !errors.Is(err, creds.ErrOwnerMismatch) {
		t.Fatalf("device swap: %v", err)
	}
	scan1 := devices.Owner{Kind: devices.OwnerScan, ID: 1}
	if _, err := creds.Open(priv, pub, ct, scan1, "snmp2c", time.Time{}, t0); !errors.Is(err, creds.ErrOwnerMismatch) {
		t.Fatalf("owner-kind swap: %v", err)
	}
}

func TestKindSwapRejected(t *testing.T) {
	pub, priv := keys(t)
	ct := credstest.Seal(pub, dev1, "snmp2c", map[string]string{"community": k16}, t0)
	if _, err := creds.Open(priv, pub, ct, dev1, "snmp3", time.Time{}, t0); !errors.Is(err, creds.ErrKindMismatch) {
		t.Fatalf("got %v", err)
	}
}

func TestStaleRejected(t *testing.T) {
	pub, priv := keys(t)
	ct := credstest.Seal(pub, dev1, "snmp2c", map[string]string{"community": k16}, t0)
	if _, err := creds.Open(priv, pub, ct, dev1, "snmp2c", t0.Add(time.Second), t0); !errors.Is(err, creds.ErrStale) {
		t.Fatalf("older than accepted: %v", err)
	}
	/* Equal is the same credential opened again on the next poll, not a rollback. */
	for _, last := range []time.Time{t0, t0.Add(-time.Second)} {
		if _, err := creds.Open(priv, pub, ct, dev1, "snmp2c", last, t0); err != nil {
			t.Fatalf("last=%v: %v", last, err)
		}
	}
}

func TestWeakSNMPv3KeyRejected(t *testing.T) {
	pub, priv := keys(t)
	open := func(kind string, s any) error {
		_, err := creds.Open(priv, pub, credstest.Seal(pub, dev1, kind, s, t0), dev1, kind, time.Time{}, t0)
		return err
	}
	short := k16[:15]
	for name, s := range map[string]any{"auth": snmp3(short, k16), "priv": snmp3(k16, short)} {
		if err := open("snmp3", s); !errors.Is(err, creds.ErrWeak) {
			t.Fatalf("%s 15: %v", name, err)
		}
	}
	if err := open("snmp3", snmp3(k16, k16)); err != nil {
		t.Fatalf("16: %v", err)
	}
	if err := open("snmp2c", map[string]string{"community": short}); !errors.Is(err, creds.ErrWeak) {
		t.Fatalf("community: %v", err)
	}
	for _, kind := range []string{"ssh_read", "telnet_read"} {
		if err := open(kind, map[string]string{"username": "u", "password": "elevenchars"}); !errors.Is(err, creds.ErrWeak) {
			t.Fatalf("%s 11: %v", kind, err)
		}
	}
}

func TestUnsupportedAuthProtoRejected(t *testing.T) {
	pub, priv := keys(t)
	for _, p := range []string{"MD5", "SHA", "sha256", ""} {
		s := snmp3(k16, k16)
		s["auth_proto"] = p
		ct := credstest.Seal(pub, dev1, "snmp3", s, t0)
		if _, err := creds.Open(priv, pub, ct, dev1, "snmp3", time.Time{}, t0); !errors.Is(err, creds.ErrMalformed) {
			t.Fatalf("auth %q: %v", p, err)
		}
	}
	for _, p := range []string{"DES", "AES192", ""} {
		s := snmp3(k16, k16)
		s["priv_proto"] = p
		ct := credstest.Seal(pub, dev1, "snmp3", s, t0)
		if _, err := creds.Open(priv, pub, ct, dev1, "snmp3", time.Time{}, t0); !errors.Is(err, creds.ErrMalformed) {
			t.Fatalf("priv %q: %v", p, err)
		}
	}
}

func TestSecretsMasked(t *testing.T) {
	pub, priv := keys(t)
	ct := credstest.Seal(pub, dev1, "snmp3", snmp3("AUTHSECRET-0123456", "PRIVSECRET-0123456"), t0)
	c, err := creds.Open(priv, pub, ct, dev1, "snmp3", time.Time{}, t0)
	if err != nil {
		t.Fatal(err)
	}
	j, _ := json.Marshal(c)
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("c", "cred", c)
	slog.New(slog.NewTextHandler(&buf, nil)).Info("c", "cred", c)
	out := fmt.Sprintf("%v %+v %#v", c, c, c) + string(j) + buf.String()
	if strings.Contains(out, "SECRET") {
		t.Fatalf("leak: %s", out)
	}
}

func TestErrorsLeakNothing(t *testing.T) {
	pub, priv := keys(t)
	ct := credstest.Seal(pub, dev1, "snmp2c", map[string]string{"community": "SECRETWEAK"}, t0)
	_, err := creds.Open(priv, pub, ct, dev1, "snmp2c", time.Time{}, t0)
	if !errors.Is(err, creds.ErrWeak) || strings.Contains(err.Error(), "SECRETWEAK") {
		t.Fatalf("got %v", err)
	}
}

func TestUndecryptable(t *testing.T) {
	pub, priv := keys(t)
	otherPub, _ := keys(t)
	ct := credstest.Seal(otherPub, dev1, "snmp2c", map[string]string{"community": k16}, t0)
	if _, err := creds.Open(priv, pub, ct, dev1, "snmp2c", time.Time{}, t0); !errors.Is(err, creds.ErrUndecryptable) {
		t.Fatalf("wrong key: %v", err)
	}
	if _, err := creds.Open(priv, pub, nil, dev1, "snmp2c", time.Time{}, t0); !errors.Is(err, creds.ErrUndecryptable) {
		t.Fatalf("empty: %v", err)
	}
	good := credstest.Seal(pub, dev1, "snmp2c", map[string]string{"community": k16}, t0)
	good[len(good)-1] ^= 1
	if _, err := creds.Open(priv, pub, good, dev1, "snmp2c", time.Time{}, t0); !errors.Is(err, creds.ErrUndecryptable) {
		t.Fatalf("tampered: %v", err)
	}
}

/* rawSeal seals an arbitrary plaintext so malformed payloads can be built. */
func rawSeal(t *testing.T, pub *[32]byte, pt string) []byte {
	t.Helper()
	ct, err := box.SealAnonymous(nil, []byte(pt), pub, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return ct
}

func TestMalformedRejected(t *testing.T) {
	pub, priv := keys(t)
	const ts = "2026-10-20T10:00:00Z"
	nonce := `"AAECAwQFBgcICQoLDA0ODw=="` /* 16 bytes */
	mk := func(v, owner, kind, ts, nc, sec string) string {
		return `{"v":` + v + `,"owner":"` + owner + `","kind":"` + kind + `","created_at":"` + ts + `","nonce":` + nc + `,"secret":` + sec + `}`
	}
	good := `{"community":"` + k16 + `"}`
	type tc struct{ kind, pt string }
	cases := map[string]tc{
		"not json":         {"snmp2c", "garbage"},
		"v2":               {"snmp2c", mk("2", "device:1", "snmp2c", ts, nonce, good)},
		"v string":         {"snmp2c", mk(`"1"`, "device:1", "snmp2c", ts, nonce, good)},
		"leading zero id":  {"snmp2c", mk("1", "device:01", "snmp2c", ts, nonce, good)},
		"owner kind":       {"snmp2c", mk("1", "host:1", "snmp2c", ts, nonce, good)},
		"owner id zero":    {"snmp2c", mk("1", "device:0", "snmp2c", ts, nonce, good)},
		"unknown kind":     {"snmp9", mk("1", "device:1", "snmp9", ts, nonce, good)},
		"bad time":         {"snmp2c", mk("1", "device:1", "snmp2c", "yesterday", nonce, good)},
		"short nonce":      {"snmp2c", mk("1", "device:1", "snmp2c", ts, `"AAEC"`, good)},
		"extra secret key": {"snmp2c", mk("1", "device:1", "snmp2c", ts, nonce, `{"community":"`+k16+`","x":1}`)},
		"missing secret":   {"snmp2c", mk("1", "device:1", "snmp2c", ts, nonce, `{}`)},
		"ssh both":         {"ssh_read", mk("1", "device:1", "ssh_read", ts, nonce, `{"username":"u","password":"twelve-chars","private_key":"k"}`)},
		"ssh neither":      {"ssh_read", mk("1", "device:1", "ssh_read", ts, nonce, `{"username":"u"}`)},
		"ssh no username":  {"ssh_read", mk("1", "device:1", "ssh_read", ts, nonce, `{"password":"twelve-chars"}`)},
		"telnet key":       {"telnet_read", mk("1", "device:1", "telnet_read", ts, nonce, `{"username":"u","private_key":"k"}`)},
		"trailing data":    {"snmp2c", mk("1", "device:1", "snmp2c", ts, nonce, good) + " {}"},
		"extra top key":    {"snmp2c", strings.Replace(mk("1", "device:1", "snmp2c", ts, nonce, good), `"v":1`, `"v":1,"zz":1`, 1)},
		"oversize":         {"snmp2c", `{"pad":"` + strings.Repeat("a", 9000) + `"}`},
	}
	for name, c := range cases {
		_, err := creds.Open(priv, pub, rawSeal(t, pub, c.pt), dev1, c.kind, time.Time{}, t0)
		if !errors.Is(err, creds.ErrMalformed) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

/* testdata/libsodium_vector.json was produced by libsodium-wrappers (crypto_box_seal); the web tests read it too. */
func TestLibsodiumVector(t *testing.T) {
	var priv, pub [32]byte
	v := loadVector(t, "libsodium_vector.json", &priv, &pub)
	c, err := creds.Open(&priv, &pub, v.ct, devices.Owner{Kind: devices.OwnerDevice, ID: 42}, "snmp3", time.Time{}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if c.User != "monitor" || c.AuthKey.Reveal() != "auth-key-0123456789" || c.PrivKey.Reveal() != "priv-key-0123456789" ||
		!c.CreatedAt.Equal(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("fields: %+v", c)
	}
}

/* testdata/browser_sealed_vector.json was sealed by the web app's sealCredential (web/app/scripts/gen-seal-vector.ts). */
func TestBrowserSealedVector(t *testing.T) {
	var priv, pub [32]byte
	v := loadVector(t, "browser_sealed_vector.json", &priv, &pub)
	for _, w := range v.Cases {
		ct, err := hex.DecodeString(w.Ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		owner := devices.Owner{Kind: devices.OwnerDevice, ID: 7}
		c, err := creds.Open(&priv, &pub, ct, owner, w.Kind, time.Time{}, t0)
		if err != nil {
			t.Fatalf("%s: %v", w.Kind, err)
		}
		if c.Owner != owner || c.Kind != w.Kind || !c.CreatedAt.Equal(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)) {
			t.Fatalf("%s: %+v", w.Kind, c)
		}
		switch w.Kind {
		case "snmp2c":
			if c.Community.Reveal() != "community-0123456789" {
				t.Fatalf("snmp2c: %+v", c)
			}
		case "snmp3":
			if c.User != "monitor" || c.AuthProto != "SHA256" || c.PrivProto != "AES" ||
				c.AuthKey.Reveal() != "auth-key-0123456789" || c.PrivKey.Reveal() != "priv-key-0123456789" {
				t.Fatalf("snmp3: %+v", c)
			}
		case "ssh_read":
			if c.Username != "admin-é" || c.Password.Reveal() != "pa55 w0rd \"q\" 12☃" {
				t.Fatalf("ssh_read: %+v", c)
			}
		default:
			t.Fatalf("unexpected kind %s", w.Kind)
		}
	}
	if len(v.Cases) != 3 {
		t.Fatalf("cases: %d", len(v.Cases))
	}
}

type vector struct {
	ct    []byte
	Cases []struct {
		Kind       string `json:"kind"`
		Ciphertext string `json:"ciphertext"`
	} `json:"cases"`
}

/* loadVector reads a fixture from testdata, filling the key pair and (for single-vector files) the ciphertext. */
func loadVector(t *testing.T, name string, priv, pub *[32]byte) vector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		PrivateKey string `json:"private_key"`
		PublicKey  string `json:"public_key"`
		Ciphertext string `json:"ciphertext"`
		Cases      []struct {
			Kind       string `json:"kind"`
			Ciphertext string `json:"ciphertext"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	dec := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	copy(priv[:], dec(f.PrivateKey))
	copy(pub[:], dec(f.PublicKey))
	v := vector{Cases: f.Cases}
	if f.Ciphertext != "" {
		v.ct = dec(f.Ciphertext)
	}
	return v
}

func TestControlCharsRejected(t *testing.T) {
	pub, priv := keys(t)
	open := func(kind string, s any) error {
		_, err := creds.Open(priv, pub, credstest.Seal(pub, dev1, kind, s, t0), dev1, kind, time.Time{}, t0)
		return err
	}
	pw := "twelve-chars"
	for _, bad := range []string{"u\r\nconfigure", "u\x00", "u\x7f", "u\t", "u\x1b[A"} {
		for _, kind := range []string{"ssh_read", "telnet_read"} {
			if err := open(kind, map[string]string{"username": bad, "password": pw}); !errors.Is(err, creds.ErrMalformed) {
				t.Errorf("%s username %q: %v", kind, bad, err)
			}
			if err := open(kind, map[string]string{"username": "u", "password": pw + bad}); !errors.Is(err, creds.ErrMalformed) {
				t.Errorf("%s password %q: %v", kind, bad, err)
			}
		}
		if err := open("snmp2c", map[string]string{"community": k16 + bad}); !errors.Is(err, creds.ErrMalformed) {
			t.Errorf("community %q: %v", bad, err)
		}
		if err := open("snmp3", snmp3(k16+bad, k16)); !errors.Is(err, creds.ErrMalformed) {
			t.Errorf("auth_key %q: %v", bad, err)
		}
		s := snmp3(k16, k16+bad)
		if err := open("snmp3", s); !errors.Is(err, creds.ErrMalformed) {
			t.Errorf("priv_key %q: %v", bad, err)
		}
		s = snmp3(k16, k16)
		s["user"] = "m" + bad
		if err := open("snmp3", s); !errors.Is(err, creds.ErrMalformed) {
			t.Errorf("snmp3 user %q: %v", bad, err)
		}
	}
	/* PEM may contain line breaks, but must parse; other controls are refused. */
	if err := open("ssh_read", map[string]string{"username": "u", "private_key": testPEM}); err != nil {
		t.Fatalf("valid pem: %v", err)
	}
	for name, k := range map[string]string{"garbage": "-----BEGIN-----", "nul": testPEM + "\x00", "tab": strings.Replace(testPEM, "\n", "\t", 1)} {
		if err := open("ssh_read", map[string]string{"username": "u", "private_key": k}); !errors.Is(err, creds.ErrMalformed) {
			t.Errorf("pem %s: %v", name, err)
		}
	}
}

func TestUsernameLengthCaps(t *testing.T) {
	pub, priv := keys(t)
	open := func(kind string, s any) error {
		_, err := creds.Open(priv, pub, credstest.Seal(pub, dev1, kind, s, t0), dev1, kind, time.Time{}, t0)
		return err
	}
	pw := "twelve-chars"
	if err := open("ssh_read", map[string]string{"username": strings.Repeat("a", 64), "password": pw}); err != nil {
		t.Fatalf("64: %v", err)
	}
	if err := open("ssh_read", map[string]string{"username": strings.Repeat("a", 65), "password": pw}); !errors.Is(err, creds.ErrMalformed) {
		t.Fatalf("65: %v", err)
	}
	s := snmp3(k16, k16)
	s["user"] = strings.Repeat("a", 32)
	if err := open("snmp3", s); err != nil {
		t.Fatalf("snmp3 32: %v", err)
	}
	s["user"] = strings.Repeat("a", 33)
	if err := open("snmp3", s); !errors.Is(err, creds.ErrMalformed) {
		t.Fatalf("snmp3 33: %v", err)
	}
}

func TestFutureCreatedAtRejected(t *testing.T) {
	pub, priv := keys(t)
	open := func(created time.Time) error {
		ct := credstest.Seal(pub, dev1, "snmp2c", map[string]string{"community": k16}, created)
		_, err := creds.Open(priv, pub, ct, dev1, "snmp2c", time.Time{}, t0)
		return err
	}
	if err := open(t0.Add(4 * time.Minute)); err != nil {
		t.Fatalf("now+4m: %v", err)
	}
	if err := open(t0.Add(6 * time.Minute)); !errors.Is(err, creds.ErrMalformed) {
		t.Fatalf("now+6m: %v", err)
	}
}

func TestRSA4096KeyAccepted(t *testing.T) {
	pub, priv := keys(t)
	rk, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	for name, der := range map[string][]byte{"pkcs1": x509.MarshalPKCS1PrivateKey(rk), "pkcs8": mustPKCS8(t, rk)} {
		typ := "RSA PRIVATE KEY"
		if name == "pkcs8" {
			typ = "PRIVATE KEY"
		}
		p := string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
		ct := credstest.Seal(pub, dev1, "ssh_read", map[string]string{"username": "u", "private_key": p}, t0)
		if _, err := creds.Open(priv, pub, ct, dev1, "ssh_read", time.Time{}, t0); err != nil {
			t.Fatalf("%s (%d bytes): %v", name, len(p), err)
		}
	}
}

func mustPKCS8(t *testing.T, k *rsa.PrivateKey) []byte {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPrivateKeyCap(t *testing.T) {
	pub, priv := keys(t)
	over := testPEM + strings.Repeat(" ", 6<<10+1-len(testPEM))
	ct := credstest.Seal(pub, dev1, "ssh_read", map[string]string{"username": "u", "private_key": over}, t0)
	if _, err := creds.Open(priv, pub, ct, dev1, "ssh_read", time.Time{}, t0); !errors.Is(err, creds.ErrMalformed) {
		t.Fatalf("6KiB+1: %v", err)
	}
	ok := testPEM + strings.Repeat(" ", 6<<10-len(testPEM))
	ct = credstest.Seal(pub, dev1, "ssh_read", map[string]string{"username": "u", "private_key": ok}, t0)
	if _, err := creds.Open(priv, pub, ct, dev1, "ssh_read", time.Time{}, t0); err != nil {
		t.Fatalf("6KiB: %v", err)
	}
}

func TestCredentialWipe(t *testing.T) {
	c := creds.Credential{Kind: creds.KindSNMP3, AuthKey: secret.New("auth-key-0123456789"), PrivKey: secret.New("priv-key-0123456789")}
	held := c
	c.Wipe()
	for _, s := range []secret.Secret{held.AuthKey, held.PrivKey} {
		if strings.Trim(s.Reveal(), "\x00") != "" {
			t.Fatal("secret survived Wipe")
		}
	}
}
