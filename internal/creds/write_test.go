package creds_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/creds/credstest"
	"github.com/beekamai/network-scheme/internal/devices"
)

const writePassword = "write-pass-0123"

/* The read path never opens a write credential: asked for, or sealed inside a read profile. */
func TestOpenRefusesTheWriteKind(t *testing.T) {
	pub, priv := keys(t)
	login := map[string]string{"username": "admin", "password": writePassword}
	w := credstest.Seal(pub, dev1, creds.KindSSHWrite, login, t0)
	for name, kind := range map[string]string{"asked for ssh_write": creds.KindSSHWrite, "ssh_write inside an ssh_read profile": creds.KindSSHRead} {
		if _, err := creds.Open(priv, pub, w, dev1, kind, time.Time{}, t0); !errors.Is(err, creds.ErrKindMismatch) {
			t.Errorf("%s: %v", name, err)
		}
	}
	r := credstest.Seal(pub, dev1, creds.KindSSHRead, login, t0)
	if _, err := creds.OpenWrite(priv, pub, r, 1, time.Time{}, t0); !errors.Is(err, creds.ErrKindMismatch) {
		t.Errorf("ssh_read opened as a write credential: %v", err)
	}
}

func rsaPEM(t *testing.T, bits int) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
}

func TestOpenWrite(t *testing.T) {
	pub, priv := keys(t)
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := x509.MarshalECPrivateKey(ek)
	if err != nil {
		t.Fatal(err)
	}
	ecPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ec}))
	for name, tc := range map[string]struct {
		secret  map[string]string
		keyType string
		err     error
	}{
		"password":      {map[string]string{"username": "admin", "password": writePassword}, "", nil},
		"rsa 2048":      {map[string]string{"username": "admin", "private_key": rsaPEM(t, 2048)}, "ssh-rsa", nil},
		"ed25519":       {map[string]string{"username": "admin", "private_key": testPEM}, "ssh-ed25519", nil},
		"ecdsa":         {map[string]string{"username": "admin", "private_key": ecPEM}, "ecdsa-sha2-nistp256", nil},
		"rsa 1024":      {map[string]string{"username": "admin", "private_key": rsaPEM(t, 1024)}, "", creds.ErrWeak},
		"weak password": {map[string]string{"username": "admin", "password": "short-pass1"}, "", creds.ErrWeak},
		"both":          {map[string]string{"username": "admin", "password": writePassword, "private_key": testPEM}, "", creds.ErrMalformed},
		"control char":  {map[string]string{"username": "adm\x1bin", "password": writePassword}, "", creds.ErrMalformed},
	} {
		ct := credstest.Seal(pub, dev1, creds.KindSSHWrite, tc.secret, t0)
		c, err := creds.OpenWrite(priv, pub, ct, 1, time.Time{}, t0)
		if !errors.Is(err, tc.err) {
			t.Errorf("%s: %v, want %v", name, err, tc.err)
			continue
		}
		if err != nil {
			continue
		}
		if c.Kind != creds.KindSSHWrite || c.Owner != dev1 || !c.CreatedAt.Equal(t0) || len(c.Nonce) != 16 || c.KeyType != tc.keyType || c.Username != "admin" {
			t.Errorf("%s: %+v", name, c)
		}
		c.Wipe()
	}
}

/* The binding inside the ciphertext: another device, a scan, an older credential. */
func TestOpenWriteBinding(t *testing.T) {
	pub, priv := keys(t)
	login := map[string]string{"username": "admin", "password": writePassword}
	ct := credstest.Seal(pub, dev1, creds.KindSSHWrite, login, t0)
	if _, err := creds.OpenWrite(priv, pub, ct, 2, time.Time{}, t0); !errors.Is(err, creds.ErrOwnerMismatch) {
		t.Errorf("device 1 opened for 2: %v", err)
	}
	scan := credstest.Seal(pub, devices.Owner{Kind: devices.OwnerScan, ID: 1}, creds.KindSSHWrite, login, t0)
	if _, err := creds.OpenWrite(priv, pub, scan, 1, time.Time{}, t0); !errors.Is(err, creds.ErrOwnerMismatch) {
		t.Errorf("scan owner: %v", err)
	}
	if _, err := creds.OpenWrite(priv, pub, ct, 1, t0.Add(time.Second), t0); !errors.Is(err, creds.ErrStale) {
		t.Errorf("older than accepted: %v", err)
	}
	a, err := creds.OpenWrite(priv, pub, ct, 1, t0, t0)
	if err != nil {
		t.Fatalf("the stored one opened again: %v", err)
	}
	b, err := creds.OpenWrite(priv, pub, credstest.Seal(pub, dev1, creds.KindSSHWrite, login, t0), 1, t0, t0)
	if err != nil || bytes.Equal(a.Nonce, b.Nonce) {
		t.Fatalf("two seals share a nonce or fail: %v", err)
	}
}
