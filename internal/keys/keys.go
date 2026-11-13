// Package keys generates domain keys (X25519) and renders the public keys.json.
package keys

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/nacl/box"
)

// InitialKeyVersion is the key_version of every domain key generated at install.
const InitialKeyVersion = 1

/* domains is the exact set of key domains keys.json must contain. */
var domains = []string{"backup", "read", "write"}

// DomainKey is an X25519 key pair for one key domain.
type DomainKey struct {
	Public, Private [32]byte
}

// NewDomainKey generates a fresh X25519 key pair.
func NewDomainKey() (DomainKey, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return DomainKey{}, fmt.Errorf("generate domain key: %w", err)
	}
	return DomainKey{Public: *pub, Private: *priv}, nil
}

// NewSymmetricKey returns 32 random bytes from the system CSPRNG.
func NewSymmetricKey() ([32]byte, error) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return [32]byte{}, fmt.Errorf("generate symmetric key: %w", err)
	}
	return k, nil
}

// Fingerprint returns the first 16 bytes of SHA-256(pub) as hex in groups of four separated by ':'.
func Fingerprint(pub [32]byte) string {
	sum := sha256.Sum256(pub[:])
	h := hex.EncodeToString(sum[:16])
	parts := make([]string, 0, 8)
	for i := 0; i < len(h); i += 4 {
		parts = append(parts, h[i:i+4])
	}
	return strings.Join(parts, ":")
}

// PublicDomain is the public part of one domain key as published in keys.json.
type PublicDomain struct {
	KeyVersion  int    `json:"key_version"`
	PublicKey   string `json:"public_key"` /* base64 std */
	Fingerprint string `json:"fingerprint"`
}

// KeysJSON is the document delivered to browsers by the gateway; it never contains private keys.
type KeysJSON struct { //nolint:revive // name fixed by the interface contract
	Version int                     `json:"version"`
	Domains map[string]PublicDomain `json:"domains"`
}

// BuildKeysJSON renders keys.json for exactly the domains read, write and backup.
// encoding/json sorts map keys, so the output is deterministic.
func BuildKeysJSON(pubs map[string][32]byte) ([]byte, error) {
	if len(pubs) != len(domains) {
		return nil, fmt.Errorf("keys.json requires exactly domains %v", domains)
	}
	doc := KeysJSON{Version: 1, Domains: make(map[string]PublicDomain, len(domains))}
	for _, d := range domains {
		pub, ok := pubs[d]
		if !ok {
			return nil, fmt.Errorf("missing domain %q", d)
		}
		if pub == ([32]byte{}) {
			return nil, errors.New("zero public key for domain " + d)
		}
		doc.Domains[d] = PublicDomain{
			KeyVersion:  InitialKeyVersion,
			PublicKey:   base64.StdEncoding.EncodeToString(pub[:]),
			Fingerprint: Fingerprint(pub),
		}
	}
	return json.Marshal(doc)
}

/* PublicOf is the X25519 public key of the private key priv. */
func PublicOf(priv *[32]byte) ([32]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(priv[:])
	if err != nil {
		return [32]byte{}, err
	}
	return [32]byte(k.PublicKey().Bytes()), nil
}

/* ErrNotSealedToKey means a ciphertext does not open under the key a re-seal was given. */
var ErrNotSealedToKey = errors.New("keys: ciphertext does not open under this key")

/*
Reseal opens the anonymous sealed box ct with the private key priv and seals
its plaintext, unchanged, to the public key next (a domain key rotation);
the plaintext is wiped.
*/
func Reseal(ct []byte, priv, next *[32]byte) ([]byte, error) {
	pub, err := PublicOf(priv)
	if err != nil {
		return nil, err
	}
	pt, ok := box.OpenAnonymous(nil, ct, &pub, priv)
	if !ok {
		return nil, ErrNotSealedToKey
	}
	defer clear(pt)
	return box.SealAnonymous(nil, pt, next, rand.Reader)
}

/*
Rotate returns the keys.json doc with domain's public key replaced by pub at
the next key version, and that version. doc must be a keys.json of exactly
the three domains.
*/
func Rotate(doc []byte, domain string, pub [32]byte) ([]byte, int, error) {
	var k KeysJSON
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&k); err != nil || k.Version != 1 || len(k.Domains) != len(domains) {
		return nil, 0, errors.New("keys.json: malformed")
	}
	cur, ok := k.Domains[domain]
	if !ok || cur.KeyVersion < InitialKeyVersion {
		return nil, 0, fmt.Errorf("keys.json: no domain %q", domain)
	}
	v := cur.KeyVersion + 1
	k.Domains[domain] = PublicDomain{KeyVersion: v, PublicKey: base64.StdEncoding.EncodeToString(pub[:]), Fingerprint: Fingerprint(pub)}
	out, err := json.Marshal(k)
	return out, v, err
}

/* Published reports the key version under which keys.json doc publishes pub for domain (0: it does not). */
func Published(doc []byte, domain string, pub [32]byte) int {
	var k KeysJSON
	if json.Unmarshal(doc, &k) != nil || k.Domains[domain].PublicKey != base64.StdEncoding.EncodeToString(pub[:]) {
		return 0
	}
	return k.Domains[domain].KeyVersion
}
