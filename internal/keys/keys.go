// Package keys generates domain keys (X25519) and renders the public keys.json.
package keys

import (
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
			KeyVersion:  1,
			PublicKey:   base64.StdEncoding.EncodeToString(pub[:]),
			Fingerprint: Fingerprint(pub),
		}
	}
	return json.Marshal(doc)
}
