// Package crypto holds small authenticated-encryption helpers.
package crypto

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

/* ErrOpen is returned for any failure to open a box (no detail on purpose). */
var ErrOpen = errors.New("crypto: cannot open box")

/*
Seal encrypts plaintext with XChaCha20-Poly1305 and binds it to aad.
The random 24-byte nonce is prepended to the returned box.
*/
func Seal(key *[32]byte, plaintext, aad []byte) ([]byte, error) {
	a, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, a.NonceSize(), a.NonceSize()+len(plaintext)+a.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return a.Seal(nonce, nonce, plaintext, aad), nil
}

/* Open decrypts a box produced by Seal; aad must match the one used to seal. */
func Open(key *[32]byte, box, aad []byte) ([]byte, error) {
	a, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	if len(box) < a.NonceSize()+a.Overhead() {
		return nil, ErrOpen
	}
	pt, err := a.Open(nil, box[:a.NonceSize()], box[a.NonceSize():], aad)
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}
