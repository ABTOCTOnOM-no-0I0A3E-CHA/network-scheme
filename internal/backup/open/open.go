/*
Package open decrypts what backup.Seal produced. It needs the private key of
the backup domain, which only the executor (and tests) hold: cmd/poller and
cmd/api must never depend on this package (checked by a test).
*/
package open

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"
)

/* Open returns the plaintext of ct (nonce||ciphertext) whose data key is sealed in dekCT, failing unless aad matches the one used to seal. */
func Open(priv, pub *[32]byte, ct, dekCT, aad []byte) ([]byte, error) {
	dek, ok := box.OpenAnonymous(nil, dekCT, pub, priv)
	if !ok {
		return nil, errors.New("backup: cannot open the data key")
	}
	defer clear(dek)
	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, fmt.Errorf("backup: %w", err)
	}
	if len(ct) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("backup: ciphertext too short")
	}
	pt, err := aead.Open(nil, ct[:aead.NonceSize()], ct[aead.NonceSize():], aad)
	if err != nil {
		return nil, errors.New("backup: authentication failed")
	}
	return pt, nil
}
