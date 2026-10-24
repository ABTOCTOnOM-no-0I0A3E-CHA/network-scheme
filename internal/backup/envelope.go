/*
Package backup seals device configurations for storage. The full copy of a
configuration is encrypted under a random data key (XChaCha20-Poly1305) and
that key is sealed to the public key of the backup domain. The poller and the
api know only the public key, so neither can open what the poller stored; the
private key belongs to the (future) executor. The opening side lives in
backup/open, which no production binary but the executor may import.
*/
package backup

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"
)

/* AAD returns the associated data that binds a ciphertext to its device and normalized hash: "device:<id>|<hex sha256>". */
func AAD(deviceID int64, sha256Hex string) []byte {
	return fmt.Appendf(nil, "device:%d|%s", deviceID, sha256Hex)
}

/*
Seal encrypts plaintext under a fresh random 32-byte data key and returns
nonce||ciphertext (24-byte random nonce first) and the data key sealed to pub
(NaCl anonymous sealed box). aad is authenticated, not encrypted. The data key
is zeroed before return and so is plaintext: the caller must not use it after
Seal, whatever the outcome.
*/
func Seal(pub *[32]byte, plaintext, aad []byte) (ct, dekCT []byte, err error) {
	defer clear(plaintext)
	if pub == nil {
		return nil, nil, errors.New("backup: no public key")
	}
	dek := make([]byte, chacha20poly1305.KeySize)
	defer clear(dek)
	if _, err := rand.Read(dek); err != nil {
		return nil, nil, fmt.Errorf("backup: random key: %w", err)
	}
	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, nil, fmt.Errorf("backup: %w", err)
	}
	out := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(out); err != nil {
		return nil, nil, fmt.Errorf("backup: random nonce: %w", err)
	}
	ct = aead.Seal(out, out[:aead.NonceSize()], plaintext, aad)
	dekCT, err = box.SealAnonymous(nil, dek, pub, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("backup: seal key: %w", err)
	}
	return ct, dekCT, nil
}
