/*
Package seal holds the executor's sealing key as three independent subkeys
derived with HKDF-SHA-256: enc (XChaCha20-Poly1305 of the change TOTP
secrets), mac (HMAC-SHA-256 of the registry rows) and state (MAC of the
state file). The sealing key itself is wiped as soon as they are derived.
*/
package seal

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"log/slog"
	"strconv"

	"golang.org/x/crypto/chacha20poly1305"

	nmsconfig "github.com/beekamai/network-scheme/internal/config"
)

/* Info labels: one per subkey, versioned, never reused for another purpose. */
const (
	infoEnc   = "nms/executor/v1/enc"
	infoMAC   = "nms/executor/v1/mac"
	infoState = "nms/executor/v1/state"
)

/*
Keys are the subkeys of the sealing key. They live in this one value so they
can be wiped together; accessors return pointers into it, never copies, and
every formatting and logging path prints "***". Wipe clears this value only:
copies made by their users (the ipad/opad state inside an HMAC, an AEAD's
key schedule) are not reachable from here.
*/
type Keys struct {
	enc, mac, state [32]byte
}

/* Derive derives the subkeys from the 32-byte sealing key; master is left untouched. */
func Derive(master *[32]byte) (*Keys, error) {
	k := new(Keys)
	for _, d := range []struct {
		info string
		dst  *[32]byte
	}{{infoEnc, &k.enc}, {infoMAC, &k.mac}, {infoState, &k.state}} {
		b, err := hkdf.Key(sha256.New, master[:], nil, d.info, len(d.dst))
		if err != nil {
			k.Wipe()
			return nil, err
		}
		copy(d.dst[:], b)
		clear(b)
	}
	return k, nil
}

/* Load reads the sealing key file, derives the subkeys and wipes the key. */
func Load(path string) (*Keys, error) {
	master, err := nmsconfig.ReadKeyFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(master[:])
	return Derive(master)
}

/* Enc is the XChaCha20-Poly1305 key of the change TOTP secrets. */
func (k *Keys) Enc() *[32]byte { return &k.enc }

/* MAC is the HMAC-SHA-256 key of the registry rows. */
func (k *Keys) MAC() *[32]byte { return &k.mac }

/* State is the HMAC-SHA-256 key of the state file. */
func (k *Keys) State() *[32]byte { return &k.state }

/* String, GoString and LogValue never render key material. */
func (*Keys) String() string { return "***" }

/* GoString implements fmt.GoStringer. */
func (*Keys) GoString() string { return "***" }

/* LogValue implements slog.LogValuer. */
func (*Keys) LogValue() slog.Value { return slog.StringValue("***") }

/* KeyVersion is the version of the sealing key the change TOTP secrets are sealed under (key_version of their registry rows). */
const KeyVersion = 1

/* totpAAD binds a change TOTP secret to its user and key version (security.md 5.2). */
func totpAAD(userID int64, keyVersion int32) []byte {
	return []byte(strconv.FormatInt(userID, 10) + "|change-totp|" + strconv.FormatInt(int64(keyVersion), 10))
}

/*
SealTOTP encrypts a change TOTP secret with XChaCha20-Poly1305 under enc,
AAD = "user_id|change-totp|key_version": a random nonce, then the ciphertext.
A ciphertext moved to another user (even with a valid row MAC) does not open.
*/
func (k *Keys) SealTOTP(userID int64, keyVersion int32, secret []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(k.enc[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(secret)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, secret, totpAAD(userID, keyVersion)), nil
}

/* OpenTOTP decrypts a change TOTP secret sealed for userID and keyVersion; any other binding fails. */
func (k *Keys) OpenTOTP(userID int64, keyVersion int32, ct []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(k.enc[:])
	if err != nil {
		return nil, err
	}
	if len(ct) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("seal: change TOTP ciphertext too short")
	}
	pt, err := aead.Open(nil, ct[:aead.NonceSize()], ct[aead.NonceSize():], totpAAD(userID, keyVersion))
	if err != nil {
		return nil, errors.New("seal: change TOTP ciphertext does not open for this user")
	}
	return pt, nil
}

/* Wipe zeroes every subkey; the Keys are unusable afterwards. */
func (k *Keys) Wipe() {
	clear(k.enc[:])
	clear(k.mac[:])
	clear(k.state[:])
}
