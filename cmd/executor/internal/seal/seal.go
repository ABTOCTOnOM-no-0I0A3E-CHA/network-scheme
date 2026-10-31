/*
Package seal holds the executor's sealing key as three independent subkeys
derived with HKDF-SHA-256: enc (XChaCha20-Poly1305 of the change TOTP
secrets), mac (HMAC-SHA-256 of the registry rows) and state (MAC of the
state file). The sealing key itself is wiped as soon as they are derived.
*/
package seal

import (
	"crypto/hkdf"
	"crypto/sha256"
	"log/slog"

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

/* Wipe zeroes every subkey; the Keys are unusable afterwards. */
func (k *Keys) Wipe() {
	clear(k.enc[:])
	clear(k.mac[:])
	clear(k.state[:])
}
