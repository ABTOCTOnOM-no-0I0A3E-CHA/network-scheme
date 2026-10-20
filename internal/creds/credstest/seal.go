// Package credstest seals read credentials exactly as the browser does.
package credstest

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/beekamai/network-scheme/internal/devices"
)

/*
Seal builds the credential payload for owner and kind with a fresh nonce and
seals it for pub (libsodium crypto_box_seal). secret is marshalled as-is, so
callers pass plain maps or structs, not secret.Secret values. It panics on
failure: it is a test helper.
*/
func Seal(pub *[32]byte, owner devices.Owner, kind string, secret any, createdAt time.Time) []byte {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	pt, err := json.Marshal(map[string]any{
		"v":          1,
		"owner":      fmt.Sprintf("%s:%d", owner.Kind, owner.ID),
		"kind":       kind,
		"created_at": createdAt.UTC().Format(time.RFC3339),
		"nonce":      base64.StdEncoding.EncodeToString(nonce),
		"secret":     secret,
	})
	if err != nil {
		panic(err)
	}
	ct, err := box.SealAnonymous(nil, pt, pub, rand.Reader)
	if err != nil {
		panic(err)
	}
	return ct
}
