// Package creds defines the sealed read-credential payload and its verification by the poller.
package creds

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/secret"
)

/* Verification failures. Messages never contain payload content. */
var (
	ErrUndecryptable = errors.New("creds: cannot decrypt credential")
	ErrOwnerMismatch = errors.New("creds: credential is bound to another owner")
	ErrKindMismatch  = errors.New("creds: credential is of another kind")
	ErrStale         = errors.New("creds: credential is older than the last accepted one")
	ErrWeak          = errors.New("creds: credential secret is too weak")
	ErrMalformed     = errors.New("creds: malformed credential payload")
)

/* Credential kinds, as stored in the access profile. */
const (
	KindSNMP2c  = "snmp2c"
	KindSNMP3   = "snmp3"
	KindSSHRead = "ssh_read"
	KindTelnet  = "telnet_read"
)

const (
	payloadVersion = 1
	maxPlaintext   = 8 << 10
	nonceLen       = 16
	maxSkew        = 5 * time.Minute
	maxField       = 2048 /* bytes */
	maxPrivateKey  = 6 << 10
	maxUsername    = 64
	maxSNMPUser    = 32 /* USM limit */
	minSNMPSecret  = 16 /* characters */
	minPassword    = 12 /* characters */
)

var (
	authProtos = map[string]bool{"SHA224": true, "SHA256": true, "SHA384": true, "SHA512": true}
	privProtos = map[string]bool{"AES": true, "AES256": true}
)

/*
Credential is a verified read credential. Only the fields of its Kind are
set; every secret field is a secret.Secret and prints as "***".
*/
type Credential struct {
	Kind      string
	Owner     devices.Owner
	CreatedAt time.Time

	Community secret.Secret /* snmp2c */

	User      string /* snmp3 */
	AuthProto string /* SHA224|SHA256|SHA384|SHA512 */
	AuthKey   secret.Secret
	PrivProto string /* AES|AES256 */
	PrivKey   secret.Secret

	Username   string        /* ssh_read, telnet_read */
	Password   secret.Secret /* ssh_read (or key), telnet_read */
	PrivateKey secret.Secret /* ssh_read only */
}

/* envelope is the plaintext sealed by the browser. */
type envelope struct {
	V         int             `json:"v"`
	Owner     string          `json:"owner"`
	Kind      string          `json:"kind"`
	CreatedAt string          `json:"created_at"`
	Nonce     string          `json:"nonce"`
	Secret    json.RawMessage `json:"secret"`
}

type snmp2cSecret struct {
	Community *string `json:"community"`
}

type snmp3Secret struct {
	User      *string `json:"user"`
	AuthProto *string `json:"auth_proto"`
	AuthKey   *string `json:"auth_key"`
	PrivProto *string `json:"priv_proto"`
	PrivKey   *string `json:"priv_key"`
}

type loginSecret struct {
	Username   *string `json:"username"`
	Password   *string `json:"password"`
	PrivateKey *string `json:"private_key"`
}
