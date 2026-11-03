/*
Package ticket is the session ticket the api issues to a logged-in panel
user and the executor verifies (security.md 5.2). v1 is {v, aud "executor",
user_id, username, iat, exp = iat + 60 s, nonce of 16 bytes}, signed with
Ed25519: the api holds the private key and only signs, the executor holds
the public key and only verifies. A ticket is the api's claim about who the
user is, nothing more: rights come from the executor's registry and every
action also needs the user's change TOTP. No write code lives here.

Wire form: base64url(payload) "." base64url(signature), both unpadded. The
payload is the canonical JSON of the claims (the fields in this order, no
whitespace, as encoding/json writes them); the signature covers a domain
label and the payload. Parse checks the signature before it decodes
anything and accepts only a payload that encodes back to exactly the same
bytes, so duplicate or unknown keys, another key order, whitespace, other
number forms and alternative string escapes are all refused; a token is at
most MaxLen bytes.
*/
package ticket

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

/* The parameters of ticket v1. */
const (
	Version   = 1
	Audience  = "executor"
	TTL       = 60 * time.Second
	Skew      = 5 * time.Second /* how far in the future iat may be (the api and the executor share the host's clock) */
	NonceSize = 16
	MaxLen    = 1024
	/* MaxUsername is the longest name a registry snapshot holds (characters). */
	MaxUsername = 64
)

/* domain separates ticket signatures from anything else the key could sign. */
const domain = "nms/ticket/v1\x00"

/* ErrInvalid is the root of every refusal; Error says why. */
var ErrInvalid = errors.New("ticket: invalid")

/* Error is a refused ticket; Reason is a short class for the audit (never the token). */
type Error struct{ Reason string }

func (e *Error) Error() string { return "ticket: " + e.Reason }

/* Is makes every Error match ErrInvalid. */
func (e *Error) Is(target error) bool { return target == ErrInvalid }

func refuse(reason string) error { return &Error{Reason: reason} }

/* Claims are the fields of a ticket; times are Unix seconds. */
type Claims struct {
	V        int
	Aud      string
	UserID   int64
	Username string
	IssuedAt int64
	Expires  int64
	Nonce    [NonceSize]byte
}

/* ID names the ticket in both audit chains: a prefix of the SHA-256 of its nonce (correlates them without carrying the token). */
func (c Claims) ID() string {
	h := sha256.Sum256(c.Nonce[:])
	return hex.EncodeToString(h[:6])
}

/* wire is the payload: the field order here is the canonical order. */
type wire struct {
	V        int    `json:"v"`
	Aud      string `json:"aud"`
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	IAT      int64  `json:"iat"`
	EXP      int64  `json:"exp"`
	Nonce    string `json:"nonce"`
}

var b64 = base64.RawURLEncoding.Strict()

/* encode is the canonical payload of c. */
func encode(c Claims) ([]byte, error) {
	return json.Marshal(wire{V: c.V, Aud: c.Aud, UserID: c.UserID, Username: c.Username, IAT: c.IssuedAt, EXP: c.Expires,
		Nonce: b64.EncodeToString(c.Nonce[:])})
}

/*
decode reads a payload strictly: one JSON object of exactly the wire fields,
nothing after it, and only the bytes encode writes for the result.
*/
func decode(payload []byte) (Claims, error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	var w wire
	if err := dec.Decode(&w); err != nil {
		return Claims{}, refuse("encoding")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Claims{}, refuse("encoding")
	}
	n, err := b64.DecodeString(w.Nonce)
	if err != nil || len(n) != NonceSize {
		return Claims{}, refuse("encoding")
	}
	c := Claims{V: w.V, Aud: w.Aud, UserID: w.UserID, Username: w.Username, IssuedAt: w.IAT, Expires: w.EXP}
	copy(c.Nonce[:], n)
	again, err := encode(c)
	if err != nil || !bytes.Equal(again, payload) {
		return Claims{}, refuse("encoding")
	}
	return c, nil
}

/* ValidUsername reports whether name can be carried by a ticket: valid UTF-8, 1..MaxUsername characters, no control or format characters. */
func ValidUsername(name string) bool {
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > MaxUsername {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return false
		}
	}
	return true
}

/* check validates the fields of c that do not depend on time. */
func (c Claims) check() error {
	switch {
	case c.V != Version:
		return refuse("version")
	case c.Aud != Audience:
		return refuse("audience")
	case c.UserID <= 0 || !ValidUsername(c.Username):
		return refuse("fields")
	case c.Expires-c.IssuedAt != int64(TTL/time.Second):
		return refuse("lifetime")
	}
	return nil
}

/*
Sign encodes and signs c as it is, without checking it (the api uses Issue;
tests forge tickets with it).
*/
func Sign(priv ed25519.PrivateKey, c Claims) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("ticket: bad signing key")
	}
	payload, err := encode(c)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, append([]byte(domain), payload...))
	tok := b64.EncodeToString(payload) + "." + b64.EncodeToString(sig)
	if len(tok) > MaxLen {
		return "", errors.New("ticket: too long")
	}
	return tok, nil
}

/* Issue signs a fresh ticket v1 for a user at now, with a random nonce. */
func Issue(priv ed25519.PrivateKey, userID int64, username string, now time.Time) (string, Claims, error) {
	c := Claims{V: Version, Aud: Audience, UserID: userID, Username: username, IssuedAt: now.Unix(),
		Expires: now.Unix() + int64(TTL/time.Second)}
	if _, err := rand.Read(c.Nonce[:]); err != nil {
		return "", Claims{}, err
	}
	if err := c.check(); err != nil {
		return "", Claims{}, err
	}
	tok, err := Sign(priv, c)
	return tok, c, err
}

/*
Parse checks the token's size, form and signature, then decodes the payload
strictly and checks every field but the times. The signature is checked
before any JSON is read.
*/
func Parse(pub ed25519.PublicKey, token string) (Claims, error) {
	if len(pub) != ed25519.PublicKeySize {
		return Claims{}, errors.New("ticket: bad verification key")
	}
	if len(token) > MaxLen {
		return Claims{}, refuse("oversize")
	}
	p, s, ok := strings.Cut(token, ".")
	if !ok || strings.Contains(s, ".") {
		return Claims{}, refuse("malformed")
	}
	payload, err := b64.DecodeString(p)
	if err != nil {
		return Claims{}, refuse("malformed")
	}
	sig, err := b64.DecodeString(s)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Claims{}, refuse("malformed")
	}
	if !ed25519.Verify(pub, append([]byte(domain), payload...), sig) {
		return Claims{}, refuse("signature")
	}
	c, err := decode(payload)
	if err != nil {
		return Claims{}, err
	}
	return c, c.check()
}

/*
Verify is Parse plus the times: now must be before exp and iat at most
Skew ahead of now. The executor adds its own checks (issued after its start,
nonce never seen before).
*/
func Verify(pub ed25519.PublicKey, token string, now time.Time) (Claims, error) {
	c, err := Parse(pub, token)
	if err != nil {
		return Claims{}, err
	}
	switch t := now.Unix(); {
	case t >= c.Expires:
		return Claims{}, refuse("expired")
	case c.IssuedAt > t+int64(Skew/time.Second):
		return Claims{}, refuse("future")
	}
	return c, nil
}
