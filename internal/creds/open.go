package creds

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/ssh"

	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/secret"
)

/*
Open decrypts a sealed-box credential with the read-domain key pair and
verifies it: strict payload format, binding to want and kind, and a
created_at strictly newer than lastAccepted (zero when none was accepted)
and not later than now+5m.
Checks run in the order malformed, owner, kind, stale, secret shape, weak.
Returned errors never contain secret material.
*/
func Open(priv, pub *[32]byte, ciphertext []byte, want devices.Owner, kind string, lastAccepted, now time.Time) (Credential, error) {
	pt, ok := box.OpenAnonymous(nil, ciphertext, pub, priv)
	if !ok {
		return Credential{}, ErrUndecryptable
	}
	defer clear(pt)
	if len(pt) > maxPlaintext {
		return Credential{}, ErrMalformed
	}
	var env envelope
	if err := decodeStrict(pt, &env); err != nil || env.V != payloadVersion {
		return Credential{}, ErrMalformed
	}
	owner, ok := parseOwner(env.Owner)
	if !ok || !validKind(env.Kind) {
		return Credential{}, ErrMalformed
	}
	createdAt, err := time.Parse(time.RFC3339, env.CreatedAt)
	if err != nil || createdAt.After(now.Add(maxSkew)) {
		return Credential{}, ErrMalformed
	}
	if n, err := base64.StdEncoding.DecodeString(env.Nonce); err != nil || len(n) != nonceLen {
		return Credential{}, ErrMalformed
	}
	if owner != want {
		return Credential{}, ErrOwnerMismatch
	}
	if env.Kind != kind {
		return Credential{}, ErrKindMismatch
	}
	if !createdAt.After(lastAccepted) {
		return Credential{}, ErrStale
	}
	c := Credential{Kind: env.Kind, Owner: owner, CreatedAt: createdAt}
	if err := c.fill(env.Secret); err != nil {
		return Credential{}, err
	}
	return c, nil
}

func validKind(k string) bool {
	return k == KindSNMP2c || k == KindSNMP3 || k == KindSSHRead || k == KindTelnet
}

/* decodeStrict rejects unknown fields and trailing data. */
func decodeStrict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrMalformed
	}
	return nil
}

/* parseOwner accepts only the canonical "device:<id>" / "scan:<id>" with id > 0. */
func parseOwner(s string) (devices.Owner, bool) {
	k, idStr, ok := strings.Cut(s, ":")
	if !ok || (k != devices.OwnerDevice && k != devices.OwnerScan) {
		return devices.Owner{}, false
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 || strconv.FormatInt(id, 10) != idStr {
		return devices.Owner{}, false
	}
	return devices.Owner{Kind: k, ID: id}, true
}

/* clean reports whether s has no C0 control characters or DEL. */
func clean(s string, allowNL bool) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if allowNL && (c == '\n' || c == '\r') {
			continue
		}
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

/* okStr reports whether *p is set, non-empty, control-free and at most limit bytes. */
func okStr(p *string, limit int) bool {
	return p != nil && *p != "" && len(*p) <= limit && clean(*p, false)
}

func short(s string, n int) bool { return utf8.RuneCountInString(s) < n }

/* fill decodes and validates the kind-specific secret object into c. */
func (c *Credential) fill(raw json.RawMessage) error {
	switch c.Kind {
	case KindSNMP2c:
		var s snmp2cSecret
		if decodeStrict(raw, &s) != nil || !okStr(s.Community, maxField) {
			return ErrMalformed
		}
		if short(*s.Community, minSNMPSecret) {
			return ErrWeak
		}
		c.Community = secret.New(*s.Community)
	case KindSNMP3:
		var s snmp3Secret
		if decodeStrict(raw, &s) != nil || !okStr(s.User, maxSNMPUser) ||
			s.AuthProto == nil || !authProtos[*s.AuthProto] ||
			s.PrivProto == nil || !privProtos[*s.PrivProto] ||
			!okStr(s.AuthKey, maxField) || !okStr(s.PrivKey, maxField) {
			return ErrMalformed
		}
		if short(*s.AuthKey, minSNMPSecret) || short(*s.PrivKey, minSNMPSecret) {
			return ErrWeak
		}
		c.User, c.AuthProto, c.PrivProto = *s.User, *s.AuthProto, *s.PrivProto
		c.AuthKey, c.PrivKey = secret.New(*s.AuthKey), secret.New(*s.PrivKey)
	default: /* ssh_read, telnet_read */
		var s loginSecret
		if decodeStrict(raw, &s) != nil || !okStr(s.Username, maxUsername) {
			return ErrMalformed
		}
		hasPw := s.Password != nil && *s.Password != ""
		hasKey := s.PrivateKey != nil && *s.PrivateKey != ""
		if s.Password != nil && !hasPw || s.PrivateKey != nil && !hasKey || hasPw == hasKey ||
			(hasKey && c.Kind != KindSSHRead) {
			return ErrMalformed
		}
		if hasPw && !okStr(s.Password, maxField) {
			return ErrMalformed
		}
		if hasKey {
			/* PEM needs line breaks; nothing else is allowed, and it must parse. */
			if len(*s.PrivateKey) > maxField || !clean(*s.PrivateKey, true) {
				return ErrMalformed
			}
			if _, err := ssh.ParseRawPrivateKey([]byte(*s.PrivateKey)); err != nil {
				return ErrMalformed
			}
		}
		if hasPw && short(*s.Password, minPassword) {
			return ErrWeak
		}
		c.Username = *s.Username
		if hasPw {
			c.Password = secret.New(*s.Password)
		} else {
			c.PrivateKey = secret.New(*s.PrivateKey)
		}
	}
	return nil
}
