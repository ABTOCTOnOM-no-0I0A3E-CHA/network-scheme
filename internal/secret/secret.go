// Package secret provides a value type that never renders its content.
package secret

import (
	"crypto/sha256"
	"crypto/subtle"
	"log/slog"
)

const mask = "***"

/*
Secret holds a sensitive value. Every formatting, JSON and logging path
yields "***"; the content is only available through Reveal.
*/
type Secret struct {
	v []byte
}

// New wraps s as a Secret.
func New(s string) Secret { return Secret{v: []byte(s)} }

// Reveal returns the underlying value. Use only at the point of consumption.
func (s Secret) Reveal() string { return string(s.v) }

// IsZero reports whether the Secret holds no value.
func (s Secret) IsZero() bool { return len(s.v) == 0 }

// String implements fmt.Stringer and always returns "***".
func (Secret) String() string { return mask }

// GoString implements fmt.GoStringer and always returns "***".
func (Secret) GoString() string { return mask }

// MarshalJSON always encodes the Secret as the string "***".
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + mask + `"`), nil }

// LogValue implements slog.LogValuer and always yields "***".
func (Secret) LogValue() slog.Value { return slog.StringValue(mask) }

/*
Wipe overwrites the value's bytes with zeros, for every copy of this Secret
(copies share them). Strings already obtained through Reveal are not
affected.
*/
func (s Secret) Wipe() { clear(s.v) }

/*
EqualString reports whether the Secret equals v, without creating a string of
the secret. It compares SHA-256 digests in constant time, so neither the
content nor the length of the secret leaks through timing. An empty Secret
equals nothing.
*/
func (s Secret) EqualString(v string) bool {
	if len(s.v) == 0 {
		return false
	}
	a, b := sha256.Sum256(s.v), sha256.Sum256([]byte(v))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}
