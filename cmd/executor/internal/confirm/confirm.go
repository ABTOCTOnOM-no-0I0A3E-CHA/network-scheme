/*
Package confirm is the executor's confirmation primitive confirm(H)
(security.md 5.2, D6). For an action that needs the user's explicit
confirmation the executor issues a challenge {challenge_id, action, H},
H = SHA-256 of the canonical description of the action, and shows the
description on its own origin; it then runs the action only on
(challenge_id, H, TOTP) with that same H, once, within 2 minutes, for the
user and the grant the challenge was issued for (authz decides ticket, grant
and TOTP). A description changed after it was shown changes H. The package
knows nothing about the actions themselves.

The canonical description is length-prefixed: the domain label, the action,
the number of fields, then each key and value, every string preceded by its
length as a 32-bit big-endian integer. Keys are strictly increasing, so one
description has exactly one encoding and no two descriptions share one.
*/
package confirm

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/beekamai/network-scheme/cmd/executor/internal/audit"
	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
)

/* Bounds of a description and of the pending challenges. */
const (
	TTL            = 2 * time.Minute
	maxFields      = 256
	maxValue       = 64 << 10
	maxDescription = 1 << 20
	maxPending     = 4096
	maxPerUser     = 16
)

const domain = "nms/confirm/v1"

var (
	actionRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,55}$`) /* "confirm." + action is an audit action */
	keyRe    = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
)

/* Field is one line of a description: what is shown as Key: Value. */
type Field struct{ Key, Value string }

/* Description is what the user confirms: the action and its fields, keys strictly increasing. */
type Description struct {
	Action string
	Fields []Field
}

/*
displayable: valid UTF-8 without control (C0, C1) or format characters
(Cf: bidirectional overrides and isolates, zero-width characters), so what
the user is shown is what H covers, character for character.
*/
func displayable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return false
		}
	}
	return true
}

/* Validate checks the action, the keys (strictly increasing) and the values (displayable UTF-8, bounded). */
func (d Description) Validate() error {
	if !actionRe.MatchString(d.Action) {
		return fmt.Errorf("confirm: bad action %q", d.Action)
	}
	if len(d.Fields) > maxFields {
		return errors.New("confirm: too many fields")
	}
	total := len(d.Action)
	for i, f := range d.Fields {
		if !keyRe.MatchString(f.Key) || (i > 0 && f.Key <= d.Fields[i-1].Key) {
			return fmt.Errorf("confirm: bad or unordered key %q", f.Key)
		}
		if len(f.Value) > maxValue || !displayable(f.Value) {
			return fmt.Errorf("confirm: bad value of %q", f.Key)
		}
		total += len(f.Key) + len(f.Value)
	}
	if total > maxDescription {
		return errors.New("confirm: description too large")
	}
	return nil
}

func appendString(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s))) // #nosec G115 -- lengths are bounded by Validate
	return append(b, s...)
}

/* Canonical is the encoding H is computed over. */
func (d Description) Canonical() ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	b := appendString(nil, domain)
	b = appendString(b, d.Action)
	b = binary.BigEndian.AppendUint32(b, uint32(len(d.Fields))) // #nosec G115 -- at most maxFields
	for _, f := range d.Fields {
		b = appendString(appendString(b, f.Key), f.Value)
	}
	return b, nil
}

/* Hash is H, the SHA-256 of the canonical description. */
func (d Description) Hash() ([32]byte, error) {
	c, err := d.Canonical()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(c), nil
}

/* decode is the strict inverse of Canonical (it proves the encoding injective in the tests). */
func decode(b []byte) (Description, error) {
	bad := errors.New("confirm: not a canonical description")
	next := func() (string, bool) {
		if len(b) < 4 {
			return "", false
		}
		n := binary.BigEndian.Uint32(b)
		if uint64(n) > uint64(len(b)-4) { // #nosec G115 -- len(b) >= 4 here
			return "", false
		}
		s := string(b[4 : 4+n])
		b = b[4+n:]
		return s, true
	}
	if dom, ok := next(); !ok || dom != domain {
		return Description{}, bad
	}
	var d Description
	var ok bool
	if d.Action, ok = next(); !ok || len(b) < 4 {
		return Description{}, bad
	}
	n := binary.BigEndian.Uint32(b)
	b = b[4:]
	if n > maxFields {
		return Description{}, bad
	}
	for range n {
		var f Field
		if f.Key, ok = next(); !ok {
			return Description{}, bad
		}
		if f.Value, ok = next(); !ok {
			return Description{}, bad
		}
		d.Fields = append(d.Fields, f)
	}
	if len(b) != 0 || d.Validate() != nil {
		return Description{}, bad
	}
	return d, nil
}

/* Challenge is what the executor shows: its id, the action, H and the description H covers. */
type Challenge struct {
	ID          string
	Action      string
	H           [32]byte
	Description Description
	User        int64
	Expires     time.Time
}

type pending struct {
	c    Challenge
	need authz.Need
}

/* Store holds the pending challenges of this process (none survives a restart: fail closed). */
type Store struct {
	auth *authz.Authorizer
	now  func() time.Time

	mu      sync.Mutex
	pending map[string]pending
}

/* New returns an empty Store deciding through a; now nil is time.Now. */
func New(a *authz.Authorizer, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{auth: a, now: now, pending: map[string]pending{}}
}

/* ErrTooMany refuses a challenge while too many are pending (for the user or in all). */
var ErrTooMany = errors.New("confirm: too many pending confirmations")

/*
Issue registers a challenge for user to confirm d with need (the grant the
action requires, decided by the executor's code, never by the client).
*/
func (s *Store) Issue(user int64, need authz.Need, d Description) (Challenge, error) {
	if user <= 0 || !need.Valid() {
		return Challenge{}, errors.New("confirm: bad user or grant")
	}
	h, err := d.Hash()
	if err != nil {
		return Challenge{}, err
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return Challenge{}, err
	}
	now := s.now()
	c := Challenge{ID: base64.RawURLEncoding.EncodeToString(id[:]), Action: d.Action, H: h, User: user, Expires: now.Add(TTL),
		Description: Description{Action: d.Action, Fields: append([]Field(nil), d.Fields...)}}
	s.mu.Lock()
	defer s.mu.Unlock()
	mine := 0
	for k, p := range s.pending {
		if !now.Before(p.c.Expires) {
			delete(s.pending, k)
		} else if p.c.User == user {
			mine++
		}
	}
	if mine >= maxPerUser || len(s.pending) >= maxPending {
		return Challenge{}, ErrTooMany
	}
	s.pending[c.ID] = pending{c: c, need: need}
	return c, nil
}

/*
Discard drops challenge id unconfirmed (its line was dropped by the user,
refused or its connection ended): it can no longer be confirmed and stops
counting against the user's pending limit.
*/
func (s *Store) Discard(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pending, id)
}

/*
Action returns the action of the pending challenge id without spending it
(web routes a challenge to the only route that may confirm it).
*/
func (s *Store) Action(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[id]
	return p.c.Action, ok
}

/*
Confirm runs the confirmation of challenge id with hash h: the challenge is
spent by this attempt whatever its outcome (one-time), it must not have
expired, h must be its H, and then authz decides req as the challenge's
user with the challenge's grant (req.User, req.Need and req.Action are
overwritten). A refusal before authz is audited here; authz audits the rest.
*/
func (s *Store) Confirm(ctx context.Context, id string, h []byte, req authz.Request) (Challenge, authz.Decision, error) {
	now := s.now()
	s.mu.Lock()
	p, ok := s.pending[id]
	delete(s.pending, id)
	s.mu.Unlock()
	ev := audit.Event{IP: req.IP, UA: req.UA, Action: "confirm.challenge", Object: "challenge", Result: audit.Denied,
		Details: map[string]any{}}
	switch {
	case !ok:
		ev.Details["class"] = "unknown_challenge"
	case !now.Before(p.c.Expires):
		ev.Details["class"] = "challenge_expired"
	case subtle.ConstantTimeCompare(h, p.c.H[:]) != 1:
		ev.Details["class"] = "h_mismatch"
	default:
		req.User, req.Need, req.Action = p.c.User, p.need, "confirm."+p.c.Action
		if req.Object == "" {
			req.Object = "challenge"
		}
		details := map[string]any{}
		for k, v := range req.Details {
			details[k] = v
		}
		details["challenge"], details["h"] = id, hex.EncodeToString(p.c.H[:])
		req.Details = details
		dec, err := s.auth.Authorize(ctx, req)
		return p.c, dec, err
	}
	if ok {
		user := p.c.User
		ev.UserID, ev.Action = &user, "confirm."+p.c.Action
		ev.Details["challenge"], ev.Details["h"] = id, hex.EncodeToString(p.c.H[:])
	}
	s.auth.Record(ctx, ev)
	return Challenge{}, authz.Decision{}, authz.ErrDenied
}
