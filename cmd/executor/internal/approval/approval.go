/*
Package approval holds the approvals of a second person (security.md 5.4
D4, D5) in the executor's memory only: an author's request (a changeset its
author confirmed, a change session asked for) waits second_person_minutes
for another user's confirmation of the same H, and is then taken once. A
restart forgets every approval (fail closed, as the challenges of confirm);
the rows the executor writes about them are history, never the ground for a
decision. The package decides only identity, H, time and use: who may
approve what (grants, the description) is the caller's.
*/
package approval

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
)

/* Refusal is an approval refused, with the code the UI has a text for (web: 422). */
type Refusal string

/* Error and RefusalCode make a Refusal an error with a code (web.Refusal). */
func (r Refusal) Error() string { return "approval: refused (" + string(r) + ")" }

/* RefusalCode is the code the UI has a text for. */
func (r Refusal) RefusalCode() string { return string(r) }

/* Refusals. */
const (
	ErrSecondPerson Refusal = "second_person_required" /* not approved (yet) by a second person */
	ErrSamePerson   Refusal = "same_person"            /* the second person is the author */
	ErrExpired      Refusal = "approval_expired"       /* unknown, expired, already used or forgotten by a restart */
	ErrMismatch     Refusal = "approval_mismatch"      /* another user, object or set of devices */
	ErrH            Refusal = "h_mismatch"             /* the second person confirmed another description */
	ErrTooMany      Refusal = "too_many_approvals"
)

/* Bounds of the pending approvals. */
const (
	maxPerUser = 16
	maxAll     = 4096
)

/* Approval is one request of an author and, once given, the second person's approval. */
type Approval struct {
	ID        string
	Kind      string /* changeset, session */
	User      int64  /* the author */
	Username  string
	Object    string /* what it is for, e.g. changeset:<id> or devices:1,2 */
	Groups    []string
	H         [32]byte
	Challenge string /* the author's confirmation, for the history */
	Expires   time.Time

	By       int64 /* the second person, once approved */
	ByName   string
	ByChal   string
	Approved bool
}

/* Store holds the approvals of this process. */
type Store struct {
	now func() time.Time
	mu  sync.Mutex
	m   map[string]*Approval
}

/* New returns an empty store; now nil is time.Now. */
func New(now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{now: now, m: map[string]*Approval{}}
}

/* NewID is a fresh approval id (128 random bits, URL-safe). */
func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

/* prune drops the expired approvals; s.mu is held. */
func (s *Store) prune(now time.Time) {
	for k, a := range s.m {
		if !now.Before(a.Expires) {
			delete(s.m, k)
		}
	}
}

/*
Request records a's request (a.ID from NewID, a.User and a.Object set) for
ttl: an earlier request of the same author for the same kind and object
goes (a new one replaces it).
*/
func (s *Store) Request(a Approval, ttl time.Duration) (Approval, error) {
	if a.ID == "" || a.User <= 0 || a.Object == "" || ttl <= 0 {
		return Approval{}, ErrMismatch
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(now)
	mine := 0
	for k, o := range s.m {
		switch {
		case o.User == a.User && o.Kind == a.Kind && o.Object == a.Object:
			delete(s.m, k)
		case o.User == a.User:
			mine++
		}
	}
	if mine >= maxPerUser || len(s.m) >= maxAll {
		return Approval{}, ErrTooMany
	}
	a.Groups = slices.Clone(a.Groups)
	a.Expires, a.Approved, a.By, a.ByName, a.ByChal = now.Add(ttl), false, 0, "", ""
	s.m[a.ID] = &a
	return a, nil
}

/* Get returns the live approval id (copied). */
func (s *Store) Get(id string) (Approval, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.m[id]
	if a == nil || !s.now().Before(a.Expires) {
		return Approval{}, false
	}
	return *a, true
}

/* Find returns the live request of kind for object (a changeset waits for its second person this way). */
func (s *Store) Find(kind, object string) (Approval, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for _, a := range s.m {
		if a.Kind == kind && a.Object == object && now.Before(a.Expires) {
			return *a, true
		}
	}
	return Approval{}, false
}

/*
Approve records by's approval of id with h, the H by confirmed: the
request is live and not approved yet, by is neither the author's id nor
the author's name (security.md 5.4 D4), and h is the request's H.
*/
func (s *Store) Approve(id string, by authz.Decision, h [32]byte, challenge string) (Approval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.m[id]
	switch {
	case a == nil || !s.now().Before(a.Expires):
		return Approval{}, ErrExpired
	case by.UserID == a.User || strings.EqualFold(by.Username, a.Username):
		return Approval{}, ErrSamePerson
	case subtle.ConstantTimeCompare(h[:], a.H[:]) != 1:
		return Approval{}, ErrH
	case a.Approved:
		return Approval{}, ErrMismatch
	}
	a.By, a.ByName, a.ByChal, a.Approved = by.UserID, by.Username, challenge, true
	return *a, nil
}

/*
Take spends approval id for user on object, once: it goes whatever the
outcome. It must be live, approved by a second person, the author's and
for this very object.
*/
func (s *Store) Take(id string, user int64, object string) (Approval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.m[id]
	delete(s.m, id)
	switch {
	case a == nil || !s.now().Before(a.Expires):
		return Approval{}, ErrExpired
	case a.User != user || a.Object != object:
		return Approval{}, ErrMismatch
	case !a.Approved:
		return Approval{}, ErrSecondPerson
	}
	return *a, nil
}

/* Drop forgets every approval of kind for object (a changeset's new revision, its discard). */
func (s *Store) Drop(kind, object string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, a := range s.m {
		if a.Kind == kind && a.Object == object {
			delete(s.m, k)
		}
	}
}
