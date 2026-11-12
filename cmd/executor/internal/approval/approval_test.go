package approval

import (
	"errors"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
)

func TestApprovalLifecycle(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := New(func() time.Time { return now })
	h := [32]byte{1}
	req := func(object string) Approval {
		id, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		a, err := s.Request(Approval{ID: id, Kind: "session", User: 7, Username: "alice", Object: object, H: h}, 30*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	a := req("devices:1,2")
	if _, err := s.Take(a.ID, 7, "devices:1,2"); !errors.Is(err, ErrSecondPerson) {
		t.Fatalf("not approved: %v", err)
	}
	a = req("devices:1,2")
	for name, by := range map[string]authz.Decision{"same id": {UserID: 7, Username: "x"}, "same name": {UserID: 8, Username: "Alice"}} {
		if _, err := s.Approve(a.ID, by, h, "c"); !errors.Is(err, ErrSamePerson) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := s.Approve(a.ID, authz.Decision{UserID: 8, Username: "bob"}, [32]byte{2}, "c"); !errors.Is(err, ErrH) {
		t.Fatalf("other H: %v", err)
	}
	if _, err := s.Approve(a.ID, authz.Decision{UserID: 8, Username: "bob"}, h, "c"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(a.ID, authz.Decision{UserID: 9, Username: "carol"}, h, "c"); !errors.Is(err, ErrMismatch) {
		t.Fatalf("approved twice: %v", err)
	}
	if _, err := s.Take(a.ID, 7, "devices:1,3"); !errors.Is(err, ErrMismatch) {
		t.Fatalf("other devices: %v", err)
	}
	if _, err := s.Take(a.ID, 7, "devices:1,2"); !errors.Is(err, ErrExpired) {
		t.Fatalf("a failed take spends it: %v", err)
	}
	a = req("devices:1,2")
	if _, err := s.Approve(a.ID, authz.Decision{UserID: 8, Username: "bob"}, h, "c"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Take(a.ID, 7, "devices:1,2"); err != nil || got.By != 8 {
		t.Fatalf("take: %+v %v", got, err)
	}
	if _, err := s.Take(a.ID, 7, "devices:1,2"); !errors.Is(err, ErrExpired) {
		t.Fatalf("taken twice: %v", err)
	}
	a = req("devices:5")
	now = now.Add(31 * time.Minute)
	if _, err := s.Approve(a.ID, authz.Decision{UserID: 8, Username: "bob"}, h, "c"); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
	/* a new request of the same author for the same object replaces the old one; Drop forgets */
	a, b := req("changeset:x"), req("changeset:x")
	if _, ok := s.Get(a.ID); ok {
		t.Fatal("the replaced request lives on")
	}
	s.Drop("session", "changeset:x")
	if _, ok := s.Find("session", "changeset:x"); ok || b.ID == "" {
		t.Fatal("dropped request found")
	}
	for i := range maxPerUser {
		req("devices:" + string(rune('a'+i)))
	}
	id, _ := NewID()
	if _, err := s.Request(Approval{ID: id, Kind: "session", User: 7, Username: "alice", Object: "devices:9", H: h}, time.Minute); !errors.Is(err, ErrTooMany) {
		t.Fatalf("over the per-user bound: %v", err)
	}
}
