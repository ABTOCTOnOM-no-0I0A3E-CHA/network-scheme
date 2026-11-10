package session_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/session"
)

/* sent are the lines of the device's journal from n on that start with prefix. */
func (f *fx) sent(n int, prefix string) []string {
	var out []string
	for _, l := range f.d.Lines()[n:] {
		if strings.HasPrefix(l, prefix) {
			out = append(out, l)
		}
	}
	return out
}

/*
ESR: exclusivity is checked again right before the commit and right before
the confirm (another login in show users: not_exclusive, nothing sent); a
second commit waits for the first one's confirm; the confirm is never sent
within the margin of the commit's timer (fake clock).
*/
func TestESRExclusivityAndTimerBeforeConfirm(t *testing.T) {
	f := newLineFx(t, "esr")
	u := f.user(t, "core")
	o := f.open(t, u)
	one := lineOf["esr"].users
	two := one + "\n   2  admin  00:10:00  15  ssh  192.0.2.201"
	f.typeLines(t, o, "configure", "hostname edge-7")
	n := len(f.d.Lines())
	f.setUsers(two)
	if _, err := f.m.Commit(ctx(t), o.ID, o.Token, f.id); !errors.Is(err, session.ErrNotExclusive) || len(f.sent(n, "commit")) != 0 {
		t.Fatalf("commit with another login: %v, sent %q", err, f.d.Lines()[n:])
	}
	f.setUsers(one)
	dd, err := f.m.Commit(ctx(t), o.ID, o.Token, f.id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.Commit(ctx(t), o.ID, o.Token, f.id); !errors.Is(err, session.ErrCommitPending) {
		t.Fatalf("a second commit while one is pending: %v", err)
	}
	n = len(f.d.Lines())
	f.setUsers(two)
	if _, err := f.m.Save(ctx(t), o.ID, o.Token, f.id, dd.SHA256); !errors.Is(err, session.ErrNotExclusive) || len(f.sent(n, "confirm")) != 0 {
		t.Fatalf("confirm with another login: %v, sent %q", err, f.d.Lines()[n:])
	}
	f.setUsers(one)
	f.offset.Add(int64(dd.Pending.Sub(f.now()) - 14*time.Second))
	if _, err := f.m.Save(ctx(t), o.ID, o.Token, f.id, dd.SHA256); !errors.Is(err, session.ErrCommitTimer) || len(f.sent(n, "confirm")) != 0 {
		t.Fatalf("confirm 14 s before the timer: %v, sent %q", err, f.d.Lines()[n:])
	}
}

/*
I1: a failed health check (the new login fails) after commit B reverts only
B (restore): commit A, confirmed before, stays, and nothing is confirmed or
copied from the snapshot without the user's confirm(H).
*/
func TestESRHealthCheckRestoresOnlyThePendingCommit(t *testing.T) {
	f := newLineFx(t, "esr")
	u := f.user(t, "core")
	o := f.open(t, u)
	f.typeLines(t, o, "configure", "hostname edge-a")
	a, err := f.m.Commit(ctx(t), o.ID, o.Token, f.id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.Save(ctx(t), o.ID, o.Token, f.id, a.SHA256); err != nil {
		t.Fatal(err)
	}
	postA := f.running()
	f.typeLines(t, o, "configure", "hostname edge-b")
	n := len(f.d.Lines())
	f.noDial.Store(true)
	_, err = f.m.Commit(ctx(t), o.ID, o.Token, f.id)
	f.noDial.Store(false)
	if !errors.Is(err, session.ErrHealth) {
		t.Fatalf("commit with a failing login: %v", err)
	}
	if f.running() != postA || len(f.sent(n, "confirm")) != 0 || len(f.sent(n, "copy")) != 0 || len(f.sent(n, "restore")) != 1 {
		t.Fatalf("after the failed health check: running is post-A %v, sent %q", f.running() == postA, f.d.Lines()[n:])
	}
}
