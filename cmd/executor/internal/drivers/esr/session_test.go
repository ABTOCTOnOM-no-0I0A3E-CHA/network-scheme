package esr

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/drvtest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/strategy"
)

func open(t *testing.T, st drivers.Strategies) (*drvtest.Term, *session, *drvtest.Alerts) {
	t.Helper()
	d, tm, al := New(), drvtest.New(t, strategy.ESR), &drvtest.Alerts{}
	s, err := d.open(context.Background(), tm, drivers.Options{SessionID: "s1", Strategies: st, Alert: al.Add})
	if err != nil {
		t.Fatal(err)
	}
	return tm, s, al
}

func edit(t *testing.T, s *session) {
	t.Helper()
	for _, l := range []string{"configure", "hostname edge-esr", "interface gigabitethernet 1/0/2", "no shutdown", "description lan"} {
		v := New().Classify(l, s.Mode(), s.Opt.Context)
		if _, err := s.Send(context.Background(), v); err != nil {
			t.Fatalf("send %q (%v): %v", l, v.Class, err)
		}
	}
}

/* Commit applies with the timer, Save is confirm; Close without confirm restores [R §1]. */
func TestCommitConfirmAndCloseRestores(t *testing.T) {
	ctx := context.Background()
	tm, s, _ := open(t, drivers.Strategies{})
	if err := s.Save(ctx); !errors.Is(err, drivers.ErrNothingToConfirm) {
		t.Fatal(err)
	}
	edit(t, s)
	if err := s.Commit(ctx, 60*time.Second); !errors.Is(err, drivers.ErrTimeout) {
		t.Fatal(err)
	}
	if err := s.Commit(ctx, 300*time.Second); err != nil || tm.D.Pending().IsZero() {
		t.Fatalf("commit: %v", err)
	}
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if !tm.D.Pending().IsZero() || snap(t, s) != s.Pre().SHA256 || tm.D.Candidate() != tm.D.Running() {
		t.Fatalf("close did not restore: %q", tm.D.Running())
	}
	want := []string{"end", "commit confirm-timeout 300", "restore", "rollback", "show running-config"}
	if got := tm.Lines(); !slices.Equal(got[len(got)-5:], want) {
		t.Fatalf("device received %q", got)
	}

	tm, s, _ = open(t, drivers.Strategies{})
	edit(t, s)
	if err := s.Commit(ctx, 600*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(ctx); err != nil || !tm.D.Pending().IsZero() || tm.D.Saved() != tm.D.Running() {
		t.Fatalf("confirm: %v", err)
	}
}

/* C7 (emulator): rollback before confirm is restore; after confirm the snapshot goes to the candidate, is committed, checked, confirmed. */
func TestRollbackBeforeAndAfterConfirm(t *testing.T) {
	ctx := context.Background()
	for _, confirmed := range []bool{false, true} {
		tm, s, al := open(t, drivers.Strategies{})
		edit(t, s)
		if err := s.Commit(ctx, 600*time.Second); err != nil {
			t.Fatal(err)
		}
		if confirmed {
			if err := s.Save(ctx); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.Rollback(ctx, s.Pre()); err != nil {
			t.Fatalf("confirmed %v: %v", confirmed, err)
		}
		if snap(t, s) != s.Pre().SHA256 || !tm.D.Pending().IsZero() || len(al.List()) != 0 {
			t.Fatalf("confirmed %v: not restored (alerts %v)", confirmed, al.List())
		}
		if got := tm.Lines(); confirmed != slices.Contains(got, "copy flash:data/nms-pre-s1 system:candidate-config") {
			t.Fatalf("confirmed %v: %q", confirmed, got)
		}
	}
}

/* After confirm a snapshot that no longer matches is committed but not confirmed: restored, high alert, failure. */
func TestRollbackMismatchIsNotConfirmed(t *testing.T) {
	ctx := context.Background()
	tm, s, al := open(t, drivers.Strategies{})
	edit(t, s)
	if err := s.Commit(ctx, 600*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(ctx); err != nil {
		t.Fatal(err)
	}
	tm.D.PutFile("flash:data/nms-pre-s1", "hostname tampered")
	if err := s.Rollback(ctx, s.Pre()); !errors.Is(err, drivers.ErrRollbackMismatch) {
		t.Fatal(err)
	}
	got := tm.Lines()
	if got[len(got)-1] == "confirm" || !tm.D.Pending().IsZero() || !slices.Equal(al.List(), []string{drivers.KindRollbackMismatch + "/high"}) {
		t.Fatalf("lines %q alerts %v", got[len(got)-4:], al.List())
	}
}

func snap(t *testing.T, s drivers.Session) [32]byte {
	t.Helper()
	c, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return c.SHA256
}

/* m3: typed lines naming the snapshot are Denied; Close deletes it, and a snapshot that cannot be deleted is reported. */
func TestSnapshotProtectedAndDeletedAtClose(t *testing.T) {
	tm, s, _ := open(t, drivers.Strategies{})
	for _, l := range []string{"copy system:running-config flash:data/nms-pre-s1", "delete flash:data/nms-pre-s1", "copy flash:data/nms-pre-s1 system:candidate-config"} {
		if v := s.Classify(l); v.Class != core.Denied || v.Reason != drivers.ReasonSnapshot {
			t.Errorf("%q = %v (%s)", l, v.Class, v.Reason)
		}
	}
	if err := s.Close(context.Background()); err != nil || !slices.Equal(tm.Deleted, []string{"flash:data/nms-pre-s1"}) {
		t.Fatalf("close: %v, deleted %q", err, tm.Deleted)
	}
	if err := s.Close(context.Background()); !errors.Is(err, drivers.ErrSnapshotLeft) {
		t.Fatalf("second close: %v", err)
	}
}
