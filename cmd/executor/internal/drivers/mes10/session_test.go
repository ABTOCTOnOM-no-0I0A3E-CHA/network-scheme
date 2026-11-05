package mes10

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/drvtest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/strategy"
)

func open(t *testing.T, st drivers.Strategies) (*drvtest.Term, *session, *drvtest.Alerts) {
	t.Helper()
	d, tm, al := New(), drvtest.New(t, strategy.MES10), &drvtest.Alerts{}
	s, err := d.open(context.Background(), tm, drivers.Options{SessionID: "s1", Strategies: st, Alert: al.Add})
	if err != nil {
		t.Fatal(err)
	}
	return tm, s, al
}

func typeLines(t *testing.T, s *session, ls ...string) {
	t.Helper()
	g := New()
	for _, l := range ls {
		v := g.Classify(l, s.Mode(), s.Opt.Context)
		if _, err := s.Send(context.Background(), v); err != nil {
			t.Fatalf("send %q (%v): %v", l, v.Class, err)
		}
	}
}

/* C7 (emulator): the snapshot copied at Open replaces running-config and the hash check passes; Save is write startup-config. */
func TestSnapshotReplaceRollbackAndSave(t *testing.T) {
	tm, s, al := open(t, drivers.Strategies{})
	ctx := context.Background()
	if _, ok := tm.D.File("flash:nms-pre-s1"); !ok {
		t.Fatal("no snapshot copied at Open")
	}
	typeLines(t, s, "conf t", "hostname edge-10", "interface gigabitethernet 0/1", "shutdown", "exit", "vlan 20", "name users", "end")
	if err := s.Rollback(ctx, s.Pre()); err != nil {
		t.Fatalf("rollback: %v %q", err, tm.D.Running())
	}
	if len(al.List()) != 0 || snap(t, s) != s.Pre().SHA256 {
		t.Fatal("not the pre-session configuration")
	}
	typeLines(t, s, "conf t", "hostname edge-10", "end")
	if err := s.Save(ctx); err != nil || tm.D.Saved() != tm.D.Running() {
		t.Fatalf("save: %v", err)
	}
	got := tm.Lines()
	if !slices.Contains(got, "replace running-config flash:nms-pre-s1") || got[len(got)-1] != "write startup-config" {
		t.Fatalf("device received %q", got)
	}
	if err := s.Rollback(ctx, drivers.NewConfig("hostname x")); !errors.Is(err, drivers.ErrSnapshot) {
		t.Fatal(err)
	}
}

/* A replaced configuration that differs from the snapshot (here: the copy was overwritten) fails with a high alert. */
func TestReplaceMismatchAlerts(t *testing.T) {
	tm, s, al := open(t, drivers.Strategies{})
	tm.D.PutFile("flash:nms-pre-s1", "!\nhostname tampered")
	if err := s.Rollback(context.Background(), s.Pre()); !errors.Is(err, drivers.ErrRollbackMismatch) {
		t.Fatal(err)
	}
	if !slices.Equal(al.List(), []string{drivers.KindRollbackMismatch + "/high"}) {
		t.Fatalf("alerts %v", al.List())
	}
}

/* reload-in arms "reload in <hours> <minutes>" and Close cancels it; Commit does not apply. */
func TestSafetyNet(t *testing.T) {
	st := New().S
	st.SafetyNet, st.ReloadMinutes = "reload-in", 75
	tm, s, _ := open(t, st)
	if tm.D.ReloadAt().IsZero() || !slices.Contains(tm.Lines(), "reload in 1 15") {
		t.Fatalf("not armed: %q", tm.Lines())
	}
	if err := s.Close(context.Background()); err != nil || !tm.D.ReloadAt().IsZero() {
		t.Fatalf("close: %v", err)
	}
	if err := s.Commit(context.Background(), 0); !errors.Is(err, drivers.ErrNotApplicable) {
		t.Fatal(err)
	}
	if _, err := s.Send(context.Background(), core.Verdict{Class: core.Safe, Line: "clear running-config"}); !errors.Is(err, drivers.ErrNotSendable) {
		t.Fatal(err)
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
	for _, l := range []string{"copy running-config flash:nms-pre-s1", "delete flash:nms-pre-s1", "copy tftp://192.0.2.1/x flash:NMS-PRE-s1"} {
		if v := s.Classify(l); v.Class != core.Denied || v.Reason != drivers.ReasonSnapshot {
			t.Errorf("%q = %v (%s)", l, v.Class, v.Reason)
		}
	}
	if err := s.Close(context.Background()); err != nil || !slices.Equal(tm.Deleted, []string{"flash:nms-pre-s1"}) {
		t.Fatalf("close: %v, deleted %q", err, tm.Deleted)
	}
	if err := s.Close(context.Background()); !errors.Is(err, drivers.ErrSnapshotLeft) {
		t.Fatalf("second close: %v", err)
	}
}
