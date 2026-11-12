package mes6

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
	d, tm, al := New(), drvtest.New(t, strategy.MES6), &drvtest.Alerts{}
	a, _ := d.Targets("interface", "gi1/0/24")
	b, _ := d.Targets("vlan", "99")
	s, err := d.open(context.Background(), tm, drivers.Options{SessionID: "s1", Context: core.Context{Mgmt: append(a, b...)}, Strategies: st, Alert: al.Add})
	if err != nil {
		t.Fatal(err)
	}
	return tm, s, al
}

func typeLines(t *testing.T, s *session, ls ...string) {
	t.Helper()
	for _, l := range ls {
		v := s.d.Classify(l, s.Mode(), s.Opt.Context)
		if v.Class != core.Safe {
			t.Fatalf("%q = %v (%s)", l, v.Class, v.Reason)
		}
		if _, err := s.Send(context.Background(), v); err != nil {
			t.Fatalf("send %q: %v", l, err)
		}
	}
}

/* C7 (emulator): the inverse journal restores the pre-session configuration and the hash check passes. */
func TestRollbackInverseJournal(t *testing.T) {
	tm, s, al := open(t, drivers.Strategies{})
	ctx := context.Background()
	typeLines(t, s, "conf", "hostname edge-7", "interface gigabitethernet1/0/1", "description to-core", "shutdown",
		"switchport access vlan 20", "exit", "interface gigabitethernet1/0/2", "no shutdown", "exit",
		"interface vlan 30", "name users", "end")
	if tm.D.Running() == s.Pre().Text {
		t.Fatal("nothing changed")
	}
	if err := s.Rollback(ctx, s.Pre()); err != nil {
		t.Fatalf("rollback: %v\n%q\n%q\n%q", err, tm.D.Running(), s.Pre().Text, tm.Lines())
	}
	if snap(t, s) != s.Pre().SHA256 || len(al.List()) != 0 {
		t.Fatalf("not the pre-session configuration (alerts %v):\n%s", al.List(), tm.D.Running())
	}
	if tm.D.Saved() != s.Pre().Text {
		t.Fatal("rollback touched startup-config")
	}
}

/* A community added in the session (a dangerous line) is removed again by the rollback. */
func TestRollbackRemovesANewCommunity(t *testing.T) {
	tm, s, al := open(t, drivers.Strategies{})
	ctx := context.Background()
	typeLines(t, s, "conf")
	if _, err := s.Send(ctx, s.d.Classify("snmp-server community e2e-ro ro", s.Mode(), s.Opt.Context)); err != nil {
		t.Fatal(err)
	}
	typeLines(t, s, "end")
	if err := s.Rollback(ctx, s.Pre()); err != nil {
		t.Fatalf("rollback: %v\n%q", err, tm.Lines())
	}
	if !slices.Contains(tm.Lines(), "no snmp-server community e2e-ro") {
		t.Fatalf("the community was not removed: %q", tm.Lines())
	}
	if snap(t, s) != s.Pre().SHA256 || len(al.List()) != 0 {
		t.Fatalf("not the pre-session configuration (alerts %v):\n%s", al.List(), tm.D.Running())
	}
}

/* A line without an inverse refuses the rollback before anything is sent; a forged target is refused. */
func TestRollbackRefusals(t *testing.T) {
	tm, s, _ := open(t, drivers.Strategies{})
	ctx := context.Background()
	if err := s.Rollback(ctx, drivers.NewConfig("hostname other")); !errors.Is(err, drivers.ErrSnapshot) {
		t.Fatalf("forged target: %v", err)
	}
	typeLines(t, s, "conf", "hostname edge-7")
	v := s.d.Classify("ip default-gateway 192.0.2.1", s.Mode(), s.Opt.Context)
	if _, err := s.Send(ctx, v); err != nil {
		t.Fatal(err)
	}
	n := len(tm.Lines())
	if err := s.Rollback(ctx, s.Pre()); !errors.Is(err, drivers.ErrNoInverse) {
		t.Fatalf("rollback without inverse: %v", err)
	}
	if len(tm.Lines()) != n {
		t.Fatalf("lines sent before the refusal: %q", tm.Lines()[n:])
	}
	if _, err := s.Send(ctx, core.Verdict{Class: core.Safe, Line: "reload"}); !errors.Is(err, drivers.ErrNotSendable) {
		t.Fatalf("forged verdict: %v", err)
	}
}

/* A rollback whose result differs from the snapshot fails with a high alert. */
func TestRollbackHashMismatchAlerts(t *testing.T) {
	tm, s, al := open(t, drivers.Strategies{})
	typeLines(t, s, "conf", "hostname edge-7", "end")
	tm.D.Reject("hostname sw-lab-01", "% Unrecognized command")
	if err := s.Rollback(context.Background(), s.Pre()); !errors.Is(err, drivers.ErrRollbackMismatch) {
		t.Fatalf("rollback: %v", err)
	}
	if !slices.Equal(al.List(), []string{drivers.KindRollbackMismatch + "/high"}) {
		t.Fatalf("alerts %v", al.List())
	}
}

/* Save is write + Y from the root (also from a configuration mode); the safety net is armed at Open and cancelled. */
func TestSaveAndSafetyNet(t *testing.T) {
	st := New().S
	st.SafetyNet = "reload-in"
	tm, s, _ := open(t, st)
	if tm.D.ReloadAt().IsZero() {
		t.Fatal("reload in not armed")
	}
	typeLines(t, s, "conf", "hostname edge-7")
	if err := s.Save(context.Background()); err != nil {
		t.Fatal(err)
	}
	if tm.D.Saved() != tm.D.Running() || !tm.D.ReloadAt().IsZero() {
		t.Fatalf("saved %v, reload %v", tm.D.Saved() == tm.D.Running(), tm.D.ReloadAt())
	}
	want := []string{"show running-config", "reload in 10", "configure", "hostname edge-7", "end", "write", "reload cancel"}
	if got := tm.Lines(); !slices.Equal(got, want) {
		t.Fatalf("device received %q", got)
	}
	if err := s.Commit(context.Background(), 0); !errors.Is(err, drivers.ErrNotApplicable) {
		t.Fatal(err)
	}
}

/*
The VLAN database inverse: the session's new VLANs go, the snapshot's VLAN
lines come back as printed. The emulator re-indents a re-added line (its
fixture prints them at column 0), so this checks the VLAN set, not the hash.
*/
func TestRollbackVLANDatabase(t *testing.T) {
	tm, s, _ := open(t, drivers.Strategies{})
	typeLines(t, s, "conf", "vlan database", "vlan 20,30", "no vlan 10", "end")
	plan, err := s.inverse(parseConfig(s.Pre().Text))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"configure", "vlan database", "no vlan 30", "vlan 10,20,99", "exit", "end"}; !slices.Equal(plan, want) {
		t.Fatalf("plan %q", plan)
	}
	_ = s.Rollback(context.Background(), s.Pre())
	if got := parseConfig(tm.D.Running()); !slices.Equal(vlanSet(got), vlanSet(parseConfig(s.Pre().Text))) {
		t.Fatalf("vlans %v", vlanSet(got))
	}
}

func vlanSet(s snapshot) []int {
	c, _ := s.find(New(), "line:vlan database")
	var out []int
	for v := range vlans(c.lines) {
		out = append(out, v)
	}
	slices.Sort(out)
	return out
}

func snap(t *testing.T, s drivers.Session) [32]byte {
	t.Helper()
	c, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return c.SHA256
}

/* m2: a typed line the device failed on leaves its effect unknown: Rollback refuses before sending anything. m3: the snapshot name is Denied. */
func TestFailedSendBreaksTheJournal(t *testing.T) {
	tm, s, _ := open(t, drivers.Strategies{})
	typeLines(t, s, "conf", "hostname edge-7")
	tm.D.Reject("^snmp-server location x$", "% Unrecognized command")
	if _, err := s.Send(context.Background(), s.Classify("snmp-server location x")); err == nil {
		t.Fatal("rejected line accepted")
	}
	n := len(tm.Lines())
	if err := s.Rollback(context.Background(), s.Pre()); !errors.Is(err, drivers.ErrNoInverse) || len(tm.Lines()) != n {
		t.Fatalf("rollback after a failed line: %v, sent %q", err, tm.Lines()[n:])
	}
	typeLines(t, s, "end")
	for _, l := range []string{"copy running-config flash:nms-pre-s1", "delete flash:NMS-PRE-s1", "copy flash:nms-pre-x running-config"} {
		if v := s.Classify(l); v.Class != core.Denied || v.Reason != drivers.ReasonSnapshot {
			t.Errorf("%q = %v (%s)", l, v.Class, v.Reason)
		}
	}
}
