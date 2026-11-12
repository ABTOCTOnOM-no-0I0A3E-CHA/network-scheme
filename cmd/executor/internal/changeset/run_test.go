package changeset_test

import (
	"context"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/changeset"
	"github.com/beekamai/network-scheme/cmd/executor/internal/confirm"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers"
	"github.com/beekamai/network-scheme/cmd/executor/internal/recording"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/session"
	"github.com/beekamai/network-scheme/cmd/executor/internal/terminal"
	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/secret"
)

/* withRunner gives the manager the session manager as its runner (Start is the real run). */
func (f *fx) withRunner(t *testing.T) *session.Manager {
	t.Helper()
	pool := f.env.Pool("nms_executor")
	bpub, bpriv := f.bpub, f.bpriv
	var sm *session.Manager
	rec, err := recording.New(recording.Config{Pool: pool, MAC: f.store.MAC, Pub: bpub, Priv: bpriv, Clean: terminal.Clean,
		Policy: f.pol.Current, Live: func(id [16]byte) bool { return sm.Live(id) }, Alert: f.pub.Alert, Audit: f.az.Record, Now: f.now})
	if err != nil {
		t.Fatal(err)
	}
	open := func(*registry.Snapshot, int64) (creds.Credential, error) {
		return creds.Credential{Username: "admin", Password: secret.New(pw)}, nil
	}
	sm = session.New(session.Config{Gate: f.guard, Auth: f.az, Policy: f.pol.Current, Pool: pool, MAC: f.store.MAC, Net: dialer{f},
		Open: open, Backups: f.cfg.Reader.(session.Backups), Locks: f.locks, Pub: f.pub, BackupPriv: bpriv, BackupPub: bpub,
		Recordings: rec, Now: f.now})
	cfg := f.cfg
	cfg.Start, cfg.Runner = nil, sm
	f.cfg, f.m = cfg, changeset.New(cfg)
	return sm
}

/* runApproved dry-runs and approves (author alone) a changeset of content and waits for its run's outcome. */
func (f *fx) runApproved(t *testing.T, u who, c changeset.Content, between func(id string)) changeset.Detail {
	t.Helper()
	tok := f.open(t, u)
	s := f.save(t, tok, "", 0, c)
	if d := f.dryRun(t, tok, s.ID, 1); !d.DryRun.Result.OK {
		t.Fatalf("dry-run: %+v", d.DryRun.Result)
	}
	if between != nil {
		between(s.ID)
	}
	cs := confirm.New(f.az, f.now)
	ch, err := f.challenge(t, cs, u, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.approve(t, cs, u, ch, s.ID, len(c.Devices)); err != nil {
		t.Fatalf("approve: %v", err)
	}
	f.m.WaitRun(s.ID)
	res, err := f.op(t, tok, "progress", map[string]any{"changeset_id": s.ID})
	if err != nil {
		t.Fatal(err)
	}
	return res.(changeset.Detail)
}

/* hashOf is the normalized hash of a device's running configuration. */
func hashOf(d *dev) [32]byte { return drivers.NewConfig(d.d.Running()).SHA256 }

/*
K1: the canary, then batches: every device of every line gets exactly the
plan's lines, MES saved at the end, ESR committed and confirmed; the
outcome is done, every service session closed and every device free.
*/
func TestRunCanaryThenBatches(t *testing.T) {
	f := newFx(t, "mes6", "mes10", "esr", "mes6", "mes10", "esr")
	f.withRunner(t)
	alice := f.user(t, "core")
	c := f.lines("descriptions everywhere", f.devs...)
	c.BatchSize = 2
	d := f.runApproved(t, alice, c, nil)
	if d.Status != changeset.StatusDone || d.Run == nil || d.Run.Result != changeset.StatusDone {
		t.Fatalf("run %+v status %s", d.Run, d.Status)
	}
	for i, dv := range f.devs {
		if !strings.Contains(dv.d.Running(), "nms-test") || !strings.Contains(dv.d.Saved(), "nms-test") {
			t.Errorf("device %d (%s): running/saved without the change", i, dv.line)
		}
		if st := d.Run.Devices[i].State; st != "saved" && st != "applied" {
			t.Errorf("device %d: %s %s", i, st, d.Run.Devices[i].Error)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM execpub.device_busy`); n != 0 {
		t.Errorf("%d device_busy rows", n)
	}
	if n := f.count(t, `SELECT count(*) FROM execpub.session_summary WHERE status = 'closed'`); n != len(f.devs) {
		t.Errorf("%d closed summaries", n)
	}
	if f.audits(t, "changeset.run", "ok") != 1 {
		t.Error("no audit row of the run")
	}
	/* every device's recording holds its lines */
	if n := f.count(t, `SELECT count(*) FROM exec.recording_manifest`); n != len(f.devs) {
		t.Errorf("%d recordings", n)
	}
}

/*
K2: a device refuses a line of the fifth device: the run stops, every
device that got a line is rolled back to its pre-session hash, the devices
after it get nothing; the alert names the device.
*/
func TestRunStopsAndRollsBackOnFifthDevice(t *testing.T) {
	f := newFx(t, "mes6", "mes10", "esr", "mes6", "mes10", "esr")
	f.withRunner(t)
	alice := f.user(t, "core")
	pre := map[int]string{}
	for i, dv := range f.devs {
		pre[i] = dv.d.Running()
	}
	f.devs[4].d.Reject(`^description`, "% Unrecognized command")
	c := f.lines("fails on the fifth", f.devs...)
	c.BatchSize = 4
	d := f.runApproved(t, alice, c, nil)
	if d.Status != changeset.StatusRolledBack || d.Run.Failed != f.devs[4].id {
		t.Fatalf("status %s, run %+v", d.Status, d.Run)
	}
	for i, dv := range f.devs[:5] {
		if hashOf(dv) != drivers.NewConfig(pre[i]).SHA256 {
			t.Errorf("device %d (%s) not back to its pre-session configuration:\n%s", i, dv.line, dv.d.Running())
		}
	}
	if d.Run.Devices[5].Sent != 0 || strings.Contains(f.devs[5].d.Running(), "nms-test") {
		t.Errorf("the device after the batch got lines: %+v", d.Run.Devices[5])
	}
	if f.count(t, `SELECT count(*) FROM execpub.alert WHERE kind = $1 AND device_id = $2`, changeset.KindFailed, f.devs[4].id) != 1 {
		t.Error("no changeset_failed alert")
	}
	if n := f.count(t, `SELECT count(*) FROM execpub.device_busy`); n != 0 {
		t.Errorf("%d device_busy rows", n)
	}
}

/* K3: a configuration changed after the dry-run refuses that device before its first line; the canary is rolled back. */
func TestRunRefusesDrift(t *testing.T) {
	f := newFx(t, "mes6", "mes10")
	f.withRunner(t)
	alice := f.user(t, "core")
	pre0 := hashOf(f.devs[0])
	d := f.runApproved(t, alice, f.lines("drift", f.devs...), func(string) {
		c := f.devs[1].d.Dial("admin")
		for _, l := range []string{"configure terminal", "hostname drifted", "end"} {
			c.Do(l)
		}
	})
	if d.Status != changeset.StatusRolledBack || d.Run.Failed != f.devs[1].id || d.Run.Reason != "config_changed" || d.Run.Devices[1].Sent != 0 {
		t.Fatalf("status %s run %+v", d.Status, d.Run)
	}
	if hashOf(f.devs[0]) != pre0 {
		t.Fatal("the canary was not rolled back")
	}
}

/* Stop in the middle (during the canary's settle time): nothing more is sent, the canary is rolled back. */
func TestRunStop(t *testing.T) {
	f := newFx(t, "mes6", "mes10")
	f.withRunner(t)
	alice := f.user(t, "core")
	tok := f.open(t, alice)
	release := changeset.HoldSettle()
	c := f.lines("stopped", f.devs...)
	c.SettleS = 30
	pre := hashOf(f.devs[0])
	s := f.save(t, tok, "", 0, c)
	f.dryRun(t, tok, s.ID, 1)
	cs := confirm.New(f.az, f.now)
	ch, _ := f.challenge(t, cs, alice, s.ID)
	if _, err := f.approve(t, cs, alice, ch, s.ID, 2); err != nil {
		t.Fatal(err)
	}
	changeset.WaitSettle()
	if _, err := f.op(t, tok, "stop", map[string]any{"changeset_id": s.ID}); err != nil {
		t.Fatal(err)
	}
	release()
	f.m.WaitRun(s.ID)
	res, _ := f.op(t, tok, "progress", map[string]any{"changeset_id": s.ID})
	d := res.(changeset.Detail)
	if d.Status != changeset.StatusRolledBack || d.Run.Reason != "stopped" || d.Run.Devices[1].Sent != 0 || hashOf(f.devs[0]) != pre {
		t.Fatalf("status %s run %+v", d.Status, d.Run)
	}
	if f.audits(t, "changeset.stop", "ok") != 1 {
		t.Error("no audit row of the stop")
	}
}

/* D6: a run interrupted by a restart ends as interrupted with the alert, nothing goes on. */
func TestRunInterruptedByRestart(t *testing.T) {
	f := newFx(t, "mes6")
	alice := f.user(t, "core")
	_, id := f.ready(t, alice, f.devs[0])
	cs := confirm.New(f.az, f.now)
	ch, _ := f.challenge(t, cs, alice, id)
	if _, err := f.approve(t, cs, alice, ch, id, 1); err != nil { /* the fake Start: run_started, then the process "dies" */
		t.Fatal(err)
	}
	m := changeset.New(f.cfg)
	if err := m.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	tok := f.open(t, alice)
	if st := f.status(t, tok, id); st != changeset.StatusInterrupted {
		t.Fatalf("status %s", st)
	}
	if f.count(t, `SELECT count(*) FROM execpub.alert WHERE kind = $1`, changeset.KindInterrupted) != 1 {
		t.Fatal("no interrupted alert")
	}
	if err := m.Recover(context.Background()); err != nil || f.count(t, `SELECT count(*) FROM execpub.alert WHERE kind = $1`, changeset.KindInterrupted) != 1 {
		t.Fatalf("a second recover alerted again: %v", err)
	}
}
