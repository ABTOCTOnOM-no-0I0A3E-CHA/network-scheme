package changeset_test

import (
	"context"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/changeset"
)

/* preVersion is the newest pre_session version of d (a run's snapshot before it changed d). */
func (f *fx) preVersion(t *testing.T, d *dev) int64 {
	t.Helper()
	var id int64
	if err := f.env.Pool("postgres").QueryRow(context.Background(), `SELECT id FROM backups.config_version
		WHERE device_id = $1 AND source = 'pre_session' ORDER BY id DESC LIMIT 1`, d.id).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func restoreOf(title string, items ...changeset.RestoreItem) changeset.Content {
	c := changeset.Content{Title: title, BatchSize: 1, Restore: items}
	for _, it := range items {
		c.Devices = append(c.Devices, it.Device)
	}
	return c
}

/*
A backup version restored through a changeset on every line: a run changes
the devices (its pre_session versions are the configurations before), then
a restore changeset of those versions brings every device back to the
version's hash; its dry-run shows the masked diff.
*/
func TestRestoreVersionOnEveryLine(t *testing.T) {
	f := newFx(t, "mes6", "mes10", "esr")
	f.withRunner(t)
	alice := f.user(t, "core")
	before := map[int64][32]byte{}
	for _, d := range f.devs {
		before[d.id] = hashOf(d)
	}
	if d := f.runApproved(t, alice, f.lines("change", f.devs...), nil); d.Status != changeset.StatusDone {
		t.Fatalf("change: %s %+v", d.Status, d.Run)
	}
	var items []changeset.RestoreItem
	for _, d := range f.devs {
		items = append(items, changeset.RestoreItem{Device: d.id, Version: f.preVersion(t, d)})
	}
	tok := f.open(t, alice)
	s := f.save(t, tok, "", 0, restoreOf("back", items...))
	dr := f.dryRun(t, tok, s.ID, 1)
	if !dr.DryRun.Result.OK {
		for _, r := range dr.DryRun.Result.Devices {
			if r.Refused != nil {
				t.Errorf("%s: %+v", r.Line, *r.Refused)
			}
		}
		t.FailNow()
	}
	for _, r := range dr.DryRun.Result.Devices {
		if r.Version == 0 || len(r.VersionSHA) != 64 {
			t.Fatalf("plan device %+v", r)
		}
	}
	if len(dr.DryRun.Result.Preview) == 0 || !strings.Contains(dr.DryRun.Result.Preview[0].Diff, "nms-test") {
		t.Fatalf("preview %+v", dr.DryRun.Result.Preview)
	}
	d := f.runApproved(t, alice, restoreOf("back again", items...), nil)
	if d.Status != changeset.StatusDone {
		t.Fatalf("restore: %s %+v", d.Status, d.Run)
	}
	for _, dv := range f.devs {
		if hashOf(dv) != before[dv.id] {
			t.Errorf("%s: not the version's configuration:\n%s", dv.line, dv.d.Running())
		}
	}
}

/*
A restore refuses a version of another device, a version whose envelope
or hash was tampered with (alert), and a difference the line's grammar
does not know as safe (listed in the dry-run, nothing sent).
*/
func TestRestoreRefusals(t *testing.T) {
	f := newFx(t, "mes6", "mes6")
	f.withRunner(t)
	alice := f.user(t, "core")
	if d := f.runApproved(t, alice, f.lines("change", f.devs...), nil); d.Status != changeset.StatusDone {
		t.Fatalf("change: %s", d.Status)
	}
	v0, v1 := f.preVersion(t, f.devs[0]), f.preVersion(t, f.devs[1])
	tok := f.open(t, alice)
	dry := func(c changeset.Content) *changeset.DeviceRefusal {
		s := f.save(t, tok, "", 0, c)
		return f.dryRun(t, tok, s.ID, 1).DryRun.Result.Devices[0].Refused
	}
	if r := dry(restoreOf("other's", changeset.RestoreItem{Device: f.devs[0].id, Version: v1})); r == nil || r.Code != "version_unknown" {
		t.Fatalf("another device's version: %+v", r)
	}
	/* a difference the grammar does not take as safe: SSH switched off on the device since */
	c := f.devs[0].d.Dial("admin")
	for _, l := range []string{"configure", "no ip ssh server", "end"} {
		c.Do(l)
	}
	if r := dry(restoreOf("ssh", changeset.RestoreItem{Device: f.devs[0].id, Version: v0})); r == nil || r.Code != "not_safe" {
		t.Fatalf("an unsafe difference: %+v", r)
	}
	if strings.Contains(f.devs[0].d.Running(), "nms-test") == false {
		t.Fatal("the refused restore changed the device")
	}
	attacktest.Tamper(t, f.env, `ALTER TABLE backups.config_version DISABLE TRIGGER USER`)
	attacktest.Tamper(t, f.env, `UPDATE backups.config_version SET sha256 = decode(repeat('00', 32), 'hex') WHERE id = $1`, v1)
	attacktest.Tamper(t, f.env, `ALTER TABLE backups.config_version ENABLE TRIGGER USER`)
	if r := dry(restoreOf("tampered", changeset.RestoreItem{Device: f.devs[1].id, Version: v1})); r == nil || r.Code != "version_tampered" {
		t.Fatalf("a tampered version: %+v", r)
	}
	if f.count(t, `SELECT count(*) FROM execpub.alert WHERE kind = $1 AND device_id = $2`, changeset.KindTamper, f.devs[1].id) == 0 {
		t.Fatal("no tamper alert")
	}
}
