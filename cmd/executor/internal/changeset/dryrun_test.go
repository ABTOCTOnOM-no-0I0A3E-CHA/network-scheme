package changeset_test

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/changeset"
	rdrivers "github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/drivers/eltexesr"
	"github.com/beekamai/network-scheme/internal/drivers/eltexmes"
	"github.com/beekamai/network-scheme/internal/ssh"
)

/* dryRun runs the dry-run of the changeset's revision rev and returns what progress shows. */
func (f *fx) dryRun(t *testing.T, token, id string, rev int) changeset.Detail {
	t.Helper()
	if _, err := f.op(t, token, "dry-run", map[string]any{"changeset_id": id, "revision": rev}); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	f.m.WaitDryRun(id)
	res, err := f.op(t, token, "progress", map[string]any{"changeset_id": id})
	if err != nil {
		t.Fatal(err)
	}
	d := res.(changeset.Detail)
	if d.DryRun == nil || d.DryRun.Running || d.DryRun.Result == nil {
		t.Fatalf("dry-run state %+v", d.DryRun)
	}
	return d
}

/* dialect is the read dialect of a line: what alone may reach a device during a dry-run. */
func dialect(line string) ssh.Dialect {
	switch line {
	case "esr":
		return eltexesr.New().Dialect()
	case "mes6":
		return eltexmes.New().ForIdentity(rdrivers.Identity{Firmware: "6.0"}).Dialect()
	}
	return eltexmes.New().ForIdentity(rdrivers.Identity{Firmware: "10.0"}).Dialect()
}

/*
A dry-run on every line: the executor reads each device itself over a
ReadOnly connection (only the read allowlist reaches the emulators, the
running configuration stays), holds device_busy meanwhile, records the
dry_run event (pre_sha256 per device, plan_sha256) and the status; the same
devices and lines give the same plan_sha256.
*/
func TestDryRunOnEveryLine(t *testing.T) {
	f := newFx(t, "mes6", "mes10", "esr")
	alice := f.user(t, "core")
	tok := f.open(t, alice)
	before := map[int64]string{}
	for _, d := range f.devs {
		before[d.id] = d.d.Running()
	}
	s := f.save(t, tok, "", 0, f.lines("descriptions", f.devs...))
	d := f.dryRun(t, tok, s.ID, 1)
	r := d.DryRun.Result
	if !r.OK || d.Status != changeset.StatusDryRunOK || len(r.Devices) != 3 || len(r.Plan) != 64 {
		t.Fatalf("dry-run %+v, status %s", r, d.Status)
	}
	for i, dv := range r.Devices {
		if dv.ID != f.devs[i].id || len(dv.Pre) != 64 || dv.Group != "core" || dv.Line != f.devs[i].line || dv.Refused != nil {
			t.Errorf("device %d: %+v", i, dv)
		}
	}
	if len(r.Preview) == 0 || !slices.Contains(r.Preview[0].Lines, "description nms-test") {
		t.Errorf("preview %+v", r.Preview)
	}
	for _, dv := range f.devs {
		if dv.d.Running() != before[dv.id] {
			t.Errorf("%s: the dry-run changed the configuration", dv.line)
		}
		dl := dialect(dv.line)
		for _, l := range dv.d.Lines() {
			if !slices.Contains(dl.PagerOff, l) && !slices.ContainsFunc(dl.Allowlist, func(c ssh.ShowCommand) bool { return c.Name == l }) {
				t.Errorf("%s: %q reached the device outside the read allowlist", dv.line, l)
			}
		}
	}
	if n := f.count(t, `SELECT count(*) FROM execpub.device_busy`); n != 0 {
		t.Errorf("%d device_busy rows left", n)
	}
	for _, dv := range f.devs {
		le, ok := f.locks.TryLock(dv.id)
		if !ok {
			t.Fatalf("lease of %d still held", dv.id)
		}
		le.Release()
	}
	var ev struct {
		OK   bool   `json:"ok"`
		Plan string `json:"plan_sha256"`
	}
	if n := len(d.Events); n != 1 || d.Events[0].Kind != "dry_run" || json.Unmarshal(d.Events[0].Payload, &ev) != nil || !ev.OK || ev.Plan != r.Plan {
		t.Fatalf("events %+v", d.Events)
	}
	if f.audits(t, "changeset.dry_run", "ok") != 1 {
		t.Error("no audit row for the dry-run")
	}
	/* deterministic: the same revision again gives the same plan */
	if again := f.dryRun(t, tok, s.ID, 1); again.DryRun.Result.Plan != r.Plan {
		t.Fatalf("plan_sha256 changed: %s / %s", again.DryRun.Result.Plan, r.Plan)
	}
}

/*
D2 on real devices: a dangerous line (here from a variable's value), a line
in the management interface's context, a line MES 6.x cannot invert and a
busy device each fail the dry-run with the device and the line; nothing
reaches a device but the read allowlist.
*/
func TestDryRunRefusals(t *testing.T) {
	f := newFx(t, "mes6", "mes6", "esr", "mes10")
	alice := f.user(t, "core")
	tok := f.open(t, alice)
	c := f.lines("refusals", f.devs...)
	c.Steps = []changeset.Step{{Line: "{{cfg}}"}, {Line: "{{cmd}}"}, {Line: "description x"}, {Line: "end"}}
	c.Vars[f.devs[0].id]["cmd"] = "no ip ssh server"                /* MES 6.x: dangerous, from a variable */
	c.Vars[f.devs[1].id]["cmd"] = "interface range gi1/0/2-3"       /* MES 6.x: safe, but no inverse of a range */
	c.Vars[f.devs[2].id]["cmd"] = "interface gigabitethernet 1/0/1" /* ESR: the management interface (registry address) */
	c.Vars[f.devs[3].id]["cmd"] = "interface gi0/2"                 /* MES 10.x: fine, but the device is busy */
	s := f.save(t, tok, "", 0, c)
	le, ok := f.locks.TryLock(f.devs[3].id) /* another connection of the executor (a backup, a session) holds it */
	if !ok {
		t.Fatal("lock")
	}
	d := f.dryRun(t, tok, s.ID, 1)
	le.Release()
	r := d.DryRun.Result
	if r.OK || d.Status != changeset.StatusDryRunFailed {
		t.Fatalf("dry-run passed: %+v", r)
	}
	want := []struct {
		code  string
		n     int
		class string
	}{{"not_safe", 2, "dangerous"}, {"no_inverse", 0, ""}, {"not_safe", 3, "dangerous"}, {"device_busy", 0, ""}}
	for i, w := range want {
		got := r.Devices[i].Refused
		if got == nil || got.Code != w.code || got.N != w.n || got.Class != w.class {
			t.Errorf("device %d (%s): %+v, want %+v", i, f.devs[i].line, got, w)
		}
	}
	for _, dv := range f.devs {
		dl := dialect(dv.line)
		for _, l := range dv.d.Lines() {
			if !slices.Contains(dl.PagerOff, l) && !slices.ContainsFunc(dl.Allowlist, func(c ssh.ShowCommand) bool { return c.Name == l }) {
				t.Errorf("%s: %q reached the device", dv.line, l)
			}
		}
	}
	/* a device in a change session (device_busy of another session) is refused too */
	if _, err := f.env.Pool("nms_executor").Exec(context.Background(), `INSERT INTO execpub.device_busy (device_id, session_id, address) VALUES ($1, gen_random_uuid(), '192.0.2.20')`,
		f.devs[3].id); err != nil {
		t.Fatal(err)
	}
	d = f.dryRun(t, tok, s.ID, 1)
	if got := d.DryRun.Result.Devices[3].Refused; got == nil || got.Code != "device_busy" {
		t.Fatalf("device in a session: %+v", got)
	}
	/* the per-user limit */
	f.policy(t, "changeset_dry_runs_per_hour: 2\n")
	if _, err := f.op(t, tok, "dry-run", map[string]any{"changeset_id": s.ID, "revision": 1}); code(err) != "dry_run_limit" {
		t.Fatalf("over the limit: %v", err)
	}
}
