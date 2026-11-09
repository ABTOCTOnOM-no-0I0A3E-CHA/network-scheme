package session_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/confirm"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
	_ "github.com/beekamai/network-scheme/cmd/executor/internal/drivers/esr"
	_ "github.com/beekamai/network-scheme/cmd/executor/internal/drivers/mes10"
	"github.com/beekamai/network-scheme/cmd/executor/internal/session"
	"github.com/beekamai/network-scheme/internal/backup"
)

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	return c
}

/* typeLines sends lines on the session's device as the terminal does: the session's Classify, Safe only. */
func (f *fx) typeLines(t *testing.T, o session.Opened, lines ...string) {
	t.Helper()
	if err := f.m.Use(o.ID, o.Token, func(s *session.Session) error {
		d := s.Devices[0]
		for _, l := range lines {
			v := d.Session.Classify(l)
			if v.Class != core.Safe {
				return fmt.Errorf("%q is %s", l, v.Class)
			}
			if _, err := d.Session.Send(ctx(t), v); err != nil {
				return fmt.Errorf("%q: %w", l, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

/* running is the hash of the device's running configuration, as the session hashes it. */
func (f *fx) running() string {
	c := drivers.NewConfig(f.d.Running())
	return hex.EncodeToString(c.SHA256[:])
}

/* rollback issues the rollback challenge of o for u and confirms it with a new code (confirm.Store and authz, as /x/confirm does). */
func (f *fx) rollback(t *testing.T, u who, o session.Opened, edit func(*confirm.Challenge)) (map[string]any, error) {
	t.Helper()
	cs := confirm.New(f.az, f.now)
	by := authz.Decision{UserID: u.id, Username: u.name}
	need, d, err := f.m.DescribeRollback(ctx(t), by, json.RawMessage(`{"session_id":"`+o.ID+`"}`))
	if err != nil {
		return nil, err
	}
	ch, err := cs.Issue(u.id, need, d)
	if err != nil {
		t.Fatal(err)
	}
	c, by, err := cs.Confirm(ctx(t), ch.ID, ch.H[:], f.req(t, u))
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if edit != nil {
		edit(&c)
	}
	res, err := f.m.RunRollback(ctx(t), c, by)
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(res)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m, nil
}

func rolledBack(t *testing.T, res map[string]any) map[string]any {
	t.Helper()
	ds, _ := res["devices"].([]any)
	if len(ds) != 1 {
		t.Fatalf("result %v", res)
	}
	return ds[0].(map[string]any)
}

func field(d confirm.Description, k string) string {
	for _, f := range d.Fields {
		if f.Key == k {
			return f.Value
		}
	}
	return ""
}

/*
C7 (emulator): for every line and every rollback strategy (MES 6.x inverse
journal, MES 10.x replace, ESR candidate / unconfirmed commit / confirmed
commit) the whole-session rollback through confirm(H) leaves the running
configuration normalizing to the pre-session snapshot from exec.
*/
func TestC7RollbackRestoresThePreSessionSnapshot(t *testing.T) {
	for _, c := range []struct {
		name, line string
		lines      []string
		esr        string /* "", "commit", "confirm" */
	}{
		{"mes6/inverse", "mes6", []string{"configure", "hostname edge-7", "interface gigabitethernet1/0/2", "description nms-c7", "end"}, ""},
		{"mes10/replace", "mes10", []string{"configure terminal", "hostname edge-7", "end"}, ""},
		{"esr/candidate", "esr", []string{"configure", "hostname edge-7", "end"}, ""},
		{"esr/unconfirmed", "esr", []string{"configure", "hostname edge-7"}, "commit"},
		{"esr/confirmed", "esr", []string{"configure", "hostname edge-7"}, "confirm"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newLineFx(t, c.line)
			u := f.user(t, "core")
			o := f.open(t, u)
			pre := o.Devices[0].PreSHA256
			if f.running() != pre {
				t.Fatal("the emulator's configuration does not hash as the snapshot")
			}
			f.typeLines(t, o, c.lines...)
			if c.esr != "" {
				dd, err := f.m.Commit(ctx(t), o.ID, o.Token, f.id)
				if err != nil {
					t.Fatalf("commit: %v", err)
				}
				if dd.Pending == nil || dd.SHA256 == pre || f.running() == pre {
					t.Fatalf("commit: %+v", dd)
				}
				if c.esr == "confirm" {
					if _, err := f.m.Save(ctx(t), o.ID, o.Token, f.id, dd.SHA256); err != nil {
						t.Fatalf("confirm: %v", err)
					}
				}
			}
			res, err := f.rollback(t, u, o, nil)
			if err != nil {
				t.Fatal(err)
			}
			if r := rolledBack(t, res); r["error"] != nil || r["sha256"] != pre || f.running() != pre {
				t.Fatalf("rollback %v: running %s, pre %s\n%s", r, f.running(), pre, f.d.Running())
			}
			if c.esr != "" {
				for _, l := range f.d.Lines() {
					if strings.HasPrefix(l, "commit") && !strings.HasPrefix(l, "commit confirm-timeout ") {
						t.Fatalf("a commit without the policy's timer: %q", l)
					}
				}
			}
			if err := f.m.Close(ctx(t), o.ID, o.Token); err != nil {
				t.Fatal(err)
			}
			f.free(t, "closed")
		})
	}
}

/* tamper changes the exec.session_device row of o as a database superuser would (the append-only trigger off). */
func (f *fx) tamper(t *testing.T, o session.Opened, set string, args ...any) {
	t.Helper()
	tx, err := f.env.Pool("postgres").Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(context.Background(), `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(context.Background(), `UPDATE exec.session_device SET `+set+` WHERE session_id = $1`, append([]any{o.ID}, args...)...); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
}

/*
C2i: a superuser's pre_ct or pre_sha256, or a validly sealed backup of
another configuration with its own hash put in the row, fails the row's MAC:
the rollback is refused before anything is sent, with a high tamper alert. A
tampered pre_session config_version row changes nothing: the rollback never
reads it (Review Focus 4c.3).
*/
func TestC2iRollbackOnlyToTheMACdSnapshot(t *testing.T) {
	f := newFx(t)
	u := f.user(t, "core")
	o := f.open(t, u)
	preText := f.d.Running()
	f.typeLines(t, o, "configure", "hostname edge-7", "end")
	var ct, dek, sum, mac []byte
	if err := f.env.Pool("postgres").QueryRow(context.Background(), `SELECT pre_ct, pre_dek_ct, pre_sha256, mac FROM exec.session_device
		WHERE session_id = $1`, o.ID).Scan(&ct, &dek, &sum, &mac); err != nil {
		t.Fatal(err)
	}
	/* the same snapshot in a new envelope: it opens under its AAD and hashes right; only the row's MAC tells */
	rct, rdek, err := backup.Seal(f.bpub, []byte(preText), backup.AAD(f.id, hex.EncodeToString(sum)))
	if err != nil {
		t.Fatal(err)
	}
	other := "hostname planted\n"
	osum := sha256.Sum256([]byte(other))
	oct, odek, err := backup.Seal(f.bpub, []byte(other), backup.AAD(f.id, hex.EncodeToString(osum[:])))
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		set  string
		args []any
	}{
		"pre_ct":           {"pre_ct = $2", []any{append(append([]byte(nil), ct...), 0)}},
		"pre_sha256":       {"pre_sha256 = $2", []any{osum[:]}},
		"a foreign backup": {"pre_ct = $2, pre_dek_ct = $3, pre_sha256 = $4", []any{oct, odek, osum[:]}},
		"a new envelope":   {"pre_ct = $2, pre_dek_ct = $3", []any{rct, rdek}},
		"the mac":          {"mac = set_byte(mac, 0, get_byte(mac, 0) # 1)", nil},
	} {
		alerts, lines := f.alerts(t, session.KindTamper), len(f.d.Lines())
		f.tamper(t, o, c.set, c.args...)
		if _, err := f.rollback(t, u, o, nil); !errors.Is(err, session.ErrSnapshotBad) {
			t.Fatalf("%s: %v", name, err)
		}
		if f.alerts(t, session.KindTamper) != alerts+1 || len(f.d.Lines()) != lines {
			t.Fatalf("%s: alerts %d, device got %q", name, f.alerts(t, session.KindTamper)-alerts, f.d.Lines()[lines:])
		}
		f.tamper(t, o, "pre_ct = $2, pre_dek_ct = $3, pre_sha256 = $4, mac = $5", ct, dek, sum, mac)
	}
	/* the poller's copy is not a rollback source: planting another configuration there changes nothing */
	if _, err := f.env.Pool("postgres").Exec(context.Background(), `UPDATE backups.config_version SET sha256 = $2
		WHERE device_id = $1 AND source = 'pre_session'`, f.id, osum[:]); err != nil {
		t.Logf("config_version not writable: %v", err) /* append-only: the point holds either way */
	}
	res, err := f.rollback(t, u, o, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r := rolledBack(t, res); r["error"] != nil || f.running() != o.Devices[0].PreSHA256 {
		t.Fatalf("rollback %v", r)
	}
}

/*
C2k primitive: the rollback runs only on the description confirmed. A
description edited after the challenge (another snapshot hash), or one the
session no longer matches (the device moved to another write group since),
is refused (changed) and the device gets nothing.
*/
func TestRollbackOnlyAsConfirmed(t *testing.T) {
	f := newFx(t)
	u := f.user(t, "core", "edge")
	o := f.open(t, u)
	f.typeLines(t, o, "configure", "hostname edge-7", "end")
	lines := len(f.d.Lines())
	key := "pre_sha256_" + fmt.Sprint(f.id)
	_, err := f.rollback(t, u, o, func(c *confirm.Challenge) {
		for i := range c.Description.Fields {
			if c.Description.Fields[i].Key == key {
				c.Description.Fields[i].Value = strings.Repeat("0", 64)
			}
		}
	})
	if !errors.Is(err, session.ErrDescription) {
		t.Fatalf("edited description: %v", err)
	}
	_, err = f.rollback(t, u, o, func(*confirm.Challenge) {
		f.row["write_group"] = "edge"
		f.put(t, "write_device", f.row)
	})
	if !errors.Is(err, session.ErrDescription) || len(f.d.Lines()) != lines {
		t.Fatalf("group changed: %v, device got %q", err, f.d.Lines()[lines:])
	}
	/* another user cannot describe it */
	other := f.user(t, "core", "edge")
	if _, _, err := f.m.DescribeRollback(ctx(t), authz.Decision{UserID: other.id}, json.RawMessage(`{"session_id":"`+o.ID+`"}`)); !errors.Is(err, session.ErrNoSession) {
		t.Fatalf("another user: %v", err)
	}
}

/* waitInterrupted runs the manager's checks until the session's summary is interrupted. */
func (f *fx) waitInterrupted(t *testing.T, o session.Opened) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for f.status(t, o.ID) == "open" && time.Now().Before(deadline) {
		f.m.Check(context.Background())
		time.Sleep(100 * time.Millisecond)
	}
	if f.status(t, o.ID) != "interrupted" {
		t.Fatalf("status %s", f.status(t, o.ID))
	}
}

/*
C6 (emulator), ESR: the link drops after a commit that waits for its
confirm. The executor ends the session as interrupted, says the device's
timer reverts the commit, never sends confirm (nor anything else), refuses
to roll back by itself (commit_timer), and the device's timer restores the
pre-session configuration.
*/
func TestC6ESRRevertsByItsTimer(t *testing.T) {
	f := newLineFx(t, "esr")
	u := f.user(t, "core")
	o := f.open(t, u)
	f.typeLines(t, o, "configure", "hostname edge-7")
	if _, err := f.m.Commit(ctx(t), o.ID, o.Token, f.id); err != nil {
		t.Fatalf("commit: %v", err)
	}
	lines := len(f.d.Lines())
	f.d.Disconnect()
	f.waitInterrupted(t, o)
	var text string
	if err := f.env.Pool("postgres").QueryRow(context.Background(), `SELECT text FROM execpub.alert WHERE kind = $1`,
		session.KindInterrupted).Scan(&text); err != nil || !strings.Contains(text, "timer") {
		t.Fatalf("alert %q: %v", text, err)
	}
	_, d, err := f.m.DescribeRollback(ctx(t), authz.Decision{UserID: u.id}, json.RawMessage(`{"session_id":"`+o.ID+`"}`))
	if err != nil || field(d, "state_"+fmt.Sprint(f.id)) != "commit_pending" {
		t.Fatalf("describe %v: %v", d, err)
	}
	res, err := f.rollback(t, u, o, nil)
	if err != nil || rolledBack(t, res)["error"] != string(session.ErrCommitTimer) {
		t.Fatalf("rollback %v: %v", res, err)
	}
	if got := f.d.Lines()[lines:]; len(got) != 0 {
		t.Fatalf("the executor sent %q after the link dropped", got)
	}
	f.d.Advance(11 * time.Minute)
	if f.running() != o.Devices[0].PreSHA256 {
		t.Fatalf("the timer did not revert the commit:\n%s", f.d.Running())
	}
}

/*
C6 (emulator), MES: the link drops mid-session. The session is interrupted
with the session_interrupted alert, and the whole-session rollback works over
a new connection from the snapshot in exec (inverse journal, hash checked);
the device is free after it.
*/
func TestC6MESRollbackAfterLinkLoss(t *testing.T) {
	f := newFx(t)
	u := f.user(t, "core")
	o := f.open(t, u)
	f.typeLines(t, o, "configure", "hostname edge-7", "end")
	f.d.Disconnect()
	f.waitInterrupted(t, o)
	if f.alerts(t, session.KindInterrupted) != 1 {
		t.Fatal("no session_interrupted alert")
	}
	f.free(t, "interrupted")
	res, err := f.rollback(t, u, o, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r := rolledBack(t, res); r["error"] != nil || f.running() != o.Devices[0].PreSHA256 {
		t.Fatalf("rollback %v:\n%s", r, f.d.Running())
	}
	f.free(t, "rolled back")
	/* done: the session is gone */
	if _, _, err := f.m.DescribeRollback(ctx(t), authz.Decision{UserID: u.id}, json.RawMessage(`{"session_id":"`+o.ID+`"}`)); !errors.Is(err, session.ErrNoSession) {
		t.Fatalf("after the rollback: %v", err)
	}
}

/* An interrupted session is not rolled back over a device another session opened since (superseded). */
func TestRollbackSupersededByALaterSession(t *testing.T) {
	f := newFx(t)
	u := f.user(t, "core")
	o := f.open(t, u)
	f.typeLines(t, o, "configure", "hostname edge-7", "end")
	f.d.Disconnect()
	f.waitInterrupted(t, o)
	o2 := f.open(t, u)
	if err := f.m.Close(ctx(t), o2.ID, o2.Token); err != nil {
		t.Fatal(err)
	}
	res, err := f.rollback(t, u, o, nil)
	if err != nil || rolledBack(t, res)["error"] != string(session.ErrSuperseded) {
		t.Fatalf("rollback %v: %v", res, err)
	}
}

/*
Diff, save, typed control lines and forms on MES 6.x: the diff shows the
change, save needs the hash of the configuration the diff showed, a typed
write opens the save flow and sends nothing, a form sends exactly the lines
shown and only Safe ones.
*/
func TestDiffSaveTypedAndForms(t *testing.T) {
	f := newFx(t)
	u := f.user(t, "core")
	o := f.open(t, u)
	act := func(op, params string) (any, error) {
		return f.m.Act(ctx(t), o.ID, o.Token, op, json.RawMessage(params))
	}
	f.typeLines(t, o, "configure", "hostname edge-7", "end")
	res, err := act("diff", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	dd := res.([]session.DeviceDiff)[0]
	if !strings.Contains(dd.Diff, "+hostname edge-7") || dd.SHA256 != f.running() {
		t.Fatalf("diff %+v", dd)
	}
	if _, err := act("save", `{"device_id":`+fmt.Sprint(f.id)+`,"sha256":"`+o.Devices[0].PreSHA256+`"}`); !errors.Is(err, session.ErrStale) {
		t.Fatalf("save of another configuration: %v", err)
	}
	if strings.Contains(f.d.Saved(), "edge-7") {
		t.Fatal("saved without the shown hash")
	}
	lines := len(f.d.Lines())
	if err := f.m.Use(o.ID, o.Token, func(s *session.Session) error {
		fl, err := f.m.Typed(ctx(t), s, f.id, s.Devices[0].Session.Classify("write"))
		if err == nil && (fl.Kind != "save" || fl.Diff.SHA256 != dd.SHA256) {
			err = fmt.Errorf("flow %+v", fl)
		}
		return err
	}); err != nil || slices.ContainsFunc(f.d.Lines()[lines:], func(l string) bool { return l != "show running-config" }) {
		t.Fatalf("typed write: %v, device got %q", err, f.d.Lines()[lines:])
	}
	if _, err := act("save", `{"device_id":`+fmt.Sprint(f.id)+`,"sha256":"`+dd.SHA256+`"}`); err != nil || !strings.Contains(f.d.Saved(), "edge-7") {
		t.Fatalf("save: %v", err)
	}
	/* forms: the equivalent commands, then exactly those */
	form := `"form":{"kind":"interface-description","interface":"gi1/0/2","description":"nms-form"}`
	res, err = act("form", `{"device_id":`+fmt.Sprint(f.id)+`,`+form+`}`)
	if err != nil {
		t.Fatal(err)
	}
	shown := res.(session.FormLines).Lines
	b, _ := json.Marshal(append(shown[:len(shown):len(shown)], "hostname x"))
	if _, err := act("form-apply", `{"device_id":`+fmt.Sprint(f.id)+`,`+form+`,"lines":`+string(b)+`}`); !errors.Is(err, session.ErrStale) {
		t.Fatalf("other lines: %v", err)
	}
	b, _ = json.Marshal(shown)
	lines = len(f.d.Lines())
	res, err = act("form-apply", `{"device_id":`+fmt.Sprint(f.id)+`,`+form+`,"lines":`+string(b)+`}`)
	if err != nil || res.(session.FormApplied).Sent != len(shown) || !slices.Equal(f.d.Lines()[lines:], append(shown, "show running-config")) {
		t.Fatalf("form-apply: %v %+v, device got %q", err, res, f.d.Lines()[lines:])
	}
	/* a form on the management interface is dangerous: not sent from a form */
	mform := `"form":{"kind":"interface-description","interface":"gi1/0/1","description":"nms-form"}`
	res, _ = act("form", `{"device_id":`+fmt.Sprint(f.id)+`,`+mform+`}`)
	b, _ = json.Marshal(res.(session.FormLines).Lines)
	lines = len(f.d.Lines())
	if _, err := act("form-apply", `{"device_id":`+fmt.Sprint(f.id)+`,`+mform+`,"lines":`+string(b)+`}`); !errors.Is(err, session.ErrFormLine) {
		t.Fatalf("management form: %v", err)
	}
	for _, l := range f.d.Lines()[lines:] {
		if strings.Contains(l, "description") {
			t.Fatalf("a dangerous form line reached the device: %q", l)
		}
	}
}
