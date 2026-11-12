package triggers_test

import (
	"encoding/json"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/beekamai/network-scheme/internal/triggers"
)

/* alert publishes an executor alert as the executor does, aged by ago (the database clock). */
func (h *harness) alert(kind, severity string, dev int64, text string, ago time.Duration) {
	h.t.Helper()
	var d any
	if dev != 0 {
		d = dev
	}
	h.exec(h.env.Pool("nms_executor"), `INSERT INTO execpub.alert (at, kind, severity, device_id, text)
		VALUES (now() - make_interval(secs => $1), $2, $3, $4, $5)`, ago.Seconds(), kind, severity, d, text)
}

/* sysOpen returns the open problem of system kind sys, object obj and device dev (0: none), if there is one. */
func (h *harness) sysOpen(sys, obj string, dev int64) (prob, bool) {
	h.t.Helper()
	for _, p := range h.openProblems(0) {
		if p.Sys == sys && p.Object == obj && p.Device == dev {
			return p, true
		}
	}
	return prob{}, false
}

func (h *harness) settle() {
	h.t.Helper()
	for range 3 {
		h.advance(5 * time.Second)
	}
}

/*
Every executor alert kind is a system problem with its fixed severity
(whatever the row says), one per kind and device however many alerts
repeat, about the device when the panel has it.
*/
func TestExecutorAlertProblems(t *testing.T) {
	h := newHarness(t)
	dev := h.newDevice()
	want := map[string]string{"executor_tamper": "disaster", "executor_bruteforce": "disaster", "executor_freeze": "warning",
		"executor_policy_invalid": "high", "executor_guards_unwritable": "high", "executor_unverifiable": "high",
		"hostkey_mismatch_write": "high", "mass_unmask": "high", "session_interrupted": "high", "session_outside_window": "warning",
		"executor_recording_failed": "high", "executor_recording_full": "warning", "executor_recording_views": "high",
		"executor_session_tamper": "high", "executor_recording_tamper": "high", "executor_unmask_views": "high", "executor_config_tamper": "high",
		"executor_password_expired": "high", "executor_line_mismatch": "high", "executor_rollback_mismatch": "high",
		"changeset_failed": "high", "changeset_rollback_failed": "high", "changeset_interrupted": "high", "executor_changeset_tamper": "high"}
	for kind := range want {
		h.alert(kind, "info", 0, "first "+kind, time.Minute)
		h.alert(kind, "info", 0, "second "+kind, 0)
		h.alert(kind, "info", dev, "on the device", 0)
	}
	h.settle()
	for kind, sev := range want {
		p, ok := h.sysOpen(kind, "executor", 0)
		if !ok || p.Device != 0 || p.Value != "second "+kind {
			t.Errorf("%s: problem %+v open %v", kind, p, ok)
			continue
		}
		if p2, ok := h.sysOpen(kind, "executor", dev); !ok || p2.Device != dev {
			t.Errorf("%s: no device problem", kind)
		}
		var got string
		if err := h.root.QueryRow(h.ctx, `SELECT severity FROM problems.problem WHERE id = $1`, p.ID).Scan(&got); err != nil || got != sev {
			t.Errorf("%s: severity %q, want %q (%v)", kind, got, sev, err)
		}
		if name := triggers.SystemName(kind); name == "System problem" {
			t.Errorf("%s has no name", kind)
		}
	}
	if n := len(h.openProblems(0)); n != 2*len(want) {
		t.Fatalf("%d open problems, want %d (one per kind and device)", n, 2*len(want))
	}
	/* The marker of a lifted freeze is not a problem itself. */
	h.alert("executor_unfrozen", "info", 0, "lifted", 0)
	h.settle()
	if _, ok := h.sysOpen("executor_unfrozen", "executor", 0); ok {
		t.Fatal("the unfrozen marker opened a problem")
	}
}

/*
An alert's problem is open for 24 h like config_drift: acknowledging does not
resolve it, age does; an alert of an unknown kind is an executor_alert with
the row's severity; one about a device the panel no longer has stays a
problem without a device.
*/
func TestExecutorAlertLifetime(t *testing.T) {
	h := newHarness(t)
	h.alert("session_interrupted", "high", 0, "interrupted", time.Hour)
	h.alert("executor_future2", "average", 0, "new kind", 0)
	h.alert("hostkey_mismatch_write", "high", 987654321, "gone device", 0)
	h.settle()
	p, ok := h.sysOpen("session_interrupted", "executor", 0)
	if !ok {
		t.Fatal("no problem")
	}
	if _, ok := h.sysOpen("executor_alert", "kind:executor_future2", 0); !ok {
		t.Fatal("unknown kind not raised as executor_alert")
	}
	if _, ok := h.sysOpen("hostkey_mismatch_write", "executor:device:987654321", 0); !ok {
		t.Fatal("alert about a device the panel does not have was dropped")
	}
	var sev string
	if err := h.root.QueryRow(h.ctx, `SELECT severity FROM problems.problem WHERE system_kind = 'executor_alert'`).Scan(&sev); err != nil || sev != "average" {
		t.Fatalf("unknown kind severity %q (%v)", sev, err)
	}
	h.exec(h.root, `UPDATE problems.problem SET state = 'acknowledged', acknowledged_at = now() WHERE id = $1`, p.ID)
	h.settle()
	if _, ok := h.sysOpen("session_interrupted", "executor", 0); !ok {
		t.Fatal("acknowledging resolved the problem")
	}
	h.exec(h.root, `UPDATE execpub.alert SET at = now() - interval '25 hours' WHERE kind = 'session_interrupted'`)
	h.settle()
	if _, ok := h.sysOpen("session_interrupted", "executor", 0); ok {
		t.Fatal("a day-old alert still open")
	}
}

/*
A freeze problem stays open past 24 h while the executor's status says
frozen, and resolves once the host lifted the freeze (executor_unfrozen
newer than the alert), even within 24 h; an older marker does not hide a
new freeze.
*/
func TestExecutorFreezeProblemFollowsTheFreeze(t *testing.T) {
	h := newHarness(t)
	exe := h.env.Pool("nms_executor")
	h.alert("executor_unfrozen", "info", 0, "lifted", 72*time.Hour)
	h.alert("executor_tamper", "disaster", 0, "bad MAC in write_grant", 30*time.Hour)
	h.exec(exe, `INSERT INTO execpub.status (enabled, frozen) VALUES (true, true)`)
	h.settle()
	if _, ok := h.sysOpen("executor_tamper", "executor", 0); !ok {
		t.Fatal("a frozen executor's tamper problem resolved with age")
	}
	h.alert("executor_unfrozen", "info", 0, "lifted", 0)
	h.exec(exe, `UPDATE execpub.status SET frozen = false`)
	h.settle()
	if _, ok := h.sysOpen("executor_tamper", "executor", 0); ok {
		t.Fatal("the tamper problem outlived freeze off")
	}
	/* A new freeze after the marker, within a minute: open; lifted again: resolved although it is fresh. */
	time.Sleep(10 * time.Millisecond)
	h.alert("executor_freeze", "warning", 0, "panel: freeze requested", 0)
	h.exec(exe, `UPDATE execpub.status SET frozen = true`)
	h.settle()
	if _, ok := h.sysOpen("executor_freeze", "executor", 0); !ok {
		t.Fatal("a new freeze did not open its problem")
	}
	time.Sleep(10 * time.Millisecond)
	h.alert("executor_unfrozen", "info", 0, "lifted", 0)
	h.exec(exe, `UPDATE execpub.status SET frozen = false, at = now()`)
	h.settle()
	if _, ok := h.sysOpen("executor_freeze", "executor", 0); ok {
		t.Fatal("a lifted freeze is still a problem")
	}
}

/*
Alert text comes from the executor and may carry device data: it is stored
and shown as plain text only, without control or format characters, and
bounded.
*/
func TestExecutorAlertTextIsPlainBoundedText(t *testing.T) {
	h := newHarness(t)
	evil := "<img src=x onerror=alert(1)>\x1b[31m\x07\u202e\u200bgone\r\nnext " + strings.Repeat("ж", 450) /* 900 bytes: the column allows 1024 */
	h.alert("mass_unmask", "high", 0, evil, 0)
	h.settle()
	p, ok := h.sysOpen("mass_unmask", "executor", 0)
	if !ok {
		t.Fatal("no problem")
	}
	if !strings.HasPrefix(p.Value, "<img src=x onerror=alert(1)> [31m") || utf8.RuneCountInString(p.Value) > 200 || !utf8.ValidString(p.Value) {
		t.Fatalf("value %q", p.Value)
	}
	for _, r := range p.Value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			t.Fatalf("value keeps %U", r)
		}
	}
}

/* Every system problem kind the engine raises has an English name and a Russian one in the panel (web/app ru.json). */
func TestEverySystemKindHasNames(t *testing.T) {
	raw, err := os.ReadFile("../../web/app/src/i18n/ru.json")
	if err != nil {
		t.Fatal(err)
	}
	var ru struct {
		Problems struct {
			SystemKind map[string]string `json:"systemKind"`
		} `json:"problems"`
	}
	if err := json.Unmarshal(raw, &ru); err != nil {
		t.Fatal(err)
	}
	kinds := []string{string(triggers.SystemPollerUnavailable), triggers.SystemUnknownSource, triggers.SystemProfileMismatch,
		triggers.SystemSSHMismatch, triggers.SystemConfigDrift, triggers.SystemExecutorAlert, triggers.SystemExecutorUnreachable}
	/* every executor kind with its own severity, so a kind added there cannot miss its names */
	kinds = append(kinds, slices.Sorted(maps.Keys(triggers.ExecutorSeverity()))...)
	for _, k := range kinds {
		if triggers.SystemName(k) == "System problem" {
			t.Errorf("%s has no English name", k)
		}
		if strings.TrimSpace(ru.Problems.SystemKind[k]) == "" {
			t.Errorf("%s has no Russian name in ru.json", k)
		}
	}
}

/*
Every alert kind the executor declares (a Kind... = "..." constant under
cmd/executor) is a problem kind of its own here, so none falls to the generic
executor_alert, and every call that raises one with a literal severity raises
the severity the panel shows (review 4c.6 m-a: a session or recording that
fails its integrity check has kinds of its own, high, apart from the freeze's
executor_tamper).
*/
func TestEveryExecutorAlertKindIsKnown(t *testing.T) {
	sev := triggers.ExecutorSeverity()
	decl := regexp.MustCompile(`\b(Kind\w+)\s*=\s*"([a-z_]+)"`)
	call := regexp.MustCompile(`(?i)\balert\(\w+, (?:(\w+)\.)?(Kind\w+), "(\w+)"`)
	/* constants by package (its directory's name) and name: packages may reuse a name for their own kind */
	names := map[string]string{}
	type use struct{ file, key, severity string }
	var uses []use
	err := filepath.WalkDir("../../cmd/executor", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		pkg := filepath.Base(filepath.Dir(p))
		for _, m := range decl.FindAllStringSubmatch(string(b), -1) {
			names[pkg+"."+m[1]] = m[2]
		}
		for _, m := range call.FindAllStringSubmatch(string(b), -1) {
			q := m[1]
			if q == "" {
				q = pkg
			}
			uses = append(uses, use{p, q + "." + m[2], m[3]})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(names) < 10 || len(uses) < 10 {
		t.Fatalf("the scan found %d kinds and %d alerts: the patterns no longer match the executor's code", len(names), len(uses))
	}
	for name, kind := range names {
		if _, ok := sev[kind]; !ok && kind != "executor_unfrozen" {
			t.Errorf("%s (%s) has no problem kind of its own: it would show as executor_alert", name, kind)
		}
	}
	for _, u := range uses {
		kind, ok := names[u.key]
		if !ok {
			t.Errorf("%s: %s is not declared", u.file, u.key)
			continue
		}
		if kind == "executor_unfrozen" {
			continue
		}
		if sev[kind] != u.severity {
			t.Errorf("%s raises %s as %s, the panel shows it as %s", u.file, kind, u.severity, sev[kind])
		}
	}
	/* the freeze's tamper stays the disaster; a session's or a recording's has its own high kind */
	for _, k := range []string{"freeze.KindTamper", "session.KindTamper", "recording.KindTamper"} {
		if _, ok := names[k]; !ok {
			t.Fatalf("%s not found", k)
		}
	}
	if names["freeze.KindTamper"] != triggers.SystemExecutorTamper || names["session.KindTamper"] != triggers.SystemSessionTamper ||
		names["recording.KindTamper"] != triggers.SystemRecordingTamper {
		t.Errorf("tamper kinds %q %q %q", names["freeze.KindTamper"], names["session.KindTamper"], names["recording.KindTamper"])
	}
}

/*
Review minor 2: an executor_unfrozen marker whose publication was retried
can be stored after the freeze that followed it. While the executor's fresh
status says frozen, the newest freeze alert stays open behind it; it resolves
once the status says not frozen.
*/
func TestLateUnfrozenMarkerDoesNotHideAFreeze(t *testing.T) {
	h := newHarness(t)
	exe := h.env.Pool("nms_executor")
	h.exec(exe, `INSERT INTO execpub.status (enabled, frozen) VALUES (true, true)`)
	h.alert("executor_freeze", "warning", 0, "panel: freeze requested", 2*time.Second)
	h.alert("executor_unfrozen", "info", 0, "the host lifted the freeze (freeze off)", 0)
	h.settle()
	if _, ok := h.sysOpen("executor_freeze", "executor", 0); !ok {
		t.Fatal("a late marker hid the freeze of a frozen executor")
	}
	h.exec(exe, `UPDATE execpub.status SET frozen = false, at = now()`)
	h.settle()
	if _, ok := h.sysOpen("executor_freeze", "executor", 0); ok {
		t.Fatal("freeze problem open on an executor that is not frozen")
	}
}

/*
Review minor 5: a stale status (older than 90 s) never hides a freeze problem
(its "not frozen" may be old news), and a stale status of an enabled executor
is a problem of its own, which resolves when the status is fresh again; a
disabled executor that stopped publishing is not.
*/
func TestStaleExecutorStatus(t *testing.T) {
	h := newHarness(t)
	exe := h.env.Pool("nms_executor")
	h.alert("executor_tamper", "disaster", 0, "bad MAC", 30*time.Hour)
	h.exec(exe, `INSERT INTO execpub.status (enabled, frozen, at) VALUES (true, false, now() - interval '5 minutes')`)
	h.settle()
	if _, ok := h.sysOpen("executor_tamper", "executor", 0); !ok {
		t.Fatal("a stale 'not frozen' hid the tamper problem")
	}
	p, ok := h.sysOpen("executor_unreachable", "executor", 0)
	if !ok {
		t.Fatal("a stale status of an enabled executor is no problem")
	}
	var sev string
	if err := h.root.QueryRow(h.ctx, `SELECT severity FROM problems.problem WHERE id = $1`, p.ID).Scan(&sev); err != nil || sev != "high" {
		t.Fatalf("severity %q (%v)", sev, err)
	}
	h.exec(exe, `UPDATE execpub.status SET at = now()`)
	h.settle()
	if _, ok := h.sysOpen("executor_unreachable", "executor", 0); ok {
		t.Fatal("unreachable while the status is fresh")
	}
	if _, ok := h.sysOpen("executor_tamper", "executor", 0); ok {
		t.Fatal("a 30 h old tamper alert open on a fresh, not frozen executor")
	}
	h.exec(exe, `UPDATE execpub.status SET enabled = false, at = now() - interval '5 minutes'`)
	h.settle()
	if _, ok := h.sysOpen("executor_unreachable", "executor", 0); ok {
		t.Fatal("a disabled executor that stopped publishing raised executor_unreachable")
	}
}

/*
Re-review minor 2: a stale status keeps open only freeze alerts newer than
the last marker; a tamper freeze lifted weeks ago does not reopen as a
disaster whenever the executor stops publishing (it is executor_unreachable).
*/
func TestStaleStatusDoesNotReopenALiftedFreeze(t *testing.T) {
	h := newHarness(t)
	exe := h.env.Pool("nms_executor")
	h.alert("executor_tamper", "disaster", 0, "bad MAC", 29*24*time.Hour)
	h.alert("executor_unfrozen", "info", 0, "the host lifted the freeze (registry reset)", 28*24*time.Hour)
	h.exec(exe, `INSERT INTO execpub.status (enabled, frozen, at) VALUES (true, false, now() - interval '5 minutes')`)
	h.settle()
	if _, ok := h.sysOpen("executor_tamper", "executor", 0); ok {
		t.Fatal("a freeze lifted weeks ago reopened on a stale status")
	}
	if _, ok := h.sysOpen("executor_unreachable", "executor", 0); !ok {
		t.Fatal("no executor_unreachable")
	}
	/* A fresh status that says frozen keeps the newest freeze open behind the marker (a late marker). */
	h.exec(exe, `UPDATE execpub.status SET frozen = true, at = now()`)
	h.settle()
	if _, ok := h.sysOpen("executor_tamper", "executor", 0); !ok {
		t.Fatal("the newest freeze of a frozen executor is hidden by an older-looking marker")
	}
}
