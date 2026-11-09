package execpolicy

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

/* The shipped example and the install template are the defaults, disabled. */
func TestShippedPoliciesAreTheDefault(t *testing.T) {
	for _, p := range []string{"deploy/policies/executor.yaml.example", "deploy/templates/executor-policy.yaml.tmpl"} {
		data, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(p)))
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse(data)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if !reflect.DeepEqual(got, Default()) || got.Enabled {
			t.Fatalf("%s: %+v", p, got)
		}
	}
}

/* A minimal file takes every default; a full one round-trips through Marshal. */
func TestParseDefaultsAndRoundTrip(t *testing.T) {
	p, err := Parse([]byte("enabled: false\n"))
	if err != nil || !reflect.DeepEqual(p, Default()) {
		t.Fatalf("%+v %v", p, err)
	}
	full := `enabled: true
confirm_mode: fido2
session_minutes: 60
idle_minutes: 15
max_devices_per_session: 3
max_config_lines_per_hour: 100
timezone: Europe/Moscow
windows:
  - days: [mon, fri]
    start: "09:00"
    end: "24:00"
outside_window: second_person
two_person_groups: [core, dc-1]
class_overrides:
  - {driver: esr, command: "clear counters", class: safe}
  - {driver: any, command: "show tech-support", class: denied}
telnet_write: true
mes_reload_in_min: 10
esr_commit_timer_s: 1200
paste_confirm_lines: 1
unmask_per_hour: 1
mass_unmask_alert: 10000
recording_max_mib: 64
recording_views_per_hour: 1
`
	p, err = Parse([]byte(full))
	if err != nil {
		t.Fatal(err)
	}
	if !p.Enabled || p.ConfirmMode != ConfirmFIDO2 || len(p.Windows) != 1 || p.Windows[0].End != "24:00" || len(p.ClassOverrides) != 2 {
		t.Fatalf("%+v", p)
	}
	out, err := Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	q, err := Parse(out)
	if err != nil || !reflect.DeepEqual(p, q) {
		t.Fatalf("round trip: %+v %v\n%s", q, err, out)
	}
}

/* Everything that is not a plain, valid policy is refused (and so disables the executor). */
func TestParseRefuses(t *testing.T) {
	for name, src := range map[string]string{
		"empty":                "",
		"comment only":         "# nothing\n",
		"not a mapping":        "- enabled: true\n",
		"unknown key":          "enabled: false\nenable: true\n",
		"duplicate key":        "enabled: false\nenabled: true\n",
		"two documents":        "enabled: false\n---\nenabled: true\n",
		"yes as bool":          "enabled: yes\n",
		"quoted bool":          "enabled: \"true\"\n",
		"anchor":               "windows: &w []\ntwo_person_groups: *w\n",
		"merge key":            "windows:\n  - &a {days: [mon], start: \"09:00\", end: \"10:00\"}\n  - <<: *a\n",
		"custom tag":           "timezone: !foo UTC\n",
		"float":                "session_minutes: 30.5\n",
		"null number":          "session_minutes:\n",
		"string number":        "session_minutes: \"30\"\n",
		"session too long":     "session_minutes: 241\n",
		"idle over session":    "session_minutes: 10\nidle_minutes: 11\n",
		"no devices":           "max_devices_per_session: 0\n",
		"esr timer low":        "esr_commit_timer_s: 119\n",
		"esr timer high":       "esr_commit_timer_s: 1201\n",
		"paste zero":           "paste_confirm_lines: 0\n",
		"reload too short":     "mes_reload_in_min: 2\n",
		"confirm mode":         "confirm_mode: sms\n",
		"outside":              "outside_window: allow\n",
		"timezone":             "timezone: Mars/Olympus\n",
		"local timezone":       "timezone: Local\n",
		"window days":          "windows: [{days: [mon, mon], start: \"09:00\", end: \"10:00\"}]\n",
		"window bad day":       "windows: [{days: [monday], start: \"09:00\", end: \"10:00\"}]\n",
		"window no days":       "windows: [{days: [], start: \"09:00\", end: \"10:00\"}]\n",
		"window overnight":     "windows: [{days: [mon], start: \"22:00\", end: \"02:00\"}]\n",
		"window clock":         "windows: [{days: [mon], start: \"9:00\", end: \"10:00\"}]\n",
		"window start 24":      "windows: [{days: [mon], start: \"24:00\", end: \"24:00\"}]\n",
		"group":                "two_person_groups: [Core]\n",
		"repeated group":       "two_person_groups: [core, core]\n",
		"override driver":      "class_overrides: [{driver: cisco, command: reload, class: safe}]\n",
		"override class":       "class_overrides: [{driver: esr, command: reload, class: fine}]\n",
		"override spaces":      "class_overrides: [{driver: esr, command: \"reload  in\", class: safe}]\n",
		"override control":     "class_overrides: [{driver: esr, command: \"reload\\tin\", class: safe}]\n",
		"override repeated":    "class_overrides: [{driver: esr, command: reload, class: safe}, {driver: esr, command: reload, class: denied}]\n",
		"override unknown key": "class_overrides: [{driver: esr, command: reload, class: safe, why: x}]\n",
		"not utf-8":            "timezone: \xff\n",
		"too large":            "enabled: false\n" + strings.Repeat("#", MaxSize),
	} {
		if p, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: accepted %+v", name, p)
		}
	}
}

/* SetEnabled flips only enabled, keeps comments and refuses an invalid file. */
func TestSetEnabled(t *testing.T) {
	src := []byte("# keep me\nenabled: false # inline\nsession_minutes: 20\n")
	out, err := SetEnabled(src, true)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(out)
	if err != nil || !p.Enabled || p.SessionMinutes != 20 || !bytes.Contains(out, []byte("# keep me")) || !bytes.Contains(out, []byte("# inline")) {
		t.Fatalf("%s %+v %v", out, p, err)
	}
	out, err = SetEnabled([]byte("session_minutes: 20\n"), true)
	if p, perr := Parse(out); err != nil || perr != nil || !p.Enabled {
		t.Fatalf("missing key: %s %v %v", out, err, perr)
	}
	if _, err := SetEnabled([]byte("enabled: maybe\n"), true); err == nil {
		t.Fatal("invalid file accepted")
	}
}

/*
FuzzPolicy: Parse never panics; whatever it accepts is valid, round-trips
through Marshal unchanged and through SetEnabled with only enabled changed.
*/
func FuzzPolicy(f *testing.F) {
	for _, s := range []string{
		"enabled: false\n", "enabled: true\nsession_minutes: 60\n",
		"windows: [{days: [mon], start: \"09:00\", end: \"10:00\"}]\n",
		"class_overrides: [{driver: any, command: \"show run\", class: denied}]\n",
		"two_person_groups: [a, b]\ntimezone: Asia/Tokyo\n", "enabled: yes\n", "&a x: *a\n", "{}",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Parse(data)
		if err != nil {
			return
		}
		if err := p.Validate(); err != nil {
			t.Fatalf("accepted an invalid policy: %v", err)
		}
		out, err := Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		q, err := Parse(out)
		if err != nil || !reflect.DeepEqual(p, q) {
			t.Fatalf("round trip: %+v / %+v %v\n%s", p, q, err, out)
		}
		on, err := SetEnabled(data, !p.Enabled)
		if err != nil {
			t.Fatalf("set enabled: %v", err)
		}
		r, err := Parse(on)
		if err != nil {
			t.Fatal(err)
		}
		r.Enabled = p.Enabled
		if !reflect.DeepEqual(p, r) {
			t.Fatalf("set enabled changed more: %+v / %+v", p, r)
		}
	})
}
