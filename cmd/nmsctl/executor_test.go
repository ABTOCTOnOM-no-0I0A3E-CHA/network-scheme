package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/execadmin"
	"github.com/beekamai/network-scheme/internal/execpolicy"
	"github.com/beekamai/network-scheme/internal/install"
)

/* daemon is a fake executor container: it answers each "docker compose exec … /executor admin" with respond. */
type daemon struct {
	fakeSys
	reqs    []execadmin.Request
	respond func(execadmin.Request) execadmin.Response
}

func (f *daemon) Run(ctx context.Context, c install.Cmd) error {
	if err := f.fakeSys.Run(ctx, c); err != nil {
		return err
	}
	var req execadmin.Request
	dec := json.NewDecoder(strings.NewReader(f.stdins[len(f.stdins)-1]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return err
	}
	f.reqs = append(f.reqs, req)
	resp := execadmin.Response{OK: true, Text: "done " + req.Cmd}
	if f.respond != nil {
		resp = f.respond(req)
	}
	b, _ := json.Marshal(resp)
	_, err := c.Stdout.Write(append(b, '\n'))
	return err
}

const execArgv = "docker compose -f /etc/nms/compose.yaml exec -T executor /executor admin"

func execRun(t *testing.T, sys install.System, stdin string, args ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	d := deps{in: strings.NewReader(stdin), out: &out, errw: &out, sys: sys, now: time.Now,
		edit: func(context.Context, string) error { return errors.New("no editor in tests") }}
	return run(context.Background(), append([]string{"executor"}, args...), d), out.String()
}

/* withPolicy points nmsctl at a policy file holding body. */
func withPolicy(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "executor.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	old := policyFile
	policyFile = p
	t.Cleanup(func() { policyFile = old })
	return p
}

/* Every command becomes exactly one request on the stdin of docker compose exec in the executor container; argv carries nothing else. */
func TestExecutorCommandsBecomeRequests(t *testing.T) {
	withPolicy(t, "enabled: false\n")
	for _, c := range []struct {
		args []string
		want execadmin.Request
	}{
		{[]string{"freeze", "on", "--reason", "incident 7"}, execadmin.Request{Cmd: "freeze-on", Reason: "incident 7"}},
		{[]string{"freeze", "off"}, execadmin.Request{Cmd: "freeze-off"}},
		{[]string{"freeze", "off", "--drop-panel-request"}, execadmin.Request{Cmd: "freeze-off", DropPanel: true}},
		{[]string{"registry", "reset", "--i-understand", "--drop-panel-request"}, execadmin.Request{Cmd: "registry-reset", IUnderstand: true, DropPanel: true}},
		{[]string{"revoke", "alice", "write", "core"}, execadmin.Request{Cmd: "revoke", User: "alice", Kind: "write", Group: "core"}},
		{[]string{"revoke", "#5", "unmask"}, execadmin.Request{Cmd: "revoke", User: "#5", Kind: "unmask"}},
		{[]string{"revoke", "alice", "--all"}, execadmin.Request{Cmd: "revoke", User: "alice", All: true}},
		{[]string{"unlock", "alice"}, execadmin.Request{Cmd: "unlock", User: "alice"}},
		{[]string{"unlock", "--global"}, execadmin.Request{Cmd: "unlock", Global: true}},
		{[]string{"model-verify", "--driver", "esr", "--model", "^ESR-1000$", "--firmware", `^1\.`, "--strategy", "commit=do", "--strategy", "pty.width=511", "--note", "stand A"},
			execadmin.Request{Cmd: "model-verify", Driver: "esr", Model: "^ESR-1000$", Firmware: `^1\.`, Note: "stand A",
				Strategies: map[string]string{"commit": "do", "pty.width": "511"}}},
		{[]string{"registry", "verify"}, execadmin.Request{Cmd: "registry-verify"}},
		{[]string{"registry", "reset", "--i-understand"}, execadmin.Request{Cmd: "registry-reset", IUnderstand: true}},
		{[]string{"registry", "reset"}, execadmin.Request{Cmd: "registry-reset"}},
		{[]string{"audit", "verify"}, execadmin.Request{Cmd: "audit-verify"}},
		{[]string{"device", "writes", "on", "--device", "7"}, execadmin.Request{Cmd: "device", Action: "writes-on", DeviceID: 7}},
		{[]string{"device", "writes", "off", "--device", "7"}, execadmin.Request{Cmd: "device", Action: "writes-off", DeviceID: 7}},
		{[]string{"device", "list"}, execadmin.Request{Cmd: "device", Action: "list"}},
		{[]string{"device", "add", "--device", "7", "--address", "10.1.2.3", "--group", "core", "--driver", "mes6", "--port", "2222",
			"--allow-ssh-rsa-sha1", "--backup-via-executor", "--fingerprint", testFP},
			execadmin.Request{Cmd: "device", Action: "add", DeviceID: 7, Address: "10.1.2.3", Group: "core", Driver: "mes6", Port: 2222,
				AllowSHA1: true, Backup: true, Fingerprint: testFP}},
		{[]string{"device", "accept-hostkey", "--device", "7", "--fingerprint", testFP},
			execadmin.Request{Cmd: "device", Action: "accept-hostkey", DeviceID: 7, Fingerprint: testFP}},
		{[]string{"policy", "show"}, execadmin.Request{Cmd: "policy-show"}},
		{[]string{"policy", "check"}, execadmin.Request{Cmd: "policy-check"}},
	} {
		sys := &daemon{}
		if code, out := execRun(t, sys, "", c.args...); code != 0 {
			t.Fatalf("%v: exit %d\n%s", c.args, code, out)
		}
		if len(sys.cmds) != 1 || cmdline(sys.cmds[0]) != execArgv {
			t.Fatalf("%v: commands %v", c.args, sys.cmds)
		}
		got := sys.reqs[0]
		if got.V != execadmin.Version {
			t.Fatalf("%v: version %d", c.args, got.V)
		}
		got.V, got.Operator = 0, ""
		if !reflect.DeepEqual(got, c.want) {
			t.Fatalf("%v:\n got %+v\nwant %+v", c.args, got, c.want)
		}
	}
}

var testFP = "SHA256:" + strings.Repeat("A", 43)

/*
Without --fingerprint, device add is two steps: the executor's preview (the
host key it read, the panel's view shown apart) is confirmed on the terminal
and the confirmation carries exactly the fingerprint shown; a "no" sends
nothing more, and there is no --yes (TOFU).
*/
func TestDeviceAddConfirmsTheShownKey(t *testing.T) {
	withPolicy(t, "enabled: false\n")
	preview := func(req execadmin.Request) execadmin.Response {
		if req.Fingerprint != "" {
			return execadmin.Response{OK: true, Text: "pinned"}
		}
		return execadmin.Response{OK: true, Device: &execadmin.Device{ID: 7, Address: "10.1.2.3", Port: 22, Group: "core", Driver: "esr",
			Algo: "ssh-ed25519", Fingerprint: testFP, PanelName: "sw\x1b]52;c;eA==\x07", PanelAddress: "10.9.9.9"}}
	}
	args := []string{"device", "add", "--device", "7", "--address", "10.1.2.3", "--group", "core", "--driver", "esr"}
	sys := &daemon{respond: preview}
	code, out := execRun(t, sys, "yes\n", args...)
	if code != 0 || len(sys.reqs) != 2 || sys.reqs[0].Fingerprint != "" || sys.reqs[1].Fingerprint != testFP {
		t.Fatalf("exit %d, requests %+v\n%s", code, sys.reqs, out)
	}
	if !strings.Contains(out, testFP) || !strings.Contains(out, "10.9.9.9") || strings.ContainsAny(out, "\x1b\x07") {
		t.Fatalf("preview not shown safely:\n%q", out)
	}
	sys = &daemon{respond: preview}
	if code, _ := execRun(t, sys, "no\n", args...); code == 0 || len(sys.reqs) != 1 {
		t.Fatalf("refused confirmation: exit %d, %d requests", code, len(sys.reqs))
	}
}

func cmdline(c install.Cmd) string { return c.Name + " " + strings.Join(c.Args, " ") }

/* Malformed commands never reach the executor; nmsctl executor runs only on the host. */
func TestExecutorUsageAndHostOnly(t *testing.T) {
	withPolicy(t, "enabled: false\n")
	for _, args := range [][]string{
		{}, {"grant"}, {"grant", "alice"}, {"grant", "alice", "write"}, {"grant", "alice", "unmask", "core"},
		{"grant", "alice", "root"}, {"revoke", "alice", "--all", "write", "core"}, {"freeze", "maybe"},
		{"unlock"}, {"unlock", "alice", "bob"}, {"model-verify", "--driver", "ios", "--model", "x", "--firmware", "y", "--note", "n"},
		{"model-verify", "--driver", "esr", "--model", "x", "--firmware", "y"}, {"registry", "verify", "--i-understand"},
		{"registry", "verify", "--drop-panel-request"}, {"freeze", "on", "--drop-panel-request"},
		{"enroll"}, {"enroll", "--replace"}, {"device", "writes", "maybe"}, {"device", "writes", "on"}, {"device", "writes", "on", "7"},
		{"device", "add", "--address", "10.1.2.3"}, {"device", "list", "--device", "7"}, {"device", "add", "--device", "7", "--yes"},
		{"device", "add", "--device", "7", "--fingerprint", "MD5:x"}, {"device", "remove", "--device", "7"}, {"enable", "now"}, {"grant", "bad\x01name", "unmask"},
	} {
		sys := &daemon{}
		if code, _ := execRun(t, sys, "", args...); code == 0 || len(sys.cmds) != 0 {
			t.Errorf("%q: exit %d, commands %v", args, code, sys.cmds)
		}
	}
	sys := &daemon{fakeSys: fakeSys{inContainer: true}}
	if code, out := execRun(t, sys, "", "registry", "verify"); code != 1 || len(sys.cmds) != 0 || !strings.Contains(out, "host") {
		t.Fatalf("in a container: exit %d %q", code, out)
	}
}

/* A refusal of the daemon is a failure of nmsctl, with the daemon's reason. */
func TestExecutorRefusalFails(t *testing.T) {
	sys := &daemon{respond: func(execadmin.Request) execadmin.Response {
		return execadmin.Response{Error: "freeze off refused: the registry does not verify"}
	}}
	code, out := execRun(t, sys, "", "freeze", "off")
	if code != 1 || !strings.Contains(out, "does not verify") {
		t.Fatalf("exit %d %q", code, out)
	}
}

/*
enroll (D10): the first request only finds the user; nmsctl shows id, name
and creation date and asks; only "yes" sends the second request with that id
and name, whose answer is printed once as a QR code.
*/
func TestEnrollConfirmsTheUser(t *testing.T) {
	created := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	respond := func(r execadmin.Request) execadmin.Response {
		if r.UserID == 0 {
			return execadmin.Response{OK: true, Confirm: &execadmin.User{ID: 42, Username: "alice", CreatedAt: created}}
		}
		return execadmin.Response{OK: true, Text: "enrolled", Enrollment: &execadmin.Enrollment{
			URI: "otpauth://totp/NMS%20changes:alice?secret=JBSWY3DPEHPK3PXP", Secret: "JBSWY3DPEHPK3PXP"}}
	}
	sys := &daemon{respond: respond}
	code, out := execRun(t, sys, "n\n", "enroll", "alice")
	if code != 1 || len(sys.reqs) != 1 || !strings.Contains(out, "#42") || !strings.Contains(out, "2026-03-04 05:06:07 UTC") {
		t.Fatalf("declined: exit %d, %d requests\n%s", code, len(sys.reqs), out)
	}
	sys = &daemon{respond: respond}
	code, out = execRun(t, sys, "yes\n", "enroll", "alice", "--replace")
	if code != 0 || len(sys.reqs) != 2 {
		t.Fatalf("exit %d, %d requests\n%s", code, len(sys.reqs), out)
	}
	if r := sys.reqs[1]; r.UserID != 42 || r.User != "alice" || !r.Replace || r.Cmd != "enroll" {
		t.Fatalf("confirmation request %+v", r)
	}
	if !strings.Contains(out, install.TOTPSecretLinePrefix+"JBSWY3DPEHPK3PXP") || !strings.Contains(out, "▀") {
		t.Fatalf("no QR or secret:\n%s", out)
	}
	for _, c := range sys.cmds {
		if strings.Contains(cmdline(c), "JBSWY3") {
			t.Fatal("secret in argv")
		}
	}
	/* CI: --yes and the secret to a new file. */
	f := filepath.Join(t.TempDir(), "totp")
	sys = &daemon{respond: respond}
	if code, out := execRun(t, sys, "", "enroll", "alice", "--yes", "--totp-secret-out", f); code != 0 {
		t.Fatalf("--yes: exit %d\n%s", code, out)
	}
	if b, err := os.ReadFile(f); err != nil || string(b) != "JBSWY3DPEHPK3PXP\n" {
		t.Fatalf("secret file %q %v", b, err)
	}
	if code, _ := execRun(t, &daemon{respond: respond}, "", "enroll", "alice", "--yes", "--totp-secret-out", f); code != 1 {
		t.Fatal("existing --totp-secret-out overwritten")
	}
}

/* grant is two steps as enroll; --yes skips the question. */
func TestGrantConfirmsTheUser(t *testing.T) {
	sys := &daemon{respond: func(r execadmin.Request) execadmin.Response {
		if r.UserID == 0 {
			return execadmin.Response{OK: true, Confirm: &execadmin.User{ID: 7, Username: "bob"}}
		}
		return execadmin.Response{OK: true, Text: "granted"}
	}}
	if code, out := execRun(t, sys, "", "grant", "bob", "write", "core", "--yes"); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if r := sys.reqs[1]; r.UserID != 7 || r.User != "bob" || r.Kind != "write" || r.Group != "core" {
		t.Fatalf("request %+v", r)
	}
}

/* enable/disable flip only enabled in the host file (comments kept) and ask the executor to reread it; an invalid file is left alone. */
func TestEnableEditsThePolicyAtomically(t *testing.T) {
	p := withPolicy(t, "# host notes\nenabled: false\nsession_minutes: 20\n")
	sys := &daemon{}
	if code, out := execRun(t, sys, "", "enable"); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	data, _ := os.ReadFile(p)
	pol, err := execpolicy.Parse(data)
	if err != nil || !pol.Enabled || pol.SessionMinutes != 20 || !bytes.Contains(data, []byte("# host notes")) {
		t.Fatalf("policy %s %v", data, err)
	}
	if len(sys.reqs) != 1 || sys.reqs[0].Cmd != "policy-reload" || sys.reqs[0].Action != "enable" {
		t.Fatalf("requests %+v", sys.reqs)
	}
	p = withPolicy(t, "enabled: false\nsession_minutes: 9999\n")
	sys = &daemon{}
	if code, _ := execRun(t, sys, "", "enable"); code != 1 || len(sys.cmds) != 0 {
		t.Fatalf("invalid policy enabled: %d %v", code, sys.cmds)
	}
	if data, _ := os.ReadFile(p); string(data) != "enabled: false\nsession_minutes: 9999\n" {
		t.Fatalf("invalid policy changed: %s", data)
	}
}

/* policy edit --file installs only a valid policy; policy check fails on an invalid host file (after the executor recorded its check). */
func TestPolicyEditAndCheck(t *testing.T) {
	p := withPolicy(t, "enabled: false\n")
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	good := filepath.Join(t.TempDir(), "good.yaml")
	_ = os.WriteFile(bad, []byte("enabled: true\nesr_commit_timer_s: 60\n"), 0o600)
	_ = os.WriteFile(good, []byte("enabled: false\nmax_devices_per_session: 2\n"), 0o600)
	sys := &daemon{}
	if code, _ := execRun(t, sys, "", "policy", "edit", "--file", bad); code != 1 || len(sys.cmds) != 0 {
		t.Fatalf("invalid edit: %d %v", code, sys.cmds)
	}
	if data, _ := os.ReadFile(p); string(data) != "enabled: false\n" {
		t.Fatalf("changed by an invalid edit: %s", data)
	}
	if code, out := execRun(t, sys, "", "policy", "edit", "--file", good); code != 0 || sys.reqs[0].Action != "edit" {
		t.Fatalf("edit: %d %s", code, out)
	}
	if data, _ := os.ReadFile(p); !strings.Contains(string(data), "max_devices_per_session: 2") {
		t.Fatalf("not installed: %s", data)
	}
	withPolicy(t, "enabled: maybe\n")
	sys = &daemon{}
	if code, _ := execRun(t, sys, "", "policy", "check"); code != 1 || len(sys.reqs) != 1 {
		t.Fatalf("check of an invalid file: %d %v", code, sys.reqs)
	}
}

/* nmsctl links no package of the executor (security.md 5.1): it reaches the daemon only through docker compose exec. */
func TestNmsctlLinksNoExecutorPackage(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/beekamai/network-scheme/cmd/nmsctl").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	deps := strings.Fields(string(out))
	if len(deps) < 50 || !strings.Contains(string(out), "network-scheme/internal/execadmin") {
		t.Fatalf("implausible dependency list (%d)", len(deps))
	}
	for _, p := range deps {
		if strings.Contains(p, "network-scheme/cmd/executor") {
			t.Errorf("nmsctl depends on %s", p)
		}
	}
}

/* Review minor 1: control characters from the daemon (database errors, api-chosen names) never reach the terminal. */
func TestDaemonTextIsTerminalSafe(t *testing.T) {
	evil := "x\x1b]52;c;cGF5bG9hZA==\x07y\u009b2Jz\x00"
	sys := &daemon{respond: func(execadmin.Request) execadmin.Response {
		return execadmin.Response{Text: "text " + evil + "\n\tok", Error: "error " + evil}
	}}
	code, out := execRun(t, sys, "", "registry", "verify")
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	if strings.ContainsAny(out, "\x1b\x07\x00\u009b") {
		t.Fatalf("control characters printed: %q", out)
	}
	if !strings.Contains(out, "x?]52;c;cGF5bG9hZA==?y?2Jz?") || !strings.Contains(out, "\n\tok") {
		t.Fatalf("output %q", out)
	}
}

/* Re-review minor 2: bidirectional and invisible format characters are neutralized too; ordinary text, Cyrillic included, is kept. */
func TestTerminalSafeBidi(t *testing.T) {
	in := "user \u202Egnp.exe\u202C \u2066x\u2069 \u200Fy\u200E \u061Cz\uFEFF \u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u044C\tok\n"
	want := "user ?gnp.exe? ?x? ?y? ?z? \u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u044C\tok\n"
	if got := terminalSafe(in); got != want {
		t.Fatalf("%q, want %q", got, want)
	}
}
