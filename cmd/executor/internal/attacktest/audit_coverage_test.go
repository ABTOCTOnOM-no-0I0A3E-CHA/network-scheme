package attacktest_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

/*
coverage is the table of the executor's audit events (security.md 10, plan
4d.2): each event and the scripted tests that prove its executor audit row
is written, each with a needle that the test's own body must contain (the
audit action or class it counts rows of). Changesets (Phase 5): authoring,
dry-run, approval, the run and its stop; automatic freezes are alerts, not
rows: the chain that would hold them may be what was tampered
with.
*/
var coverage = []struct {
	event string
	proof []struct{ dir, test, needle string }
}{
	{"session opened", []struct{ dir, test, needle string }{
		{"cmd/executor/internal/session", "TestAuditCoversTheSessionLifecycle", `"session.open", "ok"`}}},
	{"session closed", []struct{ dir, test, needle string }{
		{"cmd/executor/internal/session", "TestAuditCoversTheSessionLifecycle", `"session.close", "ok", "reason", "closed"`}}},
	{"session timed out", []struct{ dir, test, needle string }{
		{"cmd/executor/internal/session", "TestAuditCoversTheSessionLifecycle", `"session.close", "ok", "reason", "timeout"`}}},
	{"every command with its class", []struct{ dir, test, needle string }{
		{"cmd/executor/internal/terminal", "TestEveryLineIsAudited", "terminal.CommandAction"},
		{"cmd/executor/internal/terminal", "TestEveryLineIsAudited", `{"ok", "safe", 3}, {"ok", "dangerous", 2}, {"ok", "control", 1}`}}},
	{"session actions on the device (save)", []struct{ dir, test, needle string }{
		{"cmd/executor/internal/session", "TestAuditCoversTheSessionLifecycle", `"session.save"`}}},
	{"confirmations", []struct{ dir, test, needle string }{
		{"cmd/executor/internal/terminal", "TestEveryLineIsAudited", "confirm.session.line"},
		{"cmd/executor/internal/session", "TestAuditCoversTheSessionLifecycle", "confirm.session.rollback"},
		{"cmd/executor/internal/devices", "TestEveryChangeIsAudited", "confirm.device.register"},
		{"cmd/executor/internal/web", "TestConfirmFlowWithRealAuthz", "confirm.test.echo"}}},
	{"rollbacks", []struct{ dir, test, needle string }{
		{"cmd/executor/internal/session", "TestAuditCoversTheSessionLifecycle", `{"session.rollback", "ok"`}}},
	{"policy refusals", []struct{ dir, test, needle string }{
		{"cmd/executor/internal/session", "TestAuditCoversTheSessionLifecycle", `"class", "two_person"`},
		{"cmd/executor/internal/terminal", "TestEveryLineIsAudited", `{"denied", "denied", 1}`}}},
	{"failed change TOTP codes", []struct{ dir, test, needle string }{
		{"cmd/executor/internal/authz", "TestC2aNoOrWrongTOTP", `"wrong_code"`},
		{"cmd/executor/internal/session", "TestAuditCoversTheSessionLifecycle", `"class", "wrong_code"`}}},
	{"registry changes: write credentials", []struct{ dir, test, needle string }{
		{"cmd/executor/internal/wcreds", "TestStoredCredentialIsBoundInside", "credential.set"}}},
	{"registry changes: writes_enabled, host keys, devices", []struct{ dir, test, needle string }{
		{"cmd/executor/internal/devices", "TestEveryChangeIsAudited", `"device.writes"`},
		{"cmd/executor/internal/devices", "TestEveryChangeIsAudited", `"device.accept_hostkey"`},
		{"cmd/executor/internal/devices", "TestEveryChangeIsAudited", `"admin.device.add"`}}},
	{"registry changes: grants, confirmed models, registry reset", []struct{ dir, test, needle string }{
		{"cmd/executor/internal/admin", "TestEveryCommandIsAudited", `"admin.grant"`},
		{"cmd/executor/internal/admin", "TestEveryCommandIsAudited", `"admin.model-verify"`},
		{"cmd/executor/internal/admin", "TestEveryCommandIsAudited", `"admin.registry-reset"`}}},
	{"every nmsctl executor command", []struct{ dir, test, needle string }{
		{"cmd/executor/internal/admin", "TestEveryCommandIsAudited", `"admin.request"`}}},
	{"freeze and its lifting", []struct{ dir, test, needle string }{
		{"cmd/executor/internal/admin", "TestEveryCommandIsAudited", `"admin.freeze-on"`},
		{"cmd/executor/internal/admin", "TestEveryCommandIsAudited", `"admin.freeze-off"`},
		{"cmd/executor/internal/pub", "TestPanelRequestFreezesWithinFiveSeconds", "executor.freeze.panel"}}},
	{"unmasked configurations viewed and exported, refusals too", []struct{ dir, test, needle string }{
		{"cmd/executor/internal/unmask", "TestC9UnmaskNeedsGrantGroupAndTOTP", "unmask.ActionView, unmask.ActionExport"},
		{"cmd/executor/internal/unmask", "TestUnmaskLimitAndMassAlert", `"view_limit"`}}},
	{"session recordings viewed", []struct{ dir, test, needle string }{
		{"cmd/executor/internal/recording", "TestC2hReplayNeedsAuditReadAndTOTP", "recording.view"}}},
	{"changesets authored, viewed and discarded", []struct{ dir, test, needle string }{
		{"cmd/executor/internal/changeset", "TestSaveReviseDiscard", `"changeset.create", "changeset.revise", "changeset.discard", "changeset.view"`}}},
	{"changeset dry-runs", []struct{ dir, test, needle string }{
		{"cmd/executor/internal/changeset", "TestDryRunOnEveryLine", `"changeset.dry_run", "ok"`}}},
	{"changeset approvals, second persons and wrong device counts", []struct{ dir, test, needle string }{
		{"cmd/executor/internal/changeset", "TestApproveDeviceCountAndStart", `f.audits(t, changeset.ApproveAction, "denied")`},
		{"cmd/executor/internal/changeset", "TestTwoPersonAuthorCannotApprove", `f.audits(t, changeset.ApproveAction, "ok")`}}},
	{"changeset runs and their stop", []struct{ dir, test, needle string }{
		{"cmd/executor/internal/changeset", "TestRunCanaryThenBatches", `"changeset.run", "ok"`},
		{"cmd/executor/internal/changeset", "TestRunStop", `"changeset.stop", "ok"`}}},
	{"two-person session requests and approvals", []struct{ dir, test, needle string }{
		{"cmd/executor/internal/session", "TestTwoPersonSessionNeedsApproval", `{"session.request", "ok"}, {"session.approve", "ok"}, {"confirm.session.approve", "ok"}`}}},
	{"executor audit viewed", []struct{ dir, test, needle string }{
		{"cmd/executor/internal/auditview", "TestAuditViewNeedsAuditReadAndTOTP", "audit.view"},
		{"cmd/executor/internal/auditview", "TestAuditViewLimit", "audit.view"}}},
}

/*
TestAuditCoverage: every event of the table has proofs, and each proof is a
test of that name in the package's _test.go files that never skips itself
and whose body contains its needle (the audit action or class it counts).
The traced tests run in CI (TestTraceability's NMS_TRACE_JSON step), so a
listed event whose row is not written in its scripted scenario fails there.
*/
func TestAuditCoverage(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..")
	bodies := map[string]string{} /* "dir.Test" -> the function's source */
	for _, e := range coverage {
		if len(e.proof) == 0 {
			t.Errorf("%s: no proof", e.event)
		}
		for _, p := range e.proof {
			key := p.dir + "." + p.test
			if _, ok := bodies[key]; !ok {
				bodies[key] = testSource(t, filepath.Join(root, filepath.FromSlash(p.dir)), p.test)
			}
			switch body := bodies[key]; {
			case body == "":
				t.Errorf("%s: %s does not exist or can skip itself", e.event, key)
			case !strings.Contains(body, p.needle):
				t.Errorf("%s: %s does not check %s", e.event, key, p.needle)
			}
		}
	}
	/* the events security.md 10 lists for the executor, each in the table */
	for _, want := range []string{"session opened", "session closed", "session timed out", "every command with its class", "confirmations",
		"rollbacks", "policy refusals", "failed change TOTP codes", "registry changes: write credentials", "every nmsctl executor command",
		"freeze and its lifting", "unmasked configurations viewed and exported, refusals too", "session recordings viewed", "executor audit viewed"} {
		found := false
		for _, e := range coverage {
			found = found || e.event == want
		}
		if !found {
			t.Errorf("event %q is not in the table", want)
		}
	}
}

/* testSource is the source of test function name in dir's _test.go files ("" if absent or if it can skip itself). */
func testSource(t *testing.T, dir, name string) string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		src, err := os.ReadFile(f) // #nosec G304 -- the repository's own test files
		if err != nil {
			t.Fatal(err)
		}
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, f, src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range af.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == name {
				if skips(fn) {
					return ""
				}
				return string(src[fset.Position(fn.Body.Pos()).Offset:fset.Position(fn.Body.End()).Offset])
			}
		}
	}
	return ""
}
