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
ref points at the proof of a scenario: a Go test function (dir: its package
directory from the repository root), or a text that must stay in a non-Go
file (dir: that file, e.g. the e2e spec or the CI workflow).
*/
type ref struct{ dir, name string }

/*
trace is the one index of the Phase 4a attack scenarios (plan
2026-10-25-phase-4-executor, "Критерии Фазы 4" and "Review Focus 4a"; the
security traceability of 4d.3 starts from it): each scenario and where it is
proved. The attacker throughout is the api (Attacker: nms_api and the
ticket signing key), and for exec the superuser (Tamper, Copy, Stall).
*/
var trace = []struct {
	id, what string
	refs     []ref
}{
	{"C1", "executor disabled after install: every /x/* but the status 503 before any route, enable goes down the chain", []ref{
		{"cmd/executor/internal/web", "TestC1DisabledAfterInstallUntilEnabled"},
		{"cmd/executor/internal/web", "TestDisabledAnswers503"},
		{"cmd/executor/internal/authz", "TestPolicyAndFreezeGate"},
		{"cmd/executor/internal/authz", "TestPolicyCheckedAgainInsideTheWrite"},
		{"cmd/executor/internal/admin", "TestPolicyFailsClosed"},
		{"cmd/nmsctl", "TestEnableEditsThePolicyAtomically"},
		{".github/workflows/ci.yml", "sudo /usr/local/bin/nmsctl executor enable"},
		{"test/e2e/executor.spec.ts", "C1"},
	}},
	{"C2a", "no TOTP, a wrong code, another user's code", []ref{
		{"cmd/executor/internal/authz", "TestC2aNoOrWrongTOTP"},
	}},
	{"C2b", "a ticket without the grant", []ref{
		{"cmd/executor/internal/authz", "TestC2bTicketWithoutGrant"},
		{"cmd/executor/internal/confirm", "TestChallengeBindsUserAndGrant"},
	}},
	{"C2d", "the api freezes within 5 s and cannot lift the freeze", []ref{
		{"cmd/executor/internal/pub", "TestPanelRequestFreezesWithinFiveSeconds"},
		{"cmd/executor/internal/pub", "TestPanelCannotLiftFreeze"},
		{"cmd/executor/internal/pub", "TestFreezeOffCannotLiftAConcurrentRequest"},
		{"internal/httpapi", "TestExecutorFreezeRequest"},
		{"internal/httpapi", "TestNoRouteLiftsFreeze"},
		{"internal/store", "TestExecpubGrantsForAPIAndPoller"},
		{"cmd/executor/internal/web", "TestRouteTableHasNoHostOnlyRoutes"},
	}},
	{"C2e", "a planted or changed exec row (MAC) freezes", []ref{
		{"cmd/executor/internal/freeze", "TestDatabaseTamperingFreezes"},
		{"cmd/executor/internal/freeze", "TestShadowedFunctionsDoNotHideTampering"},
		{"cmd/executor/internal/registry", "TestWriteRefusesUndeclaredChanges"},
		{"cmd/executor/internal/registry", "TestTriggerCreatedDuringWriteWaitsAndFreezes"},
		{"cmd/executor/internal/registry", "TestRowPlantedDuringBootstrapFreezes"},
	}},
	{"C2f", "a rolled back version, a deleted row or state file freezes", []ref{
		{"cmd/executor/internal/freeze", "TestDatabaseTamperingFreezes"},
		{"cmd/executor/internal/freeze", "TestStateFileTamperingFreezes"},
		{"cmd/executor/internal/freeze", "TestFreezeSurvivesRestart"},
		{"cmd/executor/internal/registry", "TestWriteRefusesOldValidRows"},
		{"cmd/executor/internal/registry", "TestCheckRefusesVersionAboveCounter"},
	}},
	{"C2g", "change TOTP secrets swapped with a recomputed MAC (AAD)", []ref{
		{"cmd/executor/internal/authz", "TestC2gSwappedSecretsWithValidMAC"},
		{"cmd/executor/internal/seal", "TestTOTPSealIsBoundToTheUser"},
	}},
	{"C2k", "confirm(H): another description under the same challenge", []ref{
		{"cmd/executor/internal/confirm", "TestC2kChangedDescription"},
		{"cmd/executor/internal/confirm", "TestConfirmOnce"},
		{"cmd/executor/internal/web", "TestConfirmFlowWithRealAuthz"},
	}},
	{"C3", "TOTP replay, growing locks, global freeze", []ref{
		{"cmd/executor/internal/authz", "TestAcceptOnceAndAudit"},
		{"cmd/executor/internal/authz", "TestC3LockGrowthAndUnlock"},
		{"cmd/executor/internal/authz", "TestC3SuccessResetsLocksInARow"},
		{"cmd/executor/internal/authz", "TestC3StepSurvivesRestart"},
		{"cmd/executor/internal/authz", "TestC3GlobalFreeze"},
		{"cmd/executor/internal/authz", "TestGlobalFreezeFromMemory"},
		{"cmd/executor/internal/authz", "TestRestartKeepsGuessBudget"},
		{"cmd/executor/internal/authz", "TestRestartKeepsGlobalWindow"},
		{"cmd/executor/internal/authz", "TestParallelSameCode"},
	}},
	{"4a.7", "a device in a change session (or an alias of it) gets no SSH from the poller", []ref{
		{"internal/poller", "TestBusyDeviceGetsNoSSH"},
		{"internal/poller", "TestUnreadableBusyTableGetsNoSSH"},
		{"internal/poller", "TestAliasOfABusyDeviceGetsNoSSH"},
		{"internal/poller", "TestOtherAddressOfABusyDeviceGetsNoLogin"},
		{"internal/poller", "TestOnlyDialSSHDialsSSH"},
		{"internal/poller", "TestOnlyInternalSSHAndCredsLinkXCryptoSSH"},
		{"internal/ssh", "TestBusyHostKeySendsNoCredential"},
		{"internal/ssh", "TestBusyDevicePinnedKeyOfAnotherTypeSendsNoCredential"},
		{"internal/ssh", "TestBusyHostKeyCheckFailsClosed"},
	}},
	{"RF1", "tampering or rollback freezes; only nmsctl lifts it, after a verification that passes again", []ref{
		{"cmd/executor/internal/freeze", "TestFreezeOffRefusedWhenVerifyFails"},
		{"cmd/executor/internal/freeze", "TestFreezeOffDoesNotLiftANewFreeze"},
		{"cmd/executor/internal/freeze", "TestRequestOnAFrozenExecutorMovesNoGeneration"},
		{"cmd/executor/internal/admin", "TestFreezeOffRefusedWithFailedVerify"},
		{"cmd/executor/internal/admin", "TestBrokenAuditChainNeedsAReset"},
		{"cmd/executor/internal/admin", "TestRegistryResetRevokesEverything"},
		{"cmd/executor/internal/registry", "TestCrashWindowsAreAccepted"},
		{"cmd/executor/internal/pub", "TestPanelCannotLiftFreeze"},
	}},
	{"RF2", "the api with the ticket key and nms_api: no action without TOTP, no more than the grants, no unfreeze, no TOTP secret", []ref{
		{"cmd/executor/internal/attacktest", "TestAPICannotLearnTheChangeTOTPSecret"},
		{"cmd/executor/internal/authz", "TestC2aNoOrWrongTOTP"},
		{"cmd/executor/internal/authz", "TestC2bTicketWithoutGrant"},
		{"cmd/executor/internal/authz", "TestPanelUserDenyOnly"},
		{"cmd/executor/internal/admin", "TestBindingRefusesWhatTheAPIChanged"},
		{"internal/store", "TestAPIRoleHasNoExecRights"},
		{"internal/httpapi", "TestNoRouteLiftsFreeze"},
	}},
	{"RF3", "ticket nonce and TOTP step used once, also across a restart; locks as in security.md 5.2", []ref{
		{"cmd/executor/internal/authz", "TestTicketRefusals"},
		{"cmd/executor/internal/authz", "TestNonceKeptUntilWallExpiry"},
		{"cmd/executor/internal/authz", "TestNonceCacheFullRefuses"},
		{"cmd/executor/internal/authz", "TestC3StepSurvivesRestart"},
		{"cmd/executor/internal/authz", "TestCrashAfterAcceptedCodeDoesNotLock"},
		{"cmd/executor/internal/authz", "TestC3LockGrowthAndUnlock"},
	}},
	{"RF4", "no path from core to the executor; :8443 serves nothing of the api; cookies ignored", []ref{
		{"cmd/executor", "TestRunServesXOnlyOnXnet"},
		{"cmd/executor/internal/web", "TestOnlyTheGatewayCertificate"},
		{"cmd/executor/internal/web", "TestCookieIgnored"},
		{"test/gateway", "TestExecutorReachableOnlyByTheGatewayCertificate"},
		{"test/gateway", "TestExecutorOriginNotReachableFromInternalNetworks"},
		{"test/gateway", "TestExecutorOriginHasNoAPI"},
		{"internal/install", "TestExecutorOriginBoundToEdge"},
	}},
	{"RF5", "nmsctl links no executor package; the administration socket only inside the executor's container", []ref{
		{"cmd/nmsctl", "TestNmsctlLinksNoExecutorPackage"},
		{"cmd/executor/internal/admin", "TestSocketRefusesAnotherUID"},
		{"internal/install", "TestComposeHardening"},
		{"internal/install", "TestRunInExecutor"},
		{"scripts/check-isolation.sh", `go list -deps "./cmd/$name"`},
	}},
}

/*
Every scenario of the index has its proofs, and every proof exists: a test
function of that name in the package's _test.go files (any build tag: the
Linux-only ones run in CI), or the text in the named file. Renaming or
deleting a proof fails here until the index follows.
*/
func TestTraceability(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repository root: %v", err)
	}
	tests := map[string]map[string]bool{} /* package directory -> its test functions */
	testsOf := func(dir string) map[string]bool {
		if fns, ok := tests[dir]; ok {
			return fns
		}
		fns := map[string]bool{}
		files, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(dir), "*_test.go"))
		if err != nil || len(files) == 0 {
			t.Errorf("%s: no test files (%v)", dir, err)
		}
		fset := token.NewFileSet()
		for _, f := range files {
			af, err := parser.ParseFile(fset, f, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range af.Decls {
				if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test") {
					fns[fn.Name.Name] = true
				}
			}
		}
		tests[dir] = fns
		return fns
	}
	ids := map[string]bool{}
	for _, s := range trace {
		if ids[s.id] {
			t.Errorf("%s twice in the index", s.id)
		}
		ids[s.id] = true
		if len(s.refs) == 0 {
			t.Errorf("%s (%s): no proof", s.id, s.what)
		}
		for _, r := range s.refs {
			if strings.Contains(filepath.Base(r.dir), ".") {
				b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(r.dir)))
				if err != nil || !strings.Contains(string(b), r.name) {
					t.Errorf("%s: %s does not contain %q (%v)", s.id, r.dir, r.name, err)
				}
				continue
			}
			if !testsOf(r.dir)[r.name] {
				t.Errorf("%s: %s.%s does not exist", s.id, r.dir, r.name)
			}
		}
	}
	/* The scenarios 4a must prove (the plan's table rows owned by 4a, the 4a.7 attack, the five review focus items). */
	for _, id := range []string{"C1", "C2a", "C2b", "C2d", "C2e", "C2f", "C2g", "C2k", "C3", "4a.7", "RF1", "RF2", "RF3", "RF4", "RF5"} {
		if !ids[id] {
			t.Errorf("scenario %s is not in the index", id)
		}
	}
}
