package attacktest_test

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
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
trace is the one index of the Phase 4 attack scenarios (plan
2026-10-25-phase-4-executor, "Критерии Фазы 4" and the Review Focus lists; the
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
		{"cmd/executor/internal/session", "TestRefusals"},
		{"cmd/executor/internal/web", "TestDisabledAnswers503"},
		{"cmd/executor/internal/authz", "TestPolicyAndFreezeGate"},
		{"cmd/executor/internal/authz", "TestPolicyCheckedAgainInsideTheWrite"},
		{"cmd/executor/internal/admin", "TestPolicyFailsClosed"},
		{"cmd/nmsctl", "TestEnableEditsThePolicyAtomically"},
		{".github/workflows/ci.yml", "- name: The executor is off after install (C1), then enable, enroll and grant"},
		{".github/workflows/ci.yml", "\n          sudo /usr/local/bin/nmsctl executor enable\n"},
		{"test/e2e/executor.spec.ts", `test("C1: after nmsctl executor enable requests go past the policy gate to the route table and authz", `},
	}},
	{"C2a", "no TOTP, a wrong code, another user's code", []ref{
		{"cmd/executor/internal/authz", "TestC2aNoOrWrongTOTP"},
	}},
	{"C2b", "a ticket without the grant", []ref{
		{"cmd/executor/internal/authz", "TestC2bTicketWithoutGrant"},
		{"cmd/executor/internal/confirm", "TestChallengeBindsUserAndGrant"},
		{"cmd/executor/internal/session", "TestRefusals"},
	}},
	{"C2c", "the api changes a device's address or group: registration and connections use the registry's address only", []ref{
		{"cmd/executor/internal/devices", "TestC2cAPIChangesAddressAndGroup"},
		{"cmd/executor/internal/devices", "TestStaleConfirmationRefused"},
		{"cmd/executor/internal/devices", "TestResetDeviceUnusableUntilConfirmed"},
		{"cmd/executor/internal/devices", "TestSSRFAddressesRefused"},
		{"cmd/executor/internal/netguard", "TestSSRFAddressesRefused"},
		{"cmd/executor/internal/devices", "TestWithoutWriteAdminRefused"},
		{"cmd/executor/internal/devices", "TestEveryChangeIsAudited"},
		{"cmd/executor/internal/session", "TestBusyDeviceSilencesThePoller"},
	}},
	{"C5", "a host key other than the pinned one: refused before any credential, high alert", []ref{
		{"cmd/executor/internal/transport", "TestHostKeyStrategy"},
		{"cmd/executor/internal/transport", "TestNoKeyOfThePinnedTypeIsAMismatch"},
		{"cmd/executor/internal/transport", "TestNetguardAndHostKeyAtDial"},
		{"cmd/executor/internal/devices", "TestReplacedKeyOnlyThroughConfirmation"},
		{"cmd/executor/internal/devices", "TestSHA1HostKeyNeedsTheFlag"},
		{"cmd/executor/internal/devices", "TestForgedTicketMakesNoConnection"},
		{"cmd/executor/internal/devices", "TestHostAcceptBindsThePreviewedRow"},
		{"cmd/nmsctl", "TestDeviceAddConfirmsTheShownKey"},
		{"cmd/executor/internal/session", "TestRefusals"},
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
	{"C2j", "a write credential sealed for another device or replayed; never readable by the api or the poller", []ref{
		{"cmd/executor/internal/wcreds", "TestC2jCiphertextOfAnotherDeviceIsAMismatch"},
		{"cmd/executor/internal/wcreds", "TestC2jReplayIsStale"},
		{"cmd/executor/internal/wcreds", "TestStoredCredentialIsBoundInside"},
		{"cmd/executor/internal/wcreds", "TestAPIAndPollerCannotReadWriteCredentials"},
		{"cmd/executor/internal/wcreds", "TestDescribeTellsNothingOfTheCiphertext"},
		{"cmd/executor/internal/wcreds", "TestRunRefusesWhatChangedSinceTheConfirmation"},
		{"cmd/executor/internal/admin", "TestResetDropsEveryWriteCredential"},
		{"cmd/executor/internal/attacktest", "TestAPICannotLearnTheWriteCredential"},
		{"internal/creds", "TestOpenRefusesTheWriteKind"},
		{"internal/poller", "TestWriteCredentialKindRejected"},
	}},
	{"C2k", "confirm(H): another description under the same challenge", []ref{
		{"cmd/executor/internal/confirm", "TestC2kChangedDescription"},
		{"cmd/executor/internal/confirm", "TestConfirmOnce"},
		{"cmd/executor/internal/web", "TestConfirmFlowWithRealAuthz"},
		{"cmd/executor/internal/session", "TestRollbackOnlyAsConfirmed"},
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
		{"cmd/executor/internal/session", "TestBusyDeviceSilencesThePoller"},
	}},
	{"4c.2", "the session lifecycle: checks in order (policy, freeze, window/limit/two-person with alert, grants, writes, model, host key, credential, rules), pre-session snapshot, management context, timeouts, connection loss and restart end as interrupted with an alert and free device_busy", []ref{
		{"cmd/executor/internal/session", "TestOpenAndClose"},
		{"cmd/executor/internal/session", "TestRefusals"},
		{"cmd/executor/internal/session", "TestMgmtTargets"},
		{"cmd/executor/internal/session", "TestMgmtTargetsWidened"},
		{"cmd/executor/internal/session", "TestNothingBeforeAuthz"},
		{"cmd/executor/internal/session", "TestFreezeKeepsTheSafetyNet"},
		{"cmd/executor/internal/session", "TestNoSessionAfterRun"},
		{"cmd/executor/internal/session", "TestRecoverChecksEveryMAC"},
		{"cmd/executor/internal/backups", "TestPreSessionKeepsDriftVisible"},
		{"cmd/executor/internal/drivers/mes10", "TestFailedOpenDeletesItsSnapshot"},
		{"cmd/executor/internal/session", "TestTimeouts"},
		{"cmd/executor/internal/session", "TestAttach"},
		{"cmd/executor/internal/session", "TestConnectionLoss"},
		{"cmd/executor/internal/session", "TestRestartMidSession"},
		{"cmd/executor/internal/session", "TestBusyDeviceSilencesThePoller"},
		{"cmd/executor/internal/web", "TestSessionRoutes"},
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
		{"scripts/check-isolation.sh", `done < <(go list -deps "./cmd/$name" | tr -d '\r')`},
	}},
	{"4b.5", "the transport: registry row and netguard at dial, host key before credentials, model gate, expired password, ReadOnly allowlist, no escapes to clients", []ref{
		{"cmd/executor/internal/transport", "TestDialUsesTheVerifiedRegistry"},
		{"cmd/executor/internal/transport", "TestNetguardAndHostKeyAtDial"},
		{"cmd/executor/internal/transport", "TestModelGate"},
		{"cmd/executor/internal/transport", "TestExpiredPasswordStops"},
		{"cmd/executor/internal/transport", "TestReadOnlySendsOnlyTheAllowlist"},
		{"cmd/executor/internal/transport", "TestEscapesNeverReachTheClient"},
		{"cmd/executor/internal/strategy", "TestEveryStrategyHasResearchRef"},
	}},
	{"C4", "dangerous commands of every firmware line in every spelling (abbreviation, do, case, spaces, tabs, control characters), the management context in every spelling, save aliases never sent", []ref{
		{"cmd/executor/internal/drivers", "TestC4DangerousCommands"},
		{"cmd/executor/internal/drivers", "TestManagementContextEverySpelling"},
		{"cmd/executor/internal/drivers", "TestEverySaveAliasIsControl"},
		{"cmd/executor/internal/terminal", "TestC4EveryDangerousSpellingIsHeld"},
		{"cmd/executor/internal/terminal", "TestC4DangerousLineNeedsNameAndNewCode"},
	}},
	{"4c.3", "the line terminal: only whole classified lines reach the device; a paste over paste_confirm_lines waits for confirmation; a partial line at disconnect is dropped; device escapes (OSC 52 included) never reach the browser; Tab and ? never reach the device; Origin, first-frame token, control lines and the hourly limit", []ref{
		{"cmd/executor/internal/terminal", "TestPasteOverTheLimitWaitsForConfirmation"},
		{"cmd/executor/internal/terminal", "TestPartialLineNotSentAtDisconnect"},
		{"cmd/executor/internal/terminal", "TestDeviceEscapesNeverReachTheBrowser"},
		{"cmd/executor/internal/terminal", "TestTabAndHelpNeverReachTheDevice"},
		{"cmd/executor/internal/terminal", "TestOriginTokenControlAndLimit"},
		{"cmd/executor/internal/terminal", "TestEditorKeys"},
		{"cmd/executor/internal/terminal", "TestCleanStripsEscapes"},
	}},
	{"C7", "roll back the whole session = pre-session, hash checked, high alert otherwise (emulator; real models: stand)", []ref{
		{"cmd/executor/internal/drivers/mes6", "TestRollbackInverseJournal"},
		{"cmd/executor/internal/drivers/mes6", "TestRollbackHashMismatchAlerts"},
		{"cmd/executor/internal/drivers/mes10", "TestSnapshotReplaceRollbackAndSave"},
		{"cmd/executor/internal/drivers/mes10", "TestReplaceMismatchAlerts"},
		{"cmd/executor/internal/drivers/esr", "TestRollbackBeforeAndAfterConfirm"},
		{"cmd/executor/internal/drivers/esr", "TestRollbackMismatchIsNotConfirmed"},
		{"cmd/executor/internal/session", "TestC7RollbackRestoresThePreSessionSnapshot"},
	}},
	{"C2i", "rollback only to the snapshot of exec.session_device under its MAC: a tampered pre_ct/pre_sha256 or a foreign backup refuses with an alert; the poller's copy is never read", []ref{
		{"cmd/executor/internal/session", "TestC2iRollbackOnlyToTheMACdSnapshot"},
	}},
	{"C6", "link loss mid-session: ESR reverts by its own timer and the executor sends nothing; MES alerts and rolls back from the snapshot (emulator; real models: stand)", []ref{
		{"cmd/executor/internal/session", "TestC6ESRRevertsByItsTimer"},
		{"cmd/executor/internal/session", "TestC6MESRollbackAfterLinkLoss"},
	}},
	{"4c.4", "session actions: diff, save of the shown configuration, typed control lines to their flows, forms only as shown and Safe, no rollback over a later session; 4c.3 review: H binds the registry device, dropped challenges discarded, pre-auth bound, recording before the browser's bounds", []ref{
		{"cmd/executor/internal/session", "TestDiffSaveTypedAndForms"},
		{"cmd/executor/internal/session", "TestRollbackSupersededByALaterSession"},
		{"cmd/executor/internal/session", "TestESRExclusivityAndTimerBeforeConfirm"},
		{"cmd/executor/internal/session", "TestESRHealthCheckRestoresOnlyThePendingCommit"},
		{"cmd/executor/internal/terminal", "TestPreauthClientKey"},
		{"cmd/executor/internal/web", "TestSessionRoutes"},
		{"cmd/executor/internal/terminal", "TestDangerousLineBoundToTheRegistryDevice"},
		{"cmd/executor/internal/terminal", "TestDroppedDangerousLineDiscardsItsChallenge"},
		{"cmd/executor/internal/terminal", "TestPreauthConnectionsAreBounded"},
		{"cmd/executor/internal/terminal", "TestRecordingBeforeTheBrowserBounds"},
	}},
	{"C8", "the recording is the fact without secrets: input and output masked before anything is stored (also split across answers, chunks and blocks); the replay equals the emulator's journal and the shown output but for the masks; no known test secret in chunks, ciphertext, logs, audit or alerts (as is, base64, hex)", []ref{
		{"cmd/executor/internal/terminal", "TestC8ReplayIsTheFactWithoutSecrets"},
		{"cmd/executor/internal/recording", "TestC8RecordingHoldsNoSecret"},
		{"internal/drivers/mask", "TestStreamKeepsBlocksAcrossPieces"},
		{"internal/drivers/mask", "TestStreamOpenerDoesNotHideLaterLines"},
		{"cmd/executor/internal/recording", "TestOpenerHidesNoLaterLine"},
		{"cmd/executor/internal/recording", "TestReplayCleansAgain"},
	}},
	{"C2h", "recordings only with the audit-read grant and a change TOTP code (every other grant refused), each view audited, views per hour bounded with an alert; a swapped, deleted, truncated or duplicated chunk, a changed or missing manifest, a wrong AAD or a foreign session's chunk refuse the replay with a high alert; configurations only with unmask (C9)", []ref{
		{"cmd/executor/internal/recording", "TestC2hReplayNeedsAuditReadAndTOTP"},
		{"cmd/executor/internal/recording", "TestReplayRefusesTampering"},
		{"cmd/executor/internal/unmask", "TestC9UnmaskNeedsGrantGroupAndTOTP"},
	}},
	{"C9", "unmasked configurations only through the executor: unmask + write on the registry's group of the device + confirm(H) over (device, version) + the user's own change TOTP code (no grant, other group, no/wrong/other's code, forged or other's ticket, a device moved after the challenge: refused); /x/confirm and the other route leave the challenge unspent; sha256(normalize(Open)) checked against the version row before anything is shown (mismatch: refused, high alert); per-user hourly limit (refused, alert) and mass alert; every view and export audited, refusals too; text only, cleaned; the download a plain-text attachment forced by the gateway; the api never reads the envelope", []ref{
		{"cmd/executor/internal/unmask", "TestC9UnmaskNeedsGrantGroupAndTOTP"},
		{"cmd/executor/internal/unmask", "TestUnmaskLimitAndMassAlert"},
		{"cmd/executor/internal/unmask", "TestUnmaskRefusesTamperedVersions"},
		{"cmd/executor/internal/unmask", "TestUnmaskedTextIsCleaned"},
		{"cmd/executor/internal/unmask", "TestDescribeFromTheExecutorsData"},
		{"cmd/executor/internal/authz", "TestC2bTicketWithoutGrant"},
		{"cmd/executor/internal/web", "TestConfirmedRoutes"},
		{"cmd/executor/internal/web", "TestReadNeedFor"},
		{"internal/install", "TestCaddyExecutorSite"},
		{"internal/store", "TestAPIRoleHasNoExecRights"},
		{"internal/triggers", "TestEveryExecutorAlertKindIsKnown"},
		{"web/executor/src/configs/ConfigsPage.test.tsx", `it("lists with one code, confirms the view with the next one and shows the configuration as text only"`},
		{"web/executor/src/configs/ConfigsPage.test.tsx", `it("exports through a fetch with the code in the body and saves the executor's text"`},
	}},
	{"4d.2", "the executor's audit: viewed only with audit-read + a change TOTP code, every view itself audited and bounded per hour, filters and pages bounded, text cleaned; the whole chain (catalog of the audit tables, sealed segments, anchor) verified in the background, a break or truncation freezes with the executor_tamper disaster alert; every event of security.md 10 has its row (coverage table)", []ref{
		{"cmd/executor/internal/auditview", "TestAuditViewNeedsAuditReadAndTOTP"},
		{"cmd/executor/internal/auditview", "TestAuditViewFiltersAndPages"},
		{"cmd/executor/internal/auditview", "TestAuditViewCleansText"},
		{"cmd/executor/internal/auditview", "TestAuditViewLimit"},
		{"cmd/executor/internal/admin", "TestBackgroundAuditVerificationFreezesOnABreak"},
		{"cmd/executor/internal/admin", "TestAuditVerifyCatchesBreakAndTruncation"},
		{"cmd/executor/internal/attacktest", "TestAuditCoverage"},
		{"cmd/executor/internal/session", "TestAuditCoversTheSessionLifecycle"},
		{"cmd/executor/internal/terminal", "TestEveryLineIsAudited"},
		{"cmd/executor/internal/wcreds", "TestStoredCredentialIsBoundInside"},
		{"web/executor/src/audit/AuditPage.test.tsx", `it("reads a page with the filters and one code, shows it as text only and continues by the cursor"`},
		{"web/executor/src/audit/AuditPage.test.tsx", `it("sends nothing for a malformed filter and names the executor's refusals"`},
	}},
	{"4d.4", "end to end on the installed stack: write emulators registered from the host (device add with the console fingerprint, writes on, model-verify, grants), the write credential through the executor's page, then the full change session on mes6 and esr, its replay, the unmasked pre-session configuration and its audit row; the executor's chain verifies after the run; ZAP baseline on :8443", []ref{
		{".github/workflows/ci.yml", "- name: Register the write emulators with the executor (session e2e)"},
		{".github/workflows/ci.yml", "-e NMS_E2E_SESSION_DEVICES -w /e2e"},
		{".github/workflows/ci.yml", "- name: The change sessions ran on the write emulators, and the executor's audit chain verifies"},
		{".github/workflows/ci.yml", "target: https://localhost:8443"},
		{"test/e2e/session.spec.ts", "await storeCredential(page, id);"},
		{"test/e2e/session.spec.ts", `await g.getByTestId("nav-configs").click();`},
		{"test/e2e/session.spec.ts", `await expect(audit).toContainText("config.view");`},
	}},
	{"4c.5", "recording fails closed: a failed or full recording sends no further line (terminal and forms), chunk size bound, volume limit, the manifest at the session's end and after a restart", []ref{
		{"cmd/executor/internal/terminal", "TestRecorderFailureSendsNothing"},
		{"cmd/executor/internal/recording", "TestRecorderFailureIsFailClosed"},
		{"cmd/executor/internal/recording", "TestVolumeLimit"},
		{"cmd/executor/internal/recording", "TestChunkSizeBound"},
		{"cmd/executor/internal/recording", "TestRecover"},
		{"cmd/executor/internal/session", "TestSessionIsRecorded"},
		{"cmd/executor/internal/session", "TestFormRefusedWhenTheRecordingFails"},
		{"cmd/executor/internal/session", "TestRestartMidSession"},
		{"cmd/executor/internal/recording", "TestAnswerBoundAndEscaping"},
		{"cmd/executor/internal/recording", "TestFailedLineIsNotRecorded"},
		{"cmd/executor/internal/recording", "TestConcurrentReplaysBounded"},
		{"cmd/executor/internal/terminal", "TestConfirmationMarkersFailClosed"},
		{"cmd/executor/internal/session", "TestAbortedOpenLeavesAReplayableRecording"},
	}},
}

/*
Every scenario of the index has its proofs, and every proof exists: a test
function of that name in the package's _test.go files (any build tag: the
Linux-only ones run in CI) that never skips itself (t.Skip, Skipf, SkipNow
in its body; only skipAllowed may), or the text in the named file. Renaming
or deleting a proof fails here until the index follows.

With NMS_TRACE_JSON set to the output of go test -json over the traced
packages (CI step "Traced attack tests ran"), every traced test must also
have passed there: a skip (Docker missing, -short, a helper's skip) or an
absent test fails.
*/
func TestTraceability(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repository root: %v", err)
	}
	tests := map[string]map[string]*ast.FuncDecl{} /* package directory -> its test functions */
	testsOf := func(dir string) map[string]*ast.FuncDecl {
		if fns, ok := tests[dir]; ok {
			return fns
		}
		fns := map[string]*ast.FuncDecl{}
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
					fns[fn.Name.Name] = fn
				}
			}
		}
		tests[dir] = fns
		return fns
	}
	ids, traced := map[string]bool{}, map[string]bool{}
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
			fn := testsOf(r.dir)[r.name]
			if fn == nil {
				t.Errorf("%s: %s.%s does not exist", s.id, r.dir, r.name)
				continue
			}
			if _, ok := skipAllowed[r.dir+"."+r.name]; skips(fn) && !ok {
				t.Errorf("%s: %s.%s can skip itself, so it may prove nothing", s.id, r.dir, r.name)
			}
			traced[r.dir+"."+r.name] = true
		}
	}
	/* The scenarios 4a, 4b and 4c must prove (the plan's table rows owned by them, the 4a.7 attack, the 4a review focus items). */
	for _, id := range []string{"C1", "C2a", "C2b", "C2c", "C2d", "C2e", "C2f", "C2g", "C2i", "C2j", "C2k", "C3", "C4", "C5", "C6", "C7", "C8", "C2h", "C9", "4d.2", "4d.4", "4a.7", "4c.2", "4c.3", "4c.4", "4c.5", "RF1", "RF2", "RF3", "RF4", "RF5"} {
		if !ids[id] {
			t.Errorf("scenario %s is not in the index", id)
		}
	}
	if f := os.Getenv("NMS_TRACE_JSON"); f != "" {
		problems, err := ran(root, f, traced)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range problems {
			t.Error(p)
		}
	}
}

/* skipAllowed lists traced tests ("dir.Name") that may call t.Skip themselves, each with its reason. */
var skipAllowed = map[string]string{}

/* skips reports whether fn's body calls a Skip method (t.Skip, t.Skipf, t.SkipNow, or any receiver's). */
func skips(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if sel, ok := c.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "Skip" || sel.Sel.Name == "Skipf" || sel.Sel.Name == "SkipNow") {
				found = true
			}
		}
		return !found
	})
	return found
}

/* ran reads the go test -json output in file and lists every traced test ("dir.Name") that did not pass: skipped, failed or absent. */
func ran(root, file string, traced map[string]bool) ([]string, error) {
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return nil, err
	}
	first, _, _ := strings.Cut(string(mod), "\n")
	module := strings.TrimSpace(strings.TrimPrefix(first, "module "))
	b, err := os.ReadFile(file) // #nosec G304 -- the CI step's own output file
	if err != nil {
		return nil, err
	}
	result := map[string]string{} /* "dir.Name" -> pass, fail or skip */
	for _, line := range strings.Split(string(b), "\n") {
		var ev struct{ Action, Package, Test string }
		if json.Unmarshal([]byte(line), &ev) != nil || ev.Test == "" || strings.Contains(ev.Test, "/") {
			continue
		}
		if ev.Action == "pass" || ev.Action == "fail" || ev.Action == "skip" {
			result[strings.TrimPrefix(strings.TrimPrefix(ev.Package, module), "/")+"."+ev.Test] = ev.Action
		}
	}
	var problems []string
	for k := range traced {
		switch got := result[k]; got {
		case "pass":
		case "":
			problems = append(problems, k+": absent from "+file)
		default:
			problems = append(problems, k+": "+got+" in "+file)
		}
	}
	sort.Strings(problems)
	return problems, nil
}

/* The skip and run checks catch what they are meant to catch. */
func TestTraceabilityCatchesSkipsAndAbsentTests(t *testing.T) {
	af, err := parser.ParseFile(token.NewFileSet(), "x_test.go", `package x
func TestA(t *testing.T) { if testing.Short() { t.Skip("no") } }
func TestB(t *testing.T) { t.Run("s", func(t *testing.T) { t.SkipNow() }) }
func TestC(t *testing.T) { t.Log("skip") }`, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var got []bool
	for _, d := range af.Decls {
		got = append(got, skips(d.(*ast.FuncDecl)))
	}
	if len(got) != 3 || !got[0] || !got[1] || got[2] {
		t.Errorf("skips = %v, want [true true false]", got)
	}

	file := filepath.Join(t.TempDir(), "t.json")
	pkg := `"Package":"github.com/beekamai/network-scheme/cmd/x"`
	if err := os.WriteFile(file, []byte(`{"Action":"pass",`+pkg+`,"Test":"TestA"}
{"Action":"skip",`+pkg+`,"Test":"TestB"}
{"Action":"pass",`+pkg+`,"Test":"TestC/sub"}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	problems, err := ran(filepath.Join("..", "..", "..", ".."), file, map[string]bool{"cmd/x.TestA": true, "cmd/x.TestB": true, "cmd/x.TestC": true})
	if err != nil || len(problems) != 2 || !strings.HasPrefix(problems[0], "cmd/x.TestB: skip") || !strings.HasPrefix(problems[1], "cmd/x.TestC: absent") {
		t.Errorf("ran = %q, %v", problems, err)
	}
}
