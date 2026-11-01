package authz_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/internal/execadmin"
)

/*
I1: the recording of every guess is blocked for real (a superuser's SHARE
lock on exec.audit_event: the registry still verifies, the code is
evaluated, the write then fails on lock_timeout). After a restart the guess
budget is not reset: the in-memory guards came back from the guards file.
*/
func TestRestartKeepsGuessBudget(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	ctx := context.Background()
	tx, err := f.env.Pool("postgres").Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `LOCK TABLE exec.audit_event IN SHARE MODE`); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if err := f.try(t, u, f.wrong(t, u)); err != authz.ErrUnavailable {
			_ = tx.Rollback(ctx)
			t.Fatalf("guess %d: %v", i+1, err)
		}
	}
	_ = tx.Rollback(ctx)
	if got := f.row(t, u.id); got.failures != 0 {
		t.Fatalf("the blocked writes committed: %+v", got)
	}
	f.clk.Advance(10 * time.Second)
	f.az = f.authorizer(t) /* restart */
	if err := f.try(t, u, f.wrong(t, u)); err != authz.ErrDenied {
		t.Fatalf("4th: %v", err)
	}
	if err := f.try(t, u, f.wrong(t, u)); !errors.Is(err, authz.ErrLocked) {
		t.Fatalf("the 5th guess across a restart did not lock: %v", err)
	}
}

/* The global window survives a restart too: 20 unrecorded failures of 4 users, a restart, one more of a 5th user freezes. */
func TestRestartKeepsGlobalWindow(t *testing.T) {
	f := newFixture(t)
	var us []user
	for i := range 5 {
		us = append(us, f.enrolled(t, fmt.Sprintf("g%d-", i)))
	}
	authz.SetAbortWrite(f.az, func() error { return errors.New("injected") })
	for _, u := range us[:4] {
		for range authz.MaxFailures {
			_ = f.try(t, u, f.wrong(t, u))
		}
	}
	f.az = f.authorizer(t)
	if err := f.try(t, us[4], f.wrong(t, us[4])); err != authz.ErrDenied {
		t.Fatal(err)
	}
	if frozen, _ := f.guard.Frozen(); !frozen {
		t.Fatal("the restart reset the global window")
	}
}

/* A tampered or foreign guards file stops the executor from starting (it is never silently reset). */
func TestGuardsFileTamperRefused(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	_ = f.try(t, u, f.wrong(t, u))
	path := f.dir + "/guards"
	f.tamperFile(t, path)
	if _, err := authz.New(authz.Config{Guard: f.guard, Reg: f.reg, Keys: f.keys, Policy: f.pol, Log: f.log,
		TicketKey: ticketPub, Started: f.clk.Now(), Now: f.clk.Now, GuardsFile: path}); err == nil {
		t.Fatal("a tampered guards file was accepted")
	}
}

/*
I1 (a): a huge value planted in core.user (a superuser can drop the unique
index that bounds names) is not read into memory: the executor's
connections refuse messages over registry.MaxMessage, so the decision is
refused as unavailable instead of allocating it.
*/
func TestHugePanelValueBounded(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	db := f.env.Pool("postgres")
	ctx := context.Background()
	if _, err := db.Exec(ctx, `ALTER TABLE core."user" DROP CONSTRAINT user_username_key`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, `UPDATE core."user" SET username = $1 WHERE id = $2`, u.name, u.id)
		if _, err := db.Exec(ctx, `ALTER TABLE core."user" ADD CONSTRAINT user_username_key UNIQUE (username)`); err != nil {
			t.Error(err)
		}
	})
	if _, err := db.Exec(ctx, `UPDATE core."user" SET username = repeat('a', 2 * 1024 * 1024) WHERE id = $1`, u.id); err != nil {
		t.Fatal(err)
	}
	f.oneAudit(t, "denied", "panel_unavailable", func() {
		if err := f.try(t, u, f.code(t, u)); err != authz.ErrUnavailable {
			t.Fatalf("huge name: %v", err)
		}
	})
}

/* Open question 7: the freeze a tripped window causes commits with the failure, so a crash before Trigger leaves the registry frozen. */
func TestTripFreezeCommitsWithTheFailure(t *testing.T) {
	f := newFixture(t)
	var us []user
	for i := range 5 {
		us = append(us, f.enrolled(t, fmt.Sprintf("t%d-", i)))
	}
	authz.SetNoTrigger(f.az, true)
	for _, u := range us[:4] {
		f.fail5(t, u)
	}
	_ = f.try(t, us[4], f.wrong(t, us[4]))
	if frozen, _ := f.guard.Frozen(); frozen {
		t.Fatal("the seam did not skip Trigger")
	}
	var frz bool
	var reason *string
	if err := f.env.Pool("postgres").QueryRow(context.Background(), `SELECT "freeze", freeze_reason FROM exec.exec_state`).Scan(&frz, &reason); err != nil {
		t.Fatal(err)
	}
	if !frz || reason == nil || *reason != "change TOTP: 21 failures of 5 users within an hour" {
		t.Fatalf("exec_state freeze %v %v", frz, reason)
	}
	g := freeze.New(f.reg, f.pool, f.log) /* the restarted executor */
	if err := g.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if frozen, _ := g.Frozen(); !frozen {
		t.Fatal("not frozen after the restart")
	}
}

/* M1: a locked user gets the same answer whatever grants it holds: no oracle on the registry's grants. */
func TestLockedAnswerIgnoresGrants(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	f.fail5(t, u)
	for _, need := range []authz.Need{writeCore, {Kind: "write", Groups: []string{"edge"}}, {Kind: "unmask"}} {
		f.oneAudit(t, "denied", "locked", func() {
			if err := f.ask(f.ticketFor(t, u), f.code(t, u), need); !errors.Is(err, authz.ErrLocked) {
				t.Fatalf("%+v: %v", need, err)
			}
		})
	}
}

/* M2: a decision that passed the policy check and then waited is refused if the host disabled the executor meanwhile. */
func TestPolicyCheckedAgainInsideTheWrite(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	authz.SetBeforeDecide(f.az, func() { f.setPolicy(t, "enabled: false\n") })
	f.oneAudit(t, "denied", "disabled", func() {
		if err := f.try(t, u, f.code(t, u)); err != authz.ErrDisabled {
			t.Fatal(err)
		}
	})
	if got := f.row(t, u.id); got.lastStep != 0 || got.failures != 0 {
		t.Fatalf("the code was evaluated: %+v", got)
	}
}

/* M3: a spent nonce stays while its ticket can still verify by the wall clock, however far the monotonic clock went. */
func TestNonceKeptUntilWallExpiry(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	tok := f.ticketFor(t, u)
	if err := f.ask(tok, f.code(t, u), writeCore); err != nil {
		t.Fatal(err)
	}
	authz.SetMono(f.az, func() time.Duration { return time.Hour }) /* the wall clock was stepped back: it did not move */
	f.oneAudit(t, "denied", "ticket_replayed", func() {
		if err := f.ask(tok, f.code(t, u), writeCore); err != authz.ErrDenied {
			t.Fatal(err)
		}
	})
}

/* The nonce cache refuses when full (fail closed) instead of forgetting a nonce. */
func TestNonceCacheFullRefuses(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	authz.SetNonceCap(f.az, 2)
	_ = f.try(t, u, f.wrong(t, u))
	_ = f.try(t, u, f.wrong(t, u))
	f.oneAudit(t, "denied", "ticket_cache_full", func() {
		if err := f.try(t, u, f.code(t, u)); err != authz.ErrDenied {
			t.Fatal(err)
		}
	})
}

/* M4: a host reset waits for the decision in progress, so the decision cannot write back a state older than the reset. */
func TestResetWaitsForDecision(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	entered, release := make(chan struct{}), make(chan struct{})
	authz.SetBeforeDecide(f.az, func() { close(entered); <-release })
	done := make(chan error, 1)
	go func() { done <- f.try(t, u, f.wrong(t, u)) }()
	<-entered
	reset := make(chan struct{})
	go func() { f.az.ResetUser(u.id); close(reset) }()
	select {
	case <-reset:
		t.Fatal("ResetUser ran during a decision")
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != authz.ErrDenied {
		t.Fatal(err)
	}
	<-reset
}

/* Eight parallel requests with one code (each with its own ticket): exactly one is accepted. */
func TestParallelSameCode(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	if n := f.parallel(t, u, 8); n != 1 {
		t.Fatalf("%d accepted", n)
	}
}

/*
The decisions are ordered (sem): when the first one's write fails and it
has not yet remembered the step it consumed, a second one must not
evaluate the same code meanwhile. None is accepted.
*/
func TestParallelSameCodeWhileFirstUnrecorded(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	var aborts, afters atomic.Int64
	authz.SetAbortWrite(f.az, func() error {
		if aborts.Add(1) == 1 {
			return errors.New("injected")
		}
		return nil
	})
	authz.SetAfterWrite(f.az, func(err error) error {
		if afters.Add(1) == 1 {
			time.Sleep(300 * time.Millisecond)
		}
		return err
	})
	if n := f.parallel(t, u, 8); n != 0 {
		t.Fatalf("%d accepted with the first use unrecorded", n)
	}
}

/* parallel runs n authorizations of u's current code at once and counts the accepted ones. */
func (f *fixture) parallel(t *testing.T, u user, n int) int {
	t.Helper()
	code := f.code(t, u)
	toks := make([]string, n)
	for i := range toks {
		toks[i] = f.ticketFor(t, u)
	}
	var ok atomic.Int64
	var wg sync.WaitGroup
	for _, tok := range toks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f.ask(tok, code, writeCore) == nil {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	return int(ok.Load())
}

/* A host unlock is the host's word for the guards file too: a restart after it does not bring the old lock back. */
func TestUnlockPersistsAcrossRestart(t *testing.T) {
	f := newFixture(t)
	u := f.enrolled(t, "alice")
	authz.SetAbortWrite(f.az, func() error { return errors.New("injected") })
	for range authz.MaxFailures {
		_ = f.try(t, u, f.wrong(t, u))
	}
	authz.SetAbortWrite(f.az, nil)
	f.host(t, execadmin.Request{Cmd: execadmin.CmdUnlock, User: u.name})
	f.az = f.authorizer(t)
	if err := f.try(t, u, f.code(t, u)); err != nil {
		t.Fatalf("after unlock and restart: %v", err)
	}
}

/* tamperFile flips one byte in the body of a file. */
func (f *fixture) tamperFile(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-2] ^= 1
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
