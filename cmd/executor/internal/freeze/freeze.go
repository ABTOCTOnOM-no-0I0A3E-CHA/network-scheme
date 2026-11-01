/*
Package freeze is the executor's freeze: an in-memory latch that every
decision consults, backed by a disaster alert in execpub.alert, by a sticky
flag in the state file and by exec_state (written through the registry when
the registry still verifies). Once latched it stays latched until the host
lifts it (FreezeOff, through nmsctl executor freeze off) or, after tampering,
resets the registry.
*/
package freeze

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/state"
)

/* alertRetryEvery spaces the background retries of a failed alert (a variable for the tests). */
var alertRetryEvery = 2 * time.Second

/* ErrFrozen refuses a decision while the executor is frozen. */
var ErrFrozen = errors.New("executor is frozen")

/* Alert kinds (execpub.alert.kind, task 4a.7 turns them into problems). */
const (
	KindTamper           = "executor_tamper"            /* disaster: the registry, the state file or the audit chain was tampered with */
	KindUnverifiable     = "executor_unverifiable"      /* high: the registry cannot be verified (decisions refused) */
	KindHostFreeze       = "executor_freeze"            /* warning: the host froze the executor (nmsctl executor freeze on) */
	KindPolicyInvalid    = "executor_policy_invalid"    /* high: the policy file is invalid, the executor is disabled */
	KindBruteforce       = "executor_bruteforce"        /* disaster: change TOTP failures of several users within an hour froze the executor */
	KindGuardsUnwritable = "executor_guards_unwritable" /* high: the change TOTP guards cannot be saved, decisions are refused */
)

/* severity of the freezes Trigger alerts; any other kind is a disaster. */
var severity = map[string]string{KindHostFreeze: "warning"}

/* Timing: periodic verification (security.md 5.1a), bounds of the freeze's own writes, failures before an alert. */
const (
	Interval      = 30 * time.Second
	alertTimeout  = 5 * time.Second
	alertRetries  = 5
	recordTimeout = 2 * registry.StatementTimeout
	failureAlert  = 3
)

/*
Run's pace (variables for the tests): a verification every checkEvery, each
bounded by checkTimeout, waiting for the registry's lock included (below checkEvery).
*/
var (
	checkEvery   = Interval
	checkTimeout = Interval - 5*time.Second
)

/* Guard holds the latch and verifies the registry for every decision. */
type Guard struct {
	reg  *registry.Registry
	pool *pgxpool.Pool
	log  *slog.Logger

	mu       sync.Mutex
	frozen   bool
	reason   string
	alerted  map[string]bool /* kinds already triggered in this process */
	failures int             /* consecutive verifications failing without a verdict */
	/* gen moves with every new freeze: a freeze off lifts nothing if it moved meanwhile. */
	gen int64
	/* offSeq is the registry counter of the last freeze off: older snapshots no longer latch. */
	offSeq int64
	/* Published, if set, is called once the latch is set, after the alert (hook for execpub.status, 4a.7). */
	Published func(ctx context.Context, reason string)
}

/* New returns an unfrozen guard; call Start before any decision. */
func New(reg *registry.Registry, pool *pgxpool.Pool, log *slog.Logger) *Guard {
	return &Guard{reg: reg, pool: pool, log: log, alerted: map[string]bool{}}
}

/* Frozen reports the latch and its reason. */
func (g *Guard) Frozen() (bool, string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.frozen, g.reason
}

/*
Start bootstraps a fresh registry and runs the first verification. A
tampered registry or state file freezes; only a database error is returned
(the executor cannot run without its database).
*/
func (g *Guard) Start(ctx context.Context) error {
	if err := g.reg.Init(ctx); err != nil {
		if !errors.Is(err, registry.ErrTampered) {
			return err
		}
		g.Trigger(ctx, KindTamper, err.Error())
	}
	if err := g.Check(ctx); err != nil && !errors.Is(err, ErrFrozen) {
		return err
	}
	return nil
}

/*
View is the gate of every decision: it verifies the registry and runs fn
on the verified snapshot, only if nothing is frozen. fn decides from that
snapshot alone (registry.View). Tampering freezes; any other failure refuses
the decision, and several in a row raise an alert.
*/
func (g *Guard) View(ctx context.Context, fn func(*registry.Snapshot) error) error {
	passed := false
	err := g.reg.View(ctx, func(s *registry.Snapshot) error {
		passed = true
		g.verification(true)
		if frozen, reason := s.Frozen(); frozen {
			g.latchAt(s.Seq(), reason) /* a freeze already recorded: no new alert */
		}
		if frozen, _ := g.Frozen(); frozen {
			return ErrFrozen
		}
		return fn(s)
	})
	switch {
	case errors.Is(err, registry.ErrTampered):
		g.Trigger(ctx, KindTamper, err.Error())
		return ErrFrozen
	case err != nil && !passed && errors.Is(err, context.Canceled) && ctx.Err() != nil:
		/* The caller went away (a client disconnect): no evidence about the registry, not counted. */
		return fmt.Errorf("verify registry: %w", err)
	case err != nil && !passed:
		if g.verification(false) {
			g.alert(ctx, KindUnverifiable, "high", err.Error())
		}
		return fmt.Errorf("verify registry: %w", err)
	}
	return err
}

/*
Write is the gate of every decision that changes the registry: refused
while frozen, frozen on tampering (registry.Write). fn sees the verified
snapshot the change is based on.
*/
func (g *Guard) Write(ctx context.Context, fn func(ctx context.Context, s *registry.Snapshot, tx *registry.Tx) error) error {
	if frozen, _ := g.Frozen(); frozen {
		return ErrFrozen
	}
	err := g.reg.Write(ctx, func(ctx context.Context, s *registry.Snapshot, tx *registry.Tx) error {
		if frozen, reason := s.Frozen(); frozen {
			g.latchAt(s.Seq(), reason)
			return ErrFrozen
		}
		/* The latch again: it may have been set while this write waited for the registry. */
		if frozen, _ := g.Frozen(); frozen {
			return ErrFrozen
		}
		return fn(ctx, s, tx)
	})
	if errors.Is(err, registry.ErrTampered) {
		g.Trigger(ctx, KindTamper, err.Error())
		return ErrFrozen
	}
	return err
}

/*
HostWrite is the gate of the host's registry changes (nmsctl executor:
enroll, grant, revoke, unlock, model-verify). Unlike Write it runs while
frozen: a freeze stops decisions on devices, and the host must still be able
to revoke or unlock during an incident. The registry is verified all the
same (registry.Write) and tampering freezes.
*/
func (g *Guard) HostWrite(ctx context.Context, fn func(ctx context.Context, s *registry.Snapshot, tx *registry.Tx) error) error {
	err := g.reg.Write(ctx, fn)
	if errors.Is(err, registry.ErrTampered) {
		g.Trigger(ctx, KindTamper, err.Error())
		return fmt.Errorf("%w: %v", ErrFrozen, err)
	}
	return err
}

/* Alert publishes an alert that freezes nothing (e.g. an invalid policy), as freezes do. */
func (g *Guard) Alert(ctx context.Context, kind, sev, text string) { g.alert(ctx, kind, sev, text) }

/*
Reset resets a tampered registry (registry.Reset, host only) and then lifts
the freeze as FreezeOff does: unless a new freeze arrived meanwhile.
Tampering found on the way (the schema itself changed) freezes anew.
*/
func (g *Guard) Reset(ctx context.Context, o registry.ResetOptions) (registry.ResetReport, error) {
	g.mu.Lock()
	gen := g.gen
	g.mu.Unlock()
	rep, err := g.reg.Reset(ctx, o)
	if errors.Is(err, registry.ErrTampered) {
		g.Trigger(ctx, KindTamper, err.Error())
		return rep, fmt.Errorf("%w: %v", ErrFrozen, err)
	}
	if err != nil {
		return rep, fmt.Errorf("registry reset: %w", err)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.gen != gen {
		return rep, fmt.Errorf("%w: a new freeze arrived during the reset", ErrFrozen)
	}
	if err := g.reg.ClearFrozen(); err != nil {
		return rep, fmt.Errorf("registry reset: state file: %w", err)
	}
	g.frozen, g.reason, g.offSeq, g.failures = false, "", rep.Seq, 0
	g.alerted = map[string]bool{}
	return rep, nil
}

/* Check verifies the registry and reports whether a decision may be taken now. */
func (g *Guard) Check(ctx context.Context) error {
	return g.View(ctx, func(*registry.Snapshot) error { return nil })
}

/*
Run verifies the registry every Interval until ctx ends. Each verification
has its own deadline (checkTimeout), so a stalled one ends as a failure that
counts toward the alert instead of stopping the loop.
*/
func (g *Guard) Run(ctx context.Context) {
	t := time.NewTicker(checkEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cctx, cancel := context.WithTimeout(ctx, checkTimeout)
			if err := g.Check(cctx); err != nil && !errors.Is(err, ErrFrozen) {
				g.log.Error("registry verification failed", slog.Any("err", err))
			}
			cancel()
		}
	}
}

/* verification counts failed verifications in a row; it reports true at the failureAlert-th. */
func (g *Guard) verification(passed bool) (alert bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if passed {
		g.failures = 0
		return false
	}
	g.failures++
	return g.failures == failureAlert
}

/* latch sets the latch; setting it, or a new freeze (fresh, from Trigger), moves the generation. */
func (g *Guard) latch(reason string, fresh bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if fresh || !g.frozen {
		g.gen++
	}
	if !g.frozen {
		g.frozen, g.reason = true, state.Reason(reason)
	}
}

/* latchAt latches a freeze read from a snapshot at seq, unless a freeze off committed after that snapshot. */
func (g *Guard) latchAt(seq int64, reason string) {
	g.mu.Lock()
	/* At offSeq itself too: the freeze off's own write; a new freeze after it latches through Trigger. */
	stale := g.offSeq > 0 && seq <= g.offSeq
	g.mu.Unlock()
	if !stale {
		g.latch(reason, false)
	}
}

/*
FreezeOff lifts the freeze (host only: nmsctl executor freeze off). Under the
registry's lock it verifies the whole registry (a failed verification
refuses, tampering freezes anew) and records exec_state unfrozen, together
with whatever also declares (the audit row); then it clears the sticky flag
of the state file and the latch, unless a new freeze arrived meanwhile: a
freeze off never lifts a freeze it did not see. check, if set, runs first
(the full audit chain verification): after the generation is taken, so a
freeze it or anyone triggers meanwhile is seen too. Any error leaves the
executor frozen (the latch and the sticky flag stay set), even if exec_state
was recorded unfrozen.
*/
func (g *Guard) FreezeOff(ctx context.Context, check func(context.Context) error, also func(tx *registry.Tx) error) error {
	g.mu.Lock()
	gen := g.gen
	g.mu.Unlock()
	if check != nil {
		if err := check(ctx); err != nil {
			return err
		}
	}
	var seq int64
	err := g.reg.Write(ctx, func(_ context.Context, s *registry.Snapshot, tx *registry.Tx) error {
		window := json.RawMessage("[]")
		if st, ok := s.Get("exec_state", true); ok {
			window, _ = st.Get("global_fail_window").(json.RawMessage)
		}
		if err := tx.Put("exec_state", map[string]any{"singleton": true, "freeze": false, "freeze_reason": nil,
			"global_fail_window": window}); err != nil {
			return err
		}
		seq = tx.Seq()
		if also != nil {
			return also(tx)
		}
		return nil
	})
	if errors.Is(err, registry.ErrTampered) {
		g.Trigger(ctx, KindTamper, err.Error())
		return fmt.Errorf("%w: the registry does not verify: %v", ErrFrozen, err)
	}
	if err != nil {
		return fmt.Errorf("freeze off: %w", err)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.gen != gen {
		return fmt.Errorf("%w: a new freeze arrived during freeze off", ErrFrozen)
	}
	if err := g.reg.ClearFrozen(); err != nil {
		return fmt.Errorf("freeze off: state file: %w", err)
	}
	g.frozen, g.reason, g.offSeq, g.failures = false, "", seq, 0
	g.alerted = map[string]bool{}
	return nil
}

/* firstOf reports whether kind is triggered for the first time in this process. */
func (g *Guard) firstOf(kind string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	first := !g.alerted[kind]
	g.alerted[kind] = true
	return first
}

/*
alert publishes to execpub.alert under its own deadline, so nothing held
elsewhere can suppress it. A failed publication is logged and retried in the
background a bounded number of times; the log line is the record if all fail.
*/
func (g *Guard) alert(ctx context.Context, kind, severity, text string) {
	text = state.Reason(text)
	g.log.Warn("executor alert", slog.String("kind", kind), slog.String("severity", severity), slog.String("text", text))
	publish := func() error {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), alertTimeout)
		defer cancel()
		_, err := g.pool.Exec(ctx, `INSERT INTO execpub.alert (kind, severity, text) VALUES ($1, $2, $3)`, kind, severity, text)
		return err
	}
	if err := publish(); err != nil {
		g.log.Error("execpub.alert: cannot publish, retrying", slog.String("kind", kind), slog.Any("err", err))
		go func() {
			for i := range alertRetries {
				time.Sleep(alertRetryEvery)
				err := publish()
				if err == nil {
					return
				}
				g.log.Error("execpub.alert: retry failed", slog.String("kind", kind), slog.Int("try", i+1), slog.Any("err", err))
			}
		}()
	}
}

/*
Trigger freezes: the latch first (it alone already refuses every decision),
then the sticky flag in the local state file (no database involved, and not
behind the registry's lock, which a stalled database call may hold), then
the disaster alert (its own deadline, retried in the background), then
exec_state through the registry, which refuses to write over a registry
that does not verify, so a tampered state is never sealed as legitimate. All but the
latch happen once per kind until a freeze off, so a tampered registry found again
every Interval does not flood the log and the alerts; every step is bounded
in time, so a lock held by someone else delays nothing but exec_state.
*/
func (g *Guard) Trigger(ctx context.Context, kind, reason string) {
	reason = state.Reason(reason)
	g.latch(reason, true)
	if !g.firstOf(kind) {
		return
	}
	g.log.Error("executor frozen", slog.String("kind", kind), slog.String("reason", reason))
	if err := g.reg.MarkFrozen(reason); err != nil {
		g.log.Error("state file: cannot record the freeze", slog.Any("err", err))
	}
	sev, ok := severity[kind]
	if !ok {
		sev = "disaster"
	}
	g.alert(ctx, kind, sev, reason)
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
	defer cancel()
	err := g.reg.Write(wctx, func(_ context.Context, s *registry.Snapshot, tx *registry.Tx) error {
		window := json.RawMessage("[]")
		if st, ok := s.Get("exec_state", true); ok {
			window, _ = st.Get("global_fail_window").(json.RawMessage)
		}
		return tx.Put("exec_state", map[string]any{"singleton": true, "freeze": true, "freeze_reason": reason,
			"global_fail_window": window})
	})
	if err != nil {
		g.log.Error("exec_state: cannot record the freeze", slog.Any("err", err))
	}
	if g.Published != nil {
		g.Published(ctx, reason)
	}
}
