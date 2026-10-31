/*
Package freeze is the executor's freeze: an in-memory latch that every
decision consults, backed by a disaster alert in execpub.alert, by a sticky
flag in the state file and by exec_state (written through the registry when
the registry still verifies). Once latched it stays latched for the life of
the process; lifting a freeze is host-only (nmsctl, task 4a.4).
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
	KindTamper       = "executor_tamper"       /* disaster: the registry or the state file was tampered with */
	KindUnverifiable = "executor_unverifiable" /* high: the registry cannot be verified (decisions refused) */
)

/* Timing: periodic verification (security.md 5.1a), bounds of the freeze's own writes, failures before an alert. */
const (
	Interval      = 30 * time.Second
	alertTimeout  = 5 * time.Second
	alertRetries  = 5
	recordTimeout = 2 * registry.StatementTimeout
	failureAlert  = 3
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
			g.latch(reason) /* a freeze already recorded: no new alert */
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
			g.latch(reason)
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

/* Check verifies the registry and reports whether a decision may be taken now. */
func (g *Guard) Check(ctx context.Context) error {
	return g.View(ctx, func(*registry.Snapshot) error { return nil })
}

/* Run verifies the registry every Interval until ctx ends. */
func (g *Guard) Run(ctx context.Context) {
	t := time.NewTicker(Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := g.Check(ctx); err != nil && !errors.Is(err, ErrFrozen) {
				g.log.Error("registry verification failed", slog.Any("err", err))
			}
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

func (g *Guard) latch(reason string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.frozen {
		g.frozen, g.reason = true, state.Reason(reason)
	}
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
then the sticky flag in the local state file (no database involved), then
the disaster alert (its own deadline, retried in the background), then
exec_state through the registry, which refuses to write over a registry
that does not verify, so a tampered state is never sealed as legitimate. All but the
latch happen once per kind and process, so a tampered registry found again
every Interval does not flood the log and the alerts; every step is bounded
in time, so a lock held by someone else delays nothing but exec_state.
*/
func (g *Guard) Trigger(ctx context.Context, kind, reason string) {
	reason = state.Reason(reason)
	g.latch(reason)
	if !g.firstOf(kind) {
		return
	}
	g.log.Error("executor frozen", slog.String("kind", kind), slog.String("reason", reason))
	if err := g.reg.MarkFrozen(reason); err != nil {
		g.log.Error("state file: cannot record the freeze", slog.Any("err", err))
	}
	g.alert(ctx, kind, "disaster", reason)
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
