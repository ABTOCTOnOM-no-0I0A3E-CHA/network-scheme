/*
Package freeze is the executor's freeze: an in-memory latch that every
decision consults, backed by exec_state (written through the registry when
the registry still verifies), by a sticky flag in the state file and by a
disaster alert in execpub.alert. Once latched it stays latched for the life
of the process; lifting a freeze is host-only (nmsctl, task 4a.4).
*/
package freeze

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/state"
)

/* ErrFrozen refuses a decision while the executor is frozen. */
var ErrFrozen = errors.New("executor is frozen")

/* Alert kinds (execpub.alert.kind, task 4a.7 turns them into problems). */
const (
	KindTamper = "executor_tamper"
)

/* Interval is how often Run verifies the registry (security.md 5.1a). */
const Interval = 30 * time.Second

/* Guard holds the latch and verifies the registry for every decision. */
type Guard struct {
	reg  *registry.Registry
	pool *pgxpool.Pool
	log  *slog.Logger

	mu      sync.Mutex
	frozen  bool
	reason  string
	alerted map[string]bool /* kinds already triggered in this process */
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
Check is the gate before every decision: it verifies the registry and
returns nil only if the verification passes and nothing is frozen. Any
other outcome refuses the decision.
*/
func (g *Guard) Check(ctx context.Context) error {
	rep, err := g.reg.Verify(ctx)
	switch {
	case errors.Is(err, registry.ErrTampered):
		g.Trigger(ctx, KindTamper, err.Error())
	case err != nil:
		return fmt.Errorf("verify registry: %w", err)
	case rep.Frozen:
		g.latch(rep.Reason) /* a freeze already recorded: no new alert */
	}
	if frozen, _ := g.Frozen(); frozen {
		return ErrFrozen
	}
	return nil
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
Trigger freezes: the latch first (it alone already refuses every decision),
then the sticky flag in the state file, then exec_state through the
registry — which refuses to write over a registry that does not verify, so
a tampered state is never sealed as legitimate — and a disaster alert. All
but the latch happen once per kind and process, so a tampered registry
found again every Interval does not flood the log and the alerts.
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
	err := g.reg.Write(ctx, func(ctx context.Context, tx *registry.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO exec.exec_state (singleton, "freeze", freeze_reason, version, mac)
			VALUES (true, true, $1, $2, $3)
			ON CONFLICT (singleton) DO UPDATE SET "freeze" = true, freeze_reason = $1, version = $2, mac = $3`,
			reason, tx.Seq(), registry.Unsealed())
		return err
	})
	if err != nil {
		g.log.Error("exec_state: cannot record the freeze", slog.Any("err", err))
	}
	if _, err := g.pool.Exec(ctx, `INSERT INTO execpub.alert (kind, severity, text) VALUES ($1, 'disaster', $2)`,
		kind, reason); err != nil {
		g.log.Error("execpub.alert: cannot publish the freeze", slog.Any("err", err))
	}
	if g.Published != nil {
		g.Published(ctx, reason)
	}
}
