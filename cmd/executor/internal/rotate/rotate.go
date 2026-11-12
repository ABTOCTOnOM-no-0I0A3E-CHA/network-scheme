/*
Package rotate moves the executor to a new sealing key (nmsctl executor key
rotate, security.md 9): a one-shot run of the executor image while the
daemon is stopped, so nothing else writes a MAC meanwhile. In one
transaction (registry.Rotate) every registry row is re-MACed and every
change TOTP secret re-sealed under the next key, the append-only session,
recording and changeset rows re-MACed, an audit row appended; the state
file goes pending (current key) → committed (next key); then the guards
file is moved to the next key. Run again with the same next key after a
crash, it resumes; after it succeeded, it does nothing. Only the host then
replaces the key file (nmsctl), so the old key is gone.
*/
package rotate

import (
	"context"
	"path/filepath"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/cmd/executor/internal/audit"
	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/changeset"
	"github.com/beekamai/network-scheme/cmd/executor/internal/recording"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/session"
)

/* Config is one rotation: the current and the next key, the state directory, the host operator (for the audit). */
type Config struct {
	Pool      *pgxpool.Pool
	Old, Next *seal.Keys
	StateDir  string
	Operator  string
}

/* Sealing runs (or resumes) the rotation of c. */
func Sealing(ctx context.Context, c Config) (registry.RotateReport, error) {
	reg := registry.New(c.Pool, c.Old, filepath.Join(c.StateDir, "state"))
	ev := audit.Event{UA: "nmsctl", Action: "admin.key-rotate", Object: "sealing-key", Result: audit.OK,
		Details: map[string]any{"operator": c.Operator}}
	rep, err := reg.Rotate(ctx, c.Next, audit.Append(ev), Rekey())
	if err != nil {
		return rep, err
	}
	return rep, authz.RekeyGuards(filepath.Join(c.StateDir, "guards"), c.Old.State(), c.Next.State())
}

/* Rekey re-MACs every MACed row outside the registry. */
func Rekey() registry.Rekey {
	return registry.Rekey{Run: func(ctx context.Context, tx pgx.Tx, old, next *[32]byte) error {
		for _, f := range []func(context.Context, pgx.Tx, *[32]byte, *[32]byte) error{session.Rekey, recording.Rekey, changeset.Rekey} {
			if err := f(ctx, tx, old, next); err != nil {
				return err
			}
		}
		return nil
	}}
}
