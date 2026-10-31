package registry

import (
	"time"

	"github.com/jackc/pgx/v5"
)

/* SetHook lets the external attack tests act at a named stage of a write or of the bootstrap. */
func SetHook(r *Registry, h func(stage string, tx pgx.Tx)) { r.hook = h }

/* SetTimeouts shortens the client-side bound of one transaction and the settle wait for a test. */
func SetTimeouts(r *Registry, op, settle time.Duration) { r.opTimeout, r.settleFor = op, settle }
