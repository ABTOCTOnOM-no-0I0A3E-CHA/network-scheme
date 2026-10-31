package registry

import "github.com/jackc/pgx/v5"

/* SetHook lets the external attack tests act at a named stage of a write or of the bootstrap. */
func SetHook(r *Registry, h func(stage string, tx pgx.Tx)) { r.hook = h }
