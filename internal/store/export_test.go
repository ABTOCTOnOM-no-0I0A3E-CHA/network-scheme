package store

import (
	"context"

	"github.com/jackc/pgx/v5/stdlib"

	"github.com/beekamai/network-scheme/internal/config"
	"github.com/beekamai/network-scheme/internal/secret"
)

/* MigrateUpTo applies the embedded migrations up to version, then River's (an older installation). */
func MigrateUpTo(ctx context.Context, c config.DB, pw secret.Secret, version int64) error {
	cfg, err := poolConfig(c, pw)
	if err != nil {
		return err
	}
	db := stdlib.OpenDB(*cfg.ConnConfig)
	defer func() { _ = db.Close() }()
	p, err := provider(db)
	if err != nil {
		return err
	}
	if _, err := p.UpTo(ctx, version); err != nil {
		return err
	}
	return migrateJobs(ctx, cfg)
}
