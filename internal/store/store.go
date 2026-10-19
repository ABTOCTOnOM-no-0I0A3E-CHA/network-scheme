// Package store opens PostgreSQL connections and applies embedded migrations.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/beekamai/network-scheme/internal/config"
	"github.com/beekamai/network-scheme/internal/secret"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

/* The version table lives in core: the migrator has no CREATE on public. */
const versionTable = "core.goose_db_version"

func poolConfig(c config.DB, pw secret.Secret) (*pgxpool.Config, error) {
	if pw.IsZero() {
		return nil, errors.New("empty database password")
	}
	/*
	   Config values never enter a DSN string: a constant template is parsed and
	   the values are assigned to the structured fields afterwards.
	*/
	cfg, err := pgxpool.ParseConfig("host=placeholder sslmode=prefer connect_timeout=10")
	if err != nil {
		return nil, fmt.Errorf("database config: %w", err)
	}
	cc := cfg.ConnConfig
	cc.Host, cc.Port = c.Host, uint16(c.Port) // #nosec G115 -- range checked by config validation
	cc.Database, cc.User, cc.Password = c.Name, c.User, pw.Reveal()
	if cc.TLSConfig != nil {
		cc.TLSConfig.ServerName = c.Host
	}
	for _, fb := range cc.Fallbacks {
		fb.Host, fb.Port = c.Host, cc.Port
		if fb.TLSConfig != nil {
			fb.TLSConfig.ServerName = c.Host
		}
	}
	return cfg, nil
}

// Open creates a connection pool and verifies connectivity.
func Open(ctx context.Context, c config.DB, pw secret.Secret) (*pgxpool.Pool, error) {
	cfg, err := poolConfig(c, pw)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return pool, nil
}

func provider(db *sql.DB) (*goose.Provider, error) {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return nil, err
	}
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return nil, err
	}
	return goose.NewProvider(goose.DialectPostgres, db, sub,
		goose.WithTableName(versionTable), goose.WithSessionLocker(locker))
}

/*
Migrate applies all pending embedded migrations. The connecting role must be
the schema owner (nms_migrator); concurrent runs are serialised by an advisory lock.
*/
func Migrate(ctx context.Context, c config.DB, pw secret.Secret) error {
	cfg, err := poolConfig(c, pw)
	if err != nil {
		return err
	}
	db := stdlib.OpenDB(*cfg.ConnConfig)
	defer func() { _ = db.Close() }()
	p, err := provider(db)
	if err != nil {
		return fmt.Errorf("init migrations: %w", err)
	}
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}

// LatestVersion returns the highest embedded migration version.
func LatestVersion() (int64, error) {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return 0, err
	}
	var latest int64
	for _, e := range entries {
		v, err := goose.NumericComponent(e.Name())
		if err != nil {
			return 0, err
		}
		latest = max(latest, v)
	}
	return latest, nil
}
