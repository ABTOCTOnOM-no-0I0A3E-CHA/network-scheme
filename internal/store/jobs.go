package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
)

// JobsSchema is the schema of the River job queue tables.
const JobsSchema = "jobs"

/*
jobGrants run after every River migration (GRANT is idempotent). The api
only enqueues: INSERT plus what INSERT ... ON CONFLICT DO UPDATE SET kind ...
RETURNING needs. The poller works the queue and runs River's maintenance
(leader election, cleanup), so it gets DML on the queue tables but never on
river_migration.
*/
const jobGrants = `
REVOKE ALL ON ALL TABLES IN SCHEMA jobs FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA jobs FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE (kind) ON jobs.river_job TO nms_api;
GRANT USAGE ON SEQUENCE jobs.river_job_id_seq TO nms_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON jobs.river_job, jobs.river_leader, jobs.river_queue,
    jobs.river_notification TO nms_poller;
GRANT SELECT ON jobs.river_migration TO nms_poller;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA jobs TO nms_poller;
`

/* migrateJobs applies River's migrations in the jobs schema and grants the application roles. */
func migrateJobs(ctx context.Context, cfg *pgxpool.Config) error {
	cfg.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("open pool: %w", err)
	}
	defer pool.Close()
	m, err := rivermigrate.New(riverpgxv5.New(pool), &rivermigrate.Config{Schema: JobsSchema})
	if err != nil {
		return err
	}
	/* Concurrent migrate runs are serialised by a session lock held on its own connection. */
	lock, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer lock.Release()
	if _, err := lock.Exec(ctx, `SELECT pg_advisory_lock(hashtext('nms.jobs.migrate'))`); err != nil {
		return err
	}
	defer func() {
		_, _ = lock.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(hashtext('nms.jobs.migrate'))`)
	}()
	if _, err := m.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
		return err
	}
	_, err = pool.Exec(ctx, jobGrants)
	return err
}
