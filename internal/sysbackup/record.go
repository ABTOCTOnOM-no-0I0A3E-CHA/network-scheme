package sysbackup

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/internal/audit"
)

/* RestoreSummary is what restore hands the tools container to record (the manifest without its files). */
type RestoreSummary struct {
	ID          string    `json:"id"`
	Created     time.Time `json:"created"`
	ExecutorHWM int64     `json:"executor_hwm"`
}

/* Summary is the part of m recorded in the audit. */
func (m Manifest) Summary() RestoreSummary {
	return RestoreSummary{ID: m.ID, Created: m.Created, ExecutorHWM: m.ExecutorHWM}
}

/* RecordRestore appends the restore to the panel audit (an INSERT, as every audit write). */
func RecordRestore(ctx context.Context, pool *pgxpool.Pool, s RestoreSummary) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		_, err := audit.Append(ctx, tx, audit.Event{
			UserAgent: "nmsctl", Action: "cli.restore", ObjectType: "backup", ObjectID: s.ID, Result: "success",
			Details: map[string]any{"created": s.Created.UTC().Format(time.RFC3339), "executor_hwm": s.ExecutorHWM},
		})
		return err
	})
}
