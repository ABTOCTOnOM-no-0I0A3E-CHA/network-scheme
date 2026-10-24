/*
Package jobs defines the background jobs shared by the api (which enqueues
them) and the poller (which works them), and the River-backed enqueuer the
api uses. Jobs live in the jobs schema; each poller works its own queue.
*/
package jobs

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivertype"

	"github.com/beekamai/network-scheme/internal/store"
)

/* Job kinds. */
const (
	KindPollNow       = "poll_now"
	KindDiscoveryScan = "discovery_scan"
	KindBackupNow     = "backup_now"
)

/*
BackupGap is the width of the River uniqueness bucket for backup_now: jobs for
one device in the same BackupGap-wide period (River buckets time, it is not a
sliding window) are coalesced. The api's trigger engine additionally keeps
BackupGap between its own requests per device, and the poller enforces the gap
itself (it does not trust the api's unique key).
*/
const BackupGap = 5 * time.Minute

/* pollerIDRe keeps "poller_" + id a valid River queue name of at most 64 characters. */
var pollerIDRe = regexp.MustCompile(`^[a-z0-9]+(?:[_-][a-z0-9]+)*$`)

const maxPollerID = 64 - len("poller_")

// ValidPollerID reports whether id can name a poller (and its queue).
func ValidPollerID(id string) bool { return len(id) <= maxPollerID && pollerIDRe.MatchString(id) }

// BackupQueue returns the queue of poller pollerID that carries only backup_now jobs, so a burst of them cannot starve polls.
func BackupQueue(pollerID string) (string, error) {
	if !ValidPollerID(pollerID) {
		return "", fmt.Errorf("jobs: invalid poller id %q", pollerID)
	}
	return "backup_" + pollerID, nil
}

// Queue returns the queue worked by poller pollerID.
func Queue(pollerID string) (string, error) {
	if !ValidPollerID(pollerID) {
		return "", fmt.Errorf("jobs: invalid poller id %q", pollerID)
	}
	return "poller_" + pollerID, nil
}

/*
PollNowArgs asks the device's poller for an immediate full poll. Duplicates
are coalesced while one is queued or running; it is never retried (the next
scheduled poll follows anyway).
*/
type PollNowArgs struct {
	DeviceID int64 `json:"device_id"`
}

// Kind implements river.JobArgs.
func (PollNowArgs) Kind() string { return KindPollNow }

// InsertOpts implements river.JobArgsWithInsertOpts.
func (PollNowArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{MaxAttempts: 1, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: liveStates}}
}

/*
BackupNowArgs asks the device's poller to back up its configuration now. Only
one job per device is accepted within BackupGap (whatever its state: a burst of
config-change events makes one backup); it is never retried.
*/
type BackupNowArgs struct {
	DeviceID int64  `json:"device_id" river:"unique"`
	Source   string `json:"source,omitempty"` /* "manual" for a user's request; anything else is recorded as "event" */
}

// Kind implements river.JobArgs.
func (BackupNowArgs) Kind() string { return KindBackupNow }

// InsertOpts implements river.JobArgsWithInsertOpts.
func (BackupNowArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{MaxAttempts: 1, UniqueOpts: river.UniqueOpts{ByArgs: true, ByPeriod: BackupGap}}
}

/*
DiscoveryScanArgs asks the scan's poller for a run of discovery scan ScanID.
Duplicates are coalesced while one is queued; it is never retried.
*/
type DiscoveryScanArgs struct {
	ScanID int64 `json:"scan_id"`
}

// Kind implements river.JobArgs.
func (DiscoveryScanArgs) Kind() string { return KindDiscoveryScan }

// InsertOpts implements river.JobArgsWithInsertOpts.
func (DiscoveryScanArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{MaxAttempts: 1, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: liveStates}}
}

/* liveStates: a job is a duplicate only of one not yet finished (River's required minimum). */
var liveStates = []rivertype.JobState{
	rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRunning, rivertype.JobStateScheduled,
}

/*
Enqueuer inserts jobs in the caller's transaction through an insert-only
River client: the job exists exactly when the transaction commits.
*/
type Enqueuer struct {
	client *river.Client[pgx.Tx]
}

// NewEnqueuer returns an insert-only enqueuer over pool (it never works jobs).
func NewEnqueuer(pool *pgxpool.Pool) (*Enqueuer, error) {
	c, err := river.NewClient(riverpgxv5.New(pool), &river.Config{Schema: store.JobsSchema})
	if err != nil {
		return nil, fmt.Errorf("jobs: %w", err)
	}
	return &Enqueuer{client: c}, nil
}

// EnqueuePollNow queues an immediate poll of deviceID on the device's poller.
func (e *Enqueuer) EnqueuePollNow(ctx context.Context, tx pgx.Tx, deviceID int64) error {
	q, err := ownerQueue(ctx, tx, `SELECT poller_id FROM core.device WHERE id = $1`, "device", deviceID)
	if err != nil {
		return err
	}
	if _, err := e.client.InsertTx(ctx, tx, PollNowArgs{DeviceID: deviceID}, &river.InsertOpts{Queue: q}); err != nil {
		return fmt.Errorf("jobs: enqueue poll: %w", err)
	}
	return nil
}

// EnqueueBackupNow queues a configuration backup ("manual" or "event" source) of deviceID on the device's poller (coalesced within BackupGap).
func (e *Enqueuer) EnqueueBackupNow(ctx context.Context, tx pgx.Tx, deviceID int64, source string) error {
	q, err := ownerQueue(ctx, tx, `SELECT poller_id FROM core.device WHERE id = $1`, "device", deviceID)
	if err != nil {
		return err
	}
	q = "backup_" + strings.TrimPrefix(q, "poller_")
	if _, err := e.client.InsertTx(ctx, tx, BackupNowArgs{DeviceID: deviceID, Source: source}, &river.InsertOpts{Queue: q}); err != nil {
		return fmt.Errorf("jobs: enqueue backup: %w", err)
	}
	return nil
}

// EnqueueDiscovery queues a run of discovery scan scanID on the scan's poller.
func (e *Enqueuer) EnqueueDiscovery(ctx context.Context, tx pgx.Tx, scanID int64) error {
	q, err := ownerQueue(ctx, tx, `SELECT poller_id FROM core.discovery_scan WHERE id = $1`, "discovery scan", scanID)
	if err != nil {
		return err
	}
	if _, err := e.client.InsertTx(ctx, tx, DiscoveryScanArgs{ScanID: scanID}, &river.InsertOpts{Queue: q}); err != nil {
		return fmt.Errorf("jobs: enqueue discovery: %w", err)
	}
	return nil
}

/* ownerQueue returns the queue of the poller of object id, read by query in tx. */
func ownerQueue(ctx context.Context, tx pgx.Tx, query, what string, id int64) (string, error) {
	var pollerID string
	err := tx.QueryRow(ctx, query, id).Scan(&pollerID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("jobs: %s %d does not exist", what, id)
	}
	if err != nil {
		return "", fmt.Errorf("jobs: %w", err)
	}
	return Queue(pollerID)
}
