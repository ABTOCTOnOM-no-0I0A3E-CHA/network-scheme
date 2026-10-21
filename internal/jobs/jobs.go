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
)

// DiscoveryQueue is the queue of discovery scans (scans are not assigned to a poller).
const DiscoveryQueue = "discovery"

/* pollerIDRe keeps "poller_" + id a valid River queue name of at most 64 characters. */
var pollerIDRe = regexp.MustCompile(`^[a-z0-9]+(?:[_-][a-z0-9]+)*$`)

const maxPollerID = 64 - len("poller_")

// ValidPollerID reports whether id can name a poller (and its queue).
func ValidPollerID(id string) bool { return len(id) <= maxPollerID && pollerIDRe.MatchString(id) }

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

// DiscoveryScanArgs asks for a run of discovery scan ScanID.
type DiscoveryScanArgs struct {
	ScanID int64 `json:"scan_id"`
}

// Kind implements river.JobArgs.
func (DiscoveryScanArgs) Kind() string { return KindDiscoveryScan }

// InsertOpts implements river.JobArgsWithInsertOpts.
func (DiscoveryScanArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: DiscoveryQueue, MaxAttempts: 1, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: liveStates}}
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
	var pollerID string
	err := tx.QueryRow(ctx, `SELECT poller_id FROM core.device WHERE id = $1`, deviceID).Scan(&pollerID)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("jobs: device %d does not exist", deviceID)
	}
	if err != nil {
		return fmt.Errorf("jobs: %w", err)
	}
	q, err := Queue(pollerID)
	if err != nil {
		return err
	}
	if _, err := e.client.InsertTx(ctx, tx, PollNowArgs{DeviceID: deviceID}, &river.InsertOpts{Queue: q}); err != nil {
		return fmt.Errorf("jobs: enqueue poll: %w", err)
	}
	return nil
}

// EnqueueDiscovery queues a run of discovery scan scanID.
func (e *Enqueuer) EnqueueDiscovery(ctx context.Context, tx pgx.Tx, scanID int64) error {
	if _, err := e.client.InsertTx(ctx, tx, DiscoveryScanArgs{ScanID: scanID}, nil); err != nil {
		return fmt.Errorf("jobs: enqueue discovery: %w", err)
	}
	return nil
}
