package poller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/beekamai/network-scheme/internal/jobs"
	"github.com/beekamai/network-scheme/internal/store"
)

const (
	pollNowWorkers = 8
	/* pollNowTimeout covers a full poll: availability, collect (2 min) and inventory (4 min). */
	pollNowTimeout = 10 * time.Minute
	/* jobReloadGap is the least time between device list rereads caused by jobs. */
	jobReloadGap = 5 * time.Second
)

/* newRiver returns the job client working this poller's queue; scan runs it starts last until life ends. */
func (p *Poller) newRiver(life context.Context) (*river.Client[pgx.Tx], error) {
	q, err := jobs.Queue(p.cfg.PollerID)
	if err != nil {
		return nil, err
	}
	w := river.NewWorkers()
	river.AddWorker(w, &pollNowWorker{p: p})
	river.AddWorker(w, &discoveryWorker{p: p, life: life})
	river.AddWorker(w, &backupNowWorker{p: p})
	c, err := river.NewClient(riverpgxv5.New(p.pool), &river.Config{
		Schema:  store.JobsSchema,
		Queues:  map[string]river.QueueConfig{q: {MaxWorkers: pollNowWorkers}},
		Workers: w,
		Logger:  p.log,
	})
	if err != nil {
		return nil, fmt.Errorf("poller: job client: %w", err)
	}
	return c, nil
}

/*
reloadForJob rereads the device list for a job naming an unknown device. The
api can enqueue such jobs at will, so rereads are single-flight and at most
one runs per jobReloadGap. A job that arrived before the last reread started
relies on it. One that arrived later while the gap is still running gets the
time to wait (the worker snoozes the job instead of holding a slot); on its
retry (retry set) the reread started since then covers it, and it is cancelled
if the device is still unknown.
*/
func (p *Poller) reloadForJob(ctx context.Context, arrived time.Time, retry bool) (time.Duration, error) {
	p.jobReload.Lock()
	defer p.jobReload.Unlock()
	if !p.lastJobReload.IsZero() {
		if !p.lastJobReload.Before(arrived) {
			return 0, nil
		}
		if wait := jobReloadGap - p.now().Sub(p.lastJobReload); wait > 0 {
			if retry {
				return 0, nil
			}
			return wait, nil
		}
	}
	start := p.now()
	if err := p.reload(ctx); err != nil {
		return 0, err
	}
	p.lastJobReload = start
	p.jobReloads.Add(1)
	return 0, nil
}

/* snoozed reports whether River has already snoozed the job (metadata maintained by River, not trusted further); unreadable metadata counts as snoozed, so a job is never snoozed forever. */
func snoozed(metadata []byte) bool {
	var m struct {
		Snoozes int `json:"snoozes"`
	}
	return json.Unmarshal(metadata, &m) != nil || m.Snoozes > 0
}

/*
pollNowWorker runs an immediate full poll. It shares the device lock with the
schedule, so it waits for a poll in progress instead of overlapping it. Jobs
are inserted by the api, which is not trusted: a device not assigned to this
poller is cancelled without contact.
*/
type pollNowWorker struct {
	river.WorkerDefaults[jobs.PollNowArgs]
	p *Poller
}

// Timeout implements river.Worker.
func (*pollNowWorker) Timeout(*river.Job[jobs.PollNowArgs]) time.Duration { return pollNowTimeout }

// Work implements river.Worker.
func (w *pollNowWorker) Work(ctx context.Context, job *river.Job[jobs.PollNowArgs]) error {
	id := job.Args.DeviceID
	arrived := w.p.now()
	poll := func(d device, cache *devCache) error { return w.p.pollAll(ctx, d, cache) }
	err := w.p.sched.runNow(ctx, id, poll)
	if errors.Is(err, errNotMine) {
		/* Possibly created a moment ago: reread once before refusing. */
		wait, rerr := w.p.reloadForJob(ctx, arrived, snoozed(job.Metadata))
		if rerr != nil {
			return rerr
		}
		if wait > 0 {
			return river.JobSnooze(wait + time.Second)
		}
		err = w.p.sched.runNow(ctx, id, poll)
	}
	if errors.Is(err, errNotMine) {
		/* Debug only: the api can enqueue these at will. */
		w.p.unknownJobs.Add(1)
		w.p.log.Debug("poll now for a device not assigned here", slog.Int64("device_id", id))
		return river.JobCancel(err)
	}
	if err != nil {
		/* The outcome is in the device state; a poll is not retried, the schedule follows anyway. */
		w.p.log.Info("poll now finished with errors", slog.Int64("device_id", id), slog.String("err", err.Error()))
	}
	return nil
}
