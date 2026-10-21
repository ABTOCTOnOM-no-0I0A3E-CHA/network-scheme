package poller

import (
	"context"
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
	poll := func(d device, cache *devCache) error { return w.p.pollAll(ctx, d, cache) }
	err := w.p.sched.runNow(ctx, id, poll)
	if errors.Is(err, errNotMine) {
		/* Possibly created a moment ago: reread once before refusing. */
		if rerr := w.p.reload(ctx); rerr != nil {
			return rerr
		}
		err = w.p.sched.runNow(ctx, id, poll)
	}
	if errors.Is(err, errNotMine) {
		return river.JobCancel(err)
	}
	if err != nil {
		/* The outcome is in the device state; a poll is not retried, the schedule follows anyway. */
		w.p.log.Info("poll now finished with errors", slog.Int64("device_id", id), slog.String("err", err.Error()))
	}
	return nil
}
