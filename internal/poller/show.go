package poller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/drivers/showspec"
	"github.com/beekamai/network-scheme/internal/jobs"
	"github.com/beekamai/network-scheme/internal/ssh"
)

/*
On-demand show commands (show_now). The job names a backups.show_result row
and nothing else; the api that wrote the row is not trusted. The poller reads
the key and arguments from the row, checks the key against the driver's own
table, the arguments against their types and against this device's inventory
(an interface must be one the device reported), builds the command only with
the driver's ShowCommand (an exact allowlisted command) and sends it over the
read-only SSH profile. The output is untrusted text: invalid UTF-8, control
and format characters are removed, and at most maxShowOutput bytes are kept.
Only the result columns of the row are updated; every failure is a fixed text.
*/
const (
	maxShowOutput  = 1 << 20          /* bytes of output kept */
	showTimeout    = 90 * time.Second /* connection plus command */
	showWorkers    = 4                /* show commands running at once on this poller */
	showCleanEvery = 5 * time.Minute  /* how often expired results are deleted */
	showGap        = 6 * time.Second  /* least time between two show commands that reach a device, whoever asks */
	showInterruptT = 5 * time.Second  /* budget for recording an interrupted run */
)

/* Fixed texts stored in show_result.output of a failed command. */
const (
	errShowRefused     = "the command is not available for this device"
	errShowDeviceBusy  = "another command is already running on this device"
	errShowTooLarge    = "the output exceeds the 4 MiB limit"
	errShowTimedOut    = "the command timed out"
	errShowTooSoon     = "too many commands for this device; try again in a few seconds"
	errShowInterrupted = "the command was interrupted"
)

/* showFailed is a failed command with its fixed text; err is for debugging only and is never logged or stored. */
type showFailed struct {
	text string
	err  error
}

func (f *showFailed) Error() string { return f.text }
func (f *showFailed) Unwrap() error { return f.err }

/*
showRow is the part of a show_result row the poller acts on. A forged row can
hold anything, so nothing in it is used before runShow has checked it.
*/
type showRow struct {
	id     int64
	device int64
	key    string
	args   json.RawMessage
	status string
}

/* loadShow reads a result row that has not expired; found is false when there is none. */
func (p *Poller) loadShow(ctx context.Context, id int64) (r showRow, found bool, err error) {
	r.id = id
	err = p.pool.QueryRow(ctx, `SELECT device_id, command_key, args, status FROM backups.show_result WHERE id = $1 AND expires_at > now()`, id).
		Scan(&r.device, &r.key, &r.args, &r.status)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, false, nil
	}
	return r, err == nil, err
}

/* claimShow moves a queued row to running; false when it was not queued (a repeated or forged job). */
func (p *Poller) claimShow(ctx context.Context, id int64) (bool, error) {
	tag, err := p.pool.Exec(ctx, `UPDATE backups.show_result SET status = 'running' WHERE id = $1 AND status = 'queued' AND expires_at > now()`, id)
	return tag.RowsAffected() == 1, err
}

/* finishShow stores the outcome in the result columns of an open row. */
func (p *Poller) finishShow(ctx context.Context, id int64, status, output string, truncated bool) error {
	_, err := p.pool.Exec(ctx, `UPDATE backups.show_result SET status = $2, output = $3, truncated = $4, finished_at = now()
WHERE id = $1 AND status IN ('queued', 'running')`, id, status, output, truncated)
	return err
}

/*
runShow executes the show_now job of row id. Rows that are gone, expired or
not queued are ignored. errNotMine is returned (row untouched) when the device
is not assigned to this poller, so the worker can reread the device list.
*/
func (p *Poller) runShow(ctx context.Context, id int64) error {
	err := p.runShowRow(ctx, id)
	if err != nil && !errors.Is(err, errNotMine) {
		/*
			Best effort: a run that was interrupted (job context ended while waiting
			for the device lock, or a failure mid-flight) must not leave its row
			queued or running until it expires. A restart in the middle of a run
			still does; the row then expires on its own (TTL).
		*/
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), showInterruptT)
		defer cancel()
		_ = p.finishShow(fctx, id, "failed", errShowInterrupted, false)
	}
	return err
}

/* showTooSoon reports whether a command reached device id less than showGap ago; otherwise it records this one. */
func (p *Poller) showTooSoon(id int64) bool {
	now := p.now()
	p.showMu.Lock()
	defer p.showMu.Unlock()
	for dev, at := range p.showAt {
		if now.Sub(at) >= p.showEvery {
			delete(p.showAt, dev)
		}
	}
	if _, recent := p.showAt[id]; recent {
		return true
	}
	p.showAt[id] = now
	return false
}

func (p *Poller) runShowRow(ctx context.Context, id int64) error {
	row, found, err := p.loadShow(ctx, id)
	if err != nil || !found || row.status != "queued" {
		return err
	}
	p.showMu.Lock()
	if p.showBusy[row.device] {
		p.showMu.Unlock()
		return p.finishShow(ctx, id, "failed", errShowDeviceBusy, false)
	}
	p.showBusy[row.device] = true
	p.showMu.Unlock()
	defer func() {
		p.showMu.Lock()
		delete(p.showBusy, row.device)
		p.showMu.Unlock()
	}()
	return p.sched.runNow(ctx, row.device, func(d device, cache *devCache) error {
		/*
			The api is not trusted to pace requests: sequential rows would each cost
			an SSH login and hold the device lock, starving its polls. A row inside
			the gap is failed without contact.
		*/
		if p.showTooSoon(d.ID) {
			return p.finishShow(context.WithoutCancel(ctx), id, "failed", errShowTooSoon, false)
		}
		if ok, err := p.claimShow(ctx, id); err != nil || !ok {
			return err
		}
		cctx, cancel := context.WithTimeout(ctx, showTimeout)
		defer cancel()
		out, truncated, err := p.execShow(cctx, d, cache, row)
		fctx := context.WithoutCancel(ctx)
		if err != nil {
			text := errShowRefused
			var f *showFailed
			switch {
			case errors.Is(err, context.DeadlineExceeded):
				text = errShowTimedOut
			case errors.As(err, &f):
				text = f.text
			}
			p.log.Info("show command failed", slog.Int64("device_id", d.ID), slog.String("reason", text))
			return p.finishShow(fctx, id, "failed", text, false)
		}
		return p.finishShow(fctx, id, "done", out, truncated)
	})
}

/* execShow validates the row again and runs the command; the device lock is held. */
func (p *Poller) execShow(ctx context.Context, d device, cache *devCache, row showRow) (string, bool, error) {
	p.refresh(d, cache)
	drv, err := p.backupDriver(ctx, d, cache)
	if err != nil {
		return "", false, &showFailed{text: errIdentify, err: err}
	}
	cmd, err := p.resolveShow(ctx, d.ID, drv, row)
	if err != nil {
		return "", false, err
	}
	raw, err := p.runShowCmd(ctx, d, cache, drv, cmd)
	if err != nil {
		return "", false, err
	}
	out, truncated := cleanShowOutput(raw)
	return out, truncated, nil
}

/*
resolveShow turns a row into the exact allowlisted command: the key must be one
of the driver's show commands, the arguments exactly its typed arguments, every
interface one of this device's inventory, and the driver's ShowCommand has the
last word.
*/
func (p *Poller) resolveShow(ctx context.Context, deviceID int64, drv drivers.Driver, row showRow) (ssh.ShowCommand, error) {
	refused := func(err error) (ssh.ShowCommand, error) {
		return ssh.ShowCommand{}, &showFailed{text: errShowRefused, err: err}
	}
	var spec showspec.Spec
	found := false
	for _, s := range drv.ShowCommands() {
		if s.Key == row.key {
			spec, found = s, true
			break
		}
	}
	if !found {
		return refused(nil)
	}
	vals, _, err := showspec.ParseArgs(spec, row.args)
	if err != nil {
		return refused(err)
	}
	for i, k := range spec.Args {
		if k != showspec.InterfaceName {
			continue
		}
		var member bool
		if err := p.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM inventory.interface WHERE device_id = $1 AND name = $2)`, deviceID, vals[i]).Scan(&member); err != nil {
			return ssh.ShowCommand{}, fmt.Errorf("poller: check interface: %w", err)
		}
		if !member {
			return refused(nil)
		}
	}
	cmd, err := drv.ShowCommand(spec.Key, vals)
	if err != nil {
		return refused(err)
	}
	return cmd, nil
}

/* sshShow sends cmd over the read-only SSH profile; the dialect allowlist refuses anything else. */
func (p *Poller) sshShow(ctx context.Context, d device, cache *devCache, drv drivers.Driver, cmd ssh.ShowCommand) (string, error) {
	if drv.Dialect().ExecPrompt == nil {
		return "", &showFailed{text: errNoReader}
	}
	c, err := p.credential(ctx, devices.Owner{Kind: devices.OwnerDevice, ID: d.ID}, cache, creds.KindSSHRead)
	if err != nil {
		return "", &showFailed{text: errNoSSHProfile, err: err}
	}
	runner, err := ssh.Dial(ctx, netip.AddrPortFrom(d.Addr.Addr(), sshPort), d.ID, c, p.hostKeys, drv.Dialect())
	if err != nil {
		return "", &showFailed{text: errSSHFailed, err: err}
	}
	defer func() { _ = runner.Close() }()
	out, err := runner.Run(ctx, cmd)
	switch {
	case err == nil:
		return out, nil
	case errors.Is(err, ssh.ErrOutputTooLarge):
		return "", &showFailed{text: errShowTooLarge, err: err}
	case errors.Is(err, ssh.ErrTimeout):
		return "", &showFailed{text: errShowTimedOut, err: err}
	}
	return "", &showFailed{text: errFetchFailed, err: err}
}

/*
cleanShowOutput makes device output safe text: invalid UTF-8 becomes U+FFFD;
control characters except newline and tab, DEL, and format characters
(bidi overrides among them) are dropped. At most maxShowOutput bytes are kept,
cut on a character boundary; truncated reports the cut.
*/
func cleanShowOutput(raw string) (string, bool) {
	var b strings.Builder
	b.Grow(min(len(raw), maxShowOutput))
	truncated := false
	for i := 0; i < len(raw); {
		r, size := utf8.DecodeRuneInString(raw[i:])
		i += size
		switch {
		case r == utf8.RuneError && size == 1:
			r = utf8.RuneError
		case r == '\n' || r == '\t':
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			continue
		}
		if b.Len()+utf8.RuneLen(r) > maxShowOutput {
			truncated = true
			break
		}
		b.WriteRune(r)
	}
	return b.String(), truncated
}

/* showNowWorker runs one on-demand show command; it never retries. */
type showNowWorker struct {
	river.WorkerDefaults[jobs.ShowNowArgs]
	p *Poller
}

// Timeout implements river.Worker.
func (*showNowWorker) Timeout(*river.Job[jobs.ShowNowArgs]) time.Duration {
	return showTimeout + time.Minute
}

// Work implements river.Worker.
func (w *showNowWorker) Work(ctx context.Context, job *river.Job[jobs.ShowNowArgs]) error {
	id := job.Args.ResultID
	arrived := w.p.now()
	err := w.p.runShow(ctx, id)
	if errors.Is(err, errNotMine) {
		/* Possibly created a moment ago: reread once before refusing. */
		wait, rerr := w.p.reloadForJob(ctx, arrived, snoozed(job.Metadata))
		if rerr != nil {
			return rerr
		}
		if wait > 0 {
			return river.JobSnooze(wait + time.Second)
		}
		err = w.p.runShow(ctx, id)
	}
	if errors.Is(err, errNotMine) {
		w.p.unknownJobs.Add(1)
		w.p.log.Debug("show now for a device not assigned here", slog.Int64("result_id", id))
		/* The row is left alone: the poller that owns the device may be running it. */
		return river.JobCancel(err)
	}
	if err != nil && ctx.Err() != nil {
		return fmt.Errorf("poller: show interrupted: %w", ctx.Err())
	}
	if err != nil {
		w.p.log.Warn("show now failed", slog.Int64("result_id", id), slog.String("err", err.Error()))
	}
	return nil /* the outcome is in the row */
}

/* deleteExpiredShow deletes the results past their expiry. */
func (p *Poller) deleteExpiredShow(ctx context.Context) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM backups.show_result WHERE expires_at <= now()`)
	return err
}

/* cleanShow deletes expired results now and every showCleanEvery until ctx ends. */
func (p *Poller) cleanShow(ctx context.Context) {
	t := time.NewTicker(showCleanEvery)
	defer t.Stop()
	for {
		if err := p.deleteExpiredShow(ctx); err != nil && ctx.Err() == nil {
			p.log.Warn("deleting expired show results failed", slog.String("err", err.Error()))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
