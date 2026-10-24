package poller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/beekamai/network-scheme/internal/backup"
	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/jobs"
	"github.com/beekamai/network-scheme/internal/ssh"
)

/*
Configuration backups. A backup fetches the running configuration over the
read-only SSH profile with the driver's allowlisted command, hashes the
driver-normalized text and, only when the hash differs from the last stored
one, stores a new version: the masked copy (readable by the api) and the
envelope-encrypted full copy (readable by nobody but the executor), both made
from the RAW fetched text and written together with the backup_state row in a
single transaction. The raw text is a secret: it is never logged, never part
of an error, and the byte copy handed to the sealer is wiped. (FetchConfig
returns a Go string, which cannot be wiped; it is dropped for the GC as soon
as the run ends.)
*/
const (
	defaultBackupInterval = 24 * time.Hour
	minBackupInterval     = time.Hour
	maxBackupInterval     = 30 * 24 * time.Hour
	backupTick            = 30 * time.Second /* how often the schedule looks for due backups */
	backupTimeout         = 5 * time.Minute  /* identification (SNMP) plus the fetch */
	backupParallel        = 4                /* scheduled backups running at once */
	retryBackupAfter      = time.Hour        /* after a failed scheduled backup, or the interval if shorter */
	backupSlotWait        = 30 * time.Second /* how long a job waits for a fetch slot before it records "busy" */
	backupStartGap        = 3 * time.Second  /* per backupParallel overdue devices when spreading first runs */
	backupSpreadMax       = 10 * time.Minute
	maxConfigBytes        = 4 << 20
)

/* Sources of a version (backups.config_version.source) a poller writes. */
const (
	sourceSchedule = "schedule"
	sourceEvent    = "event"
	sourceManual   = "manual"
	sourcePreSess  = "pre_session"
)

/* numIntervals counts the interval settings of a device: the poll classes and the backup interval, which has no poll class. */
const (
	numIntervals       = numClasses + 1
	ivBackup     class = numClasses
)

/* clampBackup turns a database interval (seconds) into a duration within the backup bounds. */
func clampBackup(secs int) time.Duration {
	return min(max(time.Duration(secs)*time.Second, minBackupInterval), maxBackupInterval)
}

/*
Fixed texts of backup_state.last_error. Device output never reaches the
database through them (the same discipline as the availability reasons).
*/
const (
	errNoBackupKey   = "configuration backups are not configured on the poller"
	errNeedsWrite    = "reading the configuration of this model needs a write account; not backed up before phase 4"
	errNoReader      = "the driver cannot read the configuration"
	errNoSSHProfile  = "no usable SSH read credential"
	errSSHFailed     = "SSH connection failed"
	errIdentify      = "device identification failed"
	errFetchFailed   = "configuration fetch failed"
	errTooLarge      = "configuration exceeds the 4 MiB limit"
	errSealFailed    = "encryption of the configuration failed"
	errStoreFailed   = "storing the configuration failed"
	errBackupTimeout = "configuration backup timed out"
	errBusy          = "the poller is busy with other backups; try again later"
)

/* errBackupSkipped: the poller-side gap skipped the run, nothing was fetched (not a success, not a failure). */
var errBackupSkipped = errors.New("poller: backup skipped, the device was backed up recently")

/* backupFail is a failed backup with its fixed state text; err is for debugging only and is never logged (it may carry device text). */
type backupFail struct {
	text string
	err  error
}

func (f *backupFail) Error() string { return f.text }
func (f *backupFail) Unwrap() error { return f.err }

func fail(text string, err error) error { return &backupFail{text: text, err: err} }

/*
backupDevice backs up one device; the device lock must be held. The outcome is
recorded in backup_state (last_ok_at, or last_error with a fixed text). It
returns the failure for the schedule's retry logic; a model that needs a
write account is not a failure (it is recorded and skipped).
*/
func (p *Poller) backupDevice(ctx context.Context, d device, cache *devCache, source string, jobID *int64) error {
	if p.backupPub == nil {
		p.setBackupError(ctx, d.ID, errNoBackupKey, false)
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, backupTimeout)
	defer cancel()
	err := p.doBackup(ctx, d, cache, source, jobID)
	if err == nil {
		return nil
	}
	text := errFetchFailed
	var f *backupFail
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		text = errBackupTimeout
	case errors.As(err, &f):
		text = f.text
	}
	p.setBackupError(context.WithoutCancel(ctx), d.ID, text, false)
	p.log.Info("configuration backup failed", slog.Int64("device_id", d.ID), slog.String("reason", text))
	return err
}

func (p *Poller) doBackup(ctx context.Context, d device, cache *devCache, source string, jobID *int64) error {
	p.refresh(d, cache)
	drv, err := p.backupDriver(ctx, d, cache)
	if err != nil {
		return fail(errIdentify, err)
	}
	if drv.ConfigNeedsWrite() {
		p.setBackupError(ctx, d.ID, errNeedsWrite, true)
		return nil
	}
	raw, err := p.fetchRaw(ctx, d, cache, drv)
	if err != nil {
		return err
	}
	if len(raw) > maxConfigBytes {
		p.backupOversize.Add(1)
		return fail(errTooLarge, nil)
	}
	sum := sha256.Sum256([]byte(drv.NormalizeConfig(raw))) /* the normalized text is for the hash only */
	last, err := p.lastBackupHash(ctx, d.ID)
	if err != nil {
		return fail(errStoreFailed, err)
	}
	if last != nil && *last == sum {
		return p.touchBackup(ctx, d.ID)
	}
	masked := strings.ToValidUTF8(drv.MaskSecrets(raw), "?")
	if len(masked) > maxConfigBytes {
		p.backupOversize.Add(1)
		return fail(errTooLarge, nil)
	}
	ct, dekCT, err := backup.Seal(p.backupPub, []byte(raw), backup.AAD(d.ID, hex.EncodeToString(sum[:])))
	if err != nil {
		return fail(errSealFailed, err)
	}
	/*
		Drift: a change with an earlier version on record, unless it was taken
		right before a change session of the panel (source pre_session, which
		phase 3 never produces: every change is drift). The first version of a
		device is the baseline, not drift.
	*/
	drift := last != nil && source != sourcePreSess
	if err := p.storeVersion(ctx, d.ID, source, sum, len(raw), masked, ct, dekCT, drift, jobID); err != nil {
		return fail(errStoreFailed, err)
	}
	p.backupVersions.Add(1)
	return nil
}

/* sshFetch reads the running configuration over the read-only SSH profile, with the driver's allowlisted command only. */
func (p *Poller) sshFetch(ctx context.Context, d device, cache *devCache, drv drivers.Driver) (string, error) {
	if drv.Dialect().ExecPrompt == nil {
		return "", fail(errNoReader, nil)
	}
	c, err := p.credential(ctx, devices.Owner{Kind: devices.OwnerDevice, ID: d.ID}, cache, creds.KindSSHRead)
	if err != nil {
		return "", fail(errNoSSHProfile, err)
	}
	runner, err := ssh.Dial(ctx, netip.AddrPortFrom(d.Addr.Addr(), sshPort), d.ID, c, p.hostKeys, drv.Dialect())
	if err != nil {
		return "", fail(errSSHFailed, err)
	}
	defer func() { _ = runner.Close() }()
	raw, err := drv.FetchConfig(ctx, runner)
	if err != nil {
		if errors.Is(err, drivers.ErrNotSupported) {
			return "", fail(errNoReader, nil)
		}
		return "", fail(errFetchFailed, err)
	}
	return raw, nil
}

/* backupDriver returns the device's driver, identifying the device over SNMP when none is cached yet. */
func (p *Poller) backupDriver(ctx context.Context, d device, cache *devCache) (drivers.Driver, error) {
	if cache.drv != nil {
		return cache.drv, nil
	}
	r, closer, err := p.session(ctx, d, cache)
	if err != nil {
		return nil, err
	}
	defer func() { _ = closer.Close() }()
	return p.driver(ctx, d, cache, r)
}

/* lastBackupHash is the hash of the newest stored version: backup_state first, then the history; nil when there is none. */
func (p *Poller) lastBackupHash(ctx context.Context, id int64) (*[32]byte, error) {
	var b []byte
	err := p.pool.QueryRow(ctx, `
		SELECT coalesce((SELECT last_sha256 FROM backups.backup_state WHERE device_id = $1),
			(SELECT sha256 FROM backups.config_version WHERE device_id = $1 ORDER BY taken_at DESC, id DESC LIMIT 1))`, id).Scan(&b)
	if err != nil {
		return nil, err
	}
	if len(b) != sha256.Size {
		return nil, nil
	}
	var h [32]byte
	copy(h[:], b)
	return &h, nil
}

/* touchBackup records a successful backup that found nothing new. */
func (p *Poller) touchBackup(ctx context.Context, id int64) error {
	if _, err := p.pool.Exec(ctx, `
		INSERT INTO backups.backup_state (device_id, last_ok_at) VALUES ($1, now())
		ON CONFLICT (device_id) DO UPDATE SET last_ok_at = now(), last_error = NULL, needs_write = false`, id); err != nil {
		return fail(errStoreFailed, err)
	}
	return nil
}

/* storeVersion writes the version (masked copy and ciphertext) and the state in one transaction. */
func (p *Poller) storeVersion(ctx context.Context, id int64, source string, sum [32]byte, size int, masked string, ct, dekCT []byte, drift bool, jobID *int64) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO backups.config_version (device_id, source, sha256, size, masked, full_ct, full_dek_ct, drift, taken_by_job)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, id, source, sum[:], size, masked, ct, dekCT, drift, jobID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO backups.backup_state (device_id, last_ok_at, last_sha256) VALUES ($1, now(), $2)
			ON CONFLICT (device_id) DO UPDATE SET last_ok_at = now(), last_error = NULL, last_sha256 = $2, needs_write = false`, id, sum[:])
		return err
	})
}

/* setBackupError records a fixed failure text (and the needs_write flag); a deleted device is ignored. */
func (p *Poller) setBackupError(ctx context.Context, id int64, text string, needsWrite bool) {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO backups.backup_state (device_id, last_error, needs_write) VALUES ($1, $2, $3)
		ON CONFLICT (device_id) DO UPDATE SET last_error = $2, needs_write = $3`, id, text, needsWrite)
	if err != nil && ctx.Err() == nil {
		p.log.Warn("recording the backup state failed", slog.Int64("device_id", id), slog.String("err", err.Error()))
	}
}

/* backupSlot is when a device's next scheduled backup is due, and the interval it was planned with. */
type backupSlot struct {
	next  time.Time
	every time.Duration
}

/*
backupSpread is the window over which n devices that are overdue (or have no
backup yet) are spread: backupStartGap per backupParallel devices, at most
backupSpreadMax, so a restart or a new fleet does not open all sessions at once
and a new device still gets its baseline within a few seconds.
*/
func backupSpread(n int) time.Duration {
	return min(time.Duration(n)*backupStartGap/backupParallel, backupSpreadMax)
}

/*
seedBackupSlots plans the first run of devs. A device with a recorded
last_ok_at keeps its place (last_ok_at + interval), so a restart postpones
nothing; devices overdue or never backed up start at a random point of
backupSpread(overdue count), never later than their own interval.
*/
func (p *Poller) seedBackupSlots(ctx context.Context, devs []device, now time.Time) map[int64]backupSlot {
	ids := make([]int64, len(devs))
	for i, d := range devs {
		ids[i] = d.ID
	}
	last := map[int64]time.Time{}
	rows, err := p.pool.Query(ctx, `SELECT device_id, last_ok_at FROM backups.backup_state WHERE device_id = ANY($1) AND last_ok_at IS NOT NULL`, ids)
	if err == nil {
		var id int64
		var at time.Time
		_, err = pgx.ForEachRow(rows, []any{&id, &at}, func() error { last[id] = at; return nil })
	}
	if err != nil && ctx.Err() == nil {
		p.log.Warn("reading the backup state failed; scheduling as if none existed", slog.String("err", err.Error()))
	}
	out := make(map[int64]backupSlot, len(devs))
	var overdue []device
	for _, d := range devs {
		if at, ok := last[d.ID]; ok {
			if at.After(now) {
				at = now
			}
			if next := at.Add(d.Backup); next.After(now) {
				out[d.ID] = backupSlot{next: next, every: d.Backup}
				continue
			}
		}
		overdue = append(overdue, d)
	}
	spread := backupSpread(len(overdue))
	for _, d := range overdue {
		out[d.ID] = backupSlot{next: now.Add(jitter(min(spread, d.Backup))), every: d.Backup}
	}
	return out
}

/*
backupLoop runs the scheduled backups. First runs come from seedBackupSlots;
later ones one interval after the previous finished. A failed backup is retried
after an hour (or the interval, if shorter). Fetches share the poller's
backupParallel slots with backup_now jobs.
*/
func (p *Poller) backupLoop(ctx context.Context) {
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		slots = map[int64]backupSlot{}
		busy  = map[int64]bool{}
	)
	defer wg.Wait()
	t := time.NewTicker(p.backupTick)
	defer t.Stop()
	for {
		now := p.now()
		devs := p.sched.snapshot()
		mu.Lock()
		seen := make(map[int64]bool, len(devs))
		var fresh, due []device
		for _, d := range devs {
			seen[d.ID] = true
			s, ok := slots[d.ID]
			switch {
			case !ok || s.every != d.Backup:
				fresh = append(fresh, d)
			case !s.next.After(now) && !busy[d.ID]:
				busy[d.ID] = true
				due = append(due, d)
			}
		}
		for id := range slots {
			if !seen[id] {
				delete(slots, id)
			}
		}
		mu.Unlock()
		if len(fresh) > 0 {
			seeds := p.seedBackupSlots(ctx, fresh, now)
			mu.Lock()
			for id, s := range seeds {
				slots[id] = s
			}
			mu.Unlock()
		}
		p.pruneBackupAttempts(now)
		for _, d := range due {
			wg.Go(func() {
				err := p.backupGuarded(ctx, d.ID, sourceSchedule, nil)
				after := p.backupRetryDelay(d.ID, err, d.Backup)
				mu.Lock()
				delete(busy, d.ID)
				if _, ok := slots[d.ID]; ok {
					slots[d.ID] = backupSlot{next: p.now().Add(after), every: d.Backup}
				}
				mu.Unlock()
			})
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

/*
backupGuarded is how both the schedule and backup_now back a device up: it
takes one of the poller's backupParallel fetch slots, then the device lock, and
skips the device when it was backed up (or attempted) less than backupGap ago.
The gap is enforced here because the api, which enqueues the jobs, is not
trusted to keep it.
*/
func (p *Poller) backupGuarded(ctx context.Context, id int64, source string, jobID *int64) error {
	/*
		Jobs (event, manual) have priority: scheduled runs may hold at most
		backupParallel-1 of the slots, so one is always left for a job, and a job
		waits for it only backupSlotWait before it gives up as busy.
	*/
	wait := ctx
	if source == sourceSchedule {
		select {
		case p.schedSem <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		defer func() { <-p.schedSem }()
	} else {
		var cancel context.CancelFunc
		wait, cancel = context.WithTimeout(ctx, p.backupSlotWait)
		defer cancel()
	}
	select {
	case p.backupSem <- struct{}{}:
	case <-wait.Done():
		if ctx.Err() != nil {
			return ctx.Err()
		}
		p.setBackupError(context.WithoutCancel(ctx), id, errBusy, false)
		return fail(errBusy, nil)
	}
	defer func() { <-p.backupSem }()
	return p.sched.runNow(ctx, id, func(d device, cache *devCache) error {
		if p.backupTooSoon(ctx, id) {
			return errBackupSkipped
		}
		return p.backupDevice(ctx, d, cache, source, jobID)
	})
}

/*
backupRetryDelay is how long after a scheduled run of device id the next one
is due: a full interval only after a real success; the rest of the gap after a
run the gap skipped (nothing was fetched); an hour (or the interval, if
shorter) after a failure.
*/
func (p *Poller) backupRetryDelay(id int64, err error, every time.Duration) time.Duration {
	switch {
	case err == nil:
		return every
	case errors.Is(err, errBackupSkipped):
		p.backupMu.Lock()
		defer p.backupMu.Unlock()
		rem := p.backupGap
		if at, ok := p.backupAt[id]; ok {
			rem = p.backupGap - p.now().Sub(at)
		}
		return min(max(rem, time.Second), every)
	default:
		return min(every, retryBackupAfter)
	}
}

/* backupTooSoon reports whether device id was attempted (in memory) or backed up successfully (database clock) within backupGap; otherwise it records the attempt. */
func (p *Poller) backupTooSoon(ctx context.Context, id int64) bool {
	now := p.now()
	p.backupMu.Lock()
	defer p.backupMu.Unlock()
	if at, ok := p.backupAt[id]; ok && now.Sub(at) < p.backupGap {
		return true
	}
	var recent bool
	err := p.pool.QueryRow(ctx, `SELECT last_ok_at > now() - make_interval(secs => $2) FROM backups.backup_state WHERE device_id = $1 AND last_ok_at IS NOT NULL`,
		id, p.backupGap.Seconds()).Scan(&recent)
	if err == nil && recent {
		return true
	}
	p.backupAt[id] = now /* only a run that goes on to fetch counts as an attempt */
	return false
}

func (p *Poller) pruneBackupAttempts(now time.Time) {
	p.backupMu.Lock()
	defer p.backupMu.Unlock()
	for id, at := range p.backupAt {
		if now.Sub(at) >= p.backupGap {
			delete(p.backupAt, id)
		}
	}
}

/*
backupNowWorker backs up a device on request. Jobs are inserted by the api,
which is not trusted: a device not assigned to this poller is cancelled without
contact. It never retries (the schedule follows anyway).
*/
type backupNowWorker struct {
	river.WorkerDefaults[jobs.BackupNowArgs]
	p *Poller
}

// Timeout implements river.Worker.
func (*backupNowWorker) Timeout(*river.Job[jobs.BackupNowArgs]) time.Duration {
	return backupTimeout + time.Minute
}

// Work implements river.Worker.
func (w *backupNowWorker) Work(ctx context.Context, job *river.Job[jobs.BackupNowArgs]) error {
	id := job.Args.DeviceID
	source := sourceEvent
	if job.Args.Source == sourceManual {
		source = sourceManual
	}
	jid := job.ID
	arrived := w.p.now()
	run := func() error { return w.p.backupGuarded(ctx, id, source, &jid) }
	err := run()
	if errors.Is(err, errBackupSkipped) {
		return nil /* backed up moments ago: nothing to do */
	}
	if errors.Is(err, errNotMine) {
		/* Possibly created a moment ago: reread once before refusing. */
		wait, rerr := w.p.reloadForJob(ctx, arrived, snoozed(job.Metadata))
		if rerr != nil {
			return rerr
		}
		if wait > 0 {
			return river.JobSnooze(wait + time.Second)
		}
		err = run()
	}
	if errors.Is(err, errNotMine) {
		w.p.unknownJobs.Add(1)
		w.p.log.Debug("backup now for a device not assigned here", slog.Int64("device_id", id))
		return river.JobCancel(err)
	}
	if err != nil && ctx.Err() != nil {
		return fmt.Errorf("poller: backup interrupted: %w", ctx.Err())
	}
	return nil /* the outcome is in backup_state */
}
