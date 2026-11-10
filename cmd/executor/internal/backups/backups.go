/*
Package backups is the executor's backup scheduler (ruling Q4/R1, plan
4b.8): it backs up the configuration of the write devices whose read needs
a write account, for which the poller's read account is not enough.

What it backs up and how comes only from the executor itself: the device set
is the write_device rows with backup_via_executor of the verified registry
(freeze.Guard.View), the connection is a ReadOnly transport (the read
dialect of the line, nothing else reaches the device), the command is the
read driver's allowlisted configuration read, the masked copy is made by the
read driver's masker and the full copy is sealed to the backup domain
(internal/backup). A version is stored only when the normalized SHA-256
differs from the newest version the executor itself stored: rows of the
sources 'executor', 'pre_session' and 'post_session', which only the
executor's role can insert (trigger config_version_check_source) into an
append-only table, or when another source's version is newer than it (the
newest version must be the device's configuration; this only ever adds a
version). Nothing in backup_state, in jobs or in execpub (but the
executor's own backup_taken, for where a failure is recorded) decides
anything here; a disabled policy deletes every backup_taken stamp.

Nothing outside triggers a backup: Run is driven by its own clock only (once
a day per device with jitter), and BeforeSession is called in-process by a
change session (4c). Every connection to a device holds its Lease of Locks,
so the executor never has two SSH connections to one device, and a device
held by a session is skipped until the session releases it.

After every success the executor stamps execpub.backup_taken, which tells
the poller to stop fetching the device (internal/poller executorBacksUp).
*/
package backups

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/curve25519"

	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/strategy"
	"github.com/beekamai/network-scheme/cmd/executor/internal/transport"
	"github.com/beekamai/network-scheme/internal/backup"
	"github.com/beekamai/network-scheme/internal/config"
	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/drivers/eltexesr"
	"github.com/beekamai/network-scheme/internal/drivers/eltexmes"
	"github.com/beekamai/network-scheme/internal/ssh"
)

/* Source is the config_version.source of the scheduler's versions, SourcePreSession of a session's snapshot (both executor-only by trigger). */
const (
	Source           = "executor"
	SourcePreSession = "pre_session"
)

/* ErrFailed is the fixed backup_state.last_error of a failed executor backup (the UI maps it). */
const ErrFailed = "the executor could not back up the configuration"

/* PublicKey reads the backup-domain private key file and returns its public key; the private key is wiped (the scheduler only seals). */
func PublicKey(path string) (*[32]byte, error) {
	priv, err := config.ReadKeyFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(priv[:])
	p, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("backups: backup key %s: %w", path, err)
	}
	return (*[32]byte)(p), nil
}

/* Pace (variables for the tests). */
var (
	every       = 24 * time.Hour   /* one backup per device a day ... */
	spread      = time.Hour        /* ... plus up to this much jitter */
	firstSpread = 10 * time.Minute /* a device seen for the first time (or after a restart) starts within this */
	retryAfter  = time.Hour        /* after a failure */
	tick        = time.Minute      /* how often due devices are looked for */
	timeout     = 5 * time.Minute  /* one backup: credential, dial, read, store */
)

var (
	errNotEligible = errors.New("backups: the device is not backed up by the executor")
	errLease       = errors.New("backups: the lease is not held for the device")
	errDisabled    = errors.New("backups: the executor is disabled by its policy")
)

/* Locks are the executor's per-device connection locks: whoever holds a device's Lease is its only SSH connection. */
type Locks struct {
	mu   sync.Mutex
	held map[int64]*Lease
}

/* Lease is a held device lock. */
type Lease struct {
	l    *Locks
	id   int64
	once sync.Once
}

/* TryLock takes the lock of device id; false while someone (a session, a backup) holds it. */
func (l *Locks) TryLock(id int64) (*Lease, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.held[id] != nil {
		return nil, false
	}
	if l.held == nil {
		l.held = map[int64]*Lease{}
	}
	le := &Lease{l: l, id: id}
	l.held[id] = le
	return le, true
}

/* holds reports whether le itself (not another lease of the same device) holds its device. */
func (l *Locks) holds(le *Lease) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return le != nil && le.l == l && l.held[le.id] == le
}

/* Release frees the lock if le still holds it; repeated calls, and calls after another holder took the device, do nothing. */
func (le *Lease) Release() {
	le.once.Do(func() {
		le.l.mu.Lock()
		if le.l.held[le.id] == le {
			delete(le.l.held, le.id)
		}
		le.l.mu.Unlock()
	})
}

/* DeviceID is the device the lease holds. */
func (le *Lease) DeviceID() int64 { return le.id }

/* Config of the scheduler; every field but Enabled, Log and Now is required. */
type Config struct {
	Registry transport.Viewer /* *freeze.Guard */
	Net      transport.Dialer /* *netguard.Guard */
	/* Open opens the device's write credential from the verified snapshot (wcreds.Store.Open). */
	Open      func(s *registry.Snapshot, deviceID int64) (creds.Credential, error)
	Pool      *pgxpool.Pool
	BackupPub *[32]byte
	Locks     *Locks
	Alert     func(ctx context.Context, kind, severity string, deviceID int64, text string) error /* pub.Publisher.Alert */
	/* Enabled reports whether the executor may act (policy); nothing is backed up while it is false. */
	Enabled func() bool
	Log     *slog.Logger
	Now     func() time.Time
}

/* Scheduler backs up the executor's devices. */
type Scheduler struct {
	cfg  Config
	mu   sync.Mutex
	next map[int64]time.Time
}

/* New returns a scheduler. */
func New(cfg Config) *Scheduler {
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Enabled == nil {
		cfg.Enabled = func() bool { return true }
	}
	return &Scheduler{cfg: cfg, next: map[int64]time.Time{}}
}

func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return rand.N(d) // #nosec G404 -- spreading load, not a secret
}

/* Run backs up due devices every tick until ctx ends. */
func (s *Scheduler) Run(ctx context.Context) {
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		s.runDue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

/* runDue plans newly seen devices, forgets the others and backs up, one at a time, those due and not held. */
func (s *Scheduler) runDue(ctx context.Context) {
	if !s.cfg.Enabled() {
		s.forget(ctx, []int64{}) /* disabled: the poller takes every device back at once */
		return
	}
	ids, err := s.eligible(ctx)
	if err != nil {
		if ctx.Err() == nil {
			s.cfg.Log.Warn("executor backups: reading the registry failed", slog.String("err", err.Error()))
		}
		return
	}
	s.forget(ctx, ids)
	now := s.cfg.Now()
	var due []int64
	s.mu.Lock()
	seen := make(map[int64]bool, len(ids))
	for _, id := range ids {
		seen[id] = true
		switch n, ok := s.next[id]; {
		case !ok:
			s.next[id] = now.Add(jitter(firstSpread))
		case !n.After(now):
			due = append(due, id)
		}
	}
	for id := range s.next {
		if !seen[id] {
			delete(s.next, id)
		}
	}
	s.mu.Unlock()
	for _, id := range due {
		if ctx.Err() != nil {
			return
		}
		le, ok := s.cfg.Locks.TryLock(id)
		if !ok {
			continue /* in a session: tried again on the next tick */
		}
		err := s.backup(ctx, id)
		le.Release()
		s.plan(id, err)
	}
}

/* plan sets the next backup of id after one ended with err. */
func (s *Scheduler) plan(id int64, err error) {
	after := every + jitter(spread)
	if err != nil {
		after = retryAfter
	}
	s.mu.Lock()
	s.next[id] = s.cfg.Now().Add(after)
	s.mu.Unlock()
}

/*
Pre is the pre-session snapshot of a device: the configuration as read
(ReadOnly), its SHA-256 over the normalized text (as every version) and its
envelope sealed to the backup domain under backup.AAD(device, hex(SHA256)),
the same as its config_version row.
*/
type Pre struct {
	Text      string
	SHA256    [32]byte
	CT, DEKCT []byte
}

/*
BeforeSession reads the device of le, which the caller (a change session)
holds, before the session sends anything, and stores the configuration as a
'pre_session' version: always, whatever the device's backup_via_executor
(backup_state and the poller's stamp only for a device the executor backs
up); the version is drift when it differs from the newest one and left does
not report it as a session's result (drifted). The read uses the caller's lease, so the session's connection and the
backup's never overlap.
*/
func (s *Scheduler) BeforeSession(ctx context.Context, le *Lease, left func(context.Context, [32]byte) (bool, error)) (Pre, error) {
	if !s.cfg.Locks.holds(le) {
		return Pre{}, errLease
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	raw, sum, via, drv, err := s.read(ctx, le.id, false)
	if err != nil {
		return Pre{}, err
	}
	drift, err := s.drifted(ctx, le.id, sum, left)
	if err != nil {
		return Pre{}, err
	}
	v, err := s.version(drv, le.id, raw, sum, drift)
	if err != nil {
		return Pre{}, err
	}
	if err := s.store(ctx, le.id, sum, v, SourcePreSession, via); err != nil {
		return Pre{}, err
	}
	if via {
		s.plan(le.id, nil)
	}
	return Pre{Text: raw, SHA256: sum, CT: v.ct, DEKCT: v.dekCT}, nil
}

/* eligible lists the write_device rows with backup_via_executor of a verified snapshot. */
func (s *Scheduler) eligible(ctx context.Context) ([]int64, error) {
	ids := []int64{} /* never nil: forget compares with ALL($1), and ALL(NULL) deletes nothing */
	err := s.cfg.Registry.View(ctx, func(snap *registry.Snapshot) error {
		for _, r := range snap.Rows("write_device") {
			if via, _ := r.Get("backup_via_executor").(bool); via {
				if id, _ := r.Get("device_id").(int64); id > 0 {
					ids = append(ids, id)
				}
			}
		}
		return nil
	})
	return ids, err
}

/* forget removes the stamps of devices the executor no longer backs up, so the poller takes them back at once. */
func (s *Scheduler) forget(ctx context.Context, ids []int64) {
	if _, err := s.cfg.Pool.Exec(ctx, `DELETE FROM execpub.backup_taken WHERE device_id <> ALL($1)`, ids); err != nil && ctx.Err() == nil {
		s.cfg.Log.Warn("executor backups: clearing stale stamps failed", slog.String("err", err.Error()))
	}
}

/* shellRunner runs the read driver's allowlisted command on a ReadOnly shell. */
type shellRunner struct{ sh *transport.Shell }

func (r shellRunner) Run(ctx context.Context, cmd ssh.ShowCommand) (string, error) {
	out, err := r.sh.Run(ctx, cmd)
	if err != nil {
		return "", err
	}
	return out.Text(), nil
}

/* readDriver is the read driver of the line (its allowlist, normalizer and masker). */
func readDriver(l strategy.Line) drivers.Driver {
	switch l {
	case strategy.ESR:
		return eltexesr.New()
	case strategy.MES6:
		return eltexmes.New().ForIdentity(drivers.Identity{Firmware: "6.0"})
	default:
		return eltexmes.New().ForIdentity(drivers.Identity{Firmware: "10.0"})
	}
}

/* backup backs up device id; the caller holds its lease. A failure is recorded with the fixed ErrFailed text. */
func (s *Scheduler) backup(ctx context.Context, id int64) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	err := s.doBackup(ctx, id)
	if err != nil && !errors.Is(err, errNotEligible) && !errors.Is(err, errDisabled) {
		/* err may carry device text: debug level only, never in the database */
		s.cfg.Log.Info("executor backup failed", slog.Int64("device_id", id))
		s.cfg.Log.Debug("executor backup failed", slog.Int64("device_id", id), slog.String("err", err.Error()))
		/*
			Only for a device the executor has already backed up (its stamp or
			one of its versions): otherwise the poller still owns backup_state
			and its last result stays.
		*/
		if _, e := s.cfg.Pool.Exec(context.WithoutCancel(ctx), `INSERT INTO backups.backup_state (device_id, last_error)
			SELECT $1, $2 WHERE EXISTS (SELECT 1 FROM execpub.backup_taken WHERE device_id = $1)
				OR EXISTS (SELECT 1 FROM backups.config_version WHERE device_id = $1 AND source IN ('executor', 'pre_session', 'post_session'))
			ON CONFLICT (device_id) DO UPDATE SET last_error = $2`, id, ErrFailed); e != nil {
			s.cfg.Log.Warn("executor backups: recording the failure failed", slog.Int64("device_id", id), slog.String("err", e.Error()))
		}
	}
	return err
}

func (s *Scheduler) doBackup(ctx context.Context, id int64) error {
	raw, sum, _, drv, err := s.read(ctx, id, true)
	if err != nil {
		return err
	}
	last, err := s.lastOwn(ctx, id)
	if err != nil {
		return err
	}
	if last != nil && *last == sum {
		newest, err := s.newest(ctx, id)
		if err != nil {
			return err
		}
		if newest != nil && *newest == sum {
			return s.store(ctx, id, sum, nil, Source, true)
		}
		/* another source (the poller) stored a different configuration since: the newest version must be this one again */
	}
	v, err := s.version(drv, id, raw, sum, last != nil)
	if err != nil {
		return err
	}
	return s.store(ctx, id, sum, v, Source, true)
}

/*
read reads the running configuration of id over a ReadOnly connection with
its write credential, from the verified registry; eligible: only a device
with backup_via_executor (via reports the flag). sum is over the read
driver's normalized text, drv is that read driver.
*/
func (s *Scheduler) read(ctx context.Context, id int64, eligible bool) (raw string, sum [32]byte, via bool, drv drivers.Driver, err error) {
	if !s.cfg.Enabled() {
		return "", sum, false, nil, errDisabled
	}
	if s.cfg.BackupPub == nil {
		return "", sum, false, nil, errors.New("backups: no backup-domain key")
	}
	var c creds.Credential
	err = s.cfg.Registry.View(ctx, func(snap *registry.Snapshot) error {
		r, ok := snap.Get("write_device", id)
		if !ok {
			return errNotEligible
		}
		if via, _ = r.Get("backup_via_executor").(bool); eligible && !via {
			return errNotEligible
		}
		var err error
		c, err = s.cfg.Open(snap, id)
		return err
	})
	if err != nil {
		return "", sum, false, nil, err
	}
	sh, err := transport.Dial(ctx, transport.Config{DeviceID: id, Access: transport.ReadOnly, Registry: s.cfg.Registry,
		Net: s.cfg.Net, Alert: s.cfg.Alert,
		Credential: transport.Credential{Username: c.Username, Password: c.Password, PrivateKey: c.PrivateKey}})
	c.Wipe()
	if err != nil {
		return "", sum, false, nil, err
	}
	drv = readDriver(sh.Line())
	raw, err = drv.FetchConfig(ctx, shellRunner{sh})
	_ = sh.Close()
	if err != nil {
		return "", sum, false, nil, err
	}
	if len(raw) > drivers.MaxConfigSize {
		return "", sum, false, nil, drivers.ErrConfigTooLarge
	}
	return raw, sha256.Sum256([]byte(drv.NormalizeConfig(raw))), via, drv, nil /* the normalized text is for the hash only */
}

/* version masks raw with the read driver and seals a copy of it (Seal wipes its input) as a new version of id. */
func (s *Scheduler) version(drv drivers.Driver, id int64, raw string, sum [32]byte, drift bool) (*version, error) {
	masked := strings.ToValidUTF8(drv.MaskSecrets(raw), "?")
	if len(masked) > drivers.MaxConfigSize {
		return nil, drivers.ErrConfigTooLarge
	}
	ct, dekCT, err := backup.Seal(s.cfg.BackupPub, []byte(raw), backup.AAD(id, hex.EncodeToString(sum[:])))
	if err != nil {
		return nil, err
	}
	return &version{size: len(raw), masked: masked, ct: ct, dekCT: dekCT, drift: drift}, nil
}

/* lastOwn is the hash of the newest version the executor stored for id (sources only its role can insert); nil when none. */
func (s *Scheduler) lastOwn(ctx context.Context, id int64) (*[32]byte, error) {
	return s.hashOf(ctx, `SELECT sha256 FROM backups.config_version
		WHERE device_id = $1 AND source IN ('executor', 'pre_session', 'post_session') ORDER BY id DESC LIMIT 1`, id)
}

/* hashOf runs a query of one sha256 for id; nil when there is no row. */
func (s *Scheduler) hashOf(ctx context.Context, sql string, id int64) (*[32]byte, error) {
	var b []byte
	err := s.cfg.Pool.QueryRow(ctx, sql, id).Scan(&b)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(b) != sha256.Size {
		return nil, fmt.Errorf("backups: stored hash of %d bytes", len(b))
	}
	h := [32]byte(b)
	return &h, nil
}

/*
newest is the hash of the newest version of id of any source; nil when none.
It only ever adds a version (a forged poller row makes the executor store
the device's configuration again), never skips one.
*/
func (s *Scheduler) newest(ctx context.Context, id int64) (*[32]byte, error) {
	return s.hashOf(ctx, `SELECT sha256 FROM backups.config_version WHERE device_id = $1 ORDER BY id DESC LIMIT 1`, id)
}

/* version is a new configuration version to store. */
type version struct {
	size      int
	masked    string
	ct, dekCT []byte
	drift     bool
}

/*
store records a successful backup in one transaction: with v a new version
of source, and for a device the executor backs up (via) backup_state and
the poller's stamp.
*/
func (s *Scheduler) store(ctx context.Context, id int64, sum [32]byte, v *version, source string, via bool) error {
	return pgx.BeginFunc(ctx, s.cfg.Pool, func(tx pgx.Tx) error {
		if v != nil {
			if _, err := tx.Exec(ctx, `INSERT INTO backups.config_version (device_id, source, sha256, size, masked, full_ct, full_dek_ct, drift)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, id, source, sum[:], v.size, v.masked, v.ct, v.dekCT, v.drift); err != nil {
				return err
			}
		}
		if !via {
			return nil
		}
		if _, err := tx.Exec(ctx, `INSERT INTO backups.backup_state (device_id, last_ok_at, last_sha256) VALUES ($1, now(), $2)
			ON CONFLICT (device_id) DO UPDATE SET last_ok_at = now(), last_error = NULL, last_sha256 = $2, needs_write = false`, id, sum[:]); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO execpub.backup_taken (device_id) VALUES ($1)
			ON CONFLICT (device_id) DO UPDATE SET at = now()`, id)
		return err
	})
}

/*
drifted reports whether sum, a configuration read before a session, is
drift: it differs from the newest version of any source and left does not
say it is what a change session left since (the session package reads
its own summaries; nil: drift). A change made outside every session thus
stays visible as drift although the pre-session version, not the
poller's, records it first.
*/
func (s *Scheduler) drifted(ctx context.Context, id int64, sum [32]byte, left func(context.Context, [32]byte) (bool, error)) (bool, error) {
	newest, err := s.newest(ctx, id)
	if err != nil || newest == nil || *newest == sum {
		return false, err
	}
	if left == nil {
		return true, nil
	}
	session, err := left(ctx, sum)
	return !session, err
}
