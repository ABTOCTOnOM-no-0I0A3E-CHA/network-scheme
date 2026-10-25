/*
Package poller is the read-only collection service: it schedules
availability, metric and inventory polls of the devices assigned to it, runs
them through the device drivers with the read credentials it alone can open,
runs its discovery scans and works the poll_now and discovery_scan jobs of its
queue.
*/
package poller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/inventory"
	"github.com/beekamai/network-scheme/internal/jobs"
	"github.com/beekamai/network-scheme/internal/metrics"
	"github.com/beekamai/network-scheme/internal/snmp"
	"github.com/beekamai/network-scheme/internal/ssh"
)

/* Service timings. */
const (
	heartbeatEvery = 15 * time.Second
	healthyWithin  = 45 * time.Second
	stopTimeout    = 30 * time.Second
)

// DialFunc opens a read-only SNMP session; snmp.Dial is the production implementation.
type DialFunc func(ctx context.Context, addr netip.AddrPort, c creds.Credential, o snmp.Options) (snmp.Reader, io.Closer, error)

/*
Deps are the poller's collaborators. Nil members select the production
implementation; tests replace ICMP and SNMP dialing.
*/
type Deps struct {
	Pool *pgxpool.Pool /* connected as nms_poller */
	Priv *[32]byte     /* read-domain key pair (Config.ReadKeys) */
	Pub  *[32]byte
	/* BackupPub is the backup-domain public key (Config.BackupPubKey); nil: configuration backups are off. The private key is never available here. */
	BackupPub *[32]byte
	Pinger    Pinger            /* nil: ICMP echo via pro-bing */
	DialSNMP  DialFunc          /* nil: snmp.Dial */
	Registry  *drivers.Registry /* nil: drivers.Default() */
	Clock     func() time.Time  /* nil: time.Now */
	Logger    *slog.Logger      /* nil: slog.Default() */
	/*
		AvailabilityStarted, when set, is called as each scheduled availability
		run starts, with the time the run was due; load tests measure the
		scheduling delay with it. It must return quickly.
	*/
	AvailabilityStarted func(deviceID int64, due, started time.Time)
}

// Poller polls the devices of one poller id.
type Poller struct {
	cfg            Config
	pool           *pgxpool.Pool
	priv           *[32]byte
	pub            *[32]byte
	backupPub      *[32]byte
	backupTick     time.Duration
	backupGap      time.Duration /* least time between two backups of a device, whoever asks */
	backupSlotWait time.Duration
	schedSem       chan struct{} /* backupParallel-1 slots for scheduled runs: one is always left for jobs */
	backupSem      chan struct{} /* backupParallel fetch slots shared by the schedule and backup_now */
	backupMu       sync.Mutex
	backupAt       map[int64]time.Time                                                                      /* last backup attempt per device; guarded by backupMu */
	fetchRaw       func(ctx context.Context, d device, cache *devCache, drv drivers.Driver) (string, error) /* sshFetch; replaced in tests */
	showMu         sync.Mutex
	showEvery      time.Duration                                                                                                 /* least time between show commands per device */
	showAt         map[int64]time.Time                                                                                           /* last command that reached a device; guarded by showMu */
	showBusy       map[int64]bool                                                                                                /* devices with a show command waiting or running; guarded by showMu */
	runShowCmd     func(ctx context.Context, d device, cache *devCache, drv drivers.Driver, cmd ssh.ShowCommand) (string, error) /* sshShow; replaced in tests */
	pinger         Pinger
	dial           DialFunc
	reg            *drivers.Registry
	now            func() time.Time
	log            *slog.Logger
	sched          *scheduler
	rates          *metrics.RateCalc
	metrics        *metrics.Store
	inv            *inventory.Store
	hostKeys       *ssh.HostKeys
	disc           *discovery
	discEvery      time.Duration
	scanRecheck    time.Duration
	scanFloor      time.Duration                                          /* least interval between scheduled runs of a scan, whatever interval_s says */
	scanGap        time.Duration                                          /* least time between two runs of a scan, however requested */
	scanPanics     atomic.Int64                                           /* recovered panics of discovery runs */
	recheck        func(ctx context.Context, id int64) (scanState, error) /* scanState; replaced in tests */

	jobReload     sync.Mutex   /* single-flight reloadForJob */
	lastJobReload time.Time    /* guarded by jobReload */
	jobReloads    atomic.Int64 /* rereads done for jobs; tests read it */
	unknownJobs   atomic.Int64 /* poll_now and backup_now jobs cancelled for a device not assigned here */

	backupVersions atomic.Int64 /* configuration versions stored */
	backupOversize atomic.Int64 /* configurations refused for exceeding 4 MiB */
}

// New returns a poller for a validated cfg.
func New(cfg Config, d Deps) *Poller {
	p := &Poller{
		cfg: cfg, pool: d.Pool, priv: d.Priv, pub: d.Pub, backupPub: d.BackupPub, backupTick: backupTick, backupGap: jobs.BackupGap, backupSem: make(chan struct{}, backupParallel), schedSem: make(chan struct{}, backupParallel-1), backupSlotWait: backupSlotWait, backupAt: map[int64]time.Time{}, pinger: d.Pinger, dial: d.DialSNMP,
		reg: d.Registry, now: d.Clock, log: d.Logger,
		metrics: metrics.NewStore(d.Pool), inv: inventory.NewStore(d.Pool), hostKeys: ssh.NewHostKeys(d.Pool),
		disc: newDiscovery(), discEvery: discoveryEvery, scanRecheck: scanRecheckEvery,
		scanFloor: minScanInterval, scanGap: minScanGap,
	}
	p.recheck = p.scanState
	p.fetchRaw = p.sshFetch
	p.showEvery = showGap
	p.runShowCmd, p.showBusy, p.showAt = p.sshShow, map[int64]bool{}, map[int64]time.Time{}
	if p.pinger == nil {
		p.pinger = ICMPPinger{}
	}
	if p.dial == nil {
		p.dial = snmp.Dial
	}
	if p.reg == nil {
		p.reg = drivers.Default()
	}
	if p.now == nil {
		p.now = time.Now
	}
	if p.log == nil {
		p.log = slog.Default()
	}
	p.sched = newScheduler(cfg.Workers, p.run, p.forget)
	if hook := d.AvailabilityStarted; hook != nil {
		p.sched.started = func(id int64, c class, due, at time.Time) {
			if c == classAvail {
				hook(id, due, at)
			}
		}
	}
	p.rates = metrics.NewRateCalc(func(id int64) time.Duration { return p.sched.interval(id, classMetrics) })
	return p
}

/* forget drops the in-memory state of a device that is no longer polled here. */
func (p *Poller) forget(id int64) { p.rates.Forget(id) }

/*
Run polls until ctx ends. It fails only when the initial device list cannot
be loaded or the job client cannot start; later database errors are logged
and retried.
*/
func (p *Poller) Run(ctx context.Context) error {
	if err := p.reload(ctx); err != nil {
		return err
	}
	rc, err := p.newRiver(ctx)
	if err != nil {
		return err
	}
	if err := rc.Start(context.WithoutCancel(ctx)); err != nil {
		return fmt.Errorf("poller: start job client: %w", err)
	}
	p.log.Info("poller started", slog.String("poller_id", p.cfg.PollerID))
	var wg sync.WaitGroup
	wg.Go(func() { p.heartbeat(ctx) })
	wg.Go(func() { p.listen(ctx) })
	wg.Go(func() { p.discoverLoop(ctx) })
	wg.Go(func() { p.cleanShow(ctx) })
	if p.backupPub != nil {
		wg.Go(func() { p.backupLoop(ctx) })
	} else {
		/* Documented choice: a startup warning only; backup_now jobs record a fixed last_error per device. */
		p.log.Warn("configuration backups are disabled: backup_pub_key_file is not set")
	}
	p.sched.loop(ctx)
	wg.Wait()
	sctx, cancel := context.WithTimeout(context.Background(), stopTimeout)
	defer cancel()
	err = rc.StopAndCancel(sctx)
	p.disc.wg.Wait() /* scan runs end with ctx */
	if err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("poller: stop job client: %w", err)
	}
	return nil
}

/* reload rereads the device list of this poller into the scheduler. */
func (p *Poller) reload(ctx context.Context) error {
	devs, err := p.loadDevices(ctx)
	if err != nil {
		return err
	}
	p.sched.apply(devs)
	return nil
}

/* heartbeat records liveness now and every 15 s. */
func (p *Poller) heartbeat(ctx context.Context) {
	t := time.NewTicker(heartbeatEvery)
	defer t.Stop()
	for {
		if err := p.inv.Heartbeat(ctx, p.cfg.PollerID, p.now()); err != nil && ctx.Err() == nil {
			p.log.Warn("heartbeat failed", slog.String("err", err.Error()))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

/*
Healthy reports whether poller pollerID wrote a heartbeat within the last
45 s, by the database clock.
*/
func Healthy(ctx context.Context, pool *pgxpool.Pool, pollerID string) error {
	var fresh bool
	err := pool.QueryRow(ctx, `SELECT coalesce(bool_or(at >= now() - make_interval(secs => $2)), false)
		FROM inventory.poller_heartbeat WHERE poller_id = $1`, pollerID, healthyWithin.Seconds()).Scan(&fresh)
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	if !fresh {
		return fmt.Errorf("healthcheck: no heartbeat of poller %q within %v", pollerID, healthyWithin)
	}
	return nil
}
