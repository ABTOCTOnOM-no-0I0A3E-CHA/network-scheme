package poller

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/jobs"
	"github.com/beekamai/network-scheme/internal/snmp"
)

/* Discovery limits. */
const (
	scanConcurrency = 32            /* addresses probed at once per scan */
	maxScanRuns     = 2             /* scans of this poller running at once */
	scanTimeout     = 6 * time.Hour /* bound of one run; a /16 needs about 35 min of ICMP timeouts */
	discoveryEvery  = time.Minute   /* how often due scans are looked for */
	scanSNMPPort    = 161
	oidSysName      = "1.3.6.1.2.1.1.5.0"
)

/* errScanRefused: the scan does not exist, is disabled, is not this poller's or has no usable credential. */
var errScanRefused = errors.New("poller: scan refused")

/* scanRun is a validated scan with its opened credential. */
type scanRun struct {
	id     int64
	prefix netip.Prefix
	cred   creds.Credential
}

/* discovery tracks the scan runs of this poller. */
type discovery struct {
	mu      sync.Mutex
	running map[int64]bool
	slots   chan struct{}
	wg      sync.WaitGroup
}

func newDiscovery() *discovery {
	return &discovery{running: map[int64]bool{}, slots: make(chan struct{}, maxScanRuns)}
}

/*
prepareScan loads scan id and opens its own credential; no other profile is
ever considered. A scan that does not exist, is disabled, belongs to another
poller, has an unscannable prefix or no usable credential is refused
(errScanRefused); other errors are database failures.
*/
func (p *Poller) prepareScan(ctx context.Context, id int64) (scanRun, error) {
	var (
		prefix   netip.Prefix
		enabled  bool
		pollerID string
	)
	err := p.pool.QueryRow(ctx, `SELECT cidr, enabled, poller_id FROM core.discovery_scan WHERE id = $1`, id).
		Scan(&prefix, &enabled, &pollerID)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return scanRun{}, fmt.Errorf("%w: scan %d does not exist", errScanRefused, id)
	case err != nil:
		return scanRun{}, fmt.Errorf("poller: load scan: %w", err)
	case pollerID != p.cfg.PollerID:
		return scanRun{}, fmt.Errorf("%w: scan %d belongs to another poller", errScanRefused, id)
	case !enabled:
		return scanRun{}, fmt.Errorf("%w: scan %d is disabled", errScanRefused, id)
	}
	/* The api is not trusted to have validated the prefix. */
	if err := devices.CheckScanPrefix(prefix); err != nil {
		return scanRun{}, fmt.Errorf("%w: scan %d: %w", errScanRefused, id, err)
	}
	c, err := p.credential(ctx, devices.Owner{Kind: devices.OwnerScan, ID: id}, newDevCache(), snmpKinds...)
	if errors.Is(err, errNoProfile) {
		return scanRun{}, fmt.Errorf("%w: scan %d has no usable credential", errScanRefused, id)
	}
	if err != nil {
		return scanRun{}, err
	}
	return scanRun{id: id, prefix: prefix.Masked(), cred: c}, nil
}

/* claim marks scan id running; false if a run of it is in progress. */
func (d *discovery) claim(id int64) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.running[id] {
		return false
	}
	d.running[id] = true
	return true
}

func (d *discovery) release(id int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.running, id)
}

/* begin validates scan id and records the start of its run. */
func (p *Poller) begin(ctx context.Context, id int64) (scanRun, error) {
	run, err := p.prepareScan(ctx, id)
	if err != nil {
		return scanRun{}, err
	}
	if _, err := p.pool.Exec(ctx, `UPDATE core.discovery_scan SET last_run_at = now() WHERE id = $1`, id); err != nil {
		return scanRun{}, fmt.Errorf("poller: mark scan run: %w", err)
	}
	return run, nil
}

/*
startScan validates scan id and runs it in the background until it ends or
life ends. A scan already running is left alone (nil error).
*/
func (p *Poller) startScan(ctx, life context.Context, id int64) error {
	if !p.disc.claim(id) {
		return nil
	}
	run, err := p.begin(ctx, id)
	if err != nil {
		p.disc.release(id)
		return err
	}
	p.disc.wg.Go(func() {
		defer p.disc.release(id)
		select {
		case p.disc.slots <- struct{}{}:
		case <-life.Done():
			return
		}
		defer func() { <-p.disc.slots }()
		p.sweepScan(life, run)
	})
	return nil
}

/* sweepScan probes every host of the scan and records what answers SNMP. */
func (p *Poller) sweepScan(ctx context.Context, run scanRun) {
	ctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()
	log := p.log.With(slog.Int64("scan_id", run.id))
	known, err := p.knownAddrs(ctx, run.prefix)
	if err != nil {
		log.Warn("scan aborted", slog.String("err", err.Error()))
		return
	}
	st := devices.NewStore(p.pool)
	var found, failed atomic.Int64
	sweep(ctx, scanHosts(run.prefix), scanConcurrency, func(ctx context.Context, a netip.Addr) {
		if known[a] {
			return /* never a second session to a polled device, never into the inbox */
		}
		sys, ok := p.probe(ctx, run.cred, a)
		if !ok {
			return
		}
		if err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
			return st.UpsertDiscovered(ctx, tx, run.id, a, sys[0], sys[1], sys[2])
		}); err != nil {
			if failed.Add(1) == 1 {
				log.Warn("discovered address not stored", slog.String("err", err.Error()))
			}
			return
		}
		found.Add(1)
	})
	log.Info("scan finished", slog.Int64("answered", found.Load()), slog.Int64("not_stored", failed.Load()),
		slog.Bool("complete", ctx.Err() == nil))
}

/* knownAddrs returns the device addresses within prefix. */
func (p *Poller) knownAddrs(ctx context.Context, prefix netip.Prefix) (map[netip.Addr]bool, error) {
	rows, err := p.pool.Query(ctx, `SELECT address FROM core.device WHERE address <<= $1::cidr`, prefix)
	if err != nil {
		return nil, fmt.Errorf("poller: known addresses: %w", err)
	}
	known := map[netip.Addr]bool{}
	var a netip.Addr
	if _, err := pgx.ForEachRow(rows, []any{&a}, func() error {
		known[a.Unmap()] = true
		return nil
	}); err != nil {
		return nil, fmt.Errorf("poller: known addresses: %w", err)
	}
	return known, nil
}

/*
probe sends one ICMP echo and, if it is answered, one SNMP GET of sysObjectID,
sysDescr and sysName with the scan's credential. sys holds the cleaned values.
*/
func (p *Poller) probe(ctx context.Context, c creds.Credential, a netip.Addr) (sys [3]string, ok bool) {
	if _, alive := p.pinger.Ping(ctx, a); !alive {
		return sys, false
	}
	/* Two budgets: SNMPv3 discovers the engine before the GET. */
	gctx, cancel := context.WithTimeout(ctx, 2*p.snmpBudget())
	defer cancel()
	r, closer, err := p.dial(gctx, netip.AddrPortFrom(a, scanSNMPPort), c, p.cfg.snmpOptions())
	if err != nil {
		return sys, false
	}
	defer func() { _ = closer.Close() }()
	vars, err := r.Get(gctx, oidSysObjID, oidSysDescr, oidSysName)
	if err != nil {
		return sys, false
	}
	for _, v := range vars {
		var s string
		switch v.OID {
		case oidSysObjID:
			s, _ = snmp.AsOID(v)
			sys[0] = drivers.CleanText([]byte(s))
		case oidSysDescr:
			s, _ = snmp.AsString(v)
			sys[1] = drivers.CleanText([]byte(s))
		case oidSysName:
			s, _ = snmp.AsString(v)
			sys[2] = drivers.CleanText([]byte(s))
		}
	}
	return sys, true
}

/*
scanHosts yields the host addresses of p: IPv4 without the network and
broadcast addresses (except /31 and /32), IPv6 without the subnet-router
anycast address (except /127 and /128).
*/
func scanHosts(p netip.Prefix) iter.Seq[netip.Addr] {
	return func(yield func(netip.Addr) bool) {
		p = p.Masked()
		first := p.Addr()
		wide := first.BitLen()-p.Bits() >= 2
		for a := first; a.IsValid() && p.Contains(a); a = a.Next() {
			next := a.Next()
			last := !next.IsValid() || !p.Contains(next)
			if wide && (a == first || (last && first.Is4())) {
				continue
			}
			if !yield(a) {
				return
			}
		}
	}
}

/* sweep calls probe for every address with at most workers calls at once, until addrs or ctx end. */
func sweep(ctx context.Context, addrs iter.Seq[netip.Addr], workers int, probe func(context.Context, netip.Addr)) {
	ch := make(chan netip.Addr)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for a := range ch {
				probe(ctx, a)
			}
		})
	}
feed:
	for a := range addrs {
		select {
		case ch <- a:
		case <-ctx.Done():
			break feed
		}
	}
	close(ch)
	wg.Wait()
}

/*
discoverLoop starts the due scans of this poller now and every discEvery: an
enabled scan with a credential not yet rejected, whose last run began at
least interval_s ago. A scan still running is skipped.
*/
func (p *Poller) discoverLoop(ctx context.Context) {
	t := time.NewTicker(p.discEvery)
	defer t.Stop()
	for {
		if err := p.startDueScans(ctx); err != nil && ctx.Err() == nil {
			p.log.Warn("discovery schedule failed", slog.String("err", err.Error()))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (p *Poller) startDueScans(ctx context.Context) error {
	rows, err := p.pool.Query(ctx, `
		SELECT s.id FROM core.discovery_scan s
		WHERE s.poller_id = $1 AND s.enabled
			AND (s.last_run_at IS NULL OR s.last_run_at <= now() - make_interval(secs => s.interval_s))
			AND EXISTS (SELECT 1 FROM core.access_profile a WHERE a.owner_kind = 'scan' AND a.owner_id = s.id
				AND a.kind = ANY($2) AND a.status IN ('pending', 'ok'))
		ORDER BY s.last_run_at NULLS FIRST, s.id`, p.cfg.PollerID, snmpKinds)
	if err != nil {
		return fmt.Errorf("poller: due scans: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return fmt.Errorf("poller: due scans: %w", err)
	}
	for _, id := range ids {
		if err := p.startScan(ctx, ctx, id); err != nil {
			if !errors.Is(err, errScanRefused) {
				return err
			}
			p.log.Info("scheduled scan refused", slog.Int64("scan_id", id), slog.String("reason", err.Error()))
		}
	}
	return nil
}

/*
discoveryWorker starts a scan run on request. Jobs are inserted by the api,
which is not trusted: a scan that is missing, disabled, another poller's or
without a usable credential is cancelled without any probe. The run itself
continues in the background, so a long scan holds no job slot.
*/
type discoveryWorker struct {
	river.WorkerDefaults[jobs.DiscoveryScanArgs]
	p    *Poller
	life context.Context
}

// Work implements river.Worker.
func (w *discoveryWorker) Work(ctx context.Context, job *river.Job[jobs.DiscoveryScanArgs]) error {
	err := w.p.startScan(ctx, w.life, job.Args.ScanID)
	if errors.Is(err, errScanRefused) {
		return river.JobCancel(err)
	}
	return err
}
