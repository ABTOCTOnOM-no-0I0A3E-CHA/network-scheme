package poller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/inventory"
	"github.com/beekamai/network-scheme/internal/metrics"
	"github.com/beekamai/network-scheme/internal/snmp"
	"github.com/beekamai/network-scheme/internal/ssh"
)

const (
	collectTimeout   = 2 * time.Minute
	inventoryTimeout = 4 * time.Minute /* below the default 5-minute inventory interval */
	sshPort          = 22
)

/* errDB marks database failures, as opposed to device or credential problems. */
var errDB = errors.New("poller: database")

func isDBErr(err error) bool { return errors.Is(err, errDB) }

/*
devCache is what the poller learned about one device. It is used only with
the device lock held; the flags are set by the scheduler when the device
record changes.
*/
type devCache struct {
	readdressed atomic.Bool /* address or port changed: forget everything */
	redriven    atomic.Bool /* driver setting changed: identify again */
	drv         drivers.Driver
	creds       map[string]opened
	lastCPU     *float64
}

func newDevCache() *devCache { return &devCache{creds: map[string]opened{}} }

/* run polls class c of d; the scheduler holds the device lock. */
func (p *Poller) run(ctx context.Context, d device, cache *devCache, c class) error {
	if cache.readdressed.Swap(false) {
		cache.drv, cache.lastCPU = nil, nil
		p.rates.Forget(d.ID)
	}
	if cache.redriven.Swap(false) {
		cache.drv = nil
	}
	switch c {
	case classAvail:
		return p.availability(ctx, d, cache)
	case classMetrics:
		return p.collect(ctx, d, cache)
	default:
		return p.inventory(ctx, d, cache)
	}
}

/* pollAll runs a full poll (poll_now): availability, metrics, inventory. */
func (p *Poller) pollAll(ctx context.Context, d device, cache *devCache) error {
	var errs []error
	for c := range numClasses {
		errs = append(errs, p.run(ctx, d, cache, c))
	}
	return errors.Join(errs...)
}

/* session opens an SNMP session with the device's first usable SNMP credential. */
func (p *Poller) session(ctx context.Context, d device, cache *devCache) (snmp.Reader, io.Closer, error) {
	c, err := p.credential(ctx, d, cache, snmpKinds...)
	if err != nil {
		return nil, nil, err
	}
	return p.dial(ctx, d.Addr, c, p.cfg.snmpOptions())
}

/*
driver returns the device's driver, identifying the device on first contact:
the configured driver, or (for "auto" or an unknown name) the registry's
choice by sysObjectID and sysDescr. Identity is stored once per process and
device.
*/
func (p *Poller) driver(ctx context.Context, d device, cache *devCache, r snmp.Reader) (drivers.Driver, error) {
	if cache.drv != nil {
		return cache.drv, nil
	}
	var drv drivers.Driver
	if d.Driver != "auto" {
		if drv = p.reg.ByName(d.Driver); drv == nil {
			p.log.Warn("unknown driver, selecting by sysObjectID", slog.Int64("device_id", d.ID), slog.String("driver", drivers.CleanText([]byte(d.Driver))))
		}
	}
	if drv == nil {
		vars, err := r.Get(ctx, oidSysObjID, oidSysDescr)
		if err != nil {
			return nil, fmt.Errorf("read system group: %w", err)
		}
		var oid, descr string
		for _, v := range vars {
			switch v.OID {
			case oidSysObjID:
				oid, _ = snmp.AsOID(v)
			case oidSysDescr:
				s, _ := snmp.AsString(v)
				descr = drivers.CleanText([]byte(s))
			}
		}
		drv = p.reg.Select(oid, descr)
	}
	ident, err := drv.Identify(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("identify: %w", err)
	}
	if err := p.storeIdentity(ctx, d.ID, ident, drv.Name()); err != nil {
		return nil, fmt.Errorf("%w: %w", errDB, err)
	}
	cache.drv = drv
	return drv, nil
}

/* collect reads counters and resources and stores rates and system metrics. */
func (p *Poller) collect(ctx context.Context, d device, cache *devCache) error {
	r, closer, err := p.session(ctx, d, cache)
	if err != nil {
		return err
	}
	defer func() { _ = closer.Close() }()
	cctx, cancel := context.WithTimeout(ctx, collectTimeout)
	defer cancel()
	drv, err := p.driver(cctx, d, cache, r)
	if err != nil {
		return err
	}
	at := p.now()
	s, err := drv.Collect(cctx, r)
	if err != nil {
		return fmt.Errorf("collect: %w", err)
	}
	cache.lastCPU = s.System.CPUPct
	if s.Incomplete > 0 {
		p.log.Info("interfaces without usable counters", slog.Int64("device_id", d.ID), slog.Int("incomplete", s.Incomplete))
	}
	sys := s.System
	return errors.Join(
		p.metrics.WriteIf(ctx, p.rates.Rates(d.ID, s, at)),
		p.metrics.WriteSys(ctx, []metrics.SysPoint{{DeviceID: d.ID, TS: at, CPUPct: sys.CPUPct, MemUsedPct: sys.MemUsedPct, TempC: sys.TempC, PSUOk: sys.PSUOk}}),
	)
}

/*
inventory walks the inventory tables under an overall deadline and stores
them. Heavy tables are skipped while the device's CPU is above the threshold;
SSH is used only when the driver has a dialect and an ssh_read credential is
usable.
*/
func (p *Poller) inventory(ctx context.Context, d device, cache *devCache) error {
	r, closer, err := p.session(ctx, d, cache)
	if err != nil {
		return err
	}
	defer func() { _ = closer.Close() }()
	ictx, cancel := context.WithTimeout(ctx, inventoryTimeout)
	defer cancel()
	drv, err := p.driver(ictx, d, cache, r)
	if err != nil {
		return err
	}
	if cache.lastCPU != nil && *cache.lastCPU > p.cfg.HeavyCPUThreshold {
		ictx = drivers.WithBudget(ictx, drivers.Budget{SkipHeavy: true})
	}
	var sh drivers.ShowRunner
	if runner := p.sshRunner(ictx, d, cache, drv); runner != nil {
		defer func() { _ = runner.Close() }()
		sh = runner
	}
	at := p.now()
	inv, err := drv.Inventory(ictx, r, sh)
	if err != nil {
		return fmt.Errorf("inventory: %w", err)
	}
	p.logInventory(d.ID, inv)
	if err := p.inv.Apply(ctx, d.ID, inv, at); err != nil && !errors.Is(err, inventory.ErrNoDevice) {
		return fmt.Errorf("%w: %w", errDB, err)
	}
	return nil
}

/* sshRunner opens the driver's read-only SSH session, or returns nil when there is none to open. */
func (p *Poller) sshRunner(ctx context.Context, d device, cache *devCache, drv drivers.Driver) *ssh.Runner {
	dl := drv.Dialect()
	if dl.ExecPrompt == nil {
		return nil
	}
	c, err := p.credential(ctx, d, cache, creds.KindSSHRead)
	if err != nil {
		if !errors.Is(err, errNoProfile) {
			p.log.Warn("ssh credential unavailable", slog.Int64("device_id", d.ID), slog.String("err", err.Error()))
		}
		return nil
	}
	runner, err := ssh.Dial(ctx, netip.AddrPortFrom(d.Addr.Addr(), sshPort), d.ID, c, p.hostKeys, dl)
	if err != nil {
		p.log.Warn("ssh session failed", slog.Int64("device_id", d.ID), slog.String("err", drivers.CleanText([]byte(err.Error()))))
		return nil
	}
	return runner
}

var allTables = []drivers.Table{
	drivers.TableInterfaces, drivers.TableARP, drivers.TableMAC, drivers.TableVLANs,
	drivers.TableLLDP, drivers.TableEntities, drivers.TableRoutes,
}

/* logInventory reports dropped rows and incomplete tables; keys are table constants, never device data. */
func (p *Poller) logInventory(id int64, inv drivers.Inventory) {
	var incomplete []string
	attrs := []any{slog.Int64("device_id", id)}
	for _, t := range allTables {
		if !inv.Complete[t] {
			incomplete = append(incomplete, string(t))
		}
		if n := inv.Malformed[t]; n > 0 {
			attrs = append(attrs, slog.Int("malformed_"+string(t), n))
		}
	}
	if len(attrs) == 1 && len(incomplete) == 0 {
		return
	}
	slices.Sort(incomplete)
	attrs = append(attrs, slog.String("incomplete_tables", strings.Join(incomplete, ",")))
	p.log.Info("inventory partially read", attrs...)
}
