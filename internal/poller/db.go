package poller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/drivers"
)

const (
	listenChannel = "device_changed"
	resyncEvery   = 5 * time.Minute        /* full reread even without notifications */
	settleFor     = 300 * time.Millisecond /* coalesces a burst of notifications into one reread */
	relistenAfter = 2 * time.Second
)

/*
loadDevices reads the devices assigned to this poller with their effective
intervals: device ?? its group ?? a template (templates of the device's group,
then of its ancestors nearest first, then of its driver) ?? the poller default.
*/
func (p *Poller) loadDevices(ctx context.Context) ([]device, error) {
	tpl, err := p.loadTemplates(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := p.pool.Query(ctx, `
		SELECT d.id, d.address, d.snmp_port, d.driver, d.group_id,
			coalesce(d.interval_avail_s, g.interval_avail_s),
			coalesce(d.interval_metrics_s, g.interval_metrics_s),
			coalesce(d.interval_inventory_s, g.interval_inventory_s)
		FROM core.device d JOIN core.device_group g ON g.id = d.group_id
		WHERE d.poller_id = $1`, p.cfg.PollerID)
	if err != nil {
		return nil, fmt.Errorf("poller: load devices: %w", err)
	}
	def := [numClasses]time.Duration{p.cfg.DefaultIntervals.Availability, p.cfg.DefaultIntervals.Metrics, p.cfg.DefaultIntervals.Inventory}
	devs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (device, error) {
		var (
			d     device
			addr  netip.Addr
			port  int
			group int64
			iv    [numClasses]*int
		)
		if err := r.Scan(&d.ID, &addr, &port, &d.Driver, &group, &iv[classAvail], &iv[classMetrics], &iv[classInventory]); err != nil {
			return d, err
		}
		d.Addr = netip.AddrPortFrom(addr.Unmap(), uint16(port)) // #nosec G115 -- CHECK 1..65535 in the schema
		for c := range numClasses {
			secs := iv[c]
			if secs == nil {
				secs = tpl.interval(group, d.Driver, c)
			}
			d.Intervals[c] = def[c]
			if secs != nil {
				d.Intervals[c] = clampInterval(c, *secs)
			}
		}
		return d, nil
	})
	if err != nil {
		return nil, fmt.Errorf("poller: load devices: %w", err)
	}
	return devs, nil
}

/* maxGroupDepth bounds the walk up the group tree. */
const maxGroupDepth = 64

/* templates are the interval settings of core.monitoring_template and the group tree they apply through. */
type templates struct {
	parent   map[int64]int64 /* group -> parent group */
	byGroup  map[int64][][numClasses]*int
	byDriver map[string][][numClasses]*int
}

/* loadTemplates reads the group tree and the templates that set an interval, lowest id first. */
func (p *Poller) loadTemplates(ctx context.Context) (templates, error) {
	t := templates{parent: map[int64]int64{}, byGroup: map[int64][][numClasses]*int{}, byDriver: map[string][][numClasses]*int{}}
	rows, err := p.pool.Query(ctx, `SELECT id, parent_id FROM core.device_group WHERE parent_id IS NOT NULL`)
	if err != nil {
		return t, fmt.Errorf("poller: load groups: %w", err)
	}
	var id, parent int64
	if _, err := pgx.ForEachRow(rows, []any{&id, &parent}, func() error { t.parent[id] = parent; return nil }); err != nil {
		return t, fmt.Errorf("poller: load groups: %w", err)
	}
	rows, err = p.pool.Query(ctx, `
		SELECT driver, group_id, interval_avail_s, interval_metrics_s, interval_inventory_s
		FROM core.monitoring_template
		WHERE num_nonnulls(interval_avail_s, interval_metrics_s, interval_inventory_s) > 0
		ORDER BY id`)
	if err != nil {
		return t, fmt.Errorf("poller: load templates: %w", err)
	}
	var (
		driver *string
		group  *int64
		iv     [numClasses]*int
	)
	if _, err := pgx.ForEachRow(rows, []any{&driver, &group, &iv[classAvail], &iv[classMetrics], &iv[classInventory]}, func() error {
		switch {
		case group != nil:
			t.byGroup[*group] = append(t.byGroup[*group], iv)
		case driver != nil:
			t.byDriver[*driver] = append(t.byDriver[*driver], iv)
		}
		return nil
	}); err != nil {
		return t, fmt.Errorf("poller: load templates: %w", err)
	}
	return t, nil
}

/*
interval is the template interval (seconds) of class c for a device of group g
and driver, or nil: templates of g, then of its ancestors (nearest first), then
of the driver; the first one that sets the class wins, the lowest id first.
*/
func (t templates) interval(g int64, driver string, c class) *int {
	first := func(list [][numClasses]*int) *int {
		for _, iv := range list {
			if iv[c] != nil {
				return iv[c]
			}
		}
		return nil
	}
	at := g
	for range maxGroupDepth {
		if v := first(t.byGroup[at]); v != nil {
			return v
		}
		next, ok := t.parent[at]
		if !ok {
			break
		}
		at = next
	}
	return first(t.byDriver[driver])
}

/* clampInterval turns a database interval (seconds) into a duration within the floor of class c and 24 h. */
func clampInterval(c class, secs int) time.Duration {
	return min(max(time.Duration(secs)*time.Second, minIntervals[c]), maxIntervalDuration)
}

/*
storeIdentity records what Identify learned. The driver is written only while
the device is on "auto"; nothing is written (and nobody is notified) when
nothing changed.
*/
func (p *Poller) storeIdentity(ctx context.Context, id int64, ident drivers.Identity, driver string) error {
	_, err := p.pool.Exec(ctx, `
		UPDATE core.device SET model = nullif($2, ''), firmware = nullif($3, ''), sys_object_id = nullif($4, ''),
			driver = CASE WHEN driver = 'auto' THEN $5 ELSE driver END
		WHERE id = $1 AND (driver = 'auto' OR model IS DISTINCT FROM nullif($2, '')
			OR firmware IS DISTINCT FROM nullif($3, '') OR sys_object_id IS DISTINCT FROM nullif($4, ''))`,
		id, ident.Model, ident.Firmware, ident.SysObjectID, driver)
	if err != nil {
		return fmt.Errorf("poller: store identity: %w", err)
	}
	return nil
}

/*
listen rereads the device list on every device_changed notification (after a
short settle time), every 5 minutes, and after reconnecting.
*/
func (p *Poller) listen(ctx context.Context) {
	for {
		err := p.listenOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		p.log.Warn("device change listener failed", slog.String("err", err.Error()))
		select {
		case <-ctx.Done():
			return
		case <-time.After(relistenAfter):
		}
	}
}

func (p *Poller) listenOnce(ctx context.Context) error {
	c, err := p.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	conn := c.Hijack() /* a LISTENing connection never goes back to the pool */
	defer func() {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), relistenAfter)
		defer cancel()
		_ = conn.Close(cctx)
	}()
	if _, err := conn.Exec(ctx, `LISTEN `+listenChannel); err != nil {
		return err
	}
	/* Reread after LISTEN: no change between the first load and now is missed. */
	if err := p.reload(ctx); err != nil {
		return err
	}
	wait := func(d time.Duration) (bool, error) {
		wctx, cancel := context.WithTimeout(ctx, d)
		defer cancel()
		_, err := conn.WaitForNotification(wctx)
		switch {
		case err == nil:
			return true, nil
		case ctx.Err() == nil && errors.Is(wctx.Err(), context.DeadlineExceeded):
			return false, nil
		default:
			return false, err
		}
	}
	for {
		if _, err := wait(resyncEvery); err != nil {
			return err
		}
		for {
			more, err := wait(settleFor)
			if err != nil {
				return err
			}
			if !more {
				break
			}
		}
		if err := p.reload(ctx); err != nil {
			return err
		}
	}
}
