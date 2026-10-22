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

/* loadDevices reads the devices assigned to this poller with their effective intervals. */
func (p *Poller) loadDevices(ctx context.Context) ([]device, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT d.id, d.address, d.snmp_port, d.driver,
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
			d    device
			addr netip.Addr
			port int
			iv   [numClasses]*int
		)
		if err := r.Scan(&d.ID, &addr, &port, &d.Driver, &iv[classAvail], &iv[classMetrics], &iv[classInventory]); err != nil {
			return d, err
		}
		d.Addr = netip.AddrPortFrom(addr.Unmap(), uint16(port)) // #nosec G115 -- CHECK 1..65535 in the schema
		for c := range numClasses {
			d.Intervals[c] = def[c]
			if iv[c] != nil {
				d.Intervals[c] = clampInterval(c, *iv[c])
			}
		}
		return d, nil
	})
	if err != nil {
		return nil, fmt.Errorf("poller: load devices: %w", err)
	}
	return devs, nil
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
