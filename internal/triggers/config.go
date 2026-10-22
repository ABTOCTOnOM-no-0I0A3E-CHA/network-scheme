package triggers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

/* effTrigger is a trigger as it applies to one device: overrides merged and params re-validated. */
type effTrigger struct {
	id       int64
	name     string
	kind     Kind
	params   Params
	duration time.Duration
	severity string
}

type deviceInfo struct {
	id, groupID, parentID int64 /* parentID 0: none */
	name                  string
}

type window struct {
	groupID    int64
	start, end time.Time
}

/* devTrigger pairs a device with one of its effective triggers. */
type devTrigger struct {
	dev int64
	t   *effTrigger
}

/*
config is one consistent snapshot of devices, groups, effective triggers and
maintenance windows. Everything in it was read in one transaction and every
trigger's params were parsed again with Parse: the engine never trusts the
database to hold valid parameters.
*/
type config struct {
	devices     map[int64]*deviceInfo
	groupParent map[int64]int64
	trigKind    map[int64]Kind /* every existing trigger, even disabled */
	trigName    map[int64]string
	eff         map[int64]map[int64]*effTrigger /* device -> trigger id -> effective trigger */
	byKind      map[Kind][]devTrigger
	windows     []window
	/* Indexes for the sample evaluators: link and interface-metric triggers, system-metric triggers. */
	ifTrigs  map[int64][]*effTrigger
	sysTrigs map[int64][]*effTrigger
	ifFull   bool /* some trigger needs every interface sample, not only the down ones */
}

type triggerRow struct {
	id, template int64
	kind         Kind
	params       json.RawMessage
	durationS    int
	severity     string
	enabled      bool
	name         string
}

type overrideRow struct {
	enabled  *bool
	params   json.RawMessage
	severity *string
}

/* loadConfig reads the configuration tables in one read-only transaction. */
func loadConfig(ctx context.Context, pool *pgxpool.Pool, now time.Time, log *slog.Logger) (*config, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("triggers: load config: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	c := &config{
		devices: map[int64]*deviceInfo{}, groupParent: map[int64]int64{}, trigKind: map[int64]Kind{}, trigName: map[int64]string{},
		eff: map[int64]map[int64]*effTrigger{}, byKind: map[Kind][]devTrigger{},
	}
	driverOf := map[int64]string{}
	scan := func(q string, each func(pgx.Rows) error, args ...any) error {
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			if err := each(rows); err != nil {
				return err
			}
		}
		return rows.Err()
	}
	err = scan(`SELECT id, name, group_id, driver, coalesce(parent_id, 0) FROM core.device`, func(r pgx.Rows) error {
		d := &deviceInfo{}
		var driver string
		if err := r.Scan(&d.id, &d.name, &d.groupID, &driver, &d.parentID); err != nil {
			return err
		}
		c.devices[d.id], driverOf[d.id] = d, driver
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("triggers: load devices: %w", err)
	}
	err = scan(`SELECT id, coalesce(parent_id, 0) FROM core.device_group`, func(r pgx.Rows) error {
		var id, parent int64
		if err := r.Scan(&id, &parent); err != nil {
			return err
		}
		c.groupParent[id] = parent
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("triggers: load groups: %w", err)
	}
	byDriver, byGroup := map[string][]int64{}, map[int64][]int64{}
	err = scan(`SELECT id, driver, group_id FROM core.monitoring_template`, func(r pgx.Rows) error {
		var id int64
		var driver *string
		var group *int64
		if err := r.Scan(&id, &driver, &group); err != nil {
			return err
		}
		if driver != nil {
			byDriver[*driver] = append(byDriver[*driver], id)
		}
		if group != nil {
			byGroup[*group] = append(byGroup[*group], id)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("triggers: load templates: %w", err)
	}
	byTemplate := map[int64][]*triggerRow{}
	err = scan(`SELECT id, template_id, kind, params, duration_s, severity, enabled, name FROM core.trigger ORDER BY id`, func(r pgx.Rows) error {
		t := &triggerRow{}
		var kind string
		if err := r.Scan(&t.id, &t.template, &kind, &t.params, &t.durationS, &t.severity, &t.enabled, &t.name); err != nil {
			return err
		}
		t.kind = Kind(kind)
		c.trigKind[t.id], c.trigName[t.id] = t.kind, t.name
		byTemplate[t.template] = append(byTemplate[t.template], t)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("triggers: load triggers: %w", err)
	}
	overrides := map[int64]map[int64]overrideRow{} /* device -> trigger -> override */
	err = scan(`SELECT trigger_id, device_id, enabled, params, severity FROM core.trigger_override`, func(r pgx.Rows) error {
		var trig, dev int64
		var o overrideRow
		if err := r.Scan(&trig, &dev, &o.enabled, &o.params, &o.severity); err != nil {
			return err
		}
		if overrides[dev] == nil {
			overrides[dev] = map[int64]overrideRow{}
		}
		overrides[dev][trig] = o
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("triggers: load overrides: %w", err)
	}
	err = scan(`SELECT group_id, starts_at, ends_at FROM core.maintenance_window WHERE ends_at > $1`, func(r pgx.Rows) error {
		var w window
		if err := r.Scan(&w.groupID, &w.start, &w.end); err != nil {
			return err
		}
		c.windows = append(c.windows, w)
		return nil
	}, now)
	if err != nil {
		return nil, fmt.Errorf("triggers: load maintenance windows: %w", err)
	}

	/* Triggers without an override are parsed once and shared by their devices. */
	shared := map[int64]*effTrigger{}
	bad := map[int64]bool{}
	for id, dev := range c.devices {
		var tpls []int64
		tpls = append(tpls, byDriver[driverOf[id]]...)
		for g, hops := dev.groupID, 0; g != 0 && hops < 64; g, hops = c.groupParent[g], hops+1 {
			tpls = append(tpls, byGroup[g]...)
		}
		seenTpl := map[int64]bool{}
		for _, tpl := range tpls {
			if seenTpl[tpl] {
				continue
			}
			seenTpl[tpl] = true
			for _, row := range byTemplate[tpl] {
				ov, hasOv := overrides[id][row.id]
				enabled := row.enabled
				if hasOv && ov.enabled != nil {
					enabled = *ov.enabled
				}
				if !enabled {
					continue
				}
				var et *effTrigger
				if !hasOv {
					if bad[row.id] {
						continue
					}
					if et = shared[row.id]; et == nil {
						var err error
						if et, err = buildEffective(row, nil); err != nil {
							bad[row.id] = true
							log.Warn("trigger skipped: invalid params", slog.Int64("trigger", row.id), slog.String("error", err.Error()))
							continue
						}
						shared[row.id] = et
					}
				} else {
					var err error
					if et, err = buildEffective(row, &ov); err != nil {
						log.Warn("trigger skipped on device: invalid params", slog.Int64("trigger", row.id), slog.Int64("device", id), slog.String("error", err.Error()))
						continue
					}
				}
				if c.eff[id] == nil {
					c.eff[id] = map[int64]*effTrigger{}
				}
				if _, dup := c.eff[id][row.id]; dup {
					continue
				}
				c.eff[id][row.id] = et
				c.byKind[et.kind] = append(c.byKind[et.kind], devTrigger{dev: id, t: et})
			}
		}
	}
	c.index()
	return c, nil
}

/* index fills the per-device lists the sample evaluators walk. */
func (c *config) index() {
	c.ifTrigs, c.sysTrigs = map[int64][]*effTrigger{}, map[int64][]*effTrigger{}
	for _, dt := range c.byKind[KindIfOperDown] {
		c.ifTrigs[dt.dev] = append(c.ifTrigs[dt.dev], dt.t)
	}
	for _, dt := range c.byKind[KindTrap] {
		if dt.t.params.(*Trap).Name == trapLinkDown {
			c.ifTrigs[dt.dev] = append(c.ifTrigs[dt.dev], dt.t)
		}
	}
	for _, dt := range c.byKind[KindMetricThreshold] {
		if m := dt.t.params.(*MetricThreshold); m.isInterfaceMetric() {
			c.ifTrigs[dt.dev], c.ifFull = append(c.ifTrigs[dt.dev], dt.t), true
		} else {
			c.sysTrigs[dt.dev] = append(c.sysTrigs[dt.dev], dt.t)
		}
	}
}

/* buildEffective applies an optional override to a trigger row and re-validates everything. */
func buildEffective(row *triggerRow, ov *overrideRow) (*effTrigger, error) {
	raw, sev := row.params, row.severity
	if ov != nil {
		var err error
		if raw, err = mergeParams(row.params, ov.params); err != nil {
			return nil, err
		}
		if ov.severity != nil {
			sev = *ov.severity
		}
	}
	if !validSeverity(sev) {
		return nil, fmt.Errorf("invalid severity %q", sev)
	}
	if err := ValidateDuration(row.durationS); err != nil {
		return nil, err
	}
	p, err := Parse(string(row.kind), raw)
	if err != nil {
		return nil, err
	}
	return &effTrigger{id: row.id, name: row.name, kind: row.kind, params: p, duration: time.Duration(row.durationS) * time.Second, severity: sev}, nil
}

/* mergeParams lays the override's keys over the trigger's; a nil override keeps the trigger's params. */
func mergeParams(base, over json.RawMessage) (json.RawMessage, error) {
	if len(over) == 0 {
		return base, nil
	}
	var b, o map[string]json.RawMessage
	if err := json.Unmarshal(base, &b); err != nil {
		return nil, fmt.Errorf("trigger params: %w", err)
	}
	if err := json.Unmarshal(over, &o); err != nil {
		return nil, fmt.Errorf("override params: %w", err)
	}
	if b == nil {
		b = map[string]json.RawMessage{}
	}
	for k, v := range o {
		b[k] = v
	}
	return json.Marshal(b)
}

func validSeverity(s string) bool {
	switch s {
	case "info", "warning", "average", "high", "disaster":
		return true
	}
	return false
}

/* windowStarts returns, per group, the earliest start of a maintenance window active at now that covers it (the window's group and its subgroups). */
func (c *config) windowStarts(now time.Time) map[int64]time.Time {
	var active []window
	for _, w := range c.windows {
		if !now.Before(w.start) && now.Before(w.end) {
			active = append(active, w)
		}
	}
	if len(active) == 0 {
		return nil
	}
	out := map[int64]time.Time{}
	for g := range c.groupParent {
		for a, hops := g, 0; a != 0 && hops < 64; a, hops = c.groupParent[a], hops+1 {
			for _, w := range active {
				if w.groupID == a {
					if s, ok := out[g]; !ok || w.start.Before(s) {
						out[g] = w.start
					}
				}
			}
		}
	}
	return out
}
