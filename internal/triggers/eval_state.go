package triggers

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"time"
)

/* Availability states as the device_state_v view reports them. */
const stateUnknown = "unknown"

/* recoverEvals is how many consecutive evaluations must find a condition false before its problem resolves (flapping control). */
const recoverEvals = 2

/*
sample applies one observation of a state condition to a trigger. The
condition must hold for the trigger's duration measured on the data
timestamps (not on when the engine looked), and recovers only after
recoverEvals false observations in a row. Observations at or before the
tracker's last one, or older than a trap fact (floor), are ignored, so
re-reading an overlapping window changes nothing. canOpen false makes the
trigger close-only (a link-down trap trigger is opened by the trap alone).
*/
func (e *Engine) sample(a *actions, t *effTrigger, dev int64, obj string, ts time.Time, cond bool, value string, canOpen bool) {
	k := pkey{trig: t.id, dev: dev, obj: obj}
	p := e.open[k]
	if !canOpen && p == nil {
		return
	}
	tr := e.tracker(tkey{t.id, dev, obj})
	if !ts.After(tr.lastTS) || !ts.After(tr.floor) {
		return
	}
	tr.lastTS = ts
	if cond {
		tr.falses = 0
		if tr.firstTrue.IsZero() {
			tr.firstTrue = ts
		}
		if p == nil && canOpen && ts.Sub(tr.firstTrue) >= t.duration {
			a.open(e, openReq{key: k, severity: t.severity, value: value, evidence: ts})
		}
		return
	}
	tr.firstTrue = time.Time{}
	if p != nil {
		if tr.falses++; tr.falses >= recoverEvals {
			a.resolve(e, k, reasonRecovered, value, ts)
		}
	}
}

type stateRow struct {
	state     string
	since     *time.Time
	lastError string
}

/*
evalAvailability applies the availability triggers. A device in state unknown
(its poller is silent) neither opens nor resolves anything: the system
problem for the poller covers that case.
*/
func (e *Engine) evalAvailability(ctx context.Context, a *actions, now time.Time) error {
	trigs := e.cfg.byKind[KindAvailability]
	if len(trigs) == 0 {
		return nil
	}
	rows, err := e.pool.Query(ctx, `SELECT device_id, state, since, last_error FROM inventory.device_state_v`)
	if err != nil {
		return fmt.Errorf("triggers: read device state: %w", err)
	}
	states := make(map[int64]stateRow, len(e.cfg.devices))
	for rows.Next() {
		var id int64
		var s stateRow
		if err := rows.Scan(&id, &s.state, &s.since, &s.lastError); err != nil {
			rows.Close()
			return fmt.Errorf("triggers: read device state: %w", err)
		}
		states[id] = s
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("triggers: read device state: %w", err)
	}
	for _, dt := range trigs {
		st, ok := states[dt.dev]
		if !ok || st.state == stateUnknown {
			continue
		}
		k := pkey{trig: dt.t.id, dev: dt.dev}
		p := e.open[k]
		fires := slices.Contains(dt.t.params.(*Availability).States, st.state)
		if fires {
			if p != nil {
				e.tracker(tkey{dt.t.id, dt.dev, ""}).falses = 0
			} else if st.since != nil && now.Sub(*st.since) >= dt.t.duration {
				v := "state " + st.state
				if st.lastError != "" {
					v += ": " + st.lastError
				}
				a.open(e, openReq{key: k, severity: dt.t.severity, value: v}) /* stateless: no replay to guard against */
			}
			continue
		}
		if p == nil {
			delete(e.trackers, tkey{dt.t.id, dt.dev, ""})
			continue
		}
		tr := e.tracker(tkey{dt.t.id, dt.dev, ""})
		if tr.falses++; tr.falses >= recoverEvals {
			a.resolve(e, k, reasonRecovered, "state "+st.state, time.Time{})
		}
	}
	return nil
}

/* Windows of the sample reads: an overlap against late rows, and how far back a fresh start looks. */
const (
	sampleOverlap = 45 * time.Second
	sampleInitial = 3 * time.Minute
	sampleLimit   = 1_000_000
)

/*
evalSamples reads the interface and system samples written since the last
round (with an overlap; applying a sample twice is a no-op) and applies the
link-state and metric-threshold triggers.
*/
func (e *Engine) evalSamples(ctx context.Context, a *actions, now time.Time) error {
	from := now.Add(-sampleInitial)
	if !e.sampleTo.IsZero() {
		from = e.sampleTo.Add(-sampleOverlap)
	}
	to := now
	if len(e.cfg.sysTrigs) > 0 {
		pts, err := e.samples.SysSince(ctx, from, to, sampleLimit)
		if err != nil {
			return err
		}
		if len(pts) == sampleLimit {
			to = pts[len(pts)-1].TS
		}
		for _, p := range pts {
			for _, t := range e.cfg.sysTrigs[p.DeviceID] {
				e.sysSample(a, t, p)
			}
		}
	}
	if len(e.cfg.ifTrigs) > 0 {
		f := IfFilter{DeviceIDs: make([]int64, 0, len(e.cfg.ifTrigs))}
		for d := range e.cfg.ifTrigs {
			f.DeviceIDs = append(f.DeviceIDs, d)
		}
		if !e.cfg.ifFull {
			/* Only down samples matter, plus the samples of devices that have something to recover or confirm. */
			f.DownOrDeviceIDs = e.watchedIfDevices()
		}
		pts, err := e.samples.IfSince(ctx, from, to, f, sampleLimit)
		if err != nil {
			return err
		}
		if len(pts) == sampleLimit {
			to = pts[len(pts)-1].TS
		}
		for _, p := range pts {
			obj := "if:" + strconv.Itoa(p.IfIndex)
			for _, t := range e.cfg.ifTrigs[p.DeviceID] {
				e.ifSample(a, t, p, obj)
			}
		}
	}
	a.sampleTo = to
	e.pruneTrackers(a, from)
	return nil
}

/* watchedIfDevices lists the devices with an open interface problem or a pending interface condition; never nil. */
func (e *Engine) watchedIfDevices() []int64 {
	set := map[int64]bool{}
	for k := range e.open {
		if k.trig != 0 && len(k.obj) > 0 {
			set[k.dev] = true
		}
	}
	for k, tr := range e.trackers {
		if !tr.firstTrue.IsZero() && len(k.obj) > 0 {
			set[k.dev] = true
		}
	}
	out := make([]int64, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	return out
}

/* pruneTrackers drops trackers that carry no state: nothing pending, nothing open and older than the read window. */
func (e *Engine) pruneTrackers(a *actions, from time.Time) {
	for k, tr := range e.trackers {
		pk := pkey{trig: k.trig, dev: k.dev, obj: k.obj}
		if tr.lastTS.Before(from) && tr.floor.Before(from) && tr.firstTrue.IsZero() && e.open[pk] == nil && !a.openSet[pk] {
			delete(e.trackers, k)
		}
	}
}

/* ifSample applies one interface sample to one trigger of its device. */
func (e *Engine) ifSample(a *actions, t *effTrigger, p IfSample, obj string) {
	switch par := t.params.(type) {
	case *IfOperDown:
		if par.IfIndex == nil || *par.IfIndex == p.IfIndex {
			e.sample(a, t, p.DeviceID, obj, p.TS, !p.OperUp, "oper down", true)
		}
	case *Trap:
		/* A link-down trap trigger is closed by a poll that sees the interface up; only the trap opens it. */
		e.sample(a, t, p.DeviceID, obj, p.TS, !p.OperUp, "oper "+upDown(p.OperUp), false)
	case *MetricThreshold:
		if par.IfIndex != nil && *par.IfIndex != p.IfIndex {
			return
		}
		if v, ok := ifMetricValue(par.Metric, p); ok {
			e.sample(a, t, p.DeviceID, obj, p.TS, par.holds(v), par.describe(v), true)
		}
	}
}

func upDown(up bool) string {
	if up {
		return "up"
	}
	return "down"
}

/*
enrichInterfaceNames prefixes the values of interface problems about to open
with the interface name from the inventory (best effort, one query).
*/
func (e *Engine) enrichInterfaceNames(ctx context.Context, a *actions) {
	var devs []int64
	var idx []int32
	var at []int
	for i, r := range a.opens {
		if r.key.trig == 0 || len(r.key.obj) < 4 {
			continue
		}
		n, err := strconv.ParseInt(r.key.obj[3:], 10, 32)
		if err != nil {
			continue
		}
		devs, idx, at = append(devs, r.key.dev), append(idx, int32(n)), append(at, i) // #nosec G115 -- ParseInt bit size 32
	}
	if len(devs) == 0 {
		return
	}
	rows, err := e.pool.Query(ctx, `SELECT i.device_id, i.if_index, i.name FROM inventory.interface i
		JOIN unnest($1::bigint[], $2::int[]) AS w(d, x) ON w.d = i.device_id AND w.x = i.if_index`, devs, idx)
	if err != nil {
		return
	}
	names := map[[2]int64]string{}
	for rows.Next() {
		var d int64
		var x int32
		var n string
		if rows.Scan(&d, &x, &n) == nil {
			names[[2]int64{d, int64(x)}] = n
		}
	}
	rows.Close()
	for j, i := range at {
		if n, ok := names[[2]int64{devs[j], int64(idx[j])}]; ok && n != "" {
			a.opens[i].value = sanitize(n + ": " + a.opens[i].value)
		}
	}
}
