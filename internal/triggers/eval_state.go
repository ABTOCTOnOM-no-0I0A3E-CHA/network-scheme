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
	delete(e.held, k) /* a postponed opening of a condition that has ended is dropped */
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
	e.availFire = map[int64]bool{}
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
			e.availFire[dt.dev] = true
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
			delete(e.held, k)
			continue
		}
		tr := e.tracker(tkey{dt.t.id, dt.dev, ""})
		if tr.falses++; tr.falses >= recoverEvals {
			a.resolve(e, k, reasonRecovered, "state "+st.state, time.Time{})
		}
	}
	return nil
}

/* Windows of the sample reads: an overlap against late rows, how far back a fresh start looks, and the paging. */
const (
	sampleOverlap  = 45 * time.Second
	sampleInitial  = 3 * time.Minute
	inventoryEvery = 5 * time.Minute /* full re-read of the interface inventory for the seen-up set */
)

/*
evalSamples reads the interface and system samples written since the last
round (with an overlap; applying a sample twice is a no-op) and applies the
link-state and metric-threshold triggers. Reads are paged by timestamp, up to
samplePages pages per round: a round that cannot reach "now" saves the point it
reached, and the next round continues from there (minus the overlap), so a
large backlog or overlap cannot stall the stream.
*/
func (e *Engine) evalSamples(ctx context.Context, a *actions, now time.Time) error {
	from := now.Add(-sampleInitial)
	if !e.sampleTo.IsZero() {
		from = e.sampleTo
		if !e.sampleCut {
			from = e.sampleTo.Add(-sampleOverlap) /* the overlap only guards against late rows; a continued backlog needs none */
		}
	}
	done := now
	if len(e.cfg.sysTrigs) > 0 {
		cur := from
		for page := 0; ; page++ {
			pts, err := e.samples.SysSince(ctx, cur, now, samplePage)
			if err != nil {
				return err
			}
			for _, p := range pts {
				for _, t := range e.cfg.sysTrigs[p.DeviceID] {
					e.sysSample(a, t, p)
				}
			}
			if len(pts) < samplePage {
				break
			}
			cur = nextCursor(cur, pts[len(pts)-1].TS)
			if page+1 >= samplePages {
				done = minTime(done, cur)
				break
			}
		}
	}
	if len(e.cfg.ifTrigs) > 0 {
		if err := e.refreshSeenUp(ctx, from, now); err != nil {
			return err
		}
		f := IfFilter{DeviceIDs: make([]int64, 0, len(e.cfg.ifTrigs))}
		for d := range e.cfg.ifTrigs {
			f.DeviceIDs = append(f.DeviceIDs, d)
		}
		if !e.cfg.ifFull {
			/* Only down samples matter, plus the samples of devices that have something to recover or confirm. */
			f.DownOrDeviceIDs = e.watchedIfDevices()
		}
		cur := from
		for page := 0; ; page++ {
			pts, err := e.samples.IfSince(ctx, cur, now, f, samplePage)
			if err != nil {
				return err
			}
			for _, p := range pts {
				obj := "if:" + strconv.Itoa(p.IfIndex)
				for _, t := range e.cfg.ifTrigs[p.DeviceID] {
					e.ifSample(a, t, p, obj)
				}
			}
			if len(pts) < samplePage {
				break
			}
			cur = nextCursor(cur, pts[len(pts)-1].TS)
			if page+1 >= samplePages {
				done = minTime(done, cur)
				break
			}
		}
	}
	a.sampleTo, a.sampleCut = done, done.Before(now)
	e.pruneTrackers(a, from)
	return nil
}

/*
nextCursor is where the next page starts: just before the last timestamp read
(reading that instant again is harmless, the trackers ignore applied samples),
so rows sharing the boundary timestamp are not skipped; if that would not move
forward, the last timestamp itself, which guarantees progress.
*/
func nextCursor(cur, last time.Time) time.Time {
	if n := last.Add(-time.Microsecond); n.After(cur) {
		return n
	}
	return last
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

/*
refreshSeenUp feeds the seen-up set that "any interface" triggers use to tell
a transition from a port that was never up. Two sources: the metric samples
of the read window (every port that reported oper-up, also on devices the
cheap down-only read does not fetch), and the interface inventory, read in
full at start and every inventoryEvery (a full read, not a cursor, so a late
or older row cannot be missed). The set only grows. A port that is already
down when the engine starts, with no open problem, stays quiet until it comes
up (or a linkDown trap reports it).
*/
func (e *Engine) refreshSeenUp(ctx context.Context, from, to time.Time) error {
	need := false
	for _, dt := range e.cfg.byKind[KindIfOperDown] {
		if dt.t.params.(*IfOperDown).IfIndex == nil {
			need = true
			break
		}
	}
	if !need {
		return nil
	}
	keys, err := e.samples.IfUpSince(ctx, from, to)
	if err != nil {
		return err
	}
	for _, k := range keys {
		e.markUp([2]int64{k.DeviceID, int64(k.IfIndex)}, k.FirstUp)
	}
	if !e.upAt.IsZero() && to.Sub(e.upAt) < inventoryEvery {
		return nil
	}
	rows, err := e.pool.Query(ctx, `SELECT device_id, if_index FROM inventory.interface WHERE oper_up`)
	if err != nil {
		return fmt.Errorf("triggers: read interface inventory: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var d int64
		var x int32
		if err := rows.Scan(&d, &x); err != nil {
			return fmt.Errorf("triggers: read interface inventory: %w", err)
		}
		e.markUp([2]int64{d, int64(x)}, time.Time{}) /* up before any sample we hold */
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("triggers: read interface inventory: %w", err)
	}
	e.upAt = to
	return nil
}

/* markUp records that an interface was up at ts, keeping the earliest such time. */
func (e *Engine) markUp(k [2]int64, ts time.Time) {
	if cur, ok := e.seenUp[k]; !ok || ts.Before(cur) {
		e.seenUp[k] = ts
	}
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
		if par.IfIndex == nil {
			/* "Any interface" reports transitions only: a port never seen up (unused) stays quiet. */
			k := [2]int64{p.DeviceID, int64(p.IfIndex)}
			if p.OperUp {
				e.markUp(k, p.TS)
			} else if fu, ok := e.seenUp[k]; !ok || !p.TS.After(fu) {
				return /* never up, or this sample precedes the first time it was seen up */
			}
		}
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
