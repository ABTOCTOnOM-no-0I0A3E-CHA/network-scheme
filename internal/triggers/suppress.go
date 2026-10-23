package triggers

import "time"

/*
suppressGrace is how long before an ancestor's availability problem a
device's own problem may have opened and still count as its consequence: the
parent's duration timer usually ends a little after the children's.
*/
const suppressGrace = 5 * time.Minute

/* maxParentHops bounds the walk up the device tree (the schema allows 16 levels). */
const maxParentHops = 17

/*
suppressCtx is what decides suppression in one cycle: when each device's
availability problem opened (including the ones this cycle opens, excluding
the ones it resolves) and which groups are in an active maintenance window.
*/
type suppressCtx struct {
	avail map[int64]time.Time
	win   map[int64]time.Time /* group -> start of the earliest active window covering it */
}

func (e *Engine) isAvailability(k pkey) bool {
	return k.trig != 0 && e.cfg.trigKind[k.trig] == KindAvailability
}

/*
planSuppression computes, for every problem that stays open, whether it is
suppressed (a device with an ancestor in an open availability problem, or in a
group under maintenance) and queues the flips. A problem is suppressed only if
it did not predate the cause by more than suppressGrace, so a window starting
later or a parent failing long after does not hide a problem that was already
visible; when the cause ends the problem is un-suppressed with one
suppressed_changed event instead of a fresh "opened".
*/
func (e *Engine) planSuppression(a *actions, now time.Time) {
	e.holdPending(a, now)
	s := &suppressCtx{avail: map[int64]time.Time{}, win: e.cfg.windowStarts(now)}
	note := func(dev int64, at time.Time) {
		if t, ok := s.avail[dev]; !ok || at.Before(t) {
			s.avail[dev] = at
		}
	}
	for k, p := range e.open {
		if !a.resSet[k] && e.isAvailability(k) {
			note(k.dev, p.openedAt)
		}
	}
	for _, o := range a.opens {
		if e.isAvailability(o.key) {
			note(o.key.dev, now)
		}
	}
	e.supp = s
	for k, p := range e.open {
		if k.dev == 0 || a.resSet[k] {
			continue
		}
		if want := e.suppressedBy(k.dev, p.openedAt); want != p.suppressed {
			a.flips = append(a.flips, flipReq{p: p, to: want})
		}
	}
}

/* wantSuppressed is the state a problem opening now at dev gets. */
func (e *Engine) wantSuppressed(_ *actions, dev int64, now time.Time) bool {
	if dev == 0 || e.supp == nil {
		return false
	}
	return e.suppressedBy(dev, now)
}

func (e *Engine) suppressedBy(dev int64, openedAt time.Time) bool {
	d := e.cfg.devices[dev]
	if d == nil {
		return false
	}
	if start, ok := e.supp.win[d.groupID]; ok && !openedAt.Before(start) {
		return true
	}
	for par, hops := d.parentID, 0; par != 0 && hops < maxParentHops; hops++ {
		if at, ok := e.supp.avail[par]; ok && !openedAt.Before(at.Add(-suppressGrace)) {
			return true
		}
		pd := e.cfg.devices[par]
		if pd == nil {
			break
		}
		par = pd.parentID
	}
	return false
}

/* holdMax bounds how long an opening waits for an ancestor's outage to be decided. */
const holdMax = 15 * time.Minute

/* heldReq is an opening postponed because an ancestor's outage is still pending. */
type heldReq struct {
	req   openReq
	since time.Time
}

/*
holdPending postpones the openings of devices that have an ancestor whose
availability condition fires but whose problem is not open yet (its duration
has not elapsed). Only openings that are recomputed from current data (availability,
samples, system checks) are held: an opening that came from a syslog or trap row is
stored at once, because the stream position moves past the row in the same
transaction and nothing would read it again after a restart; if its ancestor's
problem opens later, the retroactive flip suppresses it. Without this, children whose own timers end first would
open unsuppressed and notify, defeating the suppression. A held opening is
offered again every cycle: when the ancestor's problem opens, it opens
suppressed; when the ancestor recovers, it opens normally (its own condition
has been satisfied meanwhile). Nothing is held longer than holdMax. Openings
that were never actually opened are dropped when their own condition ends
(see actions.resolve and the evaluators).
*/
func (e *Engine) holdPending(a *actions, now time.Time) {
	for k, h := range e.held {
		if e.open[k] != nil {
			delete(e.held, k)
			continue
		}
		/* A trigger that no longer applies (or a device that is gone) must not get its postponed opening. */
		if _, ok := e.cfg.devices[k.dev]; (k.dev != 0 && !ok) || (k.trig != 0 && e.cfg.eff[k.dev][k.trig] == nil) {
			delete(e.held, k)
			continue
		}
		if !a.openSet[k] {
			a.openSet[k] = true
			a.opens = append(a.opens, h.req)
		}
	}
	hasOpen := map[int64]bool{}
	for k := range e.open {
		if e.isAvailability(k) && !a.resSet[k] {
			hasOpen[k.dev] = true
		}
	}
	for k := range a.openSet {
		if e.isAvailability(k) {
			hasOpen[k.dev] = true
		}
	}
	pending := map[int64]bool{}
	for dev := range e.availFire {
		if !hasOpen[dev] {
			pending[dev] = true
		}
	}
	if len(pending) == 0 {
		for k := range e.held {
			delete(e.held, k)
		}
		return
	}
	kept := a.opens[:0]
	for _, r := range a.opens {
		h, wasHeld := e.held[r.key]
		if !wasHeld {
			h = heldReq{req: r, since: now}
		}
		if !r.event && r.key.dev != 0 && now.Sub(h.since) < holdMax && e.ancestorPending(r.key.dev, pending) {
			e.held[r.key] = h
			delete(a.openSet, r.key)
			continue
		}
		delete(e.held, r.key)
		kept = append(kept, r)
	}
	a.opens = kept
}

/* ancestorPending reports whether an ancestor of dev (not dev itself) is in pending. */
func (e *Engine) ancestorPending(dev int64, pending map[int64]bool) bool {
	d := e.cfg.devices[dev]
	for hops := 0; d != nil && d.parentID != 0 && hops < maxParentHops; hops++ {
		if pending[d.parentID] {
			return true
		}
		d = e.cfg.devices[d.parentID]
	}
	return false
}
