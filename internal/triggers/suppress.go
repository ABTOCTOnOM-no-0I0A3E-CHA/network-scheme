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
