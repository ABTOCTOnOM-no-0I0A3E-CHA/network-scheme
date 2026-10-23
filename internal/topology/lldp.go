package topology

import (
	"context"
	"sort"
)

/*
Confidence of a link by the strongest evidence behind it (percent; core.link
stores it as 0..1). Only data the reporting device does not control alone can
lift a one-sided link above 0.5.
*/
const (
	confMutual = 100 /* both sides report each other and at least one port name agrees */
	confAddr   = 80  /* one side by management address, and the neighbour's own MAC table learns the reporter on the port it names */
	confWeak   = 50  /* one side only, or only chassis / sys_name: a spoofer can say all of that */
	confMAC    = 40
	sourceLLDP = "lldp"
	sourceMAC  = "mac"

	/* confUnproven is a pair that reports each other but gives no port name that agrees: not proof, so below 1.0. */
	confUnproven = 80
	/* maxPairLinks bounds the links kept per device pair. */
	maxPairLinks = 64
)

type method int

const (
	byAddr method = iota
	byChassis
	byName
)

/* link is a link between two devices in canonical order (a < b); a zero port is unknown (NULL). */
type link struct {
	a      int64
	ai     int32
	b      int64
	bi     int32
	source string
	conf   int32
}

type linkKey struct {
	a, b   int64
	ai, bi int32
}

func (l link) key() linkKey { return linkKey{l.a, l.b, l.ai, l.bi} }

/* canon puts the ends in canonical order. */
func canon(x int64, xi int32, y int64, yi int32, source string, conf int32) link {
	if x > y {
		x, xi, y, yi = y, yi, x, xi
	}
	return link{a: x, ai: xi, b: y, bi: yi, source: source, conf: conf}
}

/* stop checks the context every 1024th call, so long loops end soon after the build timeout. */
func stop(ctx context.Context, i int) error {
	if i&1023 == 0 {
		return ctx.Err()
	}
	return nil
}

/* cand is an LLDP row matched to a known device. */
type cand struct {
	row    *lldpRow
	target int64 /* the device the row says is on the other end */
	method method
	remote int32 /* the target's port the row names, when port_id is exactly one interface of the target */
}

/*
matchRows applies the matching rules to every row, strongest first, and drops
rows whose evidence contradicts itself:

 1. The neighbour's management address is the address of exactly one device.
 2. The neighbour's chassis id is a chassis learned for exactly one device
    (chassisOf; learned only from rows the other side confirmed, see derive).
 3. The neighbour's sys_name is the name of exactly one device.

A row where two rules point at different devices is a spoofing signal and is
dropped. A device never matches itself.
*/
func matchRows(ctx context.Context, in *inputs, chassisOf map[string]int64) ([]cand, error) {
	out := make([]cand, 0, len(in.lldp))
	for i := range in.lldp {
		if err := stop(ctx, i); err != nil {
			return nil, err
		}
		r := &in.lldp[i]
		var t1, tn int64
		if r.mgmt.IsValid() {
			t1 = in.byAddr[r.mgmt]
		}
		if r.sysName != "" {
			tn = in.byName[r.sysName]
		}
		tc := chassisOf[r.chassis] /* -1: contested chassis, no evidence */
		var t int64
		var m method
		switch {
		case t1 != 0:
			t, m = t1, byAddr
			if (tn != 0 && tn != t1) || (tc > 0 && tc != t1) {
				continue
			}
		case tc > 0:
			t, m = tc, byChassis
			if tn != 0 && tn != tc {
				continue
			}
		case tn != 0:
			t, m = tn, byName
		default:
			continue
		}
		if t == r.dev {
			continue
		}
		out = append(out, cand{row: r, target: t, method: m, remote: in.portIf[textKey{t, r.portID}]})
	}
	return out, nil
}

/* learn records that chassis belongs to dev; a chassis claimed for two devices becomes contested (-1) for good. */
func learn(chassisOf map[string]int64, chassis string, dev int64) bool {
	old := chassisOf[chassis]
	switch {
	case old == dev || old < 0:
		return false
	case old == 0:
		chassisOf[chassis] = dev
	default:
		chassisOf[chassis] = -1
	}
	return true
}

/*
pairing decides which rows confirm each other. Rows between devices a < b are
reported by a about b (lo) and by b about a (hi). A lo and a hi row confirm
each other if their ports agree:

  - each side's port_id, when it names exactly one interface of the other
    device, must not name a different one than the row on that device reports
    as its local port;
  - strong: at least one such name positively agrees. Otherwise (weak) the pair
    must be the only rows between the two devices in both directions and both
    rows must be matched by address or chassis (a name alone is not enough).

partner[i] is the confirming row of row i (-1: none); strong[i] tells whether
the pair has port proof. dropped[i] is set for a row nobody confirms while the
other device does report on the same pair but only through other ports: that
row contradicts the other device's table and is discarded (this is what stops
a spoofer on one port from riding on the real device's reports on another).
The work is bounded by the per-reporter row cap of load.
*/
func pairing(ctx context.Context, cs []cand) (partner []int, strong, dropped []bool, err error) {
	partner = make([]int, len(cs))
	strong = make([]bool, len(cs))
	dropped = make([]bool, len(cs))
	for i := range partner {
		partner[i] = -1
	}
	type grp struct{ lo, hi []int }
	groups := map[[2]int64]*grp{}
	for i, c := range cs {
		k := [2]int64{c.row.dev, c.target}
		low := k[0] < k[1]
		if !low {
			k = [2]int64{k[1], k[0]}
		}
		g := groups[k]
		if g == nil {
			g = &grp{}
			groups[k] = g
		}
		if low {
			g.lo = append(g.lo, i)
		} else {
			g.hi = append(g.hi, i)
		}
	}
	compat := func(lo, hi cand) (ok, strong bool) {
		x, y := hi.remote, lo.remote /* x: a's port named by b; y: b's port named by a */
		ifA, ifB := lo.row.ifx, hi.row.ifx
		if (x != 0 && ifA != 0 && x != ifA) || (y != 0 && ifB != 0 && y != ifB) {
			return false, false
		}
		return true, (x != 0 && x == ifA) || (y != 0 && y == ifB)
	}
	n := 0
	for _, g := range groups {
		if err := stop(ctx, n); err != nil {
			return nil, nil, nil, err
		}
		n++
		/* strong pairs are found through indexes on the ports the rows name, not by comparing all rows */
		hiByIf, hiByRemote := map[int32][]int{}, map[int32][]int{}
		for _, j := range g.hi {
			if cs[j].row.ifx != 0 {
				hiByIf[cs[j].row.ifx] = append(hiByIf[cs[j].row.ifx], j)
			}
			if cs[j].remote != 0 {
				hiByRemote[cs[j].remote] = append(hiByRemote[cs[j].remote], j)
			}
		}
		try := func(i int, js []int) bool {
			for _, j := range js {
				if partner[j] >= 0 {
					continue
				}
				if ok, st := compat(cs[i], cs[j]); ok && st {
					partner[i], partner[j] = j, i
					strong[i], strong[j] = true, true
					return true
				}
			}
			return false
		}
		for _, i := range g.lo {
			if cs[i].row.ifx != 0 && try(i, hiByRemote[cs[i].row.ifx]) {
				continue
			}
			if cs[i].remote != 0 {
				try(i, hiByIf[cs[i].remote])
			}
		}
		if len(g.lo) == 1 && len(g.hi) == 1 {
			i, j := g.lo[0], g.hi[0]
			if ok, _ := compat(cs[i], cs[j]); ok && partner[i] < 0 && cs[i].method != byName && cs[j].method != byName {
				partner[i], partner[j] = j, i
			}
		}
		contradicted := func(own, other []int) {
			if len(other) == 0 {
				return
			}
			for _, j := range other {
				if partner[j] < 0 {
					return
				}
			}
			for _, i := range own {
				if partner[i] < 0 {
					dropped[i] = true
				}
			}
		}
		contradicted(g.lo, g.hi)
		contradicted(g.hi, g.lo)
	}
	return partner, strong, dropped, nil
}

/* corroborated: the neighbour's own MAC table learns the reporter's MAC on the port the row names, which the reporter does not control. */
func corroborated(in *inputs, c cand) bool {
	if c.method != byAddr || c.remote == 0 {
		return false
	}
	for _, o := range in.stations[ifKey{c.target, c.remote}] {
		if o == c.row.dev {
			return true
		}
	}
	return false
}

/*
derive computes the links the inventory supports. The chassis -> device map is
learned only from rows the other side confirmed with port proof (mutual
pairs): a chassis claimed on an unconfirmed row teaches nothing, so a spoofer
cannot poison it. Matching is repeated while the map grows (at most three
rounds), because a newly learned chassis can match more rows.
*/
func derive(ctx context.Context, in *inputs) ([]link, error) {
	chassisOf := map[string]int64{}
	var cs []cand
	var partner []int
	var strong, dropped []bool
	for round := 0; round < 3; round++ {
		var err error
		if cs, err = matchRows(ctx, in, chassisOf); err != nil {
			return nil, err
		}
		if partner, strong, dropped, err = pairing(ctx, cs); err != nil {
			return nil, err
		}
		changed := false
		for i, c := range cs {
			if partner[i] >= 0 && strong[i] && !dropped[i] {
				changed = learn(chassisOf, c.row.chassis, c.target) || changed
			}
		}
		if !changed {
			break
		}
	}
	best := map[linkKey]link{}
	put := func(l link) {
		if old, ok := best[l.key()]; !ok || l.conf > old.conf {
			best[l.key()] = l
		}
	}
	for i, c := range cs {
		if err := stop(ctx, i); err != nil {
			return nil, err
		}
		if dropped[i] {
			continue
		}
		if p := partner[i]; p >= 0 {
			if c.row.dev > c.target {
				continue /* the lo row of the pair makes the link */
			}
			o := cs[p]
			ai, bi := c.row.ifx, o.row.ifx
			if ai == 0 {
				ai = o.remote
			}
			if bi == 0 {
				bi = c.remote
			}
			conf := int32(confUnproven)
			if strong[i] {
				conf = confMutual
			}
			put(canon(c.row.dev, ai, c.target, bi, sourceLLDP, conf))
			continue
		}
		var conf int32 = confWeak
		if corroborated(in, c) {
			conf = confAddr
		}
		put(canon(c.row.dev, c.row.ifx, c.target, c.remote, sourceLLDP, conf))
	}
	for _, l := range inferMAC(in) {
		put(l)
	}
	out := make([]link, 0, len(best))
	for _, l := range best {
		out = append(out, l)
	}
	out, err := mergeNull(ctx, out)
	if err != nil {
		return nil, err
	}
	return capPairs(out), nil
}

/* capPairs keeps the maxPairLinks strongest links per device pair and sorts the result. */
func capPairs(ls []link) []link {
	sort.Slice(ls, func(i, j int) bool {
		x, y := ls[i], ls[j]
		if x.a != y.a {
			return x.a < y.a
		}
		if x.b != y.b {
			return x.b < y.b
		}
		if x.conf != y.conf {
			return x.conf > y.conf
		}
		return lessKey(x.key(), y.key())
	})
	out := make([]link, 0, len(ls))
	n := 0
	for i, l := range ls {
		if i == 0 || l.a != ls[i-1].a || l.b != ls[i-1].b {
			n = 0
		}
		if n++; n <= maxPairLinks {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool { return lessKey(out[i].key(), out[j].key()) })
	return out
}

func lessKey(x, y linkKey) bool {
	switch {
	case x.a != y.a:
		return x.a < y.a
	case x.b != y.b:
		return x.b < y.b
	case x.ai != y.ai:
		return x.ai < y.ai
	}
	return x.bi < y.bi
}
