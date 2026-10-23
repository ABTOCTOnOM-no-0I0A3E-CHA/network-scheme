package topology

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

/* sideOK: two ports of one end may be the same cable: equal, or one is unknown (zero). */
func sideOK(p, q int32) bool { return p == 0 || q == 0 || p == q }

/* sameCable reports whether x and y connect the same devices through ports that can be one cable. */
func sameCable(x, y link) bool {
	return x.a == y.a && x.b == y.b && sideOK(x.ai, y.ai) && sideOK(x.bi, y.bi)
}

func specificity(l link) int {
	n := 0
	if l.ai != 0 {
		n++
	}
	if l.bi != 0 {
		n++
	}
	return n
}

type portKey struct {
	a, b int64
	p    int32
}

/*
mergeNull makes sure one cable is one link. A link with an unknown port that
can be the same cable as a more specific link between the same devices (a MAC
inference (A,1,B,NULL) next to LLDP (A,1,B,2)) is folded into it: the specific
ports win and, when there is exactly one such link, the stronger evidence
(confidence and source) is kept; with several candidates the link is subsumed
by them all and simply dropped. Candidates are found through indexes on the
known port, so the work is linear in the number of links (a link with both
ports unknown is compared with its pair once).
*/
func mergeNull(ctx context.Context, ls []link) ([]link, error) {
	byPair := map[[2]int64][]int{}
	byA, byB := map[portKey][]int{}, map[portKey][]int{} /* fully specific links by either port */
	for i, l := range ls {
		k := [2]int64{l.a, l.b}
		byPair[k] = append(byPair[k], i)
		if specificity(l) == 2 {
			byA[portKey{l.a, l.b, l.ai}] = append(byA[portKey{l.a, l.b, l.ai}], i)
			byB[portKey{l.a, l.b, l.bi}] = append(byB[portKey{l.a, l.b, l.bi}], i)
		}
	}
	order := make([]int, 0, len(ls))
	for i, l := range ls {
		if specificity(l) < 2 {
			order = append(order, i)
		}
	}
	sort.Slice(order, func(x, y int) bool {
		i, j := order[x], order[y]
		if si, sj := specificity(ls[i]), specificity(ls[j]); si != sj {
			return si < sj
		}
		return lessKey(ls[i].key(), ls[j].key())
	})
	removed := make([]bool, len(ls))
	for n, i := range order {
		if err := stop(ctx, n); err != nil {
			return nil, err
		}
		var pool []int
		switch l := ls[i]; {
		case specificity(l) == 0:
			pool = byPair[[2]int64{l.a, l.b}]
		case l.ai != 0:
			pool = byA[portKey{l.a, l.b, l.ai}]
		default:
			pool = byB[portKey{l.a, l.b, l.bi}]
		}
		best, cands := -1, 0
		for _, j := range pool {
			if j == i || removed[j] || specificity(ls[j]) <= specificity(ls[i]) || !sameCable(ls[i], ls[j]) {
				continue
			}
			cands++
			if best < 0 || ls[j].conf > ls[best].conf || (ls[j].conf == ls[best].conf && lessKey(ls[j].key(), ls[best].key())) {
				best = j
			}
		}
		if best < 0 {
			continue
		}
		if cands == 1 && ls[i].conf > ls[best].conf {
			ls[best].conf, ls[best].source = ls[i].conf, ls[i].source
		}
		removed[i] = true
	}
	out := make([]link, 0, len(ls))
	for i, l := range ls {
		if !removed[i] {
			out = append(out, l)
		}
	}
	return out, nil
}

type stored struct {
	id     int64
	l      link
	manual bool
	misses int
}

func loadLinks(ctx context.Context, tx pgx.Tx) ([]stored, error) {
	rows, err := tx.Query(ctx, `SELECT id, a_device_id, coalesce(a_if_index, 0), b_device_id, coalesce(b_if_index, 0), source,
		round(confidence * 100)::int, manual, misses FROM core.link ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("links: %w", err)
	}
	defer rows.Close()
	var out []stored
	for rows.Next() {
		var s stored
		if err := rows.Scan(&s.id, &s.l.a, &s.l.ai, &s.l.b, &s.l.bi, &s.l.source, &s.l.conf, &s.manual, &s.misses); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

/*
apply reconciles core.link with the derived links inside tx. Rules:

  - Manual links are never changed or deleted (every write also carries
    "NOT manual"). A manual link suppresses automatic links between the same
    devices: always when a nonzero port of it equals one of the automatic
    link's; a manual port that is unknown is a wildcard only when the pair has
    at most one automatic link (otherwise it would hide parallel cables). A
    stored automatic link so suppressed disappears with a history entry.
  - A stored automatic link that is derived again is confirmed (misses = 0). If
    only its ports got more or less specific it is updated in place, not
    recreated. A duplicate of a cable that another stored link already covers
    is removed silently.
  - A link not derived is counted as missed only (a) while one of its devices
    is up under a fresh poller heartbeat, and (b) once per inventory refresh:
    markers holds, per missing link, the newest inventory time (seen_at of the
    ends' interface and LLDP rows) already counted, so rebuilding without a
    new poll adds no miss. It disappears at the MissLimit-th counted miss.
  - New links are inserted. Every appearance and disappearance writes a
    core.link_change row in the same statement.

markers is updated in place; the caller keeps it only if the transaction commits.
*/
func apply(ctx context.Context, tx pgx.Tx, in *inputs, want []link, now time.Time, markers map[int64]time.Time) (Result, error) {
	var got bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, fenceKey).Scan(&got); err != nil {
		return Result{}, fmt.Errorf("fence: %w", err)
	}
	if !got {
		return Result{}, fmt.Errorf("another topology build is running")
	}
	cur, err := loadLinks(ctx, tx)
	if err != nil {
		return Result{}, err
	}
	manual := map[[2]int64][]link{}
	taken := map[linkKey]bool{} /* identities in use (any link) */
	autoKeys := map[[2]int64]map[linkKey]bool{}
	note := func(l link) {
		k := [2]int64{l.a, l.b}
		if autoKeys[k] == nil {
			autoKeys[k] = map[linkKey]bool{}
		}
		autoKeys[k][l.key()] = true
	}
	var autos []stored
	for _, s := range cur {
		taken[s.l.key()] = true
		if s.manual {
			k := [2]int64{s.l.a, s.l.b}
			manual[k] = append(manual[k], s.l)
		} else {
			autos = append(autos, s)
			note(s.l)
		}
	}
	for _, w := range want {
		note(w)
	}
	suppressed := func(l link) bool {
		pair := [2]int64{l.a, l.b}
		for _, m := range manual[pair] {
			if !sameCable(l, m) {
				continue
			}
			if (m.ai != 0 && m.ai == l.ai) || (m.bi != 0 && m.bi == l.bi) || len(autoKeys[pair]) <= 1 {
				return true
			}
		}
		return false
	}
	var live []link
	for _, w := range want {
		if !suppressed(w) {
			live = append(live, w)
		}
	}
	wantAt := map[linkKey]int{}
	for i, w := range live {
		wantAt[w.key()] = i
	}
	used := make([]bool, len(live))

	type upd struct {
		id int64
		l  link
	}
	var confirm []upd /* same identity */
	var rekey []upd   /* same cable, other ports */
	var silent, gone, miss []int64
	var rest []stored
	kept := 0
	for n, s := range autos {
		if err := stop(ctx, n); err != nil {
			return Result{}, err
		}
		if i, ok := wantAt[s.l.key()]; ok && !used[i] {
			used[i] = true
			confirm = append(confirm, upd{s.id, live[i]})
			kept++
			continue
		}
		rest = append(rest, s)
	}
	byPair := map[[2]int64][]int{}
	for i, w := range live {
		k := [2]int64{w.a, w.b}
		byPair[k] = append(byPair[k], i)
	}
	var left []stored
	for n, s := range rest {
		if err := stop(ctx, n); err != nil {
			return Result{}, err
		}
		if suppressed(s.l) {
			gone = append(gone, s.id)
			continue
		}
		best, covered := -1, false
		for _, i := range byPair[[2]int64{s.l.a, s.l.b}] {
			if !sameCable(s.l, live[i]) {
				continue
			}
			if used[i] {
				covered = true
				continue
			}
			if !taken[live[i].key()] && (best < 0 || specificity(live[i]) > specificity(live[best])) {
				best = i
			}
		}
		switch {
		case best >= 0:
			used[best] = true
			taken[live[best].key()] = true
			rekey = append(rekey, upd{s.id, live[best]})
			kept++
		case covered:
			silent = append(silent, s.id)
		default:
			left = append(left, s)
		}
	}
	next := map[int64]time.Time{}
	for _, s := range left {
		inv := in.invAt[s.l.a]
		if t := in.invAt[s.l.b]; t.After(inv) {
			inv = t
		}
		m := markers[s.id]
		if (!in.live[s.l.a] && !in.live[s.l.b]) || inv.IsZero() || !inv.After(m) {
			if !m.IsZero() {
				next[s.id] = m
			}
			kept++
			continue
		}
		if s.misses+1 >= MissLimit {
			gone = append(gone, s.id)
			continue
		}
		next[s.id] = inv
		miss = append(miss, s.id)
		kept++
	}
	var res Result
	if len(silent) > 0 {
		if _, err := tx.Exec(ctx, `DELETE FROM core.link WHERE id = ANY($1) AND NOT manual`, silent); err != nil {
			return res, fmt.Errorf("remove duplicate links: %w", err)
		}
	}
	if len(gone) > 0 {
		tag, err := tx.Exec(ctx, `WITH del AS (DELETE FROM core.link WHERE id = ANY($1) AND NOT manual
				RETURNING id, a_device_id, a_if_index, b_device_id, b_if_index, source)
			INSERT INTO core.link_change (link_id, a_device_id, a_if_index, b_device_id, b_if_index, change, source)
			SELECT id, a_device_id, a_if_index, b_device_id, b_if_index, 'disappeared', source FROM del`, gone)
		if err != nil {
			return res, fmt.Errorf("remove links: %w", err)
		}
		res.Disappeared = int(tag.RowsAffected())
	}
	if len(miss) > 0 {
		if _, err := tx.Exec(ctx, `UPDATE core.link SET misses = misses + 1 WHERE id = ANY($1) AND NOT manual`, miss); err != nil {
			return res, fmt.Errorf("count misses: %w", err)
		}
	}
	for n, u := range rekey {
		if err := stop(ctx, n); err != nil {
			return res, err
		}
		if _, err := tx.Exec(ctx, `UPDATE core.link SET a_if_index = NULLIF($2, 0), b_if_index = NULLIF($3, 0), source = $4,
				confidence = $5::int / 100.0, misses = 0, last_confirmed = $6 WHERE id = $1 AND NOT manual`,
			u.id, u.l.ai, u.l.bi, u.l.source, u.l.conf, now); err != nil {
			return res, fmt.Errorf("update link ports: %w", err)
		}
	}
	if len(confirm) > 0 {
		ids, src, conf := make([]int64, len(confirm)), make([]string, len(confirm)), make([]int32, len(confirm))
		for i, u := range confirm {
			ids[i], src[i], conf[i] = u.id, u.l.source, u.l.conf
		}
		if _, err := tx.Exec(ctx, `UPDATE core.link l SET misses = 0, last_confirmed = $2::timestamptz, source = t.s, confidence = t.c / 100.0
			FROM unnest($1::bigint[], $3::text[], $4::int[]) AS t(id, s, c)
			WHERE l.id = t.id AND NOT l.manual AND (l.misses <> 0 OR l.source <> t.s OR l.confidence <> t.c / 100.0
			    OR l.last_confirmed < $2::timestamptz - interval '5 minutes')`, ids, now, src, conf); err != nil {
			return res, fmt.Errorf("confirm links: %w", err)
		}
	}
	var add []link
	for i, w := range live {
		if !used[i] && !taken[w.key()] {
			add = append(add, w)
		}
	}
	for start := 0; start < len(add); start += 2000 {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		end := min(start+2000, len(add))
		n := end - start
		a, ai, b, bi, src, conf := make([]int64, n), make([]int32, n), make([]int64, n), make([]int32, n), make([]string, n), make([]int32, n)
		for i, l := range add[start:end] {
			a[i], ai[i], b[i], bi[i], src[i], conf[i] = l.a, l.ai, l.b, l.bi, l.source, l.conf
		}
		tag, err := tx.Exec(ctx, `WITH ins AS (
				INSERT INTO core.link (a_device_id, a_if_index, b_device_id, b_if_index, source, confidence, manual, first_seen, last_confirmed, misses)
				SELECT a, NULLIF(ai, 0), b, NULLIF(bi, 0), s, c / 100.0, false, $7::timestamptz, $7::timestamptz, 0
				FROM unnest($1::bigint[], $2::int[], $3::bigint[], $4::int[], $5::text[], $6::int[]) AS t(a, ai, b, bi, s, c)
				ON CONFLICT (a_device_id, coalesce(a_if_index, -1), b_device_id, coalesce(b_if_index, -1)) DO NOTHING
				RETURNING id, a_device_id, a_if_index, b_device_id, b_if_index, source)
			INSERT INTO core.link_change (link_id, a_device_id, a_if_index, b_device_id, b_if_index, change, source)
			SELECT id, a_device_id, a_if_index, b_device_id, b_if_index, 'appeared', source FROM ins`,
			a, ai, b, bi, src, conf, now)
		if err != nil {
			return res, fmt.Errorf("insert links: %w", err)
		}
		res.Appeared += int(tag.RowsAffected())
	}
	res.Links = kept + res.Appeared
	clear(markers)
	for id, t := range next {
		markers[id] = t
	}
	return res, nil
}
