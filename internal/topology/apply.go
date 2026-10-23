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

/*
mergeNull makes sure one cable is one link. A link with an unknown port that
can be the same cable as a more specific link between the same devices (a MAC
inference (A,1,B,NULL) next to LLDP (A,1,B,2)) is folded into it: the specific
ports win and the stronger evidence (confidence and source) is kept.
*/
func mergeNull(ls []link) []link {
	byPair := map[[2]int64][]int{}
	for i, l := range ls {
		k := [2]int64{l.a, l.b}
		byPair[k] = append(byPair[k], i)
	}
	order := make([]int, len(ls))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(x, y int) bool {
		i, j := order[x], order[y]
		if si, sj := specificity(ls[i]), specificity(ls[j]); si != sj {
			return si < sj
		}
		return lessKey(ls[i].key(), ls[j].key())
	})
	removed := make([]bool, len(ls))
	for _, i := range order {
		if specificity(ls[i]) == 2 {
			break
		}
		best, cands := -1, 0
		for _, j := range byPair[[2]int64{ls[i].a, ls[i].b}] {
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
		/* with several candidates the link is subsumed by them all and adds nothing to any one */
		if cands == 1 && ls[i].conf > ls[best].conf {
			ls[best].conf, ls[best].source = ls[i].conf, ls[i].source
		}
		removed[i] = true
	}
	out := ls[:0:0]
	for i, l := range ls {
		if !removed[i] {
			out = append(out, l)
		}
	}
	return out
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
    "NOT manual"), and they suppress automatic links between the same devices
    on ports that can be the same cable; an existing automatic link suppressed
    this way is removed without a history entry (a person superseded it).
  - A stored automatic link that is derived again is confirmed (misses = 0). If
    only its ports got more or less specific it is updated in place, not
    recreated. A duplicate of a cable that another stored link already covers
    is removed silently.
  - A link not derived is counted as missed, but only while one of its devices
    is up under a fresh poller heartbeat (when both are unreachable the
    absence says nothing). It disappears at the MissLimit-th consecutive miss.
  - New links are inserted. Every appearance and disappearance writes a
    core.link_change row in the same statement.
*/
func apply(ctx context.Context, tx pgx.Tx, in *inputs, want []link, now time.Time) (Result, error) {
	cur, err := loadLinks(ctx, tx)
	if err != nil {
		return Result{}, err
	}
	manual := map[[2]int64][]link{}
	taken := map[linkKey]bool{} /* identities in use (any link) */
	var autos []stored
	for _, s := range cur {
		taken[s.l.key()] = true
		if s.manual {
			k := [2]int64{s.l.a, s.l.b}
			manual[k] = append(manual[k], s.l)
		} else {
			autos = append(autos, s)
		}
	}
	suppressed := func(l link) bool {
		for _, m := range manual[[2]int64{l.a, l.b}] {
			if sameCable(l, m) {
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
	for _, s := range autos {
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
	for _, s := range rest {
		if suppressed(s.l) {
			silent = append(silent, s.id)
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
	for _, s := range left {
		if !in.live[s.l.a] && !in.live[s.l.b] {
			kept++
			continue
		}
		if s.misses+1 >= MissLimit {
			gone = append(gone, s.id)
		} else {
			miss = append(miss, s.id)
			kept++
		}
	}
	var res Result
	if len(silent) > 0 {
		if _, err := tx.Exec(ctx, `DELETE FROM core.link WHERE id = ANY($1) AND NOT manual`, silent); err != nil {
			return res, fmt.Errorf("remove superseded links: %w", err)
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
	for _, u := range rekey {
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
	return res, nil
}
