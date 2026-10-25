package triggers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

/* Standard link traps: linkDown opens a problem at once, linkUp (the paired trap) closes it. */
const (
	trapLinkDown = "linkDown"
	trapLinkUp   = "linkUp"
)

/*
Event streams. Syslog and traps are read by insertion order, not by time:
eventd stamps every row with ingest_seq (migration 00016) and its single
writer commits batches sequentially, so once the engine has processed every
row up to a sequence number, no smaller one can still appear. Device clocks,
commit delays and backlogs therefore cannot hide an event, and no timestamp
takes part in deciding what was already seen. The position of each stream
(engine_state.seq) only moves forward and is saved in the same transaction as
the problems it produced, so a restart neither repeats nor loses an event.
Each round reads at most seqRange rows per stream (up to maxRanges ranges per
cycle) and aggregates them in SQL, so the cost is O(devices x triggers), not
O(rows): a device flooding one trigger is one result row. Only rows younger
than eventTSFloor are considered, which lets the database skip old chunks.
*/
const (
	eventTSFloor = 25 * time.Hour
	defaultQuiet = 15 * time.Minute /* event problems resolve after this long without a matching message */
	sampleRunes  = 200
)

/*
Configuration-change events. The traps are the standard ENTITY-MIB
entConfigChange (trap.Standard) and the name config_changed, which an operator
can give to a vendor trap OID with a trap rule; the syslog patterns are
case-insensitive substrings of messages of severity info or more severe. No
Eltex message text is documented, so these are generic and not verified on
hardware; a missed event only means the scheduled backup finds the change.
*/
const (
	trapEntConfigChange = "entConfigChange"
	trapConfigChanged   = "config_changed"
)

var configSyslogPatterns = []string{"configuration changed", "configuration saved", "config changed", "config saved", "running-config changed"}

const configSyslogSeverity = 6

func isConfigTrap(name string) bool { return name == trapEntConfigChange || name == trapConfigChanged }

const (
	streamTrap   = "trap"
	streamSyslog = "syslog"
)

/* streamPos returns the position of a stream; a stream seen for the first time starts at the current end of its table. */
func (e *Engine) streamPos(ctx context.Context, a *actions, stream string, now time.Time) (int64, error) {
	if v, ok := e.wmSeq[stream]; ok {
		return v, nil
	}
	var seq *int64
	err := e.pool.QueryRow(ctx, `SELECT seq FROM problems.engine_state WHERE name = $1`, stream).Scan(&seq)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("triggers: read stream position: %w", err)
	}
	if seq == nil {
		head, err := e.streamHead(ctx, stream, now)
		if err != nil {
			return 0, err
		}
		a.wmSeq[stream] = head
		seq = &head
	}
	e.wmSeq[stream] = *seq
	return *seq, nil
}

/* skipToHead moves a stream nobody listens to straight to its end (one bounded query), so a trigger added later starts from now. */
func (e *Engine) skipToHead(ctx context.Context, a *actions, stream string, pos int64, now time.Time) error {
	head, err := e.streamHead(ctx, stream, now)
	if err != nil {
		return err
	}
	if head > pos {
		a.wmSeq[stream] = head
	}
	return nil
}

/* eventTable names the table of a stream (a constant, never user input). */
func eventTable(stream string) string {
	if stream == streamTrap {
		return "events.trap"
	}
	return "events.syslog"
}

func (e *Engine) streamHead(ctx context.Context, stream string, now time.Time) (int64, error) {
	var head int64
	if err := e.pool.QueryRow(ctx, `SELECT coalesce(max(ingest_seq), 0) FROM `+eventTable(stream)+` WHERE ts > $1`, now.Add(-eventTSFloor)).Scan(&head); err != nil {
		return 0, fmt.Errorf("triggers: read stream head: %w", err)
	}
	return head, nil
}

/*
nextRange returns the end of the next range after lo (0: nothing new) and
whether more rows remain beyond it. The end is the seq of the seqRange-th
following row, so every row up to it is inside the range.
*/
func (e *Engine) nextRange(ctx context.Context, stream string, lo int64, floor time.Time) (hi int64, more bool, err error) {
	var n int
	err = e.pool.QueryRow(ctx, `SELECT coalesce(max(s), 0), count(*) FROM
		(SELECT ingest_seq s FROM `+eventTable(stream)+` WHERE ingest_seq > $1 AND ts > $2 ORDER BY ingest_seq LIMIT $3) x`,
		lo, floor, seqRange).Scan(&hi, &n)
	if err != nil {
		return 0, false, fmt.Errorf("triggers: read %s range: %w", stream, err)
	}
	return hi, n == seqRange, nil
}

/* evalEvents reads new traps and syslog messages and lets quiet event problems expire. */
func (e *Engine) evalEvents(ctx context.Context, a *actions, now time.Time) error {
	if err := e.readTraps(ctx, a, now); err != nil {
		return err
	}
	if err := e.readSyslog(ctx, a, now); err != nil {
		return err
	}
	e.expireQuiet(a, now)
	return nil
}

/* trapGroup is the aggregate of the traps of one name from one device (and interface) in a range. */
type trapGroup struct {
	dev     int64
	name    string
	ifIndex int
	n       int64
	maxSeq  int64
	maxTS   time.Time
}

func (e *Engine) readTraps(ctx context.Context, a *actions, now time.Time) error {
	pos, err := e.streamPos(ctx, a, streamTrap, now)
	if err != nil {
		return err
	}
	names := map[string]bool{}
	for _, dt := range e.cfg.byKind[KindTrap] {
		n := dt.t.params.(*Trap).Name
		names[n] = true
		if n == trapLinkDown {
			names[trapLinkUp] = true /* the pair that closes it */
		}
	}
	if len(e.cfg.byKind[KindIfOperDown]) > 0 {
		names[trapLinkDown], names[trapLinkUp] = true, true
	}
	if e.backupNow != nil {
		names[trapEntConfigChange], names[trapConfigChanged] = true, true
	}
	list := make([]string, 0, len(names))
	for n := range names {
		list = append(list, n)
	}
	if len(list) == 0 {
		return e.skipToHead(ctx, a, streamTrap, pos, now)
	}
	floor := now.Add(-eventTSFloor)
	for range maxRanges {
		hi, more, err := e.nextRange(ctx, streamTrap, pos, floor)
		if err != nil {
			return err
		}
		if hi == 0 {
			break
		}
		groups, err := e.trapGroups(ctx, pos, hi, floor, list)
		if err != nil {
			return err
		}
		for _, g := range groups {
			e.onTrap(a, g, now)
		}
		pos = hi
		a.wmSeq[streamTrap] = hi
		if !more {
			break
		}
	}
	return nil
}

/*
trapGroups aggregates the traps of the wanted names in (lo, hi] per device,
name and interface (for link traps: the ifIndex varbind), ordered by the
newest row, so a down/up pair keeps its order and a flapping device is one
row per direction.
*/
func (e *Engine) trapGroups(ctx context.Context, lo, hi int64, floor time.Time, names []string) ([]trapGroup, error) {
	rows, err := e.pool.Query(ctx, `
		SELECT device_id, name, coalesce(ifidx, 0), count(*), max(ingest_seq), max(ts)
		FROM (
		    SELECT device_id, name, ingest_seq, ts,
		           CASE WHEN name IN ('linkDown', 'linkUp') AND jsonb_typeof(varbinds) = 'array' THEN
		                (SELECT (v->>'value')::bigint FROM jsonb_array_elements(varbinds) v
		                 WHERE v->>'oid' LIKE '1.3.6.1.2.1.2.2.1.1.%' AND v->>'type' = 'Integer'
		                   AND v->>'value' ~ '^[1-9][0-9]{0,9}$' LIMIT 1)
		           END AS ifidx
		    FROM events.trap
		    WHERE ingest_seq > $1 AND ingest_seq <= $2 AND ts > $3 AND name = ANY($4)
		) t
		GROUP BY device_id, name, ifidx
		ORDER BY max(ingest_seq)`, lo, hi, floor, names)
	if err != nil {
		return nil, fmt.Errorf("triggers: read traps: %w", err)
	}
	defer rows.Close()
	var out []trapGroup
	for rows.Next() {
		var g trapGroup
		var idx int64
		if err := rows.Scan(&g.dev, &g.name, &idx, &g.n, &g.maxSeq, &g.maxTS); err != nil {
			return nil, fmt.Errorf("triggers: read traps: %w", err)
		}
		if idx > 0 && idx <= MaxIfIndex {
			g.ifIndex = int(idx)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

/* onTrap applies the traps of one group to the trap triggers (by name) and the interface triggers (link traps) of its device. */
func (e *Engine) onTrap(a *actions, r trapGroup, now time.Time) {
	if isConfigTrap(r.name) && e.backupNow != nil {
		if _, ok := e.cfg.devices[r.dev]; ok {
			e.cfgHints[r.dev] = now
		}
	}
	link := r.name == trapLinkDown || r.name == trapLinkUp
	idx := r.ifIndex
	obj := ""
	if idx > 0 {
		obj = "if:" + strconv.Itoa(idx)
	}
	hinted := false
	for _, t := range e.cfg.eff[r.dev] {
		switch par := t.params.(type) {
		case *Trap:
			k := pkey{trig: t.id, dev: r.dev}
			if par.Name == trapLinkDown || par.Name == trapLinkUp {
				k.obj = obj
			}
			switch {
			case par.Name == r.name:
				a.open(e, openReq{key: k, severity: t.severity, value: describeTrap(r.name, idx), event: true})
				tr := e.tracker(tkey{t.id, r.dev, k.obj})
				tr.lastEvent, tr.floor, tr.falses = now, laterOf(tr.floor, r.maxTS), 0
				hinted = hinted || link
			case par.Name == trapLinkDown && r.name == trapLinkUp:
				e.closeByTrap(a, k, r.maxTS, describeTrap(r.name, idx))
				hinted = true
			}
		case *IfOperDown:
			if !link || idx == 0 || (par.IfIndex != nil && *par.IfIndex != idx) {
				continue
			}
			k := pkey{trig: t.id, dev: r.dev, obj: obj}
			if r.name == trapLinkDown {
				e.markUp([2]int64{r.dev, int64(idx)}, time.Time{}) /* a device-reported transition */
				a.open(e, openReq{key: k, severity: t.severity, value: describeTrap(r.name, idx), event: true})
				tr := e.tracker(tkey{t.id, r.dev, obj})
				tr.floor, tr.falses, tr.firstTrue = laterOf(tr.floor, r.maxTS), 0, r.maxTS
			} else {
				e.closeByTrap(a, k, r.maxTS, describeTrap(r.name, idx))
			}
			hinted = true
		}
	}
	if hinted {
		e.pollHints[r.dev] = now
	}
}

func laterOf(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func describeTrap(name string, idx int) string {
	if idx > 0 {
		return fmt.Sprintf("trap %s, ifIndex %d", name, idx)
	}
	return "trap " + name
}

/* closeByTrap resolves the problem of k on the paired trap and makes earlier polls irrelevant. */
func (e *Engine) closeByTrap(a *actions, k pkey, ts time.Time, value string) {
	tr := e.tracker(tkey{k.trig, k.dev, k.obj})
	tr.floor, tr.firstTrue, tr.falses = laterOf(tr.floor, ts), time.Time{}, 0
	a.resolve(e, k, reasonRecovered, value, ts)
}

/* maxSyslogFilters is the engine-side bound of distinct syslog filters read per cycle (the API enforces the same bound on writes). */
const maxSyslogFilters = 256

/* sysFilter is the bound parameters of one syslog trigger condition; triggers with equal filters share one aggregate. */
type sysFilter struct {
	sev      int
	contains string
}

func syslogFilter(p *Syslog) sysFilter {
	f := sysFilter{sev: *p.SeverityMin}
	if p.Contains != nil {
		f.contains = strings.ToLower(*p.Contains) /* SQL compares with lower() on both sides */
	}
	return f
}

func (e *Engine) readSyslog(ctx context.Context, a *actions, now time.Time) error {
	pos, err := e.streamPos(ctx, a, streamSyslog, now)
	if err != nil {
		return err
	}
	filterIdx := map[sysFilter]int{}
	var sevs []int32
	var subs []string
	devSet := map[int64]bool{}
	for _, dt := range e.cfg.byKind[KindSyslog] {
		f := syslogFilter(dt.t.params.(*Syslog))
		if _, ok := filterIdx[f]; !ok {
			if len(sevs) >= maxSyslogFilters {
				if now.Sub(e.lastFilterWarn) >= time.Minute {
					e.lastFilterWarn = now
					e.log.Warn("syslog filter cap reached: further distinct filters skipped", slog.Int("cap", maxSyslogFilters))
				}
				continue
			}
			filterIdx[f] = len(sevs)
			sevs, subs = append(sevs, int32(f.sev)), append(subs, f.contains) // #nosec G115 -- 0..7
		}
		devSet[dt.dev] = true
	}
	devs := make([]int64, 0, len(devSet))
	for d := range devSet {
		devs = append(devs, d)
	}
	if len(sevs) == 0 && e.backupNow == nil {
		return e.skipToHead(ctx, a, streamSyslog, pos, now)
	}
	floor := now.Add(-eventTSFloor)
	for range maxRanges {
		hi, more, err := e.nextRange(ctx, streamSyslog, pos, floor)
		if err != nil {
			return err
		}
		if hi == 0 {
			break
		}
		if len(sevs) > 0 {
			if err := e.syslogRange(ctx, a, pos, hi, floor, sevs, subs, devs, filterIdx, now); err != nil {
				return err
			}
		}
		if e.backupNow != nil {
			if err := e.configSyslog(ctx, pos, hi, floor, now); err != nil {
				return err
			}
		}
		pos = hi
		a.wmSeq[streamSyslog] = hi
		if !more {
			break
		}
	}
	return nil
}

/* configSyslog marks the known devices that logged a configuration-change message in (lo, hi]. */
func (e *Engine) configSyslog(ctx context.Context, lo, hi int64, floor, now time.Time) error {
	rows, err := e.pool.Query(ctx, `
		SELECT DISTINCT device_id FROM events.syslog
		WHERE ingest_seq > $1 AND ingest_seq <= $2 AND ts > $3 AND severity <= $4
		  AND EXISTS (SELECT 1 FROM unnest($5::text[]) p WHERE position(p in lower(msg)) > 0)`,
		lo, hi, floor, configSyslogSeverity, configSyslogPatterns)
	if err != nil {
		return fmt.Errorf("triggers: read config-change syslog: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var dev int64
		if err := rows.Scan(&dev); err != nil {
			return fmt.Errorf("triggers: read config-change syslog: %w", err)
		}
		if _, ok := e.cfg.devices[dev]; ok {
			e.cfgHints[dev] = now
		}
	}
	return rows.Err()
}

/*
syslogRange aggregates (lo, hi] per trigger filter and device in SQL; every
filter value is a bound parameter (the substring is compared with position(),
never as a pattern).
*/
func (e *Engine) syslogRange(ctx context.Context, a *actions, lo, hi int64, floor time.Time, sevs []int32, subs []string, devs []int64, idx map[sysFilter]int, now time.Time) error {
	rows, err := e.pool.Query(ctx, `
		SELECT g.f, g.dev,
		       (SELECT left(s2.msg, $7) FROM events.syslog s2 WHERE s2.ingest_seq = g.mx AND s2.ts > $3 LIMIT 1)
		FROM (
		    SELECT (f.ord - 1)::int AS f, s.device_id AS dev, max(s.ingest_seq) AS mx
		    FROM unnest($4::int[], $5::text[]) WITH ORDINALITY AS f(sev, c, ord)
		    JOIN events.syslog s
		      ON s.ingest_seq > $1 AND s.ingest_seq <= $2 AND s.ts > $3
		     AND s.severity <= f.sev AND s.device_id = ANY($6)
		     AND (f.c = '' OR position(lower(f.c) in lower(s.msg)) > 0)
		    GROUP BY f.ord, s.device_id
		) g`, lo, hi, floor, sevs, subs, devs, sampleRunes)
	if err != nil {
		return fmt.Errorf("triggers: read syslog: %w", err)
	}
	type hit struct {
		f      int
		dev    int64
		sample *string
	}
	var hits []hit
	for rows.Next() {
		var h hit
		if err := rows.Scan(&h.f, &h.dev, &h.sample); err != nil {
			rows.Close()
			return fmt.Errorf("triggers: read syslog: %w", err)
		}
		hits = append(hits, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("triggers: read syslog: %w", err)
	}
	for _, h := range hits {
		msg := ""
		if h.sample != nil {
			msg = *h.sample
		}
		for _, t := range e.cfg.eff[h.dev] {
			par, ok := t.params.(*Syslog)
			if !ok {
				continue
			}
			if i, known := idx[syslogFilter(par)]; !known || i != h.f { /* a filter missing from idx must not alias filter 0 */
				continue
			}
			a.open(e, openReq{key: pkey{trig: t.id, dev: h.dev}, severity: t.severity, value: msg, event: true})
			e.tracker(tkey{t.id, h.dev, ""}).lastEvent = now
		}
	}
	return nil
}

/*
expireQuiet resolves event problems (syslog, and traps that have no pair)
once no matching message arrived for the trigger's duration (15 minutes when
it is 0): they have no state to poll, so silence is their recovery.
*/
func (e *Engine) expireQuiet(a *actions, now time.Time) {
	for k := range e.open {
		if k.trig == 0 {
			continue
		}
		t := e.cfg.eff[k.dev][k.trig]
		if t == nil {
			continue
		}
		switch par := t.params.(type) {
		case *Syslog:
		case *Trap:
			if par.Name == trapLinkDown && k.obj != "" {
				continue /* closed by linkUp or by a poll that sees the interface up */
			}
		default:
			continue
		}
		tr := e.tracker(tkey{k.trig, k.dev, k.obj})
		if tr.lastEvent.IsZero() || tr.lastEvent.After(now) {
			tr.lastEvent = now /* after a restart the quiet period starts over */
		}
		quiet := defaultQuiet
		if t.duration > 0 {
			quiet = t.duration
		}
		if now.Sub(tr.lastEvent) >= quiet {
			a.resolve(e, k, reasonRecovered, "no matching messages for "+quiet.String(), time.Time{})
		}
	}
}
