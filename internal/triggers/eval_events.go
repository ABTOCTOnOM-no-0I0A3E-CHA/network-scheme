package triggers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

/* oidIfIndex is the prefix of the ifIndex varbind of a link trap. */
const oidIfIndex = "1.3.6.1.2.1.2.2.1.1."

/*
Event streams. Traps are timestamped by eventd on receipt, so they are read
exactly: from the persisted watermark up to now minus eventSettle (rows still
being flushed are left for the next round). Syslog timestamps come from the
device, so its window overlaps the watermark and a seen-set drops duplicates.
*/
const (
	eventSettle    = 5 * time.Second
	syslogOverlap  = 2 * time.Minute
	eventBatch     = 5000
	defaultQuiet   = 15 * time.Minute /* event problems resolve after this long without a matching message */
	maxSyslogBytes = 8192
)

const (
	streamTrap   = "trap"
	streamSyslog = "syslog"
)

/* evKey identifies an event row: the tables have no id, so the cursor is (ts, device, content hash). */
type evKey struct {
	ts     time.Time
	dev    int64
	hash   string
	syslog bool
}

/* streamStart returns the persisted watermark of a stream; a stream seen for the first time starts at now. */
func (e *Engine) streamStart(ctx context.Context, a *actions, name string, now time.Time) (time.Time, error) {
	if w, ok := e.wm[name]; ok {
		return w, nil
	}
	var w time.Time
	err := e.pool.QueryRow(ctx, `SELECT watermark FROM problems.engine_state WHERE name = $1`, name).Scan(&w)
	if errors.Is(err, pgx.ErrNoRows) {
		w = now
		a.wm[name] = w
	} else if err != nil {
		return time.Time{}, fmt.Errorf("triggers: read watermark: %w", err)
	}
	e.wm[name] = w
	return w, nil
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

type trapRow struct {
	ts       time.Time
	dev      int64
	name     string
	varbinds *string
	hash     string
}

func (e *Engine) readTraps(ctx context.Context, a *actions, now time.Time) error {
	start, err := e.streamStart(ctx, a, streamTrap, now)
	if err != nil {
		return err
	}
	upto := now.Add(-eventSettle)
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
	if len(names) == 0 || !upto.After(start) {
		if upto.After(start) {
			a.wm[streamTrap] = upto
		}
		return nil
	}
	e.pruneSeen(false, start)
	list := make([]string, 0, len(names))
	for n := range names {
		list = append(list, n)
	}
	rows, err := e.pool.Query(ctx, `
		SELECT ts, device_id, name,
		       CASE WHEN name IN ('linkDown', 'linkUp') THEN varbinds::text END,
		       md5(trap_oid || ':' || name || ':' || varbinds::text)
		FROM events.trap
		WHERE ts >= $1 AND ts <= $2 AND name = ANY($3)
		ORDER BY ts LIMIT $4`, start, upto, list, eventBatch)
	if err != nil {
		return fmt.Errorf("triggers: read traps: %w", err)
	}
	var batch []trapRow
	for rows.Next() {
		var r trapRow
		if err := rows.Scan(&r.ts, &r.dev, &r.name, &r.varbinds, &r.hash); err != nil {
			rows.Close()
			return fmt.Errorf("triggers: read traps: %w", err)
		}
		batch = append(batch, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("triggers: read traps: %w", err)
	}
	for _, r := range batch {
		k := evKey{r.ts, r.dev, r.hash, false}
		if _, dup := e.seen[k]; dup {
			continue
		}
		a.seen = append(a.seen, k)
		e.onTrap(a, r, now)
	}
	next := upto
	if len(batch) == eventBatch {
		next = batch[len(batch)-1].ts
	}
	a.wm[streamTrap] = next
	return nil
}

/* pruneSeen forgets the seen events of a stream that precede its read window. */
func (e *Engine) pruneSeen(syslog bool, from time.Time) {
	for k := range e.seen {
		if k.syslog == syslog && k.ts.Before(from) {
			delete(e.seen, k)
		}
	}
}

/* trapIfIndex extracts the interface index from the varbinds of a link trap (0: none). */
func trapIfIndex(varbinds *string) int {
	if varbinds == nil {
		return 0
	}
	var vbs []struct {
		OID, Type, Value string
	}
	if json.Unmarshal([]byte(*varbinds), &vbs) != nil {
		return 0
	}
	for _, v := range vbs {
		if strings.HasPrefix(strings.ToLower(v.OID), oidIfIndex) && v.Type == "Integer" {
			if n, err := strconv.Atoi(v.Value); err == nil && n > 0 && n <= MaxIfIndex {
				return n
			}
		}
	}
	return 0
}

/* onTrap applies one trap to the trap triggers (by name) and the interface triggers (link traps) of its device. */
func (e *Engine) onTrap(a *actions, r trapRow, now time.Time) {
	link := r.name == trapLinkDown || r.name == trapLinkUp
	idx := 0
	if link {
		idx = trapIfIndex(r.varbinds)
	}
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
				a.open(e, openReq{key: k, severity: t.severity, value: describeTrap(r.name, idx), evidence: r.ts})
				tr := e.tracker(tkey{t.id, r.dev, k.obj})
				tr.lastEvent, tr.floor, tr.falses = r.ts, laterOf(tr.floor, r.ts), 0
				hinted = hinted || link
			case par.Name == trapLinkDown && r.name == trapLinkUp:
				e.closeByTrap(a, k, r.ts, describeTrap(r.name, idx))
				hinted = true
			}
		case *IfOperDown:
			if !link || idx == 0 || (par.IfIndex != nil && *par.IfIndex != idx) {
				continue
			}
			k := pkey{trig: t.id, dev: r.dev, obj: obj}
			if r.name == trapLinkDown {
				e.seenUp[[2]int64{r.dev, int64(idx)}] = struct{}{} /* a device-reported transition */
				a.open(e, openReq{key: k, severity: t.severity, value: describeTrap(r.name, idx), evidence: r.ts})
				tr := e.tracker(tkey{t.id, r.dev, obj})
				tr.floor, tr.falses, tr.firstTrue = laterOf(tr.floor, r.ts), 0, r.ts
			} else {
				e.closeByTrap(a, k, r.ts, describeTrap(r.name, idx))
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

type syslogRow struct {
	ts       time.Time
	dev      int64
	severity int
	msg      string
	hash     string
}

func (e *Engine) readSyslog(ctx context.Context, a *actions, now time.Time) error {
	start, err := e.streamStart(ctx, a, streamSyslog, now)
	if err != nil {
		return err
	}
	upto := now.Add(-eventSettle)
	maxSev, devSet := -1, map[int64]bool{}
	for _, dt := range e.cfg.byKind[KindSyslog] {
		maxSev = max(maxSev, *dt.t.params.(*Syslog).SeverityMin)
		devSet[dt.dev] = true
	}
	if maxSev < 0 || !upto.After(start) {
		if upto.After(start) {
			a.wm[streamSyslog] = upto
		}
		return nil
	}
	devs := make([]int64, 0, len(devSet))
	for d := range devSet {
		devs = append(devs, d)
	}
	from := start.Add(-syslogOverlap)
	e.pruneSeen(true, from)
	rows, err := e.pool.Query(ctx, `
		SELECT ts, device_id, severity, left(msg, $6), md5(host || ':' || app || ':' || msg)
		FROM events.syslog
		WHERE ts >= $1 AND ts <= $2 AND severity <= $3 AND device_id = ANY($4)
		ORDER BY ts LIMIT $5`, from, upto, maxSev, devs, eventBatch, maxSyslogBytes)
	if err != nil {
		return fmt.Errorf("triggers: read syslog: %w", err)
	}
	var batch []syslogRow
	for rows.Next() {
		var r syslogRow
		if err := rows.Scan(&r.ts, &r.dev, &r.severity, &r.msg, &r.hash); err != nil {
			rows.Close()
			return fmt.Errorf("triggers: read syslog: %w", err)
		}
		batch = append(batch, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("triggers: read syslog: %w", err)
	}
	for _, r := range batch {
		k := evKey{r.ts, r.dev, r.hash, true}
		if _, dup := e.seen[k]; dup {
			continue
		}
		a.seen = append(a.seen, k)
		lower := strings.ToLower(r.msg)
		for _, t := range e.cfg.eff[r.dev] {
			par, ok := t.params.(*Syslog)
			if !ok || r.severity > *par.SeverityMin {
				continue
			}
			if par.Contains != nil && !strings.Contains(lower, strings.ToLower(*par.Contains)) {
				continue
			}
			k := pkey{trig: t.id, dev: r.dev}
			a.open(e, openReq{key: k, severity: t.severity, value: r.msg, evidence: r.ts})
			e.tracker(tkey{t.id, r.dev, ""}).lastEvent = r.ts
		}
	}
	next := upto
	if len(batch) == eventBatch {
		next = batch[len(batch)-1].ts
	}
	a.wm[streamSyslog] = next
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
