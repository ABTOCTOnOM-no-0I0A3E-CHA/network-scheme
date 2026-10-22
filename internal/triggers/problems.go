package triggers

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/notify"
)

/* Resolve reasons written by the engine (the manual one belongs to a later phase). */
const (
	reasonRecovered = "recovered"
	reasonRemoved   = "removed"
)

/* maxValueRunes bounds last_value: it is shown in the UI and may derive from device data. */
const maxValueRunes = 200

/* pkey is the open-problem key; trig 0 means a system problem, dev 0 no device. */
type pkey struct {
	trig int64
	sys  string
	dev  int64
	obj  string
}

/* openP is a non-resolved problem as stored. */
type openP struct {
	id         int64
	key        pkey
	severity   string
	state      string
	suppressed bool
	openedAt   time.Time
	ackedAt    *time.Time
}

type openReq struct {
	key      pkey
	severity string
	value    string
	evidence time.Time /* when the evidence occurred; a problem resolved at or after it is not reopened */
}

type resolveReq struct {
	key    pkey
	reason string
	value  string
	at     time.Time /* when the recovery was observed: the timestamp of the evidence, not of the engine's round */
}

type flipReq struct {
	p  *openP
	to bool
}

/* actions are the changes one cycle wants to make; apply writes them in one transaction. */
type actions struct {
	opens     []openReq
	resolves  []resolveReq
	flips     []flipReq
	wmSeq     map[string]int64
	sampleTo  time.Time
	sampleCut bool
	openSet   map[pkey]bool
	resSet    map[pkey]bool
}

func newActions() *actions {
	return &actions{wmSeq: map[string]int64{}, openSet: map[pkey]bool{}, resSet: map[pkey]bool{}}
}

/* sanitize makes device-derived text safe for storage and display: no control or format characters, bounded length. */
func sanitize(s string) string {
	var b strings.Builder
	n := 0
	space := false
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.IsSpace(r) {
			r = ' '
		}
		if r == ' ' {
			if space || b.Len() == 0 {
				continue
			}
			space = true
		} else {
			space = false
		}
		if n++; n > maxValueRunes {
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimRight(b.String(), " ")
}

/* loadOpen replaces the mirror of non-resolved problems with what the database holds now. */
func (e *Engine) loadOpen(ctx context.Context) error {
	rows, err := e.pool.Query(ctx, `
		SELECT id, coalesce(trigger_id, 0), coalesce(system_kind, ''), coalesce(device_id, 0), object,
		       severity, state, suppressed, opened_at, acknowledged_at
		FROM problems.problem WHERE state <> 'resolved'`)
	if err != nil {
		return fmt.Errorf("triggers: load open problems: %w", err)
	}
	defer rows.Close()
	open := map[pkey]*openP{}
	for rows.Next() {
		p := &openP{}
		if err := rows.Scan(&p.id, &p.key.trig, &p.key.sys, &p.key.dev, &p.key.obj, &p.severity, &p.state, &p.suppressed, &p.openedAt, &p.ackedAt); err != nil {
			return fmt.Errorf("triggers: load open problems: %w", err)
		}
		open[p.key] = p
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("triggers: load open problems: %w", err)
	}
	e.open = open
	return nil
}

/* open asks for a problem unless one is already open (or requested) for the key. */
func (a *actions) open(e *Engine, r openReq) {
	if e.open[r.key] != nil || a.openSet[r.key] {
		return
	}
	r.value = sanitize(r.value)
	a.openSet[r.key] = true
	a.opens = append(a.opens, r)
}

/* resolve asks to close the problem of key (open now or requested in this cycle). */
func (a *actions) resolve(e *Engine, k pkey, reason, value string, at time.Time) {
	delete(e.held, k) /* a held opening is moot once its condition ended */
	if a.resSet[k] || (e.open[k] == nil && !a.openSet[k]) {
		return
	}
	a.resSet[k] = true
	a.resolves = append(a.resolves, resolveReq{key: k, reason: reason, value: sanitize(value), at: at})
}

/* name is the problem title shown in notifications. */
func (e *Engine) problemName(k pkey) string {
	if k.trig != 0 {
		if n, ok := e.cfg.trigName[k.trig]; ok {
			return n
		}
		return fmt.Sprintf("Trigger %d", k.trig)
	}
	return systemName(k.sys)
}

func (e *Engine) summary(id int64, k pkey, severity, state string, suppressed bool, opened time.Time, acked, resolved *time.Time) notify.ProblemSummary {
	s := notify.ProblemSummary{ID: id, Severity: severity, State: state, Suppressed: suppressed, Name: e.problemName(k), Object: k.obj,
		OpenedAt: opened, AckedAt: acked, ResolvedAt: resolved}
	if k.dev != 0 {
		d := k.dev
		s.DeviceID = &d
		if m, ok := e.meta[k.dev]; ok {
			s.DeviceName = m.name
			if m.group != 0 {
				g := m.group
				s.GroupID = &g
			}
		}
	}
	return s
}

/* apply writes the actions and the stream watermarks in one transaction and publishes the notifications after the commit. */
func (e *Engine) apply(ctx context.Context, a *actions, now time.Time) error {
	if len(a.opens) == 0 && len(a.resolves) == 0 && len(a.flips) == 0 && len(a.wmSeq) == 0 {
		return nil
	}
	var msgs []notify.Message
	err := pgx.BeginFunc(ctx, e.pool, func(tx pgx.Tx) error {
		msgs = msgs[:0]
		ids := map[pkey]int64{}
		created := map[pkey]*openP{}
		for start := 0; start < len(a.opens); start += writeChunk {
			chunk := a.opens[start:min(start+writeChunk, len(a.opens))]
			var trig, dev []*int64
			var sys, obj, sev, val []string
			var sup []bool
			var ev []*time.Time
			for _, r := range chunk {
				trig, dev = append(trig, nz(r.key.trig)), append(dev, nz(r.key.dev))
				sys = append(sys, r.key.sys)
				obj, sev, val = append(obj, r.key.obj), append(sev, r.severity), append(val, r.value)
				sup = append(sup, e.wantSuppressed(a, r.key.dev, now))
				if r.evidence.IsZero() {
					ev = append(ev, nil)
				} else {
					t := r.evidence
					ev = append(ev, &t)
				}
			}
			/*
				A problem resolved at or after the evidence time is not reopened by it: a
				replayed event or an old sample cannot resurrect what a newer fact closed.
			*/
			rows, err := tx.Query(ctx, `
				INSERT INTO problems.problem (trigger_id, system_kind, device_id, object, severity, suppressed, opened_at, last_value)
				SELECT i.trig, nullif(i.sys, ''), i.dev, i.obj, i.sev, i.sup, $9, nullif(i.val, '')
				FROM unnest($1::bigint[], $2::text[], $3::bigint[], $4::text[], $5::text[], $6::bool[], $7::text[], $8::timestamptz[])
				     AS i(trig, sys, dev, obj, sev, sup, val, ev)
				WHERE i.ev IS NULL OR NOT EXISTS (
				    SELECT 1 FROM problems.problem r
				    WHERE r.state = 'resolved' AND r.device_id = i.dev AND r.trigger_id = i.trig
				      AND r.object = i.obj AND r.resolved_at >= i.ev)
				ON CONFLICT (trigger_id, system_kind, device_id, object) WHERE state <> 'resolved' DO NOTHING
				RETURNING id, coalesce(trigger_id, 0), coalesce(system_kind, ''), coalesce(device_id, 0), object, severity, suppressed`,
				trig, sys, dev, obj, sev, sup, val, ev, now)
			if err != nil {
				return fmt.Errorf("insert problems: %w", err)
			}
			for rows.Next() {
				p := &openP{state: "problem", openedAt: now}
				if err := rows.Scan(&p.id, &p.key.trig, &p.key.sys, &p.key.dev, &p.key.obj, &p.severity, &p.suppressed); err != nil {
					rows.Close()
					return fmt.Errorf("insert problems: %w", err)
				}
				ids[p.key], created[p.key] = p.id, p
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return fmt.Errorf("insert problems: %w", err)
			}
		}
		for _, p := range created {
			if !p.suppressed {
				msgs = append(msgs, notify.Message{Type: notify.MessageTypeProblem, Event: notify.EventOpened,
					Problem: e.summary(p.id, p.key, p.severity, p.state, false, p.openedAt, nil, nil)})
			}
		}

		/* Resolves: problems open before this cycle and the ones created above. */
		var rid []int64
		var reason, val []string
		var at []time.Time
		type res struct {
			p *openP
			r resolveReq
		}
		var done []res
		for _, r := range a.resolves {
			p := e.open[r.key]
			if p == nil {
				p = created[r.key]
			}
			if p == nil {
				continue
			}
			when := r.at
			if when.IsZero() {
				when = now
			}
			rid, reason, val, at = append(rid, p.id), append(reason, r.reason), append(val, r.value), append(at, when)
			done = append(done, res{p, r})
		}
		/* Only rows this transaction really changed are announced: another engine may have resolved them first. */
		changed := map[int64]bool{}
		for start := 0; start < len(rid); start += writeChunk {
			end := min(start+writeChunk, len(rid))
			rows, err := tx.Query(ctx, `
				UPDATE problems.problem p SET state = 'resolved', resolved_at = greatest(u.at, p.opened_at), resolve_reason = u.reason,
				       last_value = coalesce(nullif(u.val, ''), p.last_value)
				FROM unnest($1::bigint[], $2::text[], $3::text[], $4::timestamptz[]) AS u(id, reason, val, at)
				WHERE p.id = u.id AND p.state <> 'resolved'
				RETURNING p.id`, rid[start:end], reason[start:end], val[start:end], at[start:end])
			if err != nil {
				return fmt.Errorf("resolve problems: %w", err)
			}
			for rows.Next() {
				var id int64
				if err := rows.Scan(&id); err != nil {
					rows.Close()
					return fmt.Errorf("resolve problems: %w", err)
				}
				changed[id] = true
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return fmt.Errorf("resolve problems: %w", err)
			}
		}
		for _, d := range done {
			if d.p.suppressed || !changed[d.p.id] {
				continue /* never announced, so nothing to retract; or resolved by someone else */
			}
			t := d.r.at
			if t.IsZero() || t.Before(d.p.openedAt) {
				t = laterOf(d.p.openedAt, now)
			}
			msgs = append(msgs, notify.Message{Type: notify.MessageTypeProblem, Event: notify.EventResolved,
				Problem: e.summary(d.p.id, d.p.key, d.p.severity, "resolved", false, d.p.openedAt, d.p.ackedAt, &t)})
		}

		/* Suppression flips of problems that stay open. */
		for _, to := range []bool{true, false} {
			var fid []int64
			var fl []flipReq
			for _, f := range a.flips {
				if f.to == to && !a.resSet[f.p.key] {
					fid, fl = append(fid, f.p.id), append(fl, f)
				}
			}
			flipped := map[int64]bool{}
			for start := 0; start < len(fid); start += writeChunk {
				end := min(start+writeChunk, len(fid))
				rows, err := tx.Query(ctx, `UPDATE problems.problem SET suppressed = $2 WHERE id = ANY($1) AND state <> 'resolved' AND suppressed <> $2 RETURNING id`, fid[start:end], to)
				if err != nil {
					return fmt.Errorf("update suppression: %w", err)
				}
				for rows.Next() {
					var id int64
					if err := rows.Scan(&id); err != nil {
						rows.Close()
						return fmt.Errorf("update suppression: %w", err)
					}
					flipped[id] = true
				}
				rows.Close()
				if err := rows.Err(); err != nil {
					return fmt.Errorf("update suppression: %w", err)
				}
			}
			for _, f := range fl {
				if !flipped[f.p.id] {
					continue
				}
				msgs = append(msgs, notify.Message{Type: notify.MessageTypeProblem, Event: notify.EventSuppressedChanged,
					Problem: e.summary(f.p.id, f.p.key, f.p.severity, f.p.state, to, f.p.openedAt, f.p.ackedAt, nil)})
			}
		}

		for name, w := range a.wmSeq {
			if _, err := tx.Exec(ctx, `
				INSERT INTO problems.engine_state (name, watermark, seq) VALUES ($1, $3, $2)
				ON CONFLICT (name) DO UPDATE SET seq = greatest(problems.engine_state.seq, excluded.seq), watermark = excluded.watermark`, name, w, now); err != nil {
				return fmt.Errorf("save watermark: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("triggers: %w", err)
	}
	e.publish(ctx, msgs)
	return nil
}

/* writeChunk bounds the rows of one statement. */
const writeChunk = 500

/* publishBurst and publishPause pace a storm: the hub drops a subscriber whose buffer (256) overflows, so a burst is fed in slices. */
const (
	publishBurst = 100
	publishPause = 5 * time.Millisecond
)

func nz(v int64) *int64 {
	if v == 0 {
		return nil
	}
	return &v
}

/* publish hands the notifications to every channel after the transaction committed. */
func (e *Engine) publish(ctx context.Context, msgs []notify.Message) {
	for i, m := range msgs {
		if i > 0 && i%publishBurst == 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(publishPause):
			}
		}
		for _, ch := range e.channels {
			if err := ch.Deliver(ctx, m); err != nil {
				e.log.Warn("notification channel failed", "channel", ch.Name(), "error", err.Error())
			}
		}
	}
}
