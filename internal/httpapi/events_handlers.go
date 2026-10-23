package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/beekamai/network-scheme/internal/audit"
	"github.com/beekamai/network-scheme/internal/events/trap"
	"github.com/beekamai/network-scheme/internal/rbac"
)

/* Limits of the event feed and of the trap rules (the name and OID bounds mirror the CHECKs of events.trap_rule). */
const (
	defaultEventPage    = 100
	maxEventPage        = 500
	maxEventWindow      = 31 * 24 * time.Hour
	defaultEventWindow  = 24 * time.Hour
	maxEventQuery       = 200
	maxCursor           = 4096
	maxTrapRuleName     = 1024
	maxTrapRuleOID      = 2048
	maxOIDSubIDs        = 128
	maxSubID            = 1<<32 - 1
	defaultUnidentified = 100
)

/* errTrapRuleDup marks a unique violation on events.trap_rule.trap_oid. */
var errTrapRuleDup = errors.New("httpapi: trap rule exists")

var trapSeverities = map[string]bool{"info": true, "warning": true, "average": true, "high": true, "disaster": true}

/* severityRank orders the NMS severities; eventsSQL spells the same order out. */
var severityRank = map[string]int{"info": 0, "warning": 1, "average": 2, "high": 3, "disaster": 4}

/*
eventCursor is the position after the last row of a page. The event tables
have no id, so rows are ordered by (ts, device_id, kind, dig) descending where
dig is an md5 of the row content: unique for different rows at the same
instant, so pages neither repeat nor skip them. Byte-identical rows (same
microsecond, device and content) collapse to one at a page boundary.
*/
type eventCursor struct {
	TS   int64  `json:"t"` /* microseconds since the epoch */
	Dev  int64  `json:"d"`
	Kind string `json:"k"`
	Dig  string `json:"g"`
}

var hex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)

func encodeCursor(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

/* decodeCursor reads an opaque cursor strictly; ok is false for anything this API did not issue. */
func decodeCursor(s string, dst any) bool {
	if len(s) > maxCursor {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return false
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	return dec.Decode(dst) == nil && !dec.More()
}

/* single reads an optional single-valued query parameter; ok is false when it is repeated. */
func single(q url.Values, name string) (v string, ok bool) {
	vs := q[name]
	if len(vs) > 1 {
		return "", false
	}
	if len(vs) == 1 {
		v = vs[0]
	}
	return v, true
}

/*
eventWindow reads from and to: to defaults to now, from to a day before to; a
window must be non-empty and at most 31 days wide.
*/
func (s *server) eventWindow(q url.Values) (from, to time.Time, ok bool) {
	parse := func(name string) (t time.Time, set, ok bool) {
		v, ok := single(q, name)
		if !ok || v == "" {
			return time.Time{}, false, ok
		}
		t, err := time.Parse(time.RFC3339, v)
		return t.UTC(), true, err == nil
	}
	to, setTo, okT := parse("to")
	from, setFrom, okF := parse("from")
	if !okT || !okF {
		return time.Time{}, time.Time{}, false
	}
	if !setTo {
		to = s.now().UTC()
		if setFrom && !from.Before(to) {
			to = from.Add(defaultEventWindow)
		}
	}
	if !setFrom {
		from = to.Add(-defaultEventWindow)
	}
	if !to.After(from) || to.Sub(from) > maxEventWindow {
		return time.Time{}, time.Time{}, false
	}
	return from, to, true
}

type eventResponse struct {
	TS         time.Time       `json:"ts"`
	Kind       string          `json:"kind"`
	DeviceID   int64           `json:"device_id"`
	DeviceName string          `json:"device_name"`
	Severity   *string         `json:"severity"` /* NMS scale; null for an unidentified trap */
	Name       *string         `json:"name,omitempty"`
	App        *string         `json:"app,omitempty"`
	Text       string          `json:"text"`
	Identified bool            `json:"identified"`
	Varbinds   json.RawMessage `json:"varbinds,omitempty"`
	/* VarbindsOmitted is set when the varbinds exceed the listing limit and were left out. */
	VarbindsOmitted bool `json:"varbinds_omitted,omitempty"`
	/* Count is the number of events folded into a storm row (kind "storm": Text is the folded kind, TS the minute). */
	Count *int64 `json:"count,omitempty"`
}

type eventsPage struct {
	Items      []eventResponse `json:"items"`
	NextCursor *string         `json:"next_cursor"`
}

/*
eventsSQL merges syslog and traps of the window. Syslog severity 0..7 maps to
the NMS scale (0-1 disaster, 2 high, 3 average, 4 warning, 5-7 info); a trap
without a severity ranks as info. Rows of devices outside the caller's groups
and of deleted devices drop out in the join. Storm rows (events folded above the
rate limit: one per device, folded kind and minute) come as kind "storm" with a
count and never match a text query. $1 all, $2 group ids, $3 kind,
$4 device (0: any), $5 from, $6 to, $7 query, $8 min rank, $9 cursor given,
$10-$13 cursor ($10 also bounds ts inside each branch so the planner can exclude chunks), $14 limit.
*/
/* Varbind sets over 16384 bytes of JSON text are left out of listings (they stay in the database). */
const eventsSQL = `
WITH ev AS (
  SELECT s.ts, 'syslog'::text AS kind, s.device_id, s.app AS label, s.msg AS body, true AS identified,
         NULL::jsonb AS varbinds, false AS omitted, NULL::bigint AS cnt,
         CASE WHEN s.severity <= 1 THEN 'disaster' WHEN s.severity = 2 THEN 'high'
              WHEN s.severity = 3 THEN 'average' WHEN s.severity = 4 THEN 'warning' ELSE 'info' END AS severity,
         md5(concat_ws(chr(31), s.facility, s.severity, s.host, s.app, s.msg)) AS dig
  FROM events.syslog s
  WHERE $3::text IN ('', 'syslog') AND s.ts >= $5 AND s.ts < $6 AND ($4::bigint = 0 OR s.device_id = $4)
    AND (NOT $9::bool OR s.ts <= $10)
    AND ($7::text = '' OR s.tsv @@ plainto_tsquery('simple', $7))
  UNION ALL
  SELECT t.ts, 'trap', t.device_id, t.name, t.trap_oid, t.identified,
         CASE WHEN octet_length(t.varbinds::text) <= 16384 THEN t.varbinds END,
         coalesce(octet_length(t.varbinds::text) > 16384, false), NULL::bigint,
         t.severity,
         md5(concat_ws(chr(31), t.version, t.trap_oid, t.name, t.severity, t.identified, t.varbinds::text))
  FROM events.trap t
  WHERE $3::text IN ('', 'trap') AND t.ts >= $5 AND t.ts < $6 AND ($4::bigint = 0 OR t.device_id = $4)
    AND (NOT $9::bool OR t.ts <= $10)
    AND ($7::text = '' OR t.tsv @@ plainto_tsquery('simple', $7))
  UNION ALL
  SELECT m.ts, 'storm', m.device_id, m.kind, m.kind, true, NULL, false, m.count::bigint, NULL,
         md5(concat_ws(chr(31), m.kind, m.count))
  FROM events.storm m
  WHERE $3::text IN ('', 'storm') AND $7::text = '' AND m.ts >= $5 AND m.ts < $6 AND ($4::bigint = 0 OR m.device_id = $4)
    AND (NOT $9::bool OR m.ts <= $10)
)
SELECT ev.ts, ev.kind, ev.device_id, d.name, ev.severity, ev.label, ev.body, ev.identified, ev.varbinds, ev.omitted, ev.cnt, ev.dig
FROM ev JOIN core.device d ON d.id = ev.device_id
WHERE ($1::bool OR d.group_id = ANY($2))
  AND CASE ev.severity WHEN 'disaster' THEN 4 WHEN 'high' THEN 3 WHEN 'average' THEN 2 WHEN 'warning' THEN 1 ELSE 0 END >= $8::int
  AND (NOT $9::bool OR (ev.ts, ev.device_id, ev.kind, ev.dig) < ($10, $11, $12, $13))
ORDER BY ev.ts DESC, ev.device_id DESC, ev.kind DESC, ev.dig DESC
LIMIT $14::int`

/*
listEvents serves the syslog and trap feed, newest first. Visibility follows
the devices: a device_id outside the caller's groups answers 404, other rows
of foreign devices are not returned.
*/
func (s *server) listEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	kind, okK := single(q, "kind")
	qtext, okQ := single(q, "q")
	qtext = strings.TrimSpace(qtext)
	sevMin, okS := single(q, "severity_min")
	curS, okC := single(q, "cursor")
	limit, okL := queryInt(q, "limit", defaultEventPage, 1, maxEventPage)
	from, to, okW := s.eventWindow(q)
	var devID int64
	if v, okD := single(q, "device_id"); !okD {
		writeError(w, errBadRequest)
		return
	} else if v != "" {
		var err error
		if devID, err = strconv.ParseInt(v, 10, 64); err != nil || devID < 1 {
			writeError(w, errBadRequest)
			return
		}
	}
	rank := 0
	if sevMin != "" {
		var known bool
		rank, known = severityRank[sevMin]
		okS = okS && known
	}
	var cur eventCursor
	if curS != "" {
		okC = okC && decodeCursor(curS, &cur) && (cur.Kind == "syslog" || cur.Kind == "trap" || cur.Kind == "storm") && hex32.MatchString(cur.Dig)
	}
	if !okK || !okQ || !okS || !okC || !okL || !okW || (kind != "" && kind != "syslog" && kind != "trap" && kind != "storm") ||
		utf8.RuneCountInString(qtext) > maxEventQuery || strings.ContainsFunc(qtext, func(r rune) bool { return unicode.IsControl(r) }) {
		writeError(w, errBadRequest)
		return
	}
	sc, err := s.scope(r, rbac.PermDevicesRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if devID != 0 {
		if _, err := s.deviceIn(r, sc, devID); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if !sc.all && len(sc.ids) == 0 {
		writeJSON(w, http.StatusOK, eventsPage{Items: []eventResponse{}})
		return
	}
	rows, err := s.pool.Query(r.Context(), eventsSQL, sc.all, sc.ids, kind, devID, from, to, qtext, rank,
		curS != "", time.UnixMicro(cur.TS).UTC(), cur.Dev, cur.Kind, cur.Dig, limit+1)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	digs := make([]string, 0, limit+1)
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (eventResponse, error) {
		var (
			e     eventResponse
			label string
			vb    []byte
			dig   string
		)
		if err := row.Scan(&e.TS, &e.Kind, &e.DeviceID, &e.DeviceName, &e.Severity, &label, &e.Text, &e.Identified, &vb, &e.VarbindsOmitted, &e.Count, &dig); err != nil {
			return e, err
		}
		switch e.Kind {
		case "syslog":
			e.App = &label
		case "trap":
			e.Name = &label
		}
		e.Varbinds = vb
		digs = append(digs, dig)
		return e, nil
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := eventsPage{Items: items}
	if len(items) > limit {
		out.Items = items[:limit]
		last := out.Items[limit-1]
		c := encodeCursor(eventCursor{TS: last.TS.UnixMicro(), Dev: last.DeviceID, Kind: last.Kind, Dig: digs[limit-1]})
		out.NextCursor = &c
	}
	if out.Items == nil {
		out.Items = []eventResponse{}
	}
	writeJSON(w, http.StatusOK, out)
}

type unidentifiedResponse struct {
	TrapOID        string          `json:"trap_oid"`
	Count          int64           `json:"count"`
	LastTS         time.Time       `json:"last_ts"`
	LastDeviceID   int64           `json:"last_device_id"`
	LastDeviceName string          `json:"last_device_name"`
	LastVarbinds   json.RawMessage `json:"last_varbinds,omitempty"`
	/* LastVarbindsOmitted is set when the varbinds exceed the listing limit and were left out. */
	LastVarbindsOmitted bool `json:"last_varbinds_omitted,omitempty"`
}

type unidentifiedPage struct {
	Items      []unidentifiedResponse `json:"items"`
	NextCursor *string                `json:"next_cursor"`
}

type unidentifiedCursor struct {
	TS  int64  `json:"t"`
	OID string `json:"o"`
}

/* unidentifiedSQL groups unidentified traps of visible devices by OID, newest group first; $1 all, $2 ids, $3 from, $4 to, $5 cursor given, $6-$7 cursor, $8 limit. */
const unidentifiedSQL = `
WITH u AS MATERIALIZED (
  SELECT t.trap_oid, t.ts, t.device_id, d.name AS device_name,
         CASE WHEN octet_length(t.varbinds::text) <= 16384 THEN t.varbinds END AS varbinds,
         coalesce(octet_length(t.varbinds::text) > 16384, false) AS omitted
  FROM events.trap t JOIN core.device d ON d.id = t.device_id
  WHERE NOT t.identified AND NOT EXISTS (SELECT 1 FROM events.trap_rule r WHERE r.trap_oid = t.trap_oid) AND t.ts >= $3 AND t.ts < $4 AND ($1::bool OR d.group_id = ANY($2))
), g AS (
  SELECT trap_oid, count(*) AS cnt, max(ts) AS last_ts FROM u GROUP BY trap_oid
), l AS (
  SELECT DISTINCT ON (trap_oid) trap_oid, device_id, device_name, varbinds, omitted
  FROM u ORDER BY trap_oid, ts DESC, device_id DESC
)
SELECT g.trap_oid, g.cnt, g.last_ts, l.device_id, l.device_name, l.varbinds, l.omitted
FROM g JOIN l USING (trap_oid)
WHERE NOT $5::bool OR (g.last_ts, g.trap_oid) < ($6, $7)
ORDER BY g.last_ts DESC, g.trap_oid DESC
LIMIT $8::int`

/* listUnidentified groups traps no rule or driver could name by trap_oid, with a count and the newest varbinds. */
func (s *server) listUnidentified(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	curS, okC := single(q, "cursor")
	limit, okL := queryInt(q, "limit", defaultUnidentified, 1, maxEventPage)
	from, to, okW := s.eventWindow(q)
	var cur unidentifiedCursor
	if curS != "" {
		okC = okC && decodeCursor(curS, &cur) && cur.OID != "" && len(cur.OID) <= maxTrapRuleOID
	}
	if !okC || !okL || !okW {
		writeError(w, errBadRequest)
		return
	}
	sc, err := s.scope(r, rbac.PermDevicesRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := unidentifiedPage{Items: []unidentifiedResponse{}}
	if !sc.all && len(sc.ids) == 0 {
		writeJSON(w, http.StatusOK, out)
		return
	}
	rows, err := s.pool.Query(r.Context(), unidentifiedSQL, sc.all, sc.ids, from, to,
		curS != "", time.UnixMicro(cur.TS).UTC(), cur.OID, limit+1)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (unidentifiedResponse, error) {
		var (
			u  unidentifiedResponse
			vb []byte
		)
		err := row.Scan(&u.TrapOID, &u.Count, &u.LastTS, &u.LastDeviceID, &u.LastDeviceName, &vb, &u.LastVarbindsOmitted)
		u.LastVarbinds = vb
		return u, err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out.Items = items
	if len(items) > limit {
		out.Items = items[:limit]
		last := out.Items[limit-1]
		c := encodeCursor(unidentifiedCursor{TS: last.LastTS.UnixMicro(), OID: last.TrapOID})
		out.NextCursor = &c
	}
	if out.Items == nil {
		out.Items = []unidentifiedResponse{}
	}
	writeJSON(w, http.StatusOK, out)
}

type trapRuleResponse struct {
	ID        int64     `json:"id"`
	TrapOID   string    `json:"trap_oid"`
	Name      string    `json:"name"`
	Severity  string    `json:"severity"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *server) listTrapRules(w http.ResponseWriter, r *http.Request) {
	rows, err := s.pool.Query(r.Context(), `SELECT id, trap_oid, name, severity, created_at FROM events.trap_rule ORDER BY id`)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[trapRuleResponse])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []trapRuleResponse{}
	}
	writeJSON(w, http.StatusOK, out)
}

/* validTrapOID accepts the canonical form the trap decoder produces: 1..128 sub-identifiers, each below 2^32, no leading dot or zeros, at most trap.MaxTrapOIDLen bytes. */
func validTrapOID(oid string) bool {
	if oid == "" || len(oid) > trap.MaxTrapOIDLen {
		return false
	}
	parts := strings.Split(oid, ".")
	if len(parts) > maxOIDSubIDs {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 10 || (len(p) > 1 && p[0] == '0') {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
		if n, err := strconv.ParseUint(p, 10, 64); err != nil || n > maxSubID {
			return false
		}
	}
	return true
}

func validTrapRuleName(n string) bool {
	return n != "" && len(n) <= maxTrapRuleName && utf8.ValidString(n) &&
		strings.TrimSpace(n) == n && !strings.ContainsFunc(n, unicode.IsControl)
}

/* createTrapRule names a trap OID; eventd reloads the rules on the NOTIFY of the table's trigger. */
func (s *server) createTrapRule(w http.ResponseWriter, r *http.Request) {
	var in struct {
		TrapOID  string `json:"trap_oid"`
		Name     string `json:"name"`
		Severity string `json:"severity"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if !validTrapOID(in.TrapOID) || !validTrapRuleName(in.Name) || !trapSeverities[in.Severity] {
		writeError(w, errBadRequest)
		return
	}
	var id int64
	ev := audit.Event{Action: "trap_rules.create", ObjectType: "trap_rule",
		Details: map[string]any{"trap_oid": in.TrapOID, "name": in.Name, "severity": in.Severity}}
	if !s.change(w, r, ev, func(tx pgx.Tx, ev *audit.Event) error {
		err := tx.QueryRow(r.Context(),
			`INSERT INTO events.trap_rule (trap_oid, name, severity) VALUES ($1, $2, $3) RETURNING id`,
			in.TrapOID, in.Name, in.Severity).Scan(&id)
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23505" {
			return errTrapRuleDup
		}
		if err != nil {
			return err
		}
		ev.ObjectID = strconv.FormatInt(id, 10)
		return nil
	}) {
		return
	}
	writeJSON(w, http.StatusCreated, idResponse{ID: id})
}

func (s *server) deleteTrapRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	ev := audit.Event{Action: "trap_rules.delete", ObjectType: "trap_rule", ObjectID: strconv.FormatInt(id, 10)}
	if !s.change(w, r, ev, func(tx pgx.Tx, ev *audit.Event) error {
		var oid, name string
		err := tx.QueryRow(r.Context(), `DELETE FROM events.trap_rule WHERE id = $1 RETURNING trap_oid, name`, id).Scan(&oid, &name)
		if errors.Is(err, pgx.ErrNoRows) {
			return errTrapRuleNotFound
		}
		if err != nil {
			return err
		}
		ev.Details = map[string]any{"trap_oid": oid, "name": name}
		return nil
	}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

var errTrapRuleNotFound = errors.New("httpapi: trap rule not found")
