package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/audit"
	"github.com/beekamai/network-scheme/internal/notify"
	"github.com/beekamai/network-scheme/internal/rbac"
	"github.com/beekamai/network-scheme/internal/triggers"
)

/* Limits of the problem list and of acknowledgement comments (mirrors the CHECK on problems.ack). */
const (
	defaultProblemPage = 100
	maxProblemPage     = 500
	maxAckComment      = 1000
)

var (
	errProblemNotFound = errors.New("httpapi: problem not found")
	errProblemClosed   = errors.New("httpapi: problem is resolved")
)

type problemResponse struct {
	ID         int64      `json:"id"`
	DeviceID   *int64     `json:"device_id"`
	DeviceName string     `json:"device_name"`
	GroupID    *int64     `json:"group_id"`
	Severity   string     `json:"severity"`
	State      string     `json:"state"`
	Suppressed bool       `json:"suppressed"`
	Name       string     `json:"name"`
	TriggerID  *int64     `json:"trigger_id"`
	SystemKind *string    `json:"system_kind"`
	Object     string     `json:"object"`
	OpenedAt   time.Time  `json:"opened_at"`
	AckedAt    *time.Time `json:"acknowledged_at"`
	ResolvedAt *time.Time `json:"resolved_at"`
	ResolveWhy *string    `json:"resolve_reason"`
	LastValue  *string    `json:"last_value"`
	trigName   *string
}

type problemsPage struct {
	Items      []problemResponse `json:"items"`
	NextCursor *string           `json:"next_cursor"`
}

type ackResponse struct {
	ID       int64     `json:"id"`
	UserID   int64     `json:"user_id"`
	Username *string   `json:"username"`
	Comment  string    `json:"comment"`
	At       time.Time `json:"at"`
}

type problemDetail struct {
	problemResponse
	Acks []ackResponse `json:"acks"`
}

type problemCursor struct {
	T  int64 `json:"t"` /* opened_at, microseconds since the epoch */
	ID int64 `json:"i"`
}

/* problemSelect lists the columns scanProblem reads; the caller adds the scope and the filters. */
const problemSelect = `
SELECT p.id, p.device_id, coalesce(d.name, ''), d.group_id, p.severity, p.state, p.suppressed, tr.name, p.trigger_id,
       p.system_kind, p.object, p.opened_at, p.acknowledged_at, p.resolved_at, p.resolve_reason, p.last_value
FROM problems.problem p
LEFT JOIN core.device d ON d.id = p.device_id
LEFT JOIN core.trigger tr ON tr.id = p.trigger_id`

func scanProblem(r pgx.Row) (problemResponse, error) {
	var p problemResponse
	err := r.Scan(&p.ID, &p.DeviceID, &p.DeviceName, &p.GroupID, &p.Severity, &p.State, &p.Suppressed, &p.trigName, &p.TriggerID,
		&p.SystemKind, &p.Object, &p.OpenedAt, &p.AckedAt, &p.ResolvedAt, &p.ResolveWhy, &p.LastValue)
	p.Name = problemTitle(p.trigName, p.TriggerID, p.SystemKind)
	return p, err
}

/* problemTitle names a problem like the engine does: the trigger's name, else the system kind's title. */
func problemTitle(trigName *string, trigID *int64, sysKind *string) string {
	switch {
	case trigName != nil:
		return *trigName
	case trigID != nil:
		return fmt.Sprintf("Trigger %d", *trigID)
	case sysKind != nil:
		return triggers.SystemName(*sysKind)
	}
	return ""
}

/* inGroups reports whether a problem of a device in group (nil: no device) is visible: device-less problems need a global scope. */
func (g groupScope) inGroups(group *int64) bool {
	if group == nil {
		return g.all
	}
	return g.has(*group)
}

/*
listProblems serves problems newest first, limited to devices in the caller's
groups; problems without a device are for global bindings only. Filters:
state, severity_min, device_id (404 when not visible), group_id (the group and
its subgroups; 404 when not visible) and suppressed (true: only suppressed,
false: only the others; absent: both). Paging is by an opaque cursor.
*/
func (s *server) listProblems(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state, okS := single(q, "state")
	sevMin, okV := single(q, "severity_min")
	supp, okP := single(q, "suppressed")
	curS, okC := single(q, "cursor")
	limit, okL := queryInt(q, "limit", defaultProblemPage, 1, maxProblemPage)
	ids := [2]int64{}
	okI := true
	for i, name := range []string{"device_id", "group_id"} {
		v, ok := single(q, name)
		okI = okI && ok
		if v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 1 {
				okI = false
			}
			ids[i] = n
		}
	}
	rank := 0
	if sevMin != "" {
		var known bool
		rank, known = severityRank[sevMin]
		okV = okV && known
	}
	var cur problemCursor
	if curS != "" {
		okC = okC && decodeCursor(curS, &cur) && cur.ID > 0
	}
	if !okS || !okV || !okP || !okC || !okL || !okI ||
		(state != "" && state != "problem" && state != "acknowledged" && state != "resolved") ||
		(supp != "" && supp != "true" && supp != "false") {
		writeError(w, errBadRequest)
		return
	}
	sc, err := s.scope(r, rbac.PermDevicesRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if ids[0] != 0 {
		if _, err := s.deviceIn(r, sc, ids[0]); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if ids[1] != 0 && !sc.has(ids[1]) {
		writeError(w, errNotFound)
		return
	}
	out := problemsPage{Items: []problemResponse{}}
	if !sc.all && len(sc.ids) == 0 {
		writeJSON(w, http.StatusOK, out)
		return
	}
	rows, err := s.pool.Query(r.Context(), `WITH RECURSIVE sub (id, depth) AS (
  SELECT id, 0 FROM core.device_group WHERE id = $6
  UNION ALL
  SELECT g.id, sub.depth + 1 FROM core.device_group g JOIN sub ON g.parent_id = sub.id WHERE sub.depth < 64
)`+problemSelect+`
WHERE ($1::bool OR d.group_id = ANY($2))
  AND ($3::text = '' OR p.state = $3)
  AND CASE p.severity WHEN 'disaster' THEN 4 WHEN 'high' THEN 3 WHEN 'average' THEN 2 WHEN 'warning' THEN 1 ELSE 0 END >= $4::int
  AND ($5::bigint = 0 OR p.device_id = $5)
  AND ($6::bigint = 0 OR d.group_id IN (SELECT id FROM sub))
  AND ($7::text = '' OR p.suppressed = ($7 = 'true'))
  AND (NOT $8::bool OR (p.opened_at, p.id) < ($9, $10))
ORDER BY p.opened_at DESC, p.id DESC
LIMIT $11::int`,
		sc.all, sc.ids, state, rank, ids[0], ids[1], supp, curS != "", time.UnixMicro(cur.T).UTC(), cur.ID, limit+1)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (problemResponse, error) { return scanProblem(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out.Items = items
	if len(items) > limit {
		out.Items = items[:limit]
		last := out.Items[limit-1]
		c := encodeCursor(problemCursor{T: last.OpenedAt.UnixMicro(), ID: last.ID})
		out.NextCursor = &c
	}
	if out.Items == nil {
		out.Items = []problemResponse{}
	}
	writeJSON(w, http.StatusOK, out)
}

/* getProblem returns one problem with its acknowledgement history, oldest first; a problem outside the caller's groups answers 404. */
func (s *server) getProblem(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	sc, err := s.scope(r, rbac.PermDevicesRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p, err := scanProblem(s.pool.QueryRow(r.Context(), problemSelect+` WHERE p.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !sc.inGroups(p.GroupID)) {
		writeError(w, errNotFound)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.pool.Query(r.Context(), `SELECT a.id, a.user_id, u.username, a.comment, a.at
FROM problems.ack a LEFT JOIN core."user" u ON u.id = a.user_id WHERE a.problem_id = $1 ORDER BY a.id`, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	acks, err := pgx.CollectRows(rows, pgx.RowToStructByPos[ackResponse])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if acks == nil {
		acks = []ackResponse{}
	}
	writeJSON(w, http.StatusOK, problemDetail{problemResponse: p, Acks: acks})
}

/* validAckComment accepts 1..1000 characters with some visible text; newlines and tabs are the only control characters allowed. */
func validAckComment(c string) bool {
	return utf8.ValidString(c) && utf8.RuneCountInString(c) <= maxAckComment && strings.TrimSpace(c) != "" &&
		!strings.ContainsFunc(c, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' })
}

/*
ackProblem records an acknowledgement. The first one moves the problem from
"problem" to "acknowledged" and is announced on the live feed (after the
commit, and not for suppressed problems, which were never announced); later
ones only add history rows. A resolved problem answers 409 problem_resolved.
*/
func (s *server) ackProblem(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		Comment string `json:"comment"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if !validAckComment(in.Comment) {
		writeError(w, errBadRequest)
		return
	}
	sc, err := s.scope(r, rbac.PermProblemsAck)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sess, _ := sessionFrom(r.Context())
	var announce *notify.ProblemSummary
	ev := audit.Event{Action: "problems.ack", ObjectType: "problem", ObjectID: strconv.FormatInt(id, 10), Details: map[string]any{"comment": in.Comment}}
	if !s.change(w, r, ev, func(tx pgx.Tx, _ *audit.Event) error {
		announce = nil
		p, err := scanProblem(tx.QueryRow(r.Context(), problemSelect+` WHERE p.id = $1 FOR UPDATE OF p`, id))
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && !sc.inGroups(p.GroupID)) {
			return errProblemNotFound
		}
		if err != nil {
			return err
		}
		if p.State == "resolved" {
			return errProblemClosed
		}
		if _, err := tx.Exec(r.Context(), `INSERT INTO problems.ack (problem_id, user_id, comment) VALUES ($1, $2, $3)`,
			id, sess.sess.UserID, in.Comment); err != nil {
			return err
		}
		if p.State != "problem" {
			return nil
		}
		if err := tx.QueryRow(r.Context(),
			`UPDATE problems.problem SET state = 'acknowledged', acknowledged_at = now() WHERE id = $1 AND state = 'problem' RETURNING acknowledged_at`,
			id).Scan(&p.AckedAt); err != nil {
			return err
		}
		p.State = "acknowledged"
		if !p.Suppressed {
			announce = &notify.ProblemSummary{ID: p.ID, DeviceID: p.DeviceID, DeviceName: p.DeviceName, GroupID: p.GroupID, Severity: p.Severity,
				State: p.State, Suppressed: p.Suppressed, Name: p.Name, Object: p.Object, OpenedAt: p.OpenedAt, AckedAt: p.AckedAt, ResolvedAt: p.ResolvedAt}
		}
		return nil
	}) {
		return
	}
	if announce != nil {
		s.hub.Publish(notify.Message{Type: notify.MessageTypeProblem, Event: notify.EventAcknowledged, Problem: *announce})
	}
	w.WriteHeader(http.StatusNoContent)
}
