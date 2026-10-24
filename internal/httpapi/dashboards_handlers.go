package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/audit"
	"github.com/beekamai/network-scheme/internal/rbac"
)

/*
Limits of dashboards. The widget count, the row bound and the height bound
mirror core.dashboard_widget (the DB caps 50 widgets and 50 dashboards per
owner, shared ones counting together); the grid is 12 columns wide.
*/
const (
	maxDashboardList = 100 /* own (≤ 50) and shared (≤ 50) */
	maxWidgets       = 50
	gridCols         = 12
	maxGridY         = 1000
	maxWidgetH       = 48
	maxWidgetConfig  = 2048 /* bytes of one widget's config as sent */
	maxWidgetTitle   = 100
)

var (
	errDashboardNotFound = errors.New("httpapi: dashboard not found")
	errDashboardShared   = errors.New("httpapi: shared dashboard needs dashboards.manage")
	errDashboardInvalid  = errors.New("httpapi: invalid dashboard change")
	errCapDashboards     = errors.New("httpapi: too many dashboards")
	errCapWidgets        = errors.New("httpapi: too many widgets")
)

/*
widgetTypes is the closed set of widget types with their config schemas. A
config is one JSON object with only the listed fields (unknown fields, wrong
types and values out of range are refused); the stored form is the decoded
struct encoded again, so it never carries nulls, duplicates or extra space.
The web widget registry (web/app/src/widgets) mirrors these schemas.
*/
var widgetTypes = map[string]func(json.RawMessage) (any, bool){
	"device_status": strictConfig(func(c *struct {
		Title string `json:"title,omitempty"`
	}) bool {
		return validWidgetTitle(c.Title)
	}),
	"problems": strictConfig(func(c *struct {
		Title       string `json:"title,omitempty"`
		SeverityMin string `json:"severity_min,omitempty"`
		Limit       *int   `json:"limit,omitempty"`
	}) bool {
		return validWidgetTitle(c.Title) && validSeverityMin(c.SeverityMin) && limitIn(c.Limit, 50)
	}),
	"top_devices": strictConfig(func(c *struct {
		Title  string `json:"title,omitempty"`
		Metric string `json:"metric"`
		Limit  *int   `json:"limit,omitempty"`
	}) bool {
		return validWidgetTitle(c.Title) && topDeviceMetrics[c.Metric] && limitIn(c.Limit, maxTopLimit)
	}),
	"log_stream": strictConfig(func(c *struct {
		Title       string `json:"title,omitempty"`
		Kind        string `json:"kind,omitempty"`
		SeverityMin string `json:"severity_min,omitempty"`
		Limit       *int   `json:"limit,omitempty"`
	}) bool {
		return validWidgetTitle(c.Title) && (c.Kind == "" || c.Kind == "syslog" || c.Kind == "trap") &&
			validSeverityMin(c.SeverityMin) && limitIn(c.Limit, 100)
	}),
	"metric_chart": strictConfig(func(c *struct {
		Title    string `json:"title,omitempty"`
		DeviceID int64  `json:"device_id"`
		Metric   string `json:"metric"`
		IfIndex  *int   `json:"if_index,omitempty"`
		Range    string `json:"range,omitempty"`
	}) bool {
		traffic := c.Metric == "traffic"
		return validWidgetTitle(c.Title) && c.DeviceID >= 1 &&
			(traffic || c.Metric == "cpu" || c.Metric == "mem" || c.Metric == "temp") &&
			(traffic == (c.IfIndex != nil)) && validIfIndex(c.IfIndex) &&
			(c.Range == "" || c.Range == "1h" || c.Range == "6h" || c.Range == "24h" || c.Range == "7d")
	}),
	"top_interfaces": strictConfig(func(c *struct {
		Title string `json:"title,omitempty"`
		Limit *int   `json:"limit,omitempty"`
	}) bool {
		return validWidgetTitle(c.Title) && limitIn(c.Limit, maxTopLimit)
	}),
	"recent_changes": strictConfig(func(c *struct {
		Title string `json:"title,omitempty"`
		Limit *int   `json:"limit,omitempty"`
	}) bool {
		return validWidgetTitle(c.Title) && limitIn(c.Limit, maxTopLimit)
	}),
	"mini_map": strictConfig(func(c *struct {
		Title  string `json:"title,omitempty"`
		ViewID *int64 `json:"view_id,omitempty"`
	}) bool {
		return validWidgetTitle(c.Title) && (c.ViewID == nil || *c.ViewID >= 1)
	}),
}

/* strictConfig decodes exactly one JSON object into a fresh T with known fields only and checks it. */
func strictConfig[T any](check func(*T) bool) func(json.RawMessage) (any, bool) {
	return func(raw json.RawMessage) (any, bool) {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 || raw[0] != '{' {
			return nil, false
		}
		var c T
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if dec.Decode(&c) != nil || dec.Decode(&struct{}{}) != io.EOF || !check(&c) {
			return nil, false
		}
		return &c, true
	}
}

/* validWidgetTitle: empty (the widget's own title) or up to 100 characters without control characters. */
func validWidgetTitle(t string) bool {
	return t == "" || (utf8.ValidString(t) && utf8.RuneCountInString(t) <= maxWidgetTitle && !strings.ContainsFunc(t, unicode.IsControl))
}

func validSeverityMin(s string) bool {
	_, ok := severityRank[s]
	return s == "" || ok
}

/* limitIn: absent or 1..hi. */
func limitIn(v *int, hi int) bool { return v == nil || (*v >= 1 && *v <= hi) }

/* canonicalWidgetConfig validates raw against the schema of typ and returns its stored form. */
func canonicalWidgetConfig(typ string, raw json.RawMessage) ([]byte, bool) {
	check, ok := widgetTypes[typ]
	if !ok || len(raw) > maxWidgetConfig {
		return nil, false
	}
	c, ok := check(raw)
	if !ok {
		return nil, false
	}
	b, err := json.Marshal(c)
	return b, err == nil
}

type dashboardResponse struct {
	ID             int64   `json:"id"`
	Name           string  `json:"name"`
	Shared         bool    `json:"shared"`
	DefaultForRole *string `json:"default_for_role"`
	Editable       bool    `json:"editable"`
}

type widgetResponse struct {
	ID     int64           `json:"id"`
	Type   string          `json:"type"`
	X      int             `json:"x"`
	Y      int             `json:"y"`
	W      int             `json:"w"`
	H      int             `json:"h"`
	Config json.RawMessage `json:"config"`
}

type dashboardDetailResponse struct {
	dashboardResponse
	Widgets []widgetResponse `json:"widgets"`
}

/* dashboardCaller returns the user of the request and whether it holds dashboards.manage (a global admin binding). */
func (s *server) dashboardCaller(r *http.Request) (uid int64, manage bool, err error) {
	sc, _ := sessionFrom(r.Context())
	subj, err := s.rbac.LoadSubject(r.Context(), sc.sess.UserID)
	if err != nil {
		return 0, false, err
	}
	return sc.sess.UserID, subj.Can(rbac.PermDashboardsManage, nil, nil), nil
}

/* listDashboards lists the caller's personal dashboards and every shared one. */
func (s *server) listDashboards(w http.ResponseWriter, r *http.Request) {
	uid, manage, err := s.dashboardCaller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.pool.Query(r.Context(), `SELECT id, name, shared, default_for_role FROM core.dashboard
		WHERE owner_id = $1 OR shared ORDER BY shared DESC, name, id LIMIT $2`, uid, maxDashboardList)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (dashboardResponse, error) {
		var d dashboardResponse
		err := row.Scan(&d.ID, &d.Name, &d.Shared, &d.DefaultForRole)
		d.Editable = !d.Shared || manage
		return d, err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []dashboardResponse{}
	}
	writeJSON(w, http.StatusOK, out)
}

/* dashboardCapError maps the cap triggers of core.dashboard and core.dashboard_widget. */
func dashboardCapError(err error) error {
	if pe := pgErrOf(err); pe != nil && pe.Code == "23514" {
		switch pe.Message {
		case "too many dashboards":
			return errCapDashboards
		case "too many widgets":
			return errCapWidgets
		}
	}
	return err
}

/*
takeRoleDefault makes no dashboard the default of role, so that the caller can
give it to another one. The lock serializes concurrent changes of defaults, so
the unique index on default_for_role never fires.
*/
func takeRoleDefault(r *http.Request, tx pgx.Tx, role string) error {
	if _, err := tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtext('core.dashboard.default'))`); err != nil {
		return err
	}
	_, err := tx.Exec(r.Context(), `UPDATE core.dashboard SET default_for_role = NULL WHERE default_for_role = $1`, role)
	return err
}

/*
createDashboard adds a personal dashboard, or a shared one (dashboards.manage),
optionally the default of a role (shared only; the former default of the role
stops being one).
*/
func (s *server) createDashboard(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name           string  `json:"name"`
		Shared         bool    `json:"shared"`
		DefaultForRole *string `json:"default_for_role"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if !validMapName(in.Name) || (in.DefaultForRole != nil && (!in.Shared || !rbac.Role(*in.DefaultForRole).Valid())) {
		writeError(w, errBadRequest)
		return
	}
	uid, manage, err := s.dashboardCaller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if in.Shared && !manage {
		writeError(w, errForbidden)
		return
	}
	var owner *int64
	if !in.Shared {
		owner = &uid
	}
	var id int64
	ev := audit.Event{Action: "dashboard.create", ObjectType: "dashboard",
		Details: map[string]any{"name": in.Name, "shared": in.Shared, "default_for_role": in.DefaultForRole}}
	if !s.change(w, r, ev, func(tx pgx.Tx, ev *audit.Event) error {
		if in.DefaultForRole != nil {
			if err := takeRoleDefault(r, tx, *in.DefaultForRole); err != nil {
				return err
			}
		}
		if err := tx.QueryRow(r.Context(), `INSERT INTO core.dashboard (owner_id, name, shared, default_for_role) VALUES ($1, $2, $3, $4) RETURNING id`,
			owner, in.Name, in.Shared, in.DefaultForRole).Scan(&id); err != nil {
			return dashboardCapError(err)
		}
		ev.ObjectID = strconv.FormatInt(id, 10)
		return nil
	}) {
		return
	}
	writeJSON(w, http.StatusCreated, idResponse{ID: id})
}

/*
lockDashboard locks dashboard id for a change by the caller: a personal
dashboard of another user is not found (as a missing one), a shared one needs
dashboards.manage. It reports whether the dashboard is shared.
*/
func lockDashboard(r *http.Request, tx pgx.Tx, id, uid int64, manage bool) (shared bool, err error) {
	var owner *int64
	err = tx.QueryRow(r.Context(), `SELECT owner_id, shared FROM core.dashboard WHERE id = $1 FOR UPDATE`, id).Scan(&owner, &shared)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return false, errDashboardNotFound
	case err != nil:
		return false, err
	case !shared && (owner == nil || *owner != uid):
		return false, errDashboardNotFound
	case shared && !manage:
		return false, errDashboardShared
	}
	return shared, nil
}

/* getDashboard returns a dashboard with its widgets; a personal dashboard of another user answers 404. */
func (s *server) getDashboard(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	uid, manage, err := s.dashboardCaller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.dashboardDetail(r, id, uid, manage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

/* dashboardDetail reads a dashboard visible to uid with its widgets in reading order. */
func (s *server) dashboardDetail(r *http.Request, id, uid int64, manage bool) (dashboardDetailResponse, error) {
	var (
		out   dashboardDetailResponse
		owner *int64
	)
	err := s.pool.QueryRow(r.Context(), `SELECT id, name, shared, default_for_role, owner_id FROM core.dashboard WHERE id = $1`, id).
		Scan(&out.ID, &out.Name, &out.Shared, &out.DefaultForRole, &owner)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !out.Shared && (owner == nil || *owner != uid)) {
		return out, errDashboardNotFound
	}
	if err != nil {
		return out, err
	}
	out.Editable = !out.Shared || manage
	rows, err := s.pool.Query(r.Context(), `SELECT id, type, x, y, w, h, config FROM core.dashboard_widget
		WHERE dashboard_id = $1 ORDER BY y, x, id LIMIT $2`, id, maxWidgets)
	if err != nil {
		return out, err
	}
	out.Widgets, err = pgx.CollectRows(rows, pgx.RowToStructByPos[widgetResponse])
	if out.Widgets == nil {
		out.Widgets = []widgetResponse{}
	}
	return out, err
}

/*
updateDashboard renames a dashboard and, for a shared one, makes it the
default of a role or no role's default (default_for_role null).
*/
func (s *server) updateDashboard(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		Name           *string         `json:"name"`
		DefaultForRole json.RawMessage `json:"default_for_role"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	var role *string
	setRole := in.DefaultForRole != nil
	if (in.Name == nil && !setRole) || (in.Name != nil && !validMapName(*in.Name)) ||
		(setRole && (json.Unmarshal(in.DefaultForRole, &role) != nil || (role != nil && !rbac.Role(*role).Valid()))) {
		writeError(w, errBadRequest)
		return
	}
	uid, manage, err := s.dashboardCaller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ev := audit.Event{Action: "dashboard.update", ObjectType: "dashboard", ObjectID: strconv.FormatInt(id, 10), Details: map[string]any{}}
	if in.Name != nil {
		ev.Details["name"] = *in.Name
	}
	if setRole {
		ev.Details["default_for_role"] = role
	}
	if !s.change(w, r, ev, func(tx pgx.Tx, _ *audit.Event) error {
		if role != nil {
			/* The default lock comes before the row lock, as in createDashboard. */
			if err := takeRoleDefault(r, tx, *role); err != nil {
				return err
			}
		}
		shared, err := lockDashboard(r, tx, id, uid, manage)
		if err != nil {
			return err
		}
		if role != nil && !shared {
			return errDashboardInvalid
		}
		_, err = tx.Exec(r.Context(), `UPDATE core.dashboard SET name = coalesce($2, name),
			default_for_role = CASE WHEN $3::bool THEN $4 ELSE default_for_role END WHERE id = $1`, id, in.Name, setRole, role)
		return err
	}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

/* deleteDashboard removes a dashboard with its widgets. */
func (s *server) deleteDashboard(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	uid, manage, err := s.dashboardCaller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ev := audit.Event{Action: "dashboard.delete", ObjectType: "dashboard", ObjectID: strconv.FormatInt(id, 10)}
	if !s.change(w, r, ev, func(tx pgx.Tx, ev *audit.Event) error {
		if _, err := lockDashboard(r, tx, id, uid, manage); err != nil {
			return err
		}
		var name string
		if err := tx.QueryRow(r.Context(), `DELETE FROM core.dashboard WHERE id = $1 RETURNING name`, id).Scan(&name); err != nil {
			return err
		}
		ev.Details = map[string]any{"name": name}
		return nil
	}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type widgetIn struct {
	ID     *int64          `json:"id"`
	Type   string          `json:"type"`
	X      int             `json:"x"`
	Y      int             `json:"y"`
	W      int             `json:"w"`
	H      int             `json:"h"`
	Config json.RawMessage `json:"config"`
}

/* validLayout: inside the 12-column grid, at most 1000 rows down, 1..48 rows high. */
func (wi widgetIn) validLayout() bool {
	return wi.X >= 0 && wi.W >= 1 && wi.X+wi.W <= gridCols && wi.Y >= 0 && wi.Y <= maxGridY && wi.H >= 1 && wi.H <= maxWidgetH
}

/*
putWidgets replaces the widgets of a dashboard with the given set (layout and
configs saved at once): a widget with an id of this dashboard is updated, one
without an id is added, and the ones left out are removed. Every config is
checked against the schema of its type. It answers the stored dashboard.
*/
func (s *server) putWidgets(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		Widgets []widgetIn `json:"widgets"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Widgets == nil || len(in.Widgets) > maxWidgets {
		writeError(w, errBadRequest)
		return
	}
	configs := make([][]byte, len(in.Widgets))
	given := []int64{} /* never nil: NOT (id = ANY(NULL)) would keep every row */
	for i, wi := range in.Widgets {
		c, ok := canonicalWidgetConfig(wi.Type, wi.Config)
		if !ok {
			writeError(w, errInvalidWidget)
			return
		}
		if !wi.validLayout() || (wi.ID != nil && (*wi.ID < 1 || slices.Contains(given, *wi.ID))) {
			writeError(w, errBadRequest)
			return
		}
		if wi.ID != nil {
			given = append(given, *wi.ID)
		}
		configs[i] = c
	}
	uid, manage, err := s.dashboardCaller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ev := audit.Event{Action: "dashboard.widgets.put", ObjectType: "dashboard", ObjectID: strconv.FormatInt(id, 10)}
	if !s.change(w, r, ev, func(tx pgx.Tx, ev *audit.Event) error {
		if _, err := lockDashboard(r, tx, id, uid, manage); err != nil {
			return err
		}
		rows, err := tx.Query(r.Context(), `SELECT id FROM core.dashboard_widget WHERE dashboard_id = $1`, id)
		if err != nil {
			return err
		}
		existing, err := pgx.CollectRows(rows, pgx.RowTo[int64])
		if err != nil {
			return err
		}
		for _, g := range given {
			if !slices.Contains(existing, g) {
				return errDashboardInvalid
			}
		}
		tag, err := tx.Exec(r.Context(), `DELETE FROM core.dashboard_widget WHERE dashboard_id = $1 AND NOT (id = ANY($2::bigint[]))`, id, given)
		if err != nil {
			return err
		}
		added := 0
		for i, wi := range in.Widgets {
			if wi.ID != nil {
				_, err = tx.Exec(r.Context(), `UPDATE core.dashboard_widget SET type = $2, x = $3, y = $4, w = $5, h = $6, config = $7 WHERE id = $1`,
					*wi.ID, wi.Type, wi.X, wi.Y, wi.W, wi.H, configs[i])
			} else {
				added++
				_, err = tx.Exec(r.Context(), `INSERT INTO core.dashboard_widget (dashboard_id, type, x, y, w, h, config) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
					id, wi.Type, wi.X, wi.Y, wi.W, wi.H, configs[i])
			}
			if err != nil {
				return dashboardCapError(err)
			}
		}
		ev.Details = map[string]any{"widgets": len(in.Widgets), "added": added, "removed": tag.RowsAffected()}
		return nil
	}) {
		return
	}
	out, err := s.dashboardDetail(r, id, uid, manage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
