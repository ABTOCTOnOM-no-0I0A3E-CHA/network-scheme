package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/audit"
	"github.com/beekamai/network-scheme/internal/rbac"
)

/*
Limits of the map. The name and geometry bounds mirror the CHECKs of
core.map_view, core.map_area and core.map_node_position.
*/
const (
	maxMapName       = 200
	maxViews         = 100
	maxAreasPerView  = 2000
	maxPositionBatch = 5000
	mapCoordLimit    = 1e6
)

var (
	errMapNotFound = errors.New("httpapi: map object not found")
	errCapViews    = errors.New("httpapi: too many map views")
	errCapAreas    = errors.New("httpapi: too many map areas")
	errAreaLoop    = errors.New("httpapi: map area cycle")
	errAreaDepth   = errors.New("httpapi: map area chain too deep")
	errAreaView    = errors.New("httpapi: map area parent in another view")
)

var (
	viewKinds = map[string]bool{"logical": true, "plan": true}
	areaKinds = map[string]bool{"organization": true, "building": true, "floor": true, "room": true}
)

/*
Views and areas are global admin-entered objects, not device data: any caller
holding devices.read sees their names. What they reveal about devices (node
positions, the summary status of an area) is computed from visible devices only.
*/
type viewResponse struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	BackgroundID *int64 `json:"background_id"`
}

type areaResponse struct {
	ID       int64   `json:"id"`
	ParentID *int64  `json:"parent_id"`
	Kind     string  `json:"kind"`
	Name     string  `json:"name"`
	X        float64 `json:"x"`
	Y        float64 `json:"y"`
	W        float64 `json:"w"`
	H        float64 `json:"h"`
}

/* validMapName accepts 1..200 characters, no control characters, no surrounding space. */
func validMapName(n string) bool {
	return n != "" && utf8.RuneCountInString(n) <= maxMapName && utf8.ValidString(n) &&
		strings.TrimSpace(n) == n && !strings.ContainsFunc(n, unicode.IsControl)
}

/* finiteIn reports whether v is a finite number within [-mapCoordLimit, mapCoordLimit]. */
func finiteIn(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && math.Abs(v) <= mapCoordLimit
}

/* validRect checks the geometry of an area: bounded position, positive bounded size. */
func validRect(x, y, w, h float64) bool {
	return finiteIn(x) && finiteIn(y) && finiteIn(w) && finiteIn(h) && w > 0 && h > 0
}

/* nullableID is a JSON field that tells absent from null: set is true once the key is present. */
type nullableID struct {
	set bool
	v   *int64
}

func (n *nullableID) UnmarshalJSON(b []byte) error {
	n.set = true
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		n.v = nil
		return nil
	}
	var id int64
	if err := json.Unmarshal(b, &id); err != nil {
		return err
	}
	if id < 1 {
		return errors.New("id must be positive")
	}
	n.v = &id
	return nil
}

func (s *server) listViews(w http.ResponseWriter, r *http.Request) {
	rows, err := s.pool.Query(r.Context(), `SELECT id, name, kind, background_id FROM core.map_view ORDER BY id LIMIT $1`, maxViews)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[viewResponse])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []viewResponse{}
	}
	writeJSON(w, http.StatusOK, out)
}

/* bgFKError turns a missing background (foreign key violation) into 400. */
func bgFKError(err error) error {
	if pe := pgErrOf(err); pe != nil && pe.Code == "23503" {
		return errMapBackground
	}
	return err
}

var (
	errMapBackground = errors.New("httpapi: map background not found")
	errMapInvalid    = errors.New("httpapi: invalid map object")
)

func (s *server) createView(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name         string `json:"name"`
		Kind         string `json:"kind"`
		BackgroundID *int64 `json:"background_id"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if !validMapName(in.Name) || !viewKinds[in.Kind] || (in.BackgroundID != nil && *in.BackgroundID < 1) {
		writeError(w, errBadRequest)
		return
	}
	var id int64
	ev := audit.Event{Action: "map.view.create", ObjectType: "map_view",
		Details: map[string]any{"name": in.Name, "kind": in.Kind, "background_id": in.BackgroundID}}
	if !s.change(w, r, ev, func(tx pgx.Tx, ev *audit.Event) error {
		/* One lock serializes concurrent creates so the cap counts each other. */
		if _, err := tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtext('core.map_view.cap'))`); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM core.map_view`).Scan(&n); err != nil {
			return err
		}
		if n >= maxViews {
			return errCapViews
		}
		if err := tx.QueryRow(r.Context(), `INSERT INTO core.map_view (name, kind, background_id) VALUES ($1, $2, $3) RETURNING id`,
			in.Name, in.Kind, in.BackgroundID).Scan(&id); err != nil {
			return bgFKError(err)
		}
		ev.ObjectID = strconv.FormatInt(id, 10)
		return nil
	}) {
		return
	}
	writeJSON(w, http.StatusCreated, idResponse{ID: id})
}

/* updateView changes the name, kind and background of a view; background_id null removes the background. */
func (s *server) updateView(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		Name         *string    `json:"name"`
		Kind         *string    `json:"kind"`
		BackgroundID nullableID `json:"background_id"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if (in.Name == nil && in.Kind == nil && !in.BackgroundID.set) ||
		(in.Name != nil && !validMapName(*in.Name)) || (in.Kind != nil && !viewKinds[*in.Kind]) {
		writeError(w, errBadRequest)
		return
	}
	ev := audit.Event{Action: "map.view.update", ObjectType: "map_view", ObjectID: strconv.FormatInt(id, 10), Details: map[string]any{}}
	if in.Name != nil {
		ev.Details["name"] = *in.Name
	}
	if in.Kind != nil {
		ev.Details["kind"] = *in.Kind
	}
	if in.BackgroundID.set {
		ev.Details["background_id"] = in.BackgroundID.v
	}
	if !s.change(w, r, ev, func(tx pgx.Tx, _ *audit.Event) error {
		_, err := tx.Exec(r.Context(), `UPDATE core.map_view SET name = coalesce($2, name), kind = coalesce($3, kind),
			background_id = CASE WHEN $4::bool THEN $5 ELSE background_id END WHERE id = $1`,
			id, in.Name, in.Kind, in.BackgroundID.set, in.BackgroundID.v)
		if err != nil {
			return bgFKError(err)
		}
		return needView(tx, r, id)
	}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

/* needView returns errMapNotFound unless the view exists; it holds a share lock until the end of the transaction. */
func needView(tx pgx.Tx, r *http.Request, id int64) error {
	var one int
	err := tx.QueryRow(r.Context(), `SELECT 1 FROM core.map_view WHERE id = $1 FOR SHARE`, id).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return errMapNotFound
	}
	return err
}

/* deleteView removes a view with its areas and node positions. */
func (s *server) deleteView(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	ev := audit.Event{Action: "map.view.delete", ObjectType: "map_view", ObjectID: strconv.FormatInt(id, 10)}
	if !s.change(w, r, ev, func(tx pgx.Tx, ev *audit.Event) error {
		var name string
		err := tx.QueryRow(r.Context(), `DELETE FROM core.map_view WHERE id = $1 RETURNING name`, id).Scan(&name)
		if errors.Is(err, pgx.ErrNoRows) {
			return errMapNotFound
		}
		if err != nil {
			return err
		}
		ev.Details = map[string]any{"name": name}
		return nil
	}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

/* listAreas lists the areas of a view (geometry only; the summary status is part of GET /api/topology). */
func (s *server) listAreas(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var exists bool
	if err := s.pool.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM core.map_view WHERE id = $1)`, id).Scan(&exists); err != nil {
		s.fail(w, r, err)
		return
	}
	if !exists {
		writeError(w, errNotFound)
		return
	}
	rows, err := s.pool.Query(r.Context(), `SELECT id, parent_id, kind, name, x, y, w, h FROM core.map_area WHERE view_id = $1 ORDER BY id LIMIT $2`, id, maxAreasPerView)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[areaResponse])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []areaResponse{}
	}
	writeJSON(w, http.StatusOK, out)
}

/* areaError maps the errors of the area trigger and CHECKs to client codes. */
func areaError(err error) error {
	pe := pgErrOf(err)
	if pe == nil {
		return err
	}
	switch {
	case pe.Code == "23514" && pe.ConstraintName == "map_area_parent_not_self",
		pe.Code == "23514" && strings.Contains(pe.Message, "cycle"):
		return errAreaLoop
	case pe.Code == "23514" && strings.Contains(pe.Message, "deeper than"):
		return errAreaDepth
	case pe.Code == "23514" && (strings.Contains(pe.Message, "same view") || strings.Contains(pe.Message, "change its view")):
		return errAreaView
	}
	return err
}

func (s *server) createArea(w http.ResponseWriter, r *http.Request) {
	viewID, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		ParentID *int64  `json:"parent_id"`
		Kind     string  `json:"kind"`
		Name     string  `json:"name"`
		X        float64 `json:"x"`
		Y        float64 `json:"y"`
		W        float64 `json:"w"`
		H        float64 `json:"h"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if !validMapName(in.Name) || !areaKinds[in.Kind] || !validRect(in.X, in.Y, in.W, in.H) || (in.ParentID != nil && *in.ParentID < 1) {
		writeError(w, errBadRequest)
		return
	}
	var id int64
	ev := audit.Event{Action: "map.area.create", ObjectType: "map_area",
		Details: map[string]any{"view_id": viewID, "parent_id": in.ParentID, "kind": in.Kind, "name": in.Name, "x": in.X, "y": in.Y, "w": in.W, "h": in.H}}
	if !s.change(w, r, ev, func(tx pgx.Tx, ev *audit.Event) error {
		/* The view row serializes concurrent creates so the cap counts each other. */
		var one int
		err := tx.QueryRow(r.Context(), `SELECT 1 FROM core.map_view WHERE id = $1 FOR UPDATE`, viewID).Scan(&one)
		if errors.Is(err, pgx.ErrNoRows) {
			return errMapNotFound
		}
		if err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM core.map_area WHERE view_id = $1`, viewID).Scan(&n); err != nil {
			return err
		}
		if n >= maxAreasPerView {
			return errCapAreas
		}
		if err := tx.QueryRow(r.Context(), `INSERT INTO core.map_area (view_id, parent_id, kind, name, x, y, w, h)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
			viewID, in.ParentID, in.Kind, in.Name, in.X, in.Y, in.W, in.H).Scan(&id); err != nil {
			return areaError(err)
		}
		ev.ObjectID = strconv.FormatInt(id, 10)
		return nil
	}) {
		return
	}
	writeJSON(w, http.StatusCreated, idResponse{ID: id})
}

/* areaIDs parses the {id} (view) and {area_id} URL parameters; anything but positive integers answers 404. */
func areaIDs(w http.ResponseWriter, r *http.Request) (viewID, areaID int64, ok bool) {
	viewID, ok = pathID(w, r)
	if !ok {
		return 0, 0, false
	}
	areaID, err := strconv.ParseInt(chi.URLParam(r, "area_id"), 10, 64)
	if err != nil || areaID <= 0 {
		writeError(w, errNotFound)
		return 0, 0, false
	}
	return viewID, areaID, true
}

/* updateArea changes the given fields of an area; parent_id null makes it a root. The view of an area never changes. */
func (s *server) updateArea(w http.ResponseWriter, r *http.Request) {
	viewID, areaID, ok := areaIDs(w, r)
	if !ok {
		return
	}
	var in struct {
		ParentID nullableID `json:"parent_id"`
		Kind     *string    `json:"kind"`
		Name     *string    `json:"name"`
		X        *float64   `json:"x"`
		Y        *float64   `json:"y"`
		W        *float64   `json:"w"`
		H        *float64   `json:"h"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if (!in.ParentID.set && in.Kind == nil && in.Name == nil && in.X == nil && in.Y == nil && in.W == nil && in.H == nil) ||
		(in.Kind != nil && !areaKinds[*in.Kind]) || (in.Name != nil && !validMapName(*in.Name)) {
		writeError(w, errBadRequest)
		return
	}
	ev := audit.Event{Action: "map.area.update", ObjectType: "map_area", ObjectID: strconv.FormatInt(areaID, 10),
		Details: map[string]any{"view_id": viewID}}
	for k, v := range map[string]any{"kind": in.Kind, "name": in.Name, "x": in.X, "y": in.Y, "w": in.W, "h": in.H} {
		if !isNilPtr(v) {
			ev.Details[k] = v
		}
	}
	if in.ParentID.set {
		ev.Details["parent_id"] = in.ParentID.v
	}
	if !s.change(w, r, ev, func(tx pgx.Tx, _ *audit.Event) error {
		var cur areaResponse
		err := tx.QueryRow(r.Context(), `SELECT id, parent_id, kind, name, x, y, w, h FROM core.map_area WHERE id = $1 AND view_id = $2 FOR UPDATE`,
			areaID, viewID).Scan(&cur.ID, &cur.ParentID, &cur.Kind, &cur.Name, &cur.X, &cur.Y, &cur.W, &cur.H)
		if errors.Is(err, pgx.ErrNoRows) {
			return errMapNotFound
		}
		if err != nil {
			return err
		}
		if in.ParentID.set {
			cur.ParentID = in.ParentID.v
		}
		for _, f := range []struct {
			dst *float64
			src *float64
		}{{&cur.X, in.X}, {&cur.Y, in.Y}, {&cur.W, in.W}, {&cur.H, in.H}} {
			if f.src != nil {
				*f.dst = *f.src
			}
		}
		if in.Kind != nil {
			cur.Kind = *in.Kind
		}
		if in.Name != nil {
			cur.Name = *in.Name
		}
		if !validRect(cur.X, cur.Y, cur.W, cur.H) {
			return errMapInvalid
		}
		_, err = tx.Exec(r.Context(), `UPDATE core.map_area SET parent_id = $2, kind = $3, name = $4, x = $5, y = $6, w = $7, h = $8 WHERE id = $1`,
			areaID, cur.ParentID, cur.Kind, cur.Name, cur.X, cur.Y, cur.W, cur.H)
		return areaError(err)
	}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func isNilPtr(v any) bool {
	switch p := v.(type) {
	case *string:
		return p == nil
	case *float64:
		return p == nil
	}
	return v == nil
}

/* deleteArea removes an area; its children become roots of the view. */
func (s *server) deleteArea(w http.ResponseWriter, r *http.Request) {
	viewID, areaID, ok := areaIDs(w, r)
	if !ok {
		return
	}
	ev := audit.Event{Action: "map.area.delete", ObjectType: "map_area", ObjectID: strconv.FormatInt(areaID, 10)}
	if !s.change(w, r, ev, func(tx pgx.Tx, ev *audit.Event) error {
		var name string
		err := tx.QueryRow(r.Context(), `DELETE FROM core.map_area WHERE id = $1 AND view_id = $2 RETURNING name`, areaID, viewID).Scan(&name)
		if errors.Is(err, pgx.ErrNoRows) {
			return errMapNotFound
		}
		if err != nil {
			return err
		}
		ev.Details = map[string]any{"view_id": viewID, "name": name}
		return nil
	}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type positionItem struct {
	DeviceID int64   `json:"device_id"`
	X        float64 `json:"x"`
	Y        float64 `json:"y"`
	Pinned   bool    `json:"pinned"`
}

/*
putPositions stores node positions of a view in one batch (1..5000 items),
all or nothing. A device the caller cannot see (or that does not exist)
answers 404 for the whole batch and nothing is written. An existing row is
replaced as sent, so a client unpins a node by sending pinned=false.
*/
func (s *server) putPositions(w http.ResponseWriter, r *http.Request) {
	viewID, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		Items []positionItem `json:"items"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if len(in.Items) < 1 || len(in.Items) > maxPositionBatch {
		writeError(w, errBadRequest)
		return
	}
	ids := make([]int64, len(in.Items))
	xs, ys := make([]float64, len(in.Items)), make([]float64, len(in.Items))
	pins := make([]bool, len(in.Items))
	seen := make(map[int64]struct{}, len(in.Items))
	pinned := 0
	for i, it := range in.Items {
		if _, dup := seen[it.DeviceID]; dup || it.DeviceID < 1 || !finiteIn(it.X) || !finiteIn(it.Y) {
			writeError(w, errBadRequest)
			return
		}
		seen[it.DeviceID] = struct{}{}
		ids[i], xs[i], ys[i], pins[i] = it.DeviceID, it.X, it.Y, it.Pinned
		if it.Pinned {
			pinned++
		}
	}
	sc, err := s.scope(r, rbac.PermDevicesRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ev := audit.Event{Action: "map.positions.put", ObjectType: "map_view", ObjectID: strconv.FormatInt(viewID, 10),
		Details: map[string]any{"count": len(ids), "pinned": pinned}}
	if !s.change(w, r, ev, func(tx pgx.Tx, _ *audit.Event) error {
		if err := needView(tx, r, viewID); err != nil {
			return err
		}
		var visible int
		if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM core.device WHERE id = ANY($1) AND ($2::bool OR group_id = ANY($3))`,
			ids, sc.all, sc.ids).Scan(&visible); err != nil {
			return err
		}
		if visible != len(ids) {
			return errMapNotFound
		}
		_, err := tx.Exec(r.Context(), `INSERT INTO core.map_node_position (view_id, device_id, x, y, pinned)
			SELECT $1, d, x, y, p FROM unnest($2::bigint[], $3::float8[], $4::float8[], $5::bool[]) AS t (d, x, y, p)
			ON CONFLICT (view_id, device_id) DO UPDATE SET x = EXCLUDED.x, y = EXCLUDED.y, pinned = EXCLUDED.pinned`,
			viewID, ids, xs, ys, pins)
		return err
	}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

/* backgroundsNotImplemented answers the background routes until the upload pipeline lands. */
func (s *server) backgroundsNotImplemented(w http.ResponseWriter, _ *http.Request) {
	writeError(w, errNotImplemented)
}
