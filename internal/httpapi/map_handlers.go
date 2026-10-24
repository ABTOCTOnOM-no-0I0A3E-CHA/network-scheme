package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/audit"
	"github.com/beekamai/network-scheme/internal/mapimg"
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
	errMapBackground  = errors.New("httpapi: map background not found")
	errCapBackgrounds = errors.New("httpapi: too many map backgrounds")
	errMapInvalid     = errors.New("httpapi: invalid map object")
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
		if in.BackgroundID != nil {
			if err := lockBackgroundUse(r, tx); err != nil {
				return err
			}
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
	if !s.change(w, r, ev, func(tx pgx.Tx, ev *audit.Event) error {
		var old *int64
		if in.BackgroundID.v != nil {
			if err := lockBackgroundUse(r, tx); err != nil {
				return err
			}
		}
		if err := tx.QueryRow(r.Context(), `SELECT background_id FROM core.map_view WHERE id = $1 FOR UPDATE`, id).Scan(&old); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errMapNotFound
			}
			return err
		}
		if _, err := tx.Exec(r.Context(), `UPDATE core.map_view SET name = coalesce($2, name), kind = coalesce($3, kind),
			background_id = CASE WHEN $4::bool THEN $5 ELSE background_id END WHERE id = $1`,
			id, in.Name, in.Kind, in.BackgroundID.set, in.BackgroundID.v); err != nil {
			return bgFKError(err)
		}
		if in.BackgroundID.set && old != nil && (in.BackgroundID.v == nil || *in.BackgroundID.v != *old) {
			return collectBackground(r, tx, ev, *old)
		}
		return nil
	}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

/* lockBackgroundUse serializes views taking a background with the collection of unused ones until the end of the transaction. */
func lockBackgroundUse(r *http.Request, tx pgx.Tx) error {
	_, err := tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtext('core.map_background.use'))`)
	return err
}

/*
collectBackground deletes background id when no view references it any more
(a view dropped it or was deleted in this transaction) and notes that in the audit
details. A view taking a background holds the same advisory lock, so the delete
below, a new statement after the lock, sees every such view committed.
*/
func collectBackground(r *http.Request, tx pgx.Tx, ev *audit.Event, id int64) error {
	if err := lockBackgroundUse(r, tx); err != nil {
		return err
	}
	tag, err := tx.Exec(r.Context(), `DELETE FROM core.map_background b WHERE b.id = $1
		AND NOT EXISTS (SELECT 1 FROM core.map_view v WHERE v.background_id = b.id)`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() > 0 {
		if ev.Details == nil {
			ev.Details = map[string]any{}
		}
		ev.Details["deleted_background_id"] = id
	}
	return nil
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
		var bg *int64
		err := tx.QueryRow(r.Context(), `DELETE FROM core.map_view WHERE id = $1 RETURNING name, background_id`, id).Scan(&name, &bg)
		if errors.Is(err, pgx.ErrNoRows) {
			return errMapNotFound
		}
		if err != nil {
			return err
		}
		ev.Details = map[string]any{"name": name}
		if bg != nil {
			return collectBackground(r, tx, ev, *bg)
		}
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
		if pe := pgErrOf(err); pe != nil && pe.Code == "23503" {
			return errMapNotFound /* a device deleted meanwhile */
		}
		return err
	}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

/* uploadPath is the one route whose body may exceed 1 MiB (see limitBody and the gateway). */
const uploadPath = "/api/map/backgrounds"

/* maxUploadName is the longest accepted file name of the uploaded part (it is not stored). */
const maxUploadName = 200

/* maxBackgrounds caps the stored backgrounds (rows are immutable, each up to 20 MiB). */
const maxBackgrounds = 200

/* uploadWait is how long an upload waits for the one processing slot before answering 429. */
const uploadWait = 10 * time.Second

/* uploadReadTimeout is the time a client gets to send an upload body; uploadWriteExtra is added for the answer. */
const (
	uploadReadTimeout = 5 * time.Minute
	uploadWriteExtra  = 30 * time.Second
)

/* Serving a background: at most serveSlots at a time (each holds a chunk, not the blob), a short wait, then 503. */
const (
	serveSlots = 4
	serveWait  = time.Second
	serveChunk = 1 << 20
)

/* backgroundCSP confines a served image: no loading, no scripts, a unique origin. */
const backgroundCSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; sandbox"

type backgroundResponse struct {
	ID     int64  `json:"id"`
	Mime   string `json:"mime"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}

/* tooLarge reports a body cut off by http.MaxBytesReader. */
func tooLarge(err error) bool {
	var mbe *http.MaxBytesError
	return errors.As(err, &mbe)
}

/*
readUpload takes the single file part of a multipart/form-data body: exactly
one part, named "file", with a file name of up to 200 characters, at most
mapimg.MaxBytes long. It answers the error itself and reports false on failure.
*/
func readUpload(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if mt, params, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "multipart/form-data" || params["boundary"] == "" {
		writeError(w, errNotMultipart)
		return nil, false
	}
	fail := func(err error) ([]byte, bool) {
		if tooLarge(err) {
			writeError(w, errTooLarge)
		} else {
			writeError(w, errBadRequest)
		}
		return nil, false
	}
	mr, err := r.MultipartReader()
	if err != nil {
		return fail(err)
	}
	part, err := mr.NextPart()
	if err != nil {
		return fail(err)
	}
	if name := part.FileName(); part.FormName() != "file" || name == "" || utf8.RuneCountInString(name) > maxUploadName ||
		!utf8.ValidString(name) || strings.ContainsFunc(name, unicode.IsControl) {
		writeError(w, errBadRequest)
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(part, mapimg.MaxBytes+1))
	if err != nil {
		return fail(err)
	}
	if len(data) > mapimg.MaxBytes {
		writeError(w, errTooLarge)
		return nil, false
	}
	if _, err := mr.NextPart(); err != io.EOF { /* a second part, whatever it is, or a broken body */
		if err == nil {
			err = errors.New("more than one part")
		}
		return fail(err)
	}
	return data, true
}

/*
uploadBackground stores a map background (PNG, JPEG, WebP or SVG). The type is
taken from the content, rasters are checked by header, SVG is rewritten through
an allowlist and the sanitized document is what gets stored and served.
*/
func (s *server) uploadBackground(w http.ResponseWriter, r *http.Request) {
	/* One upload at a time: a 20 MiB body plus its sanitizing tree must not pile up in a small container. */
	select {
	case s.uploadSem <- struct{}{}:
		defer func() { <-s.uploadSem }()
	case <-time.After(uploadWait):
		writeError(w, errRateLimited)
		return
	case <-r.Context().Done():
		return
	}
	/* The server-wide deadlines suit small bodies; a slow link gets a longer one for this route, counted after the slot wait. */
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(uploadReadTimeout))
	_ = rc.SetWriteDeadline(time.Now().Add(uploadReadTimeout + uploadWriteExtra))
	data, ok := readUpload(w, r)
	if !ok {
		return
	}
	res, err := mapimg.Process(data)
	switch {
	case errors.Is(err, mapimg.ErrUnsupported), errors.Is(err, mapimg.ErrNotSVG):
		writeError(w, errUnsupportedImage)
		return
	case errors.Is(err, mapimg.ErrTooLarge):
		writeError(w, errTooLarge)
		return
	case err != nil:
		writeError(w, errInvalidImage)
		return
	}
	sum := sha256.Sum256(res.Data)
	sc, _ := sessionFrom(r.Context())
	out := backgroundResponse{Mime: res.Mime, Width: res.Width, Height: res.Height, Size: len(res.Data), SHA256: hex.EncodeToString(sum[:])}
	ev := audit.Event{Action: "map.background.upload", ObjectType: "map_background",
		Details: map[string]any{"mime": out.Mime, "size": out.Size, "sha256": out.SHA256, "width": out.Width, "height": out.Height}}
	if !s.change(w, r, ev, func(tx pgx.Tx, ev *audit.Event) error {
		if _, err := tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtext('core.map_background.cap'))`); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM core.map_background`).Scan(&n); err != nil {
			return err
		}
		if n >= maxBackgrounds {
			return errCapBackgrounds
		}
		if err := tx.QueryRow(r.Context(), `INSERT INTO core.map_background (mime, bytes, width, height, sha256, uploaded_by)
			VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
			res.Mime, res.Data, res.Width, res.Height, sum[:], sc.sess.UserID).Scan(&out.ID); err != nil {
			return err
		}
		ev.ObjectID = strconv.FormatInt(out.ID, 10)
		return nil
	}) {
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

/* etagMatches reports whether an If-None-Match header lists etag (weak comparison) or "*". */
func etagMatches(header, etag string) bool {
	for _, c := range strings.Split(header, ",") {
		c = strings.TrimPrefix(strings.TrimSpace(c), "W/")
		if c == "*" || c == etag {
			return true
		}
	}
	return false
}

/*
getBackground serves a stored background. The image never runs anything: the
stored type is the response type, a sandboxing CSP and nosniff accompany it, and
the content is the sanitized document written at upload time. The row is
immutable, so the sha256 is a stable ETag.
*/
func (s *server) getBackground(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	/* Metadata first: a revalidation never touches the bytes. */
	var mimeType string
	var sum []byte
	var size int
	if err := s.pool.QueryRow(r.Context(), `SELECT mime, sha256, octet_length(bytes) FROM core.map_background WHERE id = $1`, id).
		Scan(&mimeType, &sum, &size); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			err = errMapNotFound
		}
		s.fail(w, r, err)
		return
	}
	etag := `"` + hex.EncodeToString(sum) + `"`
	h := w.Header()
	h.Set("Content-Type", mimeType)
	h.Set("Content-Security-Policy", backgroundCSP)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Disposition", `inline; filename="map.`+mapimg.Ext(mimeType)+`"`)
	h.Set("Cache-Control", "private, max-age=3600")
	h.Set("ETag", etag)
	if etagMatches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	select {
	case s.serveSem <- struct{}{}:
		defer func() { <-s.serveSem }()
	case <-time.After(serveWait):
		h.Set("Retry-After", "1")
		writeError(w, errBusy)
		return
	case <-r.Context().Done():
		return
	}
	h.Set("Content-Length", strconv.Itoa(size))
	/*
		The blob is read in chunks, each by its own query, so neither the api nor a
		pooled connection holds up to 20 MiB while a slow client drains it. Rows are
		immutable; if one is deleted mid-way the body ends short of Content-Length
		and the connection is dropped.
	*/
	for off := 0; off < size; off += serveChunk {
		var chunk []byte
		if err := s.pool.QueryRow(r.Context(), `SELECT substring(bytes from $2::int for $3::int) FROM core.map_background WHERE id = $1`,
			id, off+1, serveChunk).Scan(&chunk); err != nil || len(chunk) == 0 {
			panic(http.ErrAbortHandler)
		}
		if _, err := w.Write(chunk); err != nil {
			return
		}
	}
}

/* deleteBackground removes a background; views that used it fall back to no background (ON DELETE SET NULL). */
func (s *server) deleteBackground(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	ev := audit.Event{Action: "map.background.delete", ObjectType: "map_background", ObjectID: strconv.FormatInt(id, 10)}
	if !s.change(w, r, ev, func(tx pgx.Tx, ev *audit.Event) error {
		var mimeType string
		var size int
		var views int64
		if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM core.map_view WHERE background_id = $1`, id).Scan(&views); err != nil {
			return err
		}
		err := tx.QueryRow(r.Context(), `DELETE FROM core.map_background WHERE id = $1 RETURNING mime, octet_length(bytes)`, id).Scan(&mimeType, &size)
		if errors.Is(err, pgx.ErrNoRows) {
			return errMapNotFound
		}
		if err != nil {
			return err
		}
		ev.Details = map[string]any{"mime": mimeType, "size": size, "views_detached": views}
		return nil
	}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
