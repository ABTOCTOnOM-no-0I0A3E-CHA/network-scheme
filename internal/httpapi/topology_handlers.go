package httpapi

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/audit"
	"github.com/beekamai/network-scheme/internal/rbac"
)

/* Limits of the topology API. */
const (
	maxLinksPerPair    = 64 /* mirrors the cap of the builder */
	defaultChangesPage = 100
	maxChangesPage     = 500
)

var (
	errLinkDup  = errors.New("httpapi: link exists")
	errCapLinks = errors.New("httpapi: too many links between two devices")
)

type topoNode struct {
	DeviceID int64    `json:"device_id"`
	Name     string   `json:"name"`
	State    string   `json:"state"`
	Driver   string   `json:"driver"`
	AreaID   *int64   `json:"area_id,omitempty"` /* deepest area of the view whose rectangle holds the node */
	X        *float64 `json:"x,omitempty"`
	Y        *float64 `json:"y,omitempty"`
	Pinned   bool     `json:"pinned"`
}

type topoLink struct {
	ID         int64   `json:"id"`
	A          int64   `json:"a"`
	B          int64   `json:"b"`
	AIf        *int    `json:"a_if"`
	BIf        *int    `json:"b_if"`
	APortName  string  `json:"a_port_name"` /* from the device: render as text only */
	BPortName  string  `json:"b_port_name"`
	SpeedBps   *int64  `json:"speed_bps"` /* the lower known speed of the two ends */
	Source     string  `json:"source"`
	Confidence float64 `json:"confidence"`
	Manual     bool    `json:"manual"`
}

type areaStates struct {
	Up      int `json:"up"`
	Partial int `json:"partial"`
	Down    int `json:"down"`
	Unknown int `json:"unknown"`
}

type topoArea struct {
	areaResponse
	DeviceCount int        `json:"device_count"` /* visible devices in the area and its sub-areas */
	States      areaStates `json:"states"`
	Status      string     `json:"status"` /* worst state of those devices: down, partial, unknown or up */
}

type topologyResponse struct {
	Nodes []topoNode `json:"nodes"`
	Links []topoLink `json:"links"`
	Areas []topoArea `json:"areas"`
}

/* topologyNodesSQL: visible devices (optionally of group $4 and its subgroups) with their state; $1 all, $2 ids, $3 group filter given, $4 group. */
const topologyNodesSQL = `
WITH RECURSIVE sub (id, depth) AS (
    SELECT id, 0 FROM core.device_group WHERE $3::bool AND id = $4
  UNION ALL
    SELECT g.id, sub.depth + 1 FROM core.device_group g JOIN sub ON g.parent_id = sub.id WHERE sub.depth < 64
)
SELECT d.id, d.name, coalesce(s.state, 'unknown'), d.driver
FROM core.device d
LEFT JOIN inventory.device_state_v s ON s.device_id = d.id
WHERE ($1::bool OR d.group_id = ANY($2)) AND (NOT $3::bool OR d.group_id IN (SELECT id FROM sub))
ORDER BY d.id`

/*
topologyLinksSQL: links whose both ends are in the node set (same scope and
group filter as the nodes). The port name is the interface name, else its
alias; the speed the lower of the known (positive) end speeds. Parameters as above.
*/
const topologyLinksSQL = `
WITH RECURSIVE sub (id, depth) AS (
    SELECT id, 0 FROM core.device_group WHERE $3::bool AND id = $4
  UNION ALL
    SELECT g.id, sub.depth + 1 FROM core.device_group g JOIN sub ON g.parent_id = sub.id WHERE sub.depth < 64
)
SELECT l.id, l.a_device_id, l.b_device_id, l.a_if_index, l.b_if_index,
       coalesce(nullif(ia.name, ''), nullif(ia.alias, ''), ''), coalesce(nullif(ib.name, ''), nullif(ib.alias, ''), ''),
       least(coalesce(nullif(ia.speed_bps, 0), nullif(ib.speed_bps, 0)), coalesce(nullif(ib.speed_bps, 0), nullif(ia.speed_bps, 0))),
       l.source, l.confidence::float8, l.manual
FROM core.link l
JOIN core.device da ON da.id = l.a_device_id
JOIN core.device db ON db.id = l.b_device_id
LEFT JOIN inventory.interface ia ON ia.device_id = l.a_device_id AND ia.if_index = l.a_if_index
LEFT JOIN inventory.interface ib ON ib.device_id = l.b_device_id AND ib.if_index = l.b_if_index
WHERE ($1::bool OR (da.group_id = ANY($2) AND db.group_id = ANY($2)))
  AND (NOT $3::bool OR (da.group_id IN (SELECT id FROM sub) AND db.group_id IN (SELECT id FROM sub)))
ORDER BY l.id`

/*
getTopology serves nodes, links and areas for the map. Only devices the
caller can see (devices.read, subgroups included) appear as nodes, a link only
if both ends are visible, and the summary status of an area counts visible
devices only. group_id narrows the nodes to that group and its subgroups (404
if the caller cannot see the group). view_id adds positions, areas and the
area of each node; a node's area is the smallest area of the view whose
rectangle contains its position (nodes without a position have none). The
areas, views and their names are global admin-entered objects.
*/
func (s *server) getTopology(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	viewS, okV := single(q, "view_id")
	groupS, okG := single(q, "group_id")
	var viewID, groupID int64
	var err error
	if viewS != "" {
		viewID, err = strconv.ParseInt(viewS, 10, 64)
		okV = okV && err == nil && viewID >= 1
	}
	if groupS != "" {
		groupID, err = strconv.ParseInt(groupS, 10, 64)
		okG = okG && err == nil && groupID >= 1
	}
	if !okV || !okG {
		writeError(w, errBadRequest)
		return
	}
	sc, err := s.scope(r, rbac.PermDevicesRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ctx := r.Context()
	if groupID != 0 {
		var exists bool
		if !sc.has(groupID) {
			writeError(w, errNotFound)
			return
		}
		if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.device_group WHERE id = $1)`, groupID).Scan(&exists); err != nil {
			s.fail(w, r, err)
			return
		}
		if !exists {
			writeError(w, errNotFound)
			return
		}
	}
	if viewID != 0 {
		var exists bool
		if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.map_view WHERE id = $1)`, viewID).Scan(&exists); err != nil {
			s.fail(w, r, err)
			return
		}
		if !exists {
			writeError(w, errNotFound)
			return
		}
	}
	out := topologyResponse{Nodes: []topoNode{}, Links: []topoLink{}, Areas: []topoArea{}}
	if !sc.all && len(sc.ids) == 0 {
		writeJSON(w, http.StatusOK, out)
		return
	}
	rows, err := s.pool.Query(ctx, topologyNodesSQL, sc.all, sc.ids, groupID != 0, groupID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	nodes, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (n topoNode, err error) {
		err = row.Scan(&n.DeviceID, &n.Name, &n.State, &n.Driver)
		return n, err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if nodes != nil {
		out.Nodes = nodes
	}
	rows, err = s.pool.Query(ctx, topologyLinksSQL, sc.all, sc.ids, groupID != 0, groupID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	links, err := pgx.CollectRows(rows, pgx.RowToStructByPos[topoLink])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if links != nil {
		out.Links = links
	}
	if viewID != 0 {
		if out.Areas, err = s.placeNodes(r, viewID, out.Nodes); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, out)
}

/*
placeNodes fills the positions and areas of nodes for a view and returns the
areas with the summary of the nodes in them (sub-areas included). The node
list passed in is already restricted to visible devices, so nothing else can
reach the summary.
*/
func (s *server) placeNodes(r *http.Request, viewID int64, nodes []topoNode) ([]topoArea, error) {
	ctx := r.Context()
	rows, err := s.pool.Query(ctx, `SELECT id, parent_id, kind, name, x, y, w, h FROM core.map_area WHERE view_id = $1 ORDER BY id LIMIT $2`, viewID, maxAreasPerView)
	if err != nil {
		return nil, err
	}
	base, err := pgx.CollectRows(rows, pgx.RowToStructByPos[areaResponse])
	if err != nil {
		return nil, err
	}
	rows, err = s.pool.Query(ctx, `SELECT device_id, x, y, pinned FROM core.map_node_position WHERE view_id = $1`, viewID)
	if err != nil {
		return nil, err
	}
	pos, err := pgx.CollectRows(rows, pgx.RowToStructByPos[positionItem])
	if err != nil {
		return nil, err
	}
	byDevice := make(map[int64]positionItem, len(pos))
	for _, p := range pos {
		byDevice[p.DeviceID] = p
	}
	/* Smallest area first, so the first containing one is the deepest. */
	order := make([]int, len(base))
	for i := range order {
		order[i] = i
	}
	slices.SortFunc(order, func(a, b int) int {
		x, y := base[a].W*base[a].H, base[b].W*base[b].H
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
		return int(base[a].ID - base[b].ID)
	})
	areas := make([]topoArea, len(base))
	index := make(map[int64]int, len(base))
	for i, a := range base {
		areas[i] = topoArea{areaResponse: a}
		index[a.ID] = i
	}
	for i := range nodes {
		p, ok := byDevice[nodes[i].DeviceID]
		if !ok {
			continue
		}
		x, y := p.X, p.Y
		nodes[i].X, nodes[i].Y, nodes[i].Pinned = &x, &y, p.Pinned
		for _, k := range order {
			a := base[k]
			if x >= a.X && x < a.X+a.W && y >= a.Y && y < a.Y+a.H {
				id := a.ID
				nodes[i].AreaID = &id
				/* The state counts in the area and in every ancestor (depth <= 8; the bound also stops a corrupted loop). */
				for cur, depth := k, 0; depth < 16; depth++ {
					areas[cur].count(nodes[i].State)
					parent := base[cur].ParentID
					if parent == nil {
						break
					}
					next, ok := index[*parent]
					if !ok {
						break
					}
					cur = next
				}
				break
			}
		}
	}
	for i := range areas {
		areas[i].finish()
	}
	return areas, nil
}

func (a *topoArea) count(state string) {
	a.DeviceCount++
	switch state {
	case "up":
		a.States.Up++
	case "partial":
		a.States.Partial++
	case "down":
		a.States.Down++
	default:
		a.States.Unknown++
	}
}

/* finish sets the summary status: the worst state present; an area without visible devices is unknown. */
func (a *topoArea) finish() {
	switch {
	case a.States.Down > 0:
		a.Status = "down"
	case a.States.Partial > 0:
		a.Status = "partial"
	case a.States.Unknown > 0 || a.DeviceCount == 0:
		a.Status = "unknown"
	default:
		a.Status = "up"
	}
}

type linkChangeResponse struct {
	ID          int64     `json:"id"`
	At          time.Time `json:"at"`
	Change      string    `json:"change"`
	Source      string    `json:"source"`
	LinkID      *int64    `json:"link_id"`
	ADeviceID   int64     `json:"a_device_id"`
	ADeviceName string    `json:"a_device_name"`
	AIfIndex    *int      `json:"a_if_index"`
	APortName   string    `json:"a_port_name"`
	BDeviceID   int64     `json:"b_device_id"`
	BDeviceName string    `json:"b_device_name"`
	BIfIndex    *int      `json:"b_if_index"`
	BPortName   string    `json:"b_port_name"`
}

type linkChangesPage struct {
	Items      []linkChangeResponse `json:"items"`
	NextCursor *string              `json:"next_cursor"`
}

type changesCursor struct {
	TS int64 `json:"t"` /* microseconds since the epoch */
	ID int64 `json:"i"`
}

/* changesSQL: port names are the interface name, else its alias, else empty (device data). $1 all, $2 ids, $3 cursor given, $4-$5 cursor, $6 limit. */
const changesSQL = `
SELECT c.id, c.at, c.change, c.source, c.link_id, c.a_device_id, coalesce(da.name, ''), c.a_if_index,
       coalesce(nullif(ia.name, ''), nullif(ia.alias, ''), ''),
       c.b_device_id, coalesce(db.name, ''), c.b_if_index, coalesce(nullif(ib.name, ''), nullif(ib.alias, ''), '')
FROM core.link_change c
LEFT JOIN core.device da ON da.id = c.a_device_id
LEFT JOIN core.device db ON db.id = c.b_device_id
LEFT JOIN inventory.interface ia ON ia.device_id = c.a_device_id AND ia.if_index = c.a_if_index
LEFT JOIN inventory.interface ib ON ib.device_id = c.b_device_id AND ib.if_index = c.b_if_index
WHERE ($1::bool OR (da.group_id = ANY($2) AND db.group_id = ANY($2)))
  AND (NOT $3::bool OR (c.at, c.id) < ($4, $5))
ORDER BY c.at DESC, c.id DESC
LIMIT $6::int`

/*
listTopologyChanges serves link appearances and disappearances, newest first.
A change is visible when both ends are visible to the caller; one whose
device has been deleted since is visible only to a global binding.
*/
func (s *server) listTopologyChanges(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	curS, okC := single(q, "cursor")
	limit, okL := queryInt(q, "limit", defaultChangesPage, 1, maxChangesPage)
	var cur changesCursor
	if curS != "" {
		okC = okC && decodeCursor(curS, &cur) && cur.ID >= 1
	}
	if !okC || !okL {
		writeError(w, errBadRequest)
		return
	}
	sc, err := s.scope(r, rbac.PermDevicesRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := linkChangesPage{Items: []linkChangeResponse{}}
	if !sc.all && len(sc.ids) == 0 {
		writeJSON(w, http.StatusOK, out)
		return
	}
	rows, err := s.pool.Query(r.Context(), changesSQL, sc.all, sc.ids, curS != "", time.UnixMicro(cur.TS).UTC(), cur.ID, limit+1)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, pgx.RowToStructByPos[linkChangeResponse])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out.Items = items
	if len(items) > limit {
		out.Items = items[:limit]
		last := out.Items[limit-1]
		c := encodeCursor(changesCursor{TS: last.At.UnixMicro(), ID: last.ID})
		out.NextCursor = &c
	}
	if out.Items == nil {
		out.Items = []linkChangeResponse{}
	}
	writeJSON(w, http.StatusOK, out)
}

/* validIfIndex accepts an absent (unknown) port or a positive int32 ifIndex. */
func validIfIndex(v *int) bool { return v == nil || (*v >= 1 && *v <= math.MaxInt32) }

/*
createLink draws a manual link (confidence 1, never changed or removed by the
builder). Both devices must be visible to the caller, else 404. The ends are
stored in canonical order (smaller device id first). The appearance goes to
the change history in the same transaction; the builder reloads afterwards so
automatic links between the pair that the manual one covers are retired.
*/
func (s *server) createLink(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ADeviceID int64 `json:"a_device_id"`
		AIfIndex  *int  `json:"a_if_index"`
		BDeviceID int64 `json:"b_device_id"`
		BIfIndex  *int  `json:"b_if_index"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.ADeviceID < 1 || in.BDeviceID < 1 || in.ADeviceID == in.BDeviceID || !validIfIndex(in.AIfIndex) || !validIfIndex(in.BIfIndex) {
		writeError(w, errBadRequest)
		return
	}
	sc, err := s.scope(r, rbac.PermDevicesRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, id := range []int64{in.ADeviceID, in.BDeviceID} {
		if _, err := s.deviceIn(r, sc, id); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	a, aIf, b, bIf := in.ADeviceID, in.AIfIndex, in.BDeviceID, in.BIfIndex
	if a > b {
		a, aIf, b, bIf = b, bIf, a, aIf
	}
	var id int64
	ev := audit.Event{Action: "links.create", ObjectType: "link",
		Details: map[string]any{"a_device_id": a, "a_if_index": aIf, "b_device_id": b, "b_if_index": bIf}}
	if !s.change(w, r, ev, func(tx pgx.Tx, ev *audit.Event) error {
		/* concurrent creations for one pair count against the cap one after the other */
		if _, err := tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, fmt.Sprintf("link-pair:%d:%d", a, b)); err != nil {
			return err
		}
		/*
			A detected link with exactly these ends becomes the manual one: same row and
			id, confidence 1, no longer subject to disappearance. It already appeared in
			the history, so no change row is written; the audit record says what it was.
		*/
		var from string
		err := tx.QueryRow(r.Context(), `
WITH old AS (
    SELECT id, source FROM core.link
    WHERE a_device_id = $1 AND coalesce(a_if_index, -1) = coalesce($2::int, -1)
      AND b_device_id = $3 AND coalesce(b_if_index, -1) = coalesce($4::int, -1) AND NOT manual
    FOR UPDATE)
UPDATE core.link l SET source = 'manual', manual = true, confidence = 1, misses = 0, last_confirmed = now()
FROM old WHERE l.id = old.id RETURNING l.id, old.source`, a, aIf, b, bIf).Scan(&id, &from)
		if err == nil {
			ev.ObjectID = strconv.FormatInt(id, 10)
			ev.Details["converted_from"] = from
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var n int
		if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM core.link WHERE a_device_id = $1 AND b_device_id = $2`, a, b).Scan(&n); err != nil {
			return err
		}
		if n >= maxLinksPerPair {
			return errCapLinks
		}
		err = tx.QueryRow(r.Context(), `INSERT INTO core.link (a_device_id, a_if_index, b_device_id, b_if_index, source, confidence, manual)
			VALUES ($1, $2, $3, $4, 'manual', 1, true) RETURNING id`, a, aIf, b, bIf).Scan(&id)
		if pe := pgErrOf(err); pe != nil {
			switch pe.Code {
			case "23505":
				return errLinkDup
			case "23503":
				return errMapNotFound /* a device deleted meanwhile */
			}
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(r.Context(), `INSERT INTO core.link_change (link_id, a_device_id, a_if_index, b_device_id, b_if_index, change, source)
			VALUES ($1, $2, $3, $4, $5, 'appeared', 'manual')`, id, a, aIf, b, bIf); err != nil {
			return err
		}
		ev.ObjectID = strconv.FormatInt(id, 10)
		return nil
	}) {
		return
	}
	s.configChanged()
	writeJSON(w, http.StatusCreated, idResponse{ID: id})
}

/*
deleteLink removes a manual link; an automatic link (the builder owns it), a
missing one and one with an end the caller cannot see all answer 404. The
disappearance goes to the change history in the same transaction.
*/
func (s *server) deleteLink(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	sc, err := s.scope(r, rbac.PermDevicesRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ev := audit.Event{Action: "links.delete", ObjectType: "link", ObjectID: strconv.FormatInt(id, 10)}
	if !s.change(w, r, ev, func(tx pgx.Tx, ev *audit.Event) error {
		var a, b int64
		var aIf, bIf *int
		err := tx.QueryRow(r.Context(), `
DELETE FROM core.link l USING core.device da, core.device db
WHERE l.id = $1 AND l.manual AND da.id = l.a_device_id AND db.id = l.b_device_id
  AND ($2::bool OR (da.group_id = ANY($3) AND db.group_id = ANY($3)))
RETURNING l.a_device_id, l.a_if_index, l.b_device_id, l.b_if_index`, id, sc.all, sc.ids).Scan(&a, &aIf, &b, &bIf)
		if errors.Is(err, pgx.ErrNoRows) {
			return errMapNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(r.Context(), `INSERT INTO core.link_change (link_id, a_device_id, a_if_index, b_device_id, b_if_index, change, source)
			VALUES ($1, $2, $3, $4, $5, 'disappeared', 'manual')`, id, a, aIf, b, bIf); err != nil {
			return err
		}
		ev.Details = map[string]any{"a_device_id": a, "a_if_index": aIf, "b_device_id": b, "b_if_index": bIf}
		return nil
	}) {
		return
	}
	s.configChanged()
	w.WriteHeader(http.StatusNoContent)
}
