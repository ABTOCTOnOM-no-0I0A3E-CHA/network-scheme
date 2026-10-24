package httpapi_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/httpapi"
	"github.com/beekamai/network-scheme/internal/inventory"
	"github.com/beekamai/network-scheme/internal/rbac"
)

type topoNodeT struct {
	DeviceID int64    `json:"device_id"`
	Name     string   `json:"name"`
	State    string   `json:"state"`
	AreaID   *int64   `json:"area_id"`
	X        *float64 `json:"x"`
	Y        *float64 `json:"y"`
	Pinned   bool     `json:"pinned"`
}

type topoLinkT struct {
	ID         int64   `json:"id"`
	A          int64   `json:"a"`
	B          int64   `json:"b"`
	AIf        *int    `json:"a_if"`
	BIf        *int    `json:"b_if"`
	APortName  string  `json:"a_port_name"`
	BPortName  string  `json:"b_port_name"`
	SpeedBps   *int64  `json:"speed_bps"`
	Source     string  `json:"source"`
	Confidence float64 `json:"confidence"`
	Manual     bool    `json:"manual"`
}

type topoAreaT struct {
	ID          int64  `json:"id"`
	ParentID    *int64 `json:"parent_id"`
	DeviceCount int    `json:"device_count"`
	Status      string `json:"status"`
	States      struct {
		Up, Partial, Down, Unknown int
	} `json:"states"`
}

type topologyT struct {
	Nodes []topoNodeT `json:"nodes"`
	Links []topoLinkT `json:"links"`
	Areas []topoAreaT `json:"areas"`
}

type changeT struct {
	ID          int64  `json:"id"`
	Change      string `json:"change"`
	Source      string `json:"source"`
	ADeviceID   int64  `json:"a_device_id"`
	ADeviceName string `json:"a_device_name"`
	APortName   string `json:"a_port_name"`
	BDeviceID   int64  `json:"b_device_id"`
	BPortName   string `json:"b_port_name"`
}

type changesT struct {
	Items      []changeT `json:"items"`
	NextCursor *string   `json:"next_cursor"`
}

func (f *fixture) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.env.Pool("postgres").Exec(context.Background(), sql, args...); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
}

func (f *fixture) queryID(sql string, args ...any) int64 {
	f.t.Helper()
	var id int64
	if err := f.env.Pool("postgres").QueryRow(context.Background(), sql, args...).Scan(&id); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
	return id
}

func (f *fixture) newView() int64 {
	return f.queryID(`INSERT INTO core.map_view (name, kind) VALUES ($1, 'logical') RETURNING id`, uniqueName("view"))
}

func (f *fixture) newArea(view int64, parent *int64, x, y, w, h float64) int64 {
	return f.queryID(`INSERT INTO core.map_area (view_id, parent_id, kind, name, x, y, w, h) VALUES ($1, $2, 'room', $3, $4, $5, $6, $7) RETURNING id`,
		view, parent, uniqueName("area"), x, y, w, h)
}

func (f *fixture) newIface(dev int64, idx int, name, alias string, speed int64) {
	f.exec(`INSERT INTO inventory.interface (device_id, if_index, name, alias, speed_bps, oper_up, seen_at) VALUES ($1, $2, $3, $4, $5, true, now())`,
		dev, idx, name, alias, speed)
}

/* newLink stores a link in canonical order (the caller passes a < b). */
func (f *fixture) newLink(a int64, aIf *int, b int64, bIf *int, source string, conf float64) int64 {
	return f.queryID(`INSERT INTO core.link (a_device_id, a_if_index, b_device_id, b_if_index, source, confidence, manual) VALUES ($1, $2, $3, $4, $5, $6, $5 = 'manual') RETURNING id`,
		a, aIf, b, bIf, source, conf)
}

func (f *fixture) newChange(link *int64, a int64, aIf *int, b int64, bIf *int, change, source string, at time.Time) int64 {
	return f.queryID(`INSERT INTO core.link_change (link_id, a_device_id, a_if_index, b_device_id, b_if_index, change, source, at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
		link, a, aIf, b, bIf, change, source, at)
}

func (f *fixture) setState(dev int64, state string) {
	f.t.Helper()
	ctx := context.Background()
	pl := inventory.NewStore(f.env.Pool("nms_poller"))
	if err := pl.SetStatus(ctx, dev, state, time.Now().Add(-time.Hour), ""); err != nil {
		f.t.Fatal(err)
	}
	if err := pl.Heartbeat(ctx, "local", time.Now()); err != nil {
		f.t.Fatal(err)
	}
}

func ifx(v int) *int { return &v }

func (f *fixture) getTopology(s *subject, q url.Values) *http.Response {
	return f.do(s.authed(req{method: "GET", path: "/api/topology?" + q.Encode()}))
}

/* clearMap removes the views left by other tests so that counts and caps start from zero. */
func (f *fixture) clearMap() {
	f.exec(`DELETE FROM core.map_view`)
}

/* mapRequest builds valid requests for the topology and map routes with devices in m.target. */
func (m *matrixEnv) mapRequest(key string) (req, bool) {
	g := m.target
	switch key {
	case "GET /api/topology":
		return req{method: "GET", path: fmt.Sprintf("/api/topology?group_id=%d", g)}, true
	case "GET /api/topology/changes":
		return req{method: "GET", path: "/api/topology/changes"}, true
	case "POST /api/links":
		return req{method: "POST", path: "/api/links", body: map[string]any{"a_device_id": m.newDevice(g), "b_device_id": m.newDevice(g)}}, true
	case "DELETE /api/links/{id}":
		a, b := m.newDevice(g), m.newDevice(g)
		return req{method: "DELETE", path: fmt.Sprintf("/api/links/%d", m.newLink(a, nil, b, nil, "manual", 1))}, true
	case "GET /api/map/views":
		return req{method: "GET", path: "/api/map/views"}, true
	case "POST /api/map/views":
		return req{method: "POST", path: "/api/map/views", body: map[string]any{"name": uniqueName("v"), "kind": "logical"}}, true
	case "PATCH /api/map/views/{id}":
		return req{method: "PATCH", path: fmt.Sprintf("/api/map/views/%d", m.newView()), body: map[string]any{"name": uniqueName("v")}}, true
	case "DELETE /api/map/views/{id}":
		return req{method: "DELETE", path: fmt.Sprintf("/api/map/views/%d", m.newView())}, true
	case "GET /api/map/views/{id}/areas":
		return req{method: "GET", path: fmt.Sprintf("/api/map/views/%d/areas", m.newView())}, true
	case "POST /api/map/views/{id}/areas":
		return req{method: "POST", path: fmt.Sprintf("/api/map/views/%d/areas", m.newView()),
			body: map[string]any{"kind": "room", "name": uniqueName("a"), "x": 0, "y": 0, "w": 10, "h": 10}}, true
	case "PATCH /api/map/views/{id}/areas/{area_id}":
		v := m.newView()
		return req{method: "PATCH", path: fmt.Sprintf("/api/map/views/%d/areas/%d", v, m.newArea(v, nil, 0, 0, 5, 5)), body: map[string]any{"name": uniqueName("a")}}, true
	case "DELETE /api/map/views/{id}/areas/{area_id}":
		v := m.newView()
		return req{method: "DELETE", path: fmt.Sprintf("/api/map/views/%d/areas/%d", v, m.newArea(v, nil, 0, 0, 5, 5))}, true
	case "PUT /api/map/views/{id}/positions":
		return req{method: "PUT", path: fmt.Sprintf("/api/map/views/%d/positions", m.newView()),
			body: map[string]any{"items": []map[string]any{{"device_id": m.newDevice(g), "x": 1, "y": 2, "pinned": true}}}}, true
	case "POST /api/map/backgrounds":
		raw, ctype := multipartFile("map.png", pngBytes())
		return req{method: "POST", path: "/api/map/backgrounds", raw: raw, ctype: ctype}, true
	case "GET /api/map/backgrounds/{id}":
		return req{method: "GET", path: fmt.Sprintf("/api/map/backgrounds/%d", m.newBackground("image/png", pngBytes(), 1, 1))}, true
	case "DELETE /api/map/backgrounds/{id}":
		return req{method: "DELETE", path: fmt.Sprintf("/api/map/backgrounds/%d", m.newBackground("image/png", pngBytes(), 1, 1))}, true
	}
	return req{}, false
}

func TestTopologyScopedByGroup(t *testing.T) {
	f := newFixture(t, nil)
	f.clearMap()
	gA, gB := f.newGroup(), f.newGroup()
	viewerA := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &gA})
	global := f.login(false, rbac.Binding{Role: rbac.RoleViewer})
	a1, a2, b1 := f.newDevice(gA), f.newDevice(gA), f.newDevice(gB)
	f.newIface(a1, 1, "gi1/0/1", "uplink", 10_000_000_000)
	f.newIface(a2, 2, "", "alias-2", 1_000_000_000)
	f.newIface(b1, 3, "secret-port-b", "", 1_000_000_000)
	lAA := f.newLink(a1, ifx(1), a2, ifx(2), "lldp", 1)
	lAB := f.newLink(a1, ifx(1), b1, ifx(3), "lldp", 0.5)
	f.setState(a1, "up")
	f.setState(a2, "up")
	f.setState(b1, "down")

	view := f.newView()
	outer := f.newArea(view, nil, 0, 0, 100, 100)
	f.newArea(view, &outer, 10, 10, 20, 20)
	f.exec(`INSERT INTO core.map_node_position (view_id, device_id, x, y, pinned) VALUES ($1, $2, 15, 15, true), ($1, $3, 50, 50, false), ($1, $4, 16, 16, false)`, view, a1, a2, b1)

	got := decode[topologyT](t, f.getTopology(viewerA, url.Values{"view_id": {fmt.Sprint(view)}}))
	if len(got.Nodes) != 2 || len(got.Links) != 1 || got.Links[0].ID != lAA {
		t.Fatalf("viewer of A sees nodes %+v links %+v", got.Nodes, got.Links)
	}
	l := got.Links[0]
	if l.A != a1 || l.B != a2 || l.APortName != "gi1/0/1" || l.BPortName != "alias-2" || l.SpeedBps == nil || *l.SpeedBps != 1_000_000_000 ||
		l.Source != "lldp" || l.Confidence != 1 || l.Manual {
		t.Errorf("link = %+v", l)
	}
	if strings.Contains(fmt.Sprint(got), "secret-port-b") {
		t.Error("foreign port name leaked")
	}
	if len(got.Areas) != 2 {
		t.Fatalf("areas = %+v", got.Areas)
	}
	for _, a := range got.Areas {
		/* The down device of group B sits in the small area; it is not counted and does not colour the status. */
		want := 2
		if a.ParentID != nil {
			want = 1
		}
		if a.DeviceCount != want || a.Status != "up" || a.States.Down != 0 {
			t.Errorf("area for viewer A = %+v, want %d devices up", a, want)
		}
	}
	for _, n := range got.Nodes {
		if n.X == nil || n.Y == nil || n.AreaID == nil || (n.DeviceID == a1) != n.Pinned {
			t.Errorf("node = %+v", n)
		}
	}

	all := decode[topologyT](t, f.getTopology(global, url.Values{"view_id": {fmt.Sprint(view)}}))
	if len(all.Nodes) < 3 || len(all.Links) < 2 {
		t.Fatalf("global sees %d nodes, %d links", len(all.Nodes), len(all.Links))
	}
	var small *topoAreaT
	for i, a := range all.Areas {
		if a.ParentID != nil {
			small = &all.Areas[i]
		}
	}
	if small == nil || small.DeviceCount != 2 || small.Status != "down" || small.States.Down != 1 {
		t.Errorf("small area for global = %+v", small)
	}
	var seenAB bool
	for _, l := range all.Links {
		seenAB = seenAB || l.ID == lAB
	}
	if !seenAB {
		t.Error("global misses the cross-group link")
	}

	/* group_id narrows to the group and its subgroups; a foreign or unknown group is 404. */
	onlyB := decode[topologyT](t, f.getTopology(global, url.Values{"group_id": {fmt.Sprint(gB)}}))
	if len(onlyB.Nodes) != 1 || onlyB.Nodes[0].DeviceID != b1 || len(onlyB.Links) != 0 || len(onlyB.Areas) != 0 {
		t.Errorf("group B = %+v", onlyB)
	}
	wantError(t, f.getTopology(viewerA, url.Values{"group_id": {fmt.Sprint(gB)}}), http.StatusNotFound, "not_found")
	wantError(t, f.getTopology(global, url.Values{"group_id": {"999999999"}}), http.StatusNotFound, "not_found")
	wantError(t, f.getTopology(global, url.Values{"view_id": {"999999999"}}), http.StatusNotFound, "not_found")
	wantError(t, f.getTopology(global, url.Values{"view_id": {"x"}}), http.StatusBadRequest, "bad_request")
	wantError(t, f.getTopology(global, url.Values{"view_id": {"1", "2"}}), http.StatusBadRequest, "bad_request")
	/* No view: no positions, no areas. */
	plain := decode[topologyT](t, f.getTopology(viewerA, url.Values{}))
	if len(plain.Areas) != 0 || plain.Nodes[0].X != nil {
		t.Errorf("without view: %+v", plain)
	}
}

func TestTopologyNestedAreas(t *testing.T) {
	f := newFixture(t, nil)
	f.clearMap()
	g := f.newGroup()
	viewer := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &g})
	d1, d2, d3 := f.newDevice(g), f.newDevice(g), f.newDevice(g)
	view := f.newView()
	root := f.newArea(view, nil, 0, 0, 1000, 1000)
	mid := f.newArea(view, &root, 0, 0, 100, 100)
	leaf := f.newArea(view, &mid, 0, 0, 10, 10)
	f.exec(`INSERT INTO core.map_node_position (view_id, device_id, x, y) VALUES ($1, $2, 5, 5), ($1, $3, 50, 50), ($1, $4, 5000, 5000)`, view, d1, d2, d3)
	got := decode[topologyT](t, f.getTopology(viewer, url.Values{"view_id": {fmt.Sprint(view)}}))
	area := map[int64]int64{}
	for _, n := range got.Nodes {
		if n.AreaID != nil {
			area[n.DeviceID] = *n.AreaID
		}
	}
	if area[d1] != leaf || area[d2] != mid || len(area) != 2 {
		t.Errorf("node areas = %v (leaf %d mid %d)", area, leaf, mid)
	}
	counts := map[int64]int{}
	for _, a := range got.Areas {
		counts[a.ID] = a.DeviceCount
		if a.Status != "unknown" {
			t.Errorf("area %d status %q, want unknown (no poll data)", a.ID, a.Status)
		}
	}
	if counts[leaf] != 1 || counts[mid] != 2 || counts[root] != 2 {
		t.Errorf("counts = %v", counts)
	}
}

func TestTopologyChangesScopedAndPaged(t *testing.T) {
	f := newFixture(t, nil)
	gA, gB := f.newGroup(), f.newGroup()
	viewerA := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &gA})
	global := f.login(false, rbac.Binding{Role: rbac.RoleViewer})
	a1, a2, b1 := f.newDevice(gA), f.newDevice(gA), f.newDevice(gB)
	f.newIface(a1, 1, "gi1", "", 1)
	ghost := b1 + 1_000_000
	now := time.Now().UTC().Truncate(time.Second)
	c1 := f.newChange(nil, a1, ifx(1), a2, nil, "appeared", "lldp", now.Add(-4*time.Minute))
	c2 := f.newChange(nil, a1, nil, b1, nil, "appeared", "lldp", now.Add(-3*time.Minute))
	c3 := f.newChange(nil, a2, nil, ghost, nil, "disappeared", "mac", now.Add(-2*time.Minute))
	c4 := f.newChange(nil, a1, ifx(1), a2, nil, "disappeared", "lldp", now.Add(-time.Minute))

	get := func(s *subject, q url.Values) changesT {
		return decode[changesT](t, f.do(s.authed(req{method: "GET", path: "/api/topology/changes?" + q.Encode()})))
	}
	ids := func(c changesT) []int64 {
		var out []int64
		for _, i := range c.Items {
			out = append(out, i.ID)
		}
		return out
	}
	if got := ids(get(viewerA, url.Values{})); fmt.Sprint(got) != fmt.Sprint([]int64{c4, c1}) {
		t.Errorf("viewer A sees %v, want [%d %d]", got, c4, c1)
	}
	full := get(global, url.Values{"limit": {"500"}})
	mine := changesT{}
	for _, i := range full.Items {
		if i.ID == c1 || i.ID == c2 || i.ID == c3 || i.ID == c4 {
			mine.Items = append(mine.Items, i)
		}
	}
	if got := ids(mine); fmt.Sprint(got) != fmt.Sprint([]int64{c4, c3, c2, c1}) {
		t.Errorf("global sees %v", got)
	}
	full = mine
	if first := full.Items[0]; first.Change != "disappeared" || first.ADeviceID != a1 || first.APortName != "gi1" || first.ADeviceName == "" || first.Source != "lldp" {
		t.Errorf("newest change = %+v", first)
	}
	/* A change of a deleted device is global-only and has no name. */
	if g := full.Items[1]; g.BDeviceID != ghost || g.BPortName != "" {
		t.Errorf("ghost change = %+v", g)
	}
	/* Paging: viewer A, one row per page. */
	p1 := get(viewerA, url.Values{"limit": {"1"}})
	if len(p1.Items) != 1 || p1.NextCursor == nil || p1.Items[0].ID != c4 {
		t.Fatalf("page 1 = %+v", p1)
	}
	p2 := get(viewerA, url.Values{"limit": {"1"}, "cursor": {*p1.NextCursor}})
	if len(p2.Items) != 1 || p2.Items[0].ID != c1 || p2.NextCursor != nil {
		t.Fatalf("page 2 = %+v", p2)
	}
	for _, q := range []url.Values{{"cursor": {"bogus"}}, {"limit": {"0"}}, {"limit": {"501"}}, {"cursor": {"a", "b"}}} {
		wantError(t, f.do(viewerA.authed(req{method: "GET", path: "/api/topology/changes?" + q.Encode()})), http.StatusBadRequest, "bad_request")
	}
}

func TestEventsIncludeTopologyChanges(t *testing.T) {
	f := newFixture(t, nil)
	gA, gB := f.newGroup(), f.newGroup()
	viewerA := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &gA})
	global := f.login(false, rbac.Binding{Role: rbac.RoleViewer})
	a1, a2, b1 := f.newDevice(gA), f.newDevice(gA), f.newDevice(gB)
	f.newIface(a1, 1, "gi1", "", 1)
	f.newIface(a2, 7, "", "to-core", 1)
	now := time.Now().UTC().Truncate(time.Second)
	f.newChange(nil, a1, ifx(1), a2, ifx(7), "appeared", "lldp", now.Add(-3*time.Minute))
	f.newChange(nil, a1, nil, b1, nil, "disappeared", "lldp", now.Add(-2*time.Minute))
	f.newChange(nil, a2, nil, b1+1_000_000, nil, "appeared", "mac", now.Add(-time.Minute))
	f.syslog(a1, now.Add(-30*time.Second), 3, "sw", "noise")

	topo := url.Values{"kind": {"topology"}}
	got := decode[eventsResp](t, f.getEvents(viewerA, topo))
	if len(got.Items) != 1 {
		t.Fatalf("viewer A topology events = %+v", got.Items)
	}
	e := got.Items[0]
	n1 := e.DeviceName
	if e.Kind != "topology" || e.Name == nil || *e.Name != "appeared" || e.Severity == nil || *e.Severity != "info" || e.DeviceID != a1 {
		t.Errorf("event = %+v", e)
	}
	if !strings.HasPrefix(e.Text, n1+" gi1 ↔ ") || !strings.HasSuffix(e.Text, " to-core") {
		t.Errorf("text = %q (device %s)", e.Text, n1)
	}
	topo.Set("limit", "500")
	every := decode[eventsResp](t, f.getEvents(global, topo))
	all := eventsResp{}
	for _, i := range every.Items {
		if i.DeviceID == a1 || i.DeviceID == a2 {
			all.Items = append(all.Items, i)
		}
	}
	if len(all.Items) != 3 {
		t.Fatalf("global topology events of the test = %d", len(all.Items))
	}
	if all.Items[1].Severity == nil || *all.Items[1].Severity != "warning" {
		t.Errorf("disappeared severity = %v", all.Items[1].Severity)
	}
	if ghost := all.Items[0]; !strings.Contains(ghost.Text, "#") {
		t.Errorf("ghost text = %q", ghost.Text)
	}
	/* Mixed feed: viewer A also gets the syslog row, paged by the shared cursor. */
	feed := url.Values{"limit": {"1"}}
	seen := 0
	for {
		page := decode[eventsResp](t, f.getEvents(viewerA, feed))
		seen += len(page.Items)
		if page.NextCursor == nil {
			break
		}
		feed.Set("cursor", *page.NextCursor)
	}
	if seen != 2 {
		t.Errorf("viewer A feed has %d rows, want 2 (syslog + one topology)", seen)
	}
	/* The device filter matches either end; text search does not match topology rows. */
	if d := decode[eventsResp](t, f.getEvents(viewerA, url.Values{"kind": {"topology"}, "device_id": {fmt.Sprint(a2)}})); len(d.Items) != 1 {
		t.Errorf("device filter = %+v", d.Items)
	}
	if d := decode[eventsResp](t, f.getEvents(viewerA, url.Values{"q": {"gi1"}})); len(d.Items) != 0 {
		t.Errorf("text search matched %+v", d.Items)
	}
}

func TestManualLinks(t *testing.T) {
	var reloads atomic.Int32
	f := newFixture(t, func(d *httpapi.Deps) { d.ConfigChanged = func() { reloads.Add(1) } })
	g := f.newGroup()
	admin := f.login(false, rbac.Binding{Role: rbac.RoleAdmin})
	adminG := f.login(false, rbac.Binding{Role: rbac.RoleAdmin, GroupID: &g})
	a, b := f.newDevice(g), f.newDevice(g)
	post := func(s *subject, body map[string]any) *http.Response {
		return f.do(s.authed(req{method: "POST", path: "/api/links", body: body}))
	}

	/* Ends arrive in any order and are stored canonically. */
	resp := post(admin, map[string]any{"a_device_id": b, "a_if_index": 5, "b_device_id": a})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d", resp.StatusCode)
	}
	id := decode[struct {
		ID int64 `json:"id"`
	}](t, resp).ID
	var src string
	var manual bool
	var conf float64
	var la, lb int64
	var laIf, lbIf *int
	if err := f.env.Pool("postgres").QueryRow(context.Background(),
		`SELECT source, manual, confidence::float8, a_device_id, a_if_index, b_device_id, b_if_index FROM core.link WHERE id = $1`, id).
		Scan(&src, &manual, &conf, &la, &laIf, &lb, &lbIf); err != nil {
		t.Fatal(err)
	}
	if src != "manual" || !manual || conf != 1 || la != a || laIf != nil || lb != b || lbIf == nil || *lbIf != 5 {
		t.Errorf("stored link = %s %v %v a=%d/%v b=%d/%v", src, manual, conf, la, laIf, lb, lbIf)
	}
	var changes int
	if err := f.env.Pool("postgres").QueryRow(context.Background(),
		`SELECT count(*) FROM core.link_change WHERE link_id = $1 AND change = 'appeared' AND source = 'manual'`, id).Scan(&changes); err != nil || changes != 1 {
		t.Errorf("appeared records = %d, %v", changes, err)
	}
	wantAudit(t, f, "links.create")
	if reloads.Load() != 1 {
		t.Errorf("topology reloads = %d, want 1", reloads.Load())
	}

	wantError(t, post(admin, map[string]any{"a_device_id": a, "b_device_id": b, "b_if_index": 5}), http.StatusConflict, "link_exists")
	wantError(t, post(admin, map[string]any{"a_device_id": a, "b_device_id": a}), http.StatusBadRequest, "bad_request")
	wantError(t, post(admin, map[string]any{"a_device_id": a, "b_device_id": b, "b_if_index": 0}), http.StatusBadRequest, "bad_request")
	wantError(t, post(admin, map[string]any{"a_device_id": a, "b_device_id": b, "b_if_index": 1 << 31}), http.StatusBadRequest, "bad_request")
	wantError(t, post(admin, map[string]any{"a_device_id": a, "b_device_id": b + 1_000_000}), http.StatusNotFound, "not_found")
	wantError(t, post(adminG, map[string]any{"a_device_id": a, "b_device_id": b, "b_if_index": 9}), http.StatusForbidden, "forbidden")

	/* A manual link shows on the map. */
	topo := decode[topologyT](t, f.getTopology(admin, url.Values{"group_id": {fmt.Sprint(g)}}))
	if len(topo.Links) != 1 || !topo.Links[0].Manual || topo.Links[0].Source != "manual" {
		t.Errorf("topology links = %+v", topo.Links)
	}

	/* Pair cap. */
	for i := 1; i <= 63; i++ {
		f.newLink(a, ifx(100+i), b, ifx(100+i), "lldp", 1)
	}
	wantError(t, post(admin, map[string]any{"a_device_id": a, "b_device_id": b, "a_if_index": 4000}), http.StatusConflict, "too_many_links")

	del := func(s *subject, id int64) *http.Response {
		return f.do(s.authed(req{method: "DELETE", path: fmt.Sprintf("/api/links/%d", id)}))
	}
	auto := f.queryID(`SELECT id FROM core.link WHERE NOT manual AND a_device_id = $1 LIMIT 1`, a)
	wantError(t, del(admin, auto), http.StatusNotFound, "not_found")
	wantError(t, del(admin, 999999999), http.StatusNotFound, "not_found")
	wantError(t, del(adminG, id), http.StatusForbidden, "forbidden")
	if resp := del(admin, id); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d", resp.StatusCode)
	}
	if err := f.env.Pool("postgres").QueryRow(context.Background(),
		`SELECT count(*) FROM core.link_change WHERE link_id = $1 AND change = 'disappeared' AND source = 'manual'`, id).Scan(&changes); err != nil || changes != 1 {
		t.Errorf("disappeared records = %d, %v", changes, err)
	}
	wantAudit(t, f, "links.delete")
	if reloads.Load() != 2 {
		t.Errorf("topology reloads = %d, want 2", reloads.Load())
	}
	wantError(t, del(admin, id), http.StatusNotFound, "not_found")
}

func TestViewsAndAreas(t *testing.T) {
	f := newFixture(t, nil)
	f.clearMap()
	admin := f.login(false, rbac.Binding{Role: rbac.RoleAdmin})
	viewer := f.login(false, rbac.Binding{Role: rbac.RoleViewer})
	call := func(s *subject, method, path string, body any) *http.Response {
		return f.do(s.authed(req{method: method, path: path, body: body}))
	}
	created := func(path string, body any) int64 {
		t.Helper()
		resp := call(admin, "POST", path, body)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("POST %s = %d", path, resp.StatusCode)
		}
		return decode[struct {
			ID int64 `json:"id"`
		}](t, resp).ID
	}
	ok := func(resp *http.Response) {
		t.Helper()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("status = %d", resp.StatusCode)
		}
	}

	for _, bad := range []map[string]any{
		{"name": "", "kind": "logical"}, {"name": " x", "kind": "logical"}, {"name": "x", "kind": "bogus"},
		{"name": strings.Repeat("я", 201), "kind": "plan"}, {"name": "x\u0007", "kind": "plan"}, {"name": "x", "kind": "plan", "background_id": 0},
	} {
		wantError(t, call(admin, "POST", "/api/map/views", bad), http.StatusBadRequest, "bad_request")
	}
	wantError(t, call(admin, "POST", "/api/map/views", map[string]any{"name": "x", "kind": "plan", "background_id": 424242}), http.StatusBadRequest, "bad_request")
	v := created("/api/map/views", map[string]any{"name": "Кампус", "kind": "plan"})
	ok(call(admin, "PATCH", fmt.Sprintf("/api/map/views/%d", v), map[string]any{"name": "Campus", "kind": "logical", "background_id": nil}))
	wantError(t, call(admin, "PATCH", fmt.Sprintf("/api/map/views/%d", v), map[string]any{}), http.StatusBadRequest, "bad_request")
	wantError(t, call(admin, "PATCH", "/api/map/views/999999", map[string]any{"name": "z"}), http.StatusNotFound, "not_found")
	list := decode[[]struct {
		ID           int64  `json:"id"`
		Name         string `json:"name"`
		Kind         string `json:"kind"`
		BackgroundID *int64 `json:"background_id"`
	}](t, call(viewer, "GET", "/api/map/views", nil))
	if len(list) != 1 || list[0].ID != v || list[0].Name != "Campus" || list[0].Kind != "logical" || list[0].BackgroundID != nil {
		t.Errorf("views = %+v", list)
	}
	wantError(t, call(viewer, "POST", "/api/map/views", map[string]any{"name": "x", "kind": "plan"}), http.StatusForbidden, "forbidden")

	areaPath := fmt.Sprintf("/api/map/views/%d/areas", v)
	rect := func(extra map[string]any) map[string]any {
		m := map[string]any{"kind": "building", "name": uniqueName("b"), "x": 0, "y": 0, "w": 100, "h": 50}
		for k, val := range extra {
			m[k] = val
		}
		return m
	}
	for _, bad := range []map[string]any{
		rect(map[string]any{"w": 0}), rect(map[string]any{"h": -1}), rect(map[string]any{"x": 1e7}), rect(map[string]any{"kind": "city"}),
		rect(map[string]any{"name": ""}), rect(map[string]any{"parent_id": 0}),
	} {
		wantError(t, call(admin, "POST", areaPath, bad), http.StatusBadRequest, "bad_request")
	}
	wantError(t, call(admin, "POST", "/api/map/views/999999/areas", rect(nil)), http.StatusNotFound, "not_found")
	root := created(areaPath, rect(nil))
	child := created(areaPath, rect(map[string]any{"parent_id": root, "kind": "floor"}))
	grand := created(areaPath, rect(map[string]any{"parent_id": child, "kind": "room"}))

	/* Parent errors from the database triggers get their own codes. */
	patch := func(view, area int64, body any) *http.Response {
		return call(admin, "PATCH", fmt.Sprintf("/api/map/views/%d/areas/%d", view, area), body)
	}
	wantError(t, patch(v, root, map[string]any{"parent_id": grand}), http.StatusConflict, "area_cycle")
	wantError(t, patch(v, root, map[string]any{"parent_id": root}), http.StatusConflict, "area_cycle")
	other := f.newView()
	foreign := f.newArea(other, nil, 0, 0, 1, 1)
	wantError(t, patch(v, child, map[string]any{"parent_id": foreign}), http.StatusConflict, "area_other_view")
	wantError(t, call(admin, "POST", areaPath, rect(map[string]any{"parent_id": foreign})), http.StatusConflict, "area_other_view")
	wantError(t, patch(other, child, map[string]any{"name": "x"}), http.StatusNotFound, "not_found") /* the area belongs to another view */
	wantError(t, patch(v, child, map[string]any{"w": 0}), http.StatusBadRequest, "bad_request")
	wantError(t, patch(v, child, map[string]any{}), http.StatusBadRequest, "bad_request")
	tip := grand
	for i := 0; i < 5; i++ { /* root > child > grand > 5 more = 8 levels */
		tip = created(areaPath, rect(map[string]any{"parent_id": tip}))
	}
	wantError(t, call(admin, "POST", areaPath, rect(map[string]any{"parent_id": tip})), http.StatusConflict, "area_too_deep")
	ok(patch(v, grand, map[string]any{"name": "Room 1", "x": 3.5, "w": 20}))
	ok(patch(v, grand, map[string]any{"parent_id": nil}))
	areas := decode[[]struct {
		ID       int64   `json:"id"`
		ParentID *int64  `json:"parent_id"`
		Name     string  `json:"name"`
		X        float64 `json:"x"`
		W        float64 `json:"w"`
		Kind     string  `json:"kind"`
	}](t, call(viewer, "GET", areaPath, nil))
	for _, a := range areas {
		if a.ID == grand && (a.ParentID != nil || a.Name != "Room 1" || a.X != 3.5 || a.W != 20 || a.Kind != "room") {
			t.Errorf("patched area = %+v", a)
		}
	}
	wantError(t, call(viewer, "GET", "/api/map/views/999999/areas", nil), http.StatusNotFound, "not_found")

	/* Deleting an area detaches its children; deleting a view takes its areas and positions along. */
	ok(call(admin, "DELETE", fmt.Sprintf("%s/%d", areaPath, root), nil))
	var parent *int64
	if err := f.env.Pool("postgres").QueryRow(context.Background(), `SELECT parent_id FROM core.map_area WHERE id = $1`, child).Scan(&parent); err != nil || parent != nil {
		t.Errorf("child parent = %v, %v", parent, err)
	}
	wantError(t, call(admin, "DELETE", fmt.Sprintf("%s/%d", areaPath, root), nil), http.StatusNotFound, "not_found")
	ok(call(admin, "DELETE", fmt.Sprintf("/api/map/views/%d", v), nil))
	if n := f.queryID(`SELECT count(*) FROM core.map_area WHERE view_id = $1`, v); n != 0 {
		t.Errorf("%d areas left after view delete", n)
	}
	wantError(t, call(admin, "DELETE", fmt.Sprintf("/api/map/views/%d", v), nil), http.StatusNotFound, "not_found")
	wantAudit(t, f, "map.view.create", "map.view.update", "map.view.delete", "map.area.create", "map.area.update", "map.area.delete")
}

func TestMapCaps(t *testing.T) {
	f := newFixture(t, nil)
	f.clearMap()
	t.Cleanup(f.clearMap)
	admin := f.login(false, rbac.Binding{Role: rbac.RoleAdmin})
	f.exec(`INSERT INTO core.map_view (name, kind) SELECT 'v' || g, 'logical' FROM generate_series(1, 100) g`)
	wantError(t, f.do(admin.authed(req{method: "POST", path: "/api/map/views", body: map[string]any{"name": "one more", "kind": "logical"}})), http.StatusConflict, "too_many_views")
	f.clearMap()
	v := f.newView()
	f.exec(`INSERT INTO core.map_area (view_id, kind, name, x, y, w, h) SELECT $1, 'room', 'a' || g, 0, 0, 1, 1 FROM generate_series(1, 2000) g`, v)
	wantError(t, f.do(admin.authed(req{method: "POST", path: fmt.Sprintf("/api/map/views/%d/areas", v),
		body: map[string]any{"kind": "room", "name": "x", "x": 0, "y": 0, "w": 1, "h": 1}})), http.StatusConflict, "too_many_areas")
	other := f.newView()
	if resp := f.do(admin.authed(req{method: "POST", path: fmt.Sprintf("/api/map/views/%d/areas", other),
		body: map[string]any{"kind": "room", "name": "x", "x": 0, "y": 0, "w": 1, "h": 1}})); resp.StatusCode != http.StatusCreated {
		t.Errorf("other view create = %d", resp.StatusCode)
	}
}

func TestPositionsBatch(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	admin := f.login(false, rbac.Binding{Role: rbac.RoleAdmin})
	view := f.newView()
	d1, d2 := f.newDevice(g), f.newDevice(g)
	put := func(items []map[string]any) *http.Response {
		return f.do(admin.authed(req{method: "PUT", path: fmt.Sprintf("/api/map/views/%d/positions", view), body: map[string]any{"items": items}}))
	}
	item := func(d int64, x, y float64, pinned bool) map[string]any {
		return map[string]any{"device_id": d, "x": x, "y": y, "pinned": pinned}
	}
	type pos struct {
		x, y   float64
		pinned bool
	}
	read := func() map[int64]pos {
		rows, err := f.env.Pool("postgres").Query(context.Background(), `SELECT device_id, x, y, pinned FROM core.map_node_position WHERE view_id = $1`, view)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[int64]pos{}
		for rows.Next() {
			var d int64
			var p pos
			if err := rows.Scan(&d, &p.x, &p.y, &p.pinned); err != nil {
				t.Fatal(err)
			}
			out[d] = p
		}
		return out
	}

	if resp := put([]map[string]any{item(d1, 1.5, -2, true), item(d2, 3, 4, false)}); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("put = %d", resp.StatusCode)
	}
	if got := read(); len(got) != 2 || got[d1] != (pos{1.5, -2, true}) || got[d2] != (pos{3, 4, false}) {
		t.Errorf("positions = %+v", got)
	}
	/* An existing row is replaced; unpinning is explicit. */
	put([]map[string]any{item(d1, 9, 9, false)})
	if got := read(); got[d1] != (pos{9, 9, false}) || got[d2] != (pos{3, 4, false}) {
		t.Errorf("after replace = %+v", got)
	}
	wantAudit(t, f, "map.positions.put")

	/* A device that cannot be seen (here: does not exist) fails the whole batch without partial writes. */
	wantError(t, put([]map[string]any{item(d1, 100, 100, true), item(d2+1_000_000, 1, 1, false)}), http.StatusNotFound, "not_found")
	if got := read(); got[d1] != (pos{9, 9, false}) {
		t.Errorf("partial write: %+v", got)
	}
	wantError(t, f.do(admin.authed(req{method: "PUT", path: "/api/map/views/999999/positions", body: map[string]any{"items": []map[string]any{item(d1, 1, 1, false)}}})), http.StatusNotFound, "not_found")

	for name, items := range map[string][]map[string]any{
		"empty": {}, "duplicate": {item(d1, 1, 1, false), item(d1, 2, 2, false)}, "x too big": {item(d1, 1e6+1, 0, false)},
		"y too small": {item(d1, 0, -1e6-1, false)}, "bad id": {item(0, 0, 0, false)},
	} {
		if resp := put(items); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, resp.StatusCode)
		}
	}
	/* The bounds themselves are allowed. */
	if resp := put([]map[string]any{item(d1, 1e6, -1e6, true)}); resp.StatusCode != http.StatusNoContent {
		t.Errorf("bounds = %d", resp.StatusCode)
	}

	/* 5 000 items fit in one request; 5 001 do not. */
	ids := f.queryIDs(`INSERT INTO core.device (name, address, group_id) SELECT 'bulk' || $2::bigint || '-' || g, ('10.' || ($2::bigint % 200) || '.' || (g / 250) || '.' || (g % 250 + 1))::inet, $1
		FROM generate_series(1, 5001) g RETURNING id`, g, seq.Add(1))
	batch := make([]map[string]any, 0, 5001)
	for _, id := range ids {
		batch = append(batch, item(id, 123456.789012, -654321.098765, true))
	}
	wantStatus := func(items []map[string]any, want int) {
		t.Helper()
		if resp := put(items); resp.StatusCode != want {
			t.Errorf("%d items: status %d, want %d", len(items), resp.StatusCode, want)
		}
	}
	wantStatus(batch[:5000], http.StatusNoContent)
	wantStatus(batch, http.StatusBadRequest)
	if n := len(read()); n != 5002 {
		t.Errorf("rows = %d, want 5002 (2 earlier + 5000)", n)
	}
}

func (f *fixture) queryIDs(sql string, args ...any) []int64 {
	f.t.Helper()
	rows, err := f.env.Pool("postgres").Query(context.Background(), sql, args...)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		f.t.Fatal(err)
	}
	return out
}
