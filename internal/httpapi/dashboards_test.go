package httpapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/rbac"
)

type dashboardJSON struct {
	ID             int64   `json:"id"`
	Name           string  `json:"name"`
	Shared         bool    `json:"shared"`
	DefaultForRole *string `json:"default_for_role"`
	Editable       bool    `json:"editable"`
	Widgets        []struct {
		ID     int64           `json:"id"`
		Type   string          `json:"type"`
		X      int             `json:"x"`
		Y      int             `json:"y"`
		W      int             `json:"w"`
		H      int             `json:"h"`
		Config json.RawMessage `json:"config"`
	} `json:"widgets"`
}

/* clearSharedDashboards removes the shared dashboards left by other tests once there are atLeast of them (the cap is 50). */
func (f *fixture) clearSharedDashboards(atLeast int) {
	f.t.Helper()
	var n int
	if err := f.env.Pool("postgres").QueryRow(context.Background(), `SELECT count(*) FROM core.dashboard WHERE shared`).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	if n >= atLeast {
		f.exec(`DELETE FROM core.dashboard WHERE shared`)
	}
}

/* newDashboard inserts a personal dashboard of owner, or a shared one for owner nil. */
func (f *fixture) newDashboard(owner *int64) int64 {
	f.t.Helper()
	if owner == nil {
		f.clearSharedDashboards(40)
	}
	return f.queryID(`INSERT INTO core.dashboard (owner_id, name, shared) VALUES ($1::bigint, $2, $1::bigint IS NULL) RETURNING id`, owner, uniqueName("dash"))
}

/* sameJSON compares a stored jsonb value (which PostgreSQL re-spaces and re-orders) with want by value. */
func sameJSON(got json.RawMessage, want string) bool {
	var a, b any
	return json.Unmarshal(got, &a) == nil && json.Unmarshal([]byte(want), &b) == nil && reflect.DeepEqual(a, b)
}

func widget(typ string, x, y, w, h int, config any) map[string]any {
	return map[string]any{"type": typ, "x": x, "y": y, "w": w, "h": h, "config": config}
}

func putWidgets(f *fixture, s *subject, dash int64, ws ...map[string]any) *http.Response {
	if ws == nil {
		ws = []map[string]any{}
	}
	return f.do(s.authed(req{method: "PUT", path: fmt.Sprintf("/api/dashboards/%d/widgets", dash), body: map[string]any{"widgets": ws}}))
}

/* dashboardRequest builds valid requests for the dashboard routes (shared targets) and the widget aggregates. */
func (m *matrixEnv) dashboardRequest(key string) (req, bool) {
	path := func(format string) string { return fmt.Sprintf(format, m.newDashboard(nil)) }
	switch key {
	case "GET /api/dashboards":
		return req{method: "GET", path: "/api/dashboards"}, true
	case "POST /api/dashboards":
		m.clearSharedDashboards(40)
		return req{method: "POST", path: "/api/dashboards", body: map[string]any{"name": uniqueName("d"), "shared": true}}, true
	case "GET /api/dashboards/{id}":
		return req{method: "GET", path: path("/api/dashboards/%d")}, true
	case "PATCH /api/dashboards/{id}":
		return req{method: "PATCH", path: path("/api/dashboards/%d"), body: map[string]any{"name": uniqueName("r")}}, true
	case "DELETE /api/dashboards/{id}":
		return req{method: "DELETE", path: path("/api/dashboards/%d")}, true
	case "PUT /api/dashboards/{id}/widgets":
		return req{method: "PUT", path: path("/api/dashboards/%d/widgets"),
			body: map[string]any{"widgets": []map[string]any{widget("device_status", 0, 0, 3, 2, map[string]any{})}}}, true
	case "GET /api/stats/device-states", "GET /api/stats/top-interfaces", "GET /api/stats/config-drift":
		return req{method: "GET", path: strings.TrimPrefix(key, "GET ")}, true
	case "GET /api/stats/top-devices":
		return req{method: "GET", path: "/api/stats/top-devices?metric=cpu"}, true
	}
	return req{}, false
}

/* TestWidgetConfigSchemas: the server accepts the known widget types with their schemas only and stores configs normalized. */
func TestWidgetConfigSchemas(t *testing.T) {
	f := newFixture(t, nil)
	s := f.login(false, rbac.Binding{Role: rbac.RoleViewer})
	dash := f.newDashboard(&s.uid)

	bad := []struct {
		name string
		w    map[string]any
		code string
	}{
		{"unknown type", widget("weather", 0, 0, 2, 2, map[string]any{}), "invalid_widget"},
		{"extra field", widget("device_status", 0, 0, 2, 2, map[string]any{"group_id": 1}), "invalid_widget"},
		{"config not an object", widget("device_status", 0, 0, 2, 2, []int{}), "invalid_widget"},
		{"config null", widget("device_status", 0, 0, 2, 2, nil), "invalid_widget"},
		{"title too long", widget("device_status", 0, 0, 2, 2, map[string]any{"title": strings.Repeat("я", 101)}), "invalid_widget"},
		{"title control char", widget("device_status", 0, 0, 2, 2, map[string]any{"title": "a\nb"}), "invalid_widget"},
		{"limit zero", widget("problems", 0, 0, 2, 2, map[string]any{"limit": 0}), "invalid_widget"},
		{"limit too big", widget("problems", 0, 0, 2, 2, map[string]any{"limit": 51}), "invalid_widget"},
		{"limit string", widget("problems", 0, 0, 2, 2, map[string]any{"limit": "5"}), "invalid_widget"},
		{"limit fraction", widget("problems", 0, 0, 2, 2, map[string]any{"limit": 1.5}), "invalid_widget"},
		{"severity", widget("problems", 0, 0, 2, 2, map[string]any{"severity_min": "critical"}), "invalid_widget"},
		{"metric missing", widget("top_devices", 0, 0, 2, 2, map[string]any{}), "invalid_widget"},
		{"metric unknown", widget("top_devices", 0, 0, 2, 2, map[string]any{"metric": "disk"}), "invalid_widget"},
		{"log kind", widget("log_stream", 0, 0, 2, 2, map[string]any{"kind": "storm"}), "invalid_widget"},
		{"chart without device", widget("metric_chart", 0, 0, 2, 2, map[string]any{"metric": "cpu"}), "invalid_widget"},
		{"traffic without port", widget("metric_chart", 0, 0, 2, 2, map[string]any{"device_id": 1, "metric": "traffic"}), "invalid_widget"},
		{"port without traffic", widget("metric_chart", 0, 0, 2, 2, map[string]any{"device_id": 1, "metric": "cpu", "if_index": 1}), "invalid_widget"},
		{"chart range", widget("metric_chart", 0, 0, 2, 2, map[string]any{"device_id": 1, "metric": "cpu", "range": "2h"}), "invalid_widget"},
		{"map view", widget("mini_map", 0, 0, 2, 2, map[string]any{"view_id": 0}), "invalid_widget"},
		{"past the right edge", widget("device_status", 11, 0, 2, 2, map[string]any{}), "bad_request"},
		{"too tall", widget("device_status", 0, 0, 2, 49, map[string]any{}), "bad_request"},
		{"too far down", widget("device_status", 0, 1001, 2, 2, map[string]any{}), "bad_request"},
		{"zero width", widget("device_status", 0, 0, 0, 2, map[string]any{}), "bad_request"},
	}
	for _, c := range bad {
		wantError(t, putWidgets(f, s, dash, c.w), http.StatusBadRequest, c.code)
	}
	/* Raw, since json.Marshal would compact the padding away. */
	padded := `{"widgets":[{"type":"device_status","x":0,"y":0,"w":2,"h":2,"config":{"title":"a"` + strings.Repeat(" ", 2100) + `}}]}`
	wantError(t, f.do(s.authed(req{method: "PUT", path: fmt.Sprintf("/api/dashboards/%d/widgets", dash), raw: []byte(padded)})), http.StatusBadRequest, "invalid_widget")
	unknown := widget("device_status", 0, 0, 2, 2, map[string]any{})
	unknown["color"] = "red"
	wantError(t, putWidgets(f, s, dash, unknown), http.StatusBadRequest, "bad_request")
	many := make([]map[string]any, 51)
	for i := range many {
		many[i] = widget("device_status", 0, i, 2, 1, map[string]any{})
	}
	wantError(t, putWidgets(f, s, dash, many...), http.StatusBadRequest, "bad_request")

	good := []map[string]any{
		widget("device_status", 0, 0, 3, 2, map[string]any{"title": ""}),
		widget("problems", 3, 0, 3, 4, map[string]any{"limit": 5, "title": "Проблемы", "severity_min": "high"}),
		widget("top_devices", 6, 0, 3, 4, map[string]any{"metric": "uptime", "limit": nil}),
		widget("log_stream", 9, 0, 3, 4, map[string]any{"kind": "syslog", "limit": 100}),
		widget("metric_chart", 0, 4, 6, 4, map[string]any{"device_id": 7, "metric": "traffic", "if_index": 3, "range": "7d"}),
		widget("top_interfaces", 6, 4, 3, 4, map[string]any{}),
		widget("recent_changes", 9, 4, 3, 4, map[string]any{"limit": 20}),
		widget("mini_map", 0, 8, 12, 6, map[string]any{"view_id": nil}),
	}
	resp := putWidgets(f, s, dash, good...)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put widgets: %d %s", resp.StatusCode, body(t, resp))
	}
	got := decode[dashboardJSON](t, resp)
	want := map[string]string{
		"device_status":  `{}`,
		"problems":       `{"title":"Проблемы","severity_min":"high","limit":5}`,
		"top_devices":    `{"metric":"uptime"}`,
		"log_stream":     `{"kind":"syslog","limit":100}`,
		"metric_chart":   `{"device_id":7,"metric":"traffic","if_index":3,"range":"7d"}`,
		"top_interfaces": `{}`,
		"recent_changes": `{"limit":20}`,
		"mini_map":       `{}`,
	}
	if len(got.Widgets) != len(good) {
		t.Fatalf("widgets = %d, want %d", len(got.Widgets), len(good))
	}
	for _, w := range got.Widgets {
		if !sameJSON(w.Config, want[w.Type]) {
			t.Errorf("%s config stored as %s, want %s", w.Type, w.Config, want[w.Type])
		}
	}
	wantAudit(t, f, "dashboard.widgets.put")
}

/* TestDashboardLayoutRoundTrip: a saved layout comes back as saved; ids stay, left-out widgets go, foreign ids are refused. */
func TestDashboardLayoutRoundTrip(t *testing.T) {
	f := newFixture(t, nil)
	s := f.login(false, rbac.Binding{Role: rbac.RoleViewer})
	resp := f.do(s.authed(req{method: "POST", path: "/api/dashboards", body: map[string]any{"name": "Мой"}}))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d %s", resp.StatusCode, body(t, resp))
	}
	dash := decode[idResp](t, resp).ID
	first := decode[dashboardJSON](t, putWidgets(f, s, dash,
		widget("device_status", 0, 0, 4, 2, map[string]any{}),
		widget("problems", 4, 0, 8, 5, map[string]any{"limit": 10}),
		widget("recent_changes", 0, 2, 4, 3, map[string]any{})))
	if len(first.Widgets) != 3 {
		t.Fatalf("first save: %+v", first)
	}
	ids := map[string]int64{}
	for _, w := range first.Widgets {
		ids[w.Type] = w.ID
	}
	/* Move and resize two, drop the third, add one. */
	moved := widget("device_status", 8, 3, 4, 3, map[string]any{})
	moved["id"] = ids["device_status"]
	kept := widget("problems", 0, 0, 8, 6, map[string]any{"limit": 20})
	kept["id"] = ids["problems"]
	wantStatus(t, putWidgets(f, s, dash, moved, kept, widget("mini_map", 0, 6, 12, 6, map[string]any{})), http.StatusOK)

	got := decode[dashboardJSON](t, f.do(s.authed(req{method: "GET", path: fmt.Sprintf("/api/dashboards/%d", dash)})))
	if got.Name != "Мой" || got.Shared || !got.Editable || len(got.Widgets) != 3 {
		t.Fatalf("restored %+v", got)
	}
	byType := map[string]int{}
	for i, w := range got.Widgets {
		byType[w.Type] = i
	}
	if w := got.Widgets[byType["device_status"]]; w.ID != ids["device_status"] || w.X != 8 || w.Y != 3 || w.W != 4 || w.H != 3 {
		t.Errorf("moved widget restored as %+v", w)
	}
	if w := got.Widgets[byType["problems"]]; w.ID != ids["problems"] || w.W != 8 || w.H != 6 || !sameJSON(w.Config, `{"limit":20}`) {
		t.Errorf("resized widget restored as %+v (%s)", w, w.Config)
	}
	if _, ok := byType["recent_changes"]; ok {
		t.Error("left-out widget kept")
	}
	if _, ok := byType["mini_map"]; !ok {
		t.Error("added widget missing")
	}

	/* A widget id of another dashboard and a repeated id are refused; nothing changes. */
	other := f.newDashboard(&s.uid)
	foreign := decode[dashboardJSON](t, putWidgets(f, s, other, widget("device_status", 0, 0, 2, 2, map[string]any{}))).Widgets[0].ID
	stolen := widget("device_status", 0, 0, 2, 2, map[string]any{})
	stolen["id"] = foreign
	wantError(t, putWidgets(f, s, dash, stolen), http.StatusBadRequest, "bad_request")
	wantError(t, putWidgets(f, s, dash, moved, moved), http.StatusBadRequest, "bad_request")
	if n := len(decode[dashboardJSON](t, f.do(s.authed(req{method: "GET", path: fmt.Sprintf("/api/dashboards/%d", other)}))).Widgets); n != 1 {
		t.Errorf("other dashboard has %d widgets", n)
	}

	/* An empty set clears the dashboard. */
	wantStatus(t, putWidgets(f, s, dash), http.StatusOK)
	if n := len(decode[dashboardJSON](t, f.do(s.authed(req{method: "GET", path: fmt.Sprintf("/api/dashboards/%d", dash)}))).Widgets); n != 0 {
		t.Errorf("cleared dashboard has %d widgets", n)
	}
	wantAudit(t, f, "dashboard.create")
}

/* TestPersonalDashboardsPrivate: another user, an admin included, neither lists nor reaches a personal dashboard. */
func TestPersonalDashboardsPrivate(t *testing.T) {
	f := newFixture(t, nil)
	owner := f.login(false, rbac.Binding{Role: rbac.RoleViewer})
	dash := f.newDashboard(&owner.uid)
	wantStatus(t, putWidgets(f, owner, dash, widget("device_status", 0, 0, 2, 2, map[string]any{})), http.StatusOK)
	for _, other := range []*subject{f.login(false, rbac.Binding{Role: rbac.RoleViewer}), f.login(true, rbac.Binding{Role: rbac.RoleAdmin})} {
		for _, d := range decode[[]dashboardJSON](t, f.do(other.authed(req{method: "GET", path: "/api/dashboards"}))) {
			if d.ID == dash {
				t.Error("foreign personal dashboard listed")
			}
		}
		p := fmt.Sprintf("/api/dashboards/%d", dash)
		wantError(t, f.do(other.authed(req{method: "GET", path: p})), http.StatusNotFound, "not_found")
		wantError(t, f.do(other.authed(req{method: "PATCH", path: p, body: map[string]any{"name": "x"}})), http.StatusNotFound, "not_found")
		wantError(t, f.do(other.authed(req{method: "DELETE", path: p})), http.StatusNotFound, "not_found")
		wantError(t, putWidgets(f, other, dash), http.StatusNotFound, "not_found")
	}
	got := decode[dashboardJSON](t, f.do(owner.authed(req{method: "GET", path: fmt.Sprintf("/api/dashboards/%d", dash)})))
	if len(got.Widgets) != 1 {
		t.Errorf("owner's dashboard changed: %+v", got)
	}
	/* A personal dashboard cannot be a role default. */
	wantError(t, f.do(owner.authed(req{method: "PATCH", path: fmt.Sprintf("/api/dashboards/%d", dash), body: map[string]any{"default_for_role": "viewer"}})),
		http.StatusBadRequest, "bad_request")
	wantError(t, f.do(owner.authed(req{method: "POST", path: "/api/dashboards", body: map[string]any{"name": "x", "default_for_role": "viewer"}})),
		http.StatusBadRequest, "bad_request")
	wantStatus(t, f.do(owner.authed(req{method: "DELETE", path: fmt.Sprintf("/api/dashboards/%d", dash)})), http.StatusNoContent)
	wantAudit(t, f, "dashboard.delete")
}

/* TestSharedDashboardsNeedManage: only dashboards.manage (a global admin) creates or changes shared dashboards and role defaults. */
func TestSharedDashboardsNeedManage(t *testing.T) {
	f := newFixture(t, nil)
	f.clearSharedDashboards(0)
	g := f.newGroup()
	admin := f.login(true, rbac.Binding{Role: rbac.RoleAdmin})
	others := []*subject{
		f.login(true, rbac.Binding{Role: rbac.RoleViewer}),
		f.login(true, rbac.Binding{Role: rbac.RoleOperator}),
		f.login(true, rbac.Binding{Role: rbac.RoleAdmin, GroupID: &g}),
	}
	dash := f.newDashboard(nil)
	for _, s := range others {
		p := fmt.Sprintf("/api/dashboards/%d", dash)
		wantError(t, f.do(s.authed(req{method: "POST", path: "/api/dashboards", body: map[string]any{"name": "x", "shared": true}})), http.StatusForbidden, "forbidden")
		wantError(t, f.do(s.authed(req{method: "PATCH", path: p, body: map[string]any{"name": "x"}})), http.StatusForbidden, "forbidden")
		wantError(t, f.do(s.authed(req{method: "DELETE", path: p})), http.StatusForbidden, "forbidden")
		wantError(t, putWidgets(f, s, dash), http.StatusForbidden, "forbidden")
		got := decode[dashboardJSON](t, f.do(s.authed(req{method: "GET", path: p})))
		if !got.Shared || got.Editable {
			t.Errorf("shared dashboard for a non-manager: %+v", got)
		}
	}

	/* The admin makes two shared dashboards the viewer default in turn: the second takes the role over. */
	create := func(name string) int64 {
		resp := f.do(admin.authed(req{method: "POST", path: "/api/dashboards", body: map[string]any{"name": name, "shared": true, "default_for_role": "viewer"}}))
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create shared: %d %s", resp.StatusCode, body(t, resp))
		}
		return decode[idResp](t, resp).ID
	}
	d1 := create("Общий 1")
	d2 := create("Общий 2")
	defaults := func(s *subject) map[int64]*string {
		out := map[int64]*string{}
		for _, d := range decode[[]dashboardJSON](t, f.do(s.authed(req{method: "GET", path: "/api/dashboards"}))) {
			out[d.ID] = d.DefaultForRole
		}
		return out
	}
	if d := defaults(others[0]); d[d1] != nil || d[d2] == nil || *d[d2] != "viewer" {
		t.Errorf("defaults after second create: d1=%v d2=%v", d[d1], d[d2])
	}
	wantStatus(t, f.do(admin.authed(req{method: "PATCH", path: fmt.Sprintf("/api/dashboards/%d", d1), body: map[string]any{"default_for_role": "viewer"}})), http.StatusNoContent)
	if d := defaults(admin); d[d1] == nil || *d[d1] != "viewer" || d[d2] != nil {
		t.Errorf("defaults after patch: d1=%v d2=%v", d[d1], d[d2])
	}
	wantStatus(t, f.do(admin.authed(req{method: "PATCH", path: fmt.Sprintf("/api/dashboards/%d", d1), body: map[string]any{"default_for_role": nil}})), http.StatusNoContent)
	if d := defaults(admin); d[d1] != nil {
		t.Errorf("default not cleared: %v", *d[d1])
	}
	wantError(t, f.do(admin.authed(req{method: "PATCH", path: fmt.Sprintf("/api/dashboards/%d", d1), body: map[string]any{"default_for_role": "root"}})), http.StatusBadRequest, "bad_request")
	wantStatus(t, putWidgets(f, admin, d1, widget("device_status", 0, 0, 2, 2, map[string]any{})), http.StatusOK)
	wantStatus(t, f.do(admin.authed(req{method: "DELETE", path: fmt.Sprintf("/api/dashboards/%d", d2)})), http.StatusNoContent)
	wantAudit(t, f, "dashboard.update")
	f.clearSharedDashboards(0)
}

/* TestWidgetDataScope: the widget aggregates of a group-A user hold group-A devices only (Review Focus 5). */
func TestWidgetDataScope(t *testing.T) {
	f := newFixture(t, nil)
	a, b := f.newGroup(), f.newGroup()
	devA, devB := f.newDevice(a), f.newDevice(b)
	now := time.Now()
	for _, d := range []struct {
		id  int64
		cpu float64
	}{{devA, 10}, {devB, 90}} {
		f.setState(d.id, "up")
		f.exec(`INSERT INTO metrics.sys_metrics (device_id, ts, cpu_pct, mem_used_pct) VALUES ($1, $2, $3, $3)`, d.id, now.Add(-time.Minute), d.cpu)
		f.exec(`INSERT INTO metrics.if_metrics (device_id, if_index, ts, in_bps, out_bps, oper_up, speed_bps) VALUES ($1, 1, $2, $3, 0, true, 1000)`, d.id, now.Add(-time.Minute), d.cpu*10)
		f.newIface(d.id, 1, fmt.Sprintf("ge-%d", d.id), "", 1000)
		f.newVersion(d.id, "hostname x\n", "event", true, now.Add(-time.Minute))
	}
	viewerA := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &a})
	get := func(s *subject, p string) string {
		resp := f.do(s.authed(req{method: "GET", path: p}))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d", p, resp.StatusCode)
		}
		return body(t, resp)
	}
	type items struct {
		Items []struct {
			DeviceID int64   `json:"device_id"`
			PortName string  `json:"port_name"`
			UtilPct  float64 `json:"util_pct"`
			Value    float64 `json:"value"`
		} `json:"items"`
	}
	onlyA := func(p string) items {
		var it items
		if err := json.Unmarshal([]byte(get(viewerA, p)), &it); err != nil {
			t.Fatal(err)
		}
		if len(it.Items) != 1 || it.Items[0].DeviceID != devA {
			t.Errorf("%s as viewerA: %+v, want device %d only", p, it.Items, devA)
		}
		return it
	}
	var counts struct{ Total, Up int }
	if err := json.Unmarshal([]byte(get(viewerA, "/api/stats/device-states")), &counts); err != nil {
		t.Fatal(err)
	}
	if counts.Total != 1 || counts.Up != 1 {
		t.Errorf("device states as viewerA: %+v", counts)
	}
	if it := onlyA("/api/stats/top-devices?metric=cpu"); len(it.Items) == 1 && it.Items[0].Value != 10 {
		t.Errorf("cpu value %v", it.Items[0].Value)
	}
	onlyA("/api/stats/top-devices?metric=mem")
	if it := onlyA("/api/stats/top-devices?metric=uptime"); len(it.Items) == 1 && (it.Items[0].Value < 3000 || it.Items[0].Value > 4000) {
		t.Errorf("uptime %v s, want about an hour", it.Items[0].Value)
	}
	if it := onlyA("/api/stats/top-interfaces"); len(it.Items) == 1 && (it.Items[0].PortName != fmt.Sprintf("ge-%d", devA) || it.Items[0].UtilPct != 10) {
		t.Errorf("top interface %+v", it.Items[0])
	}
	onlyA("/api/stats/config-drift")

	/* A user bound to a third group sees nothing. */
	empty := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: ptr(f.newGroup())})
	for _, p := range []string{"/api/stats/top-devices?metric=cpu", "/api/stats/top-interfaces", "/api/stats/config-drift"} {
		if b := get(empty, p); b != "{\"items\":[]}\n" {
			t.Errorf("%s for an empty scope: %s", p, b)
		}
	}
	for _, p := range []string{"/api/stats/top-devices", "/api/stats/top-devices?metric=disk", "/api/stats/top-interfaces?limit=51", "/api/stats/config-drift?limit=0"} {
		wantError(t, f.do(viewerA.authed(req{method: "GET", path: p})), http.StatusBadRequest, "bad_request")
	}
}
