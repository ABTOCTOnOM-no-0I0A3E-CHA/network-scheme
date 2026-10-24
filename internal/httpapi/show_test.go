package httpapi_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/rbac"
)

/* showDevice creates a device of the MES driver in group g with the given interface names in its inventory. */
func (f *fixture) showDevice(g int64, ifaces ...string) int64 {
	f.t.Helper()
	id := f.newDevice(g)
	pg := f.env.Pool("postgres")
	if _, err := pg.Exec(context.Background(), `UPDATE core.device SET driver = 'eltex-mes' WHERE id = $1`, id); err != nil {
		f.t.Fatal(err)
	}
	for i, n := range ifaces {
		if _, err := pg.Exec(context.Background(), `INSERT INTO inventory.interface (device_id, if_index, name, alias, speed_bps, oper_up, seen_at)
			VALUES ($1, $2, $3, '', 1000000000, true, now())`, id, i+1, n); err != nil {
			f.t.Fatal(err)
		}
	}
	return id
}

/* newShowResult inserts a result row the way the api does, owned by user uid. */
func (f *fixture) newShowResult(dev, uid int64) int64 {
	f.t.Helper()
	var id int64
	if err := f.env.Pool("nms_api").QueryRow(context.Background(),
		`INSERT INTO backups.show_result (device_id, user_id, command_key, args) VALUES ($1, $2, 'version', '{}') RETURNING id`, dev, uid).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fixture) showRows(dev int64) int {
	f.t.Helper()
	var n int
	if err := f.env.Pool("postgres").QueryRow(context.Background(), `SELECT count(*) FROM backups.show_result WHERE device_id = $1`, dev).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

type idBody struct {
	ID int64 `json:"id"`
}

/* showRequest builds valid requests for the show routes with targets in m.target. */
func (m *matrixEnv) showRequest(key string, s *subject) (req, bool) {
	if !strings.Contains(key, "show") {
		return req{}, false
	}
	dev := m.showDevice(m.target, "gi1/0/1")
	switch key {
	case "GET /api/devices/{id}/show-commands":
		return req{method: "GET", path: fmt.Sprintf("/api/devices/%d/show-commands", dev)}, true
	case "POST /api/devices/{id}/show":
		return req{method: "POST", path: fmt.Sprintf("/api/devices/%d/show", dev), body: map[string]any{"key": "interface_status", "args": map[string]any{"interface": "gi1/0/1"}}}, true
	case "GET /api/show/{id}":
		author := m.subjects["operator"].uid
		if s != nil {
			author = s.uid
		}
		return req{method: "GET", path: fmt.Sprintf("/api/show/%d", m.newShowResult(dev, author))}, true
	}
	return req{}, false
}

type showCommandsBody struct {
	Commands []struct {
		Key  string   `json:"key"`
		Args []string `json:"args"`
	} `json:"commands"`
}

func TestShowCommandsFollowTheDriver(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	op := f.login(false, rbac.Binding{Role: rbac.RoleOperator, GroupID: &g})
	mes := decode[showCommandsBody](t, f.do(op.authed(req{method: "GET", path: fmt.Sprintf("/api/devices/%d/show-commands", f.showDevice(g))})))
	got := map[string][]string{}
	for _, c := range mes.Commands {
		got[c.Key] = c.Args
	}
	if len(got["vlan_tag"]) != 1 || got["vlan_tag"][0] != "vlan" || len(got["interface_status"]) != 1 || got["interface_status"][0] != "interface" || got["version"] == nil || len(got["version"]) != 0 {
		t.Errorf("commands = %v", got)
	}
	for k := range got {
		if strings.Contains(k, "config") {
			t.Errorf("config command offered: %s", k)
		}
	}
	/* A device whose driver is not known yet offers nothing, and nothing can be run on it. */
	auto := f.newDevice(g)
	if r := decode[showCommandsBody](t, f.do(op.authed(req{method: "GET", path: fmt.Sprintf("/api/devices/%d/show-commands", auto)}))); r.Commands == nil || len(r.Commands) != 0 {
		t.Errorf("auto driver commands = %v", r.Commands)
	}
	wantError(t, f.do(op.authed(req{method: "POST", path: fmt.Sprintf("/api/devices/%d/show", auto), body: map[string]any{"key": "version", "args": map[string]any{}}})), http.StatusBadRequest, "invalid_show")
}

/* Review Focus 4: nothing but a driver key with typed arguments from this device's inventory is queued. */
func TestShowRejectsInjection(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	op := f.login(false, rbac.Binding{Role: rbac.RoleOperator, GroupID: &g})
	dev := f.showDevice(g, "gi1/0/1", "gi1/0/2")
	other := f.showDevice(g, "gi1/0/9")
	path := fmt.Sprintf("/api/devices/%d/show", dev)
	ifc := func(v any) map[string]any { return map[string]any{"interface": v} }
	vl := func(v any) map[string]any { return map[string]any{"vlan": v} }
	cases := []struct {
		name string
		body any
		raw  string
		want string /* error code; empty: invalid_show */
	}{
		{name: "pipe", body: map[string]any{"key": "interface_status", "args": ifc("gi1/0/1 | include x")}},
		{name: "newline", body: map[string]any{"key": "interface_status", "args": ifc("gi1/0/1\nshow running-config")}},
		{name: "crlf", body: map[string]any{"key": "interface_status", "args": ifc("gi1/0/1\r\nreload")}},
		{name: "semicolon", body: map[string]any{"key": "interface_counters", "args": ifc("gi1/0/1;reload")}},
		{name: "cyrillic i", body: map[string]any{"key": "interface_status", "args": ifc("gі1/0/1")}},
		{name: "fullwidth slash", body: map[string]any{"key": "interface_status", "args": ifc("gi1／0／1")}},
		{name: "zero width", body: map[string]any{"key": "interface_status", "args": ifc("gi1/0/1\u200b")}},
		{name: "case differs", body: map[string]any{"key": "interface_status", "args": ifc("GI1/0/1")}},
		{name: "not in inventory", body: map[string]any{"key": "interface_status", "args": ifc("gi1/0/3")}},
		{name: "other device's interface", body: map[string]any{"key": "interface_status", "args": ifc("gi1/0/9")}},
		{name: "empty interface", body: map[string]any{"key": "interface_status", "args": ifc("")}},
		{name: "interface number", body: map[string]any{"key": "interface_status", "args": ifc(1)}},
		{name: "interface array", body: map[string]any{"key": "interface_status", "args": ifc([]string{"gi1/0/1"})}},
		{name: "vlan 0", body: map[string]any{"key": "vlan_tag", "args": vl(0)}},
		{name: "vlan 4095", body: map[string]any{"key": "vlan_tag", "args": vl(4095)}},
		{name: "vlan negative", body: map[string]any{"key": "vlan_tag", "args": vl(-5)}},
		{name: "vlan fraction", body: map[string]any{"key": "vlan_tag", "args": vl(1.5)}},
		{name: "vlan string", body: map[string]any{"key": "vlan_tag", "args": vl("10")}},
		{name: "vlan string injection", body: map[string]any{"key": "vlan_tag", "args": vl("10 | include x")}},
		{name: "vlan null", body: map[string]any{"key": "vlan_tag", "args": vl(nil)}},
		{name: "extra arg", body: map[string]any{"key": "vlan_tag", "args": map[string]any{"vlan": 10, "interface": "gi1/0/1"}}},
		{name: "arg for bare command", body: map[string]any{"key": "version", "args": ifc("gi1/0/1")}},
		{name: "missing args", body: map[string]any{"key": "interface_status"}},
		{name: "args array", body: map[string]any{"key": "version", "args": []any{}}},
		{name: "args string", body: map[string]any{"key": "version", "args": "x"}},
		{name: "args null", body: map[string]any{"key": "version", "args": nil}},
		{name: "unknown key", body: map[string]any{"key": "reload", "args": map[string]any{}}},
		{name: "config key", body: map[string]any{"key": "running_config", "args": map[string]any{}}},
		{name: "config command text", body: map[string]any{"key": "show running-config", "args": map[string]any{}}},
		{name: "key with a pipe", body: map[string]any{"key": "version | include x", "args": map[string]any{}}},
		{name: "empty key", body: map[string]any{"key": "", "args": map[string]any{}}},
		{name: "long key", body: map[string]any{"key": strings.Repeat("a", 5000), "args": map[string]any{}}},
		{name: "key number", raw: `{"key":1,"args":{}}`, want: "bad_request"},
		{name: "key array", raw: `{"key":["version"],"args":{}}`, want: "bad_request"},
		{name: "extra field", raw: `{"key":"version","args":{},"command":"show running-config"}`, want: "bad_request"},
		{name: "user id", raw: `{"key":"version","args":{},"user_id":1}`, want: "bad_request"},
		{name: "device id", raw: fmt.Sprintf(`{"key":"version","args":{},"device_id":%d}`, other), want: "bad_request"},
		{name: "not json", raw: `key=version`, want: "bad_request"},
		{name: "trailing data", raw: `{"key":"version","args":{}} {}`, want: "bad_request"},
		{name: "empty object", raw: `{}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f.clk.Advance(61 * time.Second) /* every attempt counts against the per-minute limit */
			r := req{method: "POST", path: path, body: c.body}
			if c.raw != "" {
				r.raw = []byte(c.raw)
			}
			want := c.want
			if want == "" {
				want = "invalid_show"
			}
			wantError(t, f.do(op.authed(r)), http.StatusBadRequest, want)
		})
	}
	if n := f.showRows(dev) + f.showRows(other); n != 0 || len(f.jobs.shows) != 0 {
		t.Fatalf("rows %d, jobs %v after the rejected requests", n, f.jobs.shows)
	}
	/* Refusals of well-formed requests are audited as failures. */
	var n int
	if err := f.env.Pool("postgres").QueryRow(context.Background(),
		`SELECT count(*) FROM audit.event WHERE action = 'devices.show' AND convert_from(payload, 'UTF8')::jsonb->>'result' = 'failure'`).Scan(&n); err != nil || n == 0 {
		t.Errorf("failure audit records = %d, %v", n, err)
	}
	f.clk.Advance(61 * time.Second)
	/* The same request with good values passes. */
	ok := f.do(op.authed(req{method: "POST", path: path, body: map[string]any{"key": "interface_status", "args": ifc("gi1/0/1")}}))
	if ok.StatusCode != http.StatusAccepted {
		t.Fatalf("valid request: %d", ok.StatusCode)
	}
}

func TestShowQueuesRowAndJobAndAudits(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	op := f.login(false, rbac.Binding{Role: rbac.RoleOperator, GroupID: &g})
	dev := f.showDevice(g, "gi1/0/1")
	resp := f.do(op.authed(req{method: "POST", path: fmt.Sprintf("/api/devices/%d/show", dev), body: map[string]any{"key": "mac_table_vlan", "args": map[string]any{"vlan": 4094}}}))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status %d %s", resp.StatusCode, f.logs.String())
	}
	id := decode[idBody](t, resp).ID
	var uid int64
	var key, args, status string
	if err := f.env.Pool("postgres").QueryRow(context.Background(),
		`SELECT user_id, command_key, args::text, status FROM backups.show_result WHERE id = $1`, id).Scan(&uid, &key, &args, &status); err != nil {
		t.Fatal(err)
	}
	if uid != op.uid || key != "mac_table_vlan" || args != `{"vlan": 4094}` || status != "queued" {
		t.Errorf("row = %d %s %s %s", uid, key, args, status)
	}
	if len(f.jobs.shows) != 1 || f.jobs.shows[0] != [2]int64{dev, id} {
		t.Errorf("jobs = %v", f.jobs.shows)
	}
	wantAudit(t, f, "devices.show")
	var details string
	if err := f.env.Pool("postgres").QueryRow(context.Background(),
		`SELECT (convert_from(payload, 'UTF8')::jsonb->'details')::text FROM audit.event WHERE action = 'devices.show' ORDER BY id DESC LIMIT 1`).Scan(&details); err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"mac_table_vlan", "4094", fmt.Sprint(id)} {
		if !strings.Contains(details, w) {
			t.Errorf("audit details %s lack %s", details, w)
		}
	}
	/* A failed enqueue leaves no row behind. */
	f.jobs.fail = true
	dev2 := f.showDevice(g)
	wantError(t, f.do(op.authed(req{method: "POST", path: fmt.Sprintf("/api/devices/%d/show", dev2), body: map[string]any{"key": "version", "args": map[string]any{}}})), http.StatusInternalServerError, "internal")
	if n := f.showRows(dev2); n != 0 {
		t.Errorf("%d rows after a failed enqueue", n)
	}
}

func TestShowOneAtATimePerDevice(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	op := f.login(false, rbac.Binding{Role: rbac.RoleOperator, GroupID: &g})
	dev := f.showDevice(g)
	post := func(d int64) *http.Response {
		return f.do(op.authed(req{method: "POST", path: fmt.Sprintf("/api/devices/%d/show", d), body: map[string]any{"key": "version", "args": map[string]any{}}}))
	}
	first := decode[idBody](t, post(dev)).ID
	wantError(t, post(dev), http.StatusConflict, "device_busy")
	pg := f.env.Pool("postgres")
	/* Still busy while running; free once finished. */
	if _, err := pg.Exec(context.Background(), `UPDATE backups.show_result SET status = 'running' WHERE id = $1`, first); err != nil {
		t.Fatal(err)
	}
	wantError(t, post(dev), http.StatusConflict, "device_busy")
	if _, err := pg.Exec(context.Background(), `UPDATE backups.show_result SET status = 'done', finished_at = now() WHERE id = $1`, first); err != nil {
		t.Fatal(err)
	}
	second := decode[idBody](t, post(dev)).ID
	wantError(t, post(dev), http.StatusConflict, "device_busy")
	/* A row stuck in "queued" (poller down) stops blocking after the busy window. */
	if _, err := pg.Exec(context.Background(), `UPDATE backups.show_result SET requested_at = now() - interval '4 minutes' WHERE id = $1`, second); err != nil {
		t.Fatal(err)
	}
	if r := post(dev); r.StatusCode != http.StatusAccepted {
		t.Fatalf("after the window: %d", r.StatusCode)
	}
	/* Other devices are not affected. */
	if r := post(f.showDevice(g)); r.StatusCode != http.StatusAccepted {
		t.Fatalf("other device: %d", r.StatusCode)
	}
}

func TestShowRateLimitPerUser(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	op := f.login(false, rbac.Binding{Role: rbac.RoleOperator, GroupID: &g})
	other := f.login(false, rbac.Binding{Role: rbac.RoleOperator, GroupID: &g})
	body := map[string]any{"key": "version", "args": map[string]any{}}
	post := func(s *subject) *http.Response {
		return f.do(s.authed(req{method: "POST", path: fmt.Sprintf("/api/devices/%d/show", f.showDevice(g)), body: body}))
	}
	for i := range 10 {
		if r := post(op); r.StatusCode != http.StatusAccepted {
			t.Fatalf("request %d: %d", i+1, r.StatusCode)
		}
	}
	wantError(t, post(op), http.StatusTooManyRequests, "rate_limited")
	if r := post(other); r.StatusCode != http.StatusAccepted {
		t.Fatalf("other user: %d", r.StatusCode)
	}
	f.clk.Advance(61 * time.Second)
	if r := post(op); r.StatusCode != http.StatusAccepted {
		t.Fatalf("after a minute: %d", r.StatusCode)
	}
}

func TestShowResultVisibility(t *testing.T) {
	f := newFixture(t, nil)
	g, gB := f.newGroup(), f.newGroup()
	author := f.login(false, rbac.Binding{Role: rbac.RoleOperator, GroupID: &g})
	peer := f.login(false, rbac.Binding{Role: rbac.RoleOperator, GroupID: &g})
	adminA := f.login(false, rbac.Binding{Role: rbac.RoleAdmin, GroupID: &g})
	global := f.login(false, rbac.Binding{Role: rbac.RoleAdmin})
	viewer := f.login(false, rbac.Binding{Role: rbac.RoleViewer})
	outsider := f.login(false, rbac.Binding{Role: rbac.RoleOperator, GroupID: &gB})
	dev := f.showDevice(g, "gi1/0/1")
	id := decode[idBody](t, f.do(author.authed(req{method: "POST", path: fmt.Sprintf("/api/devices/%d/show", dev), body: map[string]any{"key": "version", "args": map[string]any{}}}))).ID
	path := fmt.Sprintf("/api/show/%d", id)
	type result struct {
		ID        int64   `json:"id"`
		DeviceID  int64   `json:"device_id"`
		Key       string  `json:"key"`
		Status    string  `json:"status"`
		Output    *string `json:"output"`
		Truncated bool    `json:"truncated"`
		Finished  *string `json:"finished_at"`
	}
	r := decode[result](t, f.do(author.authed(req{method: "GET", path: path})))
	if r.ID != id || r.DeviceID != dev || r.Key != "version" || r.Status != "queued" || r.Output != nil || r.Finished != nil {
		t.Fatalf("queued result = %+v", r)
	}
	/* The poller finishes the row. */
	if _, err := f.env.Pool("postgres").Exec(context.Background(),
		`UPDATE backups.show_result SET status = 'done', output = $2, truncated = true, finished_at = now() WHERE id = $1`, id, "<script>alert(1)</script>\nline 2"); err != nil {
		t.Fatal(err)
	}
	resp := f.do(author.authed(req{method: "GET", path: path}))
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") || resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("headers: %q %q", ct, resp.Header.Get("Cache-Control"))
	}
	r = decode[result](t, resp)
	if r.Status != "done" || r.Output == nil || *r.Output != "<script>alert(1)</script>\nline 2" || !r.Truncated || r.Finished == nil {
		t.Fatalf("done result = %+v", r)
	}
	if got := f.do(global.authed(req{method: "GET", path: path})).StatusCode; got != http.StatusOK {
		t.Errorf("global admin: %d", got)
	}
	/* Only the author or a global admin: a peer operator and a group admin of the same group do not see it. */
	for _, s := range []*subject{peer, adminA, outsider} {
		wantError(t, f.do(s.authed(req{method: "GET", path: path})), http.StatusNotFound, "not_found")
	}
	wantError(t, f.do(viewer.authed(req{method: "GET", path: path})), http.StatusForbidden, "forbidden")
	for _, p := range []string{"/api/show/0", "/api/show/-1", "/api/show/abc", "/api/show/99999999"} {
		wantError(t, f.do(author.authed(req{method: "GET", path: p})), http.StatusNotFound, "not_found")
	}
	/* The device moved out of the author's scope: the author no longer reads it, the global admin still does. */
	if _, err := f.env.Pool("postgres").Exec(context.Background(), `UPDATE core.device SET group_id = $2 WHERE id = $1`, dev, gB); err != nil {
		t.Fatal(err)
	}
	wantError(t, f.do(author.authed(req{method: "GET", path: path})), http.StatusNotFound, "not_found")
	if got := f.do(global.authed(req{method: "GET", path: path})).StatusCode; got != http.StatusOK {
		t.Errorf("global admin after the move: %d", got)
	}
	/* Expired rows are gone for everybody. */
	if _, err := f.env.Pool("postgres").Exec(context.Background(), `UPDATE backups.show_result SET expires_at = now() - interval '1 second' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	wantError(t, f.do(global.authed(req{method: "GET", path: path})), http.StatusNotFound, "not_found")
}

func TestShowScopeIsTheDevicesGroup(t *testing.T) {
	f := newFixture(t, nil)
	g, gB := f.newGroup(), f.newGroup()
	op := f.login(false, rbac.Binding{Role: rbac.RoleOperator, GroupID: &g})
	foreign := f.showDevice(gB, "gi1/0/1")
	body := map[string]any{"key": "version", "args": map[string]any{}}
	wantError(t, f.do(op.authed(req{method: "POST", path: fmt.Sprintf("/api/devices/%d/show", foreign), body: body})), http.StatusNotFound, "not_found")
	wantError(t, f.do(op.authed(req{method: "GET", path: fmt.Sprintf("/api/devices/%d/show-commands", foreign)})), http.StatusNotFound, "not_found")
	wantError(t, f.do(op.authed(req{method: "POST", path: "/api/devices/999999/show", body: body})), http.StatusNotFound, "not_found")
	if f.showRows(foreign) != 0 || len(f.jobs.shows) != 0 {
		t.Error("a foreign request queued something")
	}
	viewer := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &g})
	wantError(t, f.do(viewer.authed(req{method: "POST", path: fmt.Sprintf("/api/devices/%d/show", f.showDevice(g)), body: body})), http.StatusForbidden, "forbidden")
}
