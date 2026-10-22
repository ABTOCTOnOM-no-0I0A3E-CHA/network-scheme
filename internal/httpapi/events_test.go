package httpapi_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/inventory"
	"github.com/beekamai/network-scheme/internal/rbac"
)

type eventItem struct {
	TS         string         `json:"ts"`
	Kind       string         `json:"kind"`
	DeviceID   int64          `json:"device_id"`
	DeviceName string         `json:"device_name"`
	Severity   *string        `json:"severity"`
	Name       *string        `json:"name"`
	App        *string        `json:"app"`
	Text       string         `json:"text"`
	Identified bool           `json:"identified"`
	Varbinds   map[string]any `json:"varbinds"`
}

type eventsResp struct {
	Items      []eventItem `json:"items"`
	NextCursor *string     `json:"next_cursor"`
}

func (f *fixture) syslog(dev int64, ts time.Time, sev int, app, msg string) {
	f.t.Helper()
	if _, err := f.env.Pool("postgres").Exec(context.Background(),
		`INSERT INTO events.syslog (ts, device_id, facility, severity, host, app, msg, raw_len) VALUES ($1, $2, 1, $3, 'h', $4, $5, 10)`,
		ts, dev, sev, app, msg); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) trap(dev int64, ts time.Time, oid, name string, sev *string, identified bool) {
	f.t.Helper()
	if _, err := f.env.Pool("postgres").Exec(context.Background(),
		`INSERT INTO events.trap (ts, device_id, version, trap_oid, name, severity, varbinds, identified) VALUES ($1, $2, 2, $3, $4, $5, '{"1.3.6.1":"v"}', $6)`,
		ts, dev, oid, name, sev, identified); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) getEvents(s *subject, q url.Values) *http.Response {
	return f.do(s.authed(req{method: "GET", path: "/api/events?" + q.Encode()}))
}

func TestEventsScopedByDeviceGroup(t *testing.T) {
	f := newFixture(t, nil)
	gA, gB := f.newGroup(), f.newGroup()
	viewerA := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &gA})
	global := f.login(false, rbac.Binding{Role: rbac.RoleViewer})
	devA, devB := f.newDevice(gA), f.newDevice(gB)
	now := time.Now().UTC().Truncate(time.Second)
	f.syslog(devA, now.Add(-time.Minute), 3, "sw", "link flap on A")
	f.syslog(devB, now.Add(-time.Minute), 3, "sw", "link flap on B")
	f.trap(devB, now.Add(-time.Minute), "1.3.6.1.4.1.99.1", "linkDown", ptr("average"), true)
	/* A device that was deleted leaves rows behind: they are not shown. */
	f.syslog(devB+100000, now.Add(-time.Minute), 3, "sw", "ghost")

	got := decode[eventsResp](t, f.getEvents(viewerA, url.Values{}))
	if len(got.Items) != 1 || got.Items[0].DeviceID != devA || got.Items[0].Text != "link flap on A" || got.Items[0].App == nil || *got.Items[0].App != "sw" {
		t.Fatalf("viewer of A = %+v", got.Items)
	}
	if got.Items[0].DeviceName == "" || got.Items[0].Severity == nil || *got.Items[0].Severity != "average" {
		t.Errorf("event = %+v", got.Items[0])
	}
	wantError(t, f.getEvents(viewerA, url.Values{"device_id": {fmt.Sprint(devB)}}), http.StatusNotFound, "not_found")
	wantError(t, f.getEvents(viewerA, url.Values{"device_id": {fmt.Sprint(devB + 100000)}}), http.StatusNotFound, "not_found")

	all := decode[eventsResp](t, f.getEvents(global, url.Values{}))
	var ids []int64
	for _, e := range all.Items {
		ids = append(ids, e.DeviceID)
		if e.Kind == "trap" && (e.Name == nil || *e.Name != "linkDown" || e.Varbinds["1.3.6.1"] != "v" || !e.Identified) {
			t.Errorf("trap = %+v", e)
		}
	}
	for _, id := range ids {
		if id == devB+100000 {
			t.Error("event of a deleted device returned")
		}
	}
	/* kind and severity_min filter */
	tr := decode[eventsResp](t, f.getEvents(global, url.Values{"kind": {"trap"}, "device_id": {fmt.Sprint(devB)}}))
	if len(tr.Items) != 1 || tr.Items[0].Kind != "trap" {
		t.Errorf("kind=trap = %+v", tr.Items)
	}
	hi := decode[eventsResp](t, f.getEvents(global, url.Values{"device_id": {fmt.Sprint(devB)}, "severity_min": {"high"}}))
	if len(hi.Items) != 0 {
		t.Errorf("severity_min=high = %+v", hi.Items)
	}
}

func ptr[T any](v T) *T { return &v }

func TestEventsFullTextSearch(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	viewer := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &g})
	dev := f.newDevice(g)
	now := time.Now().UTC()
	f.syslog(dev, now.Add(-time.Minute), 5, "sw", "Spanning tree topology change on gi1/0/7")
	f.syslog(dev, now.Add(-2*time.Minute), 5, "sw", "user admin logged in")
	f.trap(dev, now.Add(-3*time.Minute), "1.3.6.1.4.1.99.7", "spanningTreeEvent", nil, false)
	got := decode[eventsResp](t, f.getEvents(viewer, url.Values{"q": {"topology"}}))
	if len(got.Items) != 1 || !strings.Contains(got.Items[0].Text, "topology") {
		t.Errorf("q=topology = %+v", got.Items)
	}
	got = decode[eventsResp](t, f.getEvents(viewer, url.Values{"q": {"spanningtreeevent"}}))
	if len(got.Items) != 1 || got.Items[0].Kind != "trap" || got.Items[0].Severity != nil || got.Items[0].Identified {
		t.Errorf("q=trap name = %+v", got.Items)
	}
	if got := decode[eventsResp](t, f.getEvents(viewer, url.Values{"q": {"nonexistentword"}})); len(got.Items) != 0 {
		t.Errorf("no match = %+v", got.Items)
	}
}

func TestEventsCursorStableForEqualTimestamps(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	viewer := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &g})
	d1, d2 := f.newDevice(g), f.newDevice(g)
	ts := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	want := map[string]bool{}
	for i := range 7 {
		dev := d1
		if i%2 == 1 {
			dev = d2
		}
		msg := fmt.Sprintf("same instant %d", i)
		f.syslog(dev, ts, 6, "sw", msg)
		want[fmt.Sprintf("%d|%s", dev, msg)] = true
	}
	f.trap(d1, ts, "1.3.6.1.4.1.99.9", "same", ptr("info"), true)
	want[fmt.Sprintf("%d|%s", d1, "1.3.6.1.4.1.99.9")] = true

	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		q := url.Values{"limit": {"3"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		page := decode[eventsResp](t, f.getEvents(viewer, q))
		pages++
		for _, e := range page.Items {
			k := fmt.Sprintf("%d|%s", e.DeviceID, e.Text)
			if seen[k] {
				t.Errorf("event repeated across pages: %s", k)
			}
			seen[k] = true
		}
		if page.NextCursor == nil {
			break
		}
		cursor = *page.NextCursor
	}
	if pages != 3 || len(seen) != len(want) {
		t.Errorf("pages=%d seen=%d want %d events", pages, len(seen), len(want))
	}
	for k := range want {
		if !seen[k] {
			t.Errorf("event missing: %s", k)
		}
	}
	wantError(t, f.getEvents(viewer, url.Values{"cursor": {"garbage"}}), http.StatusBadRequest, "bad_request")
}

func TestEventsQueryValidation(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	viewer := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &g})
	now := time.Now().UTC()
	rfc := func(t time.Time) string { return t.Format(time.RFC3339) }
	for name, q := range map[string]url.Values{
		"window over 31 days": {"from": {rfc(now.Add(-32 * 24 * time.Hour))}, "to": {rfc(now)}},
		"inverted window":     {"from": {rfc(now)}, "to": {rfc(now.Add(-time.Hour))}},
		"bad from":            {"from": {"yesterday"}},
		"bad kind":            {"kind": {"snmp"}},
		"bad severity":        {"severity_min": {"fatal"}},
		"bad limit":           {"limit": {"501"}},
		"bad device":          {"device_id": {"0"}},
		"long q":              {"q": {strings.Repeat("a", 201)}},
		"repeated kind":       {"kind": {"trap", "syslog"}},
	} {
		t.Run(name, func(t *testing.T) { wantError(t, f.getEvents(viewer, q), http.StatusBadRequest, "bad_request") })
	}
	ok := url.Values{"from": {rfc(now.Add(-31 * 24 * time.Hour))}, "to": {rfc(now)}}
	if resp := f.getEvents(viewer, ok); resp.StatusCode != http.StatusOK {
		t.Errorf("31 day window: status %d", resp.StatusCode)
	}
}

func TestUnidentifiedTrapsGrouped(t *testing.T) {
	f := newFixture(t, nil)
	gA, gB := f.newGroup(), f.newGroup()
	viewerA := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &gA})
	devA, devB := f.newDevice(gA), f.newDevice(gB)
	now := time.Now().UTC()
	oid1, oid2 := f.newOID(), f.newOID()
	f.trap(devA, now.Add(-3*time.Minute), oid1, oid1, nil, false)
	f.trap(devA, now.Add(-2*time.Minute), oid1, oid1, nil, false)
	f.trap(devB, now.Add(-time.Minute), oid1, oid1, nil, false) /* foreign: not counted */
	f.trap(devA, now.Add(-4*time.Minute), oid2, oid2, nil, false)
	f.trap(devA, now.Add(-time.Minute), f.newOID(), "named", ptr("info"), true) /* identified: not listed */

	type group struct {
		TrapOID        string         `json:"trap_oid"`
		Count          int64          `json:"count"`
		LastDeviceID   int64          `json:"last_device_id"`
		LastDeviceName string         `json:"last_device_name"`
		LastVarbinds   map[string]any `json:"last_varbinds"`
	}
	type page struct {
		Items      []group `json:"items"`
		NextCursor *string `json:"next_cursor"`
	}
	get := func(q string) page {
		return decode[page](t, f.do(viewerA.authed(req{method: "GET", path: "/api/events/unidentified" + q})))
	}
	p := get("?limit=1")
	if len(p.Items) != 1 || p.Items[0].TrapOID != oid1 || p.Items[0].Count != 2 || p.Items[0].LastDeviceID != devA ||
		p.Items[0].LastVarbinds["1.3.6.1"] != "v" || p.NextCursor == nil {
		t.Fatalf("first page = %+v", p)
	}
	p = get("?limit=1&cursor=" + url.QueryEscape(*p.NextCursor))
	if len(p.Items) != 1 || p.Items[0].TrapOID != oid2 || p.Items[0].Count != 1 || p.NextCursor != nil {
		t.Errorf("second page = %+v", p)
	}
	wantError(t, f.do(viewerA.authed(req{method: "GET", path: "/api/events/unidentified?cursor=%21"})), http.StatusBadRequest, "bad_request")
}

func TestTrapRules(t *testing.T) {
	f := newFixture(t, nil)
	admin := f.login(false, rbac.Binding{Role: rbac.RoleAdmin})
	viewer := f.login(false, rbac.Binding{Role: rbac.RoleViewer})
	oid := f.newOID()
	body := map[string]string{"trap_oid": oid, "name": "Port flap", "severity": "high"}
	post := func(s *subject, b any) *http.Response {
		return f.do(s.authed(req{method: "POST", path: "/api/trap-rules", body: b}))
	}
	wantError(t, post(viewer, body), http.StatusForbidden, "forbidden")
	wantError(t, f.do(viewer.authed(req{method: "GET", path: "/api/trap-rules"})), http.StatusForbidden, "forbidden")

	resp := post(admin, body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status %d", resp.StatusCode)
	}
	id := decode[struct {
		ID int64 `json:"id"`
	}](t, resp).ID
	wantAudit(t, f, "trap_rules.create")
	var details string
	if err := f.env.Pool("postgres").QueryRow(context.Background(),
		`SELECT convert_from(payload, 'UTF8') FROM audit.event WHERE action = 'trap_rules.create' ORDER BY id DESC LIMIT 1`).Scan(&details); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(details, oid) || !strings.Contains(details, fmt.Sprint(id)) {
		t.Errorf("audit payload = %s", details)
	}
	wantError(t, post(admin, body), http.StatusConflict, "trap_rule_exists")

	list := decode[[]struct {
		ID       int64  `json:"id"`
		TrapOID  string `json:"trap_oid"`
		Severity string `json:"severity"`
	}](t, f.do(admin.authed(req{method: "GET", path: "/api/trap-rules"})))
	found := false
	for _, r := range list {
		found = found || (r.ID == id && r.TrapOID == oid && r.Severity == "high")
	}
	if !found {
		t.Errorf("rule missing from %+v", list)
	}

	for name, b := range map[string]map[string]string{
		"leading dot":    {"trap_oid": "." + oid, "name": "x", "severity": "info"},
		"letters":        {"trap_oid": "1.3.6.a", "name": "x", "severity": "info"},
		"empty sub-id":   {"trap_oid": "1.3..6", "name": "x", "severity": "info"},
		"sub-id too big": {"trap_oid": "1.3.4294967296", "name": "x", "severity": "info"},
		"129 sub-ids":    {"trap_oid": strings.TrimSuffix(strings.Repeat("1.", 129), "."), "name": "x", "severity": "info"},
		"empty name":     {"trap_oid": f.newOID(), "name": "", "severity": "info"},
		"long name":      {"trap_oid": f.newOID(), "name": strings.Repeat("n", 1025), "severity": "info"},
		"control char":   {"trap_oid": f.newOID(), "name": "a\x07b", "severity": "info"},
		"bad severity":   {"trap_oid": f.newOID(), "name": "x", "severity": "critical"},
	} {
		t.Run(name, func(t *testing.T) { wantError(t, post(admin, b), http.StatusBadRequest, "bad_request") })
	}

	del := func(s *subject, id int64) *http.Response {
		return f.do(s.authed(req{method: "DELETE", path: fmt.Sprintf("/api/trap-rules/%d", id)}))
	}
	wantError(t, del(viewer, id), http.StatusForbidden, "forbidden")
	if resp := del(admin, id); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status %d", resp.StatusCode)
	}
	wantAudit(t, f, "trap_rules.delete")
	wantError(t, del(admin, id), http.StatusNotFound, "not_found")
}

func TestSystemStatus(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	viewer := f.login(false, rbac.Binding{Role: rbac.RoleViewer})
	operator := f.login(false, rbac.Binding{Role: rbac.RoleOperator})
	dev := f.newDevice(g)
	ctx := context.Background()
	if _, err := f.env.Pool("postgres").Exec(ctx, `INSERT INTO events.eventd_stats (instance, updated_at, received, accepted, dropped, queue_depth)
		VALUES ('eventd-1', now(), 10, 8, 1, 3)`); err != nil {
		t.Fatal(err)
	}
	pl := inventory.NewStore(f.env.Pool("nms_poller"))
	if err := pl.SetStatus(ctx, dev, "up", time.Now().Add(-time.Hour), ""); err != nil {
		t.Fatal(err)
	}
	if err := pl.Heartbeat(ctx, "local", time.Now()); err != nil {
		t.Fatal(err)
	}

	wantError(t, f.do(viewer.authed(req{method: "GET", path: "/api/system/status"})), http.StatusForbidden, "forbidden")
	type status struct {
		Pollers []struct {
			ID               string `json:"id"`
			Devices          int64  `json:"devices"`
			DevicesReporting int64  `json:"devices_reporting"`
		} `json:"pollers"`
		Eventd []struct {
			Instance   string `json:"instance"`
			Received   int64  `json:"received"`
			Dropped    int64  `json:"dropped"`
			QueueDepth int    `json:"queue_depth"`
		} `json:"eventd"`
		DBSize int64 `json:"db_size_bytes"`
		Queues []any `json:"queues"`
	}
	st := decode[status](t, f.do(operator.authed(req{method: "GET", path: "/api/system/status"})))
	var local bool
	for _, p := range st.Pollers {
		if p.ID == "local" && p.Devices >= 1 && p.DevicesReporting >= 1 {
			local = true
		}
	}
	var ed bool
	for _, e := range st.Eventd {
		ed = ed || (e.Instance == "eventd-1" && e.Received == 10 && e.Dropped == 1 && e.QueueDepth == 3)
	}
	if !local || !ed || st.DBSize <= 0 || st.Queues == nil {
		t.Errorf("status = %+v", st)
	}
}

func TestDeviceDetailLastError(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	viewer := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &g})
	dev, quiet := f.newDevice(g), f.newDevice(g)
	ctx := context.Background()
	pl := inventory.NewStore(f.env.Pool("nms_poller"))
	const msg = `timeout "snmp" <b>&</b>`
	if err := pl.SetStatus(ctx, dev, "down", time.Now().Add(-time.Hour), msg); err != nil {
		t.Fatal(err)
	}
	if err := pl.Heartbeat(ctx, "local", time.Now()); err != nil {
		t.Fatal(err)
	}
	get := func(id int64) map[string]any {
		return decode[map[string]any](t, f.do(viewer.authed(req{method: "GET", path: fmt.Sprintf("/api/devices/%d", id)})))
	}
	if got := get(dev)["last_error"]; got != msg {
		t.Errorf("last_error = %#v", got)
	}
	if got, ok := get(quiet)["last_error"]; !ok || got != "" {
		t.Errorf("never polled last_error = %#v", got)
	}
}
