package httpapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/httpapi"
	"github.com/beekamai/network-scheme/internal/notify"
	"github.com/beekamai/network-scheme/internal/rbac"
)

/* root runs a statement as the database owner (fixtures the api role cannot create). */
func (f *fixture) root(q string, args ...any) {
	f.t.Helper()
	if _, err := f.env.Pool("postgres").Exec(context.Background(), q, args...); err != nil {
		f.t.Fatalf("%s: %v", q, err)
	}
}

func (f *fixture) rootInt(q string, args ...any) int64 {
	f.t.Helper()
	var id int64
	if err := f.env.Pool("postgres").QueryRow(context.Background(), q, args...).Scan(&id); err != nil {
		f.t.Fatalf("%s: %v", q, err)
	}
	return id
}

/* newTemplate binds a fresh template to group g. */
func (f *fixture) newTemplate(g int64) int64 {
	return f.rootInt(`INSERT INTO core.monitoring_template (name, group_id) VALUES ($1, $2) RETURNING id`, uniqueName("tpl"), g)
}

func (f *fixture) newTrigger(tpl int64) int64 {
	return f.rootInt(`INSERT INTO core.trigger (template_id, kind, params, duration_s, severity, name)
		VALUES ($1, 'availability', '{"states":["down"]}', 60, 'high', $2) RETURNING id`, tpl, uniqueName("trig"))
}

/* newProblem inserts an open problem of a fresh trigger on dev; opened is the open time. */
func (f *fixture) newProblem(dev int64, severity, state string, suppressed bool, opened time.Time) int64 {
	trig := f.newTrigger(f.newTemplate(f.groupOf(dev)))
	return f.rootInt(`INSERT INTO problems.problem (trigger_id, device_id, severity, state, suppressed, opened_at, acknowledged_at, resolved_at)
		VALUES ($1, $2, $3, $4::text, $5, $6::timestamptz, CASE WHEN $4::text = 'acknowledged' THEN $6::timestamptz END, CASE WHEN $4::text = 'resolved' THEN $6::timestamptz END) RETURNING id`,
		trig, dev, severity, state, suppressed, opened)
}

func (f *fixture) groupOf(dev int64) int64 {
	return f.rootInt(`SELECT group_id FROM core.device WHERE id = $1`, dev)
}

type problemJSON struct {
	ID         int64      `json:"id"`
	DeviceID   *int64     `json:"device_id"`
	DeviceName string     `json:"device_name"`
	GroupID    *int64     `json:"group_id"`
	Severity   string     `json:"severity"`
	State      string     `json:"state"`
	Suppressed bool       `json:"suppressed"`
	Name       string     `json:"name"`
	SystemKind *string    `json:"system_kind"`
	AckedAt    *time.Time `json:"acknowledged_at"`
	Acks       []struct {
		ID       int64   `json:"id"`
		UserID   int64   `json:"user_id"`
		Username *string `json:"username"`
		Comment  string  `json:"comment"`
	} `json:"acks"`
}

type problemsJSON struct {
	Items      []problemJSON `json:"items"`
	NextCursor *string       `json:"next_cursor"`
}

func (f *fixture) getProblems(s *subject, q url.Values) *http.Response {
	return f.do(s.authed(req{method: "GET", path: "/api/problems?" + q.Encode()}))
}

/* allProblems pages through every problem the subject may see. */
func (f *fixture) allProblems(s *subject, q url.Values) []problemJSON {
	f.t.Helper()
	var out []problemJSON
	q.Set("limit", "500")
	for {
		page := decode[problemsJSON](f.t, f.getProblems(s, q))
		out = append(out, page.Items...)
		if page.NextCursor == nil {
			return out
		}
		q.Set("cursor", *page.NextCursor)
	}
}

func ids(ps []problemJSON) []int64 {
	out := []int64{}
	for _, p := range ps {
		out = append(out, p.ID)
	}
	return out
}

func sameSet(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[int64]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}

func TestProblemsScopeFiltersAndPaging(t *testing.T) {
	f := newFixture(t, nil)
	gA, gB := f.newGroup(), f.newGroup()
	child := int(f.rootInt(`INSERT INTO core.device_group (name, parent_id) VALUES ($1, $2) RETURNING id`, uniqueName("kid"), gA))
	viewerA := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &gA})
	global := f.login(false, rbac.Binding{Role: rbac.RoleViewer})
	devA, devKid, devB := f.newDevice(gA), f.newDevice(int64(child)), f.newDevice(gB)
	t0 := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Hour)
	pA := f.newProblem(devA, "high", "problem", false, t0.Add(1*time.Minute))
	pKid := f.newProblem(devKid, "average", "problem", true, t0.Add(2*time.Minute))
	pB := f.newProblem(devB, "disaster", "problem", false, t0.Add(3*time.Minute))
	pDone := f.newProblem(devA, "info", "resolved", false, t0.Add(4*time.Minute))
	sys := f.rootInt(`INSERT INTO problems.problem (system_kind, object, severity, opened_at) VALUES ('poller_unavailable', 'poller:x', 'high', $1) RETURNING id`, t0.Add(5*time.Minute))

	got := decode[problemsJSON](t, f.getProblems(viewerA, url.Values{}))
	if !sameSet(ids(got.Items), []int64{pA, pKid, pDone}) {
		t.Fatalf("viewer of A sees %v, want %v", ids(got.Items), []int64{pA, pKid, pDone})
	}
	for _, p := range got.Items {
		if p.DeviceName == "" || p.GroupID == nil || p.Name == "" {
			t.Errorf("problem lacks device or title: %+v", p)
		}
	}
	all := f.allProblems(global, url.Values{})
	var sysSeen bool
	for _, p := range all {
		if p.ID == sys {
			sysSeen = p.DeviceID == nil && p.SystemKind != nil && *p.SystemKind == "poller_unavailable" && p.Name == "Poller is unavailable"
		}
	}
	if !sysSeen {
		t.Error("global scope should see the device-less system problem with its title")
	}
	for _, id := range []int64{pA, pKid, pB, pDone} {
		if !slices.Contains(ids(all), id) {
			t.Errorf("global scope lacks problem %d", id)
		}
	}

	type tc struct {
		q    url.Values
		want []int64
	}
	for name, c := range map[string]tc{
		"state":      {url.Values{"state": {"resolved"}}, []int64{pDone}},
		"severity":   {url.Values{"severity_min": {"average"}}, []int64{pA, pKid}},
		"suppressed": {url.Values{"suppressed": {"true"}}, []int64{pKid}},
		"visible":    {url.Values{"suppressed": {"false"}}, []int64{pA, pDone}},
		"device":     {url.Values{"device_id": {fmt.Sprint(devA)}}, []int64{pA, pDone}},
		"group":      {url.Values{"group_id": {fmt.Sprint(child)}}, []int64{pKid}},
		"group+subs": {url.Values{"group_id": {fmt.Sprint(gA)}}, []int64{pA, pKid, pDone}},
	} {
		if r := decode[problemsJSON](t, f.getProblems(viewerA, c.q)); !sameSet(ids(r.Items), c.want) {
			t.Errorf("%s: got %v, want %v", name, ids(r.Items), c.want)
		}
	}
	wantError(t, f.getProblems(viewerA, url.Values{"device_id": {fmt.Sprint(devB)}}), http.StatusNotFound, "not_found")
	wantError(t, f.getProblems(viewerA, url.Values{"group_id": {fmt.Sprint(gB)}}), http.StatusNotFound, "not_found")
	if r := decode[problemsJSON](t, f.getProblems(global, url.Values{"device_id": {fmt.Sprint(devB)}})); !sameSet(ids(r.Items), []int64{pB}) {
		t.Errorf("global device filter = %v", ids(r.Items))
	}
	for name, q := range map[string]url.Values{
		"state": {"state": {"open"}}, "severity": {"severity_min": {"x"}}, "suppressed": {"suppressed": {"1"}}, "limit0": {"limit": {"0"}},
		"limit501": {"limit": {"501"}}, "cursor": {"cursor": {"!!"}}, "device": {"device_id": {"0"}}, "twice": {"state": {"problem", "resolved"}},
	} {
		wantError(t, f.getProblems(global, q), http.StatusBadRequest, "bad_request")
		_ = name
	}

	/* Paging: equal opened_at values are neither repeated nor skipped. */
	tie := time.Now().UTC().Truncate(time.Microsecond)
	var want []int64
	for i := 0; i < 5; i++ {
		want = append(want, f.newProblem(devA, "info", "problem", false, tie))
	}
	var seen []int64
	cur := ""
	for pages := 0; ; pages++ {
		q := url.Values{"limit": {"2"}, "device_id": {fmt.Sprint(devA)}}
		if cur != "" {
			q.Set("cursor", cur)
		}
		page := decode[problemsJSON](t, f.getProblems(viewerA, q))
		seen = append(seen, ids(page.Items)...)
		if page.NextCursor == nil {
			break
		}
		cur = *page.NextCursor
		if pages > 10 {
			t.Fatal("paging does not end")
		}
	}
	if !sameSet(seen, append(want, pA, pDone)) {
		t.Errorf("paged %v, want %v + %d, %d", seen, want, pA, pDone)
	}
	last := int64(1 << 62)
	for _, id := range seen[:5] {
		if id >= last {
			t.Errorf("ties are not ordered by id descending: %v", seen)
		}
		last = id
	}
}

func TestProblemDetailAndAck(t *testing.T) {
	hub := notify.NewHub()
	f := newFixture(t, func(d *httpapi.Deps) { d.Hub = hub })
	gA, gB := f.newGroup(), f.newGroup()
	operatorA := f.login(false, rbac.Binding{Role: rbac.RoleOperator, GroupID: &gA})
	viewerA := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &gA})
	admin := f.login(false, rbac.Binding{Role: rbac.RoleAdmin})
	devA, devB := f.newDevice(gA), f.newDevice(gB)
	now := time.Now().UTC()
	p := f.newProblem(devA, "high", "problem", false, now.Add(-time.Minute))
	pB := f.newProblem(devB, "high", "problem", false, now.Add(-time.Minute))
	pDone := f.newProblem(devA, "high", "resolved", false, now.Add(-time.Minute))
	pSupp := f.newProblem(devA, "high", "problem", true, now.Add(-time.Minute))
	msgs, cancel := hub.Subscribe(nil)
	defer cancel()
	start := f.lastAuditID()
	path := func(id int64) string { return fmt.Sprintf("/api/problems/%d/ack", id) }
	ack := func(s *subject, id int64, comment any) *http.Response {
		return f.do(s.authed(req{method: "POST", path: path(id), body: map[string]any{"comment": comment}}))
	}

	/* Bad comments. */
	for name, c := range map[string]any{"empty": "", "blank": " \n\t ", "long": strings.Repeat("я", 1001), "control": "a\x00b", "number": 5} {
		wantError(t, ack(operatorA, p, c), http.StatusBadRequest, "bad_request")
		_ = name
	}
	wantError(t, f.do(operatorA.authed(req{method: "POST", path: path(p), body: map[string]any{}})), http.StatusBadRequest, "bad_request")
	wantError(t, ack(viewerA, p, "x"), http.StatusForbidden, "forbidden")
	wantError(t, ack(operatorA, pB, "x"), http.StatusNotFound, "not_found")
	wantError(t, ack(operatorA, pDone, "x"), http.StatusConflict, "problem_resolved")
	wantError(t, ack(operatorA, 999999999, "x"), http.StatusNotFound, "not_found")
	if got := decode[problemJSON](t, f.do(operatorA.authed(req{method: "GET", path: fmt.Sprintf("/api/problems/%d", p)}))); got.State != "problem" || len(got.Acks) != 0 {
		t.Fatalf("refused acks changed the problem: %+v", got)
	}

	/* The first ack moves the state and is announced once; later ones only add history. */
	wantStatus(t, ack(operatorA, p, "looking into it"), http.StatusNoContent)
	select {
	case m := <-msgs:
		if m.Event != notify.EventAcknowledged || m.Problem.ID != p || m.Problem.State != "acknowledged" || m.Problem.AckedAt == nil ||
			m.Problem.DeviceName == "" || m.Problem.GroupID == nil || *m.Problem.GroupID != gA || m.Problem.Name == "" {
			t.Errorf("message = %+v", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no acknowledged message")
	}
	first := decode[problemJSON](t, f.do(viewerA.authed(req{method: "GET", path: fmt.Sprintf("/api/problems/%d", p)})))
	wantStatus(t, ack(admin, p, "second opinion"), http.StatusNoContent)
	got := decode[problemJSON](t, f.do(viewerA.authed(req{method: "GET", path: fmt.Sprintf("/api/problems/%d", p)})))
	if got.State != "acknowledged" || got.AckedAt == nil || !got.AckedAt.Equal(*first.AckedAt) || len(got.Acks) != 2 {
		t.Fatalf("after two acks: %+v", got)
	}
	if got.Acks[0].Comment != "looking into it" || got.Acks[1].Comment != "second opinion" || got.Acks[0].Username == nil || got.Acks[0].UserID != operatorA.uid || got.Acks[1].UserID != admin.uid {
		t.Errorf("history = %+v", got.Acks)
	}
	select {
	case m := <-msgs:
		t.Errorf("a repeated ack was announced: %+v", m)
	case <-time.After(200 * time.Millisecond):
	}
	/* A suppressed problem was never announced, so its ack is not either. */
	wantStatus(t, ack(operatorA, pSupp, "noted"), http.StatusNoContent)
	select {
	case m := <-msgs:
		t.Errorf("suppressed ack announced: %+v", m)
	case <-time.After(200 * time.Millisecond):
	}
	/* Detail follows visibility. */
	wantError(t, f.do(viewerA.authed(req{method: "GET", path: fmt.Sprintf("/api/problems/%d", pB)})), http.StatusNotFound, "not_found")
	wantError(t, f.do(viewerA.authed(req{method: "GET", path: "/api/problems/0"})), http.StatusNotFound, "not_found")
	/* A problem whose acks exist keeps them when resolved; acking it is refused. */
	f.root(`UPDATE problems.problem SET state = 'resolved', resolved_at = now() WHERE id = $1`, p)
	wantError(t, ack(operatorA, p, "late"), http.StatusConflict, "problem_resolved")

	if n := f.auditCount(start, "problems.ack", "success"); n != 3 {
		t.Errorf("successful ack audit records = %d, want 3", n)
	}
	if n := f.auditCount(start, "problems.ack", "failure"); n != 4 { /* pB 404, pDone 409, missing 404, late 409 */
		t.Errorf("failed ack audit records = %d, want 4", n)
	}
}

func (f *fixture) auditSince(start int64) map[string]int {
	f.t.Helper()
	rows, err := f.env.Pool("nms_api").Query(context.Background(), `SELECT action FROM audit.event WHERE id > $1`, start)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			f.t.Fatal(err)
		}
		out[a]++
	}
	return out
}

/* auditCount counts audit records of an action with the given result. */
func (f *fixture) auditCount(start int64, action, result string) int {
	f.t.Helper()
	var n int
	if err := f.env.Pool("nms_api").QueryRow(context.Background(),
		`SELECT count(*) FROM audit.event WHERE id > $1 AND action = $2 AND convert_from(payload, 'UTF8')::jsonb->>'result' = $3`, start, action, result).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

/* auditPayload returns the payloads of an action since start. */
func (f *fixture) auditPayload(start int64, action string) []string {
	f.t.Helper()
	rows, err := f.env.Pool("nms_api").Query(context.Background(),
		`SELECT convert_from(payload, 'UTF8') FROM audit.event WHERE id > $1 AND action = $2 ORDER BY id`, start, action)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}

type tplJSON struct {
	ID               int64   `json:"id"`
	Name             string  `json:"name"`
	Driver           *string `json:"driver"`
	GroupID          *int64  `json:"group_id"`
	IntervalAvailS   *int    `json:"interval_avail_s"`
	IntervalMetricsS *int    `json:"interval_metrics_s"`
}

type trigJSON struct {
	ID        int64           `json:"id"`
	Kind      string          `json:"kind"`
	Params    json.RawMessage `json:"params"`
	DurationS int             `json:"duration_s"`
	Severity  string          `json:"severity"`
	Enabled   bool            `json:"enabled"`
	Name      string          `json:"name"`
}

func TestTemplatesAndTriggers(t *testing.T) {
	var changed atomic.Int64
	f := newFixture(t, func(d *httpapi.Deps) { d.ConfigChanged = func() { changed.Add(1) } })
	gA, gB := f.newGroup(), f.newGroup()
	admin := f.login(false, rbac.Binding{Role: rbac.RoleAdmin})
	adminA := f.login(false, rbac.Binding{Role: rbac.RoleAdmin, GroupID: &gA})
	start := f.lastAuditID()

	/* Templates: a global admin binds to drivers and groups; a scoped one only to groups of its scope. */
	name := uniqueName("tpl")
	resp := f.do(admin.authed(req{method: "POST", path: "/api/templates", body: map[string]any{"name": name, "driver": "eltex-mes", "interval_avail_s": 30}}))
	wantStatus(t, resp, http.StatusCreated)
	drv := decode[idResp](t, resp).ID
	wantError(t, f.do(admin.authed(req{method: "POST", path: "/api/templates", body: map[string]any{"name": name, "group_id": gA}})), http.StatusConflict, "template_exists")
	for name, body := range map[string]map[string]any{
		"both": {"name": uniqueName("t"), "driver": "x", "group_id": gA}, "neither": {"name": uniqueName("t")},
		"badname": {"name": " x", "group_id": gA}, "baddriver": {"name": uniqueName("t"), "driver": "A B"},
		"interval": {"name": uniqueName("t"), "group_id": gA, "interval_avail_s": 5}, "unknown": {"name": uniqueName("t"), "group_id": gA, "x": 1},
	} {
		wantError(t, f.do(admin.authed(req{method: "POST", path: "/api/templates", body: body})), http.StatusBadRequest, "bad_request")
		_ = name
	}
	wantError(t, f.do(admin.authed(req{method: "POST", path: "/api/templates", body: map[string]any{"name": uniqueName("t"), "group_id": 999999999}})), http.StatusNotFound, "not_found")
	wantError(t, f.do(adminA.authed(req{method: "POST", path: "/api/templates", body: map[string]any{"name": uniqueName("t"), "driver": "eltex-mes"}})), http.StatusForbidden, "forbidden")
	wantError(t, f.do(adminA.authed(req{method: "POST", path: "/api/templates", body: map[string]any{"name": uniqueName("t"), "group_id": gB}})), http.StatusNotFound, "not_found")
	resp = f.do(adminA.authed(req{method: "POST", path: "/api/templates", body: map[string]any{"name": uniqueName("t"), "group_id": gA}}))
	wantStatus(t, resp, http.StatusCreated)
	tA := decode[idResp](t, resp).ID
	tB := f.newTemplate(gB)

	list := func(s *subject) []tplJSON {
		return decode[[]tplJSON](t, f.do(s.authed(req{method: "GET", path: "/api/templates"})))
	}
	has := func(ts []tplJSON, id int64) bool {
		for _, x := range ts {
			if x.ID == id {
				return true
			}
		}
		return false
	}
	if l := list(admin); !has(l, drv) || !has(l, tA) || !has(l, tB) {
		t.Errorf("global admin list lacks templates: %+v", l)
	}
	if l := list(adminA); !has(l, tA) || has(l, tB) || has(l, drv) {
		t.Errorf("scoped admin list = %+v", l)
	}
	tp := fmt.Sprintf("/api/templates/%d", drv)
	wantError(t, f.do(adminA.authed(req{method: "PATCH", path: tp, body: map[string]any{"name": "z"}})), http.StatusNotFound, "not_found")
	wantError(t, f.do(adminA.authed(req{method: "GET", path: tp + "/triggers"})), http.StatusNotFound, "not_found")
	wantStatus(t, f.do(admin.authed(req{method: "PATCH", path: tp, body: map[string]any{"name": uniqueName("renamed"), "interval_avail_s": nil, "interval_metrics_s": 45}})), http.StatusNoContent)
	if d := f.rootInt(`SELECT interval_metrics_s FROM core.monitoring_template WHERE id = $1`, drv); d != 45 {
		t.Errorf("interval_metrics_s = %d", d)
	}
	wantError(t, f.do(admin.authed(req{method: "PATCH", path: tp, body: map[string]any{}})), http.StatusBadRequest, "bad_request")

	/* Triggers: parameters are validated by the engine's parser and stored canonically. */
	trigs := fmt.Sprintf("/api/templates/%d/triggers", tA)
	good := map[string]any{"kind": "metric_threshold", "params": map[string]any{"metric": "cpu", "op": "gt", "value": 90}, "duration_s": 300, "severity": "warning", "name": "CPU high"}
	resp = f.do(adminA.authed(req{method: "POST", path: trigs, body: good}))
	wantStatus(t, resp, http.StatusCreated)
	tr := decode[idResp](t, resp).ID
	var stored string
	if err := f.env.Pool("postgres").QueryRow(context.Background(), `SELECT params::text FROM core.trigger WHERE id = $1`, tr).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != `{"op": "gt", "value": 90, "metric": "cpu", "if_index": null}` {
		t.Errorf("stored params = %s", stored)
	}
	bad := func(mut func(map[string]any)) map[string]any {
		b := map[string]any{}
		for k, v := range good {
			b[k] = v
		}
		mut(b)
		return b
	}
	for name, body := range map[string]map[string]any{
		"kind":   bad(func(b map[string]any) { b["kind"] = "expr" }),
		"system": bad(func(b map[string]any) { b["kind"] = "poller_unavailable"; b["params"] = map[string]any{} }),
		"range":  bad(func(b map[string]any) { b["params"] = map[string]any{"metric": "cpu", "op": "gt", "value": 101} }),
		"extra": bad(func(b map[string]any) {
			b["params"] = map[string]any{"metric": "cpu", "op": "gt", "value": 1, "sql": "x"}
		}),
		"missing": bad(func(b map[string]any) { delete(b, "params") }),
		"syslog long": bad(func(b map[string]any) {
			b["kind"] = "syslog"
			b["params"] = map[string]any{"severity_min": 3, "contains": strings.Repeat("x", 129)}
		}),
		"duration": bad(func(b map[string]any) { b["duration_s"] = 86401 }),
		"severity": bad(func(b map[string]any) { b["severity"] = "fatal" }),
	} {
		wantError(t, f.do(adminA.authed(req{method: "POST", path: trigs, body: body})), http.StatusBadRequest, "invalid_trigger")
		_ = name
	}
	wantError(t, f.do(adminA.authed(req{method: "POST", path: trigs, body: bad(func(b map[string]any) { b["name"] = "" })})), http.StatusBadRequest, "bad_request")
	wantError(t, f.do(adminA.authed(req{method: "POST", path: trigs, body: bad(func(b map[string]any) { b["x"] = 1 })})), http.StatusBadRequest, "bad_request")
	wantError(t, f.do(adminA.authed(req{method: "POST", path: fmt.Sprintf("/api/templates/%d/triggers", tB), body: good})), http.StatusNotFound, "not_found")

	list2 := decode[[]trigJSON](t, f.do(adminA.authed(req{method: "GET", path: trigs})))
	if len(list2) != 1 || list2[0].ID != tr || list2[0].Kind != "metric_threshold" || !list2[0].Enabled || list2[0].DurationS != 300 {
		t.Fatalf("triggers = %+v", list2)
	}
	one := fmt.Sprintf("%s/%d", trigs, tr)
	wantStatus(t, f.do(adminA.authed(req{method: "PATCH", path: one, body: map[string]any{"enabled": false, "severity": "high",
		"params": map[string]any{"metric": "mem", "op": "lt", "value": 5.5}}})), http.StatusNoContent)
	if err := f.env.Pool("postgres").QueryRow(context.Background(), `SELECT params::text FROM core.trigger WHERE id = $1 AND NOT enabled AND severity = 'high'`, tr).Scan(&stored); err != nil || !strings.Contains(stored, `"mem"`) {
		t.Errorf("update not applied: %q %v", stored, err)
	}
	/* Params are checked against the stored kind; kind cannot change. */
	wantError(t, f.do(adminA.authed(req{method: "PATCH", path: one, body: map[string]any{"params": map[string]any{"states": []string{"down"}}}})), http.StatusBadRequest, "invalid_trigger")
	wantError(t, f.do(adminA.authed(req{method: "PATCH", path: one, body: map[string]any{"kind": "trap"}})), http.StatusBadRequest, "bad_request")
	wantError(t, f.do(adminA.authed(req{method: "PATCH", path: one, body: map[string]any{}})), http.StatusBadRequest, "bad_request")
	wantError(t, f.do(adminA.authed(req{method: "PATCH", path: fmt.Sprintf("%s/%d", trigs, tr+99999), body: map[string]any{"enabled": true}})), http.StatusNotFound, "not_found")
	/* A trigger is addressed through its own template only. */
	wantError(t, f.do(adminA.authed(req{method: "DELETE", path: fmt.Sprintf("/api/templates/%d/triggers/%d", tB, tr)})), http.StatusNotFound, "not_found")
	wantStatus(t, f.do(adminA.authed(req{method: "DELETE", path: one})), http.StatusNoContent)
	wantError(t, f.do(adminA.authed(req{method: "DELETE", path: one})), http.StatusNotFound, "not_found")

	/* Deleting a template removes its triggers. */
	tr2 := f.newTrigger(tA)
	wantStatus(t, f.do(adminA.authed(req{method: "DELETE", path: fmt.Sprintf("/api/templates/%d", tA)})), http.StatusNoContent)
	if n := f.rootInt(`SELECT count(*) FROM core.trigger WHERE id = $1`, tr2); n != 0 {
		t.Error("trigger outlived its template")
	}
	wantError(t, f.do(adminA.authed(req{method: "DELETE", path: fmt.Sprintf("/api/templates/%d", tB)})), http.StatusNotFound, "not_found")

	/* Every successful change reloaded the engine; refused ones did not. */
	if got := changed.Load(); got != 7 { /* 2 template creates, rename, trigger create/update/delete, template delete */
		t.Errorf("config change callbacks = %d, want 7", got)
	}
	acts := f.auditSince(start)
	for _, a := range []string{"templates.create", "templates.update", "templates.delete", "triggers.create", "triggers.update", "triggers.delete"} {
		if acts[a] == 0 {
			t.Errorf("no audit record %s: %v", a, acts)
		}
	}
	if p := f.auditPayload(start, "triggers.create"); len(p) == 0 || !strings.Contains(p[0], `"metric":"cpu"`) {
		t.Errorf("audit of triggers.create does not carry the params: %v", p)
	}
}

func TestConfigChangedOnlyAfterSuccess(t *testing.T) {
	var changed atomic.Int64
	f := newFixture(t, func(d *httpapi.Deps) { d.ConfigChanged = func() { changed.Add(1) } })
	g := f.newGroup()
	admin := f.login(false, rbac.Binding{Role: rbac.RoleAdmin})
	wantStatus(t, f.do(admin.authed(req{method: "POST", path: "/api/templates", body: map[string]any{"name": uniqueName("t"), "group_id": g}})), http.StatusCreated)
	if changed.Load() != 1 {
		t.Fatalf("callbacks after a create = %d", changed.Load())
	}
	wantError(t, f.do(admin.authed(req{method: "POST", path: "/api/templates", body: map[string]any{"name": "", "group_id": g}})), http.StatusBadRequest, "bad_request")
	wantError(t, f.do(admin.authed(req{method: "DELETE", path: "/api/templates/999999999"})), http.StatusNotFound, "not_found")
	if changed.Load() != 1 {
		t.Errorf("refused requests called the hook: %d", changed.Load())
	}
}

func TestTriggerOverrides(t *testing.T) {
	f := newFixture(t, nil)
	gA, gB := f.newGroup(), f.newGroup()
	admin := f.login(false, rbac.Binding{Role: rbac.RoleAdmin})
	adminA := f.login(false, rbac.Binding{Role: rbac.RoleAdmin, GroupID: &gA})
	devA, devB := f.newDevice(gA), f.newDevice(gB)
	tplA, tplB := f.newTemplate(gA), f.newTemplate(gB)
	metric := f.rootInt(`INSERT INTO core.trigger (template_id, kind, params, duration_s, severity, name)
		VALUES ($1, 'metric_threshold', '{"metric":"if_util_in","op":"gt","value":80,"if_index":null}', 0, 'warning', 'util') RETURNING id`, tplA)
	trigB := f.newTrigger(tplB)
	start := f.lastAuditID()
	put := func(s *subject, dev, trig int64, body any) *http.Response {
		return f.do(s.authed(req{method: "PUT", path: fmt.Sprintf("/api/devices/%d/trigger-overrides/%d", dev, trig), body: body}))
	}
	read := func(dev int64) []struct {
		TriggerID int64           `json:"trigger_id"`
		Enabled   *bool           `json:"enabled"`
		Params    json.RawMessage `json:"params"`
		Severity  *string         `json:"severity"`
	} {
		return decode[[]struct {
			TriggerID int64           `json:"trigger_id"`
			Enabled   *bool           `json:"enabled"`
			Params    json.RawMessage `json:"params"`
			Severity  *string         `json:"severity"`
		}](t, f.do(adminA.authed(req{method: "GET", path: fmt.Sprintf("/api/devices/%d/trigger-overrides", dev)})))
	}

	/* The device must be in the caller's scope and the trigger must apply to it. */
	wantError(t, put(adminA, devB, trigB, map[string]any{"enabled": false}), http.StatusNotFound, "not_found")
	wantError(t, put(adminA, devA, trigB, map[string]any{"enabled": false}), http.StatusNotFound, "not_found")
	wantError(t, put(admin, devA, trigB, map[string]any{"enabled": false}), http.StatusNotFound, "not_found")
	wantError(t, put(adminA, devA, metric+99999, map[string]any{"enabled": false}), http.StatusNotFound, "not_found")
	wantError(t, put(adminA, devA, metric, map[string]any{}), http.StatusBadRequest, "bad_request")
	wantError(t, put(adminA, devA, metric, map[string]any{"severity": "meh"}), http.StatusBadRequest, "bad_request")
	wantError(t, put(adminA, devA, metric, map[string]any{"params": []int{1}}), http.StatusBadRequest, "bad_request")
	wantError(t, put(adminA, devA, metric, map[string]any{"params": map[string]any{"value": 500}}), http.StatusBadRequest, "invalid_trigger")
	wantError(t, put(adminA, devA, metric, map[string]any{"params": map[string]any{"sql": "x"}}), http.StatusBadRequest, "invalid_trigger")
	/* if_index on a cpu metric is not valid after merging, even though each part is. */
	wantError(t, put(adminA, devA, metric, map[string]any{"params": map[string]any{"metric": "cpu", "if_index": 3}}), http.StatusBadRequest, "invalid_trigger")

	wantStatus(t, put(adminA, devA, metric, map[string]any{"enabled": true, "severity": "high", "params": map[string]any{"value": 95, "op": "gt", "if_index": 7}}), http.StatusNoContent)
	o := read(devA)
	if len(o) != 1 || o[0].TriggerID != metric || o[0].Enabled == nil || !*o[0].Enabled || o[0].Severity == nil || *o[0].Severity != "high" {
		t.Fatalf("overrides = %+v", o)
	}
	var params map[string]any
	if err := json.Unmarshal(o[0].Params, &params); err != nil || len(params) != 2 || params["value"] != float64(95) || params["if_index"] != float64(7) {
		t.Errorf("stored overlay = %s (only differing keys are kept)", o[0].Params)
	}
	/* PUT replaces; an override that changes nothing stores no params. */
	wantStatus(t, put(adminA, devA, metric, map[string]any{"enabled": false, "params": map[string]any{"value": 80}}), http.StatusNoContent)
	if o = read(devA); len(o) != 1 || o[0].Enabled == nil || *o[0].Enabled || o[0].Severity != nil || string(o[0].Params) != "null" {
		t.Errorf("replaced override = %+v params %s", o, o[0].Params)
	}
	wantError(t, f.do(adminA.authed(req{method: "GET", path: fmt.Sprintf("/api/devices/%d/trigger-overrides", devB)})), http.StatusNotFound, "not_found")
	del := func(s *subject, dev int64) *http.Response {
		return f.do(s.authed(req{method: "DELETE", path: fmt.Sprintf("/api/devices/%d/trigger-overrides/%d", dev, metric)}))
	}
	wantError(t, del(adminA, devB), http.StatusNotFound, "not_found")
	wantStatus(t, del(adminA, devA), http.StatusNoContent)
	wantError(t, del(adminA, devA), http.StatusNotFound, "not_found")
	if f.auditCount(start, "trigger_overrides.set", "success") != 2 || f.auditCount(start, "trigger_overrides.delete", "success") != 1 ||
		f.auditCount(start, "trigger_overrides.delete", "failure") != 1 {
		t.Errorf("audit = %v", f.auditSince(start))
	}
}

func TestMaintenanceWindows(t *testing.T) {
	var changed atomic.Int64
	f := newFixture(t, func(d *httpapi.Deps) { d.ConfigChanged = func() { changed.Add(1) } })
	gA, gB := f.newGroup(), f.newGroup()
	admin := f.login(false, rbac.Binding{Role: rbac.RoleAdmin})
	adminA := f.login(false, rbac.Binding{Role: rbac.RoleAdmin, GroupID: &gA})
	operator := f.login(false, rbac.Binding{Role: rbac.RoleOperator})
	now := f.clk.Now()
	rfc := func(t time.Time) string { return t.Format(time.RFC3339) }
	create := func(s *subject, g int64, from, to time.Time) *http.Response {
		return f.do(s.authed(req{method: "POST", path: "/api/maintenance", body: map[string]any{"group_id": g, "starts_at": rfc(from), "ends_at": rfc(to), "comment": "firmware"}}))
	}
	start := f.lastAuditID()

	for name, c := range map[string]struct{ from, to time.Time }{
		"ended":       {now.Add(-2 * time.Hour), now.Add(-time.Hour)},
		"reversed":    {now.Add(time.Hour), now.Add(30 * time.Minute)},
		"empty":       {now.Add(time.Hour), now.Add(time.Hour)},
		"over 7 days": {now, now.Add(7*24*time.Hour + time.Second)},
	} {
		wantError(t, create(admin, gA, c.from, c.to), http.StatusBadRequest, "invalid_window")
		_ = name
	}
	wantError(t, f.do(admin.authed(req{method: "POST", path: "/api/maintenance", body: map[string]any{"group_id": gA, "starts_at": "tomorrow", "ends_at": rfc(now)}})), http.StatusBadRequest, "bad_request")
	wantError(t, f.do(admin.authed(req{method: "POST", path: "/api/maintenance", body: map[string]any{"group_id": gA, "starts_at": rfc(now)}})), http.StatusBadRequest, "bad_request")
	wantError(t, f.do(admin.authed(req{method: "POST", path: "/api/maintenance", body: map[string]any{"group_id": gA, "starts_at": rfc(now), "ends_at": rfc(now.Add(time.Hour)), "comment": strings.Repeat("x", 1001)}})), http.StatusBadRequest, "bad_request")
	wantError(t, create(adminA, gB, now, now.Add(time.Hour)), http.StatusNotFound, "not_found")
	wantError(t, create(admin, 999999999, now, now.Add(time.Hour)), http.StatusNotFound, "not_found")
	wantError(t, create(operator, gA, now, now.Add(time.Hour)), http.StatusForbidden, "forbidden")
	if changed.Load() != 0 {
		t.Fatalf("refused requests called the hook: %d", changed.Load())
	}

	/* Exactly 7 days and a window that started in the past but still runs are fine. */
	resp := create(adminA, gA, now.Add(-time.Hour), now.Add(7*24*time.Hour-time.Hour))
	wantStatus(t, resp, http.StatusCreated)
	wA := decode[idResp](t, resp).ID
	resp = create(admin, gB, now.Add(time.Hour), now.Add(2*time.Hour))
	wantStatus(t, resp, http.StatusCreated)
	wB := decode[idResp](t, resp).ID
	if changed.Load() != 2 {
		t.Errorf("hook calls = %d, want 2", changed.Load())
	}
	f.root(`INSERT INTO core.maintenance_window (group_id, starts_at, ends_at) VALUES ($1, now() - interval '3 days', now() - interval '2 days')`, gA)

	type win struct {
		ID        int64     `json:"id"`
		GroupID   int64     `json:"group_id"`
		GroupName string    `json:"group_name"`
		EndsAt    time.Time `json:"ends_at"`
		Comment   string    `json:"comment"`
	}
	get := func(s *subject, q string) []win {
		return decode[[]win](t, f.do(s.authed(req{method: "GET", path: "/api/maintenance" + q})))
	}
	if l := get(adminA, ""); len(l) != 1 || l[0].ID != wA || l[0].GroupName == "" || l[0].Comment != "firmware" {
		t.Errorf("scoped list = %+v", l)
	}
	if l := get(adminA, "?include_ended=true"); len(l) != 2 {
		t.Errorf("scoped list with ended = %+v", l)
	}
	if l := get(admin, ""); len(l) < 2 {
		t.Errorf("global list = %+v", l)
	}
	wantError(t, f.do(adminA.authed(req{method: "GET", path: "/api/maintenance?include_ended=maybe"})), http.StatusBadRequest, "bad_request")

	wantError(t, f.do(adminA.authed(req{method: "DELETE", path: fmt.Sprintf("/api/maintenance/%d", wB)})), http.StatusNotFound, "not_found")
	wantStatus(t, f.do(adminA.authed(req{method: "DELETE", path: fmt.Sprintf("/api/maintenance/%d", wA)})), http.StatusNoContent)
	wantError(t, f.do(adminA.authed(req{method: "DELETE", path: fmt.Sprintf("/api/maintenance/%d", wA)})), http.StatusNotFound, "not_found")
	wantStatus(t, f.do(admin.authed(req{method: "DELETE", path: fmt.Sprintf("/api/maintenance/%d", wB)})), http.StatusNoContent)
	if changed.Load() != 4 {
		t.Errorf("hook calls = %d, want 4", changed.Load())
	}
	acts := f.auditSince(start)
	if acts["maintenance.create"] < 2 || acts["maintenance.delete"] < 2 {
		t.Errorf("audit = %v", acts)
	}
}

func TestDeviceParent(t *testing.T) {
	var changed atomic.Int64
	f := newFixture(t, func(d *httpapi.Deps) { d.ConfigChanged = func() { changed.Add(1) } })
	gA, gB := f.newGroup(), f.newGroup()
	admin := f.login(false, rbac.Binding{Role: rbac.RoleAdmin})
	adminA := f.login(false, rbac.Binding{Role: rbac.RoleAdmin, GroupID: &gA})
	/* An operator of B can see devices of B but cannot manage them: its devices may still be parents. */
	mixed := f.login(false, rbac.Binding{Role: rbac.RoleAdmin, GroupID: &gA}, rbac.Binding{Role: rbac.RoleViewer, GroupID: &gB})
	a1, a2, a3, b1 := f.newDevice(gA), f.newDevice(gA), f.newDevice(gA), f.newDevice(gB)
	patch := func(s *subject, id int64, body any) *http.Response {
		return f.do(s.authed(req{method: "PATCH", path: fmt.Sprintf("/api/devices/%d", id), body: body}))
	}
	parentOf := func(id int64) *int64 {
		var p *int64
		if err := f.env.Pool("postgres").QueryRow(context.Background(), `SELECT parent_id FROM core.device WHERE id = $1`, id).Scan(&p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	start := f.lastAuditID()

	wantStatus(t, patch(adminA, a2, map[string]any{"parent_id": a1}), http.StatusNoContent)
	if p := parentOf(a2); p == nil || *p != a1 {
		t.Fatalf("parent = %v", p)
	}
	if changed.Load() != 1 {
		t.Errorf("hook calls = %d", changed.Load())
	}
	detail := decode[struct {
		ParentID *int64 `json:"parent_id"`
	}](t, f.do(adminA.authed(req{method: "GET", path: fmt.Sprintf("/api/devices/%d", a2)})))
	if detail.ParentID == nil || *detail.ParentID != a1 {
		t.Errorf("device detail parent_id = %v", detail.ParentID)
	}
	/* Cycles, self and depth. */
	wantError(t, patch(adminA, a1, map[string]any{"parent_id": a2}), http.StatusConflict, "parent_cycle")
	wantError(t, patch(adminA, a1, map[string]any{"parent_id": a1}), http.StatusConflict, "parent_cycle")
	wantStatus(t, patch(adminA, a3, map[string]any{"parent_id": a2}), http.StatusNoContent)
	wantError(t, patch(adminA, a1, map[string]any{"parent_id": a3}), http.StatusConflict, "parent_cycle")
	if p := parentOf(a1); p != nil {
		t.Errorf("refused change left parent %v", *p)
	}
	chain := []int64{f.newDevice(gA)}
	for i := 1; i < 16; i++ {
		d := f.newDevice(gA)
		f.root(`UPDATE core.device SET parent_id = $1 WHERE id = $2`, chain[i-1], d)
		chain = append(chain, d)
	}
	top := f.newDevice(gA)
	wantError(t, patch(adminA, top, map[string]any{"parent_id": chain[15]}), http.StatusConflict, "parent_too_deep")
	/* Visibility of the parent. */
	wantError(t, patch(adminA, a1, map[string]any{"parent_id": b1}), http.StatusNotFound, "not_found")
	wantError(t, patch(adminA, a1, map[string]any{"parent_id": 999999999}), http.StatusNotFound, "not_found")
	wantStatus(t, patch(mixed, a1, map[string]any{"parent_id": b1}), http.StatusNoContent)
	wantError(t, patch(adminA, b1, map[string]any{"parent_id": a1}), http.StatusNotFound, "not_found")
	wantError(t, patch(adminA, a1, map[string]any{"parent_id": 0}), http.StatusBadRequest, "bad_request")
	wantError(t, patch(adminA, a1, map[string]any{"parent_id": "x"}), http.StatusBadRequest, "bad_request")
	/* null clears; it can be combined with other fields. */
	hooks := changed.Load()
	wantStatus(t, patch(admin, a1, map[string]any{"parent_id": nil, "name": uniqueName("renamed")}), http.StatusNoContent)
	if parentOf(a1) != nil || changed.Load() != hooks+1 {
		t.Errorf("parent after null = %v, hooks %d -> %d", parentOf(a1), hooks, changed.Load())
	}
	wantStatus(t, patch(admin, a1, map[string]any{"name": uniqueName("renamed")}), http.StatusNoContent)
	if changed.Load() != hooks+1 {
		t.Error("a patch without parent_id reloaded the engine")
	}
	payloads := f.auditPayload(start, "devices.update")
	if len(payloads) < 3 || !strings.Contains(payloads[0], fmt.Sprintf(`"parent_id":%d`, a1)) {
		t.Errorf("audit payloads = %v", payloads)
	}
	if n := f.auditCount(start, "devices.update", "failure"); n < 4 {
		t.Errorf("refused parent changes audited = %d", n)
	}
}

/* monitoringRequest builds valid requests for the problem, template, trigger, override and maintenance routes with targets in m.target. */
func (m *matrixEnv) monitoringRequest(key string) (req, bool) {
	g := m.target
	now := m.clk.Now()
	tpl := func() int64 { return m.newTemplate(g) }
	trig := func() (int64, int64) { t := tpl(); return t, m.newTrigger(t) }
	switch key {
	case "GET /api/problems":
		return req{method: "GET", path: fmt.Sprintf("/api/problems?device_id=%d", m.newDevice(g))}, true
	case "GET /api/problems/{id}":
		return req{method: "GET", path: fmt.Sprintf("/api/problems/%d", m.newProblem(m.newDevice(g), "high", "problem", false, now))}, true
	case "POST /api/problems/{id}/ack":
		return req{method: "POST", path: fmt.Sprintf("/api/problems/%d/ack", m.newProblem(m.newDevice(g), "high", "problem", false, now)), body: map[string]string{"comment": "seen"}}, true
	case "GET /api/templates":
		return req{method: "GET", path: "/api/templates"}, true
	case "POST /api/templates":
		return req{method: "POST", path: "/api/templates", body: map[string]any{"name": uniqueName("tpl"), "group_id": g}}, true
	case "PATCH /api/templates/{id}":
		return req{method: "PATCH", path: fmt.Sprintf("/api/templates/%d", tpl()), body: map[string]any{"name": uniqueName("tpl")}}, true
	case "DELETE /api/templates/{id}":
		return req{method: "DELETE", path: fmt.Sprintf("/api/templates/%d", tpl())}, true
	case "GET /api/templates/{id}/triggers":
		return req{method: "GET", path: fmt.Sprintf("/api/templates/%d/triggers", tpl())}, true
	case "POST /api/templates/{id}/triggers":
		return req{method: "POST", path: fmt.Sprintf("/api/templates/%d/triggers", tpl()), body: map[string]any{
			"kind": "availability", "params": map[string]any{"states": []string{"down"}}, "duration_s": 60, "severity": "high", "name": "down"}}, true
	case "PATCH /api/templates/{id}/triggers/{trigger_id}":
		t, tr := trig()
		return req{method: "PATCH", path: fmt.Sprintf("/api/templates/%d/triggers/%d", t, tr), body: map[string]any{"enabled": false}}, true
	case "DELETE /api/templates/{id}/triggers/{trigger_id}":
		t, tr := trig()
		return req{method: "DELETE", path: fmt.Sprintf("/api/templates/%d/triggers/%d", t, tr)}, true
	case "GET /api/devices/{id}/trigger-overrides":
		return req{method: "GET", path: fmt.Sprintf("/api/devices/%d/trigger-overrides", m.newDevice(g))}, true
	case "PUT /api/devices/{id}/trigger-overrides/{trigger_id}":
		_, tr := trig()
		return req{method: "PUT", path: fmt.Sprintf("/api/devices/%d/trigger-overrides/%d", m.newDevice(g), tr), body: map[string]any{"enabled": false}}, true
	case "DELETE /api/devices/{id}/trigger-overrides/{trigger_id}":
		_, tr := trig()
		dev := m.newDevice(g)
		m.root(`INSERT INTO core.trigger_override (trigger_id, device_id, enabled) VALUES ($1, $2, false)`, tr, dev)
		return req{method: "DELETE", path: fmt.Sprintf("/api/devices/%d/trigger-overrides/%d", dev, tr)}, true
	case "GET /api/maintenance":
		return req{method: "GET", path: "/api/maintenance"}, true
	case "POST /api/maintenance":
		return req{method: "POST", path: "/api/maintenance", body: map[string]any{"group_id": g, "starts_at": now.Format(time.RFC3339), "ends_at": now.Add(time.Hour).Format(time.RFC3339)}}, true
	case "DELETE /api/maintenance/{id}":
		return req{method: "DELETE", path: fmt.Sprintf("/api/maintenance/%d", m.rootInt(
			`INSERT INTO core.maintenance_window (group_id, starts_at, ends_at) VALUES ($1, now(), now() + interval '1 hour') RETURNING id`, g))}, true
	}
	return req{}, false
}
