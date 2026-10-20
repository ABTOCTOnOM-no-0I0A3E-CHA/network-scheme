package httpapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/internal/rbac"
)

type userResp struct {
	ID           int64  `json:"id"`
	Username     string `json:"username"`
	Disabled     bool   `json:"disabled"`
	TOTPEnrolled bool   `json:"totp_enrolled"`
}

type idResp struct {
	ID int64 `json:"id"`
}

type bindingResp struct {
	Role    string `json:"role"`
	GroupID *int64 `json:"group_id"`
}

type auditResp struct {
	ID         int64  `json:"id"`
	TS         string `json:"ts"`
	Action     string `json:"action"`
	UserID     *int64 `json:"user_id"`
	Result     string `json:"result"`
	ObjectType string `json:"object_type"`
	ObjectID   string `json:"object_id"`
}

func wantStatus(t *testing.T, resp *http.Response, status int) {
	t.Helper()
	if resp.StatusCode != status {
		var e errBody
		_ = json.NewDecoder(resp.Body).Decode(&e)
		t.Fatalf("status = %d, want %d; error %+v", resp.StatusCode, status, e.Error)
	}
}

/* The database is shared by the package's tests, so admin-count tests start clean. */
func (f *fixture) resetBindings() {
	f.t.Helper()
	if _, err := f.env.Pool("postgres").Exec(context.Background(), `DELETE FROM core.role_binding`); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) users(s *subject) map[int64]userResp {
	f.t.Helper()
	resp := f.do(s.authed(req{method: "GET", path: "/api/users"}))
	wantStatus(f.t, resp, http.StatusOK)
	out := map[int64]userResp{}
	for _, u := range decode[[]userResp](f.t, resp) {
		out[u.ID] = u
	}
	return out
}

func TestDisableUserKillsSessions(t *testing.T) {
	f := newFixture(t, nil)
	admin := f.login(true, rbac.Binding{Role: rbac.RoleAdmin})
	victim := f.login(false, rbac.Binding{Role: rbac.RoleViewer})
	path := fmt.Sprintf("/api/users/%d", victim.uid)

	wantStatus(t, f.do(admin.authed(req{method: "PATCH", path: path, body: map[string]bool{"disabled": true}})), http.StatusNoContent)
	wantError(t, f.do(victim.authed(req{method: "GET", path: "/api/auth/me"})), http.StatusUnauthorized, "session_expired")
	if u := f.users(admin)[victim.uid]; !u.Disabled || !u.TOTPEnrolled {
		t.Fatalf("victim = %+v, want disabled and enrolled", u)
	}
	wantStatus(t, f.do(admin.authed(req{method: "PATCH", path: path, body: map[string]bool{"disabled": false}})), http.StatusNoContent)
	if u := f.users(admin)[victim.uid]; u.Disabled {
		t.Fatalf("victim = %+v, want enabled", u)
	}
	wantError(t, f.do(admin.authed(req{method: "PATCH", path: path, body: map[string]any{}})), http.StatusBadRequest, "bad_request")
	wantError(t, f.do(admin.authed(req{method: "PATCH", path: "/api/users/99999999", body: map[string]bool{"disabled": true}})), http.StatusNotFound, "not_found")
	wantError(t, f.do(admin.authed(req{method: "PATCH", path: "/api/users/abc", body: map[string]bool{"disabled": true}})), http.StatusNotFound, "not_found")
}

func TestLastAdminConflict(t *testing.T) {
	f := newFixture(t, nil)
	f.resetBindings()
	admin := f.login(true, rbac.Binding{Role: rbac.RoleAdmin})
	self := fmt.Sprintf("/api/users/%d", admin.uid)

	wantError(t, f.do(admin.authed(req{method: "PUT", path: self + "/bindings", body: []any{}})), http.StatusConflict, "last_admin")
	wantError(t, f.do(admin.authed(req{method: "PUT", path: self + "/bindings", body: []map[string]any{{"role": "viewer", "group_id": nil}}})),
		http.StatusConflict, "last_admin")
	wantError(t, f.do(admin.authed(req{method: "PATCH", path: self, body: map[string]bool{"disabled": true}})), http.StatusConflict, "last_admin")

	second := f.login(false, rbac.Binding{Role: rbac.RoleAdmin})
	wantStatus(t, f.do(admin.authed(req{method: "PATCH", path: fmt.Sprintf("/api/users/%d", second.uid), body: map[string]bool{"disabled": true}})), http.StatusNoContent)
	/* The disabled second admin does not count. */
	wantError(t, f.do(admin.authed(req{method: "PATCH", path: self, body: map[string]bool{"disabled": true}})), http.StatusConflict, "last_admin")
	f.me(admin.cookie)
}

func TestCreateUserAndBindings(t *testing.T) {
	f := newFixture(t, nil)
	admin := f.login(true, rbac.Binding{Role: rbac.RoleAdmin})
	name := uniqueName("made")
	resp := f.do(admin.authed(req{method: "POST", path: "/api/users", body: map[string]string{"username": name, "password": goodPW}}))
	wantStatus(t, resp, http.StatusCreated)
	id := decode[idResp](t, resp).ID
	if u := f.users(admin)[id]; u.Username != name || u.Disabled || u.TOTPEnrolled {
		t.Fatalf("created = %+v", u)
	}
	/* The new user enrolls TOTP at the first login. */
	lr := decode[loginResp](t, f.do(req{method: "POST", path: "/api/auth/login", body: map[string]string{"username": name, "password": goodPW}}))
	if lr.Stage != "enroll" {
		t.Fatalf("first login stage %q", lr.Stage)
	}
	for _, c := range []struct {
		body   map[string]string
		status int
		code   string
	}{
		{map[string]string{"username": name, "password": goodPW}, http.StatusConflict, "user_exists"},
		{map[string]string{"username": uniqueName("w"), "password": "short"}, http.StatusBadRequest, "weak_password"},
		{map[string]string{"username": "bad name!", "password": goodPW}, http.StatusBadRequest, "invalid_username"},
		{map[string]string{"username": uniqueName("w")}, http.StatusBadRequest, "weak_password"},
	} {
		wantError(t, f.do(admin.authed(req{method: "POST", path: "/api/users", body: c.body})), c.status, c.code)
	}

	g := f.do(admin.authed(req{method: "POST", path: "/api/groups", body: map[string]any{"name": uniqueName("bg"), "parent_id": nil}}))
	wantStatus(t, g, http.StatusCreated)
	gid := decode[idResp](t, g).ID
	bpath := fmt.Sprintf("/api/users/%d/bindings", id)
	wantStatus(t, f.do(admin.authed(req{method: "PUT", path: bpath,
		body: []map[string]any{{"role": "auditor", "group_id": nil}, {"role": "operator", "group_id": gid}}})), http.StatusNoContent)
	resp = f.do(admin.authed(req{method: "GET", path: bpath}))
	wantStatus(t, resp, http.StatusOK)
	bs := decode[[]bindingResp](t, resp)
	if len(bs) != 2 || bs[0].Role != "auditor" || bs[0].GroupID != nil || bs[1].Role != "operator" || bs[1].GroupID == nil || *bs[1].GroupID != gid {
		t.Fatalf("bindings = %+v", bs)
	}
	wantError(t, f.do(admin.authed(req{method: "PUT", path: bpath, body: []map[string]any{{"role": "root", "group_id": nil}}})), http.StatusBadRequest, "invalid_role")
	wantError(t, f.do(admin.authed(req{method: "PUT", path: bpath, body: []map[string]any{{"role": "viewer", "group_id": 99999999}}})), http.StatusNotFound, "not_found")
	wantError(t, f.do(admin.authed(req{method: "PUT", path: "/api/users/99999999/bindings", body: []any{}})), http.StatusNotFound, "not_found")
	wantError(t, f.do(admin.authed(req{method: "GET", path: "/api/users/99999999/bindings"})), http.StatusNotFound, "not_found")
}

func TestGroupConflicts(t *testing.T) {
	f := newFixture(t, nil)
	admin := f.login(true, rbac.Binding{Role: rbac.RoleAdmin})
	create := func(name string, parent any) *http.Response {
		return f.do(admin.authed(req{method: "POST", path: "/api/groups", body: map[string]any{"name": name, "parent_id": parent}}))
	}
	pname := uniqueName("p")
	resp := create(pname, nil)
	wantStatus(t, resp, http.StatusCreated)
	p := decode[idResp](t, resp).ID
	resp = create("child", p)
	wantStatus(t, resp, http.StatusCreated)
	c := decode[idResp](t, resp).ID

	wantError(t, create(pname, nil), http.StatusConflict, "group_exists")
	wantError(t, create("x", 99999999), http.StatusNotFound, "not_found")
	wantError(t, create("", nil), http.StatusBadRequest, "bad_request")
	wantError(t, create(strings.Repeat("я", 201), nil), http.StatusBadRequest, "bad_request")
	wantError(t, f.do(admin.authed(req{method: "PATCH", path: fmt.Sprintf("/api/groups/%d", p), body: map[string]any{"parent_id": c}})), http.StatusConflict, "group_cycle")
	wantError(t, f.do(admin.authed(req{method: "PATCH", path: fmt.Sprintf("/api/groups/%d", p), body: map[string]any{}})), http.StatusBadRequest, "bad_request")
	wantError(t, f.do(admin.authed(req{method: "DELETE", path: fmt.Sprintf("/api/groups/%d", p)})), http.StatusConflict, "group_not_empty")
	wantError(t, f.do(admin.authed(req{method: "DELETE", path: "/api/groups/99999999"})), http.StatusNotFound, "not_found")

	/* Move the child to the root and rename it; the parent is then a leaf. */
	newName := uniqueName("moved")
	wantStatus(t, f.do(admin.authed(req{method: "PATCH", path: fmt.Sprintf("/api/groups/%d", c), body: map[string]any{"name": newName, "parent_id": nil}})), http.StatusNoContent)
	resp = f.do(admin.authed(req{method: "GET", path: "/api/groups"}))
	wantStatus(t, resp, http.StatusOK)
	found := false
	for _, g := range decode[[]struct {
		ID       int64  `json:"id"`
		ParentID *int64 `json:"parent_id"`
		Name     string `json:"name"`
	}](t, resp) {
		if g.ID == c {
			found = g.Name == newName && g.ParentID == nil
		}
	}
	if !found {
		t.Fatal("moved group not listed with its new name and parent")
	}
	wantStatus(t, f.do(admin.authed(req{method: "DELETE", path: fmt.Sprintf("/api/groups/%d", p)})), http.StatusNoContent)
}

func (f *fixture) lastAuditID() int64 {
	f.t.Helper()
	var id int64
	if err := f.env.Pool("nms_api").QueryRow(context.Background(), `SELECT coalesce(max(id), 0) FROM audit.event`).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func TestAdminActionsAudited(t *testing.T) {
	f := newFixture(t, nil)
	admin := f.login(true, rbac.Binding{Role: rbac.RoleAdmin})
	start := f.lastAuditID()

	resp := f.do(admin.authed(req{method: "POST", path: "/api/users", body: map[string]string{"username": uniqueName("aud"), "password": goodPW}}))
	wantStatus(t, resp, http.StatusCreated)
	uid := strconv.FormatInt(decode[idResp](t, resp).ID, 10)
	wantStatus(t, f.do(admin.authed(req{method: "PATCH", path: "/api/users/" + uid, body: map[string]bool{"disabled": true}})), http.StatusNoContent)
	wantStatus(t, f.do(admin.authed(req{method: "PUT", path: "/api/users/" + uid + "/bindings", body: []map[string]any{{"role": "viewer", "group_id": nil}}})), http.StatusNoContent)
	resp = f.do(admin.authed(req{method: "POST", path: "/api/groups", body: map[string]any{"name": uniqueName("ag"), "parent_id": nil}}))
	wantStatus(t, resp, http.StatusCreated)
	gid := strconv.FormatInt(decode[idResp](t, resp).ID, 10)
	wantStatus(t, f.do(admin.authed(req{method: "PATCH", path: "/api/groups/" + gid, body: map[string]any{"name": uniqueName("ag")}})), http.StatusNoContent)
	wantStatus(t, f.do(admin.authed(req{method: "DELETE", path: "/api/groups/" + gid})), http.StatusNoContent)
	/* A refused change is audited as a failure. */
	wantError(t, f.do(admin.authed(req{method: "POST", path: "/api/users", body: map[string]string{"username": uniqueName("w"), "password": "short-pw"}})),
		http.StatusBadRequest, "weak_password")

	rows, err := f.env.Pool("nms_api").Query(context.Background(),
		`SELECT action, user_id, convert_from(payload, 'UTF8') FROM audit.event WHERE id > $1 ORDER BY id`, start)
	if err != nil {
		t.Fatal(err)
	}
	type rec struct{ result, objType, objID string }
	got := map[string][]rec{}
	for rows.Next() {
		var (
			action, payload string
			user            *int64
		)
		if err := rows.Scan(&action, &user, &payload); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(payload, goodPW) || strings.Contains(payload, "short-pw") || strings.Contains(payload, `"password"`) {
			t.Fatalf("audit payload leaks a password: %s", payload)
		}
		var ev struct {
			Result     string `json:"result"`
			ObjectType string `json:"object_type"`
			ObjectID   string `json:"object_id"`
			IP         string `json:"ip"`
		}
		if err := json.Unmarshal([]byte(payload), &ev); err != nil {
			t.Fatal(err)
		}
		if user == nil || *user != admin.uid || ev.IP != f.ip {
			t.Fatalf("%s: user %v ip %q, want admin %d from %s", action, user, ev.IP, admin.uid, f.ip)
		}
		got[action] = append(got[action], rec{ev.Result, ev.ObjectType, ev.ObjectID})
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := map[string][]rec{
		"users.create":  {{"success", "user", uid}, {"failure", "user", ""}},
		"users.update":  {{"success", "user", uid}},
		"bindings.set":  {{"success", "user", uid}},
		"groups.create": {{"success", "group", gid}},
		"groups.update": {{"success", "group", gid}},
		"groups.delete": {{"success", "group", gid}},
	}
	for a, w := range want {
		if fmt.Sprint(got[a]) != fmt.Sprint(w) {
			t.Errorf("%s: events %+v, want %+v", a, got[a], w)
		}
	}
}

func TestAuditListing(t *testing.T) {
	f := newFixture(t, nil)
	admin := f.login(true, rbac.Binding{Role: rbac.RoleAdmin})
	auditor := f.login(false, rbac.Binding{Role: rbac.RoleAuditor})
	for range 3 {
		wantStatus(t, f.do(admin.authed(req{method: "POST", path: "/api/groups", body: map[string]any{"name": uniqueName("l"), "parent_id": nil}})), http.StatusCreated)
	}
	resp := f.do(auditor.authed(req{method: "GET", path: "/api/audit?limit=2"}))
	wantStatus(t, resp, http.StatusOK)
	page := decode[[]auditResp](t, resp)
	if len(page) != 2 || page[0].ID <= page[1].ID || page[0].Action != "groups.create" || page[0].Result != "success" ||
		page[0].UserID == nil || *page[0].UserID != admin.uid || page[0].ObjectType != "group" || page[0].TS == "" {
		t.Fatalf("page = %+v", page)
	}
	resp = f.do(auditor.authed(req{method: "GET", path: fmt.Sprintf("/api/audit?limit=1&before_id=%d", page[1].ID)}))
	wantStatus(t, resp, http.StatusOK)
	next := decode[[]auditResp](t, resp)
	if len(next) != 1 || next[0].ID >= page[1].ID {
		t.Fatalf("next page = %+v", next)
	}
	resp = f.do(auditor.authed(req{method: "GET", path: "/api/audit"}))
	wantStatus(t, resp, http.StatusOK)
	if n := len(decode[[]auditResp](t, resp)); n == 0 || n > 50 {
		t.Fatalf("default page has %d events", n)
	}
	for _, q := range []string{"limit=0", "limit=201", "limit=x", "before_id=0", "before_id=-1", "before_id=x"} {
		wantError(t, f.do(auditor.authed(req{method: "GET", path: "/api/audit?" + q})), http.StatusBadRequest, "bad_request")
	}
}
