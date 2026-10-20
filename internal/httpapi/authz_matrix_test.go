package httpapi_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/internal/httpapi"
	"github.com/beekamai/network-scheme/internal/rbac"
)

/* subjects in the order the matrix exercises them; anon has no session. */
var subjectNames = []string{"anon", "viewer", "operator", "auditor", "admin"}

/* matrix: method+pattern -> expected status for each subject. */
var matrix = map[string]map[string]int{
	"GET /api/health":       {"anon": 200, "viewer": 200, "operator": 200, "auditor": 200, "admin": 200},
	"POST /api/auth/login":  {"anon": 200, "viewer": 200, "operator": 200, "auditor": 200, "admin": 200},
	"POST /api/auth/totp":   {"anon": 204, "viewer": 204, "operator": 204, "auditor": 204, "admin": 204},
	"POST /api/auth/enroll": {"anon": 200, "viewer": 200, "operator": 200, "auditor": 200, "admin": 200},
	"POST /api/auth/stepup": {"anon": 401, "viewer": 204, "operator": 204, "auditor": 204, "admin": 204},
	"POST /api/auth/logout": {"anon": 401, "viewer": 204, "operator": 204, "auditor": 204, "admin": 204},
	"GET /api/auth/me":      {"anon": 401, "viewer": 200, "operator": 200, "auditor": 200, "admin": 200},

	"GET /api/users":               {"anon": 401, "viewer": 403, "operator": 403, "auditor": 403, "admin": 200},
	"POST /api/users":              {"anon": 401, "viewer": 403, "operator": 403, "auditor": 403, "admin": 201},
	"PATCH /api/users/{id}":        {"anon": 401, "viewer": 403, "operator": 403, "auditor": 403, "admin": 204},
	"GET /api/users/{id}/bindings": {"anon": 401, "viewer": 403, "operator": 403, "auditor": 403, "admin": 200},
	"PUT /api/users/{id}/bindings": {"anon": 401, "viewer": 403, "operator": 403, "auditor": 403, "admin": 204},
	"GET /api/groups":              {"anon": 401, "viewer": 403, "operator": 403, "auditor": 403, "admin": 200},
	"POST /api/groups":             {"anon": 401, "viewer": 403, "operator": 403, "auditor": 403, "admin": 201},
	"PATCH /api/groups/{id}":       {"anon": 401, "viewer": 403, "operator": 403, "auditor": 403, "admin": 204},
	"DELETE /api/groups/{id}":      {"anon": 401, "viewer": 403, "operator": 403, "auditor": 403, "admin": 204},
	"GET /api/audit":               {"anon": 401, "viewer": 403, "operator": 403, "auditor": 200, "admin": 200},
}

/* subject is a logged-in user (nil for anon) whose session holds a fresh step-up. */
type subject struct {
	uid          int64
	sec          string
	cookie, csrf string
}

/* authed adds the subject's cookie and CSRF token to r. */
func (s *subject) authed(r req) req {
	if s != nil {
		r.cookie, r.csrf = s.cookie, s.csrf
	}
	return r
}

/* matrixEnv is a fixture with one subject per role and a spare user for login routes. */
type matrixEnv struct {
	*fixture
	subjects    map[string]*subject
	spare       string   /* enrolled user without bindings, logged in by the login routes */
	spareBackup []string /* its unused backup codes */
}

func (f *fixture) bind(uid int64, bs ...rbac.Binding) {
	f.t.Helper()
	ctx := context.Background()
	st := rbac.NewStore(f.env.Pool("nms_api"))
	if err := pgx.BeginFunc(ctx, f.env.Pool("nms_api"), func(tx pgx.Tx) error {
		return st.SetBindings(ctx, tx, uid, bs)
	}); err != nil {
		f.t.Fatalf("bind %d: %v", uid, err)
	}
}

/* login creates a user with bindings bs and logs it in; stepUp also refreshes the step-up. */
func (f *fixture) login(stepUp bool, bs ...rbac.Binding) *subject {
	f.t.Helper()
	name := uniqueName("subj")
	s := &subject{uid: f.createUser(name)}
	f.bind(s.uid, bs...)
	s.sec, s.cookie = f.enroll(name)
	s.csrf = f.me(s.cookie).CSRFToken
	if stepUp {
		f.stepUp(s)
	}
	return s
}

/* stepUp moves the clock to a new TOTP step and steps the session up. */
func (f *fixture) stepUp(s *subject) {
	f.t.Helper()
	f.clk.Advance(30 * time.Second)
	resp := f.do(s.authed(req{method: "POST", path: "/api/auth/stepup", body: map[string]string{"code": totpCode(f.t, s.sec, f.clk.Now())}}))
	if resp.StatusCode != http.StatusNoContent {
		f.t.Fatalf("stepup status %d", resp.StatusCode)
	}
	s.cookie, _ = sessionCookie(f.t, resp)
}

func newMatrixEnv(t *testing.T) *matrixEnv {
	t.Helper()
	m := &matrixEnv{fixture: newFixture(t, nil), subjects: map[string]*subject{"anon": nil}}
	for _, n := range subjectNames[1:] {
		m.subjects[n] = m.login(false, rbac.Binding{Role: rbac.Role(n)})
	}
	/* One clock step for all: each user has its own TOTP replay counter. */
	m.clk.Advance(30 * time.Second)
	for _, n := range subjectNames[1:] {
		s := m.subjects[n]
		resp := m.do(s.authed(req{method: "POST", path: "/api/auth/stepup", body: map[string]string{"code": totpCode(t, s.sec, m.clk.Now())}}))
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("%s stepup status %d", n, resp.StatusCode)
		}
		s.cookie, _ = sessionCookie(t, resp)
	}
	m.spare = uniqueName("spare")
	m.createUser(m.spare)
	_, _, m.spareBackup = m.enrollCodes(m.spare)
	return m
}

func (m *matrixEnv) group() int64 {
	m.t.Helper()
	ctx := context.Background()
	var id int64
	if err := pgx.BeginFunc(ctx, m.env.Pool("nms_api"), func(tx pgx.Tx) error {
		var err error
		id, err = rbac.NewStore(m.env.Pool("nms_api")).CreateGroup(ctx, tx, nil, uniqueName("grp"))
		return err
	}); err != nil {
		m.t.Fatal(err)
	}
	return id
}

func (m *matrixEnv) loginSpare() string {
	m.t.Helper()
	resp := m.do(req{method: "POST", path: "/api/auth/login", body: map[string]string{"username": m.spare, "password": goodPW}})
	lr := decode[loginResp](m.t, resp)
	if lr.Stage != "totp" {
		m.t.Fatalf("spare login = %+v", lr)
	}
	return lr.Challenge
}

/*
validRequest builds a request for route key that is valid in every respect
except authorization, with fresh targets so that every subject's request
could succeed on its own.
*/
func (m *matrixEnv) validRequest(key string, s *subject) req {
	m.t.Helper()
	switch key {
	case "GET /api/health":
		return req{method: "GET", path: "/api/health"}
	case "POST /api/auth/login":
		return req{method: "POST", path: "/api/auth/login", body: map[string]string{"username": m.spare, "password": goodPW}}
	case "POST /api/auth/totp":
		code := m.spareBackup[0]
		m.spareBackup = m.spareBackup[1:]
		return req{method: "POST", path: "/api/auth/totp", body: map[string]string{"challenge": m.loginSpare(), "code": code}}
	case "POST /api/auth/enroll":
		name := uniqueName("enr")
		m.createUser(name)
		lr := decode[loginResp](m.t, m.do(req{method: "POST", path: "/api/auth/login", body: map[string]string{"username": name, "password": goodPW}}))
		u, err := url.Parse(lr.OTPAuthURI)
		if err != nil {
			m.t.Fatal(err)
		}
		return req{method: "POST", path: "/api/auth/enroll", body: map[string]string{
			"challenge": lr.Challenge, "code": totpCode(m.t, u.Query().Get("secret"), m.clk.Now()),
		}}
	case "POST /api/auth/stepup":
		code := "000000"
		if s != nil {
			m.clk.Advance(30 * time.Second)
			code = totpCode(m.t, s.sec, m.clk.Now())
		}
		return req{method: "POST", path: "/api/auth/stepup", body: map[string]string{"code": code}}
	case "POST /api/auth/logout":
		return req{method: "POST", path: "/api/auth/logout"}
	case "GET /api/auth/me":
		return req{method: "GET", path: "/api/auth/me"}
	case "GET /api/users":
		return req{method: "GET", path: "/api/users"}
	case "POST /api/users":
		return req{method: "POST", path: "/api/users", body: map[string]string{"username": uniqueName("new"), "password": goodPW}}
	case "PATCH /api/users/{id}":
		return req{method: "PATCH", path: fmt.Sprintf("/api/users/%d", m.createUser(uniqueName("tgt"))), body: map[string]bool{"disabled": true}}
	case "GET /api/users/{id}/bindings":
		return req{method: "GET", path: fmt.Sprintf("/api/users/%d/bindings", m.subjects["viewer"].uid)}
	case "PUT /api/users/{id}/bindings":
		return req{method: "PUT", path: fmt.Sprintf("/api/users/%d/bindings", m.createUser(uniqueName("tgt"))),
			body: []map[string]any{{"role": "viewer", "group_id": nil}, {"role": "operator", "group_id": m.group()}}}
	case "GET /api/groups":
		return req{method: "GET", path: "/api/groups"}
	case "POST /api/groups":
		return req{method: "POST", path: "/api/groups", body: map[string]any{"name": uniqueName("g"), "parent_id": m.group()}}
	case "PATCH /api/groups/{id}":
		return req{method: "PATCH", path: fmt.Sprintf("/api/groups/%d", m.group()), body: map[string]any{"name": uniqueName("r"), "parent_id": nil}}
	case "DELETE /api/groups/{id}":
		return req{method: "DELETE", path: fmt.Sprintf("/api/groups/%d", m.group())}
	case "GET /api/audit":
		return req{method: "GET", path: "/api/audit?limit=5"}
	}
	m.t.Fatalf("no valid request for %s", key)
	return req{}
}

func routeKeys() []string {
	var keys []string
	for _, r := range httpapi.Routes() {
		keys = append(keys, r.Method+" "+r.Pattern)
	}
	return keys
}

func TestEveryRouteInMatrix(t *testing.T) {
	keys := routeKeys()
	for _, k := range keys {
		row, ok := matrix[k]
		if !ok {
			t.Errorf("route %s has no matrix row", k)
			continue
		}
		for _, n := range subjectNames {
			if _, ok := row[n]; !ok {
				t.Errorf("matrix row %s lacks subject %s", k, n)
			}
		}
		if len(row) != len(subjectNames) {
			t.Errorf("matrix row %s has unknown subjects: %v", k, row)
		}
	}
	for k := range matrix {
		if !slices.Contains(keys, k) {
			t.Errorf("matrix row %s matches no registered route", k)
		}
	}
}

func TestAuthzMatrix(t *testing.T) {
	m := newMatrixEnv(t)
	keys := routeKeys()
	/* Logout ends the sessions the other rows need, so it runs last. */
	keys = append(slices.DeleteFunc(keys, func(k string) bool { return k == "POST /api/auth/logout" }), "POST /api/auth/logout")
	for _, k := range keys {
		for _, n := range subjectNames {
			s := m.subjects[n]
			resp := m.do(s.authed(m.validRequest(k, s)))
			want := matrix[k][n]
			if resp.StatusCode != want {
				b, _ := io.ReadAll(resp.Body)
				t.Errorf("%s as %s: status %d, want %d; body %s", k, n, resp.StatusCode, want, b)
				continue
			}
			switch want {
			case http.StatusUnauthorized:
				wantError(t, resp, want, "unauthenticated")
			case http.StatusForbidden:
				wantError(t, resp, want, "forbidden")
			}
			if k == "POST /api/auth/stepup" && want == http.StatusNoContent {
				s.cookie, _ = sessionCookie(t, resp)
			}
		}
	}
}

func TestStepUpEnforced(t *testing.T) {
	m := newMatrixEnv(t)
	/* A fresh login has no step-up. */
	admin := m.login(false, rbac.Binding{Role: rbac.RoleAdmin})
	n := 0
	for _, r := range httpapi.Routes() {
		if !r.Policy.StepUp {
			continue
		}
		n++
		k := r.Method + " " + r.Pattern
		wantError(t, m.do(admin.authed(m.validRequest(k, admin))), http.StatusForbidden, "stepup_required")
	}
	if n == 0 {
		t.Fatal("no step-up routes registered")
	}
	/* Step-up lapses after 5 minutes. */
	m.stepUp(admin)
	m.clk.Advance(5*time.Minute + time.Second)
	wantError(t, m.do(admin.authed(m.validRequest("POST /api/users", admin))), http.StatusForbidden, "stepup_required")
}

func TestRBACLoadErrorIs500(t *testing.T) {
	var d httpapi.Deps
	f := newFixture(t, func(dd *httpapi.Deps) { d = *dd })
	s := f.login(true, rbac.Binding{Role: rbac.RoleAdmin})
	/* Sessions still resolve, but loading the role bindings fails. */
	broken, err := pgxpool.NewWithConfig(context.Background(), d.Pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	broken.Close()
	d.RBAC = rbac.NewStore(broken)
	f.h = httpapi.NewRouter(d)
	wantError(t, f.do(s.authed(req{method: "GET", path: "/api/users"})), http.StatusInternalServerError, "internal")
}
