package httpapi_test

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/httpapi"
	"github.com/beekamai/network-scheme/internal/rbac"
	"github.com/beekamai/network-scheme/internal/ticket"
)

/* ticketKey signs the tickets of every fixture (the executor's ticket.pub would be its public half). */
var ticketKey = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

type ticketResp struct {
	Ticket    string    `json:"ticket"`
	ExpiresAt time.Time `json:"expires_at"`
}

/*
POST /api/executor/ticket: only a logged-in user gets one, for itself, signed
with the api's key and verifiable by the executor's; every issue is audited
with the ticket's id (never the token), and the answer is not cached.
*/
func TestExecutorTicketIssue(t *testing.T) {
	f := newFixture(t, nil)
	wantError(t, f.do(req{method: "POST", path: "/api/executor/ticket"}), http.StatusUnauthorized, "unauthenticated")
	v := f.login(false, rbac.Binding{Role: rbac.RoleViewer})
	/* Without the CSRF token the cookie session gets nothing. */
	wantError(t, f.do(req{method: "POST", path: "/api/executor/ticket", cookie: v.cookie}), http.StatusForbidden, "csrf")
	resp := f.do(v.authed(req{method: "POST", path: "/api/executor/ticket"}))
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("status %d, Cache-Control %q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
	tr := decode[ticketResp](t, resp)
	c, err := ticket.Verify(ticketKey.Public().(ed25519.PublicKey), tr.Ticket, f.clk.Now())
	if err != nil {
		t.Fatal(err)
	}
	var name string
	if err := f.env.Pool("postgres").QueryRow(context.Background(), `SELECT username FROM core."user" WHERE id = $1`, v.uid).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if c.UserID != v.uid || c.Username != name || c.IssuedAt != f.clk.Now().Unix() || !tr.ExpiresAt.Equal(time.Unix(c.Expires, 0)) {
		t.Fatalf("claims %+v for #%d %q, expires_at %v", c, v.uid, name, tr.ExpiresAt)
	}
	var details map[string]any
	if err := f.env.Pool("postgres").QueryRow(context.Background(), `SELECT convert_from(payload, 'UTF8')::jsonb->'details' FROM audit.event
		WHERE action = 'executor.ticket' AND (convert_from(payload, 'UTF8')::jsonb->>'user_id')::bigint = $1`, v.uid).Scan(&details); err != nil {
		t.Fatal(err)
	}
	if details["ticket"] != c.ID() || details["expires"] != float64(c.Expires) || len(details) != 2 {
		t.Fatalf("audit details %v", details)
	}
}

/* A disabled user gets no ticket: its session ends, and the handler reads the user again in its own transaction too. */
func TestExecutorTicketDisabledUser(t *testing.T) {
	f := newFixture(t, nil)
	v := f.login(false, rbac.Binding{Role: rbac.RoleViewer})
	if _, err := f.env.Pool("postgres").Exec(context.Background(), `UPDATE core."user" SET disabled = true WHERE id = $1`, v.uid); err != nil {
		t.Fatal(err)
	}
	resp := f.do(v.authed(req{method: "POST", path: "/api/executor/ticket"}))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("disabled user: %d", resp.StatusCode)
	}
}

/* No ticket key configured: nothing is signed. */
func TestExecutorTicketWithoutKey(t *testing.T) {
	f := newFixture(t, func(d *httpapi.Deps) { d.TicketKey = nil })
	v := f.login(false, rbac.Binding{Role: rbac.RoleViewer})
	wantError(t, f.do(v.authed(req{method: "POST", path: "/api/executor/ticket"})), http.StatusInternalServerError, "internal")
}

/* 20 tickets a minute per user; refusals are audited once a minute; other users are not affected. */
func TestExecutorTicketRateLimit(t *testing.T) {
	f := newFixture(t, nil)
	v := f.login(false, rbac.Binding{Role: rbac.RoleViewer})
	for i := 0; i < 20; i++ {
		if r := f.do(v.authed(req{method: "POST", path: "/api/executor/ticket"})); r.StatusCode != http.StatusOK {
			t.Fatalf("ticket %d: %d", i+1, r.StatusCode)
		}
	}
	wantError(t, f.do(v.authed(req{method: "POST", path: "/api/executor/ticket"})), http.StatusTooManyRequests, "rate_limited")
	wantError(t, f.do(v.authed(req{method: "POST", path: "/api/executor/ticket"})), http.StatusTooManyRequests, "rate_limited")
	if n := auditCount(t, f, "executor.ticket", "success", v.uid); n != 20 {
		t.Errorf("%d audit records of issued tickets, want 20", n)
	}
	if n := auditCount(t, f, "executor.ticket", "failure", v.uid); n != 1 {
		t.Errorf("%d audit records of refused tickets in a minute, want 1", n)
	}
	other := f.login(false, rbac.Binding{Role: rbac.RoleViewer})
	if r := f.do(other.authed(req{method: "POST", path: "/api/executor/ticket"})); r.StatusCode != http.StatusOK {
		t.Fatalf("other user: %d", r.StatusCode)
	}
	f.clk.Advance(61 * time.Second)
	if r := f.do(v.authed(req{method: "POST", path: "/api/executor/ticket"})); r.StatusCode != http.StatusOK {
		t.Fatalf("after a minute: %d", r.StatusCode)
	}
}

/* clearExecpub empties the execpub rows the executor tests use, now and at the end. */
func clearExecpub(t *testing.T, f *fixture) {
	t.Helper()
	wipe := func() {
		if _, err := f.env.Pool("postgres").Exec(context.Background(),
			`DELETE FROM execpub.freeze_request; DELETE FROM execpub.status; DELETE FROM execpub.session_summary`); err != nil {
			t.Fatal(err)
		}
	}
	wipe()
	t.Cleanup(wipe)
}

/*
POST /api/executor/freeze: a global admin with a fresh step-up inserts the
single pending request (202, 202 again while one is pending); every call is
audited with whether one was already pending; the body is ignored, so
nothing it says can lift a freeze. A group admin or a stale step-up gets
nothing in.
*/
func TestExecutorFreezeRequest(t *testing.T) {
	f := newFixture(t, nil)
	clearExecpub(t, f)
	pending := func() (n int, by int64) {
		t.Helper()
		if err := f.env.Pool("postgres").QueryRow(context.Background(),
			`SELECT count(*), coalesce(max(requested_by), 0) FROM execpub.freeze_request`).Scan(&n, &by); err != nil {
			t.Fatal(err)
		}
		return n, by
	}
	g := f.newGroup()
	groupAdmin := f.login(true, rbac.Binding{Role: rbac.RoleAdmin, GroupID: &g})
	wantError(t, f.do(groupAdmin.authed(req{method: "POST", path: "/api/executor/freeze"})), http.StatusForbidden, "forbidden")
	admin := f.login(false, rbac.Binding{Role: rbac.RoleAdmin})
	wantError(t, f.do(admin.authed(req{method: "POST", path: "/api/executor/freeze"})), http.StatusForbidden, "stepup_required")
	if n, _ := pending(); n != 0 {
		t.Fatalf("%d requests after refused calls", n)
	}
	f.stepUp(admin)
	for i, body := range []any{nil, map[string]any{"frozen": false, "off": true, "freeze": "off"}} {
		if resp := f.do(admin.authed(req{method: "POST", path: "/api/executor/freeze", body: body})); resp.StatusCode != http.StatusAccepted {
			t.Fatalf("call %d: status %d", i, resp.StatusCode)
		}
		if n, by := pending(); n != 1 || by != admin.uid {
			t.Fatalf("call %d: %d pending, requested by %d", i, n, by)
		}
	}
	if n := auditCount(t, f, "executor.freeze", "success", admin.uid); n != 2 {
		t.Fatalf("%d audit records, want 2", n)
	}
	var inserted, already bool
	if err := f.env.Pool("postgres").QueryRow(context.Background(), `
		SELECT bool_or(NOT (convert_from(payload, 'UTF8')::jsonb->'details'->>'already_pending')::bool),
		       bool_or((convert_from(payload, 'UTF8')::jsonb->'details'->>'already_pending')::bool)
		FROM audit.event WHERE action = 'executor.freeze' AND (convert_from(payload, 'UTF8')::jsonb->>'user_id')::bigint = $1`,
		admin.uid).Scan(&inserted, &already); err != nil || !inserted || !already {
		t.Fatalf("audit details: inserted %v, already pending %v, err %v", inserted, already, err)
	}
	/* The step-up lapses: no further request. */
	f.clk.Advance(5*time.Minute + time.Second)
	wantError(t, f.do(admin.authed(req{method: "POST", path: "/api/executor/freeze"})), http.StatusForbidden, "stepup_required")
}

/*
No route of the panel lifts a freeze or touches the executor beyond the
ticket, the freeze request and the two reads; /api/executor/freeze answers
only POST.
*/
func TestNoRouteLiftsFreeze(t *testing.T) {
	want := map[string]bool{"POST /api/executor/ticket": true, "POST /api/executor/freeze": true,
		"GET /api/executor/status": true, "GET /api/devices/{id}/sessions": true}
	for _, r := range httpapi.Routes() {
		k := r.Method + " " + r.Pattern
		lower := strings.ToLower(k)
		touches := strings.Contains(lower, "executor") || strings.Contains(lower, "freeze") || strings.Contains(lower, "session")
		if touches && !want[k] {
			t.Errorf("unexpected executor route %s", k)
		}
		delete(want, k)
		for _, word := range []string{"unfreeze", "thaw", "/off", "unlock", "grant", "enroll"} {
			if touches && strings.Contains(lower, word) {
				t.Errorf("route %s looks like a host-only operation (%s)", k, word)
			}
		}
	}
	for k := range want {
		t.Errorf("route %s missing", k)
	}
	f := newFixture(t, nil)
	admin := f.login(true, rbac.Binding{Role: rbac.RoleAdmin})
	for _, m := range []string{"GET", "PUT", "PATCH", "DELETE"} {
		wantError(t, f.do(admin.authed(req{method: m, path: "/api/executor/freeze"})), http.StatusMethodNotAllowed, "method_not_allowed")
	}
	for _, p := range []string{"/api/executor/unfreeze", "/api/executor/freeze/off", "/api/executor/status/frozen"} {
		for _, m := range []string{"POST", "PUT", "DELETE"} {
			wantError(t, f.do(admin.authed(req{method: m, path: p})), http.StatusNotFound, "not_found")
		}
	}
}

type execStatusResp struct {
	Known   bool       `json:"known"`
	Enabled bool       `json:"enabled"`
	Frozen  bool       `json:"frozen"`
	At      *time.Time `json:"at"`
	Stale   bool       `json:"stale"`
}

/* GET /api/executor/status: unknown before the executor published, then its row; stale after 90 s by the database clock. */
func TestExecutorStatus(t *testing.T) {
	f := newFixture(t, nil)
	clearExecpub(t, f)
	op := f.login(false, rbac.Binding{Role: rbac.RoleOperator})
	get := func() execStatusResp {
		t.Helper()
		resp := f.do(op.authed(req{method: "GET", path: "/api/executor/status"}))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d", resp.StatusCode)
		}
		return decode[execStatusResp](t, resp)
	}
	if s := get(); s.Known || s.Enabled || s.Frozen || s.At != nil || s.Stale {
		t.Fatalf("never published: %+v", s)
	}
	exe := f.env.Pool("nms_executor")
	if _, err := exe.Exec(context.Background(), `INSERT INTO execpub.status (enabled, frozen) VALUES (true, true)`); err != nil {
		t.Fatal(err)
	}
	if s := get(); !s.Known || !s.Enabled || !s.Frozen || s.At == nil || s.Stale {
		t.Fatalf("fresh: %+v", s)
	}
	if _, err := exe.Exec(context.Background(), `UPDATE execpub.status SET frozen = false, at = now() - interval '91 seconds'`); err != nil {
		t.Fatal(err)
	}
	if s := get(); !s.Known || s.Frozen || !s.Stale {
		t.Fatalf("old row: %+v", s)
	}
}

type sessionsResp struct {
	Items []struct {
		SessionID  string     `json:"session_id"`
		UserID     int64      `json:"user_id"`
		Username   *string    `json:"username"`
		OpenedAt   time.Time  `json:"opened_at"`
		ClosedAt   *time.Time `json:"closed_at"`
		Status     string     `json:"status"`
		PostSHA256 *string    `json:"post_sha256"`
	} `json:"items"`
}

/*
GET /api/devices/{id}/sessions: the device's sessions newest first with the
user's current name and a post hash prefix; another device's sessions never
show; a device outside the caller's groups is 404, as a missing one.
*/
func TestDeviceSessions(t *testing.T) {
	f := newFixture(t, nil)
	clearExecpub(t, f)
	ga, gb := f.newGroup(), f.newGroup()
	dev, other, foreign := f.newDevice(ga), f.newDevice(ga), f.newDevice(gb)
	v := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &ga})
	var name string
	if err := f.env.Pool("postgres").QueryRow(context.Background(), `SELECT username FROM core."user" WHERE id = $1`, v.uid).Scan(&name); err != nil {
		t.Fatal(err)
	}
	exe := f.env.Pool("nms_executor")
	for _, row := range []struct {
		id, status   string
		uid, device  int64
		opened, post string
	}{
		{"00000000-0000-0000-0000-000000000001", "closed", v.uid, dev, "2 hours", "ab"},
		{"00000000-0000-0000-0000-000000000002", "open", 999999999, dev, "5 minutes", ""},
		{"00000000-0000-0000-0000-000000000003", "open", v.uid, other, "0 s", ""},
		{"00000000-0000-0000-0000-000000000004", "open", v.uid, foreign, "0 s", ""},
	} {
		if _, err := exe.Exec(context.Background(), `INSERT INTO execpub.session_summary (session_id, user_id, device_id, opened_at, closed_at, status, post_sha256)
			VALUES ($1, $2, $3, now() - $4::interval, CASE WHEN $5 = 'closed' THEN now() - interval '1 hour' END, $5,
			        CASE WHEN $6 <> '' THEN decode(repeat($6, 32), 'hex') END)`,
			row.id, row.uid, row.device, row.opened, row.status, row.post); err != nil {
			t.Fatal(err)
		}
	}
	resp := f.do(v.authed(req{method: "GET", path: fmt.Sprintf("/api/devices/%d/sessions", dev)}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	got := decode[sessionsResp](t, resp).Items
	if len(got) != 2 || got[0].SessionID != "00000000-0000-0000-0000-000000000002" || got[0].Status != "open" ||
		got[0].Username != nil || got[0].ClosedAt != nil || got[0].PostSHA256 != nil ||
		got[1].Username == nil || *got[1].Username != name || got[1].Status != "closed" || got[1].ClosedAt == nil ||
		got[1].PostSHA256 == nil || *got[1].PostSHA256 != "abababababab" {
		t.Fatalf("sessions %+v", got)
	}
	resp = f.do(v.authed(req{method: "GET", path: fmt.Sprintf("/api/devices/%d/sessions?limit=1", dev)}))
	if l := decode[sessionsResp](t, resp).Items; len(l) != 1 || l[0].SessionID != "00000000-0000-0000-0000-000000000002" {
		t.Fatalf("limit 1: %+v", l)
	}
	wantError(t, f.do(v.authed(req{method: "GET", path: fmt.Sprintf("/api/devices/%d/sessions", foreign)})), http.StatusNotFound, "not_found")
	wantError(t, f.do(v.authed(req{method: "GET", path: "/api/devices/999999999/sessions"})), http.StatusNotFound, "not_found")
	for _, q := range []string{"limit=0", "limit=201", "limit=x", "limit=1&limit=2"} {
		wantError(t, f.do(v.authed(req{method: "GET", path: fmt.Sprintf("/api/devices/%d/sessions?%s", dev, q)})), http.StatusBadRequest, "bad_request")
	}
}
