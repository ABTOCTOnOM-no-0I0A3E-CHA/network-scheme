package httpapi_test

import (
	"context"
	"crypto/ed25519"
	"net/http"
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
