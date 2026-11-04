package web

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
)

/* Authorize is Identify for the fake: it records the request and answers with err. */
func (f *fakeAuth) Authorize(ctx context.Context, req authz.Request) (authz.Decision, error) {
	return f.Identify(ctx, req)
}

/*
A read is its own POST route after the fixed ones; its grant and audit
action are the read's, never the client's; a refusal of authz answers as
such and Run is not called; Run's failure is 503 (frozen: frozen).
*/
func TestAuthorizedRead(t *testing.T) {
	runs := 0
	var fail error
	rd := Read{Action: "device.list", Need: authz.Need{Kind: "write-admin"}, Run: func(_ context.Context, by authz.Decision) (any, error) {
		runs++
		return []int64{by.UserID}, fail
	}}
	h := start(t, func(c *Config) { c.Reads = map[string]Read{"/x/devices": rd} })
	if got := h.srv.Routes(); !slices.Equal(got, []string{"GET /x/status", "POST /x/confirm/issue", "POST /x/confirm", "POST /x/devices"}) {
		t.Fatalf("routes %v", got)
	}
	a := h.do(t, http.MethodPost, "/x/devices", `{"ticket":"user-4","code":"123456"}`, hdr())
	if a.status != http.StatusOK || strings.TrimSpace(a.body) != `{"result":[4]}` {
		t.Fatalf("read: %d %s", a.status, a.body)
	}
	if c := h.auth.call(0); c.Action != "device.list" || c.Need.Kind != "write-admin" || c.Code != "123456" || c.Object != "/x/devices" {
		t.Fatalf("authz got %+v", c)
	}
	if a := h.do(t, http.MethodPost, "/x/devices", `{"ticket":"user-4","code":"1","need":"unmask"}`, hdr()); a.status != http.StatusBadRequest {
		t.Errorf("unknown field: %d", a.status)
	}
	h.auth.set(authz.ErrDenied)
	if a := h.do(t, http.MethodPost, "/x/devices", `{"ticket":"user-4","code":"1"}`, hdr()); a.status != http.StatusForbidden || runs != 1 {
		t.Errorf("denied: %d, runs %d", a.status, runs)
	}
	h.auth.set(nil)
	fail = errors.New("db down")
	if a := h.do(t, http.MethodPost, "/x/devices", `{"ticket":"user-4","code":"1"}`, hdr()); a.status != http.StatusServiceUnavailable || a.code != "unavailable" {
		t.Errorf("failed run: %d %s", a.status, a.body)
	}
	fail = authz.ErrFrozen
	if a := h.do(t, http.MethodPost, "/x/devices", `{"ticket":"user-4","code":"1"}`, hdr()); a.status != http.StatusServiceUnavailable || a.code != "frozen" {
		t.Errorf("frozen run: %d %s", a.status, a.body)
	}
	for _, p := range []string{"/x/confirm", "/x/status", "/x/a/b", "/y/devices"} {
		if _, err := New(withReads(h, map[string]Read{p: rd})); err == nil {
			t.Errorf("read at %s accepted", p)
		}
	}
	if _, err := New(withReads(h, map[string]Read{"/x/other": {Action: "x", Need: authz.Need{Kind: "nope"}, Run: rd.Run}})); err == nil {
		t.Error("read with a bad grant accepted")
	}
}

func withReads(h *harness, reads map[string]Read) Config {
	c := h.srv.c
	c.Reads = reads
	return c
}
