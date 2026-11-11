package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
)

type refusalCode string

func (r refusalCode) Error() string       { return string(r) }
func (r refusalCode) RefusalCode() string { return string(r) }

/*
The session routes: open answers a session's refusal as 422 with its code
and authz's as everywhere; attach and extend take the id from the path;
close takes only the bearer token (no token: 401); any other path under
/x/sessions is 404.
*/
func TestSessionRoutes(t *testing.T) {
	var gotID, gotToken, gotOp, gotParams string
	var gotIDs []int64
	var gotApproval string
	h := start(t, func(c *Config) {
		c.Sessions = &Sessions{
			Open: func(_ context.Context, req authz.Request, ids []int64, approval string) (any, error) {
				gotIDs, gotApproval = ids, approval
				switch req.Code {
				case "422":
					return nil, refusalCode("outside_window")
				case "403":
					return nil, authz.ErrDenied
				}
				return map[string]string{"session_id": "s"}, nil
			},
			Request: func(_ context.Context, _ authz.Request, ids []int64) (any, error) {
				gotIDs = ids
				return map[string]string{"request_id": "r"}, nil
			},
			Attach: func(_ context.Context, id string, _ authz.Request) (any, error) { gotID = id; return "a", nil },
			Extend: func(_ context.Context, id string, _ authz.Request) (any, error) { gotID = id; return "e", nil },
			Close: func(_ context.Context, id, token string) error {
				gotID, gotToken = id, token
				if token != "tok" {
					return errors.New("no session")
				}
				return nil
			},
			Act: func(_ context.Context, id, token, op string, params json.RawMessage) (any, error) {
				gotID, gotToken, gotOp, gotParams = id, token, op, string(params)
				if op == "save" {
					return nil, refusalCode("diff_changed")
				}
				return op, nil
			},
		}
	})
	h.setEnabled(true)
	want := []string{"POST /x/sessions", "POST /x/sessions/request", "POST /x/sessions/{id}/attach", "POST /x/sessions/{id}/extend", "POST /x/sessions/{id}/close",
		"POST /x/sessions/{id}/diff", "POST /x/sessions/{id}/save", "POST /x/sessions/{id}/commit", "POST /x/sessions/{id}/form",
		"POST /x/sessions/{id}/form-apply"}
	for _, r := range want {
		if !slices.Contains(h.srv.Routes(), r) {
			t.Errorf("route %s missing", r)
		}
	}
	const id = "0f1e2d3c-4b5a-4987-8a6b-5c4d3e2f1a0b"
	ip := 0
	do := func(path, body string, kv ...string) answer {
		ip++
		return h.do(t, http.MethodPost, path, body, hdr(append([]string{"X-Forwarded-For", fmt.Sprintf("192.0.2.%d", 100+ip)}, kv...)...))
	}
	if a := do("/x/sessions", `{"ticket":"t","totp":"1","device_ids":[3,4]}`); a.status != 200 || !slices.Equal(gotIDs, []int64{3, 4}) {
		t.Errorf("open: %d %v", a.status, gotIDs)
	}
	if a := do("/x/sessions", `{"ticket":"t","totp":"1","device_ids":[3],"approval":"ap1"}`); a.status != 200 || gotApproval != "ap1" {
		t.Errorf("open with an approval: %d %q", a.status, gotApproval)
	}
	if a := do("/x/sessions/request", `{"ticket":"t","totp":"1","device_ids":[5,6]}`); a.status != 200 || !slices.Equal(gotIDs, []int64{5, 6}) {
		t.Errorf("request: %d %v", a.status, gotIDs)
	}
	if a := do("/x/sessions/request", `{"ticket":"t","totp":"1","device_ids":[5],"approval":"x"}`); a.status != 400 {
		t.Errorf("request with an approval: %d", a.status)
	}
	if a := do("/x/sessions", `{"ticket":"t","totp":"422","device_ids":[3]}`); a.status != 422 || a.code != "outside_window" {
		t.Errorf("refusal: %d %s", a.status, a.code)
	}
	if a := do("/x/sessions", `{"ticket":"t","totp":"403","device_ids":[3]}`); a.status != 403 {
		t.Errorf("authz refusal: %d", a.status)
	}
	if a := do("/x/sessions/"+id+"/attach", `{"ticket":"t","totp":"1"}`); a.status != 200 || gotID != id {
		t.Errorf("attach: %d %s", a.status, gotID)
	}
	if a := do("/x/sessions/"+id+"/extend", `{"ticket":"t","totp":"1"}`); a.status != 200 {
		t.Errorf("extend: %d", a.status)
	}
	if a := do("/x/sessions/"+id+"/close", `{}`); a.status != 401 {
		t.Errorf("close without a token: %d", a.status)
	}
	if a := do("/x/sessions/"+id+"/close", `{}`, "Authorization", "Bearer tok"); a.status != 200 || gotToken != "tok" {
		t.Errorf("close: %d %s", a.status, gotToken)
	}
	/* the actions take the bearer token and hand their params on; a refusal is 422 with its code */
	if a := do("/x/sessions/"+id+"/diff", `{}`); a.status != 401 {
		t.Errorf("diff without a token: %d", a.status)
	}
	if a := do("/x/sessions/"+id+"/form-apply", `{"device_id":3}`, "Authorization", "Bearer tok"); a.status != 200 || gotOp != "form-apply" ||
		gotParams != `{"device_id":3}` || gotToken != "tok" || gotID != id {
		t.Errorf("form-apply: %d %s %s", a.status, gotOp, gotParams)
	}
	if a := do("/x/sessions/"+id+"/save", `{"device_id":3,"sha256":"x"}`, "Authorization", "Bearer tok"); a.status != 422 || a.code != "diff_changed" {
		t.Errorf("save refusal: %d %s", a.status, a.code)
	}
	if a := do("/x/sessions/"+id+"/close", `{"x":1}`, "Authorization", "Bearer tok"); a.status != 400 {
		t.Errorf("close with a body: %d", a.status)
	}
	for _, p := range []string{"/x/sessions/" + id, "/x/sessions/" + id + "/open", "/x/sessions/NOT-AN-ID/close", "/x/sessions/" + id + "/close/x"} {
		if a := do(p, `{}`); a.status != 404 {
			t.Errorf("%s: %d", p, a.status)
		}
	}
}
