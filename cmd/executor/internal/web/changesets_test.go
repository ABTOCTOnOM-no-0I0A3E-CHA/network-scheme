package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
)

type detailed struct{}

func (detailed) Error() string       { return "refused" }
func (detailed) RefusalCode() string { return "bad_line" }
func (detailed) RefusalDetail() any  { return map[string]any{"device_id": 7, "step": 2} }

/*
The changeset routes: open takes the ticket and TOTP and answers the
workspace; every op takes only the bearer token (none: 401) and its params,
up to maxChangesetBody; a refusal carries its detail; nothing else is
under /x/changesets.
*/
func TestChangesetRoutes(t *testing.T) {
	var gotOp, gotToken string
	var gotLen int
	h := start(t, func(c *Config) {
		c.Changesets = &Changesets{
			Open: func(_ context.Context, req authz.Request) (any, error) {
				if req.Code != "1" {
					return nil, authz.ErrDenied
				}
				return map[string]string{"token": "w"}, nil
			},
			Op: func(_ context.Context, token, op string, params json.RawMessage) (any, error) {
				gotOp, gotToken, gotLen = op, token, len(params)
				if op == "save" && gotLen < 100 {
					return nil, detailed{}
				}
				return op, nil
			},
			Ops: []string{"list", "save", "open", "a/b"},
		}
	})
	want := []string{"POST /x/changesets/open", "POST /x/changesets/list", "POST /x/changesets/save"}
	for _, r := range h.srv.Routes() {
		if strings.HasPrefix(r, "POST /x/changesets") && !slices.Contains(want, r) {
			t.Errorf("unexpected route %s", r)
		}
	}
	ip := 0
	do := func(path, body string, kv ...string) answer {
		ip++
		return h.do(t, http.MethodPost, path, body, hdr(append([]string{"X-Forwarded-For", fmt.Sprintf("192.0.2.%d", 100+ip)}, kv...)...))
	}
	if a := do("/x/changesets/open", `{"ticket":"t","totp":"1"}`); a.status != 200 {
		t.Errorf("open: %d", a.status)
	}
	if a := do("/x/changesets/open", `{"ticket":"t","totp":"2"}`); a.status != 403 {
		t.Errorf("open denied: %d", a.status)
	}
	if a := do("/x/changesets/list", `{}`); a.status != 401 {
		t.Errorf("list without a token: %d", a.status)
	}
	if a := do("/x/changesets/list", `{}`, "Authorization", "Bearer w"); a.status != 200 || gotOp != "list" || gotToken != "w" {
		t.Errorf("list: %d %s %s", a.status, gotOp, gotToken)
	}
	a := do("/x/changesets/save", `{"x":1}`, "Authorization", "Bearer w")
	if a.status != 422 || a.code != "bad_line" || !strings.Contains(a.body, `"detail":{"device_id":7,"step":2}`) {
		t.Errorf("refusal: %d %s", a.status, a.body)
	}
	/* a changeset body may exceed the 64 KiB of the other routes */
	big := `{"lines":"` + strings.Repeat("a", 200<<10) + `"}`
	if a := do("/x/changesets/save", big, "Authorization", "Bearer w"); a.status != 200 || gotLen != len(big) {
		t.Errorf("large save: %d (%d bytes)", a.status, gotLen)
	}
	if a := do("/x/changesets/save", `{"lines":"`+strings.Repeat("a", int(maxChangesetBody))+`"}`, "Authorization", "Bearer w"); a.status != 413 {
		t.Errorf("over the bound: %d", a.status)
	}
	for _, p := range []string{"/x/changesets", "/x/changesets/a/b", "/x/changesets/dry-run", "/x/changesets/open/x"} {
		if a := do(p, `{}`, "Authorization", "Bearer w"); a.status != 404 {
			t.Errorf("%s: %d", p, a.status)
		}
	}
}
