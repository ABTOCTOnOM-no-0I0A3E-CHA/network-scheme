package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/internal/execadmin"
	"github.com/beekamai/network-scheme/internal/execpolicy"
	"github.com/beekamai/network-scheme/internal/install"
)

/*
C1 below the gateway (plan 4a.9): the policy nmsctl install renders keeps the
executor off. Every request under /x/ but /x/status answers 503
executor_disabled before the route table: a route registered for POST
/x/sessions (a placeholder of 4c's that goes to authz, as the real one will)
never runs and authz is never asked (no audit row). nmsctl executor enable
(the same edit of the file and the same reload request) lets the same
requests go down the chain: the placeholder runs and authz refuses the
compromised api's ticket for a user without a change TOTP (403 denied,
audited); without the placeholder the path is 404. disable closes it again.
*/
func TestC1DisabledAfterInstallUntilEnabled(t *testing.T) {
	out, err := install.Render(install.RenderInput{PublicHost: "nms.test", ImageTag: "1.0.0", APIImage: "nms/api", GatewayImage: "nms/gateway"})
	if err != nil {
		t.Fatal(err)
	}
	r := startLiveWith(t, out[install.PolicyFile])
	if st := r.adm.Policy.Current(); st.Err != nil || st.Enabled() {
		t.Fatalf("installed policy: enabled %v, error %v; want a valid policy that disables", st.Enabled(), st.Err)
	}
	s, err := New(r.srv.c)
	if err != nil {
		t.Fatal(err)
	}
	var reached atomic.Int64
	s.routes = append(s.routes, route{http.MethodPost, "/x/sessions", func(w http.ResponseWriter, req *http.Request, ip string) {
		reached.Add(1)
		var body struct {
			Ticket string `json:"ticket"`
		}
		if !decode(w, req, &body) || !s.admit(w, body.Ticket) {
			return
		}
		_, err := s.c.Auth.Identify(req.Context(), authz.Request{Ticket: body.Ticket, Action: "session.open", Object: "placeholder",
			IP: ip, UA: req.UserAgent()})
		if err == nil {
			err = authz.ErrDenied /* no session exists in 4a */
		}
		refused(w, err)
	}, nil})
	call := func(method, path, body string) answer {
		t.Helper()
		req := httptest.NewRequest(method, "https://executor"+path, strings.NewReader(body))
		req.Host = "nms.test:8443"
		for k, v := range hdr() {
			req.Header[k] = v
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		var e errorBody
		_ = json.Unmarshal(w.Body.Bytes(), &e)
		return answer{w.Code, w.Header(), w.Body.String(), e.Error.Code}
	}
	atk := attacktest.NewAttacker(r.env, ticketPriv)
	session := func() string { return `{"ticket":"` + atk.Ticket(t, 990001, "nobody") + `"}` }
	confirmBody := `{"ticket":"forged.ticket","challenge_id":"c","h":"` + strings.Repeat("00", 32) + `","code":"000000"}`
	setEnabled := func(on bool) {
		t.Helper()
		data, err := os.ReadFile(r.polFile)
		if err != nil {
			t.Fatal(err)
		}
		next, err := execpolicy.SetEnabled(data, on)
		if err != nil {
			t.Fatal(err)
		}
		if err := install.ReplaceFile(r.polFile, next); err != nil {
			t.Fatal(err)
		}
		action := "disable"
		if on {
			action = "enable"
		}
		if resp := r.adm.Handle(context.Background(), execadmin.Request{V: execadmin.Version, Operator: "tester",
			Cmd: execadmin.CmdPolicyReload, Action: action}); !resp.OK {
			t.Fatalf("%s: %s", action, resp.Error)
		}
	}
	decisions := func() int {
		return r.audits(t, "session.open") + r.audits(t, "confirm.issue") + r.audits(t, "confirm.challenge")
	}
	disabled := func(when string) {
		t.Helper()
		before := decisions()
		for _, c := range []struct{ method, path, body string }{
			{http.MethodPost, "/x/sessions", session()},
			{http.MethodPost, "/x/confirm/issue", issueBody(atk.Ticket(t, 990001, "nobody"))},
			{http.MethodPost, "/x/confirm", confirmBody},
			{http.MethodGet, "/x/sessions", ""},
			{http.MethodPost, "/x/nowhere", "{}"},
		} {
			if a := call(c.method, c.path, c.body); a.status != http.StatusServiceUnavailable || a.code != "executor_disabled" {
				t.Errorf("%s: %s %s = %d %s", when, c.method, c.path, a.status, a.body)
			}
		}
		if a := r.do(t, http.MethodPost, "/x/sessions", session(), hdr()); a.status != http.StatusServiceUnavailable || a.code != "executor_disabled" {
			t.Errorf("%s: POST /x/sessions without a route = %d %s", when, a.status, a.body)
		}
		if n := reached.Load(); n != 0 {
			t.Errorf("%s: the route ran %d times", when, n)
		}
		if n := decisions() - before; n != 0 {
			t.Errorf("%s: %d decisions reached authz", when, n)
		}
		if a := call(http.MethodGet, "/x/status", ""); a.status != http.StatusOK || strings.TrimSpace(a.body) != `{"enabled":false,"frozen":false}` {
			t.Errorf("%s: status %d %s", when, a.status, a.body)
		}
	}

	disabled("after install")
	setEnabled(true)
	if a := call(http.MethodPost, "/x/sessions", session()); a.status != http.StatusForbidden || a.code != "denied" {
		t.Errorf("enabled: POST /x/sessions = %d %s, want authz's 403 denied", a.status, a.body)
	}
	if n, m := reached.Load(), r.audits(t, "session.open"); n != 1 || m != 1 {
		t.Errorf("enabled: the route ran %d times, %d audit rows; want 1 and 1", n, m)
	}
	if a := call(http.MethodPost, "/x/confirm", confirmBody); a.status != http.StatusForbidden || a.code != "denied" {
		t.Errorf("enabled: POST /x/confirm = %d %s", a.status, a.body)
	}
	if a := r.do(t, http.MethodPost, "/x/sessions", session(), hdr()); a.status != http.StatusNotFound {
		t.Errorf("enabled: POST /x/sessions without a route = %d %s", a.status, a.body)
	}
	if a := call(http.MethodGet, "/x/status", ""); strings.TrimSpace(a.body) != `{"enabled":true,"frozen":false}` {
		t.Errorf("enabled: status %d %s", a.status, a.body)
	}
	setEnabled(false)
	reached.Store(0)
	disabled("after disable")
}
