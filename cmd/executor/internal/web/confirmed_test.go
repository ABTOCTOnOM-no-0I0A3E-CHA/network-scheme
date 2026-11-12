package web

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/confirm"
)

type needRefusal struct{}

func (needRefusal) Error() string       { return "no such device" }
func (needRefusal) RefusalCode() string { return "bad_params" }

/* A read with NeedFor asks authz for the grant NeedFor computes from the params; its refusal answers before authz. */
func TestReadNeedFor(t *testing.T) {
	h := start(t, func(c *Config) {
		c.Reads = map[string]Read{"/x/things": {Action: "thing.list",
			NeedFor: func(_ context.Context, p json.RawMessage) (authz.Need, error) {
				if string(p) != `{"id":7}` {
					return authz.Need{}, needRefusal{}
				}
				return authz.Need{Kind: "unmask", Groups: []string{"core"}}, nil
			},
			Run: func(context.Context, authz.Decision, json.RawMessage) (any, error) { return "ok", nil }}}
	})
	if a := h.do(t, http.MethodPost, "/x/things", `{"ticket":"user-3","code":"1","params":{"id":8}}`, hdr()); a.status != 422 || h.auth.n() != 0 {
		t.Fatalf("refused need: %d %s, %d authz calls", a.status, a.body, h.auth.n())
	}
	if a := h.do(t, http.MethodPost, "/x/things", `{"ticket":"user-3","code":"1","params":{"id":7}}`, hdr()); a.status != http.StatusOK {
		t.Fatalf("read: %d %s", a.status, a.body)
	}
	if n := h.auth.call(0).Need; n.Kind != "unmask" || len(n.Groups) != 1 || n.Groups[0] != "core" {
		t.Fatalf("need %+v", n)
	}
}

/* configAction is a confirmed-only action of the tests: described like any other, without Run. */
var configAction = Action{
	Describe: func(context.Context, authz.Decision, json.RawMessage) (authz.Need, confirm.Description, error) {
		return authz.Need{Kind: "unmask", Groups: []string{"core"}}, confirm.Description{Action: "test.config",
			Fields: []confirm.Field{{Key: "device_id", Value: "7"}}}, nil
	},
}

/*
An action confirmed on its own route (4d.1): /x/confirm leaves its challenge
unspent (404 use_route, confirm not called), so does its route for another
action's challenge; on its route it is confirmed (with the path in authz's
audit details) and answered as JSON, or as a text/plain attachment with
nosniff and the executor's CSP; a refused confirmation runs nothing.
*/
func TestConfirmedRoutes(t *testing.T) {
	var runs int
	h := start(t, func(c *Config) {
		c.Actions["test.config"] = configAction
		c.Actions["test.export"] = Action{Describe: func(context.Context, authz.Decision, json.RawMessage) (authz.Need, confirm.Description, error) {
			return authz.Need{Kind: "unmask", Groups: []string{"core"}}, confirm.Description{Action: "test.export"}, nil
		}}
		c.Confirmed = []Confirmed{
			{Path: "/x/things/{id}", Re: regexp.MustCompile(`^/x/things/([0-9]+)$`), Action: "test.config",
				Run: func(_ context.Context, ch confirm.Challenge, _ authz.Decision, objs []string) (any, error) {
					runs++
					return map[string]string{"id": objs[0], "device": ch.Description.Fields[0].Value}, nil
				}},
			{Path: "/x/download/things/{id}", Re: regexp.MustCompile(`^/x/download/things/([0-9]+)$`), Action: "test.export",
				File: func(context.Context, confirm.Challenge, authz.Decision, []string) (string, []byte, error) {
					runs++
					return "thing-7.txt", []byte("<html>text</html>\n"), nil
				}},
		}
	})
	issue := func(action string) challengeBody {
		t.Helper()
		a := h.do(t, http.MethodPost, "/x/confirm/issue", `{"ticket":"user-3","action":"`+action+`","params":{}}`, hdr())
		var ch challengeBody
		if err := json.Unmarshal([]byte(a.body), &ch); err != nil || a.status != http.StatusOK {
			t.Fatalf("issue %s: %d %s", action, a.status, a.body)
		}
		return ch
	}
	body := func(ch challengeBody) string {
		return `{"ticket":"user-3","challenge_id":"` + ch.ID + `","h":"` + ch.H + `","code":"123456"}`
	}
	view, export := issue("test.config"), issue("test.export")
	for _, a := range []answer{
		h.do(t, http.MethodPost, "/x/confirm", body(view), hdr()),
		h.do(t, http.MethodPost, "/x/things/7", body(export), hdr()),
		h.do(t, http.MethodPost, "/x/download/things/7", body(view), hdr()),
	} {
		if a.status != http.StatusNotFound || a.code != "use_route" {
			t.Fatalf("wrong route: %d %s", a.status, a.body)
		}
	}
	if _, calls := h.conf.counts(); calls != 0 || runs != 0 {
		t.Fatalf("%d confirmations, %d runs on a wrong route", calls, runs)
	}
	a := h.do(t, http.MethodPost, "/x/things/7", body(view), hdr())
	if a.status != http.StatusOK || a.body != "{\"result\":{\"device\":\"7\",\"id\":\"7\"}}\n" {
		t.Fatalf("view: %d %s", a.status, a.body)
	}
	if d := h.conf.call(0).Details; d["path"] != "/x/things/7" {
		t.Fatalf("audit details %v", d)
	}
	a = h.do(t, http.MethodPost, "/x/download/things/7", body(export), hdr())
	hd := a.header
	if a.status != http.StatusOK || a.body != "<html>text</html>\n" || hd.Get("Content-Type") != "text/plain; charset=utf-8" ||
		hd.Get("Content-Disposition") != `attachment; filename="thing-7.txt"` || hd.Get("X-Content-Type-Options") != "nosniff" ||
		hd.Get("Content-Security-Policy") == "" || hd.Get("Cache-Control") != "no-store" {
		t.Fatalf("download: %d %v %q", a.status, hd, a.body)
	}
	h.conf.err = authz.ErrDenied
	if a := h.do(t, http.MethodPost, "/x/things/7", body(issue("test.config")), hdr()); a.status != http.StatusForbidden || runs != 2 {
		t.Fatalf("refused confirmation: %d %s, %d runs", a.status, a.body, runs)
	}
	/* a route-only action without Describe, with Run, or two routes on one path are refused at New */
	for _, bad := range [][]Confirmed{
		{{Path: "/x/a/{id}", Re: regexp.MustCompile(`^/x/a/([0-9]+)$`), Action: "test.echo", Run: func(context.Context, confirm.Challenge, authz.Decision, []string) (any, error) { return nil, nil }}},
		{{Path: "/x/a/{id}", Re: regexp.MustCompile(`^/x/a/([0-9]+)$`), Action: "test.none", Run: func(context.Context, confirm.Challenge, authz.Decision, []string) (any, error) { return nil, nil }}},
		{{Path: "/x/a/{id}", Re: regexp.MustCompile(`/x/a/([0-9]+)`), Action: "test.config", Run: func(context.Context, confirm.Challenge, authz.Decision, []string) (any, error) { return nil, nil }}},
	} {
		cfg := Config{Auth: &fakeAuth{}, Confirm: &fakeConfirm{}, State: func() (bool, bool) { return true, false }, Log: h.srv.c.Log,
			ExecutorOrigin: executorOrigin, PanelOrigin: panelOrigin, CertFile: h.certs.file("executor.crt"), KeyFile: h.certs.file("executor.key"),
			ClientCAFile: h.certs.file("ca.crt"), Actions: map[string]Action{"test.echo": testAction, "test.config": configAction}, Confirmed: bad}
		if _, err := New(cfg); err == nil {
			t.Fatalf("accepted %+v", bad[0])
		}
	}
}
