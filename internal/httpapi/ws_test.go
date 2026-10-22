package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/httpapi"
	"github.com/beekamai/network-scheme/internal/notify"
	"github.com/beekamai/network-scheme/internal/rbac"
)

const wsWait = 5 * time.Second

/* wsEnv is a fixture served over a real listener, with a hub and fast re-checks. */
type wsEnv struct {
	*fixture
	hub *notify.Hub
	srv *httptest.Server
}

func newWSEnv(t *testing.T, mutate func(*httpapi.Deps)) *wsEnv {
	t.Helper()
	hub := notify.NewHub()
	f := newFixture(t, func(d *httpapi.Deps) {
		d.Hub, d.WSRecheck, d.WSHeartbeat = hub, 50*time.Millisecond, time.Hour
		if mutate != nil {
			mutate(d)
		}
	})
	srv := httptest.NewServer(f.h)
	t.Cleanup(srv.Close)
	return &wsEnv{fixture: f, hub: hub, srv: srv}
}

func (e *wsEnv) dialRaw(s *subject, origin string) (*websocket.Conn, *http.Response, error) {
	hdr := http.Header{}
	if origin != "" {
		hdr.Set("Origin", origin)
	}
	if s != nil {
		hdr.Set("Cookie", cookieName+"="+s.cookie)
	}
	ctx, cancel := context.WithTimeout(context.Background(), wsWait)
	defer cancel()
	return websocket.Dial(ctx, "ws"+strings.TrimPrefix(e.srv.URL, "http")+"/api/ws", &websocket.DialOptions{HTTPHeader: hdr})
}

func (e *wsEnv) dial(s *subject) *websocket.Conn {
	e.t.Helper()
	c, _, err := e.dialRaw(s, publicOrigin)
	if err != nil {
		e.t.Fatalf("dial: %v", err)
	}
	e.t.Cleanup(func() { _ = c.CloseNow() })
	return c
}

type wsIn struct {
	Type    string `json:"type"`
	Event   string `json:"event"`
	Problem struct {
		ID int64 `json:"id"`
	} `json:"problem"`
}

func read(t *testing.T, c *websocket.Conn) wsIn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wsWait)
	defer cancel()
	_, b, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var m wsIn
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("decode %q: %v", b, err)
	}
	return m
}

/* wantClosed waits for the server to end the socket and returns the close status (-1: dropped without one). */
func wantClosed(t *testing.T, c *websocket.Conn) websocket.StatusCode {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wsWait)
	defer cancel()
	for {
		if _, _, err := c.Read(ctx); err != nil {
			if ctx.Err() != nil {
				t.Fatal("socket still open")
			}
			return websocket.CloseStatus(err)
		}
	}
}

func problem(id int64, group *int64, sev string) notify.Message {
	return notify.Message{Type: "problem", Event: notify.EventOpened,
		Problem: notify.ProblemSummary{ID: id, GroupID: group, Severity: sev, State: "problem", Name: "x"}}
}

func (e *wsEnv) subgroup(parent int64) int64 {
	e.t.Helper()
	ctx := context.Background()
	var id int64
	if err := pgx.BeginFunc(ctx, e.env.Pool("nms_api"), func(tx pgx.Tx) (err error) {
		id, err = rbac.NewStore(e.env.Pool("nms_api")).CreateGroup(ctx, tx, &parent, uniqueName("sub"))
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
	return id
}

func TestWSRefusesUnauthenticatedAndForeignOrigin(t *testing.T) {
	e := newWSEnv(t, nil)
	g := e.newGroup()
	s := e.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &g})
	auditor := e.login(false, rbac.Binding{Role: rbac.RoleAuditor})
	for name, tc := range map[string]struct {
		s      *subject
		origin string
		status int
	}{
		"no cookie":       {nil, publicOrigin, http.StatusUnauthorized},
		"foreign origin":  {s, "https://evil.example", http.StatusForbidden},
		"http origin":     {s, "http://nms.test", http.StatusForbidden},
		"null origin":     {s, "null", http.StatusForbidden},
		"missing origin":  {s, "", http.StatusForbidden},
		"no devices.read": {auditor, publicOrigin, http.StatusForbidden},
		"bad cookie":      {&subject{cookie: "bogus"}, publicOrigin, http.StatusUnauthorized},
	} {
		t.Run(name, func(t *testing.T) {
			c, resp, err := e.dialRaw(tc.s, tc.origin)
			if err == nil {
				_ = c.CloseNow()
				t.Fatal("upgrade succeeded")
			}
			if resp == nil || resp.StatusCode != tc.status {
				t.Fatalf("status = %v, want %d (err %v)", resp, tc.status, err)
			}
		})
	}
	e.dial(s) /* the same user with a proper Origin gets in */
}

func TestWSDeliversOnlyProblemsInScope(t *testing.T) {
	e := newWSEnv(t, nil)
	gA, gB := e.newGroup(), e.newGroup()
	subA := e.subgroup(gA)
	viewerA := e.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &gA})
	viewerB := e.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &gB})
	global := e.login(false, rbac.Binding{Role: rbac.RoleViewer})
	cA, cB, cG := e.dial(viewerA), e.dial(viewerB), e.dial(global)

	/* 1: group A, 2: device-less system problem, 3: descendant of A, 4: group B. */
	e.hub.Publish(problem(1, &gA, "high"))
	e.hub.Publish(problem(2, nil, "high"))
	e.hub.Publish(problem(3, &subA, "high"))
	e.hub.Publish(problem(4, &gB, "high"))

	for _, want := range []int64{1, 3} {
		if m := read(t, cA); m.Type != "problem" || m.Event != "opened" || m.Problem.ID != want {
			t.Fatalf("viewer A got %+v, want problem %d", m, want)
		}
	}
	if m := read(t, cB); m.Problem.ID != 4 {
		t.Fatalf("viewer B first got problem %d, want 4 (group B only)", m.Problem.ID)
	}
	for _, want := range []int64{1, 2, 3, 4} {
		if m := read(t, cG); m.Problem.ID != want {
			t.Fatalf("global viewer got problem %d, want %d", m.Problem.ID, want)
		}
	}
	/* A's sentinel arrives after A's problems and B's connection never saw A's. */
	e.hub.Publish(problem(5, &gB, "high"))
	if m := read(t, cB); m.Problem.ID != 5 {
		t.Fatalf("viewer B got %d, want 5", m.Problem.ID)
	}
	e.hub.Publish(problem(6, &gA, "high"))
	if m := read(t, cA); m.Problem.ID != 6 {
		t.Fatalf("viewer A got %d, want 6 (no foreign leftovers)", m.Problem.ID)
	}
}

func TestWSPingSubscribeAndInvalidFrames(t *testing.T) {
	e := newWSEnv(t, nil)
	g := e.newGroup()
	s := e.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &g})
	ctx := context.Background()

	c := e.dial(s)
	if err := c.Write(ctx, websocket.MessageText, []byte(`{"type":"ping"}`)); err != nil {
		t.Fatal(err)
	}
	if m := read(t, c); m.Type != "pong" {
		t.Fatalf("reply to ping = %+v", m)
	}
	if err := c.Write(ctx, websocket.MessageText, []byte(`{"type":"subscribe","severity_min":"high"}`)); err != nil {
		t.Fatal(err)
	}
	if m := read(t, c); m.Type != "subscribed" {
		t.Fatalf("reply to subscribe = %+v", m)
	}
	e.hub.Publish(problem(1, &g, "warning"))
	e.hub.Publish(problem(2, &g, "disaster"))
	if m := read(t, c); m.Problem.ID != 2 {
		t.Fatalf("got problem %d, want 2 (warning is below severity_min)", m.Problem.ID)
	}

	for name, tc := range map[string]struct {
		typ  websocket.MessageType
		data string
		want websocket.StatusCode
	}{
		"unknown type":     {websocket.MessageText, `{"type":"publish"}`, websocket.StatusPolicyViolation},
		"unknown field":    {websocket.MessageText, `{"type":"ping","x":1}`, websocket.StatusPolicyViolation},
		"not json":         {websocket.MessageText, `ping`, websocket.StatusPolicyViolation},
		"trailing data":    {websocket.MessageText, `{"type":"ping"}{"type":"ping"}`, websocket.StatusPolicyViolation},
		"bad severity_min": {websocket.MessageText, `{"type":"subscribe","severity_min":"loud"}`, websocket.StatusPolicyViolation},
		"binary frame":     {websocket.MessageBinary, `{"type":"ping"}`, websocket.StatusPolicyViolation},
		"oversize frame":   {websocket.MessageText, `{"type":"ping","pad":"` + strings.Repeat("a", 1100) + `"}`, websocket.StatusMessageTooBig},
	} {
		t.Run(name, func(t *testing.T) {
			c := e.dial(s)
			if err := c.Write(ctx, tc.typ, []byte(tc.data)); err != nil {
				t.Fatal(err)
			}
			if got := wantClosed(t, c); got != tc.want {
				t.Fatalf("close status = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestWSConnectionCapPerSession(t *testing.T) {
	e := newWSEnv(t, nil)
	g := e.newGroup()
	s := e.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &g})
	other := e.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &g})
	conns := make([]*websocket.Conn, 4)
	for i := range conns {
		conns[i] = e.dial(s)
	}
	_, resp, err := e.dialRaw(s, publicOrigin)
	if err == nil || resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("5th connection: resp %v err %v, want 429", resp, err)
	}
	e.dial(other) /* another session is unaffected */
	_ = conns[0].Close(websocket.StatusNormalClosure, "")
	deadline := time.Now().Add(wsWait)
	for {
		c, _, err := e.dialRaw(s, publicOrigin)
		if err == nil {
			_ = c.CloseNow()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a freed slot was never released: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestWSClosesOnLogoutExpiryAndRevocation(t *testing.T) {
	e := newWSEnv(t, nil)
	gA, gB := e.newGroup(), e.newGroup()
	viewerBoth := func() *subject {
		return e.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &gA}, rbac.Binding{Role: rbac.RoleViewer, GroupID: &gB})
	}

	t.Run("logout", func(t *testing.T) {
		s := viewerBoth()
		c := e.dial(s)
		if resp := e.do(s.authed(req{method: "POST", path: "/api/auth/logout"})); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("logout status %d", resp.StatusCode)
		}
		if got := wantClosed(t, c); got != websocket.StatusPolicyViolation {
			t.Fatalf("close status = %d, want 1008", got)
		}
	})
	t.Run("session expiry", func(t *testing.T) {
		s := viewerBoth()
		c := e.dial(s)
		e.clk.Advance(31 * time.Minute) /* idle timeout is 30 minutes */
		if got := wantClosed(t, c); got != websocket.StatusPolicyViolation {
			t.Fatalf("close status = %d, want 1008", got)
		}
	})
	t.Run("binding shrinks", func(t *testing.T) {
		s := viewerBoth()
		c := e.dial(s)
		e.bind(s.uid, rbac.Binding{Role: rbac.RoleViewer, GroupID: &gA})
		if got := wantClosed(t, c); got != websocket.StatusPolicyViolation {
			t.Fatalf("close status = %d, want 1008", got)
		}
	})
	t.Run("bindings removed", func(t *testing.T) {
		s := viewerBoth()
		c := e.dial(s)
		e.bind(s.uid)
		if got := wantClosed(t, c); got != websocket.StatusPolicyViolation {
			t.Fatalf("close status = %d, want 1008", got)
		}
	})
	t.Run("role loses devices.read", func(t *testing.T) {
		s := viewerBoth()
		c := e.dial(s)
		e.bind(s.uid, rbac.Binding{Role: rbac.RoleAuditor})
		if got := wantClosed(t, c); got != websocket.StatusPolicyViolation {
			t.Fatalf("close status = %d, want 1008", got)
		}
	})
	t.Run("growth keeps the socket and widens the feed", func(t *testing.T) {
		s := e.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &gA})
		c := e.dial(s)
		e.hub.Publish(problem(1, &gB, "high"))
		e.bind(s.uid, rbac.Binding{Role: rbac.RoleViewer, GroupID: &gA}, rbac.Binding{Role: rbac.RoleViewer, GroupID: &gB})
		time.Sleep(500 * time.Millisecond) /* several re-check intervals */
		e.hub.Publish(problem(2, &gB, "high"))
		if m := read(t, c); m.Problem.ID != 2 {
			t.Fatalf("got problem %d, want 2 (1 predates the wider scope)", m.Problem.ID)
		}
	})
}

func TestWSClosesWhenHeartbeatIsNotAnswered(t *testing.T) {
	e := newWSEnv(t, func(d *httpapi.Deps) { d.WSHeartbeat = 100 * time.Millisecond })
	g := e.newGroup()
	s := e.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &g})
	c := e.dial(s)
	/* The client library answers pings only while reading: stay silent past 2 beats. */
	time.Sleep(600 * time.Millisecond)
	if got := wantClosed(t, c); got == websocket.StatusNormalClosure {
		t.Fatalf("close status = %d, want a policy close or drop", got)
	}
}

func TestWSInboundFrameRateLimit(t *testing.T) {
	e := newWSEnv(t, nil)
	g := e.newGroup()
	s := e.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &g})
	c := e.dial(s)
	ctx, cancel := context.WithTimeout(context.Background(), wsWait)
	defer cancel()
	for range 40 {
		if err := c.Write(ctx, websocket.MessageText, []byte(`{"type":"ping"}`)); err != nil {
			break
		}
	}
	if got := wantClosed(t, c); got != websocket.StatusPolicyViolation {
		t.Fatalf("flooding client closed with %d, want 1008", got)
	}
}

func TestWSClosesWithFrameOnShutdown(t *testing.T) {
	down := make(chan struct{})
	e := newWSEnv(t, func(d *httpapi.Deps) { d.Shutdown = down })
	g := e.newGroup()
	c := e.dial(e.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &g}))
	close(down)
	if got := wantClosed(t, c); got != websocket.StatusGoingAway {
		t.Fatalf("shutdown closed with %d, want 1001", got)
	}
}
