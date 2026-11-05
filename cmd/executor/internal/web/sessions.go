package web

import (
	"context"
	"net/http"
	"regexp"
	"strings"

	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
)

/*
Sessions are the change session routes (session.Manager, 4c.2):

  - POST /x/sessions {ticket, totp, device_ids}: open, the answer carries
    the bearer token of the session (the UI keeps it in memory only);
  - POST /x/sessions/{id}/attach {ticket, totp}: a new token for the
    session's own user (the old one stops working);
  - POST /x/sessions/{id}/extend {ticket, totp}: session_minutes from now;
  - POST /x/sessions/{id}/close {} with Authorization: Bearer <token>.

A refusal of the session's own rules answers 422 with its code (Refusal),
authz's as everywhere (refused).
*/
type Sessions struct {
	Open   func(ctx context.Context, req authz.Request, devices []int64) (any, error)
	Attach func(ctx context.Context, id string, req authz.Request) (any, error)
	Extend func(ctx context.Context, id string, req authz.Request) (any, error)
	Close  func(ctx context.Context, id, token string) error
}

var sessionRe = regexp.MustCompile(`^/x/sessions/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/(attach|extend|close)$`)

/* addSessions adds the session routes when the server has them. */
func (s *Server) addSessions() {
	if s.c.Sessions == nil {
		return
	}
	s.routes = append(s.routes, route{method: http.MethodPost, path: "/x/sessions", handle: s.openSession})
	for _, op := range []string{"attach", "extend", "close"} {
		re := regexp.MustCompile(`^/x/sessions/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/` + op + `$`)
		s.routes = append(s.routes, route{method: http.MethodPost, path: "/x/sessions/{id}/" + op, re: re, handle: s.sessionOp})
	}
}

type sessionRequest struct {
	Ticket  string  `json:"ticket"`
	TOTP    string  `json:"totp"`
	Devices []int64 `json:"device_ids"`
}

type sessionAuth struct {
	Ticket string `json:"ticket"`
	TOTP   string `json:"totp"`
}

func sessionAnswer(w http.ResponseWriter, res any, err error) {
	if err != nil {
		if !actionRefused(w, err) {
			refused(w, err)
		}
		return
	}
	reply(w, http.StatusOK, map[string]any{"result": res})
}

func (s *Server) openSession(w http.ResponseWriter, r *http.Request, ip string) {
	var req sessionRequest
	if !decode(w, r, &req) || !s.admit(w, req.Ticket) {
		return
	}
	res, err := s.c.Sessions.Open(r.Context(), authz.Request{Ticket: req.Ticket, Code: req.TOTP, IP: ip, UA: r.UserAgent()}, req.Devices)
	sessionAnswer(w, res, err)
}

func (s *Server) sessionOp(w http.ResponseWriter, r *http.Request, ip string) {
	m := sessionRe.FindStringSubmatch(r.URL.Path)
	if m == nil {
		fail(w, http.StatusNotFound, "not_found")
		return
	}
	id, op := m[1], m[2]
	if op == "close" {
		var none struct{}
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !decode(w, r, &none) || !s.admit(w, "") {
			return
		}
		if !ok || tok == "" || len(tok) > 128 {
			fail(w, http.StatusUnauthorized, "no_token")
			return
		}
		sessionAnswer(w, map[string]bool{"closed": true}, s.c.Sessions.Close(r.Context(), id, tok))
		return
	}
	var req sessionAuth
	if !decode(w, r, &req) || !s.admit(w, req.Ticket) {
		return
	}
	ar := authz.Request{Ticket: req.Ticket, Code: req.TOTP, IP: ip, UA: r.UserAgent()}
	var (
		res any
		err error
	)
	if op == "attach" {
		res, err = s.c.Sessions.Attach(r.Context(), id, ar)
	} else {
		res, err = s.c.Sessions.Extend(r.Context(), id, ar)
	}
	sessionAnswer(w, res, err)
}
