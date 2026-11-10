package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
)

/*
Changesets are the changeset workspace routes (package changeset, task
5.2):

  - POST /x/changesets/open {ticket, totp}: the bearer token of the user's
    changeset workspace (the UI keeps it in memory only);
  - POST /x/changesets/{op} {params} with Authorization: Bearer <token>,
    op one of Ops: every one decided again by the changeset package on the
    registry (the grants of the changeset's groups, now).

The approval of a changeset is a confirm(H) action on a route of its own
(Confirmed: POST /x/changesets/{id}/approve/{count}). A body may be as large
as maxChangesetBody: a changeset carries its lines.
*/
type Changesets struct {
	Open func(ctx context.Context, req authz.Request) (any, error)
	Op   func(ctx context.Context, token, op string, params json.RawMessage) (any, error)
	Ops  []string /* list, get, save, ... ([a-z-]{1,32}, never "open") */
}

/* maxChangesetBody bounds a changeset request (a revision is at most changeset.MaxContent). */
var maxChangesetBody int64 = 1 << 20

/* addChangesets adds the changeset routes when the server has them. */
func (s *Server) addChangesets() {
	if s.c.Changesets == nil {
		return
	}
	s.routes = append(s.routes, route{method: http.MethodPost, path: "/x/changesets/open", handle: s.openChangesets})
	for _, op := range s.c.Changesets.Ops {
		if op == "open" || !readPath.MatchString("/x/"+op) || strings.Contains(op, "/") {
			continue
		}
		s.routes = append(s.routes, route{method: http.MethodPost, path: "/x/changesets/" + op, handle: func(w http.ResponseWriter, r *http.Request, _ string) {
			s.changesetOp(w, r, op)
		}})
	}
}

func (s *Server) openChangesets(w http.ResponseWriter, r *http.Request, ip string) {
	var req sessionAuth
	if !decode(w, r, &req) || !s.admit(w, req.Ticket) {
		return
	}
	res, err := s.c.Changesets.Open(r.Context(), authz.Request{Ticket: req.Ticket, Code: req.TOTP, IP: ip, UA: r.UserAgent()})
	sessionAnswer(w, res, err)
}

func (s *Server) changesetOp(w http.ResponseWriter, r *http.Request, op string) {
	var params json.RawMessage
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !decodeLimit(w, r, &params, maxChangesetBody) || !s.admit(w, "") {
		return
	}
	if !ok || tok == "" || len(tok) > 128 {
		fail(w, http.StatusUnauthorized, "no_token")
		return
	}
	res, err := s.c.Changesets.Op(r.Context(), tok, op, params)
	sessionAnswer(w, res, err)
}
