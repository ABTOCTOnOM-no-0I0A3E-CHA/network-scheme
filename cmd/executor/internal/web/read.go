package web

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
)

/*
Read is an authorized read (e.g. POST /x/devices, /x/devices/probe): the
ticket and the user's change TOTP code, decided and audited by authz with
Need as Action, then Run as the decided user with the request's params. The
grant comes from the executor's code, never from the client.
*/
type Read struct {
	Action string
	Need   authz.Need
	Run    func(ctx context.Context, by authz.Decision, params json.RawMessage) (any, error)
}

var readPath = regexp.MustCompile(`^/x/[a-z0-9-]{1,32}(/[a-z0-9-]{1,32})?$`)

/* addReads adds a POST route per read, after the fixed routes (a read never replaces one). */
func (s *Server) addReads() error {
	paths := make([]string, 0, len(s.c.Reads))
	for p := range s.c.Reads {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	for _, p := range paths {
		rd := s.c.Reads[p]
		taken := slices.ContainsFunc(s.routes, func(r route) bool { return r.path == p }) || strings.HasPrefix(p, "/x/confirm")
		if !readPath.MatchString(p) || taken || rd.Run == nil || !rd.Need.Valid() {
			return fmt.Errorf("web: bad read %q", p)
		}
		s.routes = append(s.routes, route{http.MethodPost, p, func(w http.ResponseWriter, r *http.Request, ip string) { s.read(w, r, ip, p, rd) }})
	}
	return nil
}

type readRequest struct {
	Ticket string          `json:"ticket"`
	Code   string          `json:"code"`
	Params json.RawMessage `json:"params,omitempty"`
}

/*
read runs one authorized read: the bounded JSON body, the limits, authz
(ticket, TOTP, grant, audit), then Run. Run's own refusal answers as an
action's (Refusal: 422 with its code), a freeze 503 frozen, anything else
503 unavailable.
*/
func (s *Server) read(w http.ResponseWriter, r *http.Request, ip, path string, rd Read) {
	var req readRequest
	if !decode(w, r, &req) {
		return
	}
	if !s.admit(w, req.Ticket) {
		return
	}
	by, err := s.c.Auth.Authorize(r.Context(), authz.Request{Ticket: req.Ticket, Code: req.Code, Need: rd.Need, Action: rd.Action,
		Object: path, IP: ip, UA: r.UserAgent()})
	if err != nil {
		refused(w, err)
		return
	}
	res, err := rd.Run(r.Context(), by, req.Params)
	if err != nil {
		s.c.Log.Info("web: read refused or failed", slog.String("path", path), slog.Any("err", err))
		if !actionRefused(w, err) {
			fail(w, http.StatusServiceUnavailable, "unavailable")
		}
		return
	}
	reply(w, http.StatusOK, map[string]any{"result": res})
}
