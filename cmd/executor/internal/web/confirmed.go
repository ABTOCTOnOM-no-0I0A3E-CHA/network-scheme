package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/confirm"
)

/*
Confirmed is an action confirmed with confirm(H) on a route of its own
instead of /x/confirm (4d.1: POST /x/configs/{device}/{version} and
/x/download/configs/{device}/{version}), with the body of /x/confirm
{ticket, challenge_id, h, code}. Its Action is described through
/x/confirm/issue like any other (Actions[Action], without Run: /x/confirm
leaves its challenges unspent) and only a challenge of that action is
confirmed here; the route's objects (Re's submatches) go to Run or File,
which check them against the confirmed description.
*/
type Confirmed struct {
	Path   string         /* the route as Routes shows it */
	Re     *regexp.Regexp /* the whole path; its submatches are the objects */
	Action string
	/* Run answers JSON {"result": ...}; File, instead, a text/plain attachment of that name. */
	Run  func(ctx context.Context, c confirm.Challenge, by authz.Decision, objs []string) (any, error)
	File func(ctx context.Context, c confirm.Challenge, by authz.Decision, objs []string) (name string, body []byte, err error)
}

var fileName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

/* addConfirmed adds a POST route per Confirmed, after every other route. */
func (s *Server) addConfirmed() error {
	for _, c := range s.c.Confirmed {
		act, ok := s.c.Actions[c.Action]
		taken := slices.ContainsFunc(s.routes, func(r route) bool { return r.path == c.Path })
		if !ok || act.Describe == nil || act.Run != nil || (c.Run == nil) == (c.File == nil) || c.Re == nil || taken ||
			!strings.HasPrefix(c.Re.String(), "^/x/") || !strings.HasSuffix(c.Re.String(), "$") {
			return fmt.Errorf("web: bad confirmed route %q", c.Path)
		}
		s.routes = append(s.routes, route{http.MethodPost, c.Path, func(w http.ResponseWriter, r *http.Request, ip string) { s.confirmed(w, r, ip, c) }, c.Re})
	}
	return nil
}

/*
confirmed runs one: the body, the limits, a challenge of the route's action
(another stays unspent: 404), confirm.Store and authz (ticket, the user's
change TOTP code, the grant; audited), then Run or File.
*/
func (s *Server) confirmed(w http.ResponseWriter, r *http.Request, ip string, c Confirmed) {
	var req confirmRequest
	if !decode(w, r, &req) {
		return
	}
	objs := c.Re.FindStringSubmatch(r.URL.Path)
	h, err := hex.DecodeString(req.H)
	if objs == nil || err != nil || len(h) != sha256.Size || len(req.ChallengeID) > 64 {
		fail(w, http.StatusBadRequest, "bad_request")
		return
	}
	if !s.admit(w, req.Ticket) {
		return
	}
	if a, ok := s.c.Confirm.Action(req.ChallengeID); ok && a != c.Action {
		fail(w, http.StatusNotFound, "use_route")
		return
	}
	/* the path (device and version) goes into authz's audit row, refusals included */
	ch, by, err := s.c.Confirm.Confirm(r.Context(), req.ChallengeID, h, authz.Request{Ticket: req.Ticket, Code: req.Code,
		IP: ip, UA: r.UserAgent(), Details: map[string]any{"path": r.URL.Path}})
	if err != nil {
		refused(w, err)
		return
	}
	if ch.Action != c.Action { /* only if the challenge appeared between the check and the confirmation */
		fail(w, http.StatusNotFound, "use_route")
		return
	}
	if c.Run != nil {
		res, err := c.Run(r.Context(), ch, by, objs[1:])
		if err != nil {
			s.confirmedFailed(w, c, err)
			return
		}
		reply(w, http.StatusOK, map[string]any{"result": res})
		return
	}
	name, body, err := c.File(r.Context(), ch, by, objs[1:])
	if err != nil {
		s.confirmedFailed(w, c, err)
		return
	}
	if !fileName.MatchString(name) {
		name = "download.txt"
	}
	hd := w.Header()
	hd.Set("Content-Type", "text/plain; charset=utf-8")
	hd.Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) confirmedFailed(w http.ResponseWriter, c Confirmed, err error) {
	if actionRefused(w, err) {
		return
	}
	s.c.Log.Error("web: confirmed action failed", slog.String("action", c.Action), slog.Any("err", err))
	fail(w, http.StatusServiceUnavailable, "unavailable")
}
