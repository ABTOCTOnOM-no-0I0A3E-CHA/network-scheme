// Package httpapi is the HTTP API of the panel: router, middleware and handlers.
package httpapi

import (
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/internal/auth"
	"github.com/beekamai/network-scheme/internal/config"
	"github.com/beekamai/network-scheme/internal/rbac"
)

// Deps are the dependencies of the API router.
type Deps struct {
	Auth          *auth.Service
	RBAC          *rbac.Store
	Pool          *pgxpool.Pool /* for handlers that open their own transactions */
	Cfg           config.API
	Clock         func() time.Time /* for handlers that timestamp records */
	Logger        *slog.Logger     /* nil: slog.Default() */
	AuthRateLimit int              /* requests per minute per client IP on credential endpoints; 0: 10 */
}

/*
Policy is the access rule of a route. A non-public route needs a live
session and Perm (rbac.PermSelf for the user's own account); StepUp
additionally needs a step-up TOTP within the last 5 minutes.
*/
type Policy struct {
	Public bool
	Perm   rbac.Perm
	StepUp bool
}

// RouteSpec is one registered route and its policy (the authorization matrix input).
type RouteSpec struct {
	Method, Pattern string
	Policy          Policy
}

/* credentialPaths take the strict per-IP rate limit: each request checks a secret. */
var credentialPaths = map[string]bool{
	"/api/auth/login":  true,
	"/api/auth/totp":   true,
	"/api/auth/enroll": true,
	"/api/auth/stepup": true,
}

/* Concurrent Argon2 verifications (64 MiB each) and how long an excess login waits. */
const (
	maxConcurrentLogins = 4
	loginQueueWait      = 2 * time.Second
)

type server struct {
	auth      *auth.Service
	rbac      *rbac.Store
	cfg       config.API
	log       *slog.Logger
	generalRL *httprate.RateLimiter
	authRL    *httprate.RateLimiter
	loginSem  chan struct{}
	loginWait time.Duration
}

func newServer(d Deps) *server {
	s := &server{
		auth: d.Auth, rbac: d.RBAC, cfg: d.Cfg, log: d.Logger,
		loginSem: make(chan struct{}, maxConcurrentLogins), loginWait: loginQueueWait,
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	authLimit := d.AuthRateLimit
	if authLimit <= 0 {
		authLimit = defaultAuthLimit
	}
	s.generalRL, s.authRL = newLimiter(generalRateLimit), newLimiter(authLimit)
	return s
}

// NewRouter returns the API handler.
func NewRouter(d Deps) http.Handler { return newServer(d).handler() }

func (s *server) handler() http.Handler {
	r := chi.NewRouter()
	r.Use(withRequestID, s.recoverer, securityHeaders, limitBody, s.withClientIP,
		s.rateLimit, s.withSession, checkCSRF)
	r.NotFound(func(w http.ResponseWriter, _ *http.Request) { writeError(w, errNotFound) })
	r.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) { writeError(w, errMethodNotAllowed) })

	public := Policy{Public: true}
	self := Policy{Perm: rbac.PermSelf}
	s.route(r, http.MethodGet, "/api/health", public, s.health)
	s.route(r, http.MethodPost, "/api/auth/login", public, s.login)
	s.route(r, http.MethodPost, "/api/auth/totp", public, s.totp)
	s.route(r, http.MethodPost, "/api/auth/enroll", public, s.enroll)
	s.route(r, http.MethodPost, "/api/auth/stepup", self, s.stepUp)
	s.route(r, http.MethodPost, "/api/auth/logout", self, s.logout)
	s.route(r, http.MethodGet, "/api/auth/me", self, s.me)
	return r
}

/*
route is the only way to register an endpoint: it binds h to its policy so
that Routes can enumerate every route. A policy that grants nothing explicit
(non-public without Perm) or mixes public with a permission panics at start.
*/
func (s *server) route(r chi.Router, method, pattern string, p Policy, h http.HandlerFunc) {
	if p.Public == (p.Perm != "") || (p.Public && p.StepUp) {
		panic(fmt.Sprintf("httpapi: invalid policy %+v for %s %s", p, method, pattern))
	}
	r.Method(method, pattern, &policyHandler{s: s, p: p, h: h})
}

/* policyHandler enforces a route's Policy before its handler runs. */
type policyHandler struct {
	s *server
	p Policy
	h http.HandlerFunc
}

func (ph *policyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if ph.p.Public {
		ph.h(w, r)
		return
	}
	sc, ok := sessionFrom(r.Context())
	switch {
	case !ok:
		writeError(w, errUnauthenticated)
		return
	case !sc.valid:
		writeError(w, errSessionExpired)
		return
	}
	if ph.p.Perm != rbac.PermSelf {
		subj, err := ph.s.rbac.LoadSubject(r.Context(), sc.sess.UserID)
		if err != nil {
			ph.s.fail(w, r, err)
			return
		}
		if !subj.Can(ph.p.Perm, nil, nil) {
			writeError(w, errForbidden)
			return
		}
	}
	if ph.p.StepUp && !sc.sess.StepUpValid {
		writeError(w, errStepUpRequired)
		return
	}
	ph.h(w, r)
}

/*
Routes lists every registered route with its policy, sorted by pattern and
method. It panics if a route was registered other than through route.
*/
func Routes() []RouteSpec {
	var out []RouteSpec
	err := chi.Walk(newServer(Deps{}).handler().(chi.Routes),
		func(method, pattern string, h http.Handler, _ ...func(http.Handler) http.Handler) error {
			for {
				ch, ok := h.(*chi.ChainHandler)
				if !ok {
					break
				}
				h = ch.Endpoint
			}
			ph, ok := h.(*policyHandler)
			if !ok {
				return fmt.Errorf("httpapi: %s %s registered without route()", method, pattern)
			}
			out = append(out, RouteSpec{Method: method, Pattern: pattern, Policy: ph.p})
			return nil
		})
	if err != nil {
		panic(err)
	}
	slices.SortFunc(out, func(a, b RouteSpec) int {
		if c := strings.Compare(a.Pattern, b.Pattern); c != 0 {
			return c
		}
		return strings.Compare(a.Method, b.Method)
	})
	return out
}
