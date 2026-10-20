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
	Users         *auth.UserStore
	RBAC          *rbac.Store
	Pool          *pgxpool.Pool /* for handlers that open their own transactions */
	Devices       DeviceLookup  /* object checks of group-scoped device routes */
	Cfg           config.API
	Clock         func() time.Time /* timestamps of audit records; nil: time.Now */
	Logger        *slog.Logger     /* nil: slog.Default() */
	AuthRateLimit int              /* requests per minute per client IP on credential endpoints; 0: 10 */
}

/*
Policy is the access rule of a route. A non-public route needs a live
session and Perm (rbac.PermSelf for the user's own account); StepUp
additionally needs a step-up TOTP within the last 5 minutes. Scoped admits
on Perm held in any binding and leaves the object check to the handler.
*/
type Policy struct {
	Public bool
	Perm   rbac.Perm
	StepUp bool
	Scoped bool
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
	users     *auth.UserStore
	rbac      *rbac.Store
	pool      *pgxpool.Pool
	devices   DeviceLookup
	now       func() time.Time
	cfg       config.API
	log       *slog.Logger
	generalRL *httprate.RateLimiter
	authRL    *httprate.RateLimiter
	loginSem  chan struct{}
	loginWait time.Duration
}

func newServer(d Deps) *server {
	s := &server{
		auth: d.Auth, users: d.Users, rbac: d.RBAC, pool: d.Pool, devices: d.Devices, now: d.Clock, cfg: d.Cfg, log: d.Logger,
		loginSem: make(chan struct{}, maxConcurrentLogins), loginWait: loginQueueWait,
	}
	/* Compare against the canonical form browsers send; LoadAPI already did this, direct callers may not have. */
	if o, err := config.NormalizeOrigin(s.cfg.PublicOrigin); err == nil {
		s.cfg.PublicOrigin = o
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
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
		s.rateLimit, s.withSession, s.checkCSRF)
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

	/* Phase 0 permissions are global: Can(perm, nil, nil). */
	users := Policy{Perm: rbac.PermUsersManage}
	usersStepUp := Policy{Perm: rbac.PermUsersManage, StepUp: true}
	groups := Policy{Perm: rbac.PermGroupsManage}
	groupsStepUp := Policy{Perm: rbac.PermGroupsManage, StepUp: true}
	bindings := Policy{Perm: rbac.PermBindingsManage}
	bindingsStepUp := Policy{Perm: rbac.PermBindingsManage, StepUp: true}
	s.route(r, http.MethodGet, "/api/users", users, s.listUsers)
	s.route(r, http.MethodPost, "/api/users", usersStepUp, s.createUser)
	s.route(r, http.MethodPatch, "/api/users/{id}", usersStepUp, s.updateUser)
	s.route(r, http.MethodGet, "/api/users/{id}/bindings", bindings, s.getBindings)
	s.route(r, http.MethodPut, "/api/users/{id}/bindings", bindingsStepUp, s.setBindings)
	s.route(r, http.MethodGet, "/api/groups", groups, s.listGroups)
	s.route(r, http.MethodPost, "/api/groups", groups, s.createGroup)
	s.route(r, http.MethodPatch, "/api/groups/{id}", groups, s.updateGroup)
	s.route(r, http.MethodDelete, "/api/groups/{id}", groupsStepUp, s.deleteGroup)
	s.route(r, http.MethodGet, "/api/audit", Policy{Perm: rbac.PermAuditRead}, s.listAudit)
	return r
}

/*
route is the only way to register an endpoint: it binds h to its policy so
that Routes can enumerate every route. A policy that grants nothing explicit
(non-public without Perm), mixes public with a permission, or marks a
route Scoped without a real permission panics at start.
*/
func (s *server) route(r chi.Router, method, pattern string, p Policy, h http.HandlerFunc) {
	if p.Public == (p.Perm != "") || (p.Public && p.StepUp) || (p.Scoped && (p.Public || p.Perm == "" || p.Perm == rbac.PermSelf)) {
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
		admitted := subj.Can(ph.p.Perm, nil, nil)
		if ph.p.Scoped {
			admitted = subj.HoldsAnywhere(ph.p.Perm)
		}
		if !admitted {
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
func Routes() []RouteSpec { return routesOf(newServer(Deps{}).handler().(chi.Routes)) }

func routesOf(routes chi.Routes) []RouteSpec {
	var out []RouteSpec
	err := chi.Walk(routes,
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
