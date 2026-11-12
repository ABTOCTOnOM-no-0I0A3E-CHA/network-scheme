/*
Package web is the executor's HTTP server behind the gateway (/x on the
executor origin :8443, security.md 4, 5.3, 13; architecture.md 3). It
listens only on the executor's own address in xnet and speaks TLS 1.3 to
one client: the gateway, whose certificate must chain to the internal CA,
carry CN gateway and the clientAuth EKU (and match the SPKI pin when one is
configured).

Every request passes, in this order: the Cookie header is dropped (cookies
are never read and never set: a cookie set on :443 reaches :8443 too); the
security headers are set (so every answer, errors included, carries them);
the Host must name the executor origin's host, any port (421); the client's address is the one the gateway wrote into X-Forwarded-For (the
gateway overwrites the header, a single address, else 400); the Origin, if
any, must be the executor origin and a non-GET request must have one (403);
the per-IP rate limit (429); with the executor disabled by the host's
policy everything under /x/ but /x/status answers 503 executor_disabled;
the route table (404, 405); then the handler: a bounded JSON body (413,
415, 400), the per-user and global limits keyed on the ticket's verified
signature (no nonce spent), and only then authz, which audits every
decision. No CORS, no host-only operation (enroll, grant, unlock, freeze
off, policy, reset exist only in nmsctl).
*/
package web

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/confirm"
	"github.com/beekamai/network-scheme/internal/ticket"
)

/* GatewayCN is the common name of the only client certificate accepted. */
const GatewayCN = "gateway"

/* Bounds of a request and of the server; variables for the tests. */
var (
	maxBody           int64 = 64 << 10
	maxHeader               = 16 << 10
	readHeaderTimeout       = 5 * time.Second
	readTimeout             = 15 * time.Second
	writeTimeout            = 30 * time.Second
	idleTimeout             = 60 * time.Second
	shutdownGrace           = 10 * time.Second
	maxConns                = 256 /* open connections from the gateway */
)

/*
Rate limits: per client IP on every request, per user (from the ticket's
verified signature) and in all on every request that reaches authz (each
one writes an audit row and may take the registry lock).
*/
var (
	ipRate, ipBurst         = 2.0, 40.0
	userRate, userBurst     = 0.5, 10.0
	globalRate, globalBurst = 20.0, 100.0
	maxKeys                 = 10000
)

/* Authorizer is what the server needs of authz.Authorizer. */
type Authorizer interface {
	TicketUser(tok string) (int64, bool)
	Identify(ctx context.Context, req authz.Request) (authz.Decision, error)
	Authorize(ctx context.Context, req authz.Request) (authz.Decision, error)
}

/* Confirmer is what the server needs of confirm.Store. */
type Confirmer interface {
	Issue(user int64, need authz.Need, d confirm.Description) (confirm.Challenge, error)
	Action(id string) (string, bool)
	Confirm(ctx context.Context, id string, h []byte, req authz.Request) (confirm.Challenge, authz.Decision, error)
}

/*
Action is one action confirmed with confirm(H). Describe builds, from the
executor's own data and the client's params, what the user confirms (its
Action must be the action's name) and the grant it needs; Run executes the
confirmed description. The client never chooses the grant or the text. An
action without Run is confirmed only on its own route (Confirmed).
*/
type Action struct {
	Describe func(ctx context.Context, by authz.Decision, params json.RawMessage) (authz.Need, confirm.Description, error)
	Run      func(ctx context.Context, c confirm.Challenge, by authz.Decision) (any, error)
}

/*
Refusal is an action's own refusal with a code the UI has a text for: a
Describe or Run error that implements it answers 422 with that code, or the
status of its HTTPStatus method when it has one (e.g. 503 outcome_unknown).
*/
type Refusal interface {
	error
	RefusalCode() string
}

/* actionRefused answers an action's Refusal (422) or freeze (503) and reports whether it did. */
func actionRefused(w http.ResponseWriter, err error) bool {
	var rf Refusal
	switch {
	case errors.As(err, &rf):
		status := http.StatusUnprocessableEntity
		var st interface{ HTTPStatus() int }
		if errors.As(err, &st) {
			status = st.HTTPStatus()
		}
		fail(w, status, rf.RefusalCode())
	case errors.Is(err, authz.ErrFrozen):
		refused(w, err)
	default:
		return false
	}
	return true
}

/* Config builds a Server. */
type Config struct {
	CertFile, KeyFile, ClientCAFile string
	/* GatewaySPKI, if set, is the SHA-256 of the gateway certificate's public key: any other key is refused. */
	GatewaySPKI []byte
	/* ExecutorOrigin is the only Origin accepted; PanelOrigin is the only one that may frame the executor UI. */
	ExecutorOrigin, PanelOrigin string
	Auth                        Authorizer
	Confirm                     Confirmer
	/* State reports what /x/status shows: whether the policy enables the executor, and the freeze. */
	State   func() (enabled, frozen bool)
	Actions map[string]Action
	Reads   map[string]Read /* authorized reads (ticket + change TOTP) by path, POST routes of their own (read.go) */
	/* Confirmed are actions confirmed on routes of their own (confirmed.go). */
	Confirmed []Confirmed
	/* Sessions, if set, serves the change session routes (sessions.go). */
	Sessions *Sessions
	/* Terminal, if set, serves GET /x/ws (terminal.Terminal.Serve: its own Origin check and timeouts). */
	Terminal func(w http.ResponseWriter, r *http.Request, ip string)
	Log      *slog.Logger
	Now      func() time.Time /* nil: time.Now */
}

/* Server serves /x. */
type Server struct {
	c                Config
	host             string /* the executor origin's host: the only Host accepted */
	tls              *tls.Config
	csp              string
	ip, user, global *limiter
	routes           []route
}

type route struct {
	method, path string
	handle       func(w http.ResponseWriter, r *http.Request, ip string)
	re           *regexp.Regexp /* if set, the paths it matches (path is then only how Routes shows it) */
}

/* New loads the certificate, the key and the client CA (the server does not start without them) and builds the server. */
func New(cfg Config) (*Server, error) {
	if cfg.Auth == nil || cfg.Confirm == nil || cfg.State == nil || cfg.Log == nil || cfg.ExecutorOrigin == "" || cfg.PanelOrigin == "" {
		return nil, errors.New("web: incomplete configuration")
	}
	if cfg.GatewaySPKI != nil && len(cfg.GatewaySPKI) != sha256.Size {
		return nil, errors.New("web: the gateway SPKI pin must be a SHA-256")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	u, err := url.Parse(cfg.ExecutorOrigin)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("web: executor origin %q", cfg.ExecutorOrigin)
	}
	tc, err := serverTLS(cfg)
	if err != nil {
		return nil, err
	}
	s := &Server{c: cfg, tls: tc, host: u.Hostname(),
		csp: "default-src 'self'; script-src " + cfg.ExecutorOrigin + "/assets/; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
			"frame-ancestors " + cfg.PanelOrigin + "; frame-src 'none'; form-action 'none'; base-uri 'none'; object-src 'none'",
		ip:     newLimiter(ipRate, ipBurst, maxKeys, cfg.Now),
		user:   newLimiter(userRate, userBurst, maxKeys, cfg.Now),
		global: newLimiter(globalRate, globalBurst, 1, cfg.Now),
	}
	s.routes = []route{
		{http.MethodGet, "/x/status", s.status, nil},
		{http.MethodPost, "/x/confirm/issue", s.issue, nil},
		{http.MethodPost, "/x/confirm", s.confirm, nil},
	}
	s.addSessions()
	if cfg.Terminal != nil {
		s.routes = append(s.routes, route{http.MethodGet, "/x/ws", cfg.Terminal, nil})
	}
	if err := s.addReads(); err != nil {
		return nil, err
	}
	if err := s.addConfirmed(); err != nil {
		return nil, err
	}
	return s, nil
}

/* serverTLS is TLS 1.3 only, with a verified client certificate that must be the gateway's. */
func serverTLS(cfg Config) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("web: tls certificate: %w", err)
	}
	ca, err := os.ReadFile(cfg.ClientCAFile) // #nosec G304 -- path from the executor configuration
	if err != nil {
		return nil, fmt.Errorf("web: client ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("web: client ca %s: no PEM certificate", cfg.ClientCAFile)
	}
	pin := cfg.GatewaySPKI
	return &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: pool,
		NextProtos: []string{"http/1.1"},
		/* No resumption: every connection presents and verifies the gateway's certificate again. */
		SessionTicketsDisabled: true,
		VerifyConnection:       func(cs tls.ConnectionState) error { return gatewayOnly(cs, pin) },
	}, nil
}

/* gatewayOnly accepts only a verified leaf with CN gateway and the clientAuth EKU, not a CA, matching the pin if set. */
func gatewayOnly(cs tls.ConnectionState, pin []byte) error {
	if len(cs.VerifiedChains) == 0 || len(cs.PeerCertificates) == 0 {
		return errors.New("web: no verified client certificate")
	}
	leaf := cs.PeerCertificates[0]
	/*
		The handshake already verified the chain for clientAuth; the EKU and
		IsCA checks repeat it on purpose (defense in depth: a change of the
		TLS settings alone must not let a server or CA certificate through).
	*/
	switch {
	case leaf.Subject.CommonName != GatewayCN:
		return fmt.Errorf("web: client certificate CN %q is not %s", leaf.Subject.CommonName, GatewayCN)
	case !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) || leaf.IsCA:
		return errors.New("web: client certificate is not a clientAuth leaf")
	}
	if pin != nil {
		sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		if subtle.ConstantTimeCompare(sum[:], pin) != 1 {
			return errors.New("web: client certificate key does not match the pin")
		}
	}
	return nil
}

/* TLSConfig returns a copy of the server's TLS configuration (the gateway test's stub serves with it). */
func (s *Server) TLSConfig() *tls.Config { return s.tls.Clone() }

/* Routes lists the route table as "METHOD path" (the tests insist no host-only operation is there). */
func (s *Server) Routes() []string {
	out := make([]string, 0, len(s.routes))
	for _, r := range s.routes {
		out = append(out, r.method+" "+r.path)
	}
	return out
}

/*
Serve serves ln (the executor's address in xnet; the caller binds it) with
TLS until ctx ends, then shuts down gracefully within shutdownGrace.
*/
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	hs := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeader,
		/* No HTTP/2 (ALPN offers http/1.1 only). */
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ErrorLog:     slog.NewLogLogger(s.c.Log.Handler(), slog.LevelWarn),
		BaseContext:  func(net.Listener) context.Context { return context.WithoutCancel(ctx) },
	}
	errc := make(chan error, 1)
	go func() { errc <- hs.Serve(tls.NewListener(limitListener(ln, maxConns), s.tls)) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := hs.Shutdown(sctx); err != nil {
		s.c.Log.Warn("web: requests still running at shutdown, closing them", slog.Any("err", err))
		_ = hs.Close()
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

/* errorBody is every error answer: a code, and for a lock its end or that only the host can lift it. */
type errorBody struct {
	Error struct {
		Code      string     `json:"code"`
		Until     *time.Time `json:"until,omitempty"`
		Permanent bool       `json:"permanent,omitempty"`
	} `json:"error"`
}

func reply(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, code string) {
	var b errorBody
	b.Error.Code = code
	reply(w, status, b)
}

/*
refused answers an authz or confirm refusal: disabled and frozen 503, a
lock 423 with its end, unavailable 503, too many challenges 429, anything
else (denied, or an error not known here) 403.
*/
func refused(w http.ResponseWriter, err error) {
	var b errorBody
	var l *authz.LockedError
	status := http.StatusForbidden
	switch {
	case errors.Is(err, authz.ErrDisabled):
		status, b.Error.Code = http.StatusServiceUnavailable, "executor_disabled"
	case errors.Is(err, authz.ErrFrozen):
		status, b.Error.Code = http.StatusServiceUnavailable, "frozen"
	case errors.As(err, &l):
		status, b.Error.Code, b.Error.Permanent = http.StatusLocked, "locked", l.Permanent
		if !l.Permanent {
			u := l.Until.UTC()
			b.Error.Until = &u
		}
	case errors.Is(err, authz.ErrLocked):
		status, b.Error.Code = http.StatusLocked, "locked"
	case errors.Is(err, authz.ErrUnavailable):
		status, b.Error.Code = http.StatusServiceUnavailable, "unavailable"
	case errors.Is(err, confirm.ErrTooMany):
		status, b.Error.Code = http.StatusTooManyRequests, "too_many_challenges"
	default:
		b.Error.Code = "denied"
	}
	reply(w, status, b)
}

/* limited answers 429 with Retry-After in whole seconds. */
func limited(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(max(1, int((wait+time.Second-1)/time.Second))))
	fail(w, http.StatusTooManyRequests, "rate_limited")
}

/* ServeHTTP is the whole request path (see the package comment). */
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Header.Del("Cookie")
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", s.csp)
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

	if !s.ownHost(r.Host) {
		fail(w, http.StatusMisdirectedRequest, "misdirected")
		return
	}
	ip, ok := clientIP(r)
	if !ok {
		fail(w, http.StatusBadRequest, "bad_request")
		return
	}
	origins := r.Header.Values("Origin")
	if len(origins) > 1 || (len(origins) == 1 && origins[0] != s.c.ExecutorOrigin) || (len(origins) == 0 && r.Method != http.MethodGet) {
		fail(w, http.StatusForbidden, "origin")
		return
	}
	if ok, wait := s.ip.allow(ipKey(ip)); !ok {
		limited(w, wait)
		return
	}
	if enabled, _ := s.c.State(); !enabled && r.URL.Path != "/x/status" {
		fail(w, http.StatusServiceUnavailable, "executor_disabled")
		return
	}
	var allow []string
	for _, rt := range s.routes {
		if rt.path != r.URL.Path && (rt.re == nil || !rt.re.MatchString(r.URL.Path)) {
			continue
		}
		if rt.method == r.Method {
			rt.handle(w, r, ip)
			return
		}
		allow = append(allow, rt.method)
	}
	if len(allow) == 0 {
		fail(w, http.StatusNotFound, "not_found")
		return
	}
	h.Set("Allow", allow[0])
	fail(w, http.StatusMethodNotAllowed, "method_not_allowed")
}

/*
ownHost reports whether a Host header names the executor origin's host
(any port: the gateway passes the browser's Host, whose port is the
published one).
*/
func (s *Server) ownHost(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1] /* an IPv6 literal without a port: only a matching pair */
	}
	return strings.EqualFold(host, s.host)
}

/*
clientIP is the browser's address as the gateway wrote it: exactly one
X-Forwarded-For value holding one address. The gateway sets the header
itself and overwrites whatever the browser sent (Caddyfile, header_up), so
a second value or a list means the request did not come that way.
*/
func clientIP(r *http.Request) (string, bool) {
	v := r.Header.Values("X-Forwarded-For")
	if len(v) != 1 {
		return "", false
	}
	a, err := netip.ParseAddr(v[0])
	if err != nil || a.Zone() != "" {
		return "", false
	}
	return a.Unmap().String(), true
}

/*
ipKey is the per-IP limit key: the address, for IPv6 its /64 (one client
rotating addresses within its prefix must not fill the limiter, whose full
table refuses new keys).
*/
func ipKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil || a.Is4() {
		return ip
	}
	return netip.PrefixFrom(a, 64).Masked().String()
}

/* status shows only whether the executor is enabled and frozen (Q14): no grants, devices or sessions. */
func (s *Server) status(w http.ResponseWriter, _ *http.Request, _ string) {
	enabled, frozen := s.c.State()
	reply(w, http.StatusOK, map[string]bool{"enabled": enabled, "frozen": frozen})
}

/*
decode reads a JSON body of at most maxBody bytes into v strictly: the
content type must be JSON, unknown fields and trailing data are refused.
It answers the error itself and reports whether to go on.
*/
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		fail(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return false
	}
	if r.ContentLength > maxBody {
		fail(w, http.StatusRequestEntityTooLarge, "too_large")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil {
		if _, terr := dec.Token(); !errors.Is(terr, io.EOF) {
			err = errors.New("trailing data")
		}
	}
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		fail(w, http.StatusRequestEntityTooLarge, "too_large")
		return false
	case err != nil:
		fail(w, http.StatusBadRequest, "bad_request")
		return false
	}
	return true
}

/*
admit applies the per-user limit (the user of a ticket whose signature
verifies; a ticket that does not verify is limited by its IP only, and authz
then refuses and audits it) and the global limit, before anything reaches
authz.
*/
func (s *Server) admit(w http.ResponseWriter, tok string) bool {
	if len(tok) > ticket.MaxLen {
		fail(w, http.StatusBadRequest, "bad_request")
		return false
	}
	if user, ok := s.c.Auth.TicketUser(tok); ok {
		if ok, wait := s.user.allow(strconv.FormatInt(user, 10)); !ok {
			limited(w, wait)
			return false
		}
	}
	if ok, wait := s.global.allow(""); !ok {
		limited(w, wait)
		return false
	}
	return true
}

type issueRequest struct {
	Ticket string          `json:"ticket"`
	Action string          `json:"action"`
	Params json.RawMessage `json:"params"`
}

type field struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type challengeBody struct {
	ID      string    `json:"challenge_id"`
	Action  string    `json:"action"`
	H       string    `json:"h"`
	Fields  []field   `json:"fields"`
	Expires time.Time `json:"expires"`
}

/*
issue registers a confirmation challenge for an action of the executor's
table: only for a user whose ticket authz accepts (Identify), with the
description and the grant the action builds itself.
*/
func (s *Server) issue(w http.ResponseWriter, r *http.Request, ip string) {
	var req issueRequest
	if !decode(w, r, &req) {
		return
	}
	act, ok := s.c.Actions[req.Action]
	if !ok {
		fail(w, http.StatusNotFound, "unknown_action")
		return
	}
	if !s.admit(w, req.Ticket) {
		return
	}
	by, err := s.c.Auth.Identify(r.Context(), authz.Request{Ticket: req.Ticket, Action: "confirm.issue", Object: req.Action,
		IP: ip, UA: r.UserAgent()})
	if err != nil {
		refused(w, err)
		return
	}
	need, d, err := act.Describe(r.Context(), by, req.Params)
	if err != nil && actionRefused(w, err) {
		return
	}
	if err != nil {
		s.c.Log.Info("web: action not described", slog.String("action", req.Action), slog.Any("err", err))
		fail(w, http.StatusBadRequest, "bad_params")
		return
	}
	if d.Action != req.Action {
		s.c.Log.Error("web: an action described another", slog.String("action", req.Action), slog.String("described", d.Action))
		fail(w, http.StatusInternalServerError, "internal")
		return
	}
	c, err := s.c.Confirm.Issue(by.UserID, need, d)
	if err != nil {
		if errors.Is(err, confirm.ErrTooMany) {
			refused(w, err)
			return
		}
		s.c.Log.Error("web: cannot issue a challenge", slog.String("action", req.Action), slog.Any("err", err))
		fail(w, http.StatusInternalServerError, "internal")
		return
	}
	body := challengeBody{ID: c.ID, Action: c.Action, H: hex.EncodeToString(c.H[:]), Fields: []field{}, Expires: c.Expires.UTC()}
	for _, f := range c.Description.Fields {
		body.Fields = append(body.Fields, field{f.Key, f.Value})
	}
	reply(w, http.StatusOK, body)
}

type confirmRequest struct {
	Ticket      string `json:"ticket"`
	ChallengeID string `json:"challenge_id"`
	H           string `json:"h"`
	Code        string `json:"code"`
}

/*
confirm runs a confirmation: the challenge, its H, the ticket and the
user's change TOTP code (confirm.Store and authz decide and audit), then
the action on the confirmed description.
*/
func (s *Server) confirm(w http.ResponseWriter, r *http.Request, ip string) {
	var req confirmRequest
	if !decode(w, r, &req) {
		return
	}
	h, err := hex.DecodeString(req.H)
	if err != nil || len(h) != sha256.Size || len(req.ChallengeID) > 64 {
		fail(w, http.StatusBadRequest, "bad_request")
		return
	}
	if !s.admit(w, req.Ticket) {
		return
	}
	/* An action confirmed on a route of its own (Confirmed) is not confirmed here: its challenge is left unspent. */
	if a, ok := s.c.Confirm.Action(req.ChallengeID); ok && s.c.Actions[a].Run == nil {
		fail(w, http.StatusNotFound, "use_route")
		return
	}
	c, by, err := s.c.Confirm.Confirm(r.Context(), req.ChallengeID, h, authz.Request{Ticket: req.Ticket, Code: req.Code,
		IP: ip, UA: r.UserAgent()})
	if err != nil {
		refused(w, err)
		return
	}
	act, ok := s.c.Actions[c.Action]
	if !ok || act.Run == nil {
		s.c.Log.Error("web: a confirmed challenge names no action", slog.String("action", c.Action))
		fail(w, http.StatusInternalServerError, "internal")
		return
	}
	res, err := act.Run(r.Context(), c, by)
	if err != nil && actionRefused(w, err) {
		return
	}
	if err != nil {
		s.c.Log.Error("web: confirmed action failed", slog.String("action", c.Action), slog.Any("err", err))
		fail(w, http.StatusInternalServerError, "action_failed")
		return
	}
	reply(w, http.StatusOK, map[string]any{"action": c.Action, "result": res})
}
