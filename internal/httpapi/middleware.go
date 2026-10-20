package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/httprate"

	"github.com/beekamai/network-scheme/internal/auth"
	"github.com/beekamai/network-scheme/internal/config"
	"github.com/beekamai/network-scheme/internal/httpapi/clientip"
)

const (
	maxBodyBytes     = 1 << 20 /* 1 MiB per request body */
	generalRateLimit = 600     /* requests per minute per client IP */
	defaultAuthLimit = 10      /* requests per minute per client IP on credential endpoints */
	cookieName       = "__Host-nms_session"
	csrfHeader       = "X-CSRF-Token"
)

type ctxKey int

const (
	keyRequestID ctxKey = iota
	keyClientIP
	keySession
	keySubject /* rbac.Subject loaded by the route policy */
)

/* sessionCtx is the outcome of the session cookie check. */
type sessionCtx struct {
	token string
	sess  auth.Session
	valid bool /* false: a cookie was sent but its session is gone */
}

func requestID(ctx context.Context) string {
	id, _ := ctx.Value(keyRequestID).(string)
	return id
}

func clientIP(ctx context.Context) netip.Addr {
	a, _ := ctx.Value(keyClientIP).(netip.Addr)
	return a
}

func sessionFrom(ctx context.Context) (sessionCtx, bool) {
	sc, ok := ctx.Value(keySession).(sessionCtx)
	return sc, ok
}

/* withRequestID tags every request with a fresh random ID; client-supplied IDs are ignored. */
func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 12)
		_, _ = rand.Read(b) /* crypto/rand.Read never fails */
		id := hex.EncodeToString(b)
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), keyRequestID, id)))
	})
}

/* recoverer turns a handler panic into a logged 500 without details in the body. */
func (s *server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			v := recover()
			if v == nil {
				return
			}
			if v == http.ErrAbortHandler { /* net/http's own abort signal */
				panic(v)
			}
			s.log.ErrorContext(r.Context(), "handler panic",
				slog.String("request_id", requestID(r.Context())),
				slog.Any("panic", v), slog.String("stack", string(debug.Stack())))
			writeError(w, errInternal)
		}()
		next.ServeHTTP(w, r)
	})
}

/* securityHeaders marks every API response as non-sniffable and non-cacheable. */
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

/* limitBody rejects declared oversize bodies at once and caps streamed ones. */
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > maxBodyBytes {
			writeError(w, errTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

/* withClientIP resolves the client address once (see clientip.FromRequest). */
func (s *server) withClientIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := clientip.FromRequest(r, s.cfg.TrustedProxyCIDRs)
		if !a.IsValid() {
			writeError(w, errBadRequest)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), keyClientIP, a)))
	})
}

func newLimiter(perMinute int) *httprate.RateLimiter {
	return httprate.NewRateLimiter(perMinute, time.Minute,
		httprate.WithKeyFuncs(func(r *http.Request) (string, error) { return clientIP(r.Context()).String(), nil }),
		httprate.WithLimitHandler(func(w http.ResponseWriter, _ *http.Request) { writeError(w, errRateLimited) }),
		httprate.WithErrorHandler(func(w http.ResponseWriter, _ *http.Request, _ error) { writeError(w, errInternal) }),
	)
}

/*
rateLimit applies the general per-IP limit to every request and the strict
one on top of it to the credential-checking endpoints.
*/
func (s *server) rateLimit(next http.Handler) http.Handler {
	general := s.generalRL.Handler(next)
	strict := s.authRL.Handler(general)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if credentialPaths[r.URL.Path] {
			strict.ServeHTTP(w, r)
			return
		}
		general.ServeHTTP(w, r)
	})
}

/*
withSession resolves the session cookie. A cookie whose session is gone is
cleared and remembered, so protected routes answer session_expired.
*/
func (s *server) withSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil || c.Value == "" {
			next.ServeHTTP(w, r)
			return
		}
		sess, err := s.auth.Authenticate(r.Context(), c.Value)
		sc := sessionCtx{token: c.Value, sess: sess, valid: err == nil}
		switch {
		case errors.Is(err, auth.ErrSessionExpired):
			clearSessionCookie(w)
		case err != nil:
			s.fail(w, r, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), keySession, sc)))
	})
}

/*
checkCSRF guards every state-changing request: an Origin header, when
present, must equal the configured public origin (a request without one
comes from a non-browser client and still needs the token), and with a live
session X-CSRF-Token must equal Session.CSRF (constant time).
*/
func (s *server) checkCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if o := r.Header.Values("Origin"); len(o) > 0 && (len(o) != 1 || !s.originAllowed(o[0])) {
			writeError(w, errCSRF)
			return
		}
		if sc, ok := sessionFrom(r.Context()); ok && sc.valid {
			got := r.Header.Get(csrfHeader)
			if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(sc.sess.CSRF)) != 1 {
				writeError(w, errCSRF)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

/* originAllowed reports whether an Origin header value names the public origin once normalised ("null" and malformed values fail). */
func (s *server) originAllowed(o string) bool {
	n, err := config.NormalizeOrigin(o)
	return err == nil && n == s.cfg.PublicOrigin
}

/* setSessionCookie replaces any session cookie already queued (e.g. a clear) in this response. */
func setSessionCookie(w http.ResponseWriter, token string) {
	h := w.Header()
	h["Set-Cookie"] = slices.DeleteFunc(h["Set-Cookie"], func(v string) bool {
		return strings.HasPrefix(v, cookieName+"=")
	})
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: token, Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: "", Path: "/", MaxAge: -1, /* Max-Age=0 */
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}
