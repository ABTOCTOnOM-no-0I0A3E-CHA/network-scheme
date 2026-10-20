package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

/* Excess concurrent logins wait briefly for an Argon2 slot, then get 429 without verifying. */
func TestLoginConcurrencyCap(t *testing.T) {
	s := newServer(Deps{}) /* no auth service: a call past the semaphore would panic */
	s.loginWait = 50 * time.Millisecond
	for range cap(s.loginSem) {
		s.loginSem <- struct{}{}
	}
	h := s.handler()
	r := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"u","password":"p"}`))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "192.0.2.1:1"
	rec := httptest.NewRecorder()
	start := time.Now()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), `"rate_limited"`) {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}
	if d := time.Since(start); d < s.loginWait {
		t.Fatalf("answered after %v, want a wait of %v", d, s.loginWait)
	}
	if cap(s.loginSem) != 4 {
		t.Fatalf("cap = %d, want 4", cap(s.loginSem))
	}
}
