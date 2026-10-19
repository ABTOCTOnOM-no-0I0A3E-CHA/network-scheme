package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/beekamai/network-scheme/internal/auth"
)

/*
decodeJSON reads exactly one JSON object with known fields into dst. On
failure it answers the request and returns false.
*/
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, errMediaType)
		return false
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err := dec.Decode(dst)
	if err == nil && dec.Decode(&struct{}{}) != io.EOF {
		err = errors.New("trailing data")
	}
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		writeError(w, errTooLarge)
		return false
	case err != nil:
		writeError(w, errBadRequest)
		return false
	}
	return true
}

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

/*
acquireLogin takes one of the password-verification slots, waiting at most
loginWait. Every Argon2 run holds 64 MiB, so their number is bounded.
*/
func (s *server) acquireLogin(ctx context.Context) (release func(), ok bool) {
	t := time.NewTimer(s.loginWait)
	defer t.Stop()
	select {
	case s.loginSem <- struct{}{}:
		return func() { <-s.loginSem }, true
	case <-t.C:
		return nil, false
	case <-ctx.Done():
		return nil, false
	}
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Stage      string `json:"stage"`
	Challenge  string `json:"challenge"`
	OTPAuthURI string `json:"otpauth_uri,omitempty"`
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	var in loginRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	release, ok := s.acquireLogin(r.Context())
	if !ok {
		writeError(w, errRateLimited)
		return
	}
	defer release()
	step, err := s.auth.BeginLogin(r.Context(), in.Username, in.Password, clientIP(r.Context()).String())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, loginResponse{Stage: step.Kind, Challenge: step.ChallengeID, OTPAuthURI: step.OTPAuthURI})
}

type codeRequest struct {
	Challenge string `json:"challenge"`
	Code      string `json:"code"`
}

func (s *server) totp(w http.ResponseWriter, r *http.Request) {
	var in codeRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	ns, err := s.auth.CompleteTOTP(r.Context(), in.Challenge, in.Code, clientIP(r.Context()).String(), r.UserAgent())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	setSessionCookie(w, ns.Token)
	w.WriteHeader(http.StatusNoContent)
}

type enrollResponse struct {
	BackupCodes []string `json:"backup_codes"`
}

func (s *server) enroll(w http.ResponseWriter, r *http.Request) {
	var in codeRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	ns, codes, err := s.auth.CompleteEnroll(r.Context(), in.Challenge, in.Code, clientIP(r.Context()).String(), r.UserAgent())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	setSessionCookie(w, ns.Token)
	writeJSON(w, http.StatusOK, enrollResponse{BackupCodes: codes})
}

type stepUpRequest struct {
	Code string `json:"code"`
}

func (s *server) stepUp(w http.ResponseWriter, r *http.Request) {
	var in stepUpRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	sc, _ := sessionFrom(r.Context())
	tok, err := s.auth.StepUp(r.Context(), sc.token, in.Code)
	if err != nil {
		if errors.Is(err, auth.ErrSessionExpired) {
			clearSessionCookie(w)
		}
		s.fail(w, r, err)
		return
	}
	setSessionCookie(w, tok)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	sc, _ := sessionFrom(r.Context())
	if err := s.auth.Logout(r.Context(), sc.token); err != nil {
		s.fail(w, r, err)
		return
	}
	clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

type roleResponse struct {
	Role    string `json:"role"`
	GroupID *int64 `json:"group_id"`
}

type meResponse struct {
	ID        int64          `json:"id"`
	Username  string         `json:"username"`
	Roles     []roleResponse `json:"roles"`
	CSRFToken string         `json:"csrf_token"`
}

func (s *server) me(w http.ResponseWriter, r *http.Request) {
	sc, _ := sessionFrom(r.Context())
	subj, err := s.rbac.LoadSubject(r.Context(), sc.sess.UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	roles := make([]roleResponse, 0, len(subj.Bindings))
	for _, b := range subj.Bindings {
		roles = append(roles, roleResponse{Role: string(b.Role), GroupID: b.GroupID})
	}
	writeJSON(w, http.StatusOK, meResponse{
		ID: sc.sess.UserID, Username: sc.sess.Username, Roles: roles, CSRFToken: sc.sess.CSRF,
	})
}
