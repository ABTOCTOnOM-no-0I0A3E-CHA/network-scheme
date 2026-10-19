package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/beekamai/network-scheme/internal/auth"
)

/* apiError is a client-facing error: a stable snake_case code and a Russian message. */
type apiError struct {
	status int
	code   string
	msg    string
}

/* Error catalogue. Messages never carry internal details. */
var (
	errBadRequest       = apiError{http.StatusBadRequest, "bad_request", "Некорректный запрос"}
	errUnauthenticated  = apiError{http.StatusUnauthorized, "unauthenticated", "Требуется вход в систему"}
	errInvalidCreds     = apiError{http.StatusUnauthorized, "invalid_credentials", "Неверное имя пользователя, пароль или код"}
	errChallengeExpired = apiError{http.StatusUnauthorized, "challenge_expired", "Время на ввод кода истекло, войдите заново"}
	errSessionExpired   = apiError{http.StatusUnauthorized, "session_expired", "Сессия истекла, войдите заново"}
	errCSRF             = apiError{http.StatusForbidden, "csrf", "Отсутствует или неверен CSRF-токен"}
	errForbidden        = apiError{http.StatusForbidden, "forbidden", "Недостаточно прав"}
	errStepUpRequired   = apiError{http.StatusForbidden, "stepup_required", "Требуется повторное подтверждение кодом TOTP"}
	errNotFound         = apiError{http.StatusNotFound, "not_found", "Не найдено"}
	errMethodNotAllowed = apiError{http.StatusMethodNotAllowed, "method_not_allowed", "Метод не поддерживается"}
	errTooLarge         = apiError{http.StatusRequestEntityTooLarge, "payload_too_large", "Слишком большой запрос"}
	errMediaType        = apiError{http.StatusUnsupportedMediaType, "unsupported_media_type", "Ожидается Content-Type: application/json"}
	errLocked           = apiError{http.StatusLocked, "locked", "Учётная запись временно заблокирована"}
	errRateLimited      = apiError{http.StatusTooManyRequests, "rate_limited", "Слишком много запросов, повторите позже"}
	errInternal         = apiError{http.StatusInternalServerError, "internal", "Внутренняя ошибка сервера"}
)

type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

/* writeJSON sends v with status; the security headers are set by the router. */
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, e apiError) {
	writeJSON(w, e.status, errorBody{errorDetail{Code: e.code, Message: e.msg}})
}

/*
fail answers err: known auth outcomes map to their codes; anything else is
logged with the request ID and answered with a bare 500.
*/
func (s *server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var e apiError
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		e = errInvalidCreds
	case errors.Is(err, auth.ErrLocked):
		e = errLocked
	case errors.Is(err, auth.ErrRateLimited):
		e = errRateLimited
	case errors.Is(err, auth.ErrChallengeExpired):
		e = errChallengeExpired
	case errors.Is(err, auth.ErrSessionExpired):
		e = errSessionExpired
	default:
		s.log.ErrorContext(r.Context(), "request failed",
			slog.String("request_id", requestID(r.Context())),
			slog.String("method", r.Method), slog.String("path", r.URL.Path),
			slog.String("error", err.Error()))
		e = errInternal
	}
	writeError(w, e)
}
