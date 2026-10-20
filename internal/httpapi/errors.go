package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/beekamai/network-scheme/internal/auth"
	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/rbac"
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
	errConflictUser     = apiError{http.StatusConflict, "user_exists", "Пользователь с таким именем уже существует"}
	errConflictGroup    = apiError{http.StatusConflict, "group_exists", "Группа с таким именем уже есть у этого родителя"}
	errGroupNotEmpty    = apiError{http.StatusConflict, "group_not_empty", "Группа содержит дочерние группы"}
	errGroupCycle       = apiError{http.StatusConflict, "group_cycle", "Группу нельзя переместить внутрь неё самой"}
	errLastAdmin        = apiError{http.StatusConflict, "last_admin", "Нельзя лишить системы последнего администратора"}
	errInvalidUsername  = apiError{http.StatusBadRequest, "invalid_username", "Недопустимое имя пользователя"}
	errWeakPassword     = apiError{http.StatusBadRequest, "weak_password", "Пароль короче 12 символов или есть в списке скомпрометированных"}
	errInvalidRole      = apiError{http.StatusBadRequest, "invalid_role", "Неизвестная роль"}
	errAddressExists    = apiError{http.StatusConflict, "address_exists", "Устройство с таким адресом и портом SNMP уже есть"}
	errNotPending       = apiError{http.StatusConflict, "not_pending", "Находка уже обработана"}
	errStaleKey         = apiError{http.StatusBadRequest, "stale_key", "Учётные данные зашифрованы устаревшим ключом, обновите страницу"}
	errCIDRTooWide      = apiError{http.StatusBadRequest, "cidr_too_wide", "Подсеть шире /16 (более 65 536 адресов)"}
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

/* knownErrors maps domain errors to their client-facing form. */
var knownErrors = []struct {
	err error
	api apiError
}{
	{auth.ErrInvalidCredentials, errInvalidCreds},
	{auth.ErrLocked, errLocked},
	{auth.ErrRateLimited, errRateLimited},
	{auth.ErrChallengeExpired, errChallengeExpired},
	{auth.ErrSessionExpired, errSessionExpired},
	{auth.ErrUserExists, errConflictUser},
	{auth.ErrBadUsername, errInvalidUsername},
	{auth.ErrPasswordTooShort, errWeakPassword},
	{auth.ErrPasswordCompromised, errWeakPassword},
	{auth.ErrUserNotFound, errNotFound},
	{rbac.ErrUserNotFound, errNotFound},
	{rbac.ErrGroupNotFound, errNotFound},
	{rbac.ErrGroupExists, errConflictGroup},
	{rbac.ErrGroupNotEmpty, errGroupNotEmpty},
	{rbac.ErrGroupCycle, errGroupCycle},
	{rbac.ErrLastAdmin, errLastAdmin},
	{rbac.ErrInvalidRole, errInvalidRole},
	{devices.ErrNotFound, errNotFound},
	{devices.ErrGroupNotFound, errNotFound},
	{devices.ErrAddressExists, errAddressExists},
	{devices.ErrNotPending, errNotPending},
	{devices.ErrInvalid, errBadRequest},
	{errKeyVersion, errStaleKey},
}

/* knownError reports the client-facing form of err, if it is a known outcome. */
func knownError(err error) (apiError, bool) {
	for _, k := range knownErrors {
		if errors.Is(err, k.err) {
			return k.api, true
		}
	}
	return apiError{}, false
}

/*
fail answers err: known domain outcomes map to their codes; anything else is
logged with the request ID and answered with a bare 500.
*/
func (s *server) fail(w http.ResponseWriter, r *http.Request, err error) {
	e, ok := knownError(err)
	if !ok {
		s.log.ErrorContext(r.Context(), "request failed",
			slog.String("request_id", requestID(r.Context())),
			slog.String("method", r.Method), slog.String("path", r.URL.Path),
			slog.String("error", err.Error()))
		e = errInternal
	}
	writeError(w, e)
}
