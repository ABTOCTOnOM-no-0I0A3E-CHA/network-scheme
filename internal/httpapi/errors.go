package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/beekamai/network-scheme/internal/auth"
	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/rbac"
	"github.com/beekamai/network-scheme/internal/store"
)

/* apiError is a client-facing error: a stable snake_case code and a Russian message. */
type apiError struct {
	status int
	code   string
	msg    string
}

/* Error catalogue. Messages never carry internal details. */
var (
	errBadRequest         = apiError{http.StatusBadRequest, "bad_request", "Некорректный запрос"}
	errUnauthenticated    = apiError{http.StatusUnauthorized, "unauthenticated", "Требуется вход в систему"}
	errInvalidCreds       = apiError{http.StatusUnauthorized, "invalid_credentials", "Неверное имя пользователя, пароль или код"}
	errChallengeExpired   = apiError{http.StatusUnauthorized, "challenge_expired", "Время на ввод кода истекло, войдите заново"}
	errSessionExpired     = apiError{http.StatusUnauthorized, "session_expired", "Сессия истекла, войдите заново"}
	errCSRF               = apiError{http.StatusForbidden, "csrf", "Отсутствует или неверен CSRF-токен"}
	errForbidden          = apiError{http.StatusForbidden, "forbidden", "Недостаточно прав"}
	errStepUpRequired     = apiError{http.StatusForbidden, "stepup_required", "Требуется повторное подтверждение кодом TOTP"}
	errNotFound           = apiError{http.StatusNotFound, "not_found", "Не найдено"}
	errMethodNotAllowed   = apiError{http.StatusMethodNotAllowed, "method_not_allowed", "Метод не поддерживается"}
	errTooLarge           = apiError{http.StatusRequestEntityTooLarge, "payload_too_large", "Слишком большой запрос"}
	errMediaType          = apiError{http.StatusUnsupportedMediaType, "unsupported_media_type", "Ожидается Content-Type: application/json"}
	errConflictUser       = apiError{http.StatusConflict, "user_exists", "Пользователь с таким именем уже существует"}
	errConflictGroup      = apiError{http.StatusConflict, "group_exists", "Группа с таким именем уже есть у этого родителя"}
	errGroupNotEmpty      = apiError{http.StatusConflict, "group_not_empty", "Группа содержит дочерние группы"}
	errGroupCycle         = apiError{http.StatusConflict, "group_cycle", "Группу нельзя переместить внутрь неё самой"}
	errLastAdmin          = apiError{http.StatusConflict, "last_admin", "Нельзя лишить системы последнего администратора"}
	errInvalidUsername    = apiError{http.StatusBadRequest, "invalid_username", "Недопустимое имя пользователя"}
	errWeakPassword       = apiError{http.StatusBadRequest, "weak_password", "Пароль короче 12 символов или есть в списке скомпрометированных"}
	errInvalidRole        = apiError{http.StatusBadRequest, "invalid_role", "Неизвестная роль"}
	errAddressExists      = apiError{http.StatusConflict, "address_exists", "Устройство с таким адресом и портом SNMP уже есть"}
	errNotPending         = apiError{http.StatusConflict, "not_pending", "Находка уже обработана"}
	errStaleKey           = apiError{http.StatusBadRequest, "stale_key", "Учётные данные зашифрованы устаревшим ключом, обновите страницу"}
	errCIDRTooWide        = apiError{http.StatusBadRequest, "cidr_too_wide", "Подсеть шире /16 (более 65 536 адресов)"}
	errTooManyPoints      = apiError{http.StatusBadRequest, "too_many_points", "Слишком много точек: сузьте период или увеличьте шаг"}
	errTrapRuleExists     = apiError{http.StatusConflict, "trap_rule_exists", "Правило для этого OID уже есть"}
	errProblemResolved    = apiError{http.StatusConflict, "problem_resolved", "Проблема уже закрыта"}
	errTemplateExists     = apiError{http.StatusConflict, "template_exists", "Шаблон с таким именем уже есть"}
	errInvalidTrigger     = apiError{http.StatusBadRequest, "invalid_trigger", "Недопустимые параметры триггера"}
	errTooManyTriggers    = apiError{http.StatusConflict, "too_many_triggers", "В шаблоне не может быть больше 100 триггеров"}
	errTooManyTemplates   = apiError{http.StatusConflict, "too_many_templates", "У группы (с учётом родительских) или драйвера не может быть больше 50 шаблонов"}
	errTooManyWindows     = apiError{http.StatusConflict, "too_many_windows", "У группы не может быть больше 100 незавершённых окон обслуживания"}
	errTooManyFilters     = apiError{http.StatusConflict, "too_many_filters", "Достигнут предел различных фильтров syslog (256)"}
	errInvalidWindow      = apiError{http.StatusBadRequest, "invalid_window", "Недопустимое окно обслуживания: не более 7 суток, конец в будущем и позже начала"}
	errParentCycle        = apiError{http.StatusConflict, "parent_cycle", "Родитель образует цикл"}
	errParentTooDeep      = apiError{http.StatusConflict, "parent_too_deep", "Цепочка родителей длиннее 16 устройств"}
	errLinkExists         = apiError{http.StatusConflict, "link_exists", "Такая связь уже есть"}
	errTooManyLinks       = apiError{http.StatusConflict, "too_many_links", "Между двумя устройствами не может быть больше 64 связей"}
	errTooManyViews       = apiError{http.StatusConflict, "too_many_views", "Видов карты не может быть больше 100"}
	errTooManyAreas       = apiError{http.StatusConflict, "too_many_areas", "В виде не может быть больше 2000 областей"}
	errAreaCycle          = apiError{http.StatusConflict, "area_cycle", "Родитель области образует цикл"}
	errAreaTooDeep        = apiError{http.StatusConflict, "area_too_deep", "Вложенность областей больше 8 уровней"}
	errAreaOtherView      = apiError{http.StatusConflict, "area_other_view", "Родитель области должен быть в том же виде"}
	errTooManyBackgrounds = apiError{http.StatusConflict, "too_many_backgrounds", "Подложек не может быть больше 200"}
	errTooManyDashboards  = apiError{http.StatusConflict, "too_many_dashboards", "Дашбордов не может быть больше 50 (общих — тоже 50)"}
	errTooManyWidgets     = apiError{http.StatusConflict, "too_many_widgets", "На дашборде не может быть больше 50 виджетов"}
	errInvalidWidget      = apiError{http.StatusBadRequest, "invalid_widget", "Неизвестный тип виджета или недопустимые настройки"}
	errNotMultipart       = apiError{http.StatusUnsupportedMediaType, "unsupported_media_type", "Ожидается Content-Type: multipart/form-data"}
	errUnsupportedImage   = apiError{http.StatusUnsupportedMediaType, "unsupported_media", "Подложка должна быть PNG, JPEG, WebP или SVG"}
	errInvalidImage       = apiError{http.StatusBadRequest, "invalid_image", "Файл подложки повреждён или не допускается (не больше 16384 пикселей по каждой стороне)"}
	errLocked             = apiError{http.StatusLocked, "locked", "Учётная запись временно заблокирована"}
	errRateLimited        = apiError{http.StatusTooManyRequests, "rate_limited", "Слишком много запросов, повторите позже"}
	errBusy               = apiError{http.StatusServiceUnavailable, "busy", "Сервер занят отдачей подложек, повторите позже"}
	errQueryTimeout       = apiError{http.StatusServiceUnavailable, "query_timeout", "Запрос выполнялся слишком долго: уточните условия или повторите позже"}
	errInternal           = apiError{http.StatusInternalServerError, "internal", "Внутренняя ошибка сервера"}
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
	{errTrapRuleDup, errTrapRuleExists},
	{errTrapRuleNotFound, errNotFound},
	{errProblemNotFound, errNotFound},
	{errProblemClosed, errProblemResolved},
	{errTemplateDup, errTemplateExists},
	{errTemplateNotFound, errNotFound},
	{errTriggerParams, errInvalidTrigger},
	{errCapTriggers, errTooManyTriggers},
	{errCapTemplates, errTooManyTemplates},
	{errCapFilters, errTooManyFilters},
	{errCapWindows, errTooManyWindows},
	{errMaintenanceNotFound, errNotFound},
	{devices.ErrParentCycle, errParentCycle},
	{devices.ErrParentDepth, errParentTooDeep},
	{errLinkDup, errLinkExists},
	{errCapLinks, errTooManyLinks},
	{errCapViews, errTooManyViews},
	{errCapAreas, errTooManyAreas},
	{errAreaLoop, errAreaCycle},
	{errAreaDepth, errAreaTooDeep},
	{errAreaView, errAreaOtherView},
	{errMapNotFound, errNotFound},
	{errCapBackgrounds, errTooManyBackgrounds},
	{errMapBackground, errBadRequest},
	{errMapInvalid, errBadRequest},
	{errShowInvalid, apiShowInvalid},
	{errDashboardNotFound, errNotFound},
	{errDashboardShared, errForbidden},
	{errDashboardInvalid, errBadRequest},
	{errCapDashboards, errTooManyDashboards},
	{errCapWidgets, errTooManyWidgets},
	{errShowBusy, apiShowBusy},
	{store.ErrTimeout, errQueryTimeout},
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
