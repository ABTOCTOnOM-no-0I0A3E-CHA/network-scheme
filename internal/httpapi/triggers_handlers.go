package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/beekamai/network-scheme/internal/audit"
	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/rbac"
	"github.com/beekamai/network-scheme/internal/triggers"
)

var (
	errTemplateNotFound = errors.New("httpapi: template or trigger not found")
	errTemplateDup      = errors.New("httpapi: template name taken")
	errTriggerParams    = errors.New("httpapi: invalid trigger params")
)

/* pgErrOf returns the PostgreSQL error inside err, if any. */
func pgErrOf(err error) *pgconn.PgError {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe
	}
	return nil
}

/* driverName bounds the driver a template is bound to; the registry of drivers is not consulted (api does not link them). */
var driverName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

/*
configChanged tells the trigger engine, after a committed change, to reload
its configuration now. Without a hook the engine's own 30 s reload applies it.
*/
func (s *server) configChanged() {
	if s.onConfig != nil {
		s.onConfig()
	}
}

/* validTriggerName is validGroupName that also rejects format characters (bidi controls), like the UI. */
func validTriggerName(n string) bool {
	return validGroupName(n) && !strings.ContainsFunc(n, func(r rune) bool { return unicode.Is(unicode.Cf, r) })
}

/* pathInt64 parses a named URL parameter as a positive integer; anything else answers 404. */
func pathInt64(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, name), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, errNotFound)
		return 0, false
	}
	return id, true
}

type templateResponse struct {
	ID                 int64   `json:"id"`
	Name               string  `json:"name"`
	Driver             *string `json:"driver"`
	GroupID            *int64  `json:"group_id"`
	IntervalAvailS     *int    `json:"interval_avail_s"`
	IntervalMetricsS   *int    `json:"interval_metrics_s"`
	IntervalInventoryS *int    `json:"interval_inventory_s"`
}

const templateCols = `id, name, driver, group_id, interval_avail_s, interval_metrics_s, interval_inventory_s`

/* visible: a driver template needs a global scope, a group template its group in scope. */
func (t templateResponse) visibleIn(sc groupScope) bool {
	if t.GroupID != nil {
		return sc.has(*t.GroupID)
	}
	return sc.all
}

/* template loads a template the caller may manage; a missing and a foreign one are both errTemplateNotFound. */
func (s *server) template(r *http.Request, sc groupScope, id int64) (templateResponse, error) {
	var t templateResponse
	err := s.pool.QueryRow(r.Context(), `SELECT `+templateCols+` FROM core.monitoring_template WHERE id = $1`, id).Scan(
		&t.ID, &t.Name, &t.Driver, &t.GroupID, &t.IntervalAvailS, &t.IntervalMetricsS, &t.IntervalInventoryS)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !t.visibleIn(sc)) {
		return t, errTemplateNotFound
	}
	return t, err
}

/* listTemplates lists the templates bound to the caller's groups; driver templates only for a global scope. */
func (s *server) listTemplates(w http.ResponseWriter, r *http.Request) {
	sc, err := s.scope(r, rbac.PermTriggersManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.pool.Query(r.Context(), `SELECT `+templateCols+` FROM core.monitoring_template ORDER BY id`)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	all, err := pgx.CollectRows(rows, pgx.RowToStructByPos[templateResponse])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]templateResponse, 0, len(all))
	for _, t := range all {
		if t.visibleIn(sc) {
			out = append(out, t)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

/* writeErr maps a unique violation on the template name and a dangling group to their codes. */
func templateWriteErr(err error) error {
	switch pe := pgErrOf(err); {
	case pe != nil && pe.Code == "23505":
		return errTemplateDup
	case pe != nil && pe.Code == "23503":
		return devices.ErrGroupNotFound
	}
	return err
}

/*
createTemplate binds a template to a driver (global scope only; a scoped
caller gets 403) or to a group in the caller's scope (else 404). Exactly one
of driver and group_id is given.
*/
func (s *server) createTemplate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name               string          `json:"name"`
		Driver             *string         `json:"driver"`
		GroupID            *int64          `json:"group_id"`
		IntervalAvailS     json.RawMessage `json:"interval_avail_s"`
		IntervalMetricsS   json.RawMessage `json:"interval_metrics_s"`
		IntervalInventoryS json.RawMessage `json:"interval_inventory_s"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	var iv [3]*int
	valid := validTriggerName(in.Name) && (in.Driver == nil) != (in.GroupID == nil) &&
		(in.Driver == nil || driverName.MatchString(*in.Driver)) && (in.GroupID == nil || *in.GroupID > 0)
	for i, raw := range []json.RawMessage{in.IntervalAvailS, in.IntervalMetricsS, in.IntervalInventoryS} {
		_, v, ok := parseInterval(raw)
		valid, iv[i] = valid && ok, v
	}
	if !valid {
		writeError(w, errBadRequest)
		return
	}
	sc, err := s.scope(r, rbac.PermTriggersManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	switch {
	case in.Driver != nil && !sc.all:
		writeError(w, errForbidden)
		return
	case in.GroupID != nil && !sc.has(*in.GroupID):
		writeError(w, errNotFound)
		return
	}
	var id int64
	ev := audit.Event{Action: "templates.create", ObjectType: "template",
		Details: map[string]any{"name": in.Name, "driver": in.Driver, "group_id": in.GroupID, "interval_avail_s": iv[0], "interval_metrics_s": iv[1], "interval_inventory_s": iv[2]}}
	if !s.change(w, r, ev, func(tx pgx.Tx, ev *audit.Event) error {
		if err := capTemplates(r.Context(), tx, in.Driver, in.GroupID); err != nil {
			return err
		}
		err := tx.QueryRow(r.Context(), `INSERT INTO core.monitoring_template (name, driver, group_id, interval_avail_s, interval_metrics_s, interval_inventory_s)
			VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`, in.Name, in.Driver, in.GroupID, iv[0], iv[1], iv[2]).Scan(&id)
		if err != nil {
			return templateWriteErr(err)
		}
		ev.ObjectID = strconv.FormatInt(id, 10)
		return nil
	}) {
		return
	}
	s.configChanged()
	writeJSON(w, http.StatusCreated, idResponse{ID: id})
}

/* updateTemplate renames a template or changes its intervals (null clears one); the binding itself cannot change. */
func (s *server) updateTemplate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		Name               *string         `json:"name"`
		IntervalAvailS     json.RawMessage `json:"interval_avail_s"`
		IntervalMetricsS   json.RawMessage `json:"interval_metrics_s"`
		IntervalInventoryS json.RawMessage `json:"interval_inventory_s"`
	}
	sc, err := s.scope(r, rbac.PermTriggersManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.template(r, sc, id); err != nil {
		s.fail(w, r, err)
		return
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	details := map[string]any{}
	valid := true
	if in.Name != nil {
		valid = valid && validTriggerName(*in.Name)
		details["name"] = *in.Name
	}
	var set [3]bool
	var iv [3]*int
	for i, f := range []struct {
		key string
		raw json.RawMessage
	}{{"interval_avail_s", in.IntervalAvailS}, {"interval_metrics_s", in.IntervalMetricsS}, {"interval_inventory_s", in.IntervalInventoryS}} {
		sv, v, ok := parseInterval(f.raw)
		valid = valid && ok
		if sv {
			set[i], iv[i], details[f.key] = true, v, v
		}
	}
	if !valid || len(details) == 0 {
		writeError(w, errBadRequest)
		return
	}
	ev := audit.Event{Action: "templates.update", ObjectType: "template", ObjectID: strconv.FormatInt(id, 10), Details: details}
	if !s.change(w, r, ev, func(tx pgx.Tx, _ *audit.Event) error {
		tag, err := tx.Exec(r.Context(), `UPDATE core.monitoring_template SET
			name = coalesce($2, name),
			interval_avail_s = CASE WHEN $3::bool THEN $4::int ELSE interval_avail_s END,
			interval_metrics_s = CASE WHEN $5::bool THEN $6::int ELSE interval_metrics_s END,
			interval_inventory_s = CASE WHEN $7::bool THEN $8::int ELSE interval_inventory_s END
			WHERE id = $1`, id, in.Name, set[0], iv[0], set[1], iv[1], set[2], iv[2])
		if err != nil {
			return templateWriteErr(err)
		}
		if tag.RowsAffected() == 0 {
			return errTemplateNotFound
		}
		return nil
	}) {
		return
	}
	s.configChanged()
	w.WriteHeader(http.StatusNoContent)
}

/* deleteTemplate removes a template with its triggers and their overrides; the engine then resolves their open problems as removed. */
func (s *server) deleteTemplate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	sc, err := s.scope(r, rbac.PermTriggersManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	t, err := s.template(r, sc, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ev := audit.Event{Action: "templates.delete", ObjectType: "template", ObjectID: strconv.FormatInt(id, 10),
		Details: map[string]any{"name": t.Name, "driver": t.Driver, "group_id": t.GroupID}}
	if !s.change(w, r, ev, func(tx pgx.Tx, _ *audit.Event) error {
		tag, err := tx.Exec(r.Context(), `DELETE FROM core.monitoring_template WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errTemplateNotFound
		}
		return nil
	}) {
		return
	}
	s.configChanged()
	w.WriteHeader(http.StatusNoContent)
}

type triggerResponse struct {
	ID         int64           `json:"id"`
	TemplateID int64           `json:"template_id"`
	Kind       string          `json:"kind"`
	Params     json.RawMessage `json:"params"`
	DurationS  int             `json:"duration_s"`
	Severity   string          `json:"severity"`
	Enabled    bool            `json:"enabled"`
	Name       string          `json:"name"`
}

const triggerCols = `id, template_id, kind, params, duration_s, severity, enabled, name`

/* canonicalParams validates params for kind with the engine's own parser and returns the re-encoded parsed value: raw request bytes are never stored. */
func canonicalParams(kind string, raw json.RawMessage) (json.RawMessage, error) {
	p, err := triggers.ParseUser(kind, raw)
	if err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

func (s *server) listTriggers(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	sc, err := s.scope(r, rbac.PermTriggersManage)
	if err == nil {
		_, err = s.template(r, sc, id)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.pool.Query(r.Context(), `SELECT `+triggerCols+` FROM core.trigger WHERE template_id = $1 ORDER BY id`, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[triggerResponse])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []triggerResponse{}
	}
	writeJSON(w, http.StatusOK, out)
}

/*
createTrigger adds a trigger to a template the caller may manage. kind is one
of availability, if_oper_down, metric_threshold, trap, syslog; params are
validated by the engine's parser (a bad kind or params answers 400
invalid_trigger) and stored re-encoded from the parsed value.
*/
func (s *server) createTrigger(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		Kind      string          `json:"kind"`
		Params    json.RawMessage `json:"params"`
		DurationS int             `json:"duration_s"`
		Severity  string          `json:"severity"`
		Enabled   *bool           `json:"enabled"`
		Name      string          `json:"name"`
	}
	sc, err := s.scope(r, rbac.PermTriggersManage)
	if err == nil {
		_, err = s.template(r, sc, tid)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if !validTriggerName(in.Name) {
		writeError(w, errBadRequest)
		return
	}
	params, perr := canonicalParams(in.Kind, in.Params)
	if perr != nil || triggers.ValidateDuration(in.DurationS) != nil || !trapSeverities[in.Severity] {
		writeError(w, errInvalidTrigger)
		return
	}
	enabled := in.Enabled == nil || *in.Enabled
	var id int64
	ev := audit.Event{Action: "triggers.create", ObjectType: "trigger",
		Details: map[string]any{"template_id": tid, "kind": in.Kind, "params": params, "duration_s": in.DurationS, "severity": in.Severity, "enabled": enabled, "name": in.Name}}
	if !s.change(w, r, ev, func(tx pgx.Tx, ev *audit.Event) error {
		if err := capTriggers(r.Context(), tx, tid); err != nil {
			return err
		}
		err := tx.QueryRow(r.Context(), `INSERT INTO core.trigger (template_id, kind, params, duration_s, severity, enabled, name)
			VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7) RETURNING id`, tid, in.Kind, string(params), in.DurationS, in.Severity, enabled, in.Name).Scan(&id)
		if pe := pgErrOf(err); pe != nil && pe.Code == "23503" {
			return errTemplateNotFound
		}
		if err != nil {
			return err
		}
		if in.Kind == string(triggers.KindSyslog) {
			if err := capSyslogFilters(r.Context(), tx); err != nil {
				return err
			}
		}
		ev.ObjectID = strconv.FormatInt(id, 10)
		return nil
	}) {
		return
	}
	s.configChanged()
	writeJSON(w, http.StatusCreated, idResponse{ID: id})
}

/* updateTrigger changes name, severity, duration, enabled or params; the kind is fixed and params are validated against it. */
func (s *server) updateTrigger(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathID(w, r)
	if !ok {
		return
	}
	id, ok := pathInt64(w, r, "trigger_id")
	if !ok {
		return
	}
	var in struct {
		Params    json.RawMessage `json:"params"`
		DurationS *int            `json:"duration_s"`
		Severity  *string         `json:"severity"`
		Enabled   *bool           `json:"enabled"`
		Name      *string         `json:"name"`
	}
	sc, err := s.scope(r, rbac.PermTriggersManage)
	if err == nil {
		_, err = s.template(r, sc, tid)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	details := map[string]any{"template_id": tid}
	if in.Name != nil {
		if !validTriggerName(*in.Name) {
			writeError(w, errBadRequest)
			return
		}
		details["name"] = *in.Name
	}
	if in.DurationS != nil {
		if triggers.ValidateDuration(*in.DurationS) != nil {
			writeError(w, errInvalidTrigger)
			return
		}
		details["duration_s"] = *in.DurationS
	}
	if in.Severity != nil {
		if !trapSeverities[*in.Severity] {
			writeError(w, errInvalidTrigger)
			return
		}
		details["severity"] = *in.Severity
	}
	if in.Enabled != nil {
		details["enabled"] = *in.Enabled
	}
	setParams := in.Params != nil
	if len(details) == 1 && !setParams {
		writeError(w, errBadRequest)
		return
	}
	ev := audit.Event{Action: "triggers.update", ObjectType: "trigger", ObjectID: strconv.FormatInt(id, 10), Details: details}
	if !s.change(w, r, ev, func(tx pgx.Tx, ev *audit.Event) error {
		var kind string
		err := tx.QueryRow(r.Context(), `SELECT kind FROM core.trigger WHERE id = $1 AND template_id = $2 FOR UPDATE`, id, tid).Scan(&kind)
		if errors.Is(err, pgx.ErrNoRows) {
			return errTemplateNotFound
		}
		if err != nil {
			return err
		}
		var params any
		if setParams {
			p, err := canonicalParams(kind, in.Params)
			if err != nil {
				return errTriggerParams
			}
			params = string(p)
			ev.Details["params"] = p
		}
		_, err = tx.Exec(r.Context(), `UPDATE core.trigger SET
			params = coalesce($2::jsonb, params), duration_s = coalesce($3, duration_s), severity = coalesce($4, severity),
			enabled = coalesce($5, enabled), name = coalesce($6, name) WHERE id = $1`,
			id, params, in.DurationS, in.Severity, in.Enabled, in.Name)
		if err != nil || kind != string(triggers.KindSyslog) || !setParams {
			return err
		}
		return capSyslogFilters(r.Context(), tx)
	}) {
		return
	}
	s.configChanged()
	w.WriteHeader(http.StatusNoContent)
}

/* deleteTrigger removes a trigger with its overrides; the engine then resolves its open problems as removed. */
func (s *server) deleteTrigger(w http.ResponseWriter, r *http.Request) {
	tid, ok := pathID(w, r)
	if !ok {
		return
	}
	id, ok := pathInt64(w, r, "trigger_id")
	if !ok {
		return
	}
	sc, err := s.scope(r, rbac.PermTriggersManage)
	if err == nil {
		_, err = s.template(r, sc, tid)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ev := audit.Event{Action: "triggers.delete", ObjectType: "trigger", ObjectID: strconv.FormatInt(id, 10), Details: map[string]any{"template_id": tid}}
	if !s.change(w, r, ev, func(tx pgx.Tx, ev *audit.Event) error {
		var name string
		err := tx.QueryRow(r.Context(), `DELETE FROM core.trigger WHERE id = $1 AND template_id = $2 RETURNING name`, id, tid).Scan(&name)
		if errors.Is(err, pgx.ErrNoRows) {
			return errTemplateNotFound
		}
		if err != nil {
			return err
		}
		ev.Details["name"] = name
		return nil
	}) {
		return
	}
	s.configChanged()
	w.WriteHeader(http.StatusNoContent)
}

type overrideResponse struct {
	TriggerID int64           `json:"trigger_id"`
	Enabled   *bool           `json:"enabled"`
	Params    json.RawMessage `json:"params"`
	Severity  *string         `json:"severity"`
}

/* listOverrides returns a device's per-trigger exceptions. */
func (s *server) listOverrides(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if _, err := s.authorizeDevice(r, rbac.PermTriggersManage, id); err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.pool.Query(r.Context(), `SELECT trigger_id, enabled, params, severity FROM core.trigger_override WHERE device_id = $1 ORDER BY trigger_id`, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[overrideResponse])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []overrideResponse{}
	}
	writeJSON(w, http.StatusOK, out)
}

/* applicableTriggerSQL reads a trigger that applies to the device: its template is bound to the device's driver or to the device's group or an ancestor. */
const applicableTriggerSQL = `
SELECT t.kind, t.params, t.template_id FROM core.trigger t
JOIN core.monitoring_template m ON m.id = t.template_id
JOIN core.device d ON d.id = $2
WHERE t.id = $1 AND (m.driver = d.driver OR m.group_id IN (
  WITH RECURSIVE anc (id, depth) AS (
    SELECT d.group_id, 0
    UNION ALL
    SELECT g.parent_id, anc.depth + 1 FROM anc JOIN core.device_group g ON g.id = anc.id WHERE g.parent_id IS NOT NULL AND anc.depth < 64
  ) SELECT id FROM anc))`

/*
putOverride replaces the device's exception to a trigger of an applicable
template. enabled, severity and params are optional but at least one is
needed; params lay keys over the trigger's (null removes an optional key) and
the merged result must be a valid condition (else 400 invalid_trigger). Only
the keys that differ from the trigger are stored, re-encoded from the parsed
value.
*/
func (s *server) putOverride(w http.ResponseWriter, r *http.Request) {
	devID, ok := pathID(w, r)
	if !ok {
		return
	}
	trigID, ok := pathInt64(w, r, "trigger_id")
	if !ok {
		return
	}
	if _, err := s.authorizeDevice(r, rbac.PermTriggersManage, devID); err != nil {
		s.fail(w, r, err)
		return
	}
	var in struct {
		Enabled  *bool           `json:"enabled"`
		Params   json.RawMessage `json:"params"`
		Severity *string         `json:"severity"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	hasParams := len(in.Params) > 0 && string(bytes.TrimSpace(in.Params)) != "null"
	if (in.Enabled == nil && !hasParams && in.Severity == nil) || (in.Severity != nil && !trapSeverities[*in.Severity]) ||
		(hasParams && bytes.TrimSpace(in.Params)[0] != '{') {
		writeError(w, errBadRequest)
		return
	}
	var kind string
	var base json.RawMessage
	var tplID int64
	err := s.pool.QueryRow(r.Context(), applicableTriggerSQL, trigID, devID).Scan(&kind, &base, &tplID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, errNotFound)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var overlay any /* nil: no param exceptions */
	var overlayDetail json.RawMessage
	if hasParams {
		o, err := canonicalOverlay(kind, base, in.Params)
		if err != nil {
			/* A template outside the caller's scope may be overridden for the caller's own device, but its kind and params stay hidden: no validation answer, only 404. */
			sc, serr := s.scope(r, rbac.PermTriggersManage)
			if serr == nil {
				_, serr = s.template(r, sc, tplID)
			}
			if serr != nil {
				writeError(w, errNotFound)
				return
			}
			writeError(w, errInvalidTrigger)
			return
		}
		if o != nil {
			overlay, overlayDetail = string(o), o
		}
	}
	ev := audit.Event{Action: "trigger_overrides.set", ObjectType: "device", ObjectID: strconv.FormatInt(devID, 10),
		Details: map[string]any{"trigger_id": trigID, "enabled": in.Enabled, "severity": in.Severity, "params": overlayDetail}}
	if !s.change(w, r, ev, func(tx pgx.Tx, _ *audit.Event) error {
		_, err := tx.Exec(r.Context(), `INSERT INTO core.trigger_override (trigger_id, device_id, enabled, params, severity)
			VALUES ($1, $2, $3, $4::jsonb, $5)
			ON CONFLICT (trigger_id, device_id) DO UPDATE SET enabled = EXCLUDED.enabled, params = EXCLUDED.params, severity = EXCLUDED.severity`,
			trigID, devID, in.Enabled, overlay, in.Severity)
		if pe := pgErrOf(err); pe != nil && pe.Code == "23503" {
			return errTemplateNotFound /* the trigger or the device vanished meanwhile */
		}
		return err
	}) {
		return
	}
	s.configChanged()
	w.WriteHeader(http.StatusNoContent)
}

/*
canonicalOverlay validates that the override's keys over base give a valid
condition of kind and returns the canonical overlay: the keys of the parsed
merged value that differ from the parsed base, nil when none do.
*/
func canonicalOverlay(kind string, base, over json.RawMessage) (json.RawMessage, error) {
	merged, err := triggers.MergeParams(base, over)
	if err != nil {
		return nil, err
	}
	pm, err := canonicalParams(kind, merged)
	if err != nil {
		return nil, err
	}
	pb, err := canonicalParams(kind, base)
	if err != nil {
		return nil, err
	}
	var mm, bm map[string]json.RawMessage
	if err := json.Unmarshal(pm, &mm); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(pb, &bm); err != nil {
		return nil, err
	}
	diff := map[string]json.RawMessage{}
	for k, v := range mm {
		if !bytes.Equal(v, bm[k]) {
			diff[k] = v
		}
	}
	if len(diff) == 0 {
		return nil, nil
	}
	return json.Marshal(diff)
}

func (s *server) deleteOverride(w http.ResponseWriter, r *http.Request) {
	devID, ok := pathID(w, r)
	if !ok {
		return
	}
	trigID, ok := pathInt64(w, r, "trigger_id")
	if !ok {
		return
	}
	if _, err := s.authorizeDevice(r, rbac.PermTriggersManage, devID); err != nil {
		s.fail(w, r, err)
		return
	}
	ev := audit.Event{Action: "trigger_overrides.delete", ObjectType: "device", ObjectID: strconv.FormatInt(devID, 10), Details: map[string]any{"trigger_id": trigID}}
	if !s.change(w, r, ev, func(tx pgx.Tx, _ *audit.Event) error {
		tag, err := tx.Exec(r.Context(), `DELETE FROM core.trigger_override WHERE trigger_id = $1 AND device_id = $2`, trigID, devID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errTemplateNotFound
		}
		return nil
	}) {
		return
	}
	s.configChanged()
	w.WriteHeader(http.StatusNoContent)
}

const (
	maxTriggersPerTemplate  = 100
	maxTemplatesPerBinding  = 50
	maxDistinctSyslogFilter = 256
)

var (
	errCapTriggers  = errors.New("httpapi: too many triggers in a template")
	errCapTemplates = errors.New("httpapi: too many templates")
	errCapFilters   = errors.New("httpapi: too many distinct syslog filters")
)

/* capTemplates limits the templates of one group (or one driver); the group row (or an advisory lock for a driver) serializes concurrent creates. */
func capTemplates(ctx context.Context, tx pgx.Tx, driver *string, group *int64) error {
	var n int
	if group != nil {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM core.device_group WHERE id = $1 FOR UPDATE`, *group); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM core.monitoring_template WHERE group_id = $1`, *group).Scan(&n); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('template-driver:' || $1::text))`, *driver); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM core.monitoring_template WHERE driver = $1`, *driver).Scan(&n); err != nil {
			return err
		}
	}
	if n >= maxTemplatesPerBinding {
		return errCapTemplates
	}
	return nil
}

/* capTriggers limits the triggers of a template; the template row is locked so concurrent creates count each other. */
func capTriggers(ctx context.Context, tx pgx.Tx, template int64) error {
	var n int
	if _, err := tx.Exec(ctx, `SELECT 1 FROM core.monitoring_template WHERE id = $1 FOR UPDATE`, template); err != nil {
		return err
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM core.trigger WHERE template_id = $1`, template).Scan(&n); err != nil {
		return err
	}
	if n >= maxTriggersPerTemplate {
		return errCapTriggers
	}
	return nil
}

/*
capSyslogFilters runs after a syslog trigger was written: the engine reads the
syslog stream once per distinct (severity_min, contains) filter, so their
number is bounded globally. An advisory lock serializes writers; returning an
error rolls the write back.
*/
func capSyslogFilters(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('syslog-filters'))`); err != nil {
		return err
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM (SELECT DISTINCT params->>'severity_min', lower(coalesce(params->>'contains', '')) FROM core.trigger WHERE kind = 'syslog') f`).Scan(&n); err != nil {
		return err
	}
	if n > maxDistinctSyslogFilter {
		return errCapFilters
	}
	return nil
}
