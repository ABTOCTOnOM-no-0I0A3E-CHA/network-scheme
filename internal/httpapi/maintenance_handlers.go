package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/audit"
	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/rbac"
)

/* Limits of a maintenance window (mirrors the CHECKs of core.maintenance_window). */
const (
	maxMaintenanceSpan    = 7 * 24 * time.Hour
	maxMaintenanceComment = 1000
	maxMaintenanceList    = 1000
)

var errMaintenanceNotFound = errors.New("httpapi: maintenance window not found")

type maintenanceResponse struct {
	ID        int64     `json:"id"`
	GroupID   int64     `json:"group_id"`
	GroupName string    `json:"group_name"`
	StartsAt  time.Time `json:"starts_at"`
	EndsAt    time.Time `json:"ends_at"`
	Comment   string    `json:"comment"`
}

const maintenanceSelect = `SELECT w.id, w.group_id, g.name, w.starts_at, w.ends_at, w.comment
FROM core.maintenance_window w JOIN core.device_group g ON g.id = w.group_id`

/* listMaintenance lists windows of the caller's groups that have not ended (include_ended=true: all), newest start first. */
func (s *server) listMaintenance(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	inc, ok := single(q, "include_ended")
	if !ok || (inc != "" && inc != "true" && inc != "false") {
		writeError(w, errBadRequest)
		return
	}
	sc, err := s.scope(r, rbac.PermMaintenanceManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !sc.all && len(sc.ids) == 0 {
		writeJSON(w, http.StatusOK, []maintenanceResponse{})
		return
	}
	rows, err := s.pool.Query(r.Context(), maintenanceSelect+`
WHERE ($1::bool OR w.group_id = ANY($2)) AND ($3::bool OR w.ends_at > $4)
ORDER BY w.starts_at DESC, w.id DESC LIMIT $5`, sc.all, sc.ids, inc == "true", s.now(), maxMaintenanceList)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[maintenanceResponse])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []maintenanceResponse{}
	}
	writeJSON(w, http.StatusOK, out)
}

/*
createMaintenance opens a window for a group of the caller's scope (else
404). Problems of the group's devices, subgroups included, open suppressed
while it lasts. It may start in the past but must end in the future, after it
starts, and last at most 7 days (else 400 invalid_window).
*/
func (s *server) createMaintenance(w http.ResponseWriter, r *http.Request) {
	var in struct {
		GroupID  int64     `json:"group_id"`
		StartsAt time.Time `json:"starts_at"`
		EndsAt   time.Time `json:"ends_at"`
		Comment  string    `json:"comment"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.GroupID < 1 || in.StartsAt.IsZero() || in.EndsAt.IsZero() || !validMaintenanceComment(in.Comment) {
		writeError(w, errBadRequest)
		return
	}
	in.StartsAt, in.EndsAt = in.StartsAt.UTC().Truncate(time.Microsecond), in.EndsAt.UTC().Truncate(time.Microsecond)
	if !in.EndsAt.After(in.StartsAt) || in.EndsAt.Sub(in.StartsAt) > maxMaintenanceSpan || !in.EndsAt.After(s.now()) {
		writeError(w, errInvalidWindow)
		return
	}
	sc, err := s.scope(r, rbac.PermMaintenanceManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !sc.has(in.GroupID) {
		writeError(w, errNotFound)
		return
	}
	var id int64
	ev := audit.Event{Action: "maintenance.create", ObjectType: "maintenance_window",
		Details: map[string]any{"group_id": in.GroupID, "starts_at": in.StartsAt, "ends_at": in.EndsAt, "comment": in.Comment}}
	if !s.change(w, r, ev, func(tx pgx.Tx, ev *audit.Event) error {
		/* The group row serializes concurrent creates so the cap counts each other. */
		if _, err := tx.Exec(r.Context(), `SELECT 1 FROM core.device_group WHERE id = $1 FOR UPDATE`, in.GroupID); err != nil {
			return err
		}
		var open int
		if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM core.maintenance_window WHERE group_id = $1 AND ends_at > now()`, in.GroupID).Scan(&open); err != nil {
			return err
		}
		if open >= maxWindowsPerGroup {
			return errCapWindows
		}
		err := tx.QueryRow(r.Context(), `INSERT INTO core.maintenance_window (group_id, starts_at, ends_at, comment)
			VALUES ($1, $2, $3, $4) RETURNING id`, in.GroupID, in.StartsAt, in.EndsAt, in.Comment).Scan(&id)
		if pe := pgErrOf(err); pe != nil && pe.Code == "23503" {
			return devices.ErrGroupNotFound
		}
		if err != nil {
			return err
		}
		ev.ObjectID = strconv.FormatInt(id, 10)
		return nil
	}) {
		return
	}
	s.configChanged()
	writeJSON(w, http.StatusCreated, idResponse{ID: id})
}

/* deleteMaintenance ends a window early (removes it); the engine releases the suppression it caused. */
func (s *server) deleteMaintenance(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	sc, err := s.scope(r, rbac.PermMaintenanceManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ev := audit.Event{Action: "maintenance.delete", ObjectType: "maintenance_window", ObjectID: strconv.FormatInt(id, 10)}
	if !s.change(w, r, ev, func(tx pgx.Tx, ev *audit.Event) error {
		var gid int64
		var from, to time.Time
		err := tx.QueryRow(r.Context(), `SELECT group_id, starts_at, ends_at FROM core.maintenance_window WHERE id = $1 FOR UPDATE`, id).Scan(&gid, &from, &to)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && !sc.has(gid)) {
			return errMaintenanceNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(r.Context(), `DELETE FROM core.maintenance_window WHERE id = $1`, id); err != nil {
			return err
		}
		ev.Details = map[string]any{"group_id": gid, "starts_at": from, "ends_at": to}
		return nil
	}) {
		return
	}
	s.configChanged()
	w.WriteHeader(http.StatusNoContent)
}

/* validMaintenanceComment accepts up to 1000 characters; newlines and tabs are the only control characters allowed. */
func validMaintenanceComment(c string) bool {
	return utf8.ValidString(c) && utf8.RuneCountInString(c) <= maxMaintenanceComment &&
		!strings.ContainsFunc(c, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' })
}
