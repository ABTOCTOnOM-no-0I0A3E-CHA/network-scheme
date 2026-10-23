package httpapi

import (
	"encoding/json"
	"maps"
	"net/http"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/audit"
	"github.com/beekamai/network-scheme/internal/auth"
	"github.com/beekamai/network-scheme/internal/rbac"
)

/* maxGroupName mirrors the CHECK on core.device_group.name. */
const maxGroupName = 200

/* pathID parses the {id} URL parameter; anything but a positive integer answers 404. */
func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, errNotFound)
		return 0, false
	}
	return id, true
}

/*
change runs fn in a transaction and appends ev (completed by fn, e.g. with the
id of a created object) as its last statement, so the change and its audit
record commit together. A change refused with a known client error is rolled
back and audited with result "failure" in a transaction of its own. It answers
the request itself on failure and returns false.
*/
func (s *server) change(w http.ResponseWriter, r *http.Request, ev audit.Event, fn func(tx pgx.Tx, ev *audit.Event) error) bool {
	ctx := r.Context()
	sc, _ := sessionFrom(ctx)
	uid := sc.sess.UserID
	ev.TS, ev.UserID = s.now(), &uid
	ev.IP, ev.UserAgent = clientIP(ctx).String(), auth.CleanUserAgent(r.UserAgent())
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := fn(tx, &ev); err != nil {
			return err
		}
		ev.Result = "success"
		_, err := audit.Append(ctx, tx, ev)
		return err
	})
	if err == nil {
		return true
	}
	if e, ok := knownError(err); ok && e.status < http.StatusInternalServerError {
		ev.Result = "failure"
		ev.Details = maps.Clone(ev.Details)
		if ev.Details == nil {
			ev.Details = map[string]any{}
		}
		ev.Details["error"] = e.code
		if aerr := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
			_, err := audit.Append(ctx, tx, ev)
			return err
		}); aerr != nil {
			err = aerr
		}
	}
	s.fail(w, r, err)
	return false
}

type userResponse struct {
	ID           int64  `json:"id"`
	Username     string `json:"username"`
	Disabled     bool   `json:"disabled"`
	TOTPEnrolled bool   `json:"totp_enrolled"`
}

type idResponse struct {
	ID int64 `json:"id"`
}

func (s *server) listUsers(w http.ResponseWriter, r *http.Request) {
	us, err := s.users.List(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]userResponse, 0, len(us))
	for _, u := range us {
		out = append(out, userResponse{ID: u.ID, Username: u.Username, Disabled: u.Disabled, TOTPEnrolled: u.TOTPEnrolled})
	}
	writeJSON(w, http.StatusOK, out)
}

/* createUser adds a user without TOTP; it enrolls at the first login. */
func (s *server) createUser(w http.ResponseWriter, r *http.Request) {
	var in loginRequest
	if !decodeJSON(w, r, &in) {
		return
	}
	/* The password never reaches the audit record; the name only once valid. */
	details := map[string]any{}
	if name, err := auth.NormalizeUsername(in.Username); err == nil {
		details["username"] = name
	}
	release, ok := s.acquireLogin(r.Context()) /* Argon2 hashing holds 64 MiB */
	if !ok {
		writeError(w, errRateLimited)
		return
	}
	defer release()
	var id int64
	ev := audit.Event{Action: "users.create", ObjectType: "user", Details: details}
	if !s.change(w, r, ev, func(tx pgx.Tx, ev *audit.Event) error {
		var err error
		if id, err = s.users.Create(r.Context(), tx, in.Username, in.Password); err != nil {
			return err
		}
		ev.ObjectID = strconv.FormatInt(id, 10)
		return nil
	}) {
		return
	}
	writeJSON(w, http.StatusCreated, idResponse{ID: id})
}

/* updateUser enables or disables a user; disabling ends its sessions and keeps one admin. */
func (s *server) updateUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		Disabled *bool `json:"disabled"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Disabled == nil {
		writeError(w, errBadRequest)
		return
	}
	disabled := *in.Disabled
	ev := audit.Event{Action: "users.update", ObjectType: "user", ObjectID: strconv.FormatInt(id, 10),
		Details: map[string]any{"disabled": disabled}}
	if !s.change(w, r, ev, func(tx pgx.Tx, _ *audit.Event) error {
		if disabled {
			if err := s.rbac.GuardNotLastAdmin(r.Context(), tx, id); err != nil {
				return err
			}
		}
		return s.users.SetDisabled(r.Context(), tx, id, disabled)
	}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) getBindings(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var exists bool
	if err := s.pool.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM core."user" WHERE id = $1)`, id).Scan(&exists); err != nil {
		s.fail(w, r, err)
		return
	}
	if !exists {
		writeError(w, errNotFound)
		return
	}
	subj, err := s.rbac.LoadSubject(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]roleResponse, 0, len(subj.Bindings))
	for _, b := range subj.Bindings {
		out = append(out, roleResponse{Role: string(b.Role), GroupID: b.GroupID})
	}
	writeJSON(w, http.StatusOK, out)
}

/* setBindings replaces all role bindings of a user; dropping the last global admin is refused. */
func (s *server) setBindings(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in []roleResponse
	if !decodeJSON(w, r, &in) {
		return
	}
	if in == nil { /* JSON null: an empty set must be explicit */
		writeError(w, errBadRequest)
		return
	}
	bs := make([]rbac.Binding, 0, len(in))
	for _, b := range in {
		bs = append(bs, rbac.Binding{Role: rbac.Role(b.Role), GroupID: b.GroupID})
	}
	ev := audit.Event{Action: "bindings.set", ObjectType: "user", ObjectID: strconv.FormatInt(id, 10),
		Details: map[string]any{"bindings": in}}
	if !s.change(w, r, ev, func(tx pgx.Tx, _ *audit.Event) error {
		return s.rbac.SetBindings(r.Context(), tx, id, bs)
	}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type groupResponse struct {
	ID       int64  `json:"id"`
	ParentID *int64 `json:"parent_id"`
	Name     string `json:"name"`
}

/* validGroupName: non-empty, at most maxGroupName characters, no control characters or outer spaces. */
func validGroupName(n string) bool {
	return n != "" && utf8.RuneCountInString(n) <= maxGroupName &&
		strings.TrimSpace(n) == n && !strings.ContainsFunc(n, unicode.IsControl)
}

func (s *server) listGroups(w http.ResponseWriter, r *http.Request) {
	gs, err := s.rbac.ListGroups(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]groupResponse, 0, len(gs))
	for _, g := range gs {
		out = append(out, groupResponse{ID: g.ID, ParentID: g.ParentID, Name: g.Name})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) createGroup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name     string `json:"name"`
		ParentID *int64 `json:"parent_id"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if !validGroupName(in.Name) {
		writeError(w, errBadRequest)
		return
	}
	var id int64
	ev := audit.Event{Action: "groups.create", ObjectType: "group",
		Details: map[string]any{"name": in.Name, "parent_id": in.ParentID}}
	if !s.change(w, r, ev, func(tx pgx.Tx, ev *audit.Event) error {
		var err error
		if id, err = s.rbac.CreateGroup(r.Context(), tx, in.ParentID, in.Name); err != nil {
			return err
		}
		ev.ObjectID = strconv.FormatInt(id, 10)
		return nil
	}) {
		return
	}
	writeJSON(w, http.StatusCreated, idResponse{ID: id})
}

/*
updateGroup renames and/or moves a group. An absent field is left unchanged;
"parent_id": null moves the group to the root.
*/
func (s *server) updateGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		Name     *string         `json:"name"`
		ParentID json.RawMessage `json:"parent_id"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	move := in.ParentID != nil
	var parent *int64
	if (in.Name == nil && !move) || (in.Name != nil && !validGroupName(*in.Name)) ||
		(move && json.Unmarshal(in.ParentID, &parent) != nil) {
		writeError(w, errBadRequest)
		return
	}
	details := map[string]any{}
	if in.Name != nil {
		details["name"] = *in.Name
	}
	if move {
		details["parent_id"] = parent
	}
	ev := audit.Event{Action: "groups.update", ObjectType: "group", ObjectID: strconv.FormatInt(id, 10), Details: details}
	if !s.change(w, r, ev, func(tx pgx.Tx, _ *audit.Event) error {
		if in.Name != nil {
			if err := s.rbac.RenameGroup(r.Context(), tx, id, *in.Name); err != nil {
				return err
			}
		}
		if move {
			return s.rbac.MoveGroup(r.Context(), tx, id, parent)
		}
		return nil
	}) {
		return
	}
	s.configChanged()
	w.WriteHeader(http.StatusNoContent)
}

/* deleteGroup removes a leaf group and the bindings scoped to it; a group with children is refused. */
func (s *server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	ev := audit.Event{Action: "groups.delete", ObjectType: "group", ObjectID: strconv.FormatInt(id, 10)}
	if !s.change(w, r, ev, func(tx pgx.Tx, _ *audit.Event) error {
		return s.rbac.DeleteGroup(r.Context(), tx, id)
	}) {
		return
	}
	s.configChanged()
	w.WriteHeader(http.StatusNoContent)
}
