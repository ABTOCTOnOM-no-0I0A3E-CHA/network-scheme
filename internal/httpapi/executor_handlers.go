package httpapi

import (
	"crypto/ed25519"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/audit"
	"github.com/beekamai/network-scheme/internal/auth"
	"github.com/beekamai/network-scheme/internal/rbac"
	"github.com/beekamai/network-scheme/internal/ticket"
)

/* ticketsPerMinute bounds the executor session tickets a user gets: every executor action needs a fresh one. */
const ticketsPerMinute = 20

type ticketResponse struct {
	Ticket    string    `json:"ticket"`
	ExpiresAt time.Time `json:"expires_at"`
}

/*
executorTicket issues a session ticket v1 for the caller (security.md 5.2):
only for the live session's user, read again from core.user in the
transaction that audits the issue (a disabled or deleted user gets none),
at most ticketsPerMinute a user. Refusals by the limit are audited at most
once a minute per user. The ticket grants nothing by itself: the executor
takes rights from its own registry and needs the user's change TOTP.
*/
func (s *server) executorTicket(w http.ResponseWriter, r *http.Request) {
	if len(s.ticketKey) != ed25519.PrivateKeySize {
		s.fail(w, r, errors.New("no ticket key configured"))
		return
	}
	sc, _ := sessionFrom(r.Context())
	uid, at := sc.sess.UserID, s.now()
	obj := strconv.FormatInt(uid, 10)
	if !s.ticketRL.allow(uid, at, ticketsPerMinute) {
		if s.ticketAuditRL.allow(uid, at, 1) {
			ev := audit.Event{Action: "executor.ticket", ObjectType: "user", ObjectID: obj, Details: map[string]any{}}
			s.change(w, r, ev, func(pgx.Tx, *audit.Event) error { return auth.ErrRateLimited })
			return
		}
		writeError(w, errRateLimited)
		return
	}
	var tok string
	var claims ticket.Claims
	ev := audit.Event{Action: "executor.ticket", ObjectType: "user", ObjectID: obj, Details: map[string]any{}}
	if !s.change(w, r, ev, func(tx pgx.Tx, ev *audit.Event) error {
		var name string
		var disabled bool
		err := tx.QueryRow(r.Context(), `SELECT username, disabled FROM core."user" WHERE id = $1`, uid).Scan(&name, &disabled)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && disabled) {
			return auth.ErrSessionExpired
		}
		if err != nil {
			return err
		}
		if tok, claims, err = ticket.Issue(s.ticketKey, uid, name, at); err != nil {
			return err
		}
		ev.Details["ticket"], ev.Details["expires"] = claims.ID(), claims.Expires
		return nil
	}) {
		s.ticketRL.refund(uid, at)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, ticketResponse{Ticket: tok, ExpiresAt: time.Unix(claims.Expires, 0).UTC()})
}

/*
executorFreeze asks the executor to freeze (security.md 5.1a): it only
inserts the caller's id into execpub.freeze_request (the api's sole right on
the executor) and answers 202; the executor freezes within 5 s. A request
already pending inserts nothing and is as good (target-less ON CONFLICT DO
NOTHING: the api has no SELECT on the table, migration 00026). Nothing here
can lift a freeze: the body is ignored, and only nmsctl on the host does
that. Audited (executor.freeze) with whether a request was already pending.
*/
func (s *server) executorFreeze(w http.ResponseWriter, r *http.Request) {
	sc, _ := sessionFrom(r.Context())
	uid := sc.sess.UserID
	ev := audit.Event{Action: "executor.freeze", ObjectType: "executor", ObjectID: "executor", Details: map[string]any{}}
	if !s.change(w, r, ev, func(tx pgx.Tx, ev *audit.Event) error {
		tag, err := tx.Exec(r.Context(), `INSERT INTO execpub.freeze_request (requested_by) VALUES ($1) ON CONFLICT DO NOTHING`, uid)
		if err != nil {
			return err
		}
		ev.Details["already_pending"] = tag.RowsAffected() == 0
		return nil
	}) {
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

/* executorStaleAfter: a status row older than this means the executor stopped publishing (it rewrites the row every 30 s). */
const executorStaleAfter = 90 * time.Second

type executorStatus struct {
	Known   bool       `json:"known"`
	Enabled bool       `json:"enabled"`
	Frozen  bool       `json:"frozen"`
	At      *time.Time `json:"at"`
	Stale   bool       `json:"stale"`
}

/*
executorStatusGet reports what the executor last published in
execpub.status: whether it is enabled (its policy) and frozen, when, and
whether that is older than executorStaleAfter by the database clock. known
is false while the executor never published.
*/
func (s *server) executorStatusGet(w http.ResponseWriter, r *http.Request) {
	var st executorStatus
	err := s.pool.QueryRow(r.Context(), `SELECT enabled, frozen, at, at < now() - make_interval(secs => $1) FROM execpub.status`,
		executorStaleAfter.Seconds()).Scan(&st.Enabled, &st.Frozen, &st.At, &st.Stale)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		s.fail(w, r, err)
		return
	default:
		st.Known = true
	}
	writeJSON(w, http.StatusOK, st)
}

/* Bounds of GET /api/devices/{id}/sessions. */
const (
	defaultSessionPage = 50
	maxSessionPage     = 200
)

type sessionSummary struct {
	SessionID  string     `json:"session_id"`
	UserID     int64      `json:"user_id"`
	Username   *string    `json:"username"`
	OpenedAt   time.Time  `json:"opened_at"`
	ClosedAt   *time.Time `json:"closed_at"`
	Status     string     `json:"status"`
	PostSHA256 *string    `json:"post_sha256"`
}

/*
deviceSessions lists the change sessions of a device in the caller's scope
(execpub.session_summary, newest first): a foreign or missing device answers
404, as every scoped device route. username is the panel's current name of
the user (null once deleted); post_sha256 is a 12-character prefix, as for
backups.
*/
func (s *server) deviceSessions(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	limit, okL := queryInt(r.URL.Query(), "limit", defaultSessionPage, 1, maxSessionPage)
	if !okL {
		writeError(w, errBadRequest)
		return
	}
	if _, err := s.authorizeDevice(r, rbac.PermDevicesRead, id); err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.pool.Query(r.Context(), `
		SELECT s.session_id::text, s.user_id, u.username, s.opened_at, s.closed_at, s.status,
		       left(encode(s.post_sha256, 'hex'), 12)
		FROM execpub.session_summary s LEFT JOIN core."user" u ON u.id = s.user_id
		WHERE s.device_id = $1 ORDER BY s.opened_at DESC, s.session_id LIMIT $2`, id, limit)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, pgx.RowToStructByPos[sessionSummary])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items == nil {
		items = []sessionSummary{}
	}
	writeJSON(w, http.StatusOK, struct {
		Items []sessionSummary `json:"items"`
	}{items})
}
