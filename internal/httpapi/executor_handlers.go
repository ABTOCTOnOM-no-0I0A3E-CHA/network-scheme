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
