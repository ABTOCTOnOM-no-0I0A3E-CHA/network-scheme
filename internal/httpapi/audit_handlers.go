package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

/* Page size of GET /api/audit. */
const (
	defaultAuditPage = 50
	maxAuditPage     = 200
)

type auditResponse struct {
	ID         int64     `json:"id"`
	TS         time.Time `json:"ts"`
	Action     string    `json:"action"`
	UserID     *int64    `json:"user_id"`
	Result     string    `json:"result"`
	ObjectType string    `json:"object_type"`
	ObjectID   string    `json:"object_id"`
}

/*
listAudit returns audit events newest first, before_id exclusive. Details, IP
and user agent stay in the database; the listing shows who did what to what.
*/
func (s *server) listAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := defaultAuditPage
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxAuditPage {
			writeError(w, errBadRequest)
			return
		}
		limit = n
	}
	var before *int64
	if v := q.Get("before_id"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			writeError(w, errBadRequest)
			return
		}
		before = &n
	}
	rows, err := s.pool.Query(r.Context(),
		`SELECT id, ts, action, user_id, payload FROM audit.event
		 WHERE $1::bigint IS NULL OR id < $1 ORDER BY id DESC LIMIT $2`, before, limit)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (auditResponse, error) {
		var (
			e       auditResponse
			payload []byte
			p       struct {
				Result     string `json:"result"`
				ObjectType string `json:"object_type"`
				ObjectID   string `json:"object_id"`
			}
		)
		if err := row.Scan(&e.ID, &e.TS, &e.Action, &e.UserID, &payload); err != nil {
			return e, err
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return e, fmt.Errorf("audit event %d: %w", e.ID, err)
		}
		e.Result, e.ObjectType, e.ObjectID = p.Result, p.ObjectType, p.ObjectID
		return e, nil
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []auditResponse{}
	}
	writeJSON(w, http.StatusOK, out)
}
