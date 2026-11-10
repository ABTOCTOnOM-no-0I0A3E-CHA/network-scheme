/*
Package auditview is POST /x/audit (plan 4d.2): the executor's own audit
chain for a user with the audit-read grant and a change TOTP code (authz
decides and audits the request like every read). Filters: a time range,
the user, the action (exact, or a prefix ending in '*'), the device (the
object device:N or devices:..., or the details' device_id) and the result;
newest first, at most maxPage rows a page, the next page by the cursor (the
last id shown). Rows are read in a read-only transaction of the registry
(no connection of its own); every string that may come from a device or a
client (user agent, object, details) is cleaned like the terminal's output
and bounded, and the UI renders it as text only. Every view is itself an
audit row (audit.view, with its filters and the rows shown) and views per
user and hour are bounded (past it: refused, audited).
*/
package auditview

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/cmd/executor/internal/audit"
	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/internal/execadmin"
)

/* Actions: the read (authz's row) and the view's own row. */
const (
	ActionRead = "audit.read"
	ActionView = "audit.view"
)

/* Refusal is a refusal with the code the UI has a text for (web: 422). */
type Refusal string

func (r Refusal) Error() string { return "auditview: refused (" + string(r) + ")" }

/* RefusalCode is the code the UI has a text for. */
func (r Refusal) RefusalCode() string { return string(r) }

/* Refusals. */
const (
	ErrParams    Refusal = "bad_params"
	ErrViewLimit Refusal = "view_limit"
)

/* Bounds (variables for the tests). */
var (
	maxPage      = 100
	defPage      = 50
	maxDetails   = 4 << 10 /* bytes of a row's details shown; the rest is cut with a marker */
	viewsPerHour = 120
	readTimeout  = 15 * time.Second
)

/* Reader is the registry's read-only transaction (registry.Registry.Read). */
type Reader interface {
	Read(ctx context.Context, d time.Duration, fn func(ctx context.Context, tx pgx.Tx) error) error
}

/* Config builds a View; Now may be nil. */
type Config struct {
	Reg   Reader
	Clean func(string) string                       /* terminal.Clean */
	Audit func(ctx context.Context, ev audit.Event) /* authz.Authorizer.Record */
	Now   func() time.Time
}

/* View serves /x/audit. */
type View struct {
	c     Config
	mu    sync.Mutex
	views map[int64][]time.Time
}

/* New returns a View. */
func New(c Config) (*View, error) {
	if c.Reg == nil || c.Clean == nil || c.Audit == nil {
		return nil, errors.New("auditview: incomplete configuration")
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return &View{c: c, views: map[int64][]time.Time{}}, nil
}

/* Need is the read's grant: audit-read (ruling R3, as the recordings). */
func Need() authz.Need { return authz.Need{Kind: execadmin.KindAuditRead} }

/* Filter is the params of a read; every field optional. */
type Filter struct {
	From   *time.Time `json:"from,omitempty"`
	To     *time.Time `json:"to,omitempty"`
	User   int64      `json:"user_id,omitempty"`
	Action string     `json:"action,omitempty"`
	Device int64      `json:"device_id,omitempty"`
	Result string     `json:"result,omitempty"`
	Before int64      `json:"before,omitempty"` /* the cursor: rows with a smaller id */
	Limit  int        `json:"limit,omitempty"`
}

var actionRe = regexp.MustCompile(`^[a-z0-9_.-]{1,64}\*?$`)

func (f *Filter) check() error {
	switch {
	case f.User < 0, f.Device < 0, f.Before < 0, f.Limit < 0 || f.Limit > maxPage,
		f.Action != "" && !actionRe.MatchString(f.Action),
		f.Result != "" && f.Result != audit.OK && f.Result != audit.Denied && f.Result != audit.Error,
		f.From != nil && f.To != nil && !f.From.Before(*f.To):
		return ErrParams
	}
	if f.Limit == 0 {
		f.Limit = defPage
	}
	return nil
}

/* Row is one audit row as shown: text only, cleaned. */
type Row struct {
	ID      int64     `json:"id"`
	TS      time.Time `json:"ts"`
	User    *int64    `json:"user_id"`
	IP      string    `json:"ip"`
	UA      string    `json:"user_agent"`
	Action  string    `json:"action"`
	Object  string    `json:"object"`
	Result  string    `json:"result"`
	Details string    `json:"details"` /* the details as compact JSON text, cleaned and bounded */
}

/* Page is a read's answer; Next is the cursor of the next page (0: none). */
type Page struct {
	Rows []Row `json:"rows"`
	Next int64 `json:"next"`
}

func nullable[T comparable](v T) *T {
	var zero T
	if v == zero {
		return nil
	}
	return &v
}

/* Run is the read's Run: the limit, the rows, the view's own audit row. */
func (v *View) Run(ctx context.Context, by authz.Decision, params json.RawMessage) (any, error) {
	var f Filter
	dec := json.NewDecoder(bytes.NewReader(params))
	dec.DisallowUnknownFields()
	if len(params) == 0 || dec.Decode(&f) != nil || dec.More() || f.check() != nil {
		return nil, ErrParams
	}
	user := by.UserID
	ev := audit.Event{UserID: &user, Action: ActionView, Object: "audit", Result: audit.OK, Details: map[string]any{"filter": f}}
	if !v.take(user) {
		ev.Result, ev.Details["class"] = audit.Denied, string(ErrViewLimit)
		v.c.Audit(ctx, ev)
		return nil, ErrViewLimit
	}
	p, err := v.read(ctx, f)
	if err != nil {
		ev.Result = audit.Error
		v.c.Audit(ctx, ev)
		return nil, fmt.Errorf("%w: %w", authz.ErrUnavailable, err)
	}
	ev.Details["rows"] = len(p.Rows)
	v.c.Audit(ctx, ev)
	return p, nil
}

func (v *View) read(ctx context.Context, f Filter) (Page, error) {
	var prefix, exact *string
	if f.Action != "" {
		if a, ok := cutStar(f.Action); ok {
			prefix = &a
		} else {
			exact = &f.Action
		}
	}
	var dev *string
	if f.Device > 0 {
		s := strconv.FormatInt(f.Device, 10)
		dev = &s
	}
	p := Page{Rows: []Row{}}
	err := v.c.Reg.Read(ctx, readTimeout, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, ts, user_id, COALESCE(pg_catalog.host(ip), ''), COALESCE(ua, ''), action, COALESCE(object, ''), result, payload
			FROM exec.audit_event
			WHERE ($1::timestamptz IS NULL OR ts >= $1) AND ($2::timestamptz IS NULL OR ts < $2)
				AND ($3::bigint IS NULL OR user_id = $3)
				AND ($4::text IS NULL OR action = $4)
				AND ($5::text IS NULL OR pg_catalog.left(action, pg_catalog.length($5)) = $5)
				AND ($6::text IS NULL OR result = $6)
				AND ($7::bigint IS NULL OR id < $7)
				AND ($8::text IS NULL OR object = 'device:' || $8
					OR (pg_catalog.left(object, 8) = 'devices:' AND ',' || pg_catalog.substr(object, 9) || ',' LIKE '%,' || $8 || ',%')
					OR pg_catalog.convert_from(payload, 'UTF8')::jsonb #>> '{details,device_id}' = $8)
			ORDER BY id DESC LIMIT $9`,
			f.From, f.To, nullable(f.User), exact, prefix, nullable(f.Result), nullable(f.Before), dev, f.Limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				r       Row
				payload []byte
			)
			if err := rows.Scan(&r.ID, &r.TS, &r.User, &r.IP, &r.UA, &r.Action, &r.Object, &r.Result, &payload); err != nil {
				return err
			}
			r.UA, r.Object, r.Details = v.c.Clean(r.UA), v.c.Clean(r.Object), v.details(payload)
			p.Rows = append(p.Rows, r)
		}
		return rows.Err()
	})
	if len(p.Rows) == f.Limit {
		p.Next = p.Rows[len(p.Rows)-1].ID
	}
	return p, err
}

func cutStar(s string) (string, bool) {
	if n := len(s); n > 1 && s[n-1] == '*' {
		return s[:n-1], true
	}
	return "", false
}

/* details is the payload's details as compact JSON text, cleaned, at most maxDetails bytes (cut on a character, marked). */
func (v *View) details(payload []byte) string {
	var e struct {
		Details json.RawMessage `json:"details"`
	}
	var b bytes.Buffer
	if json.Unmarshal(payload, &e) != nil || json.Compact(&b, e.Details) != nil {
		return "(unreadable)"
	}
	s := v.c.Clean(b.String())
	if len(s) > maxDetails {
		n := maxDetails
		for n > 0 && !utf8.RuneStart(s[n]) {
			n--
		}
		s = s[:n] + " …"
	}
	return s
}

/* take counts a view of user; false past viewsPerHour in the last hour. */
func (v *View) take(user int64) bool {
	now := v.c.Now()
	v.mu.Lock()
	defer v.mu.Unlock()
	k := 0
	at := v.views[user]
	for _, t := range at {
		if now.Sub(t) < time.Hour {
			at[k] = t
			k++
		}
	}
	at = at[:k]
	if len(at) >= viewsPerHour {
		v.views[user] = at
		return false
	}
	v.views[user] = append(at, now)
	return true
}
