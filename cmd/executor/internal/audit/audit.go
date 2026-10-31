/*
Package audit is the executor's own audit chain in exec.audit_event, apart
from the panel's: every row stores the exact JSON bytes that were hashed,
hash = SHA-256(prev_hash || payload), and the head (last id, hash) is both in
exec.audit_head and, as the anchor, in the executor's state file. Rows are
appended only through the registry (registry.Tx.Audit, registry.Append),
which checks under its lock that the chain ends at the anchored head and
anchors the new head with the change; so a rewound head, a truncated tail or
a rewritten row is caught by the executor itself (security.md 10).
*/
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/state"
)

/* Results of an audited action (exec.audit_event.result). */
const (
	OK     = "ok"
	Denied = "denied"
	Error  = "error"
)

/* Bounds of the indexed columns (the table's CHECKs). */
const (
	maxUA      = 512
	maxObject  = 256
	maxPayload = 65536
)

var actionRe = regexp.MustCompile(`^[a-z0-9_.-]{1,64}$`)

/*
Event is one audit row. Its JSON encoding, in this field order with TS in
UTC at microsecond precision, is the hashed payload; the indexed columns
(ts, user_id, ip, ua, action, object, result) repeat it for queries and
must agree with it. UserID is the panel user the action is about or by
(nil for the host); Details never hold a secret.
*/
type Event struct {
	TS      time.Time      `json:"ts"`
	UserID  *int64         `json:"user_id"`
	IP      string         `json:"ip"`
	UA      string         `json:"user_agent"`
	Action  string         `json:"action"`
	Object  string         `json:"object"`
	Result  string         `json:"result"`
	Details map[string]any `json:"details"`
}

func chainHash(prev, payload []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write(payload)
	return h.Sum(nil)
}

/* cut returns s as valid UTF-8 of at most n bytes, cut on a character boundary. */
func cut(s string, n int) string {
	s = string(bytes.ToValidUTF8([]byte(s), []byte("?")))
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

/* prepare validates e and returns it normalized with its payload and its IP column. */
func prepare(e Event) (Event, []byte, *netip.Addr, error) {
	if !actionRe.MatchString(e.Action) {
		return e, nil, nil, fmt.Errorf("audit: bad action %q", e.Action)
	}
	if e.Result != OK && e.Result != Denied && e.Result != Error {
		return e, nil, nil, fmt.Errorf("audit: bad result %q", e.Result)
	}
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	e.TS = e.TS.UTC().Truncate(time.Microsecond)
	e.UA, e.Object = cut(e.UA, maxUA), cut(e.Object, maxObject)
	var ip *netip.Addr
	if e.IP != "" {
		a, err := netip.ParseAddr(e.IP)
		if err != nil || a.Zone() != "" {
			return e, nil, nil, fmt.Errorf("audit: bad ip %q", e.IP)
		}
		a = a.Unmap()
		e.IP, ip = a.String(), &a
	}
	payload, err := json.Marshal(e)
	if err != nil {
		return e, nil, nil, fmt.Errorf("audit: encode event: %w", err)
	}
	if len(payload) > maxPayload {
		return e, nil, nil, fmt.Errorf("audit: event of %d bytes", len(payload))
	}
	return e, payload, ip, nil
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

/*
Append returns the registry.Appender of events: each row chained on the
previous one, in order, and exec.audit_head moved to the last. Every id
must come after the head (ids only grow); anything else is tampering.
*/
func Append(events ...Event) registry.Appender {
	return func(ctx context.Context, tx pgx.Tx, head state.AuditHead) (state.AuditHead, error) {
		for _, ev := range events {
			e, payload, ip, err := prepare(ev)
			if err != nil {
				return head, err
			}
			hash := chainHash(head.Hash, payload)
			var c columns
			var gotPayload, gotPrev, gotHash []byte
			/* What was stored, read back: a trigger rewriting the row would be sealed into the anchor otherwise. */
			if err := tx.QueryRow(ctx, `INSERT INTO exec.audit_event (ts, user_id, ip, ua, action, object, result, payload, prev_hash, hash)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
				RETURNING id, ts, user_id, ip, ua, action, object, result, payload, prev_hash, hash`,
				e.TS, e.UserID, ip, nullable(e.UA), e.Action, nullable(e.Object), e.Result, payload, head.Hash, hash).Scan(
				&c.id, &c.ts, &c.userID, &c.ip, &c.ua, &c.action, &c.object, &c.result, &gotPayload, &gotPrev, &gotHash); err != nil {
				return head, fmt.Errorf("audit: insert event: %w", err)
			}
			id := c.id
			switch {
			case id <= head.LastID:
				return head, fmt.Errorf("%w: audit id %d after head %d", registry.ErrTampered, id, head.LastID)
			case !bytes.Equal(gotPayload, payload) || !bytes.Equal(gotPrev, head.Hash) || !bytes.Equal(gotHash, hash) || !c.match(payload):
				return head, fmt.Errorf("%w: audit row %d stored other values than appended", registry.ErrTampered, id)
			}
			head = state.AuditHead{LastID: id, Hash: hash}
		}
		if _, err := tx.Exec(ctx, `UPDATE exec.audit_head SET last_id = $1, hash = $2`, head.LastID, head.Hash); err != nil {
			return head, fmt.Errorf("audit: advance the head: %w", err)
		}
		return head, nil
	}
}

/* Break reasons reported by Verify. */
const (
	ReasonPrevMismatch    = "prev mismatch"
	ReasonHashMismatch    = "hash mismatch"
	ReasonIndexedMismatch = "indexed column mismatch"
	ReasonHeadMismatch    = "head mismatch"
	ReasonAnchorMissing   = "anchor missing (truncated or rewritten)"
)

/* Break is the first row at which the chain fails verification. */
type Break struct {
	ID     int64  `json:"id"`
	Reason string `json:"reason"`
}

/* Result is the verified prefix of the chain: Count rows up to LastID, ending in LastHash; Break is nil when all is intact. */
type Result struct {
	Count    int64  `json:"count"`
	LastID   int64  `json:"last_id"`
	LastHash []byte `json:"last_hash"`
	Break    *Break `json:"break,omitempty"`
}

/*
Verify recomputes the chain after base in id order inside tx (one
snapshot): each row chains on the previous (the first on base), its hash is
SHA-256(prev_hash || payload) over the stored bytes, its indexed columns
agree with the payload and ids strictly increase; exec.audit_head points at
the last row; and the chain contains anchor, the head committed in the
executor's state file (registry.AuditBounds gives both). The chain may
extend past the anchor (a change in flight) but never end before it nor
differ at it: that is a truncation or a rewrite, even with a matching
exec.audit_head. Rows up to base are not verified (base moves only on a
registry reset after a break). A broken chain is reported in Result.Break
with a nil error; err is for database failures.
*/
func Verify(ctx context.Context, tx pgx.Tx, base, anchor state.AuditHead) (Result, error) {
	res := Result{LastID: base.LastID, LastHash: base.Hash}
	var headID int64
	var headHash []byte
	if err := tx.QueryRow(ctx, `SELECT last_id, hash FROM exec.audit_head`).Scan(&headID, &headHash); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			res.Break = &Break{Reason: ReasonHeadMismatch}
			return res, nil
		}
		return res, fmt.Errorf("audit: read the head: %w", err)
	}
	rows, err := tx.Query(ctx, `SELECT id, ts, user_id, ip, ua, action, object, result, payload, prev_hash, hash
		FROM exec.audit_event WHERE id > $1 ORDER BY id`, base.LastID)
	if err != nil {
		return res, fmt.Errorf("audit: read events: %w", err)
	}
	defer rows.Close()
	anchored := anchor.LastID == base.LastID && bytes.Equal(anchor.Hash, base.Hash)
	for rows.Next() {
		var c columns
		var payload, prev, sum []byte
		if err := rows.Scan(&c.id, &c.ts, &c.userID, &c.ip, &c.ua, &c.action, &c.object, &c.result, &payload, &prev, &sum); err != nil {
			return res, fmt.Errorf("audit: scan event: %w", err)
		}
		reason := ""
		switch {
		case c.id <= res.LastID:
			reason = ReasonPrevMismatch
		case !anchored && c.id > anchor.LastID:
			reason = ReasonAnchorMissing
		case !bytes.Equal(prev, res.LastHash):
			reason = ReasonPrevMismatch
		case !bytes.Equal(chainHash(prev, payload), sum):
			reason = ReasonHashMismatch
		case !c.match(payload):
			reason = ReasonIndexedMismatch
		case c.id == anchor.LastID && !bytes.Equal(sum, anchor.Hash):
			reason = ReasonAnchorMissing
		}
		if reason != "" {
			res.Break = &Break{ID: c.id, Reason: reason}
			return res, nil
		}
		anchored = anchored || c.id == anchor.LastID
		res.Count++
		res.LastID, res.LastHash = c.id, sum
	}
	if err := rows.Err(); err != nil {
		return res, fmt.Errorf("audit: read events: %w", err)
	}
	switch {
	case !anchored:
		res.Break = &Break{ID: anchor.LastID, Reason: ReasonAnchorMissing}
	case headID != res.LastID || !bytes.Equal(headHash, res.LastHash):
		res.Break = &Break{ID: headID, Reason: ReasonHeadMismatch}
	}
	return res, nil
}

/* columns are the indexed columns of one row, as stored. */
type columns struct {
	id             int64
	ts             time.Time
	userID         *int64
	ip             *netip.Prefix
	ua, object     *string
	action, result string
}

/* match reports whether the indexed columns agree with the hashed payload. */
func (c columns) match(payload []byte) bool {
	var e Event
	if err := json.Unmarshal(payload, &e); err != nil {
		return false
	}
	ip := ""
	if c.ip != nil {
		ip = c.ip.Addr().String()
	}
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	sameUser := (e.UserID == nil) == (c.userID == nil) && (c.userID == nil || *e.UserID == *c.userID)
	return sameUser && e.TS.Equal(c.ts) && e.IP == ip && e.UA == str(c.ua) && e.Action == c.action &&
		e.Object == str(c.object) && e.Result == c.result
}
