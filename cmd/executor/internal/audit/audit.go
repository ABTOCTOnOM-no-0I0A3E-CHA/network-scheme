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
			/*
				What was stored, read back: a BEFORE trigger rewriting the row would be
				sealed into the anchor otherwise. An AFTER trigger changing it later is
				not seen here (the full verification and the catalog check of 4d.2 are).
			*/
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
	ReasonSealedMismatch  = "sealed segment changed"
	ReasonNoAnchor        = "no anchor (state file unreadable)"
	ReasonUnvouched       = "rows before it are not vouched by a trusted hash (rewritten)"
)

/* Break is the first row at which the chain fails verification. */
type Break struct {
	ID     int64  `json:"id"`
	Reason string `json:"reason"`
}

/*
Result of a verification: Count rows verified (sealed segments and the live
chain up to the anchor), Unanchored rows after the anchor (a change in
flight, or rows nothing vouches for), Unverified rows outside every checked
range (before a base a reset moved); the last row of the chain (LastID,
LastHash); Break is nil when all that is checked is intact.
*/
type Result struct {
	Count      int64  `json:"count"`
	Unanchored int64  `json:"unanchored"`
	Unverified int64  `json:"unverified"`
	LastID     int64  `json:"last_id"`
	LastHash   []byte `json:"last_hash"`
	Break      *Break `json:"break,omitempty"`
}

func same(a, b state.AuditHead) bool { return a.LastID == b.LastID && bytes.Equal(a.Hash, b.Hash) }

/*
walk checks the rows after from in id order (up to toID; 0: all): ids
strictly increase, each row chains on the previous (the first on from), its
hash is SHA-256(prev_hash || payload) over the stored bytes and its indexed
columns agree with the payload; then check may refuse the row or end the
walk. It returns the head of the last row that passed, how many passed, and
the first break.
*/
func walk(ctx context.Context, tx pgx.Tx, from state.AuditHead, toID int64,
	check func(id int64, sum []byte) (reason string, stop bool)) (state.AuditHead, int64, *Break, error) {
	last, n := from, int64(0)
	rows, err := tx.Query(ctx, `SELECT id, ts, user_id, ip, ua, action, object, result, payload, prev_hash, hash
		FROM exec.audit_event WHERE id > $1 AND ($2 = 0 OR id <= $2) ORDER BY id`, from.LastID, toID)
	if err != nil {
		return last, n, nil, fmt.Errorf("audit: read events: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var c columns
		var payload, prev, sum []byte
		if err := rows.Scan(&c.id, &c.ts, &c.userID, &c.ip, &c.ua, &c.action, &c.object, &c.result, &payload, &prev, &sum); err != nil {
			return last, n, nil, fmt.Errorf("audit: scan event: %w", err)
		}
		reason, stop := "", false
		switch {
		case c.id <= last.LastID, !bytes.Equal(prev, last.Hash):
			reason = ReasonPrevMismatch
		case !bytes.Equal(chainHash(prev, payload), sum):
			reason = ReasonHashMismatch
		case !c.match(payload):
			reason = ReasonIndexedMismatch
		case check != nil:
			reason, stop = check(c.id, sum)
		}
		if reason != "" {
			return last, n, &Break{ID: c.id, Reason: reason}, nil
		}
		last, n = state.AuditHead{LastID: c.id, Hash: sum}, n+1
		if stop {
			break
		}
	}
	return last, n, nil, rows.Err()
}

/* sealed checks one sealed segment: it must chain from From and end exactly at To. */
func sealed(ctx context.Context, tx pgx.Tx, g state.Segment) (state.AuditHead, int64, *Break, error) {
	last, n, brk, err := walk(ctx, tx, g.From, g.To.LastID, nil)
	if err == nil && brk == nil && !same(last, g.To) {
		brk = &Break{ID: g.To.LastID, Reason: ReasonSealedMismatch}
	}
	return last, n, brk, err
}

/*
live checks the live chain from base against anchor, up to the anchor: a row
after the anchor id while the anchor was not seen, or a row at its id with
another hash, is a truncation or a rewrite. It returns the end of the
verified prefix, the rows verified, whether the anchor was reached, and the
first break.
*/
func live(ctx context.Context, tx pgx.Tx, base, anchor state.AuditHead) (state.AuditHead, int64, bool, *Break, error) {
	if same(base, anchor) {
		return base, 0, true, nil, nil
	}
	reached := false
	last, n, brk, err := walk(ctx, tx, base, 0, func(id int64, sum []byte) (string, bool) {
		switch {
		case id > anchor.LastID:
			return ReasonAnchorMissing, false
		case id == anchor.LastID && !bytes.Equal(sum, anchor.Hash):
			return ReasonAnchorMissing, false
		case id == anchor.LastID:
			reached = true
			return "", true
		}
		return "", false
	})
	if err == nil && brk == nil && !reached {
		brk = &Break{ID: anchor.LastID, Reason: ReasonAnchorMissing}
	}
	return last, n, reached, brk, err
}

/* stats reads the last row of the chain (or the empty head), the number of rows and of those after id. */
func stats(ctx context.Context, tx pgx.Tx, after int64) (state.AuditHead, int64, int64, error) {
	tail := state.AuditHead{Hash: make([]byte, sha256.Size)}
	var total, past int64
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.count(*), pg_catalog.count(*) FILTER (WHERE id > $1) FROM exec.audit_event`,
		after).Scan(&total, &past); err != nil {
		return tail, 0, 0, fmt.Errorf("audit: count events: %w", err)
	}
	err := tx.QueryRow(ctx, `SELECT id, hash FROM exec.audit_event ORDER BY id DESC LIMIT 1`).Scan(&tail.LastID, &tail.Hash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return tail, 0, 0, fmt.Errorf("audit: read the tail: %w", err)
	}
	return tail, total, past, nil
}

/*
Verify checks the audit chain inside tx (one snapshot) against c (the state
file's view, registry.AuditChain): every sealed segment again, then the live
chain from its base up to and including the anchor, the head committed in
the state file. The chain may extend past the anchor (a change in flight:
reported as Unanchored, not counted as verified) but never end before it
nor differ at it: that is a truncation or a rewrite, even with a matching
exec.audit_head, which must point at the last row. A broken chain is
reported in Result.Break with a nil error; err is for database failures.
*/
func Verify(ctx context.Context, tx pgx.Tx, c state.Chain) (Result, error) {
	var res Result
	var headID int64
	var headHash []byte
	if err := tx.QueryRow(ctx, `SELECT last_id, hash FROM exec.audit_head`).Scan(&headID, &headHash); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			res.Break = &Break{Reason: ReasonHeadMismatch}
			return res, nil
		}
		return res, fmt.Errorf("audit: read the head: %w", err)
	}
	tail, total, past, err := stats(ctx, tx, c.Anchor.LastID)
	if err != nil {
		return res, err
	}
	res.LastID, res.LastHash = tail.LastID, tail.Hash
	for _, g := range c.Sealed {
		_, n, brk, err := sealed(ctx, tx, g)
		if err != nil || brk != nil {
			res.Break = brk
			return res, err
		}
		res.Count += n
	}
	_, n, _, brk, err := live(ctx, tx, c.Base, c.Anchor)
	if err != nil || brk != nil {
		res.Break = brk
		return res, err
	}
	res.Count += n
	res.Unanchored = past
	res.Unverified = total - res.Count - past
	if headID != tail.LastID || !bytes.Equal(headHash, tail.Hash) {
		res.Break = &Break{ID: headID, Reason: ReasonHeadMismatch}
	}
	return res, nil
}

/* Range is the rows after From up to To (ids). */
type Range struct {
	From int64 `json:"after"`
	To   int64 `json:"to"`
}

/* Plan is what a registry reset does with the audit chain (PlanReset). */
type Plan struct {
	Chain      state.Chain     /* the new sealed segments and base (Anchor unused) */
	Intact     bool            /* everything covered before is vouched in full and nothing lies past the anchor */
	Break      *Break          /* the first break found, if any */
	Vouched    []state.Segment /* the ranges a trusted end hash proves (kept sealed), with their endpoint hashes */
	Suspect    []Range         /* ranges covered before that no trusted end proves any more: may be forged */
	Unanchored int64           /* rows after the anchor (all rows when the state file was unreadable) */
}

/*
vouch walks back from end, a trusted head (the state file's anchor or a
sealed segment's To), down to floor. The row at end's id must exist, carry
end's hash and verify itself (hash over prev_hash and payload, indexed
columns); each earlier row must verify itself too and its hash must be the
prev_hash of the vouched row after it. The walk stops at the first row that
fails (or at floor) and returns the vouched segment: From is that row's id
(or floor) with the prev_hash of the earliest vouched row. A hash chain
proves rows only backward from a trusted end hash: forward from a start
hash anyone can recompute it. ok is false when the end row itself fails:
then nothing in the range is vouched.
*/
func vouch(ctx context.Context, tx pgx.Tx, end state.AuditHead, floor int64) (state.Segment, bool, error) {
	rows, err := tx.Query(ctx, `SELECT id, ts, user_id, ip, ua, action, object, result, payload, prev_hash, hash
		FROM exec.audit_event WHERE id > $1 AND id <= $2 ORDER BY id DESC`, floor, end.LastID)
	if err != nil {
		return state.Segment{}, false, fmt.Errorf("audit: read events: %w", err)
	}
	defer rows.Close()
	from, expect, n := floor, end.Hash, 0
	for rows.Next() {
		var c columns
		var payload, prev, sum []byte
		if err := rows.Scan(&c.id, &c.ts, &c.userID, &c.ip, &c.ua, &c.action, &c.object, &c.result, &payload, &prev, &sum); err != nil {
			return state.Segment{}, false, fmt.Errorf("audit: scan event: %w", err)
		}
		if (n == 0 && c.id != end.LastID) || !bytes.Equal(sum, expect) || !bytes.Equal(chainHash(prev, payload), sum) || !c.match(payload) {
			from = c.id
			break
		}
		n++
		expect = prev
	}
	if err := rows.Err(); err != nil {
		return state.Segment{}, false, fmt.Errorf("audit: read events: %w", err)
	}
	if n == 0 {
		return state.Segment{}, end.LastID == floor, nil
	}
	return state.Segment{From: state.AuditHead{LastID: from, Hash: expect}, To: end}, true, nil
}

/*
PlanReset decides how a registry reset continues the audit chain, whose
last row is tail, from what the state file said (old; known is false when
it was unreadable: then nothing is vouched). Only trusted end hashes vouch
for rows, walking backward: each sealed segment's To and the anchor. An
intact chain (everything it covered is vouched, nothing past the anchor)
keeps its bounds. Otherwise only the vouched ranges are kept, as sealed
segments that every later verification checks, and the live chain starts
again at the tail; everything else is reported: ranges that may be forged
and rows past the anchor that nothing vouches for. A range never ends
anywhere but at a trusted end, so a forged prefix is never sealed.
*/
func PlanReset(ctx context.Context, tx pgx.Tx, old state.Chain, known bool, tail state.AuditHead) (Plan, error) {
	if !known {
		_, total, _, err := stats(ctx, tx, 0)
		return Plan{Chain: state.Chain{Base: tail}, Break: &Break{Reason: ReasonNoAnchor}, Unanchored: total,
			Suspect: []Range{{From: 0, To: tail.LastID}}}, err
	}
	p := Plan{Intact: true}
	fail := func(b *Break, r Range) {
		p.Intact = false
		if p.Break == nil {
			p.Break = b
		}
		if r.To > r.From {
			p.Suspect = append(p.Suspect, r)
		}
	}
	check := func(start, end state.AuditHead, reason string) error {
		if end.LastID <= start.LastID {
			if !same(start, end) {
				fail(&Break{ID: end.LastID, Reason: reason}, Range{})
			}
			return nil
		}
		seg, ok, err := vouch(ctx, tx, end, start.LastID)
		switch {
		case err != nil:
			return err
		case !ok:
			fail(&Break{ID: end.LastID, Reason: reason}, Range{From: start.LastID, To: end.LastID})
			return nil
		case !same(seg.From, start):
			fail(&Break{ID: seg.From.LastID, Reason: ReasonUnvouched}, Range{From: start.LastID, To: seg.From.LastID})
		}
		p.Vouched = append(p.Vouched, seg)
		return nil
	}
	for _, g := range old.Sealed {
		if err := check(g.From, g.To, ReasonSealedMismatch); err != nil {
			return p, err
		}
	}
	if err := check(old.Base, old.Anchor, ReasonAnchorMissing); err != nil {
		return p, err
	}
	var err error
	if _, _, p.Unanchored, err = stats(ctx, tx, max(old.Anchor.LastID, old.Base.LastID)); err != nil {
		return p, err
	}
	if p.Unanchored > 0 {
		p.Intact = false
	}
	if p.Intact {
		p.Chain = state.Chain{Sealed: old.Sealed, Base: old.Base}
		return p, nil
	}
	p.Chain = state.Chain{Sealed: p.Vouched, Base: tail}
	return p, nil
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
