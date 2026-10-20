package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Break reasons reported by Verify.
const (
	ReasonHashMismatch    = "hash mismatch"
	ReasonPrevMismatch    = "prev mismatch"
	ReasonIndexedMismatch = "indexed column mismatch"
	ReasonHeadMismatch    = "head mismatch"
)

// Break is the first record at which the chain fails verification.
type Break struct {
	ID     int64
	Reason string
}

/*
VerifyResult describes the verified prefix of the chain: Count records up to
LastID, ending in LastHash. Break is nil when the whole chain and its head
are intact.
*/
type VerifyResult struct {
	Count    int64
	LastID   int64
	LastHash []byte
	Break    *Break
}

/*
The head travels with every row as uncorrelated scalar subqueries (evaluated
once), so events and head come from one statement snapshot even on a pool,
while rows still stream in id order from the primary key.
*/
const verifySQL = `SELECT id, ts, action, user_id, payload, prev_hash, hash,
	(SELECT last_id FROM audit.chain_head), (SELECT hash FROM audit.chain_head)
	FROM audit.event ORDER BY id`

/* emptySQL checks the head of a log that looked empty, in one snapshot. */
const emptySQL = `SELECT last_id, hash, EXISTS (SELECT 1 FROM audit.event)
	FROM audit.chain_head`

/* maxAttempts bounds restarts when the log stops being empty mid-verification. */
const maxAttempts = 3

/*
Verify streams the log in id order and recomputes the chain. Each payload is
hashed as stored, never re-serialised; the indexed columns (action, user_id,
ts) must match the payload, and the last record must match audit.chain_head.
A broken chain is reported in VerifyResult.Break with a nil error; err is for
database failures only. Truncation together with a rewritten head is only
caught by CheckAnchors.
*/
func Verify(ctx context.Context, q Querier) (VerifyResult, error) {
	for range maxAttempts {
		res, empty, err := verifyOnce(ctx, q)
		if err != nil || !empty {
			return res, err
		}
		var headID int64
		var headHash []byte
		var appeared bool
		err = q.QueryRow(ctx, emptySQL).Scan(&headID, &headHash, &appeared)
		if errors.Is(err, pgx.ErrNoRows) {
			res.Break = &Break{Reason: ReasonHeadMismatch}
			return res, nil
		}
		if err != nil {
			return res, fmt.Errorf("audit: read chain head: %w", err)
		}
		if appeared {
			continue /* the first record was committed meanwhile: verify again */
		}
		if headID != 0 || !bytes.Equal(headHash, zeroHash) {
			res.Break = &Break{ID: headID, Reason: ReasonHeadMismatch}
		}
		return res, nil
	}
	return VerifyResult{}, errors.New("audit: log kept changing during verification")
}

/* verifyOnce verifies a non-empty log; empty reports that no rows were seen. */
func verifyOnce(ctx context.Context, q Querier) (res VerifyResult, empty bool, err error) {
	res.LastHash = zeroHash
	rows, err := q.Query(ctx, verifySQL)
	if err != nil {
		return res, false, fmt.Errorf("audit: read events: %w", err)
	}
	defer rows.Close()

	var (
		seen               bool
		id                 int64
		headID             *int64 /* NULL when the head row is gone */
		ts                 time.Time
		action             string
		userID             *int64
		payload, prev, sum []byte
		headHash           []byte
	)
	for rows.Next() {
		if err := rows.Scan(&id, &ts, &action, &userID, &payload, &prev, &sum, &headID, &headHash); err != nil {
			return res, false, fmt.Errorf("audit: scan event: %w", err)
		}
		seen = true
		reason := ""
		switch {
		case !bytes.Equal(prev, res.LastHash):
			reason = ReasonPrevMismatch
		case !bytes.Equal(chainHash(prev, payload), sum):
			reason = ReasonHashMismatch
		case !indexedMatch(payload, ts, action, userID):
			reason = ReasonIndexedMismatch
		}
		if reason != "" {
			res.Break = &Break{ID: id, Reason: reason}
			return res, false, nil
		}
		res.Count++
		res.LastID, res.LastHash = id, sum
	}
	if err := rows.Err(); err != nil {
		return res, false, fmt.Errorf("audit: read events: %w", err)
	}
	if !seen {
		return res, true, nil
	}
	if headID == nil {
		res.Break = &Break{Reason: ReasonHeadMismatch}
	} else if *headID != res.LastID || !bytes.Equal(headHash, res.LastHash) {
		res.Break = &Break{ID: *headID, Reason: ReasonHeadMismatch}
	}
	return res, false, nil
}

/* indexedMatch reports whether the query columns agree with the hashed payload. */
func indexedMatch(payload []byte, ts time.Time, action string, userID *int64) bool {
	var p struct {
		TS     time.Time `json:"ts"`
		Action string    `json:"action"`
		UserID *int64    `json:"user_id"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return false
	}
	sameUser := (p.UserID == nil) == (userID == nil) && (userID == nil || *p.UserID == *userID)
	return p.Action == action && p.TS.Equal(ts) && sameUser
}
