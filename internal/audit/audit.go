/*
Package audit is the append-only, hash-chained audit log of the panel.
Every record stores the exact JSON bytes that were hashed;
hash = SHA-256(prev_hash || payload), and audit.chain_head holds the tail.
*/
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// HashSize is the length of every chain hash in bytes (SHA-256).
const HashSize = sha256.Size

/* zeroHash is the prev_hash of the first record and the hash of an empty chain. */
var zeroHash = make([]byte, HashSize)

/*
Event is one audit record. Its JSON encoding, in this field order with TS in
UTC (RFC 3339, microsecond precision), is the hashed payload.
*/
type Event struct {
	TS         time.Time      `json:"ts"`
	UserID     *int64         `json:"user_id"`
	IP         string         `json:"ip"`
	UserAgent  string         `json:"user_agent"`
	Action     string         `json:"action"`
	ObjectType string         `json:"object_type"`
	ObjectID   string         `json:"object_id"`
	Result     string         `json:"result"`
	Details    map[string]any `json:"details"`
}

// Querier is the read access Verify and CheckAnchors need; pgx.Tx and *pgxpool.Pool satisfy it.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func chainHash(prev, payload []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write(payload)
	return h.Sum(nil)
}

/*
Append adds e to the chain inside tx and returns its id. The chain head is
locked FOR UPDATE until tx ends, so concurrent appenders are serialised and
ids grow in chain order; a rolled-back tx leaves only an id gap. Use READ
COMMITTED (the default): under REPEATABLE READ a concurrent append makes the
head lock fail with a serialization error. A zero TS means now.
*/
func Append(ctx context.Context, tx pgx.Tx, e Event) (id int64, err error) {
	if e.Action == "" {
		return 0, errors.New("audit: empty action")
	}
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	/* timestamptz keeps microseconds: the indexed ts column must equal the payload. */
	e.TS = e.TS.UTC().Truncate(time.Microsecond)
	payload, err := json.Marshal(e)
	if err != nil {
		return 0, fmt.Errorf("audit: encode event: %w", err)
	}

	var prev []byte
	if err := tx.QueryRow(ctx,
		`SELECT hash FROM audit.chain_head FOR UPDATE`).Scan(&prev); err != nil {
		return 0, fmt.Errorf("audit: lock chain head: %w", err)
	}
	hash := chainHash(prev, payload)
	if err := tx.QueryRow(ctx,
		`INSERT INTO audit.event (ts, action, user_id, payload, prev_hash, hash)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		e.TS, e.Action, e.UserID, payload, prev, hash).Scan(&id); err != nil {
		return 0, fmt.Errorf("audit: insert event: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE audit.chain_head SET last_id = $1, hash = $2`, id, hash); err != nil {
		return 0, fmt.Errorf("audit: advance chain head: %w", err)
	}
	return id, nil
}
