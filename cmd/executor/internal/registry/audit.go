package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/cmd/executor/internal/state"
)

/*
Appender appends rows to the executor's audit chain (package audit) inside
tx, starting from head, and returns the new head. The registry runs it under
its lock in the transaction of a change (Tx.Audit) or alone (Append), then
insists the chain in the database ends exactly at the returned head and
anchors that head in the state file with the change: exec.audit_head can
then never be put back without the next verification seeing it.
*/
type Appender func(ctx context.Context, tx pgx.Tx, head state.AuditHead) (state.AuditHead, error)

/*
checkAuditHead insists that the chain in the database ends at want, the head
anchored in the state file: exec.audit_head says so, the row it points to
has that hash and no row comes after it. A rewound or rewritten head, a
truncated tail or a row planted after the head is tampering. O(1): the whole
chain is verified by package audit (nmsctl executor audit verify).
*/
func checkAuditHead(ctx context.Context, tx pgx.Tx, want state.AuditHead) error {
	var lastID int64
	var hash, rowHash []byte
	var maxID *int64
	if err := tx.QueryRow(ctx, `SELECT h.last_id, h.hash,
			(SELECT pg_catalog.max(e.id) FROM exec.audit_event e),
			(SELECT e.hash FROM exec.audit_event e WHERE e.id = h.last_id)
		FROM exec.audit_head h`).Scan(&lastID, &hash, &maxID, &rowHash); err != nil {
		return fmt.Errorf("registry: read audit_head: %w", err)
	}
	switch {
	case lastID != want.LastID || !bytes.Equal(hash, want.Hash):
		return tampered("audit chain head %d does not match the state file (%d)", lastID, want.LastID)
	case want.LastID == 0 && maxID != nil:
		return tampered("audit rows without a head")
	case want.LastID != 0 && (maxID == nil || *maxID != want.LastID || !bytes.Equal(rowHash, want.Hash)):
		return tampered("audit chain does not end at its head %d", want.LastID)
	}
	return nil
}

/* appendAudit runs the appenders from head and checks the chain ends at the head they return. */
func appendAudit(ctx context.Context, tx pgx.Tx, head state.AuditHead, audit []Appender) (state.AuditHead, error) {
	if len(audit) == 0 {
		return head, nil
	}
	var err error
	for _, a := range audit {
		if head, err = a(ctx, tx, head); err != nil {
			return head, err
		}
	}
	if head.LastID <= 0 || len(head.Hash) != sha256.Size {
		return head, fmt.Errorf("registry: appender returned head %d", head.LastID)
	}
	return head, checkAuditHead(ctx, tx, head)
}

/*
Append adds rows to the executor's audit chain without changing the
registry, under the registry's lock and through the same two-phase record
in the state file (the new head is anchored there). It runs while frozen
too: a freeze stops decisions, not their record. The chain must end at the
anchored head first (else ErrTampered: freeze). As for Write, an error other
than ErrTampered does not mean the rows were not appended.
*/
func (r *Registry) Append(ctx context.Context, a Appender) error {
	if err := r.lock(ctx); err != nil {
		return err
	}
	defer r.unlock()
	ctx, cancel := context.WithTimeout(ctx, r.opTimeout)
	defer cancel()
	f, err := r.load()
	if err != nil {
		return err
	}
	if f, err = r.settle(ctx, f); err != nil {
		return err
	}
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := pinSession(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `LOCK TABLE exec.audit_head IN EXCLUSIVE MODE`); err != nil {
		return err
	}
	if err := checkAuditHead(ctx, tx, f.Committed.AuditHead); err != nil {
		return err
	}
	head, err := appendAudit(ctx, tx, f.Committed.AuditHead, []Appender{a})
	if err != nil {
		return err
	}
	next := f.Committed
	next.AuditHead = head
	return r.commit(ctx, tx, f, next)
}

/*
AuditChain is what the audit chain is verified against (state.File.Chain):
the sealed segments a registry reset kept, the base the live chain is
verified from, and the anchor, the head committed in the state file. The
chain in the database always extends the anchor (a change in flight only
adds rows), so a chain that does not contain it was truncated or rewritten.
*/
func (r *Registry) AuditChain() (state.Chain, error) {
	f, err := r.load()
	return f.Chain(), err
}

/*
Read runs fn in a read-only transaction pinned to pg_catalog and bounded by
d (server and client side), without the registry's lock, for what is not
the registry: the audit chain (package audit) and core.user, read for
display and refusal only (deny-only, security.md 5.1a). Decisions never read
the registry here (TestRegistryBoundary): only View hands out verified
registry rows.
*/
func (r *Registry) Read(ctx context.Context, d time.Duration, fn func(ctx context.Context, tx pgx.Tx) error) error {
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := pinSession(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL statement_timeout = %d", d.Milliseconds())); err != nil {
		return err
	}
	return fn(ctx, tx)
}
