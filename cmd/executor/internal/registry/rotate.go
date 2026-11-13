package registry

import (
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/state"
)

/*
Rekey re-MACs the rows outside the registry (the append-only session,
recording and changeset rows) inside the rotation's transaction. Run must
check each row's MAC under old and rewrite it under next over the very same
input: a row that does not verify fails the rotation, it is never vouched
for by the next key. Those tables are not locked (the executor's role may
update only their mac column, which LOCK does not accept): the daemon is
stopped meanwhile, and a row added behind the rotation's snapshot keeps the
retired key's MAC, so it fails its verification afterwards (never accepted).
*/
type Rekey struct {
	Run func(ctx context.Context, tx pgx.Tx, old, next *[32]byte) error
}

/* RotateTimeout bounds one rotation (the transaction and each of its statements): it rewrites every MAC in exec. */
const RotateTimeout = 30 * time.Minute

/* RotateReport tells what Rotate did. */
type RotateReport struct {
	Version int32 /* the next key's version */
	Rows    int   /* registry rows re-MACed, the counter included */
	TOTPs   int   /* change TOTP secrets re-sealed */
	Resumed bool  /* a committed rotation was finished */
	Already bool  /* the state file is the next key's already: nothing done */
}

/*
Rotate moves exec to the sealing key next. Under the registry's locks, in
one transaction, it verifies the whole registry under the current key,
re-puts every row at a new counter value with its MAC under next (the
change TOTP secrets re-sealed under next's enc subkey at next's version),
re-MACs the rows outside the registry (rekey) and appends audit; then it
commits in two phases through the state file: pending (MACed with the
current key and naming next by its ID) before COMMIT, committed (MACed with
next, at the next key version) after. Nothing else settles a pending
rotation (settle refuses it: the daemon freezes), so a crash leaves either
the old state (the transaction aborted: Rotate drops the record and starts
over) or a committed rotation that Rotate, called again with next,
finishes. Once the state file opens under next, Rotate does nothing. The
registry keeps the current keys: the process must not use it afterwards
(the executor's rotate command exits).
*/
func (r *Registry) Rotate(ctx context.Context, next *seal.Keys, audit Appender, rekey Rekey) (RotateReport, error) {
	var rep RotateReport
	if err := r.lock(ctx); err != nil {
		return rep, err
	}
	defer r.unlock()
	ctx, cancel := context.WithTimeout(ctx, RotateTimeout)
	defer cancel()
	if f, err := state.Load(r.path, next.State()); err == nil {
		rep.Version, rep.Already = f.SealVersion(), true
		return rep, nil
	}
	f, err := r.load()
	if err != nil {
		return rep, err
	}
	rep.Version = f.SealVersion() + 1
	if f.PendingKey != nil {
		if !hmac.Equal(f.PendingKey, next.ID()) {
			return rep, errors.New("registry: a rotation to another sealing key is in flight")
		}
		st, err := r.xactStatus(ctx, f.PendingXID)
		switch {
		case err != nil:
			return rep, err
		case st == "committed":
			rep.Resumed = true
			return rep, r.finish(f, next, rep.Version)
		case st == "aborted" || st == "":
			f.Pending, f.PendingXID, f.PendingKey = nil, 0, nil
			if err := r.save(f); err != nil {
				return rep, err
			}
		default:
			return rep, errUnsettled
		}
	}
	if f, err = r.settleWait(ctx, f); err != nil {
		return rep, err
	}
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return rep, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := pinSession(ctx, tx); err != nil {
		return rep, err
	}
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout = "+strconv.FormatInt(RotateTimeout.Milliseconds(), 10)); err != nil {
		return rep, err
	}
	if err := lockRegistry(ctx, tx); err != nil {
		return rep, err
	}
	var seq int64
	if err := tx.QueryRow(ctx, `SELECT seq FROM exec.registry_counter FOR UPDATE`).Scan(&seq); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return rep, tampered("registry_counter missing")
		}
		return rep, err
	}
	if err := checkCatalog(ctx, tx); err != nil {
		return rep, err
	}
	pre, err := scan(ctx, tx, r.keys.MAC())
	if err != nil {
		return rep, oversized(err)
	}
	hash, err := pre.check()
	if err != nil {
		return rep, err
	}
	if err := match(f, pre.seq, hash); err != nil {
		return rep, err
	}
	if err := checkAuditHead(ctx, tx, f.Committed.AuditHead); err != nil {
		return rep, err
	}
	ops, err := r.rotateOps(pre, next, f.SealVersion(), rep.Version, &rep)
	if err != nil {
		return rep, err
	}
	if err := fits(pre, ops); err != nil {
		return rep, err
	}
	if rekey.Run != nil {
		if err := rekey.Run(ctx, tx, r.keys.MAC(), next.MAC()); err != nil {
			return rep, oversized(err)
		}
	}
	rep.Rows = len(ops)
	r.step("rekeyed", tx)
	var appenders []Appender
	if audit != nil {
		appenders = []Appender{audit}
	}
	return rep, r.applyWith(ctx, tx, f, pre, ops, seq+1, f.Committed.AuditHead, appenders, next.MAC(),
		func(ctx context.Context, tx pgx.Tx, f state.File, rec state.Record) error {
			return r.commitRotation(ctx, tx, f, rec, next, rep.Version)
		})
}

/* rotateOps re-puts every registry row as it is, the change TOTP secrets re-sealed from version cur (current key) to nv (next). */
func (r *Registry) rotateOps(pre *Snapshot, next *seal.Keys, cur, nv int32, rep *RotateReport) ([]op, error) {
	counter, err := newPut(counterTable, map[string]any{"singleton": true})
	if err != nil {
		return nil, err
	}
	ops := []op{counter}
	for _, rw := range pre.rows {
		if rw.t.name == counterTable {
			continue
		}
		vals := map[string]any{}
		for _, c := range rw.t.columns() {
			vals[c.name] = rw.typed[c.name]
		}
		if rw.t.name == "change_totp" {
			user, _ := vals["user_id"].(int64)
			ct, _ := vals["ciphertext"].([]byte)
			if kv, _ := vals["key_version"].(int64); kv != int64(cur) {
				return nil, tampered("change TOTP of user #%d at key version %d, the key is at %d", user, kv, cur)
			}
			pt, err := r.keys.OpenTOTP(user, cur, ct)
			if err != nil {
				return nil, tampered("the change TOTP secret of user #%d does not open", user)
			}
			nct, err := next.SealTOTP(user, nv, pt)
			clear(pt)
			if err != nil {
				return nil, err
			}
			vals["ciphertext"], vals["key_version"] = nct, int64(nv)
			rep.TOTPs++
		}
		o, err := newPut(rw.t.name, vals)
		if err != nil {
			return nil, fmt.Errorf("registry rotate: %w", err)
		}
		ops = append(ops, o)
	}
	return ops, nil
}

/*
commitRotation records the rotation as pending in the state file under the
current key (with its transaction id and next's ID), commits, and writes
the committed record under next. A COMMIT that certainly did not happen
drops the record; an ambiguous one is left for Rotate to settle.
*/
func (r *Registry) commitRotation(ctx context.Context, tx pgx.Tx, f state.File, rec state.Record, next *seal.Keys, version int32) error {
	var xid string
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.pg_current_xact_id()::pg_catalog.text`).Scan(&xid); err != nil {
		return err
	}
	xid8, err := strconv.ParseUint(xid, 10, 64)
	if err != nil || xid8 == 0 {
		return fmt.Errorf("registry: transaction id %q", xid)
	}
	f.Pending, f.PendingXID, f.PendingKey = &rec, xid8, next.ID()
	if err := r.save(f); err != nil {
		return err
	}
	r.step("pending", tx)
	if err := r.commitTx(ctx, tx); err != nil {
		var pe *pgconn.PgError
		if (errors.As(err, &pe) && pe.SeverityUnlocalized == "ERROR") || pgconn.SafeToRetry(err) || errors.Is(err, pgx.ErrTxCommitRollback) {
			f.Pending, f.PendingXID, f.PendingKey = nil, 0, nil
			return errors.Join(err, r.save(f))
		}
		return fmt.Errorf("registry: the rotation's COMMIT may or may not have happened; run the rotation again to settle it: %w", err)
	}
	r.step("committed", tx)
	return r.finish(f, next, version)
}

/* finish writes the committed rotation (f.Pending) as the state file of next, at version, keeping the sticky freeze. */
func (r *Registry) finish(f state.File, next *seal.Keys, version int32) error {
	r.fileMu.Lock()
	defer r.fileMu.Unlock()
	cur, err := r.loadLocked()
	if err != nil {
		return err
	}
	f.Frozen, f.FreezeReason = cur.Frozen, cur.FreezeReason
	f.Committed, f.Pending, f.PendingXID, f.PendingKey, f.KeyVersion = *f.Pending, nil, 0, nil, version
	return state.Save(r.path, next.State(), f)
}

/*
RekeyTable re-MACs every row of one table outside the registry (a Rekey's
Run): query selects the rows; row scans one and returns its key (the
parameters of update after the MAC), its stored MAC and its MAC under the
current and the next key, both over the input its reader verifies. A stored
MAC other than the current one fails the rotation. update sets mac = $1
for the key ($2…) and must match only while mac is still the checked one
(its last parameter): any other outcome is tampering. It returns the number
of rows rewritten.
*/
func RekeyTable(ctx context.Context, tx pgx.Tx, table, query, update string,
	row func(rows pgx.Rows) (key []any, stored, mOld, mNext []byte, err error)) (int, error) {
	type change struct {
		key           []any
		stored, mNext []byte
	}
	rows, err := tx.Query(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("rekey %s: %w", table, err)
	}
	var all []change
	for rows.Next() {
		key, stored, mOld, mNext, err := row(rows)
		if err != nil {
			rows.Close()
			return 0, fmt.Errorf("rekey %s: %w", table, err)
		}
		if !hmac.Equal(stored, mOld) {
			rows.Close()
			return 0, tampered("rekey: a row of %s fails its MAC under the current key", table)
		}
		all = append(all, change{key, stored, mNext})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("rekey %s: %w", table, err)
	}
	args := make([][]any, len(all))
	for i, c := range all {
		args[i] = append(append([]any{c.mNext}, c.key...), c.stored)
	}
	return len(all), UpdateEach(ctx, tx, table, update, args)
}

/*
UpdateEach runs update once per argument list in tx, in batches; each must
change exactly one row (it matches the old value it replaces), any other
outcome is tampering.
*/
func UpdateEach(ctx context.Context, tx pgx.Tx, table, update string, args [][]any) error {
	for i := 0; i < len(args); i += rekeyBatch {
		b := &pgx.Batch{}
		for _, a := range args[i:min(i+rekeyBatch, len(args))] {
			b.Queue(update, a...)
		}
		res := tx.SendBatch(ctx, b)
		for range b.Len() {
			tag, err := res.Exec()
			if err == nil && tag.RowsAffected() != 1 {
				err = tampered("rekey: a row of %s changed under the rotation", table)
			}
			if err != nil {
				_ = res.Close()
				return err
			}
		}
		if err := res.Close(); err != nil {
			return err
		}
	}
	return nil
}

const rekeyBatch = 500
