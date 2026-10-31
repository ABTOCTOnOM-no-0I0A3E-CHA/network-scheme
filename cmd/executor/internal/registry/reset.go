package registry

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"os"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/cmd/executor/internal/state"
)

/* ResetDevice is a device kept by a reset, for the host to check its address before accepting a host key again. */
type ResetDevice struct {
	ID      int64      `json:"id"`
	Address netip.Addr `json:"address"`
}

/* ResetReport says what a registry reset changed. */
type ResetReport struct {
	Seq     int64         /* the counter value every row now carries */
	Grants  int           /* grants revoked */
	TOTPs   int           /* change TOTP enrollments removed */
	Devices []ResetDevice /* devices kept with writes disabled, host key cleared and both flags off */
	/* Profiles is the number of confirmed model profiles removed. */
	Profiles int
	/* OldAnchor is the audit head the state file held (zero if it was unreadable); Tail the chain's actual last row the reset continues from. */
	OldAnchor, Tail state.AuditHead
	/* Base is where the verification of the audit chain starts from now on: unchanged if the rows from the old base reach Tail intact, else Tail. */
	Base state.AuditHead
}

/* ResetOptions are the parts of a reset that belong to the audit package. */
type ResetOptions struct {
	/* Audit returns the appender of the reset's own audit row (required). */
	Audit func(ResetReport) Appender
	/* ChainIntact reports whether the rows from base to tail chain correctly (whatever exec.audit_head says). */
	ChainIntact func(ctx context.Context, tx pgx.Tx, base, tail state.AuditHead) (bool, error)
}

/*
Reset is the way out of a freeze after real tampering (host only: nmsctl
executor registry reset --i-understand, security.md 5.1a). Nothing in the
registry can be trusted any more, so it keeps only what grants nothing on
its own and re-seals it under a new base:

  - every grant is revoked;
  - every change TOTP enrollment is removed (an older secret of the same
    user, a reset failure counter or last step could have been put back):
    users enroll again;
  - every device keeps its id, address, port, line and group, with
    writes_enabled, allow_ssh_rsa_sha1 and backup_via_executor false and no
    pinned host key (a planted pin would otherwise be sealed as accepted);
    the report lists them, since the address may be the attacker's: it is
    confirmed again when the host key is accepted;
  - every confirmed model profile is removed (model-verify again);
  - write credentials stay (bound to their device inside the ciphertext;
    the address they go to is confirmed with the host key);
  - exec_state is unfrozen with an empty failure window.

The schema itself must be intact (the catalog check): a trigger, rule or
policy is fixed first, as the superuser, never sealed. The state file is
first rewritten frozen (it may be missing or invalid), so a crash or a
failure anywhere leaves the executor frozen; the new counter is above every
value seen in the database and the old file. The audit chain continues from
its actual tail, whatever exec.audit_head or the old anchor said; if the
rows from the old base do not reach the tail intact, verification starts
at the tail from now on (rows cannot be repaired). The caller lifts the
freeze afterwards (freeze.Guard.Reset).
*/
func (r *Registry) Reset(ctx context.Context, o ResetOptions) (ResetReport, error) {
	var rep ResetReport
	if o.Audit == nil || o.ChainIntact == nil {
		return rep, errors.New("registry reset: audit and chain check are required")
	}
	if err := r.lock(ctx); err != nil {
		return rep, err
	}
	defer r.unlock()
	ctx, cancel := context.WithTimeout(ctx, r.opTimeout)
	defer cancel()
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return rep, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := pinSession(ctx, tx); err != nil {
		return rep, err
	}
	if err := lockRegistry(ctx, tx); err != nil {
		return rep, err
	}
	if err := checkCatalog(ctx, tx); err != nil {
		return rep, fmt.Errorf("registry reset: the exec schema itself was changed; restore it first: %w", err)
	}
	pre, err := scan(ctx, tx)
	if err != nil {
		return rep, fmt.Errorf("registry reset: %w", err)
	}
	f, err := r.resetFile(pre)
	if err != nil {
		return rep, err
	}
	rep.OldAnchor = f.Committed.AuditHead
	if rep.Tail, err = auditTail(ctx, tx); err != nil {
		return rep, err
	}
	rep.Base = f.Base()
	if rep.Base.LastID > rep.Tail.LastID {
		rep.Base = rep.Tail
	} else if intact, err := o.ChainIntact(ctx, tx, rep.Base, rep.Tail); err != nil {
		return rep, fmt.Errorf("registry reset: verify the audit chain: %w", err)
	} else if !intact {
		rep.Base = rep.Tail
	}
	base := rep.Base
	f.AuditBase = &base
	rep.Seq = max(f.Committed.HWM+1, pre.seq+1)
	for _, rw := range pre.rows {
		rep.Seq = max(rep.Seq, rw.version+1)
	}
	ops, err := resetOps(pre, &rep)
	if err != nil {
		return rep, err
	}
	return rep, r.apply(ctx, tx, f, pre, ops, rep.Seq, rep.Tail, []Appender{o.Audit(rep)})
}

/*
resetFile writes the state file anew, frozen, keeping its committed record
and audit base if it is readable (the pending record is dropped: the
reset's own transaction, under the registry's locks, sees whatever
committed). Saves made by the reset keep the flag; only
freeze.Guard.Reset lifts it.
*/
func (r *Registry) resetFile(pre *Snapshot) (state.File, error) {
	r.fileMu.Lock()
	defer r.fileMu.Unlock()
	f, err := state.Load(r.path, r.keys.State())
	if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, state.ErrInvalid) {
		return f, err
	}
	if err != nil {
		empty := sha256.Sum256(nil)
		f = state.File{Committed: state.Record{HWM: pre.seq, StateHash: empty[:],
			AuditHead: state.AuditHead{Hash: make([]byte, sha256.Size)}}}
	}
	f.Pending, f.PendingXID = nil, 0
	f.Frozen, f.FreezeReason = true, "registry reset in progress"
	return f, state.Save(r.path, r.keys.State(), f)
}

/* auditTail is the last row of the audit chain (id, hash), or the empty head. */
func auditTail(ctx context.Context, tx pgx.Tx) (state.AuditHead, error) {
	h := state.AuditHead{Hash: make([]byte, sha256.Size)}
	err := tx.QueryRow(ctx, `SELECT e.id, e.hash FROM exec.audit_event e ORDER BY e.id DESC LIMIT 1`).Scan(&h.LastID, &h.Hash)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return state.AuditHead{Hash: make([]byte, sha256.Size)}, nil
	case err != nil:
		return h, fmt.Errorf("registry reset: read the audit chain: %w", err)
	case len(h.Hash) != sha256.Size:
		return h, fmt.Errorf("registry reset: audit row %d has a malformed hash", h.LastID)
	}
	return h, nil
}

/* resetOps declares the reset registry: every surviving row re-put (re-sealed at the new counter), the rest deleted. */
func resetOps(pre *Snapshot, rep *ResetReport) ([]op, error) {
	var ops []op
	put := func(table string, vals map[string]any) error {
		o, err := newPut(table, vals)
		if err == nil {
			ops = append(ops, o)
		}
		return err
	}
	if err := errors.Join(put(counterTable, map[string]any{"singleton": true}),
		put(stateTable, map[string]any{"singleton": true, "freeze": false, "freeze_reason": nil, "global_fail_window": []byte("[]")})); err != nil {
		return nil, err
	}
	for _, rw := range pre.rows {
		switch rw.t.name {
		case counterTable, stateTable:
			continue
		case "write_grant", "change_totp", "model_profile":
			switch rw.t.name {
			case "write_grant":
				rep.Grants++
			case "change_totp":
				rep.TOTPs++
			default:
				rep.Profiles++
			}
			ops = append(ops, op{t: rw.t, key: rw.key, del: true, params: keyParams(rw)})
			continue
		}
		vals := map[string]any{}
		for _, c := range rw.t.columns() {
			vals[c.name] = rw.typed[c.name]
		}
		if rw.t.name == "write_device" {
			id, _ := vals["device_id"].(int64)
			addr, _ := vals["address"].(netip.Addr)
			rep.Devices = append(rep.Devices, ResetDevice{ID: id, Address: addr})
			for _, c := range []string{"writes_enabled", "allow_ssh_rsa_sha1", "backup_via_executor"} {
				vals[c] = false
			}
			vals["hostkey_algo"], vals["hostkey_fp"] = nil, nil
		}
		if err := put(rw.t.name, vals); err != nil {
			return nil, fmt.Errorf("registry reset: %w", err)
		}
	}
	return ops, nil
}

/* keyParams turns a scanned row's key back into query parameters. */
func keyParams(rw *row) []any {
	params := make([]any, 0, len(rw.t.pk))
	for _, c := range rw.t.pk {
		v, _ := norm(c, rw.typed[c.name])
		params = append(params, v.param)
	}
	return params
}
