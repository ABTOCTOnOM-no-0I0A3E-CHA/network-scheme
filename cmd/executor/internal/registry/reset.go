package registry

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"os"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/cmd/executor/internal/state"
)

/*
ResetDevice is a device kept by a reset with every routing field it keeps:
none of them is confirmed (the registry was tampered with), so the host
checks them all before the device is used again (4b.3).
*/
type ResetDevice struct {
	ID       int64      `json:"id"`
	Address  netip.Addr `json:"address"`
	Port     int64      `json:"port"`
	Protocol string     `json:"protocol"`
	Group    string     `json:"write_group"`
	Driver   string     `json:"write_driver"`
}

/* ResetReport says what a registry reset changed. */
type ResetReport struct {
	Seq     int64         /* the counter value every row now carries */
	Grants  int           /* grants revoked */
	TOTPs   int           /* change TOTP enrollments removed */
	Devices []ResetDevice /* devices kept with writes disabled, no host key and both flags off */
	/* Dropped lists the device and credential rows removed because their MAC did not verify ("write_device 7"): register them again. */
	Dropped []string
	/* Profiles is the number of confirmed model profiles removed. */
	Profiles int
	/* Known: the state file was readable. OldAnchor is the audit head it vouched for (the pending one if that change committed). */
	Known     bool
	OldAnchor state.AuditHead
	Tail      state.AuditHead /* the last row of the audit chain, which the reset continues */
	Chain     state.Chain     /* the audit chain's new sealed segments and base */
}

/* ResetOptions are the parts of a reset that belong to the audit package. */
type ResetOptions struct {
	/* Audit returns the appender of the reset's own audit row (required). */
	Audit func(ResetReport) Appender
	/*
		Plan decides the audit chain's new sealed segments and base from what the
		state file said (old; known false: unreadable) and the chain's tail
		(audit.PlanReset; required).
	*/
	Plan func(ctx context.Context, tx pgx.Tx, old state.Chain, known bool, tail state.AuditHead) (state.Chain, error)
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
  - a device or write credential row whose MAC does not verify (planted or
    changed) is removed and reported: register it again;
  - every other device keeps its id, address, port, protocol, line and
    group (all listed in the report: an old valid row may have been put
    back), with writes_enabled, allow_ssh_rsa_sha1 and backup_via_executor
    false and no pinned host key (a planted pin would otherwise be sealed);
  - every confirmed model profile is removed (model-verify again);
  - every other write credential stays (bound to its device inside the
    ciphertext);
  - exec_state is unfrozen with an empty failure window.

The schema itself must be intact (the catalog check): a trigger, rule or
policy is fixed first, as the superuser, never sealed. The state file is
first rewritten frozen (it may be missing or invalid), so a crash or a
failure anywhere leaves the executor frozen; the new counter is above every
value seen in the database and the old file. The audit chain continues from
its actual tail; what is verified of it from now on is decided by o.Plan
against the anchor the old state file vouched for. The caller lifts the
freeze afterwards (freeze.Guard.Reset).
*/
func (r *Registry) Reset(ctx context.Context, o ResetOptions) (ResetReport, error) {
	var rep ResetReport
	if o.Audit == nil || o.Plan == nil {
		return rep, errors.New("registry reset: audit and chain plan are required")
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
	pre, err := scan(ctx, tx, nil)
	if err != nil {
		return rep, fmt.Errorf("registry reset: %w", err)
	}
	f, old, known, err := r.resetFile(ctx, pre)
	if err != nil {
		return rep, err
	}
	rep.Known, rep.OldAnchor = known, old.Anchor
	if rep.Tail, err = auditTail(ctx, tx); err != nil {
		return rep, err
	}
	if rep.Chain, err = o.Plan(ctx, tx, old, known, rep.Tail); err != nil {
		return rep, fmt.Errorf("registry reset: verify the audit chain: %w", err)
	}
	base := rep.Chain.Base
	f.AuditBase, f.AuditSealed = &base, rep.Chain.Sealed
	rep.Seq = max(f.Committed.HWM+1, pre.seq+1)
	for _, rw := range pre.rows {
		rep.Seq = max(rep.Seq, rw.version+1)
	}
	ops, err := resetOps(pre, r.keys.MAC(), &rep)
	if err != nil {
		return rep, err
	}
	return rep, r.apply(ctx, tx, f, pre, ops, rep.Seq, rep.Tail, []Appender{o.Audit(rep)})
}

/*
resetFile writes the state file anew, frozen, keeping its committed record,
audit base and sealed segments if it is readable, and returns the audit
chain it vouched for: its anchor is the pending record's if that change
committed (pg_xact_status), else the committed one (the pending record is
dropped: the reset's own transaction, under the registry's locks, sees
whatever committed). Saves made by the reset keep the flag; only
freeze.Guard.Reset lifts it.
*/
func (r *Registry) resetFile(ctx context.Context, pre *Snapshot) (state.File, state.Chain, bool, error) {
	r.fileMu.Lock()
	f, err := state.Load(r.path, r.keys.State())
	r.fileMu.Unlock() /* never held across a database call (xactStatus below) */
	if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, state.ErrInvalid) {
		return f, state.Chain{}, false, err
	}
	known := err == nil
	if !known {
		empty := sha256.Sum256(nil)
		f = state.File{Committed: state.Record{HWM: pre.seq, StateHash: empty[:],
			AuditHead: state.AuditHead{Hash: make([]byte, sha256.Size)}}}
	}
	old := f.Chain()
	if f.Pending != nil {
		if st, err := r.xactStatus(ctx, f.PendingXID); err == nil && st == "committed" {
			old.Anchor = f.Pending.AuditHead
		}
	}
	f.Pending, f.PendingXID = nil, 0
	f.Frozen, f.FreezeReason = true, "registry reset in progress"
	r.fileMu.Lock()
	defer r.fileMu.Unlock()
	return f, old, known, state.Save(r.path, r.keys.State(), f)
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
func resetOps(pre *Snapshot, macKey *[32]byte, rep *ResetReport) ([]op, error) {
	var ops []op
	put := func(table string, vals map[string]any) error {
		o, err := newPut(table, vals)
		if err == nil {
			ops = append(ops, o)
		}
		return err
	}
	del := func(rw *row) { ops = append(ops, op{t: rw.t, key: rw.key, del: true, params: keyParams(rw)}) }
	if err := errors.Join(put(counterTable, map[string]any{"singleton": true}),
		put(stateTable, map[string]any{"singleton": true, "freeze": false, "freeze_reason": nil, "global_fail_window": []byte("[]")})); err != nil {
		return nil, err
	}
	for _, rw := range pre.rows {
		switch rw.t.name {
		case counterTable, stateTable:
			continue
		case "write_grant":
			rep.Grants++
			del(rw)
			continue
		case "change_totp":
			rep.TOTPs++
			del(rw)
			continue
		case "model_profile":
			rep.Profiles++
			del(rw)
			continue
		}
		vals := map[string]any{}
		for _, c := range rw.t.columns() {
			vals[c.name] = rw.typed[c.name]
		}
		id, _ := vals["device_id"].(int64)
		if !hmac.Equal(rw.mac, macOf(macKey, rw.canonical())) {
			rep.Dropped = append(rep.Dropped, fmt.Sprintf("%s %d", rw.t.name, id))
			del(rw)
			continue
		}
		if rw.t.name == "write_device" {
			d := ResetDevice{ID: id}
			d.Address, _ = vals["address"].(netip.Addr)
			d.Port, _ = vals["port"].(int64)
			d.Protocol, _ = vals["protocol"].(string)
			d.Group, _ = vals["write_group"].(string)
			d.Driver, _ = vals["write_driver"].(string)
			rep.Devices = append(rep.Devices, d)
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
