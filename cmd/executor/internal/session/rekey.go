package session

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
)

/*
Rekey re-MACs every session row from the mac subkey old to next inside a
rotation's transaction (registry.Rekey): over the inputs Recover verifies,
the envelopes of session_device by the SHA-256 the database computes.
*/
func Rekey(ctx context.Context, tx pgx.Tx, old, next *[32]byte) error {
	mo, mn := &Manager{cfg: Config{MAC: old}}, &Manager{cfg: Config{MAC: next}}
	_, err := registry.RekeyTable(ctx, tx, "exec.session", `SELECT id, user_id, opened_at, policy_snapshot, mac FROM exec.session`,
		`UPDATE exec.session SET mac = $1 WHERE id = $2 AND mac = $3`,
		func(rows pgx.Rows) ([]any, []byte, []byte, []byte, error) {
			var r recovered
			if err := rows.Scan(&r.id, &r.user, &r.opened, &r.snap, &r.mac); err != nil {
				return nil, nil, nil, nil, err
			}
			var ps policySnapshot
			if err := json.Unmarshal(r.snap, &ps); err != nil {
				return nil, nil, nil, nil, errors.New("malformed policy snapshot")
			}
			snap, err := json.Marshal(ps)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			return []any{r.id}, r.mac, mo.sessionMAC(r.id, r.user, r.opened, snap), mn.sessionMAC(r.id, r.user, r.opened, snap), nil
		})
	if err != nil {
		return err
	}
	_, err = registry.RekeyTable(ctx, tx, "exec.session_device",
		`SELECT session_id, device_id, pre_sha256, sha256(pre_ct), sha256(pre_dek_ct), mac FROM exec.session_device`,
		`UPDATE exec.session_device SET mac = $1 WHERE session_id = $2 AND device_id = $3 AND mac = $4`,
		func(rows pgx.Rows) ([]any, []byte, []byte, []byte, error) {
			var (
				sid             [16]byte
				dev             int64
				pre, ct, k, mac []byte
			)
			if err := rows.Scan(&sid, &dev, &pre, &ct, &k, &mac); err != nil {
				return nil, nil, nil, nil, err
			}
			return []any{sid, dev}, mac, mo.macOf("session_device", sid[:], i64(dev), pre, ct, k),
				mn.macOf("session_device", sid[:], i64(dev), pre, ct, k), nil
		})
	if err != nil {
		return err
	}
	_, err = registry.RekeyTable(ctx, tx, "exec.session_event", `SELECT id, session_id, at, kind, payload, mac FROM exec.session_event`,
		`UPDATE exec.session_event SET mac = $1 WHERE id = $2 AND mac = $3`,
		func(rows pgx.Rows) ([]any, []byte, []byte, []byte, error) {
			var (
				id           int64
				sid          [16]byte
				at           time.Time
				kind         string
				payload, mac []byte
			)
			if err := rows.Scan(&id, &sid, &at, &kind, &payload, &mac); err != nil {
				return nil, nil, nil, nil, err
			}
			var p map[string]any
			if err := json.Unmarshal(payload, &p); err != nil {
				return nil, nil, nil, nil, errors.New("malformed event payload")
			}
			enc, err := json.Marshal(p)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			return []any{id}, mac, mo.EventMAC(id, sid, at, kind, enc), mn.EventMAC(id, sid, at, kind, enc), nil
		})
	return err
}
