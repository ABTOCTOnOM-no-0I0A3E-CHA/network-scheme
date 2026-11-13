package changeset

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
)

/*
Rekey re-MACs every changeset row from the mac subkey old to next inside a
rotation's transaction (registry.Rekey), over the inputs Load verifies.
*/
func Rekey(ctx context.Context, tx pgx.Tx, old, next *[32]byte) error {
	so, sn := &Store{MAC: old}, &Store{MAC: next}
	_, err := registry.RekeyTable(ctx, tx, "exec.changeset", `SELECT id, author, author_username, kind, created_at, mac FROM exec.changeset`,
		`UPDATE exec.changeset SET mac = $1 WHERE id = $2 AND mac = $3`,
		func(rows pgx.Rows) ([]any, []byte, []byte, []byte, error) {
			var (
				id         [16]byte
				author     int64
				name, kind string
				created    time.Time
				mac        []byte
			)
			if err := rows.Scan(&id, &author, &name, &kind, &created, &mac); err != nil {
				return nil, nil, nil, nil, err
			}
			return []any{id}, mac, so.changesetMAC(id, author, name, kind, created), sn.changesetMAC(id, author, name, kind, created), nil
		})
	if err != nil {
		return err
	}
	_, err = registry.RekeyTable(ctx, tx, "exec.changeset_revision", `SELECT changeset_id, rev, created_at, content_sha256, mac FROM exec.changeset_revision`,
		`UPDATE exec.changeset_revision SET mac = $1 WHERE changeset_id = $2 AND rev = $3 AND mac = $4`,
		func(rows pgx.Rows) ([]any, []byte, []byte, []byte, error) {
			var (
				id       [16]byte
				rev      int
				at       time.Time
				sum, mac []byte
			)
			if err := rows.Scan(&id, &rev, &at, &sum, &mac); err != nil {
				return nil, nil, nil, nil, err
			}
			return []any{id, rev}, mac, so.revisionMAC(id, rev, at, sum), sn.revisionMAC(id, rev, at, sum), nil
		})
	if err != nil {
		return err
	}
	_, err = registry.RekeyTable(ctx, tx, "exec.changeset_event",
		`SELECT id, changeset_id, rev, at, kind, coalesce(device_id, 0), session_id, payload, mac FROM exec.changeset_event`,
		`UPDATE exec.changeset_event SET mac = $1 WHERE id = $2 AND mac = $3`,
		func(rows pgx.Rows) ([]any, []byte, []byte, []byte, error) {
			var (
				e            Event
				id           [16]byte
				payload, mac []byte
			)
			if err := rows.Scan(&e.ID, &id, &e.Rev, &e.At, &e.Kind, &e.Device, &e.Session, &payload, &mac); err != nil {
				return nil, nil, nil, nil, err
			}
			var x any
			dec := json.NewDecoder(bytes.NewReader(payload))
			dec.UseNumber()
			if err := dec.Decode(&x); err != nil {
				return nil, nil, nil, nil, errors.New("malformed event payload")
			}
			var err error
			if e.Payload, err = json.Marshal(x); err != nil {
				return nil, nil, nil, nil, err
			}
			return []any{e.ID}, mac, so.eventMAC(e, id), sn.eventMAC(e, id), nil
		})
	return err
}
