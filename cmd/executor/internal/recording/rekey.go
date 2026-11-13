package recording

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
)

/*
Rekey re-MACs every recording row from the mac subkey old to next inside a
rotation's transaction (registry.Rekey), over the inputs the replay
verifies (a chunk's envelope parts by the SHA-256 the database computes).
*/
func Rekey(ctx context.Context, tx pgx.Tx, old, next *[32]byte) error {
	so, sn := &Store{c: Config{MAC: old}}, &Store{c: Config{MAC: next}}
	_, err := registry.RekeyTable(ctx, tx, "exec.recording_chunk",
		`SELECT session_id, device_id, n, sha256(ct), sha256(dek_ct), mac FROM exec.recording_chunk`,
		`UPDATE exec.recording_chunk SET mac = $1 WHERE session_id = $2 AND device_id = $3 AND n = $4 AND mac = $5`,
		func(rows pgx.Rows) ([]any, []byte, []byte, []byte, error) {
			var (
				sid       [16]byte
				dev       int64
				n         int
				c, k, mac []byte
			)
			if err := rows.Scan(&sid, &dev, &n, &c, &k, &mac); err != nil {
				return nil, nil, nil, nil, err
			}
			return []any{sid, dev, n}, mac, so.chunkMAC(sid, dev, n, c, k), sn.chunkMAC(sid, dev, n, c, k), nil
		})
	if err != nil {
		return err
	}
	_, err = registry.RekeyTable(ctx, tx, "exec.recording_manifest",
		`SELECT session_id, device_id, chunks, sha256, mac FROM exec.recording_manifest`,
		`UPDATE exec.recording_manifest SET mac = $1 WHERE session_id = $2 AND device_id = $3 AND mac = $4`,
		func(rows pgx.Rows) ([]any, []byte, []byte, []byte, error) {
			var (
				sid      [16]byte
				dev      int64
				chunks   int
				sum, mac []byte
			)
			if err := rows.Scan(&sid, &dev, &chunks, &sum, &mac); err != nil {
				return nil, nil, nil, nil, err
			}
			return []any{sid, dev}, mac, so.manifestMAC(sid, dev, chunks, sum), sn.manifestMAC(sid, dev, chunks, sum), nil
		})
	return err
}
