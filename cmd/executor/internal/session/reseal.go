package session

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
)

/*
ResealBackup re-seals the DEK of every pre-session backup (session_device.pre_dek_ct)
for a backup-domain rotation, inside its transaction: each row's MAC is
checked under mac first, reseal returns the DEK sealed to the next key (nil:
it already is), and the row's MAC is rewritten under the same key over the
new pre_dek_ct; each update matches the old MAC. It returns the number of
rows rewritten.
*/
func ResealBackup(ctx context.Context, tx pgx.Tx, mac *[32]byte, reseal func([]byte) ([]byte, error)) (int, error) {
	m := &Manager{cfg: Config{MAC: mac}}
	rows, err := tx.Query(ctx, `SELECT session_id, device_id, pre_sha256, sha256(pre_ct), pre_dek_ct, mac FROM exec.session_device`)
	if err != nil {
		return 0, err
	}
	var args [][]any
	for rows.Next() {
		var (
			sid                  [16]byte
			dev                  int64
			pre, ct, dek, stored []byte
		)
		if err := rows.Scan(&sid, &dev, &pre, &ct, &dek, &stored); err != nil {
			rows.Close()
			return 0, err
		}
		k := sha256.Sum256(dek)
		if !hmac.Equal(stored, m.macOf("session_device", sid[:], i64(dev), pre, ct, k[:])) {
			rows.Close()
			return 0, fmt.Errorf("%w: a session_device row fails its MAC", registry.ErrTampered)
		}
		nd, err := reseal(dek)
		if err != nil {
			rows.Close()
			return 0, fmt.Errorf("the pre-session backup of device %d: %w", dev, err)
		}
		if nd == nil {
			continue
		}
		nk := sha256.Sum256(nd)
		args = append(args, []any{nd, m.macOf("session_device", sid[:], i64(dev), pre, ct, nk[:]), sid, dev, stored})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	return len(args), registry.UpdateEach(ctx, tx, "exec.session_device",
		`UPDATE exec.session_device SET pre_dek_ct = $1, mac = $2 WHERE session_id = $3 AND device_id = $4 AND mac = $5`, args)
}
