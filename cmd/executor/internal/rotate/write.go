package rotate

import (
	"context"
	"errors"
	"fmt"

	"github.com/beekamai/network-scheme/cmd/executor/internal/audit"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/internal/keys"
)

/*
WriteDomain re-seals every write credential of the registry from the
write-domain private key old to the public key of next (nmsctl keys rotate
write, the daemon stopped), in one registry change with its audit row. A
credential already sealed to next (a resumed rotation) is left; one that
opens under neither is tampering (registry.ErrTampered), and nothing is
written. It returns the number of credentials re-sealed.
*/
func WriteDomain(ctx context.Context, reg *registry.Registry, old, next *[32]byte, operator string) (int, error) {
	pub, err := keys.PublicOf(next)
	if err != nil {
		return 0, err
	}
	n := 0
	err = reg.Write(ctx, func(_ context.Context, s *registry.Snapshot, tx *registry.Tx) error {
		n = 0
		for _, row := range s.Rows("write_credential") {
			id, _ := row.Get("device_id").(int64)
			ct, _ := row.Get("ciphertext").([]byte)
			nct, err := keys.Reseal(ct, old, &pub)
			if errors.Is(err, keys.ErrNotSealedToKey) {
				if _, again := keys.Reseal(ct, next, &pub); again == nil {
					continue
				}
				return fmt.Errorf("%w: the write credential of device %d opens under neither write key", registry.ErrTampered, id)
			}
			if err != nil {
				return err
			}
			if err := tx.Put("write_credential", map[string]any{"device_id": id, "kind": row.Get("kind"), "ciphertext": nct,
				"created_at": row.Get("created_at"), "nonce": row.Get("nonce")}); err != nil {
				return err
			}
			n++
		}
		tx.Audit(audit.Append(audit.Event{UA: "nmsctl", Action: "admin.key-rotate", Object: "write-domain", Result: audit.OK,
			Details: map[string]any{"operator": operator, "resealed": n, "fingerprint": keys.Fingerprint(pub)}}))
		return nil
	})
	return n, err
}
