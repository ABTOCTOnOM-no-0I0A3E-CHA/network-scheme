package rotate

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/nacl/box"

	"github.com/beekamai/network-scheme/cmd/executor/internal/audit"
	"github.com/beekamai/network-scheme/cmd/executor/internal/recording"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/session"
	"github.com/beekamai/network-scheme/cmd/executor/internal/state"
	"github.com/beekamai/network-scheme/internal/keys"
)

/* BackupReport counts what a backup-domain rotation re-sealed. */
type BackupReport struct {
	Backups    int `json:"backups"`    /* backups.config_version rows */
	Unreadable int `json:"unreadable"` /* config versions opening under neither key: left as they are */
	Sessions   int `json:"sessions"`   /* pre-session backups (exec.session_device) */
	Chunks     int `json:"chunks"`     /* recording chunks */
	Manifests  int `json:"manifests"`  /* recording manifests */
}

/* errNeither: a DEK opens under neither the retired nor the next backup key. */
var errNeither = errors.New("sealed to neither backup key")

/*
BackupDomain is the backup-domain key rotation (nmsctl keys rotate backup),
run in a one-shot executor container while the daemon is stopped and after
the poller took the next public key. Design (security.md 9, migration 00033):
every envelope's random DEK is re-sealed from the retired key old to next;
the bodies stay as they are. Rejected alternative: a key version per row
with old keys kept until "retired" would need no UPDATE right at all, but
it keeps the retired private key alive as long as any history (the rows
are never deleted), so a rotation would not limit what a leaked key opens.
The price of the chosen design is a narrow UPDATE right: only nms_executor,
only the sealed-DEK columns and what covers them (the exec rows' MAC, a
recording manifest's hash); every rewrite of an exec row is checked under
the sealing key's MAC first and matches its old value. Everything runs in
one transaction with the executor's audit row (registry.AppendLong), so a
crash leaves all rows as they were; run again, rows already sealed to next
are skipped. A config version the poller planted that opens under neither
key is counted and left (it never restores: the executor rechecks the hash
on opening); an exec row that does so fails the rotation (tampering).
*/
func BackupDomain(ctx context.Context, reg *registry.Registry, mac, old, next *[32]byte, operator string) (BackupReport, error) {
	nextPub, err := keys.PublicOf(next)
	if err != nil {
		return BackupReport{}, err
	}
	reseal := func(ct []byte) ([]byte, error) {
		if dek, ok := box.OpenAnonymous(nil, ct, &nextPub, next); ok {
			clear(dek)
			return nil, nil
		}
		nct, err := keys.Reseal(ct, old, &nextPub)
		if errors.Is(err, keys.ErrNotSealedToKey) {
			return nil, errNeither
		}
		return nct, err
	}
	var rep BackupReport
	err = reg.AppendLong(ctx, func(ctx context.Context, tx pgx.Tx, head state.AuditHead) (state.AuditHead, error) {
		var err error
		rep = BackupReport{}
		if rep.Backups, rep.Unreadable, err = resealConfigs(ctx, tx, reseal); err != nil {
			return head, err
		}
		strict := func(ct []byte) ([]byte, error) {
			nct, err := reseal(ct)
			if errors.Is(err, errNeither) {
				err = fmt.Errorf("%w: %v", registry.ErrTampered, err)
			}
			return nct, err
		}
		if rep.Sessions, err = session.ResealBackup(ctx, tx, mac, strict); err != nil {
			return head, err
		}
		if rep.Chunks, rep.Manifests, err = recording.ResealBackup(ctx, tx, mac, strict); err != nil {
			return head, err
		}
		return audit.Append(audit.Event{UA: "nmsctl", Action: "admin.key-rotate", Object: "backup-domain", Result: audit.OK,
			Details: map[string]any{"operator": operator, "fingerprint": keys.Fingerprint(nextPub), "backups": rep.Backups,
				"unreadable": rep.Unreadable, "sessions": rep.Sessions, "chunks": rep.Chunks, "manifests": rep.Manifests}})(ctx, tx, head)
	})
	return rep, err
}

/* resealConfigs re-seals the DEK of every config version; it returns the rows rewritten and those opening under neither key. */
func resealConfigs(ctx context.Context, tx pgx.Tx, reseal func([]byte) ([]byte, error)) (int, int, error) {
	rows, err := tx.Query(ctx, `SELECT id, full_dek_ct FROM backups.config_version`)
	if err != nil {
		return 0, 0, err
	}
	var args [][]any
	bad := 0
	for rows.Next() {
		var (
			id  int64
			dek []byte
		)
		if err := rows.Scan(&id, &dek); err != nil {
			rows.Close()
			return 0, 0, err
		}
		nd, err := reseal(dek)
		switch {
		case errors.Is(err, errNeither):
			bad++
		case err != nil:
			rows.Close()
			return 0, 0, err
		case nd != nil:
			args = append(args, []any{nd, id, dek})
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	return len(args), bad, registry.UpdateEach(ctx, tx, "backups.config_version",
		`UPDATE backups.config_version SET full_dek_ct = $1 WHERE id = $2 AND full_dek_ct = $3`, args)
}
