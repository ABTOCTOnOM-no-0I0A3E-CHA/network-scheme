package recording

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
)

/*
ResealBackup re-seals the DEK of every recording chunk for a backup-domain
rotation, inside its transaction, as session.ResealBackup does: each chunk's
MAC is checked under mac, its dek_ct re-sealed (reseal returns nil when it
already is) and the MAC rewritten over it. A manifest's hash covers every
chunk's sha256(dek_ct): it must equal the hash of the chunks as they were
(count and order too, else tampering), and is rewritten with its MAC over
the chunks as they are now. It returns the chunks and manifests rewritten.
*/
func ResealBackup(ctx context.Context, tx pgx.Tx, mac *[32]byte, reseal func([]byte) ([]byte, error)) (int, int, error) {
	st := &Store{c: Config{MAC: mac}}
	type key struct {
		sid [16]byte
		dev int64
	}
	type totals struct {
		n         int
		old, next hash.Hash
	}
	recs := map[key]*totals{}
	rows, err := tx.Query(ctx, `SELECT session_id, device_id, n, sha256(ct), dek_ct, mac FROM exec.recording_chunk ORDER BY session_id, device_id, n`)
	if err != nil {
		return 0, 0, err
	}
	var chunks [][]any
	for rows.Next() {
		var (
			k              key
			n              int
			c, dek, stored []byte
		)
		if err := rows.Scan(&k.sid, &k.dev, &n, &c, &dek, &stored); err != nil {
			rows.Close()
			return 0, 0, err
		}
		ks := sha256.Sum256(dek)
		if !hmac.Equal(stored, st.chunkMAC(k.sid, k.dev, n, c, ks[:])) {
			rows.Close()
			return 0, 0, fmt.Errorf("%w: a recording chunk fails its MAC", registry.ErrTampered)
		}
		nd, err := reseal(dek)
		if err != nil {
			rows.Close()
			return 0, 0, fmt.Errorf("a recording chunk of device %d: %w", k.dev, err)
		}
		nks := ks
		if nd != nil {
			nks = sha256.Sum256(nd)
			chunks = append(chunks, []any{nd, st.chunkMAC(k.sid, k.dev, n, c, nks[:]), k.sid, k.dev, n, stored})
		}
		t := recs[k]
		if t == nil {
			t = &totals{old: sha256.New(), next: sha256.New()}
			recs[k] = t
		}
		if n != t.n {
			rows.Close()
			return 0, 0, fmt.Errorf("%w: recording chunk %d where %d belongs", registry.ErrTampered, n, t.n)
		}
		t.old.Write(c)
		t.old.Write(ks[:])
		t.next.Write(c)
		t.next.Write(nks[:])
		t.n++
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	if err := registry.UpdateEach(ctx, tx, "exec.recording_chunk",
		`UPDATE exec.recording_chunk SET dek_ct = $1, mac = $2 WHERE session_id = $3 AND device_id = $4 AND n = $5 AND mac = $6`, chunks); err != nil {
		return 0, 0, err
	}

	rows, err = tx.Query(ctx, `SELECT session_id, device_id, chunks, sha256, mac FROM exec.recording_manifest`)
	if err != nil {
		return 0, 0, err
	}
	var manifests [][]any
	for rows.Next() {
		var (
			k           key
			n           int
			sum, stored []byte
		)
		if err := rows.Scan(&k.sid, &k.dev, &n, &sum, &stored); err != nil {
			rows.Close()
			return 0, 0, err
		}
		t := recs[k]
		if t == nil {
			t = &totals{old: sha256.New(), next: sha256.New()}
		}
		if !hmac.Equal(stored, st.manifestMAC(k.sid, k.dev, n, sum)) || n != t.n || !hmac.Equal(sum, t.old.Sum(nil)) {
			rows.Close()
			return 0, 0, fmt.Errorf("%w: a recording manifest does not match its chunks", registry.ErrTampered)
		}
		if next := t.next.Sum(nil); !hmac.Equal(next, sum) {
			manifests = append(manifests, []any{next, st.manifestMAC(k.sid, k.dev, n, next), k.sid, k.dev, stored})
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	return len(chunks), len(manifests), registry.UpdateEach(ctx, tx, "exec.recording_manifest",
		`UPDATE exec.recording_manifest SET sha256 = $1, mac = $2 WHERE session_id = $3 AND device_id = $4 AND mac = $5`, manifests)
}
