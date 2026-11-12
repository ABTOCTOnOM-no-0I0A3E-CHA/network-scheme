package recording

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/internal/testdb"
)

/* A rotation re-MACs the chunk and manifest rows over the inputs the replay verifies: they match the next key only. */
func TestRekeyMovesRecordingRows(t *testing.T) {
	env := testdb.New(t)
	attacktest.Reset(t, env)
	ctx := context.Background()
	old, next := &[32]byte{1}, &[32]byte{2}
	so, sn := &Store{c: Config{MAC: old}}, &Store{c: Config{MAC: next}}
	sid := [16]byte{0: 7}
	ct, dek := []byte("chunk"), []byte("dek")
	c, k := sha256.Sum256(ct), sha256.Sum256(dek)
	total := sha256.Sum256(append(c[:], k[:]...))
	attacktest.Tamper(t, env, `INSERT INTO exec.session (id, user_id, opened_at, policy_snapshot, mac)
		VALUES ('07000000-0000-0000-0000-000000000000', 1, now(), '{}', decode(repeat('00', 32), 'hex'));
		INSERT INTO exec.session_device (session_id, device_id, pre_sha256, pre_ct, pre_dek_ct, mac)
		VALUES ('07000000-0000-0000-0000-000000000000', 3, decode(repeat('00', 32), 'hex'), '\x01', '\x01', decode(repeat('00', 32), 'hex'))`)
	pool := env.Pool("nms_executor")
	if _, err := pool.Exec(ctx, `INSERT INTO exec.recording_chunk (session_id, device_id, n, ct, dek_ct, mac) VALUES ($1, 3, 0, $2, $3, $4)`,
		sid, ct, dek, so.chunkMAC(sid, 3, 0, c[:], k[:])); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO exec.recording_manifest (session_id, device_id, chunks, sha256, mac) VALUES ($1, 3, 1, $2, $3)`,
		sid, total[:], so.manifestMAC(sid, 3, 1, total[:])); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := Rekey(ctx, tx, old, next); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var cm, mm []byte
	if err := pool.QueryRow(ctx, `SELECT c.mac, m.mac FROM exec.recording_chunk c JOIN exec.recording_manifest m USING (session_id, device_id)`).
		Scan(&cm, &mm); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cm, sn.chunkMAC(sid, 3, 0, c[:], k[:])) || !bytes.Equal(mm, sn.manifestMAC(sid, 3, 1, total[:])) {
		t.Fatal("rows not re-MACed under the next key")
	}
}
