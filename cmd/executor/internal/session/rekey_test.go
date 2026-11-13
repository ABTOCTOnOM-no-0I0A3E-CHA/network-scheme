package session

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/internal/testdb"
)

/* rekey runs Rekey in its own transaction. */
func rekey(t *testing.T, env *testdb.Env, old, next *[32]byte) error {
	t.Helper()
	ctx := context.Background()
	tx, err := env.Pool("nms_executor").Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := Rekey(ctx, tx, old, next); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

/*
A rotation re-MACs the session, session_device and session_event rows so
that Recover verifies them under the next key and no longer under the
retired one; a row that fails its MAC stops the rotation (never laundered).
*/
func TestRekeyMovesSessionRows(t *testing.T) {
	env := testdb.New(t)
	attacktest.Reset(t, env)
	ctx := context.Background()
	old, next := &[32]byte{1}, &[32]byte{2}
	pool := env.Pool("nms_executor")
	mo, mn := &Manager{cfg: Config{MAC: old, Pool: pool}}, &Manager{cfg: Config{MAC: next, Pool: pool}}
	id := [16]byte{0: 1}
	opened := time.Now().UTC().Truncate(time.Microsecond)
	snap, _ := json.Marshal(policySnapshot{Sum: "ab"})
	pre, ct, dek := sha256.Sum256([]byte("cfg")), []byte("ct"), []byte("dek")
	payload := []byte(`{"reason":"x"}`)
	if _, err := pool.Exec(ctx, `INSERT INTO exec.session (id, user_id, opened_at, policy_snapshot, mac) VALUES ($1, 5, $2, $3, $4)`,
		id, opened, snap, mo.sessionMAC(id, 5, opened, snap)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO exec.session_device (session_id, device_id, pre_sha256, pre_ct, pre_dek_ct, mac)
		VALUES ($1, 9, $2, $3, $4, $5)`, id, pre[:], ct, dek, mo.DeviceMAC(id, 9, pre, ct, dek)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO exec.session_event (id, session_id, at, kind, payload, mac) VALUES (1, $1, $2, 'closed', $3, $4)`,
		id, opened, payload, mo.EventMAC(1, id, opened, "closed", payload)); err != nil {
		t.Fatal(err)
	}
	if err := rekey(t, env, old, next); err != nil {
		t.Fatal(err)
	}
	page, _, bad, err := mn.recoverPage(ctx, [16]byte{})
	if err != nil || bad != 0 || len(page) != 1 || len(page[0].devs) != 1 || !page[0].ended {
		t.Fatalf("under the next key: %+v bad %d %v", page, bad, err)
	}
	if _, _, bad, err := mo.recoverPage(ctx, [16]byte{}); err != nil || bad != 3 {
		t.Fatalf("under the retired key: bad %d %v", bad, err)
	}
	/* A planted event (its MAC is not the key's): the next rotation refuses to vouch for it. */
	if _, err := env.Pool("postgres").Exec(ctx, `INSERT INTO exec.session_event (id, session_id, at, kind, payload, mac)
		VALUES (2, $1, now(), 'closed', '{}', decode(repeat('00', 32), 'hex'))`, id); err != nil {
		t.Fatal(err)
	}
	if err := rekey(t, env, next, old); !errors.Is(err, registry.ErrTampered) {
		t.Fatalf("a planted row was re-MACed: %v", err)
	}
	if _, _, bad, _ := mn.recoverPage(ctx, [16]byte{}); bad != 1 {
		t.Fatalf("the failed rotation changed rows: bad %d", bad)
	}
}
