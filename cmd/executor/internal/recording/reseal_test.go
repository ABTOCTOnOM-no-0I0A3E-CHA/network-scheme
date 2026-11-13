package recording_test

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"

	"golang.org/x/crypto/nacl/box"

	"github.com/beekamai/network-scheme/cmd/executor/internal/recording"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/terminal"
	"github.com/beekamai/network-scheme/internal/keys"
)

/*
A backup-domain rotation re-seals every chunk's DEK and rewrites the chunk
MACs and the manifest hash: the recording replays under the next key, the
same text, and no longer under the retired one; run again it rewrites
nothing; a planted chunk stops it.
*/
func TestResealBackupKeepsRecordingsReplayable(t *testing.T) {
	defer recording.SetMaxChunk(64)()
	f := newFx(t)
	ctx := context.Background()
	id := f.session(t, 7)
	f.record(t, id, 7)
	before, err := f.st.Replay(ctx, id, 7)
	if err != nil {
		t.Fatal(err)
	}
	npub, npriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reseal := func(ct []byte) ([]byte, error) {
		if _, ok := box.OpenAnonymous(nil, ct, npub, npriv); ok {
			return nil, nil
		}
		return keys.Reseal(ct, f.priv, npub)
	}
	run := func() (int, int, error) {
		tx, err := f.env.Pool("nms_executor").Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		c, m, err := recording.ResealBackup(ctx, tx, f.mac, reseal)
		if err != nil {
			return c, m, err
		}
		return c, m, tx.Commit(ctx)
	}
	n := len(f.chunks(t, id, 7))
	if c, m, err := run(); err != nil || c != n || m != 1 || n < 2 {
		t.Fatalf("reseal: %d chunks of %d, %d manifests, %v", c, n, m, err)
	}
	next, err := recording.New(recording.Config{Pool: f.env.Pool("nms_executor"), MAC: f.mac, Pub: npub, Priv: npriv, Clean: terminal.Clean,
		Policy: f.pol.Current, Live: func([16]byte) bool { return false },
		Alert: func(context.Context, string, string, int64, string) error { return nil }, Audit: f.az.Record})
	if err != nil {
		t.Fatal(err)
	}
	after, err := next.Replay(ctx, id, 7)
	if err != nil || len(after.Events) != len(before.Events) || after.Events[1].Data != before.Events[1].Data {
		t.Fatalf("replay under the next key: %v", err)
	}
	if _, err := f.st.Replay(ctx, id, 7); !errors.Is(err, recording.ErrTampered) {
		t.Fatalf("replay under the retired key: %v", err)
	}
	if c, m, err := run(); err != nil || c != 0 || m != 0 {
		t.Fatalf("second run: %d %d %v", c, m, err)
	}
	other := f.session(t, 8)
	if _, err := f.env.Pool("nms_executor").Exec(ctx, `INSERT INTO exec.recording_chunk (session_id, device_id, n, ct, dek_ct, mac)
		VALUES ($1, 8, 0, '\x01', '\x01', $2)`, other, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(); !errors.Is(err, registry.ErrTampered) {
		t.Fatalf("a planted chunk: %v", err)
	}
}
