package rotate_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/rotate"
	"github.com/beekamai/network-scheme/internal/keys"
)

/* sealTo seals pt to the public key of priv. */
func sealTo(t *testing.T, priv *[32]byte, pt string) []byte {
	t.Helper()
	pub, err := keys.PublicOf(priv)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := box.SealAnonymous(nil, []byte(pt), &pub, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return ct
}

func opens(priv *[32]byte, ct []byte) bool {
	pub, _ := keys.PublicOf(priv)
	_, ok := box.OpenAnonymous(nil, ct, &pub, priv)
	return ok
}

/*
The write-domain rotation re-seals every write credential to the next key
in one registry change (audited); run again it re-seals nothing; a
credential that opens under neither key (planted) stops it before anything
is written: a ciphertext of a retired key never opens again.
*/
func TestWriteDomainRotation(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	old, next, other := &[32]byte{5: 1}, &[32]byte{5: 2}, &[32]byte{5: 3} /* distinct after X25519 clamping */
	reg := registry.New(f.env.Pool("nms_executor"), f.old, filepath.Join(f.dir, "state"))
	put := func(id int64, ct []byte) {
		t.Helper()
		if err := reg.Write(ctx, func(_ context.Context, _ *registry.Snapshot, tx *registry.Tx) error {
			return tx.Put("write_credential", map[string]any{"device_id": id, "kind": "ssh_write", "ciphertext": ct,
				"created_at": time.Now(), "nonce": make([]byte, 16)})
		}); err != nil {
			t.Fatal(err)
		}
	}
	put(1, sealTo(t, old, "one"))
	put(2, sealTo(t, old, "two"))
	cts := func() map[int64][]byte {
		out := map[int64][]byte{}
		if err := reg.View(ctx, func(s *registry.Snapshot) error {
			for _, r := range s.Rows("write_credential") {
				id, _ := r.Get("device_id").(int64)
				out[id], _ = r.Get("ciphertext").([]byte)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if n, err := rotate.WriteDomain(ctx, reg, old, next, "root"); err != nil || n != 2 {
		t.Fatalf("rotation: %d %v", n, err)
	}
	for id, ct := range cts() {
		if !opens(next, ct) || opens(old, ct) {
			t.Fatalf("credential %d not re-sealed to the next key only", id)
		}
	}
	if n, err := rotate.WriteDomain(ctx, reg, old, next, "root"); err != nil || n != 0 {
		t.Fatalf("resumed rotation: %d %v", n, err)
	}
	put(3, sealTo(t, other, "planted"))
	before := cts()
	if _, err := rotate.WriteDomain(ctx, reg, next, old, "root"); !errors.Is(err, registry.ErrTampered) {
		t.Fatalf("a credential under neither key: %v", err)
	}
	if after := cts(); !bytes.Equal(after[1], before[1]) || !bytes.Equal(after[2], before[2]) {
		t.Fatal("the refused rotation changed credentials")
	}
	var n int
	if err := f.env.Pool("postgres").QueryRow(ctx, `SELECT count(*) FROM exec.audit_event WHERE action = 'admin.key-rotate' AND object = 'write-domain'`).
		Scan(&n); err != nil || n != 2 {
		t.Fatalf("audit rows %d %v", n, err)
	}
}
