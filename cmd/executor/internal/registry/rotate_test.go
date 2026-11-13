package registry

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/state"
	"github.com/beekamai/network-scheme/internal/testdb"
)

func nextKeys(t *testing.T) *seal.Keys {
	t.Helper()
	k, err := seal.Derive(&[32]byte{43})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

/* noAudit: the audit row is the rotate package's (tested there). */
var noAudit Appender

/* enrollTOTP stores user's change TOTP secret sealed under the registry's key at its version. */
func enrollTOTP(t *testing.T, r *Registry, user int64, secret string) {
	t.Helper()
	ct, err := r.keys.SealTOTP(user, r.keys.Version(), []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Write(context.Background(), func(_ context.Context, _ *Snapshot, tx *Tx) error {
		return tx.Put("change_totp", map[string]any{"user_id": user, "username_snapshot": "u", "ciphertext": ct,
			"key_version": r.keys.Version(), "last_step": 0, "failures": 0, "lock_until": nil, "lock_count": 0})
	}); err != nil {
		t.Fatal(err)
	}
}

/* rotated is the registry of the next key over the same database and state file (the restarted daemon). */
func rotated(t *testing.T, env *testdb.Env, r *Registry, next *seal.Keys) *Registry {
	t.Helper()
	f, err := state.Load(r.path, next.State())
	if err != nil {
		t.Fatalf("state file under the next key: %v", err)
	}
	next.SetVersion(f.SealVersion())
	return New(env.Pool("nms_executor"), next, r.path)
}

/*
A rotation re-MACs every row and re-seals every change TOTP secret under the
next key at the next version; afterwards only the next key verifies, the
current one finds the registry tampered, and a second run does nothing.
*/
func TestRotateMovesTheRegistryToTheNextKey(t *testing.T) {
	env, r := fresh(t)
	ctx := context.Background()
	if err := grant(ctx, r, 1); err != nil {
		t.Fatal(err)
	}
	enrollTOTP(t, r, 7, "JBSWY3DPEHPK3PXP")
	before := verify(t, r)
	next := nextKeys(t)
	rep, err := r.Rotate(ctx, next, noAudit, Rekey{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Version != 2 || rep.TOTPs != 1 || rep.Rows != 4 || rep.Already || rep.Resumed {
		t.Fatalf("report %+v", rep)
	}
	n := rotated(t, env, r, next)
	if got := verify(t, n); got.Seq != before.Seq+1 || got.Frozen {
		t.Fatalf("after rotation %+v (before %+v)", got, before)
	}
	if f := loadState(t, n); f.KeyVersion != 2 || f.Pending != nil || f.PendingKey != nil {
		t.Fatalf("state %+v", f)
	}
	if err := n.View(ctx, func(s *Snapshot) error {
		row, _ := s.Get("change_totp", 7)
		ct, _ := row.Get("ciphertext").([]byte)
		if kv, _ := row.Get("key_version").(int64); kv != 2 {
			t.Errorf("key_version %d", kv)
		}
		if pt, err := next.OpenTOTP(7, 2, ct); err != nil || string(pt) != "JBSWY3DPEHPK3PXP" {
			t.Errorf("under the next key: %q %v", pt, err)
		}
		if _, err := keys(t).OpenTOTP(7, 1, ct); err == nil {
			t.Error("the re-sealed secret opens under the retired key")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Verify(ctx); !errors.Is(err, ErrTampered) {
		t.Fatalf("the retired key still verifies: %v", err)
	}
	if again, err := r.Rotate(ctx, next, noAudit, Rekey{}); err != nil || !again.Already {
		t.Fatalf("second run %+v %v", again, err)
	}
	if err := grant(ctx, n, 2); err != nil {
		t.Fatalf("a write after the rotation: %v", err)
	}
}

/*
Crash windows: before COMMIT the rotation leaves the current key's state
(the next run starts over); after COMMIT only the rotation run again with
the same next key finishes it, while the daemon with either key refuses
(freeze): never a registry accepted with MACs of two keys.
*/
func TestRotateCrashWindows(t *testing.T) {
	ctx := context.Background()
	for _, stage := range []string{"rekeyed", "pending", "committed"} {
		env, r := fresh(t)
		if err := grant(ctx, r, 1); err != nil {
			t.Fatal(err)
		}
		next := nextKeys(t)
		crashAt(t, r, stage, func() error {
			_, err := r.Rotate(ctx, next, noAudit, Rekey{})
			return err
		})
		old := New(env.Pool("nms_executor"), keys(t), r.path)
		_, err := old.Verify(ctx)
		switch stage {
		case "committed":
			if !errors.Is(err, ErrTampered) {
				t.Fatalf("%s: the current key accepts a committed rotation: %v", stage, err)
			}
			if _, err := New(env.Pool("nms_executor"), next, r.path).Verify(ctx); !errors.Is(err, ErrTampered) {
				t.Fatalf("%s: the next key accepts an unfinished rotation: %v", stage, err)
			}
		case "pending":
			/* The daemon refuses to settle a rotation it cannot finish. */
			if !errors.Is(err, ErrTampered) {
				t.Fatalf("%s: %v", stage, err)
			}
		default:
			if err != nil {
				t.Fatalf("%s: %v", stage, err)
			}
		}
		rep, err := old.Rotate(ctx, next, noAudit, Rekey{})
		if err != nil {
			t.Fatalf("%s: resume: %v", stage, err)
		}
		if rep.Resumed != (stage == "committed") || rep.Version != 2 {
			t.Fatalf("%s: resume report %+v", stage, rep)
		}
		if got := verify(t, rotated(t, env, r, next)); got.Frozen {
			t.Fatalf("%s: after resume %+v", stage, got)
		}
	}
}

/* A registry row that does not verify under the current key stops the rotation before anything is written. */
func TestRotateRefusesATamperedRegistry(t *testing.T) {
	env, r := fresh(t)
	ctx := context.Background()
	if err := grant(ctx, r, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := env.Pool("postgres").Exec(ctx, `UPDATE exec.write_grant SET username_snapshot = 'x'`); err != nil {
		t.Fatal(err)
	}
	f := loadState(t, r)
	if _, err := r.Rotate(ctx, nextKeys(t), noAudit, Rekey{}); !errors.Is(err, ErrTampered) {
		t.Fatalf("rotation over a tampered registry: %v", err)
	}
	if g := loadState(t, r); g.Pending != nil || !bytes.Equal(g.Committed.StateHash, f.Committed.StateHash) {
		t.Fatalf("state changed: %+v", g)
	}
}

/* A rotation in flight to one key is never settled by a run with another. */
func TestRotateRefusesAnotherNextKey(t *testing.T) {
	_, r := fresh(t)
	ctx := context.Background()
	crashAt(t, r, "committed", func() error {
		_, err := r.Rotate(ctx, nextKeys(t), noAudit, Rekey{})
		return err
	})
	other, err := seal.Derive(&[32]byte{44})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Rotate(ctx, other, noAudit, Rekey{}); err == nil {
		t.Fatal("another key settled the rotation")
	}
}
