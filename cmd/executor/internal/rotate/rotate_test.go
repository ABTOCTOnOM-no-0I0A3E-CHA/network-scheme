package rotate_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/changeset"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/rotate"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/state"
	"github.com/beekamai/network-scheme/internal/testdb"
)

func TestMain(m *testing.M) { testdb.Main(m) }

const guardsLabel = "authz-guards"

func derive(t *testing.T, b byte) *seal.Keys {
	t.Helper()
	k, err := seal.Derive(&[32]byte{b})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

type fixture struct {
	env       *testdb.Env
	dir       string
	old, next *seal.Keys
	cs        [16]byte
}

/* setup: a bootstrapped registry with a grant, a changeset with an event, and a guards file, all under the current key. */
func setup(t *testing.T) fixture {
	t.Helper()
	env := testdb.New(t)
	attacktest.Reset(t, env)
	ctx := context.Background()
	f := fixture{env: env, dir: t.TempDir(), old: derive(t, 42), next: derive(t, 43)}
	reg := registry.New(env.Pool("nms_executor"), f.old, filepath.Join(f.dir, "state"))
	if err := reg.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err := reg.Write(ctx, func(_ context.Context, _ *registry.Snapshot, tx *registry.Tx) error {
		return tx.Put("write_grant", map[string]any{"user_id": 1, "kind": "write", "write_group": "core", "username_snapshot": "u"})
	}); err != nil {
		t.Fatal(err)
	}
	s := f.store(f.old)
	c, err := s.Create(ctx, 42, "alice", changeset.Content{Title: "t", Devices: []int64{3}, Steps: []changeset.Step{{Line: "configure"}}, BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	f.cs = c.ID
	if _, err := s.Event(ctx, c.ID, 1, "dry_run", 3, nil, map[string]any{"n": 1.5}); err != nil {
		t.Fatal(err)
	}
	if err := state.SaveSealed(filepath.Join(f.dir, "guards"), f.old.State(), guardsLabel, []byte(`{"v":1,"users":[],"window":[]}`)); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f fixture) store(k *seal.Keys) *changeset.Store {
	return &changeset.Store{Pool: f.env.Pool("nms_executor"), MAC: k.MAC(),
		Alert: func(context.Context, string, string, int64, string) error { return nil }}
}

func (f fixture) run(t *testing.T) (registry.RotateReport, error) {
	t.Helper()
	return rotate.Sealing(context.Background(), rotate.Config{Pool: f.env.Pool("nms_executor"), Old: f.old, Next: f.next,
		StateDir: f.dir, Operator: "root"})
}

/*
The rotation moves the registry, the append-only rows, the state file and
the guards file to the next key and records itself in the executor's audit;
the retired key opens none of them. A second run changes nothing.
*/
func TestSealingRotation(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	rep, err := f.run(t)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Version != 2 || rep.Already {
		t.Fatalf("report %+v", rep)
	}
	f.next.SetVersion(rep.Version)
	if _, err := registry.New(f.env.Pool("nms_executor"), f.next, filepath.Join(f.dir, "state")).Verify(ctx); err != nil {
		t.Fatalf("the registry under the next key: %v", err)
	}
	if _, err := registry.New(f.env.Pool("nms_executor"), f.old, filepath.Join(f.dir, "state")).Verify(ctx); !errors.Is(err, registry.ErrTampered) {
		t.Fatalf("the retired key still verifies: %v", err)
	}
	if c, err := f.store(f.next).Load(ctx, f.cs); err != nil || len(c.Events) != 1 {
		t.Fatalf("the changeset under the next key: %+v %v", c, err)
	}
	if _, err := f.store(f.old).Load(ctx, f.cs); err == nil {
		t.Fatal("the changeset still verifies under the retired key")
	}
	g := filepath.Join(f.dir, "guards")
	if _, err := state.LoadSealed(g, f.next.State(), guardsLabel, 1<<20); err != nil {
		t.Fatalf("guards under the next key: %v", err)
	}
	if _, err := state.LoadSealed(g, f.old.State(), guardsLabel, 1<<20); err == nil {
		t.Fatal("guards still open under the retired key")
	}
	var n int
	if err := f.env.Pool("postgres").QueryRow(ctx, `SELECT count(*) FROM exec.audit_event WHERE action = 'admin.key-rotate'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("audit rows %d %v", n, err)
	}
	if again, err := f.run(t); err != nil || !again.Already {
		t.Fatalf("second run %+v %v", again, err)
	}
}

/*
Attack (security.md 18): rows planted or rewritten in the database by
someone without the key (the api's side cannot even reach exec; a database
superuser can) are never vouched for by the next key: the rotation fails
and leaves everything under the current key.
*/
func TestSealingRotationRefusesPlantedRows(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	attacktest.Tamper(t, f.env, `ALTER TABLE exec.changeset_event DISABLE TRIGGER changeset_event_append_only;
		UPDATE exec.changeset_event SET kind = 'run_started';
		ALTER TABLE exec.changeset_event ENABLE TRIGGER changeset_event_append_only`)
	if _, err := f.run(t); !errors.Is(err, registry.ErrTampered) {
		t.Fatalf("rotation over a rewritten row: %v", err)
	}
	if _, err := registry.New(f.env.Pool("nms_executor"), f.old, filepath.Join(f.dir, "state")).Verify(ctx); err != nil {
		t.Fatalf("the failed rotation left the registry: %v", err)
	}
	if _, err := state.LoadSealed(filepath.Join(f.dir, "guards"), f.old.State(), guardsLabel, 1<<20); err != nil {
		t.Fatalf("the failed rotation moved the guards: %v", err)
	}
}
