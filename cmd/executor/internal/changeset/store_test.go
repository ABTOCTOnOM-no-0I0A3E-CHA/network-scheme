package changeset_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/changeset"
	"github.com/beekamai/network-scheme/internal/testdb"
)

func TestMain(m *testing.M) { testdb.Main(m) }

/* alerts records the alerts a store raises. */
type alerts struct {
	mu    sync.Mutex
	kinds []string
}

func (a *alerts) add(_ context.Context, kind, _ string, _ int64, _ string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.kinds = append(a.kinds, kind)
	return nil
}

func (a *alerts) count(kind string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, k := range a.kinds {
		if k == kind {
			n++
		}
	}
	return n
}

func newStore(t *testing.T, key byte) (*changeset.Store, *testdb.Env, *alerts) {
	t.Helper()
	env := testdb.New(t)
	attacktest.Reset(t, env)
	al := &alerts{}
	return &changeset.Store{Pool: env.Pool("nms_executor"), MAC: &[32]byte{key}, Alert: al.add}, env, al
}

func content(title string) changeset.Content {
	return changeset.Content{Title: title, Devices: []int64{3, 4}, Steps: []changeset.Step{{Line: "configure"}, {Line: "hostname {{h}}"}},
		Vars: map[int64]map[string]string{3: {"h": "a"}, 4: {"h": "b"}}, BatchSize: 1}
}

/* A changeset reads back as written: newest revision, every event, its payload as the MAC covers it. */
func TestStoreRoundTrip(t *testing.T) {
	s, _, al := newStore(t, 1)
	ctx := context.Background()
	cs, err := s.Create(ctx, 42, "alice", content("one"))
	if err != nil {
		t.Fatal(err)
	}
	rev, err := s.Revise(ctx, cs.ID, 1, content("two"))
	if err != nil || rev != 2 {
		t.Fatalf("revise: %d %v", rev, err)
	}
	if _, err := s.Revise(ctx, cs.ID, 1, content("stale")); !errors.Is(err, changeset.ErrConflict) {
		t.Fatalf("stale revision: %v", err)
	}
	if _, err := s.Revise(ctx, cs.ID, 5, content("gap")); !errors.Is(err, changeset.ErrConflict) {
		t.Fatalf("revision after a gap: %v", err)
	}
	sid := [16]byte{9}
	if _, err := s.Event(ctx, cs.ID, 2, "dry_run", 3, &sid, map[string]any{"plan_sha256": "ab", "devices": []any{map[string]any{"id": int64(1) << 60}}}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(ctx, cs.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Rev != 2 || got.Content.Title != "two" || got.Author != 42 || got.AuthorName != "alice" || got.Kind != changeset.KindLines ||
		len(got.Events) != 1 || got.Events[0].Device != 3 || *got.Events[0].Session != sid {
		t.Fatalf("loaded %+v", got)
	}
	if string(got.Events[0].Payload) != `{"devices":[{"id":1152921504606846976}],"plan_sha256":"ab"}` {
		t.Fatalf("payload %s", got.Events[0].Payload)
	}
	if al.count(changeset.KindTamper) != 0 {
		t.Fatal("tamper alert on clean rows")
	}
	if _, err := s.Load(ctx, [16]byte{1}); !errors.Is(err, changeset.ErrNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
}

/*
Every row is under the executor's MAC: a superuser who changes the
content, moves a revision or an event to another changeset, drops a
revision in the middle or writes rows with another key gets ErrTampered and
the high alert, never a changeset.
*/
func TestStoreRefusesTamperedRows(t *testing.T) {
	ctx := context.Background()
	/* around is sql as the superuser with the append-only triggers of tables off (one statement each) */
	around := func(t *testing.T, env *testdb.Env, tables []string, sql string, args ...any) {
		for _, tb := range tables {
			attacktest.Tamper(t, env, `ALTER TABLE exec.`+tb+` DISABLE TRIGGER `+tb+`_append_only`)
		}
		for _, q := range strings.Split(sql, ";") {
			if strings.TrimSpace(q) != "" {
				n := strings.Count(q, "$2")
				if n > 0 {
					attacktest.Tamper(t, env, q, args...)
				} else {
					attacktest.Tamper(t, env, q, args[:1]...)
				}
			}
		}
		for _, tb := range tables {
			attacktest.Tamper(t, env, `ALTER TABLE exec.`+tb+` ENABLE TRIGGER `+tb+`_append_only`)
		}
	}
	rev, ev, own := []string{"changeset_revision"}, []string{"changeset_event"}, []string{"changeset"}
	both := []string{"changeset_revision", "changeset_event"}
	for name, attack := range map[string]func(t *testing.T, env *testdb.Env, a, b [16]byte){
		"content changed": func(t *testing.T, env *testdb.Env, a, _ [16]byte) {
			around(t, env, rev, `UPDATE exec.changeset_revision SET content = $2 WHERE changeset_id = $1 AND rev = 2`, a, content("evil").Canonical())
		},
		"content and its hash changed": func(t *testing.T, env *testdb.Env, a, _ [16]byte) {
			around(t, env, rev, `UPDATE exec.changeset_revision SET content = $2, content_sha256 = sha256($2) WHERE changeset_id = $1 AND rev = 2`,
				a, content("evil").Canonical())
		},
		"revision of another changeset": func(t *testing.T, env *testdb.Env, a, b [16]byte) {
			around(t, env, both, `DELETE FROM exec.changeset_event WHERE changeset_id = $1; DELETE FROM exec.changeset_revision WHERE changeset_id = $1 AND rev = 2;
				INSERT INTO exec.changeset_revision SELECT $1, rev, created_at, content, content_sha256, mac FROM exec.changeset_revision WHERE changeset_id = $2 AND rev = 2`, a, b)
		},
		"event of another changeset": func(t *testing.T, env *testdb.Env, a, b [16]byte) {
			attacktest.Tamper(t, env, `INSERT INTO exec.changeset_event (id, changeset_id, rev, at, kind, payload, mac)
				SELECT nextval('exec.changeset_event_id_seq'), $1, rev, at, kind, payload, mac FROM exec.changeset_event WHERE changeset_id = $2`, a, b)
		},
		"event payload changed": func(t *testing.T, env *testdb.Env, a, _ [16]byte) {
			around(t, env, ev, `UPDATE exec.changeset_event SET payload = '{"ok": true, "plan_sha256": "ff"}' WHERE changeset_id = $1`, a)
		},
		"middle revision gone": func(t *testing.T, env *testdb.Env, a, _ [16]byte) {
			around(t, env, both, `DELETE FROM exec.changeset_event WHERE changeset_id = $1; DELETE FROM exec.changeset_revision WHERE changeset_id = $1 AND rev = 1`, a)
		},
		"author changed": func(t *testing.T, env *testdb.Env, a, _ [16]byte) {
			around(t, env, own, `UPDATE exec.changeset SET author = 7 WHERE id = $1`, a)
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, env, al := newStore(t, 1)
			a, err := s.Create(ctx, 42, "alice", content("a1"))
			if err != nil {
				t.Fatal(err)
			}
			b, err := s.Create(ctx, 43, "bob", content("b1"))
			if err != nil {
				t.Fatal(err)
			}
			for _, cs := range []changeset.Changeset{a, b} {
				if _, err := s.Revise(ctx, cs.ID, 1, content("rev2")); err != nil {
					t.Fatal(err)
				}
				if _, err := s.Event(ctx, cs.ID, 2, "dry_run", 0, nil, map[string]any{"ok": false, "plan_sha256": "00"}); err != nil {
					t.Fatal(err)
				}
			}
			attack(t, env, a.ID, b.ID)
			if _, err := s.Load(ctx, a.ID); !errors.Is(err, changeset.ErrTampered) {
				t.Fatalf("load: %v", err)
			}
			if al.count(changeset.KindTamper) == 0 {
				t.Fatal("no tamper alert")
			}
			if _, err := s.Load(ctx, b.ID); err != nil {
				t.Fatalf("the other changeset: %v", err)
			}
		})
	}
	/* rows written under another key */
	s, env, al := newStore(t, 1)
	other := &changeset.Store{Pool: env.Pool("nms_executor"), MAC: &[32]byte{2}}
	cs, err := other.Create(ctx, 42, "alice", content("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx, cs.ID); !errors.Is(err, changeset.ErrTampered) || al.count(changeset.KindTamper) != 1 {
		t.Fatalf("foreign MAC: %v", err)
	}
}
