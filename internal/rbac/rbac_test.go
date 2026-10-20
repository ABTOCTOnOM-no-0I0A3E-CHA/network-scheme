package rbac_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/auth"
	"github.com/beekamai/network-scheme/internal/rbac"
	"github.com/beekamai/network-scheme/internal/testdb"
)

func TestMain(m *testing.M) { testdb.Main(m) }

func i64(v int64) *int64 { return &v }

func TestCanGlobalAndGroupScoped(t *testing.T) {
	all := []rbac.Perm{rbac.PermSelf, rbac.PermUsersManage, rbac.PermGroupsManage, rbac.PermBindingsManage, rbac.PermAuditRead}
	admin := rbac.Subject{UserID: 1, Bindings: []rbac.Binding{{Role: rbac.RoleAdmin}}}
	for _, p := range all {
		if !admin.Can(p, nil, nil) {
			t.Errorf("global admin must have %s", p)
		}
	}
	op := rbac.Subject{UserID: 2, Bindings: []rbac.Binding{{Role: rbac.RoleOperator, GroupID: i64(1)}}}
	for _, p := range all {
		if got, want := op.Can(p, i64(1), nil), p == rbac.PermSelf; got != want {
			t.Errorf("operator on group 1, %s: got %v want %v", p, got, want)
		}
	}
	aud := rbac.Subject{UserID: 3, Bindings: []rbac.Binding{{Role: rbac.RoleAuditor}}}
	for _, p := range all {
		want := p == rbac.PermSelf || p == rbac.PermAuditRead
		if got := aud.Can(p, nil, nil); got != want {
			t.Errorf("auditor, %s: got %v want %v", p, got, want)
		}
	}
	/* A group-scoped admin does not cover objects outside the tree. */
	gadmin := rbac.Subject{UserID: 4, Bindings: []rbac.Binding{{Role: rbac.RoleAdmin, GroupID: i64(1)}}}
	if gadmin.Can(rbac.PermUsersManage, nil, nil) {
		t.Error("group admin must not manage users globally")
	}
}

func TestGroupBindingCoversDescendants(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	st := rbac.NewStore(env.Pool("nms_api"))
	tx := begin(t, env)
	a, _ := st.CreateGroup(ctx, tx, nil, uniq("A"))
	b, _ := st.CreateGroup(ctx, tx, &a, uniq("B"))
	c, err := st.CreateGroup(ctx, tx, &b, uniq("C"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := st.CreateGroup(ctx, tx, nil, uniq("D"))
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	anc, err := st.Ancestors(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(anc) != 2 || anc[0] != b || anc[1] != a {
		t.Fatalf("ancestors of C = %v, want [%d %d]", anc, b, a)
	}
	s := rbac.Subject{UserID: 1, Bindings: []rbac.Binding{{Role: rbac.RoleAdmin, GroupID: &a}}}
	ancB, _ := st.Ancestors(ctx, b)
	ancD, _ := st.Ancestors(ctx, d)
	for name, ok := range map[string]bool{
		"A": s.Can(rbac.PermGroupsManage, &a, nil),
		"B": s.Can(rbac.PermGroupsManage, &b, ancB),
		"C": s.Can(rbac.PermGroupsManage, &c, anc),
	} {
		if !ok {
			t.Errorf("binding on A must cover %s", name)
		}
	}
	if s.Can(rbac.PermGroupsManage, &d, ancD) {
		t.Error("binding on A must not cover sibling D")
	}
}

func TestLastAdminProtected(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	st := rbac.NewStore(env.Pool("nms_api"))
	admin := []rbac.Binding{{Role: rbac.RoleAdmin}}
	resetBindings(t, env)
	u1, u2 := newUser(t, env), newUser(t, env)
	mustSet(t, env, st, u1, admin)
	if err := set(env, st, u1, nil); !errors.Is(err, rbac.ErrLastAdmin) {
		t.Fatalf("remove only admin: %v, want ErrLastAdmin", err)
	}
	if err := set(env, st, u1, []rbac.Binding{{Role: rbac.RoleViewer}}); !errors.Is(err, rbac.ErrLastAdmin) {
		t.Fatalf("downgrade only admin: %v, want ErrLastAdmin", err)
	}
	/* A group-scoped admin does not count as a global admin. */
	g := mustGroup(t, env, st, uniq("g"))
	mustSet(t, env, st, u2, []rbac.Binding{{Role: rbac.RoleAdmin, GroupID: &g}})
	if err := set(env, st, u1, nil); !errors.Is(err, rbac.ErrLastAdmin) {
		t.Fatalf("group admin must not count: %v", err)
	}
	mustSet(t, env, st, u2, admin)
	if err := set(env, st, u1, nil); err != nil {
		t.Fatalf("with a second admin: %v", err)
	}
	sub, err := st.LoadSubject(ctx, u1)
	if err != nil || len(sub.Bindings) != 0 {
		t.Fatalf("LoadSubject = %+v, %v", sub, err)
	}
}

func TestLastAdminConcurrent(t *testing.T) {
	env := testdb.New(t)
	st := rbac.NewStore(env.Pool("nms_api"))
	resetBindings(t, env)
	u1, u2 := newUser(t, env), newUser(t, env)
	admin := []rbac.Binding{{Role: rbac.RoleAdmin}}
	mustSet(t, env, st, u1, admin)
	mustSet(t, env, st, u2, admin)
	var wg sync.WaitGroup
	var ok atomic.Int32
	for _, u := range []int64{u1, u2} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := set(env, st, u, nil); err == nil {
				ok.Add(1)
			} else if !errors.Is(err, rbac.ErrLastAdmin) {
				t.Errorf("unexpected: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("%d concurrent removals succeeded, want exactly 1", ok.Load())
	}
}

/*
disable runs GuardNotLastAdmin and SetDisabled in one transaction, as the API
does, pausing for pause between them to widen any race window.
*/
func disable(env *testdb.Env, st *rbac.Store, user int64, pause time.Duration) error {
	ctx := context.Background()
	return pgx.BeginFunc(ctx, env.Pool("nms_api"), func(tx pgx.Tx) error {
		if err := st.GuardNotLastAdmin(ctx, tx, user); err != nil {
			return err
		}
		time.Sleep(pause)
		return auth.NewUserStore(env.Pool("nms_api")).SetDisabled(ctx, tx, user, true)
	})
}

func TestGuardNotLastAdmin(t *testing.T) {
	env := testdb.New(t)
	st := rbac.NewStore(env.Pool("nms_api"))
	resetBindings(t, env)
	u1, u2, plain := newUser(t, env), newUser(t, env), newUser(t, env)
	mustSet(t, env, st, u1, []rbac.Binding{{Role: rbac.RoleAdmin}})
	if err := disable(env, st, u1, 0); !errors.Is(err, rbac.ErrLastAdmin) {
		t.Fatalf("disable only admin: %v, want ErrLastAdmin", err)
	}
	if err := disable(env, st, plain, 0); err != nil {
		t.Fatalf("disable non-admin: %v", err)
	}
	/* A disabled admin does not count as a remaining admin. */
	mustSet(t, env, st, plain, []rbac.Binding{{Role: rbac.RoleAdmin}})
	if err := disable(env, st, u1, 0); !errors.Is(err, rbac.ErrLastAdmin) {
		t.Fatalf("disabled second admin must not count: %v", err)
	}
	mustSet(t, env, st, u2, []rbac.Binding{{Role: rbac.RoleAdmin}})
	if err := disable(env, st, u1, 0); err != nil {
		t.Fatalf("with a second admin: %v", err)
	}
}

func TestGuardNotLastAdminConcurrentDisable(t *testing.T) {
	env := testdb.New(t)
	st := rbac.NewStore(env.Pool("nms_api"))
	resetBindings(t, env)
	u1, u2 := newUser(t, env), newUser(t, env)
	mustSet(t, env, st, u1, []rbac.Binding{{Role: rbac.RoleAdmin}})
	mustSet(t, env, st, u2, []rbac.Binding{{Role: rbac.RoleAdmin}})
	var wg sync.WaitGroup
	var ok atomic.Int32
	start := make(chan struct{})
	for _, u := range []int64{u1, u2} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := disable(env, st, u, 300*time.Millisecond); err == nil {
				ok.Add(1)
			} else if !errors.Is(err, rbac.ErrLastAdmin) {
				t.Errorf("unexpected: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("%d concurrent disables succeeded, want exactly 1", ok.Load())
	}
}

func TestGroupCycleRejected(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	st := rbac.NewStore(env.Pool("nms_api"))
	a := mustGroup(t, env, st, uniq("A"))
	tx := begin(t, env)
	b, err := st.CreateGroup(ctx, tx, &a, uniq("B"))
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct{ id, parent int64 }{"under child": {a, b}, "under self": {a, a}} {
		tx := begin(t, env)
		if err := st.MoveGroup(ctx, tx, c.id, &c.parent); !errors.Is(err, rbac.ErrGroupCycle) {
			t.Errorf("%s: %v, want ErrGroupCycle", name, err)
		}
		_ = tx.Rollback(ctx)
	}
	/* A legal move works, and deleting a non-leaf is refused. */
	tx = begin(t, env)
	if err := st.MoveGroup(ctx, tx, b, nil); err != nil {
		t.Fatalf("legal move: %v", err)
	}
	_ = tx.Rollback(ctx)
	tx = begin(t, env)
	if err := st.DeleteGroup(ctx, tx, a); !errors.Is(err, rbac.ErrGroupNotEmpty) {
		t.Errorf("delete non-leaf: %v", err)
	}
	_ = tx.Rollback(ctx)
}

func TestDuplicateAndGlobalBindings(t *testing.T) {
	env := testdb.New(t)
	resetBindings(t, env)
	st := rbac.NewStore(env.Pool("nms_api"))
	u := newUser(t, env)
	mustSet(t, env, st, u, []rbac.Binding{{Role: rbac.RoleAdmin}, {Role: rbac.RoleAdmin}})
	if err := set(env, st, u, []rbac.Binding{{Role: "root"}}); !errors.Is(err, rbac.ErrInvalidRole) {
		t.Errorf("invalid role: %v", err)
	}
	if err := set(env, st, u, []rbac.Binding{{Role: rbac.RoleAdmin}, {Role: rbac.RoleViewer, GroupID: i64(99999)}}); !errors.Is(err, rbac.ErrGroupNotFound) {
		t.Errorf("unknown group: %v", err)
	}
	sub, err := st.LoadSubject(context.Background(), u)
	if err != nil || len(sub.Bindings) != 1 {
		t.Fatalf("bindings = %+v, %v (failed set must roll back)", sub, err)
	}
}

func begin(t *testing.T, env *testdb.Env) pgx.Tx {
	t.Helper()
	tx, err := env.Pool("nms_api").Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func set(env *testdb.Env, st *rbac.Store, user int64, b []rbac.Binding) error {
	ctx := context.Background()
	tx, err := env.Pool("nms_api").Begin(ctx)
	if err != nil {
		return err
	}
	if err := st.SetBindings(ctx, tx, user, b); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}

func mustSet(t *testing.T, env *testdb.Env, st *rbac.Store, user int64, b []rbac.Binding) {
	t.Helper()
	if err := set(env, st, user, b); err != nil {
		t.Fatal(err)
	}
}

func mustGroup(t *testing.T, env *testdb.Env, st *rbac.Store, name string) int64 {
	t.Helper()
	tx := begin(t, env)
	id, err := st.CreateGroup(context.Background(), tx, nil, name)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	return id
}

var userSeq atomic.Int64

func newUser(t *testing.T, env *testdb.Env) int64 {
	t.Helper()
	ctx := context.Background()
	tx := begin(t, env)
	id, err := auth.NewUserStore(env.Pool("nms_api")).Create(ctx, tx,
		fmt.Sprintf("user%d", userSeq.Add(1)), "Tangerine-Lighthouse-Quorum-81")
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return id
}

/* The database is shared by the package's tests, so admin tests start clean. */
func resetBindings(t *testing.T, env *testdb.Env) {
	t.Helper()
	if _, err := env.Pool("postgres").Exec(context.Background(), `DELETE FROM core.role_binding`); err != nil {
		t.Fatal(err)
	}
}

func uniq(prefix string) string { return fmt.Sprintf("%s-%d", prefix, userSeq.Add(1)) }
