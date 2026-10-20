package rbac_test

import (
	"context"
	"slices"
	"testing"

	"github.com/beekamai/network-scheme/internal/rbac"
	"github.com/beekamai/network-scheme/internal/testdb"
)

/* tree creates A > B > C and a separate root D. */
func tree(t *testing.T, env *testdb.Env, st *rbac.Store) (a, b, c, d int64) {
	t.Helper()
	ctx := context.Background()
	tx := begin(t, env)
	a, _ = st.CreateGroup(ctx, tx, nil, uniq("A"))
	b, _ = st.CreateGroup(ctx, tx, &a, uniq("B"))
	c, _ = st.CreateGroup(ctx, tx, &b, uniq("C"))
	d, err := st.CreateGroup(ctx, tx, nil, uniq("D"))
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return
}

func TestVisibleGroupsDescendants(t *testing.T) {
	env := testdb.New(t)
	st := rbac.NewStore(env.Pool("nms_api"))
	a, b, c, d := tree(t, env, st)
	s := rbac.Subject{UserID: 1, Bindings: []rbac.Binding{{Role: rbac.RoleViewer, GroupID: &a}}}
	all, ids, err := st.VisibleGroups(context.Background(), s, rbac.PermDevicesRead)
	if err != nil || all {
		t.Fatalf("all=%v err=%v", all, err)
	}
	slices.Sort(ids)
	if want := []int64{a, b, c}; !slices.Equal(ids, want) || slices.Contains(ids, d) {
		t.Fatalf("ids=%v want %v", ids, want)
	}
	/* A role without the permission sees nothing. */
	aud := rbac.Subject{UserID: 2, Bindings: []rbac.Binding{{Role: rbac.RoleAuditor, GroupID: &a}}}
	if all, ids, err := st.VisibleGroups(context.Background(), aud, rbac.PermDevicesRead); err != nil || all || len(ids) != 0 {
		t.Fatalf("auditor: all=%v ids=%v err=%v", all, ids, err)
	}
	/* Overlapping bindings do not duplicate ids. */
	s.Bindings = append(s.Bindings, rbac.Binding{Role: rbac.RoleOperator, GroupID: &b})
	_, ids, _ = st.VisibleGroups(context.Background(), s, rbac.PermDevicesRead)
	if len(ids) != 3 {
		t.Fatalf("ids=%v want 3 distinct", ids)
	}
}

func TestVisibleGroupsGlobal(t *testing.T) {
	env := testdb.New(t)
	st := rbac.NewStore(env.Pool("nms_api"))
	s := rbac.Subject{UserID: 1, Bindings: []rbac.Binding{{Role: rbac.RoleViewer}}}
	all, ids, err := st.VisibleGroups(context.Background(), s, rbac.PermDevicesRead)
	if err != nil || !all || len(ids) != 0 {
		t.Fatalf("all=%v ids=%v err=%v", all, ids, err)
	}
}

func TestHoldsAnywhere(t *testing.T) {
	g := int64(7)
	cases := []struct {
		name string
		s    rbac.Subject
		p    rbac.Perm
		want bool
	}{
		{"group viewer reads", rbac.Subject{Bindings: []rbac.Binding{{Role: rbac.RoleViewer, GroupID: &g}}}, rbac.PermDevicesRead, true},
		{"group viewer cannot poll", rbac.Subject{Bindings: []rbac.Binding{{Role: rbac.RoleViewer, GroupID: &g}}}, rbac.PermDevicesPoll, false},
		{"global operator polls", rbac.Subject{Bindings: []rbac.Binding{{Role: rbac.RoleOperator}}}, rbac.PermDevicesPoll, true},
		{"operator cannot manage", rbac.Subject{Bindings: []rbac.Binding{{Role: rbac.RoleOperator}}}, rbac.PermDevicesManage, false},
		{"group admin credentials", rbac.Subject{Bindings: []rbac.Binding{{Role: rbac.RoleAdmin, GroupID: &g}}}, rbac.PermDeviceCredentials, true},
		{"auditor none", rbac.Subject{Bindings: []rbac.Binding{{Role: rbac.RoleAuditor}}}, rbac.PermDevicesRead, false},
		{"no bindings", rbac.Subject{}, rbac.PermDevicesRead, false},
		{"self always", rbac.Subject{}, rbac.PermSelf, true},
	}
	for _, c := range cases {
		if got := c.s.HoldsAnywhere(c.p); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestDepthCapOnCorruptCycle(t *testing.T) {
	env := testdb.New(t)
	st := rbac.NewStore(env.Pool("nms_api"))
	a, b, _, _ := tree(t, env, st)
	ctx := context.Background()
	su := env.Pool("postgres")
	/* The application cannot form a cycle; a superuser can (corruption). */
	if _, err := su.Exec(ctx, `UPDATE core.device_group SET parent_id = $1 WHERE id = $2`, b, a); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = su.Exec(ctx, `UPDATE core.device_group SET parent_id = NULL WHERE id = $1`, a) })
	s := rbac.Subject{UserID: 1, Bindings: []rbac.Binding{{Role: rbac.RoleViewer, GroupID: &a}}}
	if _, _, err := st.VisibleGroups(ctx, s, rbac.PermDevicesRead); err == nil {
		t.Fatal("cycle must produce an error")
	}
}
