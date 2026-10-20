package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/auth"
	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/rbac"
	"github.com/beekamai/network-scheme/internal/testdb"
)

type fakeDevices map[int64]devices.Device

func (f fakeDevices) Get(_ context.Context, id int64) (devices.Device, error) {
	if d, ok := f[id]; ok {
		return d, nil
	}
	return devices.Device{}, devices.ErrNotFound
}

func TestScopedPolicyAdmission(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	pool := env.Pool("nms_api")
	st := rbac.NewStore(pool)
	var grp [2]int64
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) (err error) {
		for i := range grp {
			if grp[i], err = st.CreateGroup(ctx, tx, nil, fmt.Sprintf("scoped-%d-%s", i, t.Name())); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	user := func(name string, bs ...rbac.Binding) int64 {
		var id int64
		err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) (err error) {
			if id, err = auth.NewUserStore(pool).Create(ctx, tx, name, "Tangerine-Lighthouse-Quorum-81"); err != nil {
				return err
			}
			return st.SetBindings(ctx, tx, id, bs)
		})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	viewer := user("scoped_viewer", rbac.Binding{Role: rbac.RoleViewer, GroupID: &grp[0]})
	none := user("scoped_none")

	s := newServer(Deps{RBAC: st, Pool: pool, Devices: fakeDevices{1: {ID: 1, GroupID: grp[0]}, 2: {ID: 2, GroupID: grp[1]}}})
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
			uid := map[string]int64{"viewer": viewer, "none": none}[q.Header.Get("X-Test-User")]
			next.ServeHTTP(w, q.WithContext(context.WithValue(q.Context(), keySession,
				sessionCtx{valid: true, sess: auth.Session{UserID: uid}})))
		})
	})
	s.route(r, http.MethodGet, "/scoped/{id}", Policy{Perm: rbac.PermDevicesRead, Scoped: true},
		func(w http.ResponseWriter, q *http.Request) {
			var id int64
			if _, err := fmt.Sscan(chi.URLParam(q, "id"), &id); err != nil {
				s.fail(w, q, err)
				return
			}
			if _, err := s.authorizeDevice(q, rbac.PermDevicesRead, id); err != nil {
				s.fail(w, q, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
	s.route(r, http.MethodGet, "/global", Policy{Perm: rbac.PermDevicesRead},
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

	do := func(user, path string) int {
		q := httptest.NewRequest(http.MethodGet, path, nil)
		q.Header.Set("X-Test-User", user)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, q)
		return w.Code
	}
	for _, c := range []struct {
		user, path string
		want       int
	}{
		{"viewer", "/scoped/1", 204},  /* own group */
		{"viewer", "/scoped/2", 404},  /* foreign device */
		{"viewer", "/scoped/99", 404}, /* missing device */
		{"viewer", "/global", 403},    /* a group binding does not pass an unscoped policy */
		{"none", "/scoped/1", 403},    /* no binding with the permission anywhere */
	} {
		if got := do(c.user, c.path); got != c.want {
			t.Errorf("%s %s: got %d want %d", c.user, c.path, got, c.want)
		}
	}
}

func TestRoutePanicsOnInconsistentPolicy(t *testing.T) {
	for name, p := range map[string]Policy{
		"scoped public":       {Public: true, Scoped: true},
		"scoped without perm": {Scoped: true},
		"scoped self":         {Perm: rbac.PermSelf, Scoped: true},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("route accepted an inconsistent policy")
				}
			}()
			newServer(Deps{}).route(chi.NewRouter(), http.MethodGet, "/x", p, func(http.ResponseWriter, *http.Request) {})
		})
	}
}
