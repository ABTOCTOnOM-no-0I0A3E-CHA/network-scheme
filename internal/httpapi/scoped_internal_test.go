package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/internal/auth"
	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/rbac"
	"github.com/beekamai/network-scheme/internal/testdb"
)

/* queryCounter counts the queries sent through a pool. */
type queryCounter struct{ n atomic.Int64 }

func (c *queryCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	c.n.Add(1)
	return ctx
}

func (c *queryCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

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

	var dev [2]int64
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) (err error) {
		for i := range dev {
			addr := netip.AddrFrom4([4]byte{203, 0, 113, byte(i + 1)})
			if dev[i], err = devices.NewStore(pool).Create(ctx, tx, devices.NewDevice{Name: "scoped", Address: addr, GroupID: grp[i]}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	counter := &queryCounter{}
	cfg := pool.Config()
	cfg.ConnConfig.Tracer = counter
	counted, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(counted.Close)
	s := newServer(Deps{RBAC: rbac.NewStore(counted), Pool: counted, Devices: devices.NewStore(counted)})
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
	own, foreign := fmt.Sprintf("/scoped/%d", dev[0]), fmt.Sprintf("/scoped/%d", dev[1])
	queries := map[string]int64{} /* by user and path */
	for _, c := range []struct {
		user, path string
		want       int
	}{
		{"viewer", own, 204},                 /* own group */
		{"viewer", foreign, 404},             /* foreign device */
		{"viewer", "/scoped/999999999", 404}, /* missing device */
		{"viewer", "/global", 403},           /* a group binding does not pass an unscoped policy */
		{"none", own, 403},                   /* no binding with the permission anywhere */
	} {
		before := counter.n.Load()
		if got := do(c.user, c.path); got != c.want {
			t.Errorf("%s %s: got %d want %d", c.user, c.path, got, c.want)
		}
		queries[c.user+c.path] = counter.n.Load() - before
	}
	/* A foreign and a missing device cost the same work as an own one: no timing oracle. */
	qOwn, qForeign, qMissing := queries["viewer"+own], queries["viewer"+foreign], queries["viewer/scoped/999999999"]
	if qForeign != qMissing || qForeign != qOwn {
		t.Errorf("query counts differ: own %d, foreign %d, missing %d", qOwn, qForeign, qMissing)
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
