package devices_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/rbac"
	"github.com/beekamai/network-scheme/internal/testdb"
)

func TestMain(m *testing.M) { testdb.Main(m) }

var seq atomic.Int64

/* nextAddr returns a fresh 10.x.y.z address so tests never collide on the shared database. */
func nextAddr() netip.Addr {
	n := seq.Add(1)
	return netip.AddrFrom4([4]byte{10, byte(n >> 16), byte(n >> 8), byte(n)})
}

func begin(t *testing.T, env *testdb.Env, role string) pgx.Tx {
	t.Helper()
	tx, err := env.Pool(role).Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	return tx
}

/* newGroup creates a committed group so that other pool connections see it. */
func newGroup(t *testing.T, env *testdb.Env) int64 {
	t.Helper()
	ctx := context.Background()
	tx := begin(t, env, "nms_api")
	id, err := rbac.NewStore(env.Pool("nms_api")).CreateGroup(ctx, tx, nil, fmt.Sprintf("g-%d", seq.Add(1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return id
}

func create(t *testing.T, env *testdb.Env, st *devices.Store, d devices.NewDevice) int64 {
	t.Helper()
	ctx := context.Background()
	tx := begin(t, env, "nms_api")
	id, err := st.Create(ctx, tx, d)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return id
}

func code(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

func TestDeviceAddressUnique(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	st := devices.NewStore(env.Pool("nms_api"))
	g := newGroup(t, env)
	addr := nextAddr()
	create(t, env, st, devices.NewDevice{Name: "a", Address: addr, GroupID: g})

	tx := begin(t, env, "nms_api")
	if _, err := st.Create(ctx, tx, devices.NewDevice{Name: "b", Address: addr, GroupID: g}); !errors.Is(err, devices.ErrAddressExists) {
		t.Fatalf("same address and port: got %v, want ErrAddressExists", err)
	}
	_ = tx.Rollback(ctx)

	create(t, env, st, devices.NewDevice{Name: "c", Address: addr, SNMPPort: 1161, GroupID: g})
}

func TestCreateGetUpdateDelete(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	st := devices.NewStore(env.Pool("nms_api"))
	g := newGroup(t, env)
	addr := nextAddr()
	id := create(t, env, st, devices.NewDevice{Name: "sw1", Address: addr, GroupID: g})

	d, err := st.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if d.Name != "sw1" || d.Address != addr || d.SNMPPort != 161 || d.Driver != "auto" || d.PollerID != "local" || d.GroupID != g {
		t.Errorf("defaults: %+v", d)
	}

	name, port, avail := "sw2", 1161, 30
	tx := begin(t, env, "nms_api")
	if err := st.Update(ctx, tx, id, devices.Patch{Name: &name, SNMPPort: &port, Intervals: &devices.Intervals{AvailS: &avail}}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	d, _ = st.Get(ctx, id)
	if d.Name != "sw2" || d.SNMPPort != 1161 || d.Intervals.AvailS == nil || *d.Intervals.AvailS != 30 || d.Intervals.MetricsS != nil {
		t.Errorf("after update: %+v", d)
	}

	if _, err := st.Get(ctx, -1); !errors.Is(err, devices.ErrNotFound) {
		t.Errorf("Get missing: %v", err)
	}
	tx = begin(t, env, "nms_api")
	if err := st.Update(ctx, tx, -1, devices.Patch{Name: &name}); !errors.Is(err, devices.ErrNotFound) {
		t.Errorf("Update missing: %v", err)
	}
	_ = tx.Rollback(ctx)

	tx = begin(t, env, "nms_api")
	if err := st.PutProfile(ctx, tx, devices.Owner{Kind: "device", ID: id}, "snmp2c", []byte("x"), 1); err != nil {
		t.Fatal(err)
	}
	if err := st.Delete(ctx, tx, id); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get(ctx, id); !errors.Is(err, devices.ErrNotFound) {
		t.Errorf("Get after delete: %v", err)
	}
	var n int
	q := `SELECT count(*) FROM core.access_profile WHERE owner_kind = 'device' AND owner_id = $1`
	if err := env.Pool("nms_poller").QueryRow(ctx, q, id).Scan(&n); err != nil || n != 0 {
		t.Errorf("profiles after device delete: %d %v", n, err)
	}
}

func TestCreateUnknownGroup(t *testing.T) {
	env := testdb.New(t)
	st := devices.NewStore(env.Pool("nms_api"))
	tx := begin(t, env, "nms_api")
	_, err := st.Create(context.Background(), tx, devices.NewDevice{Name: "x", Address: nextAddr(), GroupID: -5})
	if !errors.Is(err, devices.ErrGroupNotFound) {
		t.Fatalf("got %v, want ErrGroupNotFound", err)
	}
}

func TestListFilteredByGroups(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	st := devices.NewStore(env.Pool("nms_api"))
	a, b := newGroup(t, env), newGroup(t, env)
	ida := create(t, env, st, devices.NewDevice{Name: "a", Address: nextAddr(), GroupID: a})
	idb := create(t, env, st, devices.NewDevice{Name: "b", Address: nextAddr(), GroupID: b})

	got, err := st.List(ctx, devices.Filter{GroupIDs: []int64{a}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != ida {
		t.Fatalf("filter [A]: %+v", got)
	}
	if got, _ := st.List(ctx, devices.Filter{}); len(got) != 0 {
		t.Errorf("empty filter must return nothing, got %d", len(got))
	}
	all, _ := st.List(ctx, devices.Filter{All: true})
	seen := map[int64]bool{}
	for _, d := range all {
		seen[d.ID] = true
	}
	if !seen[ida] || !seen[idb] {
		t.Errorf("All must include both devices")
	}
}

func TestProfilesNeverReturnCiphertext(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	st := devices.NewStore(env.Pool("nms_api"))
	g := newGroup(t, env)
	id := create(t, env, st, devices.NewDevice{Name: "a", Address: nextAddr(), GroupID: g})
	owner := devices.Owner{Kind: "device", ID: id}

	tx := begin(t, env, "nms_api")
	secret := []byte("SEALED-CIPHERTEXT-BYTES")
	if err := st.PutProfile(ctx, tx, owner, "snmp3", secret, 1); err != nil {
		t.Fatal(err)
	}
	if err := st.PutProfile(ctx, tx, owner, "snmp3", secret, 2); err != nil { /* replace */
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	ps, err := st.Profiles(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 || ps[0].Kind != "snmp3" || ps[0].Status != "pending" || ps[0].UpdatedAt.IsZero() {
		t.Fatalf("profiles: %+v", ps)
	}
	if s := fmt.Sprintf("%+v %#v", ps, ps); strings.Contains(s, string(secret)) {
		t.Error("ProfileInfo leaks ciphertext")
	}
	/* The API role cannot read the ciphertext column at all. */
	_, err = env.Pool("nms_api").Exec(ctx, `SELECT ciphertext FROM core.access_profile`)
	if code(err) != "42501" {
		t.Errorf("nms_api SELECT ciphertext: %v, want 42501", err)
	}

	tx = begin(t, env, "nms_api")
	if err := st.PutProfile(ctx, tx, owner, "bogus", secret, 1); !errors.Is(err, devices.ErrInvalid) {
		t.Errorf("bad kind: %v", err)
	}
	_ = tx.Rollback(ctx)
	tx = begin(t, env, "nms_api")
	if err := st.PutProfile(ctx, tx, devices.Owner{Kind: "device", ID: -1}, "snmp2c", secret, 1); !errors.Is(err, devices.ErrNotFound) {
		t.Errorf("missing owner: %v", err)
	}
	_ = tx.Rollback(ctx)

	tx = begin(t, env, "nms_api")
	if err := st.DeleteProfile(ctx, tx, owner, "snmp3"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteProfile(ctx, tx, owner, "snmp3"); !errors.Is(err, devices.ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
	_ = tx.Rollback(ctx)
}

func newScan(t *testing.T, env *testdb.Env, st *devices.Store, g int64) int64 {
	t.Helper()
	ctx := context.Background()
	tx := begin(t, env, "nms_api")
	id, err := st.CreateScan(ctx, tx, devices.NewScan{CIDR: netip.MustParsePrefix("10.200.0.0/24"), GroupID: g, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestDiscoveredDeduplicated(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	st := devices.NewStore(env.Pool("nms_api"))
	pst := devices.NewStore(env.Pool("nms_poller"))
	g := newGroup(t, env)
	s1, s2 := newScan(t, env, st, g), newScan(t, env, st, g)
	addr := nextAddr()

	for i, s := range []int64{s1, s2} {
		tx := begin(t, env, "nms_poller")
		if err := pst.UpsertDiscovered(ctx, tx, s, addr, "1.3.6.1", "descr", fmt.Sprintf("name%d", i)); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	items, err := st.Inbox(ctx, devices.InboxFilter{All: true})
	if err != nil {
		t.Fatal(err)
	}
	var hits []devices.Discovered
	for _, it := range items {
		if it.Address == addr {
			hits = append(hits, it)
		}
	}
	if len(hits) != 1 || hits[0].ScanID != s2 || hits[0].SysName != "name1" {
		t.Fatalf("expected one row from the latest scan: %+v", hits)
	}
}

func TestAcceptCreatesDevice(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	st := devices.NewStore(env.Pool("nms_api"))
	pst := devices.NewStore(env.Pool("nms_poller"))
	g, target := newGroup(t, env), newGroup(t, env)
	s := newScan(t, env, st, g)
	addr, addr2 := nextAddr(), nextAddr()
	tx := begin(t, env, "nms_poller")
	for _, a := range []netip.Addr{addr, addr2} {
		if err := pst.UpsertDiscovered(ctx, tx, s, a, "1.3.6.1.4.1.89", "MES2324", "sw"); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	find := func(a netip.Addr) devices.Discovered {
		items, _ := st.Inbox(ctx, devices.InboxFilter{All: true})
		for _, it := range items {
			if it.Address == a {
				return it
			}
		}
		t.Fatalf("%s not in inbox", a)
		return devices.Discovered{}
	}
	it := find(addr)

	tx = begin(t, env, "nms_api")
	devID, err := st.Accept(ctx, tx, it.ID, "core-sw", target)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	d, err := st.Get(ctx, devID)
	if err != nil || d.GroupID != target || d.Address != addr || d.Name != "core-sw" || d.SysObjectID != "1.3.6.1.4.1.89" {
		t.Fatalf("device: %+v %v", d, err)
	}
	if find(addr).Status != "accepted" {
		t.Error("status must be accepted")
	}
	tx = begin(t, env, "nms_api")
	if _, err := st.Accept(ctx, tx, it.ID, "again", target); !errors.Is(err, devices.ErrNotPending) {
		t.Errorf("second accept: %v", err)
	}
	_ = tx.Rollback(ctx)

	/* A re-discovery of an accepted address keeps its status. */
	tx = begin(t, env, "nms_poller")
	if err := pst.UpsertDiscovered(ctx, tx, s, addr, "x", "y", "z"); err != nil {
		t.Fatal(err)
	}
	_ = tx.Commit(ctx)
	if find(addr).Status != "accepted" {
		t.Error("upsert must not reset status")
	}

	it2 := find(addr2)
	tx = begin(t, env, "nms_api")
	if err := st.Ignore(ctx, tx, it2.ID); err != nil {
		t.Fatal(err)
	}
	_ = tx.Commit(ctx)
	if find(addr2).Status != "ignored" {
		t.Error("status must be ignored")
	}
	pend, _ := st.Inbox(ctx, devices.InboxFilter{All: true, Status: "pending"})
	for _, p := range pend {
		if p.Address == addr || p.Address == addr2 {
			t.Error("status filter leaks non-pending rows")
		}
	}
}

func TestPollerGrants(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	st := devices.NewStore(env.Pool("nms_api"))
	g := newGroup(t, env)
	id := create(t, env, st, devices.NewDevice{Name: "a", Address: nextAddr(), GroupID: g})
	tx := begin(t, env, "nms_api")
	if err := st.PutProfile(ctx, tx, devices.Owner{Kind: "device", ID: id}, "snmp2c", []byte("c"), 1); err != nil {
		t.Fatal(err)
	}
	_ = tx.Commit(ctx)
	newScan(t, env, st, g)

	p := env.Pool("nms_poller")
	for _, q := range []string{
		`SELECT * FROM core.device`,
		`SELECT ciphertext FROM core.access_profile`,
		`UPDATE core.access_profile SET status = 'ok'`,
		`UPDATE core.device SET model = 'm', firmware = 'f', sys_object_id = '1', driver = 'eltex'`,
		`UPDATE core.discovery_scan SET last_run_at = now()`,
	} {
		if _, err := p.Exec(ctx, q); err != nil {
			t.Errorf("%s: %v", q, err)
		}
	}
	for _, q := range []string{
		`INSERT INTO core.device (name, address, group_id) VALUES ('x', '10.254.0.1', 1)`,
		`UPDATE core.access_profile SET ciphertext = '\x00'`,
		`UPDATE core.device SET name = 'n'`,
		`DELETE FROM core.device`,
		`INSERT INTO core.discovery_scan (cidr, group_id) VALUES ('10.0.0.0/8', 1)`,
		`UPDATE core.discovery_scan SET enabled = false`,
	} {
		if _, err := p.Exec(ctx, q); code(err) != "42501" {
			t.Errorf("%s: got %v, want 42501", q, err)
		}
	}
	if _, err := env.Pool("nms_api").Exec(ctx, `CREATE TABLE core.x (a int)`); code(err) != "42501" {
		t.Errorf("nms_api CREATE: %v", err)
	}
}
