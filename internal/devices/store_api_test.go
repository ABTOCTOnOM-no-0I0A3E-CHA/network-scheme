package devices_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/testdb"
)

/*
TestConcurrentFirstPutProfile: two transactions setting the same first
profile of an owner serialize on the owner row instead of one failing with a
unique violation.
*/
func TestConcurrentFirstPutProfile(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	st := devices.NewStore(env.Pool("nms_api"))
	id := create(t, env, st, devices.NewDevice{Name: "c", Address: nextAddr(), GroupID: newGroup(t, env)})
	owner := devices.Owner{Kind: devices.OwnerDevice, ID: id}

	tx1 := begin(t, env, "nms_api")
	if err := st.PutProfile(ctx, tx1, owner, "snmp3", []byte{1}, 1); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		tx2, err := env.Pool("nms_api").Begin(ctx)
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = tx2.Rollback(ctx) }()
		if err := st.PutProfile(ctx, tx2, owner, "snmp3", []byte{2}, 1); err != nil {
			done <- err
			return
		}
		done <- tx2.Commit(ctx)
	}()
	time.Sleep(300 * time.Millisecond) /* let the second put reach the database and wait */
	if err := tx1.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("second concurrent put: %v", err)
	}
	ps, err := st.Profiles(ctx, owner)
	if err != nil || len(ps) != 1 {
		t.Fatalf("profiles = %+v, %v", ps, err)
	}
}

func TestRefreshInsecure(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	st := devices.NewStore(env.Pool("nms_api"))
	id := create(t, env, st, devices.NewDevice{Name: "i", Address: nextAddr(), GroupID: newGroup(t, env)})
	owner := devices.Owner{Kind: devices.OwnerDevice, ID: id}
	step := func(fn func(tx pgx.Tx) error, want bool) {
		t.Helper()
		tx := begin(t, env, "nms_api")
		if err := fn(tx); err != nil {
			t.Fatal(err)
		}
		if err := st.RefreshInsecure(ctx, tx, id); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		d, err := st.Get(ctx, id)
		if err != nil || d.InsecureProtocols != want {
			t.Fatalf("insecure = %v (%v), want %v", d.InsecureProtocols, err, want)
		}
	}
	step(func(tx pgx.Tx) error { return st.PutProfile(ctx, tx, owner, "snmp3", []byte{1}, 1) }, false)
	step(func(tx pgx.Tx) error { return st.PutProfile(ctx, tx, owner, "telnet_read", []byte{1}, 1) }, true)
	step(func(tx pgx.Tx) error { return st.DeleteProfile(ctx, tx, owner, "telnet_read") }, false)
}

func TestLockDevice(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	st := devices.NewStore(env.Pool("nms_api"))
	id := create(t, env, st, devices.NewDevice{Name: "l", Address: nextAddr(), GroupID: newGroup(t, env)})
	tx := begin(t, env, "nms_api")
	d, err := st.Lock(ctx, tx, id)
	if err != nil || d.ID != id || d.Name != "l" {
		t.Fatalf("lock = %+v, %v", d, err)
	}
	if _, err := st.Lock(ctx, tx, id+1_000_000); !errors.Is(err, devices.ErrNotFound) {
		t.Fatalf("lock missing: %v", err)
	}
}

func TestScanGetListUpdate(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	st := devices.NewStore(env.Pool("nms_api"))
	g1, g2 := newGroup(t, env), newGroup(t, env)
	s1, s2 := newScan(t, env, st, g1), newScan(t, env, st, g2)

	if got, err := st.ListScans(ctx, devices.Filter{}); err != nil || len(got) != 0 {
		t.Fatalf("zero filter: %+v, %v", got, err)
	}
	got, err := st.ListScans(ctx, devices.Filter{GroupIDs: []int64{g1}})
	if err != nil || len(got) != 1 || got[0].ID != s1 {
		t.Fatalf("filtered: %+v, %v", got, err)
	}
	all, err := st.ListScans(ctx, devices.Filter{All: true})
	if err != nil || len(all) < 2 {
		t.Fatalf("all: %+v, %v", all, err)
	}

	cidr := netip.MustParsePrefix("192.0.2.0/28")
	off, iv := false, 3600
	tx := begin(t, env, "nms_api")
	if err := st.UpdateScan(ctx, tx, s2, devices.ScanPatch{CIDR: &cidr, GroupID: &g1, Enabled: &off, IntervalS: &iv}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	sc, err := st.GetScan(ctx, s2)
	if err != nil || sc.CIDR != cidr || sc.GroupID != g1 || sc.Enabled || sc.IntervalS != 3600 {
		t.Fatalf("updated scan = %+v, %v", sc, err)
	}
	if _, err := st.GetScan(ctx, s2+1_000_000); !errors.Is(err, devices.ErrNotFound) {
		t.Fatalf("missing scan: %v", err)
	}
	tx = begin(t, env, "nms_api")
	if err := st.UpdateScan(ctx, tx, s2+1_000_000, devices.ScanPatch{Enabled: &off}); !errors.Is(err, devices.ErrNotFound) {
		t.Fatalf("update missing scan: %v", err)
	}
}

func TestGetDiscovered(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	st := devices.NewStore(env.Pool("nms_api"))
	pst := devices.NewStore(env.Pool("nms_poller"))
	g := newGroup(t, env)
	s := newScan(t, env, st, g)
	addr := nextAddr()
	tx := begin(t, env, "nms_poller")
	if err := pst.UpsertDiscovered(ctx, tx, s, addr, "1.3.6.1", "d", "n"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	items, err := st.Inbox(ctx, devices.InboxFilter{GroupIDs: []int64{g}})
	if err != nil || len(items) != 1 {
		t.Fatalf("inbox: %+v, %v", items, err)
	}
	d, err := st.GetDiscovered(ctx, items[0].ID)
	if err != nil || d.Address != addr || d.GroupID != g || d.ScanID != s {
		t.Fatalf("get discovered = %+v, %v", d, err)
	}
	if _, err := st.GetDiscovered(ctx, items[0].ID+1_000_000); !errors.Is(err, devices.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
}
