package inventory_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/inventory"
	"github.com/beekamai/network-scheme/internal/rbac"
	"github.com/beekamai/network-scheme/internal/testdb"
)

func TestMain(m *testing.M) { testdb.Main(m) }

var seq atomic.Int64

/* newDevice creates a device assigned to pollerID ("" = default) in a new group. */
func newDevice(t *testing.T, env *testdb.Env, pollerID string) int64 {
	t.Helper()
	ctx := context.Background()
	pool := env.Pool("nms_api")
	var id int64
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		n := seq.Add(1)
		g, err := rbac.NewStore(pool).CreateGroup(ctx, tx, nil, fmt.Sprintf("inv%d", n))
		if err != nil {
			return err
		}
		id, err = devices.NewStore(pool).Create(ctx, tx, devices.NewDevice{Name: fmt.Sprintf("d%d", n),
			Address: netip.AddrFrom4([4]byte{198, 18, byte(n >> 8), byte(n)}), GroupID: g, PollerID: pollerID})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func allComplete() map[drivers.Table]bool {
	m := map[drivers.Table]bool{}
	for _, t := range []drivers.Table{drivers.TableInterfaces, drivers.TableARP, drivers.TableMAC, drivers.TableVLANs,
		drivers.TableLLDP, drivers.TableEntities, drivers.TableRoutes} {
		m[t] = true
	}
	return m
}

/* fullInventory has one row per table whose keys and values derive from k. */
func fullInventory(k int) drivers.Inventory {
	inv := drivers.NewInventory()
	inv.Complete = allComplete()
	b := byte(k)
	mac := fmt.Sprintf("00:11:22:33:44:%02x", b)
	inv.Interfaces = []drivers.Interface{{Index: k, Name: fmt.Sprintf("ge%d", k), Alias: "<b>up</b>", SpeedBps: 1e9, OperUp: true}}
	inv.ARP = []drivers.ARPEntry{{IP: netip.AddrFrom4([4]byte{10, 0, 0, b}), MAC: mac, IfIndex: k}}
	inv.MAC = []drivers.MACEntry{{MAC: mac, VLAN: 10, IfIndex: k}}
	inv.VLANs = []drivers.VLAN{{ID: k, Name: fmt.Sprintf("v%d", k)}}
	inv.LLDP = []drivers.LLDPNeighbor{{LocalIfIndex: k, LocalPortResolved: true, ChassisID: mac, PortID: "gi1/0/1", PortDescr: "uplink", SysName: "sw"}}
	inv.Entities = []drivers.Entity{{Index: k, Class: "chassis", Name: "c", Model: "MES2424", Serial: "S"}}
	inv.Routes = []drivers.Route{{Dest: netip.PrefixFrom(netip.AddrFrom4([4]byte{10, b, 0, 0}), 16), IfIndex: k, Proto: "local"}}
	return inv
}

/* merge appends the rows of b to a (completeness of a is kept). */
func merge(a, b drivers.Inventory) drivers.Inventory {
	a.Interfaces = append(a.Interfaces, b.Interfaces...)
	a.ARP = append(a.ARP, b.ARP...)
	a.MAC = append(a.MAC, b.MAC...)
	a.VLANs = append(a.VLANs, b.VLANs...)
	a.LLDP = append(a.LLDP, b.LLDP...)
	a.Entities = append(a.Entities, b.Entities...)
	a.Routes = append(a.Routes, b.Routes...)
	return a
}

var counted = map[string]string{
	"interface": "if_index", "arp_entry": "if_index", "mac_entry": "if_index", "vlan": "vlan_id",
	"lldp_neighbor": "local_if_index", "entity": "ent_index", "route": "if_index",
}

/* keys returns the sorted key column (an if_index-like value from fullInventory) of every row per table. */
func keys(t *testing.T, env *testdb.Env, deviceID int64) map[string][]int {
	t.Helper()
	out := map[string][]int{}
	for tbl, col := range counted {
		rows, err := env.Pool("postgres").Query(context.Background(),
			`SELECT `+col+` FROM inventory.`+tbl+` WHERE device_id = $1 ORDER BY 1`, deviceID)
		if err != nil {
			t.Fatal(err)
		}
		ks, err := pgx.CollectRows(rows, pgx.RowTo[int])
		if err != nil {
			t.Fatal(err)
		}
		out[tbl] = ks
	}
	return out
}

func wantKeys(t *testing.T, got map[string][]int, tbl string, want ...int) {
	t.Helper()
	if fmt.Sprint(got[tbl]) != fmt.Sprint(want) {
		t.Errorf("%s keys = %v, want %v", tbl, got[tbl], want)
	}
}

func TestApplyReplacesCompleteTables(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	st := inventory.NewStore(env.Pool("nms_poller"))
	dev := newDevice(t, env, "")
	t0 := time.Now().UTC().Truncate(time.Second)

	/* A duplicate row in one poll must not break the upsert. */
	first := merge(merge(fullInventory(1), fullInventory(2)), fullInventory(2))
	if err := st.Apply(ctx, dev, first, t0); err != nil {
		t.Fatal(err)
	}
	for tbl := range counted {
		wantKeys(t, keys(t, env, dev), tbl, 1, 2)
	}

	second := merge(fullInventory(2), fullInventory(3))
	if err := st.Apply(ctx, dev, second, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	got := keys(t, env, dev)
	for tbl := range counted {
		wantKeys(t, got, tbl, 2, 3)
	}
	var seen time.Time
	if err := env.Pool("postgres").QueryRow(ctx, `SELECT seen_at FROM inventory.interface WHERE device_id = $1 AND if_index = 2`, dev).Scan(&seen); err != nil {
		t.Fatal(err)
	}
	if !seen.Equal(t0.Add(time.Minute)) {
		t.Errorf("seen_at = %v, want %v", seen, t0.Add(time.Minute))
	}

	/* An empty but complete walk empties the table. */
	empty := drivers.NewInventory()
	empty.Complete[drivers.TableVLANs] = true
	if err := st.Apply(ctx, dev, empty, t0.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	got = keys(t, env, dev)
	wantKeys(t, got, "vlan")
	wantKeys(t, got, "interface", 2, 3)
}

func TestApplyKeepsIncompleteTables(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	st := inventory.NewStore(env.Pool("nms_poller"))
	dev := newDevice(t, env, "")
	t0 := time.Now().UTC().Truncate(time.Second)
	if err := st.Apply(ctx, dev, merge(fullInventory(1), fullInventory(2)), t0); err != nil {
		t.Fatal(err)
	}
	/* The FDB walk timed out after one row: MAC is not complete, the rest is. */
	partial := fullInventory(3)
	partial.Complete[drivers.TableMAC] = false
	partial.Errors[drivers.TableMAC] = context.DeadlineExceeded
	if err := st.Apply(ctx, dev, partial, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	got := keys(t, env, dev)
	wantKeys(t, got, "mac_entry", 1, 2, 3)
	wantKeys(t, got, "interface", 3)
	wantKeys(t, got, "route", 3)

	/* A table absent from Complete counts as incomplete. */
	none := drivers.NewInventory()
	if err := st.Apply(ctx, dev, none, t0.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	wantKeys(t, keys(t, env, dev), "mac_entry", 1, 2, 3)
}

func TestApplyUnknownDevice(t *testing.T) {
	env := testdb.New(t)
	st := inventory.NewStore(env.Pool("nms_poller"))
	if err := st.Apply(context.Background(), 1<<40, fullInventory(1), time.Now()); !errors.Is(err, inventory.ErrNoDevice) {
		t.Fatalf("Apply on a missing device = %v, want ErrNoDevice", err)
	}
}

func TestStatusSinceOnlyOnChange(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	st := inventory.NewStore(env.Pool("nms_poller"))
	dev := newDevice(t, env, "")
	t0 := time.Now().UTC().Truncate(time.Second)

	read := func() (state string, since, last time.Time, errText string) {
		t.Helper()
		if err := env.Pool("postgres").QueryRow(ctx, `SELECT state, since, last_poll_at, last_error
			FROM inventory.device_status WHERE device_id = $1`, dev).Scan(&state, &since, &last, &errText); err != nil {
			t.Fatal(err)
		}
		return
	}
	steps := []struct {
		state     string
		at        time.Time
		wantSince time.Time
	}{
		{"up", t0, t0},
		{"up", t0.Add(30 * time.Second), t0},
		{"down", t0.Add(60 * time.Second), t0.Add(60 * time.Second)},
		{"down", t0.Add(90 * time.Second), t0.Add(60 * time.Second)},
		{"partial", t0.Add(120 * time.Second), t0.Add(120 * time.Second)},
	}
	for _, s := range steps {
		if err := st.SetStatus(ctx, dev, s.state, s.at, "timeout\x00\x1b[31m"); err != nil {
			t.Fatal(err)
		}
		state, since, last, errText := read()
		if state != s.state || !since.Equal(s.wantSince) || !last.Equal(s.at) || errText != "timeout[31m" {
			t.Errorf("after %s at %v: state=%s since=%v last=%v err=%q", s.state, s.at, state, since, last, errText)
		}
	}
	/* An older status (reordered write) changes nothing. */
	if err := st.SetStatus(ctx, dev, "up", t0.Add(10*time.Second), ""); err != nil {
		t.Fatal(err)
	}
	if state, _, _, _ := read(); state != "partial" {
		t.Errorf("stale status overwrote: state=%s", state)
	}
	if err := st.SetStatus(ctx, dev, "sideways", t0.Add(time.Hour), ""); !errors.Is(err, inventory.ErrInvalid) {
		t.Errorf("bad state = %v, want ErrInvalid", err)
	}
}

func TestUnknownWhenHeartbeatStale(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	st := inventory.NewStore(env.Pool("nms_poller"))
	api := inventory.NewStore(env.Pool("nms_api"))
	poller := fmt.Sprintf("p%d", seq.Add(1))
	dev := newDevice(t, env, poller)
	fresh := newDevice(t, env, poller) /* no status yet */
	now := time.Now().UTC().Truncate(time.Second)

	state := func(id int64) inventory.DeviceState {
		t.Helper()
		m, err := api.States(ctx, []int64{dev, fresh})
		if err != nil {
			t.Fatal(err)
		}
		return m[id]
	}
	if err := st.SetStatus(ctx, dev, "up", now.Add(-time.Minute), ""); err != nil {
		t.Fatal(err)
	}
	/* No heartbeat at all: unknown. */
	if s := state(dev); s.State != "unknown" {
		t.Errorf("without heartbeat: %+v", s)
	}
	if err := st.Heartbeat(ctx, poller, now); err != nil {
		t.Fatal(err)
	}
	if s := state(dev); s.State != "up" || s.Since == nil || !s.Since.Equal(now.Add(-time.Minute)) {
		t.Errorf("fresh heartbeat: %+v", s)
	}
	if s := state(fresh); s.State != "unknown" || s.Since != nil {
		t.Errorf("device without status: %+v", s)
	}
	/* The heartbeat never moves backwards. */
	if err := st.Heartbeat(ctx, poller, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if s := state(dev); s.State != "up" {
		t.Errorf("older heartbeat regressed state: %+v", s)
	}
	/* 91 s of silence: unknown, since when the heartbeat went stale. */
	stale := now.Add(-91 * time.Second)
	if _, err := env.Pool("postgres").Exec(ctx, `UPDATE inventory.poller_heartbeat SET at = $2 WHERE poller_id = $1`, poller, stale); err != nil {
		t.Fatal(err)
	}
	if s := state(dev); s.State != "unknown" || s.Since == nil || !s.Since.Equal(stale.Add(90*time.Second)) {
		t.Errorf("stale heartbeat: %+v", s)
	}
	/* A heartbeat from the future is capped at the database clock. */
	if err := st.Heartbeat(ctx, poller, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	var at time.Time
	if err := env.Pool("postgres").QueryRow(ctx, `SELECT at FROM inventory.poller_heartbeat WHERE poller_id = $1`, poller).Scan(&at); err != nil {
		t.Fatal(err)
	}
	if at.After(time.Now().Add(time.Minute)) {
		t.Errorf("future heartbeat stored as %v", at)
	}
	/* A status written by another poller than the device's does not count. */
	other := newDevice(t, env, "")
	if err := st.SetStatus(ctx, other, "up", now, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := env.Pool("postgres").Exec(ctx, `UPDATE core.device SET poller_id = $2 WHERE id = $1`, other, poller); err != nil {
		t.Fatal(err)
	}
	m, err := api.States(ctx, []int64{other})
	if err != nil {
		t.Fatal(err)
	}
	if m[other].State != "unknown" {
		t.Errorf("status of the previous poller shown: %+v", m[other])
	}
}

func wantDenied(t *testing.T, what string, err error) {
	t.Helper()
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "42501" {
		t.Errorf("%s: err = %v, want 42501", what, err)
	}
}

/* updateCol is a writable-looking column of each table for the UPDATE probe. */
var updateCol = map[string]string{
	"interface": "seen_at = now()", "arp_entry": "seen_at = now()", "mac_entry": "seen_at = now()",
	"vlan": "seen_at = now()", "lldp_neighbor": "seen_at = now()", "entity": "seen_at = now()",
	"route": "seen_at = now()", "device_status": "state = 'up'", "poller_heartbeat": "at = now()",
	"profile_seen": "created_at = now()",
}

func TestApiCannotWriteInventory(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	dev := newDevice(t, env, "")
	if err := inventory.NewStore(env.Pool("nms_poller")).Apply(ctx, dev, fullInventory(1), time.Now()); err != nil {
		t.Fatal(err)
	}
	api := env.Pool("nms_api")
	inserts := map[string]string{
		"interface":        `INSERT INTO inventory.interface VALUES ($1, 99, 'x', '', 0, true, now())`,
		"arp_entry":        `INSERT INTO inventory.arp_entry VALUES ($1, '10.9.9.9', '00:00:00:00:00:01', 1, now())`,
		"mac_entry":        `INSERT INTO inventory.mac_entry VALUES ($1, '00:00:00:00:00:01', 1, 1, now())`,
		"vlan":             `INSERT INTO inventory.vlan VALUES ($1, 99, 'x', now())`,
		"lldp_neighbor":    `INSERT INTO inventory.lldp_neighbor VALUES ($1, 1, 'c', 'p', 'n', NULL, now())`,
		"entity":           `INSERT INTO inventory.entity VALUES ($1, 99, 'x', 'x', 'x', 'x', now())`,
		"route":            `INSERT INTO inventory.route VALUES ($1, '10.99.0.0/16', NULL, 1, 'x', now())`,
		"device_status":    `INSERT INTO inventory.device_status VALUES ($1, 'up', now(), now(), 'local', '')`,
		"poller_heartbeat": `INSERT INTO inventory.poller_heartbeat VALUES ('hb' || $1::bigint, now())`,
		"profile_seen":     `INSERT INTO inventory.profile_seen VALUES ('device', $1, 'snmp3', now())`,
	}
	for tbl, q := range inserts {
		_, err := api.Exec(ctx, q, dev)
		wantDenied(t, "api INSERT "+tbl, err)
		_, err = api.Exec(ctx, `UPDATE inventory.`+tbl+` SET `+updateCol[tbl]+` WHERE true`)
		wantDenied(t, "api UPDATE "+tbl, err)
		_, err = api.Exec(ctx, `DELETE FROM inventory.`+tbl)
		wantDenied(t, "api DELETE "+tbl, err)
	}
	/*
		The API reads states through the view; raw status and credential times stay
		hidden. It may read the heartbeat (poller id and time; the problem engine
		and the status page need it) but not write it (checked above).
	*/
	for _, tbl := range []string{"device_status", "profile_seen"} {
		_, err := api.Exec(ctx, `SELECT * FROM inventory.`+tbl)
		wantDenied(t, "api SELECT "+tbl, err)
	}
	/* Nobody but the poller writes: the host CLI neither. */
	_, err := env.Pool("nms_cli").Exec(ctx, inserts["interface"], dev)
	wantDenied(t, "cli INSERT interface", err)
	/* The poller never forgets an accepted credential time. */
	_, err = env.Pool("nms_poller").Exec(ctx, `DELETE FROM inventory.profile_seen`)
	wantDenied(t, "poller DELETE profile_seen", err)
}

func TestInventoryRemovedWithDevice(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	st := inventory.NewStore(env.Pool("nms_poller"))
	dev := newDevice(t, env, "")
	if err := st.Apply(ctx, dev, fullInventory(1), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := st.SetStatus(ctx, dev, "up", time.Now(), ""); err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(ctx, env.Pool("nms_api"), func(tx pgx.Tx) error {
		return devices.NewStore(env.Pool("nms_api")).Delete(ctx, tx, dev)
	}); err != nil {
		t.Fatal(err)
	}
	for tbl, n := range keys(t, env, dev) {
		if len(n) != 0 {
			t.Errorf("%s keeps rows of a deleted device", tbl)
		}
	}
	/* Status of a deleted device is silently dropped. */
	if err := st.SetStatus(ctx, dev, "down", time.Now(), ""); err != nil {
		t.Errorf("SetStatus on deleted device: %v", err)
	}
}

func TestProfileSeenMonotonic(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	st := inventory.NewStore(env.Pool("nms_poller"))
	owner := devices.Owner{Kind: devices.OwnerScan, ID: seq.Add(1)}
	at, err := st.ProfileSeen(ctx, owner, "snmp3")
	if err != nil || !at.IsZero() {
		t.Fatalf("unseen = %v, %v", at, err)
	}
	t0 := time.Now().UTC().Truncate(time.Second)
	for _, ts := range []time.Time{t0, t0.Add(-time.Hour), t0.Add(-time.Second)} {
		if err := st.MarkProfileSeen(ctx, owner, "snmp3", ts); err != nil {
			t.Fatal(err)
		}
	}
	if at, err := st.ProfileSeen(ctx, owner, "snmp3"); err != nil || !at.Equal(t0) {
		t.Fatalf("seen = %v, %v; want %v", at, err, t0)
	}
	if at, _ := st.ProfileSeen(ctx, owner, "snmp2c"); !at.IsZero() {
		t.Errorf("other kind seen = %v", at)
	}
}

func TestListPages(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	dev := newDevice(t, env, "")
	inv := drivers.NewInventory()
	for i := 1; i <= 5; i++ {
		inv = merge(inv, fullInventory(i))
	}
	at := time.Now().UTC().Truncate(time.Second)
	if err := inventory.NewStore(env.Pool("nms_poller")).Apply(ctx, dev, inv, at); err != nil {
		t.Fatal(err)
	}
	api := inventory.NewStore(env.Pool("nms_api"))
	p1, err := api.Interfaces(ctx, dev, inventory.Page{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	p3, err := api.Interfaces(ctx, dev, inventory.Page{Limit: 2, Offset: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(p1) != 2 || p1[0].IfIndex != 1 || p1[1].IfIndex != 2 || len(p3) != 1 || p3[0].IfIndex != 5 {
		t.Fatalf("pages = %+v / %+v", p1, p3)
	}
	if p1[0].Alias != "<b>up</b>" || p1[0].SpeedBps != 1e9 || !p1[0].OperUp || !p1[0].SeenAt.Equal(at) {
		t.Errorf("row = %+v", p1[0])
	}
	arp, err := api.ARP(ctx, dev, inventory.Page{Limit: 10})
	if err != nil || len(arp) != 5 || arp[0].MAC != "00:11:22:33:44:01" || arp[0].IP != "10.0.0.1" {
		t.Errorf("arp = %+v, %v", arp, err)
	}
	mac, err := api.MAC(ctx, dev, inventory.Page{Limit: 10})
	if err != nil || len(mac) != 5 || mac[0].VLAN != 10 {
		t.Errorf("mac = %+v, %v", mac, err)
	}
	vl, err := api.VLANs(ctx, dev, inventory.Page{Limit: 10})
	if err != nil || len(vl) != 5 || vl[4].VLANID != 5 {
		t.Errorf("vlans = %+v, %v", vl, err)
	}
	ll, err := api.LLDP(ctx, dev, inventory.Page{Limit: 10})
	if err != nil || len(ll) != 5 || ll[0].MgmtAddr != nil || ll[0].PortID != "gi1/0/1" {
		t.Errorf("lldp = %+v, %v", ll, err)
	}
	var descr string
	var resolved int
	if err := env.Pool("postgres").QueryRow(ctx, `SELECT min(remote_port_descr), count(*) FILTER (WHERE local_port_resolved) FROM inventory.lldp_neighbor WHERE device_id = $1`, dev).Scan(&descr, &resolved); err != nil || descr != "uplink" || resolved != 5 {
		t.Errorf("lldp port resolution = %q, %d, %v", descr, resolved, err)
	}
	en, err := api.Entities(ctx, dev, inventory.Page{Limit: 10})
	if err != nil || len(en) != 5 || en[0].Model != "MES2424" {
		t.Errorf("entities = %+v, %v", en, err)
	}
	rt, err := api.Routes(ctx, dev, inventory.Page{Limit: 10})
	if err != nil || len(rt) != 5 || rt[0].Dest != "10.1.0.0/16" || rt[0].NextHop != nil {
		t.Errorf("routes = %+v, %v", rt, err)
	}
}

func TestApplyStoresPortKind(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	st := inventory.NewStore(env.Pool("nms_poller"))
	dev := newDevice(t, env, "")
	inv := drivers.NewInventory()
	inv.Complete = map[drivers.Table]bool{drivers.TableInterfaces: true}
	inv.Interfaces = []drivers.Interface{
		{Index: 1, Name: "gi1", PortKind: drivers.PortRJ45},
		{Index: 2, Name: "te1", PortKind: drivers.PortSFP},
		{Index: 3, Name: "vlan1"},
		{Index: 4, Name: "x", PortKind: "bogus"},
	}
	for range 2 { /* the second poll updates existing rows */
		if err := st.Apply(ctx, dev, inv, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := env.Pool("postgres").Query(ctx, `SELECT port_kind FROM inventory.interface WHERE device_id = $1 ORDER BY if_index`, dev)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"rj45", "sfp", "other", "other"}; !slices.Equal(got, want) {
		t.Fatalf("port_kind = %v, want %v", got, want)
	}
}
