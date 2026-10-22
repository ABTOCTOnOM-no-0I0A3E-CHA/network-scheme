package devices_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/testdb"
)

/*
TestScanIDGuard: a scan id always names the same scan for its sealed
profile. As nms_api: explicit ids, id changes and re-use of a deleted id are
refused, and deleting a scan removes its profile.
*/
func TestScanIDGuard(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	api := env.Pool("nms_api")
	st := devices.NewStore(api)
	g := newGroup(t, env)
	var id int64
	if err := pgx.BeginFunc(ctx, api, func(tx pgx.Tx) (err error) {
		if id, err = st.CreateScan(ctx, tx, devices.NewScan{CIDR: netip.MustParsePrefix("10.240.0.0/24"), GroupID: g, Enabled: true}); err != nil {
			return err
		}
		return st.PutProfile(ctx, tx, devices.Owner{Kind: devices.OwnerScan, ID: id}, "snmp2c", []byte("sealed"), 1)
	}); err != nil {
		t.Fatal(err)
	}
	var poller string
	if err := api.QueryRow(ctx, `SELECT poller_id FROM core.discovery_scan WHERE id = $1`, id).Scan(&poller); err != nil || poller != "local" {
		t.Fatalf("poller_id = %q, %v", poller, err)
	}
	insert := func(explicit int64) error {
		_, err := api.Exec(ctx, `INSERT INTO core.discovery_scan (id, cidr, group_id) OVERRIDING SYSTEM VALUE
			VALUES ($1, '10.241.0.0/24', $2)`, explicit, g)
		return err
	}
	if err := insert(id + 1_000_000); code(err) != "42501" {
		t.Fatalf("explicit unused id: want 42501, got %v", err)
	}
	if _, err := api.Exec(ctx, `UPDATE core.discovery_scan SET id = id + 1_000_000 WHERE id = $1`, id); err == nil {
		t.Fatal("id change accepted")
	}
	/* One session: currval equals the deleted id, so only the tombstone refuses it. */
	conn, err := api.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	var fresh int64
	if err := conn.QueryRow(ctx, `INSERT INTO core.discovery_scan (cidr, group_id) VALUES ('10.242.0.0/24', $1) RETURNING id`, g).Scan(&fresh); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO core.access_profile (owner_kind, owner_id, kind, ciphertext, key_version)
		VALUES ('scan', $1, 'snmp3', 'sealed', 1)`, fresh); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `DELETE FROM core.discovery_scan WHERE id = $1`, fresh); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := env.Pool("postgres").QueryRow(ctx, `SELECT count(*) FROM core.access_profile WHERE owner_kind = 'scan' AND owner_id = $1`, fresh).Scan(&n); err != nil || n != 0 {
		t.Fatalf("scan profiles after delete: %d, %v", n, err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO core.discovery_scan (id, cidr, group_id) OVERRIDING SYSTEM VALUE
		VALUES ($1, '10.242.0.0/24', $2)`, fresh, g); code(err) != "42501" {
		t.Fatalf("re-create deleted id: want 42501, got %v", err)
	}
	/* Deleting one scan leaves the profile of another. */
	if err := env.Pool("postgres").QueryRow(ctx, `SELECT count(*) FROM core.access_profile WHERE owner_kind = 'scan' AND owner_id = $1`, id).Scan(&n); err != nil || n != 1 {
		t.Fatalf("profile of the other scan: %d, %v", n, err)
	}
}

/* TestDiscoveredTextBounded: device-derived text above 1024 characters is refused by the schema. */
func TestDiscoveredTextBounded(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	g := newGroup(t, env)
	var scan int64
	if err := env.Pool("nms_api").QueryRow(ctx, `INSERT INTO core.discovery_scan (cidr, group_id) VALUES ('10.243.0.0/24', $1) RETURNING id`, g).Scan(&scan); err != nil {
		t.Fatal(err)
	}
	poller := env.Pool("nms_poller")
	for i, col := range []string{"sys_object_id", "sys_descr", "sys_name"} {
		_, err := poller.Exec(ctx, `INSERT INTO core.discovered (scan_id, address, `+col+`) VALUES ($1, $2, $3)`,
			scan, netip.AddrFrom4([4]byte{10, 243, 0, byte(i + 1)}), strings.Repeat("ж", 1025))
		if code(err) != "23514" {
			t.Errorf("%s of 1025 characters: want 23514, got %v", col, err)
		}
	}
	if _, err := poller.Exec(ctx, `INSERT INTO core.discovered (scan_id, address, sys_descr) VALUES ($1, '10.243.0.9', $2)`,
		scan, strings.Repeat("ж", 1024)); err != nil {
		t.Fatalf("1024 characters: %v", err)
	}
}

/* TestUpsertDiscoveredSkipsKnownDevice: an address already used by a device never enters the inbox. */
func TestUpsertDiscoveredSkipsKnownDevice(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	st := devices.NewStore(env.Pool("nms_poller"))
	g := newGroup(t, env)
	known := nextAddr()
	create(t, env, devices.NewStore(env.Pool("nms_api")), devices.NewDevice{Name: "known", Address: known, SNMPPort: 1161, GroupID: g})
	var scan int64
	if err := env.Pool("nms_api").QueryRow(ctx, `INSERT INTO core.discovery_scan (cidr, group_id) VALUES ('10.244.0.0/24', $1) RETURNING id`, g).Scan(&scan); err != nil {
		t.Fatal(err)
	}
	fresh := nextAddr()
	for _, a := range []netip.Addr{known, fresh} {
		if err := pgx.BeginFunc(ctx, env.Pool("nms_poller"), func(tx pgx.Tx) error {
			return st.UpsertDiscovered(ctx, tx, scan, a, "1.3.6.1.4.1.1", "descr", "name")
		}); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := env.Pool("postgres").QueryRow(ctx, `SELECT count(*) FROM core.discovered WHERE address = $1`, known).Scan(&n); err != nil || n != 0 {
		t.Fatalf("known device in the inbox: %d, %v", n, err)
	}
	if err := env.Pool("postgres").QueryRow(ctx, `SELECT count(*) FROM core.discovered WHERE address = $1`, fresh).Scan(&n); err != nil || n != 1 {
		t.Fatalf("fresh address: %d, %v", n, err)
	}
}
