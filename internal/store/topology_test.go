package store_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/internal/testdb"
)

func topoDevices(t *testing.T, api *pgxpool.Pool, n int, base string) []int64 {
	t.Helper()
	ctx := context.Background()
	var g int64
	if err := api.QueryRow(ctx, `INSERT INTO core.device_group (name) VALUES ($1) RETURNING id`, base).Scan(&g); err != nil {
		t.Fatal(err)
	}
	ids := make([]int64, n)
	for i := range ids {
		if err := api.QueryRow(ctx, `INSERT INTO core.device (name, address, group_id) VALUES ('t', $1::inet, $2) RETURNING id`,
			fmt.Sprintf("%s.%d", base, i+1), g).Scan(&ids[i]); err != nil {
			t.Fatal(err)
		}
	}
	return ids
}

func TestLinkConstraints(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	api := env.Pool("nms_api")
	d := topoDevices(t, api, 3, "10.20.0")
	a, b := d[0], d[1]
	ins := func(a int64, ai *int, b int64, bi *int, source string, conf float64, manual bool) error {
		_, err := api.Exec(ctx, `INSERT INTO core.link (a_device_id, a_if_index, b_device_id, b_if_index, source, confidence, manual)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`, a, ai, b, bi, source, conf, manual)
		return err
	}
	one, two, zero := 1, 2, 0
	if err := ins(a, &one, b, &one, "lldp", 1, false); err != nil {
		t.Fatal(err)
	}
	requireCode(t, ins(a, &one, b, &one, "cdp", 0.5, false), "23505", "duplicate identity")
	if err := ins(a, &two, b, &one, "lldp", 1, false); err != nil {
		t.Errorf("other port: %v", err)
	}
	if err := ins(a, nil, b, nil, "mac", 0.4, false); err != nil {
		t.Fatal(err)
	}
	requireCode(t, ins(a, nil, b, nil, "mac", 0.4, false), "23505", "duplicate with NULL ports")
	requireCode(t, ins(b, &one, a, &one, "lldp", 1, false), "23514", "non-canonical order")
	requireCode(t, ins(a, nil, a, nil, "lldp", 1, false), "23514", "self link")
	for name, err := range map[string]error{
		"bad source":            ins(a, nil, d[2], nil, "snmp", 1, false),
		"confidence over 1":     ins(a, nil, d[2], nil, "lldp", 1.01, false),
		"confidence negative":   ins(a, nil, d[2], nil, "lldp", -0.1, false),
		"manual flag mismatch":  ins(a, nil, d[2], nil, "lldp", 1, true),
		"manual source no flag": ins(a, nil, d[2], nil, "manual", 1, false),
		"if index zero":         ins(a, &zero, d[2], nil, "lldp", 1, false),
	} {
		requireCode(t, err, "23514", name)
	}
	if err := ins(a, nil, d[2], nil, "manual", 1, true); err != nil {
		t.Errorf("manual link: %v", err)
	}
	_, err := api.Exec(ctx, `UPDATE core.link SET misses = -1 WHERE a_device_id = $1`, a)
	requireCode(t, err, "23514", "negative misses")
	/* Deleting a device removes its links. */
	if _, err := api.Exec(ctx, `DELETE FROM core.device WHERE id = $1`, d[2]); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := api.QueryRow(ctx, `SELECT count(*) FROM core.link WHERE source = 'manual'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("links after device delete = %d, %v", n, err)
	}
}

func TestTopologyIdsAreGuarded(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	api := env.Pool("nms_api")
	d := topoDevices(t, api, 2, "10.20.1")
	for _, sql := range []string{
		`INSERT INTO core.map_view (id, name, kind) OVERRIDING SYSTEM VALUE VALUES (900001, 'v', 'logical')`,
		`INSERT INTO core.map_background (id, mime, bytes, width, height, sha256, uploaded_by) OVERRIDING SYSTEM VALUE
			VALUES (900001, 'image/png', '\x00', 1, 1, decode(repeat('00', 32), 'hex'), 1)`,
	} {
		_, err := api.Exec(ctx, sql)
		requireDenied2(t, err, sql)
	}
	_, err := api.Exec(ctx, `INSERT INTO core.link (id, a_device_id, b_device_id, source, confidence, manual) OVERRIDING SYSTEM VALUE
		VALUES (900001, $1, $2, 'lldp', 1, false)`, d[0], d[1])
	requireDenied2(t, err, "explicit link id")

	var lid, vid, vid2, aid, bid int64
	if err := api.QueryRow(ctx, `INSERT INTO core.link (a_device_id, b_device_id, source, confidence, manual) VALUES ($1, $2, 'lldp', 1, false) RETURNING id`,
		d[0], d[1]).Scan(&lid); err != nil {
		t.Fatal(err)
	}
	_, err = api.Exec(ctx, `UPDATE core.link SET id = id + 1000 WHERE id = $1`, lid)
	requireCode(t, err, "428C9", "link id change")
	if _, err := api.Exec(ctx, `DELETE FROM core.link WHERE id = $1`, lid); err != nil {
		t.Fatal(err)
	}
	_, err = api.Exec(ctx, `INSERT INTO core.link (id, a_device_id, b_device_id, source, confidence, manual) OVERRIDING SYSTEM VALUE
		VALUES ($3, $1, $2, 'lldp', 1, false)`, d[0], d[1], lid)
	requireDenied2(t, err, "reuse of a deleted link id")

	if err := api.QueryRow(ctx, `INSERT INTO core.map_view (name, kind) VALUES ('v', 'logical') RETURNING id`).Scan(&vid); err != nil {
		t.Fatal(err)
	}
	if err := api.QueryRow(ctx, `INSERT INTO core.map_view (name, kind) VALUES ('v2', 'logical') RETURNING id`).Scan(&vid2); err != nil {
		t.Fatal(err)
	}
	if err := api.QueryRow(ctx, `INSERT INTO core.map_area (view_id, kind, name, x, y, w, h) VALUES ($1, 'room', 'r', 0, 0, 1, 1) RETURNING id`, vid).Scan(&aid); err != nil {
		t.Fatal(err)
	}
	if err := api.QueryRow(ctx, `INSERT INTO core.map_background (mime, bytes, width, height, sha256, uploaded_by)
		VALUES ('image/png', '\x00', 1, 1, decode(repeat('00', 32), 'hex'), 1) RETURNING id`).Scan(&bid); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Exec(ctx, `DELETE FROM core.map_view WHERE id = $1`, vid); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Exec(ctx, `DELETE FROM core.map_background WHERE id = $1`, bid); err != nil {
		t.Fatal(err)
	}
	_, err = api.Exec(ctx, `INSERT INTO core.map_view (id, name, kind) OVERRIDING SYSTEM VALUE VALUES ($1, 'v', 'logical')`, vid)
	requireDenied2(t, err, "reuse of a deleted view id")
	_, err = api.Exec(ctx, `INSERT INTO core.map_area (id, view_id, kind, name, x, y, w, h) OVERRIDING SYSTEM VALUE
		VALUES ($1, $2, 'room', 'r', 0, 0, 1, 1)`, aid, vid2)
	requireDenied2(t, err, "reuse of a deleted area id")
	_, err = api.Exec(ctx, `INSERT INTO core.map_background (id, mime, bytes, width, height, sha256, uploaded_by) OVERRIDING SYSTEM VALUE
		VALUES ($1, 'image/png', '\x00', 1, 1, decode(repeat('00', 32), 'hex'), 1)`, bid)
	requireDenied2(t, err, "reuse of a deleted background id")
}

func TestLinkChangeIsAppendOnly(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	api := env.Pool("nms_api")
	d := topoDevices(t, api, 2, "10.20.2")
	if _, err := api.Exec(ctx, `INSERT INTO core.link_change (link_id, a_device_id, b_device_id, change, source)
		VALUES (NULL, $1, $2, 'appeared', 'lldp')`, d[0], d[1]); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Exec(ctx, `SELECT id, link_id, a_device_id, a_if_index, b_device_id, b_if_index, change, source, at FROM core.link_change`); err != nil {
		t.Fatal(err)
	}
	/* Deleting the devices leaves the history intact. */
	if _, err := api.Exec(ctx, `DELETE FROM core.device WHERE id = ANY($1)`, d); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := api.QueryRow(ctx, `SELECT count(*) FROM core.link_change WHERE a_device_id = $1`, d[0]).Scan(&n); err != nil || n != 1 {
		t.Fatalf("history after device delete = %d, %v", n, err)
	}
	_, err := api.Exec(ctx, `INSERT INTO core.link_change (a_device_id, b_device_id, change, source, at) VALUES (1, 2, 'appeared', 'lldp', '2000-01-01')`)
	requireDenied2(t, err, "explicit at")
	for name, sql := range map[string]string{
		"bad change": `INSERT INTO core.link_change (a_device_id, b_device_id, change, source) VALUES (1, 2, 'moved', 'lldp')`,
		"bad source": `INSERT INTO core.link_change (a_device_id, b_device_id, change, source) VALUES (1, 2, 'appeared', 'x')`,
		"bad order":  `INSERT INTO core.link_change (a_device_id, b_device_id, change, source) VALUES (2, 1, 'appeared', 'lldp')`,
		"if index 0": `INSERT INTO core.link_change (a_device_id, a_if_index, b_device_id, change, source) VALUES (1, 0, 2, 'appeared', 'lldp')`,
	} {
		_, err := api.Exec(ctx, sql)
		requireCode(t, err, "23514", name)
	}
	mods := []string{`UPDATE core.link_change SET change = 'disappeared'`, `DELETE FROM core.link_change`, `TRUNCATE core.link_change`}
	for _, sql := range mods {
		requireDenied(t, "nms_api", sql)
	}
	owner := env.Pool("nms_migrator")
	for _, sql := range mods {
		_, err := owner.Exec(ctx, sql)
		requireCode(t, err, "42501", "owner "+sql)
	}
}

func TestMapAreaTree(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	api := env.Pool("nms_api")
	var v1, v2 int64
	for _, p := range []*int64{&v1, &v2} {
		if err := api.QueryRow(ctx, `INSERT INTO core.map_view (name, kind) VALUES ('v', 'logical') RETURNING id`).Scan(p); err != nil {
			t.Fatal(err)
		}
	}
	add := func(view int64, parent *int64) (int64, error) {
		var id int64
		err := api.QueryRow(ctx, `INSERT INTO core.map_area (view_id, parent_id, kind, name, x, y, w, h) VALUES ($1, $2, 'room', 'a', 0, 0, 10, 10) RETURNING id`,
			view, parent).Scan(&id)
		return id, err
	}
	a, err := add(v1, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := add(v1, &a)
	if err != nil {
		t.Fatal(err)
	}
	c, err := add(v1, &b)
	if err != nil {
		t.Fatal(err)
	}
	_, err = api.Exec(ctx, `UPDATE core.map_area SET parent_id = $1 WHERE id = $2`, c, a)
	requireCode(t, err, "23514", "cycle")
	_, err = api.Exec(ctx, `UPDATE core.map_area SET parent_id = id WHERE id = $1`, a)
	requireCode(t, err, "23514", "self parent")
	_, err = add(v2, &a)
	requireCode(t, err, "23514", "parent in another view")
	_, err = api.Exec(ctx, `UPDATE core.map_area SET view_id = $1 WHERE id = $2`, v2, a)
	requireCode(t, err, "23514", "view change")

	/* Depth 8 is allowed, 9 is not; grafting a deep subtree is checked too. */
	last := c
	for i := 4; i <= 8; i++ {
		if last, err = add(v1, &last); err != nil {
			t.Fatalf("level %d: %v", i, err)
		}
	}
	_, err = add(v1, &last)
	requireCode(t, err, "23514", "9th level")
	x, err := add(v1, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = api.Exec(ctx, `UPDATE core.map_area SET parent_id = $1 WHERE id = $2`, x, a)
	requireCode(t, err, "23514", "graft deep subtree")

	/* Deleting the parent orphans the children. */
	if _, err := api.Exec(ctx, `DELETE FROM core.map_area WHERE id = $1`, b); err != nil {
		t.Fatal(err)
	}
	var p *int64
	if err := api.QueryRow(ctx, `SELECT parent_id FROM core.map_area WHERE id = $1`, c).Scan(&p); err != nil || p != nil {
		t.Fatalf("child parent after delete = %v, %v", p, err)
	}
}

func TestMapGeometryAndBackground(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	api := env.Pool("nms_api")
	d := topoDevices(t, api, 1, "10.20.3")
	var vid int64
	if err := api.QueryRow(ctx, `INSERT INTO core.map_view (name, kind) VALUES ('g', 'plan') RETURNING id`).Scan(&vid); err != nil {
		t.Fatal(err)
	}
	area := func(x, y, w, h string) error {
		_, err := api.Exec(ctx, fmt.Sprintf(`INSERT INTO core.map_area (view_id, kind, name, x, y, w, h) VALUES ($1, 'room', 'a', %s, %s, %s, %s)`, x, y, w, h), vid)
		return err
	}
	if err := area("-1000000", "1000000", "1000000", "0.5"); err != nil {
		t.Errorf("bounds: %v", err)
	}
	for _, c := range [][4]string{
		{"'NaN'", "0", "1", "1"}, {"'Infinity'", "0", "1", "1"}, {"0", "'-Infinity'", "1", "1"},
		{"1000001", "0", "1", "1"}, {"0", "-1000001", "1", "1"},
		{"0", "0", "0", "1"}, {"0", "0", "-1", "1"}, {"0", "0", "1", "0"},
		{"0", "0", "1000001", "1"}, {"0", "0", "1", "'NaN'"},
	} {
		requireCode(t, area(c[0], c[1], c[2], c[3]), "23514", fmt.Sprint(c))
	}
	pos := func(x string) error {
		_, err := api.Exec(ctx, fmt.Sprintf(`INSERT INTO core.map_node_position (view_id, device_id, x, y) VALUES ($1, $2, %s, 0)
			ON CONFLICT (view_id, device_id) DO UPDATE SET x = EXCLUDED.x`, x), vid, d[0])
		return err
	}
	if err := pos("5"); err != nil {
		t.Fatal(err)
	}
	if err := pos("6"); err != nil {
		t.Errorf("upsert: %v", err)
	}
	requireCode(t, pos("'NaN'"), "23514", "NaN position")
	requireCode(t, pos("2000000"), "23514", "far position")

	bg := func(mime string, size, w, h, hashLen int) error {
		_, err := api.Exec(ctx, `INSERT INTO core.map_background (mime, bytes, width, height, sha256, uploaded_by)
			VALUES ($1, decode(repeat('00', $2), 'hex'), $3, $4, decode(repeat('00', $5), 'hex'), 1)`, mime, size, w, h, hashLen)
		return err
	}
	const mib = 1024 * 1024
	if err := bg("image/png", 20*mib, 16384, 1, 32); err != nil {
		t.Errorf("20 MiB: %v", err)
	}
	for name, err := range map[string]error{
		"over 20 MiB":  bg("image/png", 20*mib+1, 1, 1, 32),
		"empty":        bg("image/png", 0, 1, 1, 32),
		"gif":          bg("image/gif", 10, 1, 1, 32),
		"width 0":      bg("image/png", 10, 0, 1, 32),
		"height big":   bg("image/png", 10, 1, 16385, 32),
		"short sha256": bg("image/png", 10, 1, 1, 31),
	} {
		requireCode(t, err, "23514", name)
	}
	/* Deleting a background detaches it from the views. */
	var bid int64
	if err := api.QueryRow(ctx, `INSERT INTO core.map_background (mime, bytes, width, height, sha256, uploaded_by)
		VALUES ('image/svg+xml', '\x3c', 1, 1, decode(repeat('00', 32), 'hex'), 1) RETURNING id`).Scan(&bid); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Exec(ctx, `UPDATE core.map_view SET background_id = $1 WHERE id = $2`, bid, vid); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Exec(ctx, `DELETE FROM core.map_background WHERE id = $1`, bid); err != nil {
		t.Fatal(err)
	}
	var cur *int64
	if err := api.QueryRow(ctx, `SELECT background_id FROM core.map_view WHERE id = $1`, vid).Scan(&cur); err != nil || cur != nil {
		t.Errorf("background after delete = %v, %v", cur, err)
	}
	requireDenied(t, "nms_api", `UPDATE core.map_background SET width = 2`)
	_, err := api.Exec(ctx, `INSERT INTO core.map_view (name, kind) VALUES ('x', 'grid')`)
	requireCode(t, err, "23514", "view kind")
}

func TestTopologyGrantsByRole(t *testing.T) {
	tables := []string{"link", "link_change", "map_view", "map_area", "map_node_position", "map_background"}
	for _, role := range []string{"nms_poller", "nms_eventd", "nms_cli"} {
		for _, tbl := range tables {
			requireDenied(t, role, `SELECT 1 FROM core.`+tbl)
		}
		requireDenied(t, role, `DELETE FROM core.link`)
		requireDenied(t, role, `INSERT INTO core.link_change (a_device_id, b_device_id, change, source) VALUES (1, 2, 'appeared', 'lldp')`)
		requireDenied(t, role, `INSERT INTO core.map_view (name, kind) VALUES ('x', 'logical')`)
	}
	api := testdb.New(t).Pool("nms_api")
	for _, tbl := range tables {
		if _, err := api.Exec(context.Background(), `SELECT 1 FROM core.`+tbl); err != nil {
			t.Errorf("api select %s: %v", tbl, err)
		}
	}
}
