package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/internal/testdb"
)

/* backupFixture creates a device (through the api) and a user (through the owner). */
func backupFixture(t *testing.T, base string) (dev, user int64) {
	t.Helper()
	ctx := context.Background()
	env := testdb.New(t)
	dev = topoDevices(t, env.Pool("nms_api"), 1, base)[0]
	if err := env.Pool("nms_migrator").QueryRow(ctx,
		`INSERT INTO core."user" (username, password_phc) VALUES ($1, 'x') RETURNING id`, "u-"+base).Scan(&user); err != nil {
		t.Fatal(err)
	}
	return dev, user
}

const insertVersion = `INSERT INTO backups.config_version (device_id, source, sha256, size, masked, full_ct, full_dek_ct)
	VALUES ($1, $2, $3, $4, $5, $6, $7)`

func TestConfigVersionGrantsAndAppendOnly(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	dev, _ := backupFixture(t, "10.30.0")
	poller, api, owner := env.Pool("nms_poller"), env.Pool("nms_api"), env.Pool("nms_migrator")
	sum := make([]byte, 32)
	if _, err := poller.Exec(ctx, insertVersion, dev, "schedule", sum, 5, "hostname x", []byte("ct"), []byte("dek")); err != nil {
		t.Fatal(err)
	}
	/* The api reads the masked copy and metadata, never the ciphertext. */
	if _, err := api.Exec(ctx, `SELECT id, device_id, taken_at, source, sha256, size, masked, drift, taken_by_job FROM backups.config_version`); err != nil {
		t.Errorf("api select allowed columns: %v", err)
	}
	for _, sql := range []string{
		`SELECT full_ct FROM backups.config_version`,
		`SELECT full_dek_ct FROM backups.config_version`,
		`SELECT * FROM backups.config_version`,
		`SELECT count(full_ct) FROM backups.config_version`,
		`SELECT 1 FROM backups.config_version WHERE full_ct IS NOT NULL`,
		`SELECT cv FROM backups.config_version cv`,
		`INSERT INTO backups.config_version (device_id, source, sha256, size, masked, full_ct, full_dek_ct) VALUES (1, 'manual', '\x00', 0, '', '\x00', '\x00')`,
		`UPDATE backups.config_version SET masked = 'x'`,
		`DELETE FROM backups.config_version`,
		`TRUNCATE backups.config_version`,
	} {
		requireDenied(t, "nms_api", sql)
	}
	/* The poller inserts ciphertext but cannot read it back. */
	if _, err := poller.Exec(ctx, `SELECT id, device_id, taken_at, source, sha256, size, drift, taken_by_job FROM backups.config_version`); err != nil {
		t.Errorf("poller select allowed columns: %v", err)
	}
	for _, sql := range []string{
		`SELECT full_ct FROM backups.config_version`,
		`SELECT full_dek_ct FROM backups.config_version`,
		`SELECT masked FROM backups.config_version`,
		`SELECT * FROM backups.config_version`,
	} {
		requireDenied(t, "nms_poller", sql)
	}
	/* The poller can neither backdate nor rewrite a version. */
	_, err := poller.Exec(ctx, `INSERT INTO backups.config_version (device_id, taken_at, source, sha256, size, masked, full_ct, full_dek_ct)
		VALUES ($1, '2000-01-01', 'manual', $2, 0, '', '\x00', '\x00')`, dev, sum)
	requireCode(t, err, "42501", "explicit taken_at")
	for _, sql := range []string{`UPDATE backups.config_version SET masked = 'x'`, `DELETE FROM backups.config_version`, `TRUNCATE backups.config_version`} {
		requireDenied(t, "nms_poller", sql)
		_, err := owner.Exec(ctx, sql)
		requireCode(t, err, "42501", "owner "+sql)
	}
	for _, role := range []string{"nms_eventd", "nms_cli"} {
		requireDenied(t, role, `SELECT 1 FROM backups.config_version`)
		requireDenied(t, role, `SELECT 1 FROM backups.backup_state`)
		requireDenied(t, role, `SELECT 1 FROM backups.show_result`)
	}
	/* A device delete leaves its history alone (no cascade into the append-only table). */
	if _, err := api.Exec(ctx, `DELETE FROM core.device WHERE id = $1`, dev); err != nil {
		t.Errorf("device delete: %v", err)
	}
}

func TestConfigVersionChecks(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	dev, _ := backupFixture(t, "10.30.1")
	poller := env.Pool("nms_poller")
	sum, mib4 := make([]byte, 32), 4*1024*1024
	ok := func(source string, sha []byte, size int, masked string, ct, dek []byte) error {
		_, err := poller.Exec(ctx, insertVersion, dev, source, sha, size, masked, ct, dek)
		return err
	}
	if err := ok("pre_session", sum, mib4, "x", []byte("c"), []byte("d")); err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"bad source":      ok("auto", sum, 1, "x", []byte("c"), []byte("d")),
		"short sha":       ok("manual", make([]byte, 31), 1, "x", []byte("c"), []byte("d")),
		"negative size":   ok("manual", sum, -1, "x", []byte("c"), []byte("d")),
		"size over 4 MiB": ok("manual", sum, mib4+1, "x", []byte("c"), []byte("d")),
		"masked over 4":   ok("manual", sum, 1, strings.Repeat("a", mib4+1), []byte("c"), []byte("d")),
		"full_ct over":    ok("manual", sum, 1, "x", make([]byte, mib4+1025), []byte("d")),
		"empty dek":       ok("manual", sum, 1, "x", []byte("c"), []byte{}),
		"dek over 1024":   ok("manual", sum, 1, "x", []byte("c"), make([]byte, 1025)),
	} {
		requireCode(t, err, "23514", name)
	}
	_, err := poller.Exec(ctx, insertVersion, dev, "manual", sum, 1, "x", nil, []byte("d"))
	requireCode(t, err, "23502", "null full_ct")
}

func TestBackupStateAndShowResult(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	dev, user := backupFixture(t, "10.30.2")
	api, poller := env.Pool("nms_api"), env.Pool("nms_poller")

	if _, err := poller.Exec(ctx, `INSERT INTO backups.backup_state (device_id, last_ok_at) VALUES ($1, now())`, dev); err != nil {
		t.Fatal(err)
	}
	if _, err := poller.Exec(ctx, `UPDATE backups.backup_state SET needs_write = true`); err != nil {
		t.Error(err)
	}
	if _, err := api.Exec(ctx, `SELECT * FROM backups.backup_state`); err != nil {
		t.Error(err)
	}
	for _, sql := range []string{
		`INSERT INTO backups.backup_state (device_id) VALUES (1)`,
		`UPDATE backups.backup_state SET needs_write = false`,
		`DELETE FROM backups.backup_state`,
	} {
		requireDenied(t, "nms_api", sql)
	}
	requireDenied(t, "nms_poller", `DELETE FROM backups.backup_state`)

	var id int64
	if err := api.QueryRow(ctx, `INSERT INTO backups.show_result (device_id, user_id, command_key, args)
		VALUES ($1, $2, 'interface', '{"if":"gi1/0/1"}') RETURNING id`, dev, user).Scan(&id); err != nil {
		t.Fatal(err)
	}
	/* The api requests; it neither fills results nor changes expiry or status. */
	for _, sql := range []string{
		`INSERT INTO backups.show_result (device_id, user_id, command_key, output) VALUES (1, 1, 'x', 'o')`,
		`INSERT INTO backups.show_result (device_id, user_id, command_key, status) VALUES (1, 1, 'x', 'done')`,
		`INSERT INTO backups.show_result (device_id, user_id, command_key, expires_at) VALUES (1, 1, 'x', now() + interval '99 days')`,
		`UPDATE backups.show_result SET output = 'x'`,
		`DELETE FROM backups.show_result`,
	} {
		requireDenied(t, "nms_api", sql)
	}
	/* The poller writes only result columns, and may delete (TTL). */
	if _, err := poller.Exec(ctx, `UPDATE backups.show_result SET status = 'done', finished_at = now(), output = 'ok', truncated = true WHERE id = $1`, id); err != nil {
		t.Error(err)
	}
	for _, sql := range []string{
		`UPDATE backups.show_result SET command_key = 'other'`,
		`UPDATE backups.show_result SET expires_at = now() + interval '1 year'`,
		`UPDATE backups.show_result SET user_id = 1`,
		`INSERT INTO backups.show_result (device_id, user_id, command_key) VALUES (1, 1, 'x')`,
	} {
		requireDenied(t, "nms_poller", sql)
	}
	_, err := poller.Exec(ctx, `UPDATE backups.show_result SET status = 'weird'`)
	requireCode(t, err, "23514", "status enum")
	_, err = poller.Exec(ctx, `UPDATE backups.show_result SET output = repeat('x', 1048577)`)
	requireCode(t, err, "23514", "output over 1 MiB")
	if _, err := poller.Exec(ctx, `UPDATE backups.show_result SET output = repeat('x', 1048576)`); err != nil {
		t.Errorf("output at 1 MiB: %v", err)
	}
	_, err = api.Exec(ctx, `INSERT INTO backups.show_result (device_id, user_id, command_key) VALUES ($1, $2, 'Bad Key')`, dev, user)
	requireCode(t, err, "23514", "command key shape")
	_, err = api.Exec(ctx, `INSERT INTO backups.show_result (device_id, user_id, command_key, args) VALUES ($1, $2, 'k', '[]')`, dev, user)
	requireCode(t, err, "23514", "args not object")
	if _, err := poller.Exec(ctx, `DELETE FROM backups.show_result WHERE id = $1`, id); err != nil {
		t.Errorf("poller ttl delete: %v", err)
	}
}

func TestDashboardsRulesAndGrants(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	_, user := backupFixture(t, "10.30.3")
	api := env.Pool("nms_api")

	var personal int64
	if err := api.QueryRow(ctx, `INSERT INTO core.dashboard (owner_id, name) VALUES ($1, 'mine') RETURNING id`, user).Scan(&personal); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Exec(ctx, `INSERT INTO core.dashboard (name, shared, default_for_role) VALUES ('ops', true, 'operator')`); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, sql, code string }{
		{"shared with owner", `INSERT INTO core.dashboard (owner_id, name, shared) VALUES (1, 'x', true)`, "23514"},
		{"personal without owner", `INSERT INTO core.dashboard (name) VALUES ('x')`, "23514"},
		{"personal default", `INSERT INTO core.dashboard (owner_id, name, default_for_role) VALUES (1, 'x', 'admin')`, "23514"},
		{"unknown role", `INSERT INTO core.dashboard (name, shared, default_for_role) VALUES ('x', true, 'root')`, "23514"},
		{"duplicate default", `INSERT INTO core.dashboard (name, shared, default_for_role) VALUES ('y', true, 'operator')`, "23505"},
		{"empty name", `INSERT INTO core.dashboard (name, shared) VALUES ('', true)`, "23514"},
	}
	for _, c := range cases {
		_, err := api.Exec(ctx, c.sql)
		requireCode(t, err, c.code, c.name)
	}
	/* Ids come from the sequence only. */
	_, err := api.Exec(ctx, `INSERT INTO core.dashboard (id, name, shared) OVERRIDING SYSTEM VALUE VALUES (99999, 'x', true)`)
	requireCode(t, err, "42501", "explicit id")

	w := `INSERT INTO core.dashboard_widget (dashboard_id, type, x, y, w, h, config) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)`
	if _, err := api.Exec(ctx, w, personal, "device-status", 0, 0, 4, 3, `{"a":1}`); err != nil {
		t.Fatal(err)
	}
	bad := map[string][]any{
		"x negative":   {personal, "t", -1, 0, 4, 3, `{}`},
		"x over":       {personal, "t", 1001, 0, 4, 3, `{}`},
		"w zero":       {personal, "t", 0, 0, 0, 3, `{}`},
		"h over 48":    {personal, "t", 0, 0, 4, 49, `{}`},
		"bad type":     {personal, "Bad Type", 0, 0, 4, 3, `{}`},
		"config array": {personal, "t", 0, 0, 4, 3, `[]`},
		"config big":   {personal, "t", 0, 0, 4, 3, `{"a":"` + strings.Repeat("x", 16384) + `"}`},
	}
	for name, args := range bad {
		_, err := api.Exec(ctx, w, args...)
		requireCode(t, err, "23514", name)
	}
	if _, err := api.Exec(ctx, w, personal, "t", 1000, 1000, 48, 48, `{"a":"`+strings.Repeat("x", 16300)+`"}`); err != nil {
		t.Errorf("widget at limits: %v", err)
	}
	/* Caps: 50 widgets per dashboard, 50 dashboards per owner. */
	if _, err := api.Exec(ctx, `INSERT INTO core.dashboard_widget (dashboard_id, type, x, y, w, h)
		SELECT $1, 't', 0, 0, 1, 1 FROM generate_series(1, 48)`, personal); err != nil {
		t.Fatal(err)
	}
	_, err = api.Exec(ctx, w, personal, "t", 0, 0, 1, 1, `{}`)
	requireCode(t, err, "23514", "51st widget")
	if _, err := api.Exec(ctx, `INSERT INTO core.dashboard (owner_id, name) SELECT $1, 'd' FROM generate_series(1, 49)`, user); err != nil {
		t.Fatal(err)
	}
	_, err = api.Exec(ctx, `INSERT INTO core.dashboard (owner_id, name) VALUES ($1, 'over')`, user)
	requireCode(t, err, "23514", "51st dashboard")
	/* Caps cannot be bypassed by moving rows. */
	var other, extra int64
	if err := api.QueryRow(ctx, `INSERT INTO core.dashboard (name, shared) VALUES ('spare', true) RETURNING id`).Scan(&other); err != nil {
		t.Fatal(err)
	}
	if err := api.QueryRow(ctx, `INSERT INTO core.dashboard_widget (dashboard_id, type, x, y, w, h) VALUES ($1, 't', 0, 0, 1, 1) RETURNING id`, other).Scan(&extra); err != nil {
		t.Fatal(err)
	}
	_, err = api.Exec(ctx, `UPDATE core.dashboard_widget SET dashboard_id = $1 WHERE id = $2`, personal, extra)
	requireCode(t, err, "23514", "widget move into full dashboard")
	_, err = api.Exec(ctx, `UPDATE core.dashboard SET owner_id = $1, shared = false WHERE id = $2`, user, other)
	requireCode(t, err, "23514", "dashboard move into full owner")
	if _, err := api.Exec(ctx, `UPDATE core.dashboard SET name = 'renamed' WHERE owner_id = $1`, user); err != nil {
		t.Errorf("rename at cap: %v", err)
	}
	/* Deleting a dashboard removes its widgets. */
	if _, err := api.Exec(ctx, `DELETE FROM core.dashboard WHERE id = $1`, personal); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := api.QueryRow(ctx, `SELECT count(*) FROM core.dashboard_widget WHERE dashboard_id = $1`, personal).Scan(&n); err != nil || n != 0 {
		t.Errorf("widgets after delete = %d, %v", n, err)
	}
	for _, role := range []string{"nms_poller", "nms_eventd", "nms_cli"} {
		requireDenied(t, role, `SELECT 1 FROM core.dashboard`)
		requireDenied(t, role, `SELECT 1 FROM core.dashboard_widget`)
		requireDenied(t, role, `INSERT INTO core.dashboard (name, shared) VALUES ('x', true)`)
	}
}

func TestBackupIntervalAndPortKind(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	dev, _ := backupFixture(t, "10.30.4")
	api, poller := env.Pool("nms_api"), env.Pool("nms_poller")
	if _, err := api.Exec(ctx, `UPDATE core.device SET interval_backup_s = 3600 WHERE id = $1`, dev); err != nil {
		t.Fatal(err)
	}
	for _, v := range []int{3599, 2592001} {
		_, err := api.Exec(ctx, `UPDATE core.device SET interval_backup_s = $1 WHERE id = $2`, v, dev)
		requireCode(t, err, "23514", "interval out of range")
	}
	if _, err := api.Exec(ctx, `UPDATE core.device_group SET interval_backup_s = 86400`); err != nil {
		t.Error(err)
	}
	if _, err := api.Exec(ctx, `UPDATE core.monitoring_template SET interval_backup_s = 86400`); err != nil {
		t.Error(err)
	}
	_, err := api.Exec(ctx, `UPDATE core.device_group SET interval_backup_s = 10`)
	requireCode(t, err, "23514", "group interval")
	_, err = api.Exec(ctx, `UPDATE core.monitoring_template SET interval_backup_s = 10`)
	requireCode(t, err, "23514", "template interval")
	for _, sql := range []string{`SELECT interval_backup_s FROM core.device`, `SELECT interval_backup_s FROM core.device_group`, `SELECT interval_backup_s FROM core.monitoring_template`} {
		if _, err := poller.Exec(ctx, sql); err != nil {
			t.Errorf("poller %q: %v", sql, err)
		}
	}
	requireDenied(t, "nms_poller", `UPDATE core.device SET interval_backup_s = 3600`)

	ins := `INSERT INTO inventory.interface (device_id, if_index, name, alias, speed_bps, oper_up, seen_at, port_kind) VALUES ($1, $2, 'p', '', 0, true, now(), $3)`
	if _, err := poller.Exec(ctx, ins, dev, 1, "sfp"); err != nil {
		t.Fatal(err)
	}
	_, err = poller.Exec(ctx, ins, dev, 2, "usb")
	requireCode(t, err, "23514", "port kind")
	var k string
	if err := api.QueryRow(ctx, `SELECT port_kind FROM inventory.interface WHERE if_index = 1 AND device_id = $1`, dev).Scan(&k); err != nil || k != "sfp" {
		t.Errorf("api port_kind = %q, %v", k, err)
	}
}
