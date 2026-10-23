package store_test

import (
	"context"
	"github.com/jackc/pgx/v5"
	"strings"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/testdb"
)

func TestEventdRoleGrants(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	eventd := env.Pool("nms_eventd")
	for _, sql := range []string{
		`INSERT INTO events.syslog (ts, device_id, facility, severity, host, app, msg, raw_len) VALUES (now(), 1, 3, 4, 'h', 'a', 'link down', 20)`,
		`INSERT INTO events.trap (ts, device_id, version, trap_oid, name, severity, varbinds, identified) VALUES (now(), 1, 2, '1.3.6.1.6.3.1.1.5.3', 'linkDown', NULL, '[]', true)`,
		`INSERT INTO events.storm (ts, device_id, kind, count) VALUES (date_trunc('minute', now()), 1, 'syslog', 500)`,
		`INSERT INTO events.eventd_stats (instance, updated_at, received) VALUES ('t1', now(), 1)
			ON CONFLICT (instance) DO UPDATE SET received = events.eventd_stats.received + excluded.received, updated_at = excluded.updated_at`,
		`UPDATE events.eventd_stats SET dropped = dropped + 1 WHERE instance = 't1'`,
		`SELECT id, address, snmp_port FROM core.device LIMIT 1`,
		`SELECT device_id, kind, ciphertext, key_version, status FROM core.event_auth_profile_v LIMIT 1`,
		`SELECT trap_oid, name, severity FROM events.trap_rule`,
	} {
		if _, err := eventd.Exec(ctx, sql); err != nil {
			t.Errorf("eventd: %q: %v", sql, err)
		}
	}
	/* The poll_now enqueue: the same insert as the api's. */
	var id int64
	if err := eventd.QueryRow(ctx, `INSERT INTO jobs.river_job (args, kind, max_attempts, queue, state)
		VALUES ('{}', 'poll_now', 1, 'probe', 'available') RETURNING id`).Scan(&id); err != nil {
		t.Errorf("eventd enqueue: %v", err)
	}
	for _, sql := range []string{
		/* Events are append-only for eventd. */
		`UPDATE events.syslog SET msg = 'x'`,
		`DELETE FROM events.syslog`,
		`UPDATE events.trap SET name = 'x'`,
		`DELETE FROM events.trap`,
		`UPDATE events.storm SET count = 1`,
		`DELETE FROM events.storm`,
		`TRUNCATE events.syslog`,
		`DELETE FROM events.eventd_stats`,
		`INSERT INTO events.trap_rule (trap_oid, name, severity) VALUES ('1.3', 'x', 'info')`,
		`UPDATE events.trap_rule SET name = 'x'`,
		/* Nothing of the other domains. */
		`SELECT 1 FROM inventory.device_status`,
		`SELECT 1 FROM inventory.interface`,
		`SELECT 1 FROM inventory.device_state_v`,
		`SELECT 1 FROM metrics.availability`,
		`SELECT 1 FROM metrics.if_metrics_5m`,
		`SELECT 1 FROM audit.event`,
		`SELECT 1 FROM audit.chain_head`,
		`DELETE FROM audit.event`,
		`SELECT 1 FROM core."user"`,
		`SELECT 1 FROM core.session`,
		`SELECT 1 FROM core.device_group`,
		`SELECT 1 FROM ssh_hosts.host_key`,
		`INSERT INTO inventory.poller_heartbeat (poller_id, at) VALUES ('x', now())`,
		`INSERT INTO metrics.availability (device_id, ts, icmp_ok, snmp_ok, state) VALUES (1, now(), true, true, 'up')`,
		/* Read-only on core. */
		`UPDATE core.device SET driver = 'x'`,
		`DELETE FROM core.device`,
		`UPDATE core.access_profile SET status = 'ok'`,
		`SELECT 1 FROM core.access_profile`,
		`SELECT kind FROM core.access_profile`,
		`INSERT INTO jobs.river_job (args, kind, max_attempts, queue, state) VALUES ('{}', 'discovery_scan', 1, 'probe', 'available')`,
		`UPDATE jobs.river_job SET kind = 'discovery_scan'`,
		/* The queue: enqueue only. */
		`UPDATE jobs.river_job SET state = 'completed'`,
		`UPDATE jobs.river_job SET args = '{}'`,
		`DELETE FROM jobs.river_job`,
		`DELETE FROM jobs.river_migration`,
	} {
		requireDenied(t, "nms_eventd", sql)
	}
}

/* The exec schema does not exist yet; the sweep covers it once it does. */
func TestEventdRoleHasNoSchemaAccessOutsideItsDomain(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	rows, err := env.Pool("postgres").Query(ctx, `SELECT nspname, has_schema_privilege('nms_eventd', oid, 'USAGE'),
		has_schema_privilege('nms_eventd', oid, 'CREATE') FROM pg_namespace
		WHERE nspname NOT LIKE 'pg\_%' AND nspname <> 'information_schema'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	allowed := map[string]bool{"core": true, "events": true, "jobs": true}
	for rows.Next() {
		var name string
		var usage, create bool
		if err := rows.Scan(&name, &usage, &create); err != nil {
			t.Fatal(err)
		}
		if create {
			t.Errorf("nms_eventd can CREATE in schema %s", name)
		}
		/* TimescaleDB's own schemas are usable by everyone (extension default). */
		if usage && !allowed[name] && !strings.Contains(name, "timescaledb") {
			t.Errorf("nms_eventd has USAGE on schema %s", name)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestAPIEventsGrants(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	api := env.Pool("nms_api")
	for _, sql := range []string{
		`SELECT count(*) FROM events.syslog`, `SELECT count(*) FROM events.trap`,
		`SELECT count(*) FROM events.storm`, `SELECT count(*) FROM events.eventd_stats`,
		`INSERT INTO events.trap_rule (trap_oid, name, severity) VALUES ('1.3.6.1.4.1.99.1', 'custom', 'high')`,
		`UPDATE events.trap_rule SET severity = 'info' WHERE trap_oid = '1.3.6.1.4.1.99.1'`,
		`DELETE FROM events.trap_rule WHERE trap_oid = '1.3.6.1.4.1.99.1'`,
	} {
		if _, err := api.Exec(ctx, sql); err != nil {
			t.Errorf("api: %q: %v", sql, err)
		}
	}
	for _, sql := range []string{
		`INSERT INTO events.syslog (ts, device_id, facility, severity, host, app, msg, raw_len) VALUES (now(), 1, 3, 4, 'h', 'a', 'm', 1)`,
		`INSERT INTO events.trap (ts, device_id, version, trap_oid, name, varbinds, identified) VALUES (now(), 1, 2, '1', 'n', '[]', true)`,
		`INSERT INTO events.storm (ts, device_id, kind, count) VALUES (now(), 1, 'trap', 1)`,
		`INSERT INTO events.eventd_stats (instance, updated_at) VALUES ('api', now())`,
		`UPDATE events.eventd_stats SET received = 0`,
		`UPDATE events.syslog SET msg = 'x'`,
		`DELETE FROM events.syslog`,
		`DELETE FROM events.trap`,
		`TRUNCATE events.trap_rule`,
		`CREATE TABLE events.x (id int)`,
	} {
		requireDenied(t, "nms_api", sql)
	}
	/* The poller and the cli have nothing in events. */
	for _, role := range []string{"nms_poller", "nms_cli"} {
		requireDenied(t, role, `SELECT 1 FROM events.syslog`)
		requireDenied(t, role, `SELECT 1 FROM events.trap_rule`)
	}
}

func TestEventsFullTextSearch(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	if _, err := env.Pool("nms_eventd").Exec(ctx, `INSERT INTO events.syslog (ts, device_id, facility, severity, host, app, msg, raw_len)
		VALUES (now(), 77, 3, 4, 'sw1', 'link', 'Interface gi1/0/7 changed state to down', 40),
		       (now(), 77, 3, 6, 'sw1', 'link', 'Interface gi1/0/7 changed state to up', 38)`); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := env.Pool("nms_api").QueryRow(ctx, `SELECT count(*) FROM events.syslog
		WHERE device_id = 77 AND tsv @@ plainto_tsquery('simple', 'down')`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("search down = %d, %v; want 1", n, err)
	}
	if err := env.Pool("nms_api").QueryRow(ctx, `SELECT count(*) FROM events.syslog
		WHERE device_id = 77 AND tsv @@ plainto_tsquery('simple', 'interface state')`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("search 'interface state' = %d, %v; want 2", n, err)
	}
	/* Traps are searchable by name and by varbind value. */
	if _, err := env.Pool("nms_eventd").Exec(ctx, `INSERT INTO events.trap (ts, device_id, version, trap_oid, name, varbinds, identified)
		VALUES (now(), 77, 2, '1.3.6.1.6.3.1.1.5.3', 'linkDown', '[{"oid":"1.3.6.1.2.1.2.2.1.1","value":"portname7"}]', true)`); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"linkdown", "portname7"} {
		if err := env.Pool("nms_api").QueryRow(ctx, `SELECT count(*) FROM events.trap WHERE device_id = 77 AND tsv @@ plainto_tsquery('simple', $1)`, q).Scan(&n); err != nil || n != 1 {
			t.Fatalf("trap search %q = %d, %v; want 1", q, n, err)
		}
	}
}

func TestEventsBounds(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	long := make([]byte, 8193)
	for i := range long {
		long[i] = 'a'
	}
	for _, c := range []struct {
		name, sql string
		args      []any
	}{
		{"long msg", `INSERT INTO events.syslog (ts, device_id, facility, severity, host, app, msg, raw_len) VALUES (now(), 1, 3, 4, 'h', 'a', $1, 1)`, []any{string(long)}},
		{"bad severity", `INSERT INTO events.syslog (ts, device_id, facility, severity, host, app, msg, raw_len) VALUES (now(), 1, 3, 8, 'h', 'a', 'm', 1)`, nil},
		{"bad trap severity", `INSERT INTO events.trap (ts, device_id, version, trap_oid, name, severity, varbinds, identified) VALUES (now(), 1, 2, '1', 'n', 'bogus', '[]', true)`, nil},
		{"bad rule severity", `INSERT INTO events.trap_rule (trap_oid, name, severity) VALUES ('1.3.9', 'n', 'bogus')`, nil},
	} {
		if _, err := env.Pool("nms_migrator").Exec(ctx, c.sql, c.args...); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}

func TestTrapRuleChangeNotifies(t *testing.T) {
	env := testdb.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := env.Pool("nms_eventd").Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `LISTEN trap_rules`); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		`INSERT INTO events.trap_rule (trap_oid, name, severity) VALUES ('1.3.6.1.4.1.99.2', 'n', 'info')`,
		`UPDATE events.trap_rule SET name = 'm' WHERE trap_oid = '1.3.6.1.4.1.99.2'`,
		`DELETE FROM events.trap_rule WHERE trap_oid = '1.3.6.1.4.1.99.2'`,
	} {
		if _, err := env.Pool("nms_api").Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
		wctx, wcancel := context.WithTimeout(ctx, 5*time.Second)
		n, err := conn.Conn().WaitForNotification(wctx)
		wcancel()
		if err != nil || n.Channel != "trap_rules" {
			t.Fatalf("%q: notification %v, %v", sql, n, err)
		}
	}
}

func TestDeviceStateViewShowsLastError(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	pg := env.Pool("postgres")
	var gid, did int64
	if err := pg.QueryRow(ctx, `INSERT INTO core.device_group (name) VALUES ('last-error-group') RETURNING id`).Scan(&gid); err != nil {
		t.Fatal(err)
	}
	if err := pg.QueryRow(ctx, `INSERT INTO core.device (name, address, group_id, poller_id)
		VALUES ('le', '198.51.100.250', $1, 'le-poller') RETURNING id`, gid).Scan(&did); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.Exec(ctx, `INSERT INTO inventory.device_status (device_id, state, since, last_poll_at, poller_id, last_error)
		VALUES ($1, 'down', now(), now(), 'le-poller', 'SNMP request timed out')`, did); err != nil {
		t.Fatal(err)
	}
	read := func() string {
		var s string
		if err := env.Pool("nms_api").QueryRow(ctx, `SELECT last_error FROM inventory.device_state_v WHERE device_id = $1`, did).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	/* No heartbeat: the poller is silent, so the old reason is not shown. */
	if got := read(); got != "" {
		t.Fatalf("last_error without heartbeat = %q, want empty", got)
	}
	if _, err := pg.Exec(ctx, `INSERT INTO inventory.poller_heartbeat (poller_id, at) VALUES ('le-poller', now())`); err != nil {
		t.Fatal(err)
	}
	if got := read(); got != "SNMP request timed out" {
		t.Fatalf("last_error = %q", got)
	}
}

func TestEventAuthProfileViewExposesOnlySNMPDeviceProfiles(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	pg := env.Pool("postgres")
	var gid, did, sid int64
	if err := pg.QueryRow(ctx, `INSERT INTO core.device_group (name) VALUES ('view-group') RETURNING id`).Scan(&gid); err != nil {
		t.Fatal(err)
	}
	if err := pg.QueryRow(ctx, `INSERT INTO core.device (name, address, group_id) VALUES ('v', '198.51.100.251', $1) RETURNING id`, gid).Scan(&did); err != nil {
		t.Fatal(err)
	}
	if err := pg.QueryRow(ctx, `INSERT INTO core.discovery_scan (cidr, group_id) VALUES ('198.51.100.0/24', $1) RETURNING id`, gid).Scan(&sid); err != nil {
		t.Fatal(err)
	}
	for _, r := range []struct {
		kind, owner string
		id          int64
	}{{"snmp2c", "device", did}, {"snmp3", "device", did}, {"ssh_read", "device", did}, {"telnet_read", "device", did}, {"snmp2c", "scan", sid}, {"ssh_read", "scan", sid}} {
		if _, err := pg.Exec(ctx, `INSERT INTO core.access_profile (owner_kind, owner_id, kind, ciphertext, key_version) VALUES ($1, $2, $3, decode('00', 'hex'), 1)`, r.owner, r.id, r.kind); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := env.Pool("nms_eventd").Query(ctx, `SELECT device_id, kind FROM core.event_auth_profile_v WHERE device_id = $1 OR device_id = $2`, did, sid)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]int{}
	for rows.Next() {
		var id int64
		var kind string
		if err := rows.Scan(&id, &kind); err != nil {
			t.Fatal(err)
		}
		if id != did {
			t.Errorf("view returned a scan-owned row: %d %s", id, kind)
		}
		got[kind]++
	}
	if len(got) != 2 || got["snmp2c"] != 1 || got["snmp3"] != 1 {
		t.Errorf("view kinds = %v, want exactly snmp2c and snmp3 of the device", got)
	}
	/* Nobody but eventd reads the view. */
	requireDenied(t, "nms_poller", `SELECT 1 FROM core.event_auth_profile_v`)
	requireDenied(t, "nms_api", `SELECT 1 FROM core.event_auth_profile_v`)
}

func TestTrapVarbindsBound(t *testing.T) {
	env := testdb.New(t)
	big := `"` + strings.Repeat("a", 300001) + `"`
	if _, err := env.Pool("nms_eventd").Exec(context.Background(), `INSERT INTO events.trap (ts, device_id, version, trap_oid, name, varbinds, identified)
		VALUES (now(), 1, 2, '1', 'n', $1::jsonb, true)`, big); err == nil {
		t.Fatal("oversized varbinds accepted")
	}
}

/* TestEventsCompression compresses old chunks (generated tsv + GIN) and checks reads and a late insert. */
func TestEventsCompression(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	pg, ev, api := env.Pool("postgres"), env.Pool("nms_eventd"), env.Pool("nms_api")
	old := time.Now().Add(-30 * 24 * time.Hour).Truncate(time.Second)
	if _, err := ev.Exec(ctx, `INSERT INTO events.syslog (ts, device_id, facility, severity, host, app, msg, raw_len)
		VALUES ($1, 901, 3, 4, 'h', 'a', 'compressme one', 10), ($1, 901, 3, 4, 'h', 'a', 'other two', 10)`, old); err != nil {
		t.Fatal(err)
	}
	if _, err := ev.Exec(ctx, `INSERT INTO events.trap (ts, device_id, version, trap_oid, name, varbinds, identified)
		VALUES ($1, 901, 2, '1.3.6.1.6.3.1.1.5.3', 'linkDown', '[{"value":"compressvb"}]', true)`, old); err != nil {
		t.Fatal(err)
	}
	for _, tbl := range []string{"events.syslog", "events.trap"} {
		var n int
		if err := pg.QueryRow(ctx, `SELECT count(*) FROM (SELECT compress_chunk(c, if_not_compressed => true)
			FROM show_chunks($1::regclass, older_than => now() - interval '10 days') c) x`, tbl).Scan(&n); err != nil || n == 0 {
			t.Fatalf("compress %s: %d chunks, %v", tbl, n, err)
		}
		if err := pg.QueryRow(ctx, `SELECT count(*) FROM chunk_compression_stats($1::regclass) WHERE compression_status = 'Compressed'`, tbl).Scan(&n); err != nil || n == 0 {
			t.Fatalf("%s: no compressed chunk (%d, %v)", tbl, n, err)
		}
	}
	var n int
	if err := api.QueryRow(ctx, `SELECT count(*) FROM events.syslog WHERE device_id = 901 AND tsv @@ plainto_tsquery('simple', 'compressme')`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("tsv search in compressed chunk = %d, %v", n, err)
	}
	if err := api.QueryRow(ctx, `SELECT count(*) FROM events.syslog WHERE device_id = 901 AND ts >= $1 AND ts <= $1`, old).Scan(&n); err != nil || n != 2 {
		t.Fatalf("(device_id, ts) read in compressed chunk = %d, %v", n, err)
	}
	if err := api.QueryRow(ctx, `SELECT count(*) FROM events.trap WHERE device_id = 901 AND tsv @@ plainto_tsquery('simple', 'compressvb')`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("trap tsv search in compressed chunk = %d, %v", n, err)
	}
	/* A late event lands in the compressed chunk as the unprivileged writer. */
	if _, err := ev.Exec(ctx, `INSERT INTO events.syslog (ts, device_id, facility, severity, host, app, msg, raw_len)
		VALUES ($1, 901, 3, 4, 'h', 'a', 'latecomer', 10)`, old.Add(time.Minute)); err != nil {
		t.Fatalf("late insert into a compressed chunk as nms_eventd: %v", err)
	}
	if err := api.QueryRow(ctx, `SELECT count(*) FROM events.syslog WHERE device_id = 901 AND tsv @@ plainto_tsquery('simple', 'latecomer')`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("late event not found = %d, %v", n, err)
	}
	/* ingest_seq: assigned to every row (INSERT and COPY alike) by the sequence default, increasing in commit order, readable from compressed chunks. */
	var seqs []int64
	rows, err := api.Query(ctx, `SELECT ingest_seq FROM events.syslog WHERE device_id = 901 ORDER BY ingest_seq`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var q *int64
		if err := rows.Scan(&q); err != nil || q == nil {
			t.Fatalf("ingest_seq missing: %v", err)
		}
		seqs = append(seqs, *q)
	}
	rows.Close()
	if len(seqs) != 3 || seqs[0] >= seqs[1] || seqs[1] >= seqs[2] {
		t.Fatalf("ingest_seq = %v", seqs)
	}
	if _, err := ev.CopyFrom(ctx, pgx.Identifier{"events", "trap"}, []string{"ts", "device_id", "version", "trap_oid", "name", "severity", "varbinds", "identified"},
		pgx.CopyFromRows([][]any{{old, int64(901), int16(2), "1.3.6.1.6.3.1.1.5.4", "linkUp", nil, "[]", true}})); err != nil {
		t.Fatalf("COPY as nms_eventd with the existing column list: %v", err)
	}
	var cnt int
	if err := api.QueryRow(ctx, `SELECT count(*) FROM events.trap WHERE device_id = 901 AND ingest_seq IS NOT NULL AND ingest_seq > 0`).Scan(&cnt); err != nil || cnt != 2 {
		t.Fatalf("trap rows with ingest_seq = %d, %v", cnt, err)
	}
}

/* TestEventdCannotChooseIngestSeq: eventd inserts every column but ingest_seq, which only the sequence default may fill. */
func TestEventdCannotChooseIngestSeq(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	ev := env.Pool("nms_eventd")
	_, err := ev.Exec(ctx, `INSERT INTO events.syslog (ts, device_id, facility, severity, host, app, msg, raw_len, ingest_seq) VALUES (now(), 1, 1, 1, 'h', 'a', 'm', 1, 5)`)
	requireCode(t, err, "42501", "syslog insert naming ingest_seq")
	_, err = ev.Exec(ctx, `INSERT INTO events.trap (ts, device_id, version, trap_oid, name, varbinds, identified, ingest_seq) VALUES (now(), 1, 2, '1.3', 'n', '[]', true, 5)`)
	requireCode(t, err, "42501", "trap insert naming ingest_seq")
	_, err = ev.CopyFrom(ctx, pgx.Identifier{"events", "syslog"}, []string{"ts", "device_id", "facility", "severity", "host", "app", "msg", "raw_len", "ingest_seq"},
		pgx.CopyFromRows([][]any{{time.Now(), int64(1), int16(1), int16(1), "h", "a", "m", 1, int64(5)}}))
	requireCode(t, err, "42501", "syslog COPY naming ingest_seq")
	if _, err := ev.CopyFrom(ctx, pgx.Identifier{"events", "syslog"}, []string{"ts", "device_id", "facility", "severity", "host", "app", "msg", "raw_len"},
		pgx.CopyFromRows([][]any{{time.Now(), int64(1), int16(1), int16(1), "h", "a", "m", 1}})); err != nil {
		t.Fatalf("the normal COPY must work: %v", err)
	}
	if _, err := ev.Exec(ctx, `UPDATE events.syslog SET ingest_seq = 1`); err == nil {
		t.Fatal("eventd must not update rows")
	}
}
