package store_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/internal/store"
	"github.com/beekamai/network-scheme/internal/testdb"
)

/* mac32 is a 32-byte placeholder for the MAC and hash columns. */
const mac32 = `decode(repeat('00', 32), 'hex')`

var execImmutable = []string{"exec.session", "exec.session_device", "exec.session_event",
	"exec.recording_chunk", "exec.recording_manifest", "exec.audit_event"}

/*
grantsOf describes the rights of role on table: table-level privileges by name,
column-level ones as PRIV(col,...), in a fixed order; "" when there are none.
Schema USAGE is not taken into account.
*/
func grantsOf(t *testing.T, role, table string) string {
	t.Helper()
	var s string
	err := testdb.New(t).Pool("postgres").QueryRow(context.Background(), `
		SELECT coalesce(string_agg(g, ' ' ORDER BY o), '') FROM (
			SELECT o, CASE WHEN has_table_privilege($1::text, $2::text::regclass, p) THEN p
				ELSE (SELECT p || '(' || string_agg(attname::text, ',' ORDER BY attname::text) || ')'
				      FROM pg_attribute
				      WHERE attrelid = $2::text::regclass AND attnum > 0 AND NOT attisdropped
				        AND p IN ('SELECT', 'INSERT', 'UPDATE', 'REFERENCES')
				        AND has_column_privilege($1::text, attrelid, attnum, p)) END AS g
			FROM unnest(array['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'])
				WITH ORDINALITY AS u (p, o)) x
		WHERE g IS NOT NULL`, role, table).Scan(&s)
	if err != nil {
		t.Fatalf("grants of %s on %s: %v", role, table, err)
	}
	return s
}

/* relations lists the tables and views of the given schemas as quoted names. */
func relations(t *testing.T, schemas ...string) []string {
	t.Helper()
	rows, err := testdb.New(t).Pool("postgres").Query(context.Background(), `
		SELECT format('%I.%I', n.nspname, c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = ANY ($1) AND c.relkind IN ('r', 'v', 'm', 'p', 'f') ORDER BY 1`, schemas)
	if err != nil {
		t.Fatal(err)
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return names
}

/* requireGrants checks role's rights on every relation of schemas against want (absent = none). */
func requireGrants(t *testing.T, role string, want map[string]string, schemas ...string) {
	t.Helper()
	seen := map[string]bool{}
	for _, rel := range relations(t, schemas...) {
		seen[rel] = true
		if got := grantsOf(t, role, rel); got != want[rel] {
			t.Errorf("%s on %s: got %q, want %q", role, rel, got, want[rel])
		}
	}
	for rel := range want {
		if !seen[rel] {
			t.Errorf("%s: expected relation %s not found", role, rel)
		}
	}
}

func TestAPIRoleHasNoExecRights(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	root := env.Pool("postgres")
	count := func(sql string) int {
		var n int
		if err := root.QueryRow(ctx, sql).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	/* Guard the enumeration below: 14 tables, 3 sequences, 1 function. */
	if n := count(`SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'exec' AND c.relkind = 'r'`); n != 14 {
		t.Fatalf("exec tables = %d, want 14", n)
	}
	if n := count(`SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'exec' AND c.relkind = 'S'`); n != 3 {
		t.Fatalf("exec sequences = %d, want 3", n)
	}
	if n := count(`SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'exec'`); n != 1 {
		t.Fatalf("exec functions = %d, want 1", n)
	}
	for _, role := range []string{"nms_api", "nms_poller", "nms_eventd", "nms_cli"} {
		var rights []string
		rows, err := root.Query(ctx, `
			SELECT 'schema ' || nspname FROM pg_namespace
			WHERE nspname = 'exec' AND (has_schema_privilege($1::text, oid, 'USAGE') OR has_schema_privilege($1::text, oid, 'CREATE'))
			UNION ALL
			SELECT 'table ' || c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = 'exec' AND c.relkind IN ('r', 'v', 'm', 'p', 'f') AND (
				has_table_privilege($1::text, c.oid, 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
				OR has_any_column_privilege($1::text, c.oid, 'SELECT, INSERT, UPDATE, REFERENCES'))
			UNION ALL
			SELECT 'sequence ' || c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = 'exec' AND CASE WHEN c.relkind = 'S' THEN has_sequence_privilege($1::text, c.oid, 'USAGE, SELECT, UPDATE') END
			UNION ALL
			SELECT 'function ' || p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
			WHERE n.nspname = 'exec' AND has_function_privilege($1::text, p.oid, 'EXECUTE')`, role)
		if err != nil {
			t.Fatal(err)
		}
		if rights, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
			t.Fatal(err)
		}
		if len(rights) > 0 {
			t.Errorf("%s has rights in exec: %v", role, rights)
		}
		requireDenied(t, role, `SELECT 1 FROM exec.exec_state`)
		requireDenied(t, role, `INSERT INTO exec.exec_state ("freeze", version, mac) VALUES (false, 1, '\x00')`)
		requireDenied(t, role, `UPDATE exec.write_device SET writes_enabled = true`)
		requireDenied(t, role, `DELETE FROM exec.write_grant`)
		requireDenied(t, role, `SELECT exec.reject_modification()`)
	}
	/* eventd and the CLI do not even see execpub. */
	for _, role := range []string{"nms_eventd", "nms_cli"} {
		var usage bool
		if err := root.QueryRow(ctx, `SELECT has_schema_privilege($1::text, 'execpub', 'USAGE')`, role).Scan(&usage); err != nil || usage {
			t.Errorf("%s has USAGE on execpub (err %v)", role, err)
		}
		requireDenied(t, role, `SELECT 1 FROM execpub.status`)
	}
}

func TestExecutorRoleGrants(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	const dml = "SELECT INSERT UPDATE DELETE"
	want := map[string]string{
		"exec.registry_counter": dml, "exec.write_device": dml, "exec.write_grant": dml, "exec.change_totp": dml,
		"exec.exec_state": "SELECT INSERT UPDATE", "exec.model_profile": dml, "exec.write_credential": dml,
		"exec.audit_head":        "SELECT UPDATE",
		"execpub.freeze_request": "SELECT DELETE",
		"execpub.alert":          dml, "execpub.device_busy": dml, "execpub.session_summary": dml, "execpub.status": dml,
		"core.device":            "SELECT(address,driver,firmware,group_id,id,model,name)",
		`core."user"`:            "SELECT(created_at,disabled,id,username)",
		"backups.config_version": "SELECT INSERT(device_id,drift,full_ct,full_dek_ct,masked,sha256,size,source,taken_by_job)",
		"backups.backup_state":   "SELECT INSERT UPDATE",
	}
	for _, rel := range execImmutable {
		want[rel] = "SELECT INSERT"
	}
	/* Every relation of every schema the executor can reach: exactly the list, nothing else. */
	requireGrants(t, "nms_executor", want, "exec", "execpub", "core", "backups")

	rows, err := env.Pool("postgres").Query(ctx, `
		SELECT nspname, has_schema_privilege('nms_executor', oid, 'USAGE'), has_schema_privilege('nms_executor', oid, 'CREATE')
		FROM pg_namespace WHERE nspname NOT LIKE 'pg\_%' AND nspname <> 'information_schema'`)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"exec": true, "execpub": true, "core": true, "backups": true}
	n := 0
	for rows.Next() {
		var name string
		var usage, create bool
		if err := rows.Scan(&name, &usage, &create); err != nil {
			t.Fatal(err)
		}
		if create {
			t.Errorf("nms_executor can CREATE in schema %s", name)
		}
		if usage && !allowed[name] && !strings.Contains(name, "timescaledb") {
			t.Errorf("nms_executor has USAGE on schema %s", name)
		}
		if usage && allowed[name] {
			n++
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if n != len(allowed) {
		t.Errorf("nms_executor has USAGE on %d of its %d schemas", n, len(allowed))
	}

	rows, err = env.Pool("postgres").Query(ctx, `
		SELECT format('%I.%I', n.nspname, c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE CASE WHEN c.relkind = 'S' AND n.nspname NOT LIKE '%timescaledb%'
		  THEN has_sequence_privilege('nms_executor', c.oid, 'USAGE, SELECT, UPDATE') END ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	seqs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(seqs, " "); got != "backups.config_version_id_seq exec.audit_event_id_seq exec.model_profile_id_seq exec.session_event_id_seq execpub.alert_id_seq" {
		t.Errorf("nms_executor sequences: %s", got)
	}

	/* Behaviour behind the catalog: the denied core columns and tables really are denied. */
	for _, sql := range []string{
		`SELECT snmp_port FROM core.device`,
		`SELECT * FROM core.device`,
		`UPDATE core.device SET address = '192.0.2.1'`,
		`SELECT password_phc FROM core."user"`,
		`SELECT totp_secret_enc FROM core."user"`,
		`UPDATE core."user" SET disabled = false`,
		`SELECT 1 FROM core.access_profile`,
		`SELECT 1 FROM core.session`,
		`SELECT 1 FROM backups.show_result`,
		`UPDATE backups.config_version SET drift = true`,
		`INSERT INTO backups.config_version (device_id, taken_at, source, sha256, size, masked, full_ct, full_dek_ct)
			VALUES (1, '2000-01-01', 'executor', ` + mac32 + `, 0, '', '\x00', '\x00')`,
		`TRUNCATE exec.write_device`,
		`SELECT 1 FROM audit.event`,
		`SELECT 1 FROM jobs.river_job`,
	} {
		requireDenied(t, "nms_executor", sql)
	}
	exe := env.Pool("nms_executor")
	for _, sql := range []string{
		`SELECT id, name, address, model, firmware, driver, group_id FROM core.device`,
		`SELECT id, username, disabled FROM core."user"`,
		`SELECT * FROM backups.config_version`,
		`SELECT * FROM backups.backup_state`,
	} {
		if _, err := exe.Exec(ctx, sql); err != nil {
			t.Errorf("executor %q: %v", sql, err)
		}
	}
}

func TestExecpubGrantsForAPIAndPoller(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	requireGrants(t, "nms_api", map[string]string{
		"execpub.freeze_request": "INSERT(requested_by)",
		"execpub.alert":          "SELECT", "execpub.device_busy": "SELECT",
		"execpub.session_summary": "SELECT", "execpub.status": "SELECT",
	}, "execpub")
	requireGrants(t, "nms_poller", map[string]string{
		"execpub.device_busy": "SELECT", "execpub.session_summary": "SELECT",
	}, "execpub")
	for _, role := range []string{"nms_eventd", "nms_cli"} {
		requireGrants(t, role, map[string]string{}, "execpub")
	}

	api, exe := env.Pool("nms_api"), env.Pool("nms_executor")
	/*
		A pending request stays one row: repeated requests (a flood) succeed
		without growing it. The api uses ON CONFLICT without a target (a target
		needs SELECT on it, which the api does not get).
	*/
	for i := range 3 {
		if _, err := api.Exec(ctx, `INSERT INTO execpub.freeze_request (requested_by) VALUES ($1) ON CONFLICT DO NOTHING`, 7+i); err != nil {
			t.Fatalf("api freeze request %d: %v", i, err)
		}
	}
	for _, sql := range []string{
		`INSERT INTO execpub.freeze_request (requested_by) VALUES (8) ON CONFLICT (singleton) DO NOTHING`,
		`INSERT INTO execpub.freeze_request (requested_by, at) VALUES (7, '2000-01-01') ON CONFLICT DO NOTHING`,
		`INSERT INTO execpub.freeze_request (singleton, requested_by) VALUES (true, 7) ON CONFLICT DO NOTHING`,
		`INSERT INTO execpub.freeze_request (requested_by) VALUES (7) ON CONFLICT (singleton) DO UPDATE SET requested_by = 7`,
		`INSERT INTO execpub.freeze_request (requested_by) VALUES (7) ON CONFLICT DO NOTHING RETURNING at`,
		`SELECT 1 FROM execpub.freeze_request`,
		`INSERT INTO execpub.alert (kind, severity, text) VALUES ('x', 'info', 'x')`,
		`INSERT INTO execpub.status (enabled, frozen) VALUES (false, false)`,
		`INSERT INTO execpub.device_busy (device_id, session_id) VALUES (1, gen_random_uuid())`,
		`INSERT INTO execpub.session_summary (session_id, user_id, device_id, opened_at, status) VALUES (gen_random_uuid(), 1, 1, now(), 'open')`,
	} {
		requireDenied(t, "nms_api", sql)
	}
	set := map[string]string{"execpub.freeze_request": "requested_by = 1", "execpub.alert": "text = ''",
		"execpub.device_busy": "since = now()", "execpub.session_summary": "closed_at = now()",
		"execpub.status": "frozen = false"}
	for _, rel := range relations(t, "execpub") {
		for _, sql := range []string{"UPDATE " + rel + " SET " + set[rel], "DELETE FROM " + rel, "TRUNCATE " + rel} {
			for _, role := range []string{"nms_api", "nms_poller", "nms_eventd", "nms_cli"} {
				requireDenied(t, role, sql)
			}
		}
	}
	for _, sql := range []string{`SELECT 1 FROM execpub.alert`, `SELECT 1 FROM execpub.status`, `SELECT 1 FROM execpub.freeze_request`,
		`INSERT INTO execpub.freeze_request (requested_by) VALUES (1) ON CONFLICT DO NOTHING`,
		`INSERT INTO execpub.alert (kind, severity, text) VALUES ('x', 'info', 'x')`,
		`INSERT INTO execpub.status (enabled, frozen) VALUES (false, false)`,
		`INSERT INTO execpub.device_busy (device_id, session_id) VALUES (1, gen_random_uuid())`,
		`INSERT INTO execpub.session_summary (session_id, user_id, device_id, opened_at, status) VALUES (gen_random_uuid(), 1, 1, now(), 'open')`} {
		requireDenied(t, "nms_poller", sql)
	}
	for _, sql := range []string{`SELECT 1 FROM execpub.device_busy`, `SELECT 1 FROM execpub.session_summary`} {
		if _, err := env.Pool("nms_poller").Exec(ctx, sql); err != nil {
			t.Errorf("poller %q: %v", sql, err)
		}
	}

	/* The executor consumes requests (read, delete) and publishes everything else. */
	var n int
	if err := exe.QueryRow(ctx, `WITH d AS (DELETE FROM execpub.freeze_request WHERE requested_by = 7 RETURNING 1) SELECT count(*) FROM d`).Scan(&n); err != nil || n != 1 {
		t.Errorf("executor consumes the single freeze request: n %d, err %v", n, err)
	}
	/* Once consumed, the api can ask again. */
	if _, err := api.Exec(ctx, `INSERT INTO execpub.freeze_request (requested_by) VALUES (9) ON CONFLICT DO NOTHING`); err != nil {
		t.Errorf("api freeze request after consumption: %v", err)
	}
	if err := exe.QueryRow(ctx, `WITH d AS (DELETE FROM execpub.freeze_request WHERE requested_by = 9 RETURNING 1) SELECT count(*) FROM d`).Scan(&n); err != nil || n != 1 {
		t.Errorf("second freeze request: n %d, err %v", n, err)
	}
	requireDenied(t, "nms_executor", `INSERT INTO execpub.freeze_request (requested_by) VALUES (1)`)
	requireDenied(t, "nms_executor", `UPDATE execpub.freeze_request SET requested_by = 1`)
	for _, sql := range []string{
		`INSERT INTO execpub.status (enabled, frozen) VALUES (false, true)
			ON CONFLICT (singleton) DO UPDATE SET frozen = excluded.frozen, at = now()`,
		`INSERT INTO execpub.alert (kind, severity, device_id, text) VALUES ('executor_tamper', 'disaster', NULL, 'mac')`,
	} {
		if _, err := exe.Exec(ctx, sql); err != nil {
			t.Errorf("executor %q: %v", sql, err)
		}
	}
	var frozen bool
	if err := api.QueryRow(ctx, `SELECT frozen FROM execpub.status`).Scan(&frozen); err != nil || !frozen {
		t.Errorf("api reads status: frozen %v, err %v", frozen, err)
	}
}

/*
The api's target-less ON CONFLICT DO NOTHING swallows a violation of any
unique index or exclusion constraint of freeze_request: the singleton primary
key must stay the only one (00026), else a request could be dropped silently
while none is pending.
*/
func TestFreezeRequestOnlyUniqueIndex(t *testing.T) {
	var unique, excl int
	if err := testdb.New(t).Pool("postgres").QueryRow(context.Background(), `
		SELECT (SELECT count(*) FROM pg_index WHERE indrelid = 'execpub.freeze_request'::regclass AND indisunique),
		       (SELECT count(*) FROM pg_constraint WHERE conrelid = 'execpub.freeze_request'::regclass AND contype = 'x')`).
		Scan(&unique, &excl); err != nil {
		t.Fatal(err)
	}
	if unique != 1 || excl != 0 {
		t.Fatalf("freeze_request: %d unique indexes, %d exclusion constraints; want only the primary key", unique, excl)
	}
}

/*
Every api INSERT into freeze_request wakes the executor through channel
execpub_freeze, also one that inserted nothing (a request already pending);
the payload is empty: the executor reads the table itself.
*/
func TestFreezeRequestNotifies(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	conn, err := env.Pool("nms_executor").Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `LISTEN execpub_freeze`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = env.Pool("postgres").Exec(context.Background(), `DELETE FROM execpub.freeze_request`)
	})
	for i := range 2 {
		if _, err := env.Pool("nms_api").Exec(ctx, `INSERT INTO execpub.freeze_request (requested_by) VALUES (5) ON CONFLICT DO NOTHING`); err != nil {
			t.Fatal(err)
		}
		wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		n, err := conn.Conn().WaitForNotification(wctx)
		cancel()
		if err != nil {
			t.Fatalf("insert %d: no notification: %v", i, err)
		}
		if n.Channel != "execpub_freeze" || n.Payload != "" {
			t.Fatalf("insert %d: notification %q %q", i, n.Channel, n.Payload)
		}
	}
}

/* insertSession writes one row in each append-only table, as the executor. */
func insertSession(t *testing.T, id string, dev int64) {
	t.Helper()
	exe := testdb.New(t).Pool("nms_executor")
	for _, st := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO exec.session (id, user_id, opened_at, policy_snapshot, mac) VALUES ($1, 1, now(), '{}', ` + mac32 + `)`, []any{id}},
		{`INSERT INTO exec.session_device (session_id, device_id, pre_sha256, pre_ct, pre_dek_ct, mac)
			VALUES ($1, $2, ` + mac32 + `, '\x01', '\x01', ` + mac32 + `)`, []any{id, dev}},
		{`INSERT INTO exec.session_event (session_id, at, kind, payload, mac) VALUES ($1, now(), 'command', '{"line": "x"}', ` + mac32 + `)`, []any{id}},
		{`INSERT INTO exec.recording_chunk (session_id, device_id, n, ct, dek_ct, mac) VALUES ($1, $2, 0, '\x01', '\x01', ` + mac32 + `)`, []any{id, dev}},
		{`INSERT INTO exec.recording_manifest (session_id, device_id, chunks, sha256, mac) VALUES ($1, $2, 1, ` + mac32 + `, ` + mac32 + `)`, []any{id, dev}},
		{`INSERT INTO exec.audit_event (ts, user_id, ip, ua, action, object, result, payload, prev_hash, hash)
			VALUES (now(), 1, '192.0.2.1', 'ua', 'session.open', 'session:' || $1::text, 'ok', '\x00', ` + mac32 + `, ` + mac32 + `)`, []any{id}},
	} {
		if _, err := exe.Exec(context.Background(), st.sql, st.args...); err != nil {
			t.Fatalf("%s: %v", st.sql, err)
		}
	}
}

func TestExecImmutableTablesRejectModificationForEveryRole(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	insertSession(t, "6f1d0000-0000-4000-8000-000000000001", 910001)
	count := func() string {
		var parts []string
		for _, rel := range execImmutable {
			var n int
			if err := env.Pool("postgres").QueryRow(ctx, `SELECT count(*) FROM `+rel).Scan(&n); err != nil {
				t.Fatal(err)
			}
			parts = append(parts, fmt.Sprintf("%s=%d", rel, n))
		}
		return strings.Join(parts, " ")
	}
	before := count()
	col := map[string]string{"exec.audit_event": "hash"}
	for _, rel := range execImmutable {
		c := col[rel]
		if c == "" {
			c = "mac"
		}
		for _, sql := range []string{
			fmt.Sprintf("UPDATE %s SET %s = %s", rel, c, c),
			fmt.Sprintf("UPDATE %s SET %s = %s WHERE false", rel, c, c),
			"DELETE FROM " + rel,
			"TRUNCATE " + rel + " CASCADE",
		} {
			/* The owner and the superuser pass every privilege check: the trigger stops them. */
			for _, role := range []string{"nms_migrator", "postgres", "nms_executor", "nms_api", "nms_poller", "nms_eventd", "nms_cli"} {
				requireDenied(t, role, sql)
			}
		}
	}
	if after := count(); after != before {
		t.Errorf("append-only tables changed: %s -> %s", before, after)
	}

	/* The chain head is the single row that may change, and only by an UPDATE. */
	exe := env.Pool("nms_executor")
	if _, err := exe.Exec(ctx, `UPDATE exec.audit_head SET last_id = last_id, hash = hash`); err != nil {
		t.Errorf("executor update audit_head: %v", err)
	}
	for _, role := range []string{"nms_migrator", "postgres", "nms_executor"} {
		requireDenied(t, role, `DELETE FROM exec.audit_head`)
		requireDenied(t, role, `TRUNCATE exec.audit_head`)
	}
	requireDenied(t, "nms_executor", `INSERT INTO exec.audit_head (singleton, last_id, hash) VALUES (true, 1, `+mac32+`)`)
	owner := env.Pool("nms_migrator")
	_, err := owner.Exec(ctx, `INSERT INTO exec.audit_head (singleton, last_id, hash) VALUES (true, 1, `+mac32+`)`)
	requireCode(t, err, "23505", "second audit_head row")
	_, err = owner.Exec(ctx, `INSERT INTO exec.audit_head (singleton, last_id, hash) VALUES (false, 1, `+mac32+`)`)
	requireCode(t, err, "23514", "non-singleton audit_head row")
	var rows int
	if err := env.Pool("postgres").QueryRow(ctx, `SELECT count(*) FROM exec.audit_head`).Scan(&rows); err != nil || rows != 1 {
		t.Errorf("audit_head rows = %d, err %v", rows, err)
	}
	/*
		audit_event ids come from the identity only: a plain explicit id is refused
		by GENERATED ALWAYS, one with OVERRIDING SYSTEM VALUE by the id guard.
	*/
	_, err = exe.Exec(ctx, `INSERT INTO exec.audit_event (id, ts, action, result, payload, prev_hash, hash)
		VALUES (1, now(), 'x', 'ok', '\x00', `+mac32+`, `+mac32+`)`)
	requireCode(t, err, "428C9", "explicit audit_event id")
	for _, role := range []string{"nms_executor", "nms_migrator"} {
		_, err = env.Pool(role).Exec(ctx, `INSERT INTO exec.audit_event (id, ts, action, result, payload, prev_hash, hash)
			OVERRIDING SYSTEM VALUE VALUES (1000000, now(), 'x', 'ok', '\x00', `+mac32+`, `+mac32+`)`)
		requireCode(t, err, "42501", role+": audit_event id with OVERRIDING SYSTEM VALUE")
	}

	/* Registry rows are the executor's to change, but never by TRUNCATE. */
	for _, sql := range []string{
		`INSERT INTO exec.write_device (device_id, address, write_group, write_driver, version, mac) VALUES (910001, '192.0.2.1', 'g', 'mes6', 1, ` + mac32 + `)`,
		`UPDATE exec.write_device SET port = 2222, version = 2 WHERE device_id = 910001`,
		`DELETE FROM exec.write_device WHERE device_id = 910001`,
	} {
		if _, err := exe.Exec(ctx, sql); err != nil {
			t.Errorf("executor %q: %v", sql, err)
		}
	}
}

func TestExecChecks(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	exe := env.Pool("nms_executor")
	const sid = "6f1d0000-0000-4000-8000-000000000002"
	insertSession(t, sid, 920001)
	/* Every statement runs as the executor; ok rows first, then each bound broken once. */
	ok := []string{
		`INSERT INTO exec.registry_counter (seq, mac) VALUES (0, M)`,
		`INSERT INTO exec.write_device (device_id, address, write_group, write_driver, version, mac) VALUES (920001, '192.0.2.10', 'core-sw', 'mes6', 1, M)`,
		`INSERT INTO exec.write_device (device_id, address, port, write_group, write_driver, hostkey_algo, hostkey_fp, writes_enabled, version, mac)
			VALUES (920002, '2001:db8::1', 65535, 'g.1_a-b', 'esr', 'ssh-ed25519', 'SHA256:' || repeat('A', 43), true, 1, M)`,
		`INSERT INTO exec.write_grant (user_id, kind, write_group, username_snapshot, version, mac) VALUES (920001, 'write', 'core-sw', 'alice', 1, M)`,
		`INSERT INTO exec.write_grant (user_id, kind, write_group, username_snapshot, version, mac) VALUES (920001, 'write', 'edge', 'alice', 1, M)`,
		`INSERT INTO exec.write_grant (user_id, kind, username_snapshot, version, mac) VALUES (920001, 'unmask', 'alice', 1, M)`,
		`INSERT INTO exec.change_totp (user_id, username_snapshot, ciphertext, key_version, version, mac)
			VALUES (920001, repeat('a', 64), repeat('x', 1024)::bytea, 1, 1, M)`,
		`INSERT INTO exec.exec_state ("freeze", freeze_reason, version, mac) VALUES (true, repeat('r', 1024), 1, M)`,
		`INSERT INTO exec.model_profile (write_driver, model_re, firmware_re, strategies, note, version, mac)
			VALUES ('mes10', '^MES53', '^10\.', '{"pager": "off"}', 'bench', 1, M)`,
		`INSERT INTO exec.write_credential (device_id, kind, ciphertext, created_at, nonce, version, mac)
			VALUES (920001, 'ssh_write', repeat('x', 8240)::bytea, now(), decode(repeat('00', 16), 'hex'), 1, M)`,
		`INSERT INTO exec.recording_chunk (session_id, device_id, n, ct, dek_ct, mac) VALUES ('` + sid + `', 920001, 1, repeat('x', 1024 * 1024 + 1024)::bytea, '\x01', M)`,
		`INSERT INTO execpub.alert (kind, severity, device_id, text) VALUES ('hostkey_mismatch_write', 'high', 920001, repeat('t', 1024))`,
		`INSERT INTO execpub.session_summary (session_id, user_id, device_id, opened_at, status) VALUES ('` + sid + `', 1, 920001, now(), 'open')`,
		`INSERT INTO execpub.session_summary (session_id, user_id, device_id, opened_at, closed_at, status, post_sha256)
			VALUES ('` + sid + `', 1, 920002, now(), now(), 'rolled_back', M)`,
		`INSERT INTO execpub.device_busy (device_id, session_id) VALUES (920001, '` + sid + `')`,
	}
	for _, sql := range ok {
		if _, err := exe.Exec(ctx, strings.ReplaceAll(sql, " M)", " "+mac32+")")); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	wd := func(cols, vals string) string {
		return `INSERT INTO exec.write_device (device_id, address, write_group, write_driver, version, mac` + cols + `) VALUES ` + vals
	}
	bad := map[string]string{
		"device id 0":            wd("", `(0, '192.0.2.1', 'g', 'mes6', 1, M)`),
		"port 0":                 wd(", port", `(920010, '192.0.2.1', 'g', 'mes6', 1, M, 0)`),
		"port 65536":             wd(", port", `(920010, '192.0.2.1', 'g', 'mes6', 1, M, 65536)`),
		"telnet":                 wd(", protocol", `(920010, '192.0.2.1', 'g', 'mes6', 1, M, 'telnet')`),
		"unknown driver":         wd("", `(920010, '192.0.2.1', 'g', 'mes7', 1, M)`),
		"network address":        wd("", `(920010, '192.0.2.0/24', 'g', 'mes6', 1, M)`),
		"group with space":       wd("", `(920010, '192.0.2.1', 'core sw', 'mes6', 1, M)`),
		"group uppercase":        wd("", `(920010, '192.0.2.1', 'Core', 'mes6', 1, M)`),
		"group 65 chars":         wd("", `(920010, '192.0.2.1', repeat('g', 65), 'mes6', 1, M)`),
		"algo without fp":        wd(", hostkey_algo", `(920010, '192.0.2.1', 'g', 'mes6', 1, M, 'ssh-rsa')`),
		"unknown algo":           wd(", hostkey_algo, hostkey_fp", `(920010, '192.0.2.1', 'g', 'mes6', 1, M, 'ssh-dss', 'SHA256:' || repeat('A', 43))`),
		"short fp":               wd(", hostkey_algo, hostkey_fp", `(920010, '192.0.2.1', 'g', 'mes6', 1, M, 'ssh-rsa', 'SHA256:' || repeat('A', 42))`),
		"md5 fp":                 wd(", hostkey_algo, hostkey_fp", `(920010, '192.0.2.1', 'g', 'mes6', 1, M, 'ssh-rsa', 'MD5:' || repeat('A', 43))`),
		"writes without hostkey": wd(", writes_enabled", `(920010, '192.0.2.1', 'g', 'mes6', 1, M, true)`),
		"version 0":              wd("", `(920010, '192.0.2.1', 'g', 'mes6', 0, M)`),
		"mac 31 bytes":           `INSERT INTO exec.write_device (device_id, address, write_group, write_driver, version, mac) VALUES (920010, '192.0.2.1', 'g', 'mes6', 1, decode(repeat('00', 31), 'hex'))`,
		"grant kind":             `INSERT INTO exec.write_grant (user_id, kind, username_snapshot, version, mac) VALUES (920002, 'admin', 'bob', 1, M)`,
		"write without group":    `INSERT INTO exec.write_grant (user_id, kind, username_snapshot, version, mac) VALUES (920002, 'write', 'bob', 1, M)`,
		"unmask with group":      `INSERT INTO exec.write_grant (user_id, kind, write_group, username_snapshot, version, mac) VALUES (920002, 'unmask', 'g', 'bob', 1, M)`,
		"empty snapshot":         `INSERT INTO exec.write_grant (user_id, kind, username_snapshot, version, mac) VALUES (920002, 'audit-read', '', 1, M)`,
		"snapshot 65 chars":      `INSERT INTO exec.write_grant (user_id, kind, username_snapshot, version, mac) VALUES (920002, 'audit-read', repeat('b', 65), 1, M)`,
		"totp ct 1025":           `INSERT INTO exec.change_totp (user_id, username_snapshot, ciphertext, key_version, version, mac) VALUES (920002, 'bob', repeat('x', 1025)::bytea, 1, 1, M)`,
		"totp ct empty":          `INSERT INTO exec.change_totp (user_id, username_snapshot, ciphertext, key_version, version, mac) VALUES (920002, 'bob', '\x', 1, 1, M)`,
		"totp key version 0":     `INSERT INTO exec.change_totp (user_id, username_snapshot, ciphertext, key_version, version, mac) VALUES (920002, 'bob', '\x01', 0, 1, M)`,
		"totp last step -1":      `INSERT INTO exec.change_totp (user_id, username_snapshot, ciphertext, key_version, last_step, version, mac) VALUES (920002, 'bob', '\x01', 1, -1, 1, M)`,
		"totp failures -1":       `INSERT INTO exec.change_totp (user_id, username_snapshot, ciphertext, key_version, failures, version, mac) VALUES (920002, 'bob', '\x01', 1, -1, 1, M)`,
		"totp lock count -1":     `INSERT INTO exec.change_totp (user_id, username_snapshot, ciphertext, key_version, lock_count, version, mac) VALUES (920002, 'bob', '\x01', 1, -1, 1, M)`,
		"credential 8241":        `INSERT INTO exec.write_credential (device_id, kind, ciphertext, created_at, nonce, version, mac) VALUES (920002, 'ssh_write', repeat('x', 8241)::bytea, now(), decode(repeat('00', 16), 'hex'), 1, M)`,
		"credential read kind":   `INSERT INTO exec.write_credential (device_id, kind, ciphertext, created_at, nonce, version, mac) VALUES (920002, 'ssh_read', '\x01', now(), decode(repeat('00', 16), 'hex'), 1, M)`,
		"credential nonce 15":    `INSERT INTO exec.write_credential (device_id, kind, ciphertext, created_at, nonce, version, mac) VALUES (920002, 'ssh_write', '\x01', now(), decode(repeat('00', 15), 'hex'), 1, M)`,
		"state not singleton":    `INSERT INTO exec.exec_state (singleton, "freeze", version, mac) VALUES (false, true, 1, M)`,
		"counter not singleton":  `INSERT INTO exec.registry_counter (singleton, seq, mac) VALUES (false, 0, M)`,
		"counter negative":       `INSERT INTO exec.registry_counter (singleton, seq, mac) VALUES (true, -1, M)`,
		"profile array":          `INSERT INTO exec.model_profile (write_driver, model_re, firmware_re, strategies, note, version, mac) VALUES ('esr', 'a', 'b', '[]', 'n', 1, M)`,
		"profile empty note":     `INSERT INTO exec.model_profile (write_driver, model_re, firmware_re, note, version, mac) VALUES ('esr', 'a', 'b', '', 1, M)`,
		"profile model_re 257":   `INSERT INTO exec.model_profile (write_driver, model_re, firmware_re, note, version, mac) VALUES ('esr', repeat('a', 257), 'b', 'n', 1, M)`,
		"profile driver":         `INSERT INTO exec.model_profile (write_driver, model_re, firmware_re, note, version, mac) VALUES ('mes', 'a', 'b', 'n', 1, M)`,
		"session array policy":   `INSERT INTO exec.session (id, user_id, opened_at, policy_snapshot, mac) VALUES (gen_random_uuid(), 1, now(), '[]', M)`,
		"session user 0":         `INSERT INTO exec.session (id, user_id, opened_at, policy_snapshot, mac) VALUES (gen_random_uuid(), 0, now(), '{}', M)`,
		"pre sha 31":             `INSERT INTO exec.session_device (session_id, device_id, pre_sha256, pre_ct, pre_dek_ct, mac) VALUES ('` + sid + `', 920003, decode(repeat('00', 31), 'hex'), '\x01', '\x01', M)`,
		"pre dek empty":          `INSERT INTO exec.session_device (session_id, device_id, pre_sha256, pre_ct, pre_dek_ct, mac) VALUES ('` + sid + `', 920003, M, '\x01', '\x', M)`,
		"pre ct over cap":        `INSERT INTO exec.session_device (session_id, device_id, pre_sha256, pre_ct, pre_dek_ct, mac) VALUES ('` + sid + `', 920003, M, repeat('x', 4 * 1024 * 1024 + 1025)::bytea, '\x01', M)`,
		"event kind":             `INSERT INTO exec.session_event (session_id, at, kind, payload, mac) VALUES ('` + sid + `', now(), 'Bad Kind', '{}', M)`,
		"event payload string":   `INSERT INTO exec.session_event (session_id, at, kind, payload, mac) VALUES ('` + sid + `', now(), 'x', '"x"', M)`,
		"chunk n -1":             `INSERT INTO exec.recording_chunk (session_id, device_id, n, ct, dek_ct, mac) VALUES ('` + sid + `', 920001, -1, '\x01', '\x01', M)`,
		"chunk over cap":         `INSERT INTO exec.recording_chunk (session_id, device_id, n, ct, dek_ct, mac) VALUES ('` + sid + `', 920001, 2, repeat('x', 1024 * 1024 + 1025)::bytea, '\x01', M)`,
		"audit result":           `INSERT INTO exec.audit_event (ts, action, result, payload, prev_hash, hash) VALUES (now(), 'x', 'maybe', '\x00', M, M)`,
		"audit action":           `INSERT INTO exec.audit_event (ts, action, result, payload, prev_hash, hash) VALUES (now(), 'Open Session', 'ok', '\x00', M, M)`,
		"audit prev hash 31":     `INSERT INTO exec.audit_event (ts, action, result, payload, prev_hash, hash) VALUES (now(), 'x', 'ok', '\x00', decode(repeat('00', 31), 'hex'), M)`,
		"audit ua 513":           `INSERT INTO exec.audit_event (ts, action, ua, result, payload, prev_hash, hash) VALUES (now(), 'x', repeat('u', 513), 'ok', '\x00', M, M)`,
		"audit payload over":     `INSERT INTO exec.audit_event (ts, action, result, payload, prev_hash, hash) VALUES (now(), 'x', 'ok', repeat('x', 65537)::bytea, M, M)`,
		"alert severity":         `INSERT INTO execpub.alert (kind, severity, text) VALUES ('x', 'critical', 'x')`,
		"alert text 1025":        `INSERT INTO execpub.alert (kind, severity, text) VALUES ('x', 'high', repeat('t', 1025))`,
		"alert kind":             `INSERT INTO execpub.alert (kind, severity, text) VALUES ('Tamper!', 'high', 'x')`,
		"summary status":         `INSERT INTO execpub.session_summary (session_id, user_id, device_id, opened_at, status) VALUES (gen_random_uuid(), 1, 1, now(), 'done')`,
		"summary closed early":   `INSERT INTO execpub.session_summary (session_id, user_id, device_id, opened_at, closed_at, status) VALUES (gen_random_uuid(), 1, 1, now(), now() - interval '1 s', 'closed')`,
		"summary open closed":    `INSERT INTO execpub.session_summary (session_id, user_id, device_id, opened_at, closed_at, status) VALUES (gen_random_uuid(), 1, 1, now(), now(), 'open')`,
		"summary post sha 31":    `INSERT INTO execpub.session_summary (session_id, user_id, device_id, opened_at, status, post_sha256) VALUES (gen_random_uuid(), 1, 1, now(), 'closed', decode(repeat('00', 31), 'hex'))`,
		"status not singleton":   `INSERT INTO execpub.status (singleton, enabled, frozen) VALUES (false, false, false)`,
		"busy device 0":          `INSERT INTO execpub.device_busy (device_id, session_id) VALUES (0, gen_random_uuid())`,
	}
	for name, sql := range bad {
		_, err := exe.Exec(ctx, strings.ReplaceAll(strings.ReplaceAll(sql, " M)", " "+mac32+")"), " M,", " "+mac32+","))
		requireCode(t, err, "23514", name)
	}
	_, err := exe.Exec(ctx, `INSERT INTO exec.write_grant (user_id, kind, username_snapshot, version, mac) VALUES (920001, 'unmask', 'alice', 1, `+mac32+`)`)
	requireCode(t, err, "23505", "duplicate grant without a group")
	_, err = env.Pool("nms_api").Exec(ctx, `INSERT INTO execpub.freeze_request (requested_by) VALUES (0)`)
	requireCode(t, err, "23514", "freeze request by user 0")
	_, err = exe.Exec(ctx, `INSERT INTO exec.recording_chunk (session_id, device_id, n, ct, dek_ct, mac) VALUES ('`+sid+`', 920099, 5, '\x01', '\x01', `+mac32+`)`)
	requireCode(t, err, "23503", "chunk of a device outside the session")
}

/* Session and executor-scheduler versions come from the executor alone, and the executor writes nothing else. */
func TestConfigVersionSourcesByWriter(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	dev, _ := backupFixture(t, "10.31.0")
	insert := func(role, source string) error {
		_, err := env.Pool(role).Exec(ctx, insertVersion, dev, source, make([]byte, 32), 1, "x", []byte("c"), []byte("d"))
		return err
	}
	executorSources, pollerSources := []string{"pre_session", "post_session", "executor"}, []string{"schedule", "event", "manual"}
	for _, source := range executorSources {
		if err := insert("nms_executor", source); err != nil {
			t.Errorf("executor source %s: %v", source, err)
		}
		requireCode(t, insert("nms_poller", source), "42501", "poller source "+source)
		requireCode(t, insert("nms_migrator", source), "42501", "owner source "+source)
	}
	for _, source := range pollerSources {
		if err := insert("nms_poller", source); err != nil {
			t.Errorf("poller source %s: %v", source, err)
		}
		requireCode(t, insert("nms_executor", source), "42501", "executor source "+source)
	}
	requireCode(t, insert("nms_poller", "auto"), "23514", "unknown source")
	var n int
	if err := env.Pool("postgres").QueryRow(ctx, `SELECT count(*) FROM backups.config_version WHERE device_id = $1`, dev).Scan(&n); err != nil || n != 6 {
		t.Errorf("stored versions = %d, want 6 (err %v)", n, err)
	}
}

/* The executor cannot switch off the guards, and nothing in exec/execpub has another owner or default privileges. */
func TestExecSchemaOwnershipAndTriggerBypass(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	for _, sql := range []string{
		`ALTER TABLE exec.audit_event DISABLE TRIGGER audit_event_append_only`,
		`ALTER TABLE exec.session DISABLE TRIGGER ALL`,
		`ALTER TABLE backups.config_version DISABLE TRIGGER config_version_check_source`,
		`SET session_replication_role = replica`,
	} {
		requireDenied(t, "nms_executor", sql)
	}
	root := env.Pool("postgres")
	rows, err := root.Query(ctx, `
		SELECT format('%I.%I %s', n.nspname, c.relname, r.rolname) FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_roles r ON r.oid = c.relowner
		WHERE n.nspname IN ('exec', 'execpub') AND r.rolname <> 'nms_migrator'
		UNION ALL
		SELECT format('schema %I %s', n.nspname, r.rolname) FROM pg_namespace n JOIN pg_roles r ON r.oid = n.nspowner
		WHERE n.nspname IN ('exec', 'execpub') AND r.rolname <> 'nms_migrator'
		UNION ALL
		SELECT format('function %I.%I %s', n.nspname, p.proname, r.rolname) FROM pg_proc p
		JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_roles r ON r.oid = p.proowner
		WHERE n.nspname IN ('exec', 'execpub') AND r.rolname <> 'nms_migrator'`)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	if len(foreign) > 0 {
		t.Errorf("not owned by nms_migrator: %v", foreign)
	}
	var owned, acls int
	if err := root.QueryRow(ctx, `SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname IN ('exec', 'execpub')`).Scan(&owned); err != nil || owned < 20 {
		t.Errorf("exec/execpub relations = %d: the enumeration is broken (err %v)", owned, err)
	}
	if err := root.QueryRow(ctx, `SELECT count(*) FROM pg_default_acl d JOIN pg_namespace n ON n.oid = d.defaclnamespace
		WHERE n.nspname IN ('exec', 'execpub')`).Scan(&acls); err != nil || acls != 0 {
		t.Errorf("default privileges in exec/execpub = %d (err %v)", acls, err)
	}
}

/*
TestExecMigrationOnPhase3Database applies 00024 to a database migrated to the
end of Phase 3 (00022) that already holds a config version, as an upgrade does.
The database is prepared as deploy/postgres/initdb/10-roles.sh does.
*/
func TestExecMigrationOnPhase3Database(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	const db = "nms_phase3"
	if _, err := env.Pool("postgres").Exec(ctx, `CREATE DATABASE `+db); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = env.Pool("postgres").Exec(context.Background(), `DROP DATABASE IF EXISTS `+db+` WITH (FORCE)`)
	})
	open := func(role string) *pgxpool.Pool {
		c, pw := env.Config(role)
		c.Name = db
		p, err := store.Open(ctx, c, pw)
		if err != nil {
			t.Fatalf("open %s: %v", role, err)
		}
		t.Cleanup(p.Close)
		return p
	}
	root := open("postgres")
	for _, sql := range []string{
		`REVOKE ALL ON DATABASE ` + db + ` FROM PUBLIC`,
		`GRANT CONNECT ON DATABASE ` + db + ` TO nms_migrator, nms_api, nms_cli, nms_poller, nms_eventd, nms_executor`,
		`GRANT CREATE ON DATABASE ` + db + ` TO nms_migrator`,
		`REVOKE ALL ON SCHEMA public FROM PUBLIC`,
		`GRANT USAGE ON SCHEMA public TO nms_migrator`,
		`CREATE EXTENSION IF NOT EXISTS timescaledb`,
		`CREATE SCHEMA core AUTHORIZATION nms_migrator`,
		`CREATE SCHEMA audit AUTHORIZATION nms_migrator`,
	} {
		if _, err := root.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	mc, mpw := env.Config("nms_migrator")
	mc.Name = db
	if err := store.MigrateUpTo(ctx, mc, mpw, 22); err != nil {
		t.Fatalf("migrate to Phase 3: %v", err)
	}
	owner := open("nms_migrator")
	var exists bool
	if err := owner.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname IN ('exec', 'execpub'))`).Scan(&exists); err != nil || exists {
		t.Fatalf("exec schemas before 00024: %v %v", exists, err)
	}
	/* Phase 3 data: a device with a scheduled config version. */
	var dev int64
	if err := owner.QueryRow(ctx, `WITH g AS (INSERT INTO core.device_group (name) VALUES ('p3') RETURNING id)
		INSERT INTO core.device (name, address, group_id) SELECT 'd', '192.0.2.50', id FROM g RETURNING id`).Scan(&dev); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, insertVersion, dev, "schedule", make([]byte, 32), 1, "x", []byte("c"), []byte("d")); err != nil {
		t.Fatal(err)
	}

	if err := store.Migrate(ctx, mc, mpw); err != nil {
		t.Fatalf("migrate Phase 3 database: %v", err)
	}
	want, err := store.LatestVersion()
	if err != nil {
		t.Fatal(err)
	}
	var got int64
	var versions, validated int
	if err := owner.QueryRow(ctx, `SELECT max(version_id) FROM core.goose_db_version`).Scan(&got); err != nil || got != want {
		t.Fatalf("goose version = %d, want %d (err %v)", got, want, err)
	}
	if err := owner.QueryRow(ctx, `SELECT count(*) FROM backups.config_version WHERE source = 'schedule'`).Scan(&versions); err != nil || versions != 1 {
		t.Errorf("Phase 3 config versions = %d, err %v", versions, err)
	}
	if err := owner.QueryRow(ctx, `SELECT count(*) FROM pg_constraint
		WHERE conname = 'config_version_source_check' AND convalidated`).Scan(&validated); err != nil || validated != 1 {
		t.Errorf("validated source check = %d, err %v", validated, err)
	}
	if _, err := open("nms_executor").Exec(ctx, insertVersion, dev, "post_session", make([]byte, 32), 1, "x", []byte("c"), []byte("d")); err != nil {
		t.Errorf("executor post_session version: %v", err)
	}
	var usage bool
	if err := root.QueryRow(ctx, `SELECT has_schema_privilege('nms_api', 'exec', 'USAGE')`).Scan(&usage); err != nil || usage {
		t.Errorf("api USAGE on exec after upgrade: %v %v", usage, err)
	}
}
