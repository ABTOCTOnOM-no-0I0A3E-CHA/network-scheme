package store_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/beekamai/network-scheme/internal/testdb"
)

func requireCode(t *testing.T, err error, code, what string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Errorf("%s: want SQLSTATE %s, got %v", what, code, err)
	}
}

func TestDeviceParentCycleAndDepth(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	api := env.Pool("nms_api")
	var g int64
	if err := api.QueryRow(ctx, `INSERT INTO core.device_group (name) VALUES ('tree') RETURNING id`).Scan(&g); err != nil {
		t.Fatal(err)
	}
	add := func(i int, parent *int64) int64 {
		var id int64
		err := api.QueryRow(ctx, `INSERT INTO core.device (name, address, group_id, parent_id) VALUES ('n', $1::inet, $2, $3) RETURNING id`,
			fmt.Sprintf("10.9.%d.%d", i/200, i%200+1), g, parent).Scan(&id)
		if err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
		return id
	}
	a := add(1, nil)
	b := add(2, &a)
	c := add(3, &b)
	_, err := api.Exec(ctx, `UPDATE core.device SET parent_id = $1 WHERE id = $2`, c, a)
	requireCode(t, err, "23514", "cycle a->c")
	_, err = api.Exec(ctx, `UPDATE core.device SET parent_id = id WHERE id = $1`, a)
	requireCode(t, err, "23514", "self parent")

	/* A chain of 16 devices is allowed, the 17th level is rejected. */
	last := c
	for i := 4; i <= 16; i++ {
		last = add(i, &last)
	}
	_, err = api.Exec(ctx, `INSERT INTO core.device (name, address, group_id, parent_id) VALUES ('n', '10.9.250.1', $1, $2)`, g, last)
	requireCode(t, err, "23514", "17th level")
	/* Grafting the 16-chain under another node also exceeds the depth. */
	x := add(100, nil)
	_, err = api.Exec(ctx, `UPDATE core.device SET parent_id = $1 WHERE id = $2`, x, a)
	requireCode(t, err, "23514", "graft deep subtree")

	/* Deleting the parent orphans the children. */
	if _, err := api.Exec(ctx, `DELETE FROM core.device WHERE id = $1`, b); err != nil {
		t.Fatal(err)
	}
	var p *int64
	if err := api.QueryRow(ctx, `SELECT parent_id FROM core.device WHERE id = $1`, c).Scan(&p); err != nil || p != nil {
		t.Fatalf("child parent after delete = %v, %v", p, err)
	}
	/* The api can set and clear the parent. */
	if _, err := api.Exec(ctx, `UPDATE core.device SET parent_id = $1 WHERE id = $2`, x, c); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Exec(ctx, `UPDATE core.device SET parent_id = NULL WHERE id = $1`, c); err != nil {
		t.Fatal(err)
	}
}

func requireDenied2(t *testing.T, err error, what string) {
	t.Helper()
	requireCode(t, err, "42501", what)
}

func TestMonitoringTemplateConstraints(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	api := env.Pool("nms_api")
	var g int64
	if err := api.QueryRow(ctx, `INSERT INTO core.device_group (name) VALUES ('tpl') RETURNING id`).Scan(&g); err != nil {
		t.Fatal(err)
	}
	var seeded int
	if err := api.QueryRow(ctx, `SELECT count(*) FROM core.trigger t JOIN core.monitoring_template m ON m.id = t.template_id
		WHERE m.driver IN ('generic-snmp', 'eltex-mes', 'eltex-esr')`).Scan(&seeded); err != nil || seeded != 9 {
		t.Fatalf("seeded triggers = %d, %v", seeded, err)
	}
	_, err := api.Exec(ctx, `INSERT INTO core.monitoring_template (name) VALUES ('neither')`)
	requireCode(t, err, "23514", "template without target")
	_, err = api.Exec(ctx, `INSERT INTO core.monitoring_template (name, driver, group_id) VALUES ('both', 'x', $1)`, g)
	requireCode(t, err, "23514", "template with both targets")
	var tpl int64
	if err := api.QueryRow(ctx, `INSERT INTO core.monitoring_template (name, group_id) VALUES ('ok', $1) RETURNING id`, g).Scan(&tpl); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		`INSERT INTO core.trigger (template_id, kind, severity, name) VALUES ($1, 'regex', 'high', 'x')`,
		`INSERT INTO core.trigger (template_id, kind, severity, name) VALUES ($1, 'trap', 'urgent', 'x')`,
		`INSERT INTO core.trigger (template_id, kind, severity, name, duration_s) VALUES ($1, 'trap', 'high', 'x', 86401)`,
		`INSERT INTO core.trigger (template_id, kind, severity, name, params) VALUES ($1, 'trap', 'high', 'x', '[]')`,
		`INSERT INTO core.trigger (template_id, kind, severity, name, params) VALUES ($1, 'trap', 'high', 'x', jsonb_build_object('a', repeat('x', 5000)))`,
	} {
		_, err := api.Exec(ctx, sql, tpl)
		requireCode(t, err, "23514", sql)
	}
	_, err = api.Exec(ctx, `INSERT INTO core.maintenance_window (group_id, starts_at, ends_at) VALUES ($1, now(), now())`, g)
	requireCode(t, err, "23514", "empty window")
	_, err = api.Exec(ctx, `INSERT INTO core.maintenance_window (group_id, starts_at, ends_at)
		VALUES ($1, now(), now() + interval '7 days 1 second')`, g)
	requireCode(t, err, "23514", "window over 7 days")
	if _, err := api.Exec(ctx, `INSERT INTO core.maintenance_window (group_id, starts_at, ends_at)
		VALUES ($1, now(), now() + interval '7 days')`, g); err != nil {
		t.Errorf("7 day window: %v", err)
	}

	/* Template and trigger ids come from the sequence only, and are not reused. */
	for _, sql := range []string{
		`INSERT INTO core.monitoring_template (id, name, driver) OVERRIDING SYSTEM VALUE VALUES (900001, 'e', 'x')`,
		`INSERT INTO core.trigger (id, template_id, kind, severity, name) OVERRIDING SYSTEM VALUE VALUES (900001, $1, 'trap', 'high', 'x')`,
	} {
		var err error
		if strings.Contains(sql, "$1") {
			_, err = api.Exec(ctx, sql, tpl)
		} else {
			_, err = api.Exec(ctx, sql)
		}
		requireDenied2(t, err, sql)
	}
	var trg int64
	if err := api.QueryRow(ctx, `INSERT INTO core.trigger (template_id, kind, severity, name) VALUES ($1, 'trap', 'high', 'x') RETURNING id`, tpl).Scan(&trg); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Exec(ctx, `DELETE FROM core.trigger WHERE id = $1`, trg); err != nil {
		t.Fatal(err)
	}
	_, err = api.Exec(ctx, `INSERT INTO core.trigger (id, template_id, kind, severity, name) OVERRIDING SYSTEM VALUE VALUES ($2, $1, 'trap', 'high', 'x')`, tpl, trg)
	requireDenied2(t, err, "reuse of a deleted trigger id")
	if _, err := api.Exec(ctx, `INSERT INTO core.maintenance_window (group_id, starts_at, ends_at, comment)
		VALUES ($1, now(), now() + interval '1 hour', 'x')`, g); err != nil {
		t.Fatal(err)
	}
}

func TestProblemOpenKeyUniqueness(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	api := env.Pool("nms_api")
	var g, dev, trg int64
	if err := api.QueryRow(ctx, `INSERT INTO core.device_group (name) VALUES ('pdev') RETURNING id`).Scan(&g); err != nil {
		t.Fatal(err)
	}
	if err := api.QueryRow(ctx, `INSERT INTO core.device (name, address, group_id) VALUES ('p', '10.8.0.1', $1) RETURNING id`, g).Scan(&dev); err != nil {
		t.Fatal(err)
	}
	if err := api.QueryRow(ctx, `SELECT id FROM core.trigger LIMIT 1`).Scan(&trg); err != nil {
		t.Fatal(err)
	}
	open := func(trigger *int64, kind *string, device *int64, object string) error {
		_, err := api.Exec(ctx, `INSERT INTO problems.problem (trigger_id, system_kind, device_id, object, severity)
			VALUES ($1, $2, $3, $4, 'high')`, trigger, kind, device, object)
		return err
	}
	if err := open(&trg, nil, &dev, ""); err != nil {
		t.Fatal(err)
	}
	requireCode(t, open(&trg, nil, &dev, ""), "23505", "duplicate open trigger problem")
	if err := open(&trg, nil, &dev, "if:3"); err != nil {
		t.Fatalf("other object: %v", err)
	}
	/* System problems without a device: NULLs compare equal in the key. */
	pk := "poller_unavailable"
	if err := open(nil, &pk, nil, "poller:a"); err != nil {
		t.Fatal(err)
	}
	requireCode(t, open(nil, &pk, nil, "poller:a"), "23505", "duplicate open system problem")
	if err := open(nil, &pk, nil, "poller:b"); err != nil {
		t.Fatalf("other poller: %v", err)
	}
	if err := open(&trg, nil, &dev, "if:2147483647"); err != nil {
		t.Fatalf("max if index: %v", err)
	}
	/* A resolved problem frees the key. */
	if _, err := api.Exec(ctx, `UPDATE problems.problem SET state = 'resolved', resolved_at = now(), resolve_reason = 'recovered'
		WHERE trigger_id = $1 AND object = ''`, trg); err != nil {
		t.Fatal(err)
	}
	if err := open(&trg, nil, &dev, ""); err != nil {
		t.Fatalf("reopen after resolve: %v", err)
	}
	bad := "Bad Kind"
	for name, err := range map[string]error{
		"no source":          open(nil, nil, &dev, ""),
		"both sources":       open(&trg, &pk, &dev, ""),
		"trigger no device":  open(&trg, nil, nil, ""),
		"trigger bad object": open(&trg, nil, &dev, "poller:a"),
		"if index zero":      open(&trg, nil, &dev, "if:0"),
		"if index leading 0": open(&trg, nil, &dev, "if:012"),
		"if index over max":  open(&trg, nil, &dev, "if:2147483648"),
		"bad system kind":    open(nil, &bad, nil, ""),
		"object over 200":    open(nil, &pk, nil, strings.Repeat("x", 201)),
		"resolved no time": func() error {
			_, e := api.Exec(ctx, `INSERT INTO problems.problem (system_kind, severity, state) VALUES ('x', 'high', 'resolved')`)
			return e
		}(),
		"acknowledged no time": func() error {
			_, e := api.Exec(ctx, `INSERT INTO problems.problem (system_kind, severity, state) VALUES ('x', 'high', 'acknowledged')`)
			return e
		}(),
		"bad severity": func() error {
			_, e := api.Exec(ctx, `INSERT INTO problems.problem (system_kind, severity) VALUES ('x', 'urgent')`)
			return e
		}(),
		"resolution time without state": func() error {
			_, e := api.Exec(ctx, `INSERT INTO problems.problem (system_kind, severity, resolved_at) VALUES ('x', 'high', now())`)
			return e
		}(),
	} {
		requireCode(t, err, "23514", name)
	}
}

func TestAckIsInsertOnly(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	api := env.Pool("nms_api")
	var pid int64
	if err := api.QueryRow(ctx, `INSERT INTO problems.problem (system_kind, severity) VALUES ('ack_test', 'high') RETURNING id`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Exec(ctx, `INSERT INTO problems.ack (problem_id, user_id, comment) VALUES ($1, 1, 'looking')`, pid); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Exec(ctx, `SELECT id, problem_id, user_id, comment, at FROM problems.ack`); err != nil {
		t.Fatal(err)
	}
	_, err := api.Exec(ctx, `INSERT INTO problems.ack (problem_id, user_id, comment, at) VALUES ($1, 1, 'x', '2000-01-01')`, pid)
	requireCode(t, err, "42501", "explicit at")
	_, err = api.Exec(ctx, `INSERT INTO problems.ack (problem_id, user_id, comment) VALUES ($1, 1, '')`, pid)
	requireCode(t, err, "23514", "empty comment")
	_, err = api.Exec(ctx, `INSERT INTO problems.ack (problem_id, user_id, comment) VALUES ($1, 1, repeat('x', 1001))`, pid)
	requireCode(t, err, "23514", "comment over 1000")
	for _, sql := range []string{
		`UPDATE problems.ack SET comment = 'x'`,
		`DELETE FROM problems.ack`,
		`TRUNCATE problems.ack`,
	} {
		requireDenied(t, "nms_api", sql)
	}
	/* Not even the owner can modify the history. */
	owner := env.Pool("nms_migrator")
	for _, sql := range []string{`UPDATE problems.ack SET comment = 'x'`, `DELETE FROM problems.ack`, `TRUNCATE problems.ack`} {
		_, err := owner.Exec(ctx, sql)
		requireCode(t, err, "42501", "owner "+sql)
	}
}

func TestProblemsAndTemplateGrantsByRole(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	if _, err := env.Pool("nms_poller").Exec(ctx, `SELECT id, name, driver, group_id, interval_avail_s FROM core.monitoring_template`); err != nil {
		t.Errorf("poller select template: %v", err)
	}
	for _, role := range []string{"nms_poller", "nms_eventd"} {
		for _, sql := range []string{
			`SELECT 1 FROM problems.problem`,
			`SELECT 1 FROM problems.ack`,
			`SELECT 1 FROM problems.engine_state`,
			`INSERT INTO problems.engine_state (name, watermark) VALUES ('x', now())`,
			`SELECT 1 FROM core.trigger`,
			`SELECT 1 FROM core.trigger_override`,
			`SELECT 1 FROM core.maintenance_window`,
		} {
			requireDenied(t, role, sql)
		}
	}
	for _, sql := range []string{
		`INSERT INTO core.monitoring_template (name, driver) VALUES ('p', 'x')`,
		`UPDATE core.monitoring_template SET name = 'p'`,
		`DELETE FROM core.monitoring_template`,
	} {
		requireDenied(t, "nms_poller", sql)
	}
	requireDenied(t, "nms_eventd", `SELECT 1 FROM core.monitoring_template`)

	api := env.Pool("nms_api")
	for _, sql := range []string{
		`INSERT INTO problems.engine_state (name, watermark) VALUES ('events', now())`,
		`UPDATE problems.engine_state SET watermark = now()`,
		`SELECT 1 FROM problems.problem`,
		`DELETE FROM core.trigger_override`,
	} {
		if _, err := api.Exec(ctx, sql); err != nil {
			t.Errorf("api: %q: %v", sql, err)
		}
	}
	requireDenied(t, "nms_api", `DELETE FROM problems.problem WHERE false`)
	requireDenied(t, "nms_api", `CREATE TABLE problems.x (id int)`)
}
