package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/testdb"
)

func TestJobQueueSchema(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	var n int
	if err := env.Pool("nms_migrator").QueryRow(ctx, `SELECT count(*) FROM pg_tables
		WHERE schemaname = 'jobs' AND tablename IN ('river_job', 'river_leader', 'river_queue', 'river_migration')`).Scan(&n); err != nil || n != 4 {
		t.Fatalf("river tables in jobs = %d, %v", n, err)
	}
	/* Nothing of River lands in public. */
	if err := env.Pool("nms_migrator").QueryRow(ctx, `SELECT count(*) FROM pg_tables WHERE tablename LIKE 'river%' AND schemaname <> 'jobs'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("river tables outside jobs = %d, %v", n, err)
	}
	insert := `INSERT INTO jobs.river_job (args, kind, max_attempts, queue, state) VALUES ('{}', 'probe', 1, 'probe', 'available') RETURNING id`
	var id int64
	if err := env.Pool("nms_api").QueryRow(ctx, insert).Scan(&id); err != nil {
		t.Fatalf("api insert: %v", err)
	}
	/* The api only enqueues: it cannot change, delete or take over jobs. */
	for _, sql := range []string{
		`UPDATE jobs.river_job SET state = 'completed'`,
		`UPDATE jobs.river_job SET args = '{}'`,
		`DELETE FROM jobs.river_job`,
		`INSERT INTO jobs.river_leader (leader_id, name, elected_at, expires_at) VALUES ('x', 'default', now(), now())`,
		`DELETE FROM jobs.river_migration`,
		`TRUNCATE jobs.river_job`,
	} {
		requireDenied(t, "nms_api", sql)
	}
	for _, sql := range []string{`SELECT 1 FROM jobs.river_job`, insert} {
		requireDenied(t, "nms_cli", sql)
	}
	requireDenied(t, "nms_poller", `DELETE FROM jobs.river_migration`)
	/* The poller works the queue. */
	if _, err := env.Pool("nms_poller").Exec(ctx, `UPDATE jobs.river_job SET state = 'completed', finalized_at = now() WHERE id = $1`, id); err != nil {
		t.Fatalf("poller update: %v", err)
	}
	if _, err := env.Pool("nms_poller").Exec(ctx, `DELETE FROM jobs.river_job WHERE id = $1`, id); err != nil {
		t.Fatalf("poller delete: %v", err)
	}
}

func TestDeviceChangeNotifies(t *testing.T) {
	env := testdb.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := env.Pool("nms_poller").Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `LISTEN device_changed`); err != nil {
		t.Fatal(err)
	}
	api := env.Pool("nms_api")
	var g, d int64
	if err := api.QueryRow(ctx, `INSERT INTO core.device_group (name) VALUES ('notify-'||gen_random_uuid()) RETURNING id`).Scan(&g); err != nil {
		t.Fatal(err)
	}
	if err := api.QueryRow(ctx, `INSERT INTO core.device (name, address, group_id) VALUES ('n', '198.51.100.77', $1) RETURNING id`, g).Scan(&d); err != nil {
		t.Fatal(err)
	}
	wait := func(what string) {
		t.Helper()
		if _, err := conn.Conn().WaitForNotification(ctx); err != nil {
			t.Fatalf("%s: no notification: %v", what, err)
		}
	}
	wait("insert")
	for _, c := range []struct{ what, sql string }{
		{"device update", `UPDATE core.device SET interval_avail_s = 60 WHERE id = $1`},
		{"group update", `UPDATE core.device_group SET interval_metrics_s = 120 WHERE id = (SELECT group_id FROM core.device WHERE id = $1)`},
		{"device delete", `DELETE FROM core.device WHERE id = $1`},
	} {
		if _, err := api.Exec(ctx, c.sql, d); err != nil {
			t.Fatalf("%s: %v", c.what, err)
		}
		wait(c.what)
	}
}
