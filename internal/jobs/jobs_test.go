package jobs_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/jobs"
	"github.com/beekamai/network-scheme/internal/testdb"
)

func TestMain(m *testing.M) { testdb.Main(m) }

func TestQueueNames(t *testing.T) {
	for id, want := range map[string]string{"local": "poller_local", "site-2": "poller_site-2", "a_b9": "poller_a_b9"} {
		if got, err := jobs.Queue(id); err != nil || got != want {
			t.Errorf("Queue(%q) = %q, %v", id, got, err)
		}
	}
	for _, id := range []string{"", "Local", "a b", "x;y", "-a", string(make([]byte, 65))} {
		if _, err := jobs.Queue(id); err == nil {
			t.Errorf("Queue(%q) accepted", id)
		}
	}
}

func TestEnqueuePollNowCoalesces(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	api := env.Pool("nms_api")
	var g, d int64
	if err := api.QueryRow(ctx, `INSERT INTO core.device_group (name) VALUES ('jobs-'||gen_random_uuid()) RETURNING id`).Scan(&g); err != nil {
		t.Fatal(err)
	}
	if err := api.QueryRow(ctx, `INSERT INTO core.device (name, address, group_id) VALUES ('j', '198.51.100.90', $1) RETURNING id`, g).Scan(&d); err != nil {
		t.Fatal(err)
	}
	enq, err := jobs.NewEnqueuer(api)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := pgx.BeginFunc(ctx, api, func(tx pgx.Tx) error { return enq.EnqueuePollNow(ctx, tx, d) }); err != nil {
			t.Fatalf("enqueue as nms_api: %v", err)
		}
	}
	var n int
	var queue string
	if err := env.Pool("nms_poller").QueryRow(ctx, `SELECT count(*), min(queue) FROM jobs.river_job
		WHERE kind = 'poll_now' AND (args->>'device_id')::bigint = $1`, d).Scan(&n, &queue); err != nil {
		t.Fatal(err)
	}
	if n != 1 || queue != "poller_local" {
		t.Fatalf("jobs = %d in %q, want 1 in poller_local", n, queue)
	}
	/* A rolled-back transaction leaves no job behind. */
	_ = pgx.BeginFunc(ctx, api, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM core.device WHERE id = -1`); err != nil {
			return err
		}
		return enq.EnqueuePollNow(ctx, tx, -1)
	})
	if err := env.Pool("nms_poller").QueryRow(ctx, `SELECT count(*) FROM jobs.river_job WHERE (args->>'device_id')::bigint = -1`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("job for a missing device: %d, %v", n, err)
	}
}
