package triggers_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestSSHHostKeyMismatchProblem(t *testing.T) {
	h := newHarness(t)
	dev := h.newDevice(onPoller("px"))
	h.heartbeat("px")
	problem := func() bool {
		for _, p := range h.openProblems(dev) {
			if p.Sys == "ssh_host_key_mismatch" {
				return true
			}
		}
		return false
	}
	h.step()
	if problem() {
		t.Fatal("problem without a mismatch")
	}
	h.exec(h.poller, `INSERT INTO ssh_hosts.mismatch (device_id, seen_fingerprint, address) VALUES ($1, 'SHA256:x', '10.0.0.1')`, dev)
	h.advance(5 * time.Second)
	if !problem() {
		t.Fatal("mismatch did not open a problem")
	}
	/* The poller keeps retrying: rows keep coming, the problem stays and is not duplicated. */
	h.exec(h.poller, `INSERT INTO ssh_hosts.mismatch (device_id, seen_fingerprint, address) VALUES ($1, 'SHA256:x', '10.0.0.1')`, dev)
	h.advance(5 * time.Second)
	if n := len(h.openProblems(dev)); n != 1 {
		t.Fatalf("open problems = %d", n)
	}
	/* The pin was reset and no new rejection arrived for longer than the window: it recovers after two evaluations. */
	h.exec(h.root, `UPDATE ssh_hosts.mismatch SET at = now() - interval '2 hours'`)
	h.advance(5 * time.Second)
	h.advance(5 * time.Second)
	if problem() {
		t.Fatal("problem did not recover")
	}
}

func TestOnlyTheNeededColumnsOfTheHostKeyAndHeartbeatTablesAreReadable(t *testing.T) {
	h := newHarness(t)
	for _, sql := range []string{
		`SELECT seen_fingerprint FROM ssh_hosts.mismatch`,
		`SELECT address FROM ssh_hosts.mismatch`,
		`SELECT * FROM ssh_hosts.host_key`,
		`INSERT INTO ssh_hosts.mismatch (device_id, seen_fingerprint, address) VALUES (1, 'SHA256:x', '10.0.0.1')`,
		`INSERT INTO inventory.poller_heartbeat (poller_id, at) VALUES ('evil', now())`,
		`UPDATE inventory.poller_heartbeat SET at = now()`,
	} {
		_, err := h.api.Exec(context.Background(), sql)
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "42501" {
			t.Errorf("%s as nms_api: %v, want permission denied", sql, err)
		}
	}
	for _, sql := range []string{`SELECT device_id, at FROM ssh_hosts.mismatch`, `SELECT poller_id, at FROM inventory.poller_heartbeat`} {
		if _, err := h.api.Exec(context.Background(), sql); err != nil {
			t.Errorf("%s as nms_api: %v", sql, err)
		}
	}
}
