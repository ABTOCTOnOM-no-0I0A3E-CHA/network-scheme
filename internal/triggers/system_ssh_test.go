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
		t.Fatal("problem without a pin or mismatch")
	}
	settle := func() {
		for range 3 {
			h.advance(5 * time.Second)
		}
	}
	/* A pinned device whose newest rejection is later than the pin's last use. */
	h.exec(h.poller, `INSERT INTO ssh_hosts.host_key (device_id, algorithm, fingerprint_sha256, last_seen) VALUES ($1, 'ssh-ed25519', 'SHA256:p', now() - interval '1 hour')`, dev)
	settle()
	if problem() {
		t.Fatal("pin without a mismatch opened a problem")
	}
	h.exec(h.poller, `INSERT INTO ssh_hosts.mismatch (device_id, seen_fingerprint, address) VALUES ($1, 'SHA256:x', '10.0.0.1')`, dev)
	h.advance(5 * time.Second)
	if !problem() {
		t.Fatal("mismatch did not open a problem")
	}
	/* Hours pass with no inventory poll (no new rows), and the SNMP side fails: still open, never duplicated. */
	h.exec(h.root, `UPDATE ssh_hosts.mismatch SET at = now() - interval '5 hours'`)
	h.exec(h.root, `UPDATE ssh_hosts.host_key SET last_seen = now() - interval '6 hours'`)
	h.setState(dev, "down", h.clk.Now())
	settle()
	if n := len(h.openProblems(dev)); !problem() || n < 1 {
		t.Fatalf("problem lost without a later successful connection (open=%d)", n)
	}
	/* A later successful connection with the pinned key recovers it (after two evaluations). */
	h.exec(h.poller, `UPDATE ssh_hosts.host_key SET last_seen = now()`)
	h.advance(5 * time.Second)
	if !problem() {
		t.Fatal("resolved after one evaluation")
	}
	h.advance(5 * time.Second)
	if problem() {
		t.Fatal("problem did not recover after a successful connection")
	}
	/* A new rejection reopens it; resetting the pin on the host recovers it. */
	h.exec(h.poller, `INSERT INTO ssh_hosts.mismatch (device_id, seen_fingerprint, address) VALUES ($1, 'SHA256:x', '10.0.0.1')`, dev)
	settle()
	if !problem() {
		t.Fatal("new mismatch did not reopen the problem")
	}
	h.exec(h.root, `DELETE FROM ssh_hosts.host_key`)
	settle()
	if problem() {
		t.Fatal("problem did not recover after the pin was reset")
	}
}

func TestOnlyTheNeededColumnsOfTheHostKeyAndHeartbeatTablesAreReadable(t *testing.T) {
	h := newHarness(t)
	for _, sql := range []string{
		`SELECT seen_fingerprint FROM ssh_hosts.mismatch`,
		`SELECT address FROM ssh_hosts.mismatch`,
		`SELECT * FROM ssh_hosts.host_key`,
		`SELECT fingerprint_sha256 FROM ssh_hosts.host_key`,
		`UPDATE ssh_hosts.host_key SET last_seen = now()`,
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
	for _, sql := range []string{`SELECT device_id, at FROM ssh_hosts.mismatch`, `SELECT device_id, last_seen FROM ssh_hosts.host_key`, `SELECT poller_id, at FROM inventory.poller_heartbeat`} {
		if _, err := h.api.Exec(context.Background(), sql); err != nil {
			t.Errorf("%s as nms_api: %v", sql, err)
		}
	}
}
