package triggers_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/metrics"
	"github.com/beekamai/network-scheme/internal/notify"
	"github.com/beekamai/network-scheme/internal/triggers"
	"github.com/beekamai/network-scheme/internal/triggers/metricsrc"
)

/* backupCalls collects the backups the engine asked for. */
type backupCalls struct {
	mu   sync.Mutex
	devs []int64
}

func (b *backupCalls) hook(_ context.Context, id int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.devs = append(b.devs, id)
	return nil
}

func (b *backupCalls) count(id int64) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, d := range b.devs {
		if d == id {
			n++
		}
	}
	return n
}

func (h *harness) withBackups() *backupCalls {
	calls := &backupCalls{}
	h.eng = triggers.New(triggers.Config{Pool: h.api, Samples: metricsrc.Source{Store: metrics.NewStore(h.api)}, Channels: []notify.Channel{notify.Panel{Hub: h.hub}},
		Clock: h.clk, BackupNow: calls.hook})
	h.step() /* stream watermarks */
	return calls
}

/* A storm of configuration-change events (traps and syslog) asks for one backup per device and BackupGap. */
func TestConfigChangeEventsRequestOneBackupPer5Min(t *testing.T) {
	h := newHarness(t)
	calls := h.withBackups()
	dev, other := h.newDevice(), h.newDevice()
	h.step()
	for i := range 60 {
		h.writeTrap(dev, h.clk.Now(), "entConfigChange", 0)
		h.writeSyslog(dev, h.clk.Now(), 5, "Configuration changed by admin")
		if i%2 == 0 {
			h.writeTrap(dev, h.clk.Now(), "config_changed", 0)
		}
	}
	h.step()
	h.advance(5 * time.Second)
	if n := calls.count(dev); n != 1 {
		t.Fatalf("storm: %d backups requested, want 1", n)
	}
	if n := calls.count(other); n != 0 {
		t.Fatalf("quiet device: %d backups requested", n)
	}
	/* Within the gap another event changes nothing. */
	h.advance(2 * time.Minute)
	h.writeSyslog(dev, h.clk.Now(), 6, "configuration saved")
	h.advance(5 * time.Second)
	if n := calls.count(dev); n != 1 {
		t.Fatalf("event inside the gap: %d requests, want 1", n)
	}
	/* After the gap the next event is served. */
	h.advance(4 * time.Minute)
	h.writeTrap(dev, h.clk.Now(), "entConfigChange", 0)
	h.advance(5 * time.Second)
	if n := calls.count(dev); n != 2 {
		t.Fatalf("event after the gap: %d requests, want 2", n)
	}
	/* Noise does not trigger: debug-level messages and other trap names. */
	h.writeSyslog(other, h.clk.Now(), 7, "configuration changed")
	h.writeSyslog(other, h.clk.Now(), 5, "interface up")
	h.writeTrap(other, h.clk.Now(), "linkDown", 1)
	h.advance(5 * time.Second)
	if n := calls.count(other); n != 0 {
		t.Fatalf("unrelated events requested %d backups", n)
	}
}

/* config_drift opens for a drift version, stays acknowledged-open, and resolves after 24 h or when a clean newer version appears. */
func TestConfigDriftProblem(t *testing.T) {
	h := newHarness(t)
	dev, quiet := h.newDevice(onPoller("px")), h.newDevice(onPoller("px"))
	h.heartbeat("px")
	insert := func(d int64, sha byte, drift bool) {
		sum := make([]byte, 32)
		sum[0] = sha
		h.exec(h.poller, `INSERT INTO backups.config_version (device_id, source, sha256, size, masked, full_ct, full_dek_ct, drift)
			VALUES ($1, 'schedule', $2, 1, 'x', '\x00', '\x00', $3)`, d, sum, drift)
	}
	has := func(d int64) *prob {
		for _, p := range h.openProblems(d) {
			if p.Sys == "config_drift" {
				return &p
			}
		}
		return nil
	}
	settle := func() {
		for range 3 {
			h.advance(5 * time.Second)
		}
	}
	insert(dev, 1, false) /* the baseline is not drift */
	insert(quiet, 9, false)
	settle()
	if has(dev) != nil {
		t.Fatal("baseline opened config_drift")
	}
	insert(dev, 2, true)
	settle()
	p := has(dev)
	if p == nil {
		t.Fatal("drift version did not open config_drift")
	}
	if p.Object != "config" || has(quiet) != nil {
		t.Fatalf("problem %+v / quiet device has one: %v", p, has(quiet))
	}
	var sev string
	if err := h.api.QueryRow(h.ctx, `SELECT severity FROM problems.problem WHERE id = $1`, p.ID).Scan(&sev); err != nil || sev != "warning" {
		t.Fatalf("severity = %q, %v", sev, err)
	}
	/* Acknowledged: stays open. */
	h.exec(h.root, `UPDATE problems.problem SET state = 'acknowledged', acknowledged_at = now() WHERE id = $1`, p.ID)
	settle()
	if has(dev) == nil {
		t.Fatal("acknowledged config_drift disappeared")
	}
	/* A newer clean version resolves it. */
	insert(dev, 3, false)
	settle()
	if has(dev) != nil {
		t.Fatal("config_drift stayed open after a non-drift version")
	}
	/* Drift again, then 24 h pass. */
	insert(dev, 4, true)
	settle()
	if has(dev) == nil {
		t.Fatal("second drift did not open a problem")
	}
	h.advance(24*time.Hour + time.Minute)
	settle()
	if has(dev) != nil {
		t.Fatal("config_drift stayed open after 24 h")
	}
}
