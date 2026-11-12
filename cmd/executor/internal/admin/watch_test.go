package admin_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/internal/execadmin"
)

/*
4d.2: the background verification of the whole audit chain catches what
only a full verification shows — a rewritten row, a truncated tail with its
exec.audit_head rewound, an AFTER trigger added to exec.audit_event, the
append-only trigger disabled — and freezes with the executor_tamper disaster
alert, as nmsctl executor audit verify does. An intact chain does nothing.
*/
func TestBackgroundAuditVerificationFreezesOnABreak(t *testing.T) {
	for name, c := range map[string]struct{ sql, reason string }{
		"intact": {"", ""},
		"rewritten row": {`ALTER TABLE exec.audit_event DISABLE TRIGGER audit_event_append_only;
			UPDATE exec.audit_event SET payload = convert_to(replace(convert_from(payload, 'UTF8'), 'tester', 'mallory'), 'UTF8')
				WHERE id = (SELECT min(id) + 1 FROM exec.audit_event);
			ALTER TABLE exec.audit_event ENABLE TRIGGER audit_event_append_only`, "hash mismatch"},
		"truncation": {`ALTER TABLE exec.audit_event DISABLE TRIGGER audit_event_append_only;
			DELETE FROM exec.audit_event WHERE id > (SELECT max(id) - 2 FROM exec.audit_event);
			ALTER TABLE exec.audit_event ENABLE TRIGGER audit_event_append_only;
			UPDATE exec.audit_head SET (last_id, hash) = (SELECT id, hash FROM exec.audit_event ORDER BY id DESC LIMIT 1)`, "anchor missing"},
		"after trigger": {`CREATE TRIGGER sneaky AFTER INSERT ON exec.audit_event FOR EACH ROW EXECUTE FUNCTION core.guard_identity_id()`,
			"audit tables changed"},
		"append-only off": {`ALTER TABLE exec.audit_event DISABLE TRIGGER audit_event_append_only`, "audit tables changed"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			for range 4 {
				if resp := f.do(execadmin.Request{Cmd: "registry-verify"}); !resp.OK {
					t.Fatal(resp.Error)
				}
			}
			if c.sql != "" {
				/* the schema outlives the test's data (attacktest.Reset): put the triggers back */
				t.Cleanup(func() {
					attacktest.Tamper(t, f.env, `DROP TRIGGER IF EXISTS sneaky ON exec.audit_event;
						ALTER TABLE exec.audit_event ENABLE TRIGGER audit_event_append_only`)
				})
				attacktest.Tamper(t, f.env, c.sql)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				defer close(done)
				f.admin.WatchAudit(ctx, 20*time.Millisecond)
			}()
			deadline := time.Now().Add(10 * time.Second)
			if c.sql == "" {
				deadline = time.Now().Add(500 * time.Millisecond)
			}
			for time.Now().Before(deadline) {
				if frozen, _ := f.guard.Frozen(); frozen {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			cancel()
			<-done
			frozen, reason := f.guard.Frozen()
			alerts := f.count(t, `SELECT count(*) FROM execpub.alert WHERE kind = 'executor_tamper' AND severity = 'disaster'`)
			switch {
			case c.sql == "" && (frozen || alerts != 0):
				t.Fatalf("an intact chain froze: %s", reason)
			case c.sql != "" && (!frozen || !strings.Contains(reason, c.reason) || alerts == 0):
				t.Fatalf("frozen %v (%q), %d disaster alerts; want %q", frozen, reason, alerts, c.reason)
			}
		})
	}
}
