package session_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/session"
)

/*
4d.2, security.md 10 (a scripted session): every event of a change session
is an executor audit row — a refusal of the policy (session.open denied,
two_person), a failed change TOTP code (session.open denied, wrong_code),
the opening (session.open ok), a save (session.save), the confirmed
rollback (confirm.session.rollback) and its outcome (session.rollback), the
close (session.close, closed) and a timeout (session.close, timeout).
*/
func TestAuditCoversTheSessionLifecycle(t *testing.T) {
	f := newFx(t)
	u := f.user(t, "core")
	ctx := context.Background()
	rows := func(action, result, key, value string) int {
		return f.count(t, `SELECT count(*) FROM exec.audit_event WHERE action = $1 AND result = $2 AND user_id = $3
			AND ($4 = '' OR convert_from(payload, 'UTF8')::jsonb #>> ARRAY['details', $4] = $5)`, action, result, u.id, key, value)
	}
	f.policy(t, "two_person_groups: [core]\n")
	if _, err := f.m.Open(ctx, f.req(t, u), []int64{f.id}); !errors.Is(err, session.ErrTwoPerson) {
		t.Fatalf("two-person group: %v", err)
	}
	f.policy(t, "")
	wrong := f.req(t, u)
	wrong.Code = "000000"
	if _, err := f.m.Open(ctx, wrong, []int64{f.id}); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("wrong code: %v", err)
	}
	f.az.ResetUser(u.id)

	o := f.open(t, u)
	f.typeLines(t, o, "configure", "hostname edge-7", "end")
	res, err := f.m.Act(ctx, o.ID, o.Token, "diff", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	dd := res.([]session.DeviceDiff)[0]
	if _, err := f.m.Act(ctx, o.ID, o.Token, "save", json.RawMessage(fmt.Sprintf(`{"device_id":%d,"sha256":%q}`, f.id, dd.SHA256))); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := f.rollback(t, u, o, nil); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if err := f.m.Close(ctx, o.ID, o.Token); err != nil {
		t.Fatal(err)
	}
	f.free(t, "closed")
	o = f.open(t, u)
	f.offset.Add(int64(10*time.Minute + time.Second))
	f.m.Check(ctx)
	if f.status(t, o.ID) != "timeout" {
		t.Fatalf("idle: %s", f.status(t, o.ID))
	}
	for _, c := range []struct {
		action, result, key, value string
		want                       int
	}{
		{"session.open", "denied", "class", "two_person", 1},
		{"session.open", "denied", "class", "wrong_code", 1},
		{"session.open", "ok", "", "", 3}, /* authz accepts the code of the two-person refusal too */
		{"session.save", "ok", "device_id", fmt.Sprint(f.id), 1},
		{"confirm.session.rollback", "ok", "", "", 1},
		{"session.rollback", "ok", "", "", 1},
		{"session.close", "ok", "reason", "closed", 1},
		{"session.close", "ok", "reason", "timeout", 1},
	} {
		if n := rows(c.action, c.result, c.key, c.value); n != c.want {
			t.Errorf("%s %s %s=%s: %d rows, want %d", c.action, c.result, c.key, c.value, n, c.want)
		}
	}
}
