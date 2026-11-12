package terminal_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/terminal"
)

/*
4d.2, security.md 10 (a scripted terminal): every classified line is an
executor audit row (session.command) with its device, class and the masked
normalized line: a denied line (result denied), a safe one, a dangerous one
held for its confirmation and its confirmation (confirm.session.line), and
a control line handed to its flow; the secret of a typed line is masked.
*/
func TestEveryLineIsAudited(t *testing.T) {
	t.Cleanup(terminal.Unlimited())
	f := newFx(t)
	l := lines[0]
	c := f.dial(t, l.id)
	if res := c.line("delete flash:nms-pre-s1"); res["type"] != "refused" || res["code"] != "denied" {
		t.Fatalf("snapshot name: %v", res)
	}
	f.mustSend(t, c, l.id, l.cfg)
	f.mustSend(t, c, l.id, "interface "+l.mgmtIf)
	if res := c.do("keys", "description nms-test\r"); len(res) != 1 || res[0]["type"] != "dangerous" {
		t.Fatalf("dangerous: %v", res)
	}
	if res := f.confirm(t, c, f.issue(t, c), f.names[l.id], f.newCode(t)); len(res) != 1 || res[0]["type"] != "output" {
		t.Fatalf("confirmed: %v", res)
	}
	f.mustSend(t, c, l.id, "end")
	if res := c.line("write"); res["type"] != "flow" && res["type"] != "refused" {
		t.Fatalf("control: %v", res)
	}
	if res := c.do("keys", "enable password Secr3tPw9\r"); len(res) != 1 || res[0]["type"] != "dangerous" {
		t.Fatalf("secret line: %v", res)
	}
	rows := func(result, class string) int {
		return count(t, f, `SELECT count(*) FROM exec.audit_event WHERE action = $1 AND result = $2 AND user_id = $3
			AND convert_from(payload, 'UTF8')::jsonb #>> '{details,class}' = $4 AND convert_from(payload, 'UTF8')::jsonb #>> '{details,device_id}' = $5`,
			terminal.CommandAction, result, f.u.id, class, fmt.Sprint(l.id))
	}
	for _, w := range []struct {
		result, class string
		want          int
	}{{"denied", "denied", 1}, {"ok", "safe", 3}, {"ok", "dangerous", 2}, {"ok", "control", 1}} {
		if n := rows(w.result, w.class); n != w.want {
			t.Errorf("session.command %s %s: %d rows, want %d", w.result, w.class, n, w.want)
		}
	}
	if n := count(t, f, `SELECT count(*) FROM exec.audit_event WHERE action = 'confirm.session.line' AND result = 'ok'`); n != 1 {
		t.Errorf("%d confirm.session.line rows", n)
	}
	if n := count(t, f, `SELECT count(*) FROM exec.audit_event WHERE convert_from(payload, 'UTF8') LIKE '%Secr3tPw9%'`); n != 0 {
		t.Errorf("the typed secret is in %d audit rows", n)
	}
}

func count(t *testing.T, f *fx, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := f.env.Pool("postgres").QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
