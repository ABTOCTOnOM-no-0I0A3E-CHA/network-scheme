package terminal_test

import (
	"context"
	"encoding/hex"
	"errors"
	"maps"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/terminal"
)

/* dangerous types a dangerous line on dev (in an interface of the management context) and issues its challenge. */
func (f *fx) dangerous(t *testing.T, c *client) map[string]any {
	t.Helper()
	if res := c.do("keys", "description nms-test\r"); len(res) != 1 || res[0]["type"] != "dangerous" {
		t.Fatalf("not held: %v", res)
	}
	return f.issue(t, c)
}

/*
RULING R8 and the group re-check: a dangerous line's H binds the registry's
address and port; when the write_device row moves the device to another
address or write group between the challenge and the confirmation, the line
is refused (changed) and the device gets nothing.
*/
func TestDangerousLineBoundToTheRegistryDevice(t *testing.T) {
	t.Cleanup(terminal.Unlimited())
	f := newFx(t)
	l := lines[0]
	c := f.dial(t, l.id)
	f.mustSend(t, c, l.id, l.cfg)
	f.mustSend(t, c, l.id, "interface "+l.mgmtIf)
	before := f.typed(l.id)
	orig := maps.Clone(f.rows[l.id])
	for _, change := range []map[string]any{{"address": netip.MustParseAddr("192.0.2.99")}, {"port": 2222}, {"write_group": "edge"}} {
		f.az.ResetUser(f.u.id)
		ch := f.dangerous(t, c)
		row := maps.Clone(orig)
		maps.Copy(row, change)
		f.put(t, "write_device", row)
		res := f.confirm(t, c, ch, f.names[l.id], f.newCode(t))
		f.put(t, "write_device", orig)
		if len(res) != 1 || res[0]["code"] != "changed" || f.typed(l.id) != before {
			t.Fatalf("%v: %v, device got %d lines", change, res, f.typed(l.id)-before)
		}
	}
	/* unchanged: sent */
	res := f.confirm(t, c, f.dangerous(t, c), f.names[l.id], f.newCode(t))
	if len(res) != 1 || res[0]["type"] != "output" || f.typed(l.id) != before+1 {
		t.Fatalf("unchanged: %v", res)
	}
}

/* A dangerous line dropped (Ctrl-C) or refused for the name discards its challenge: it can no longer be confirmed. */
func TestDroppedDangerousLineDiscardsItsChallenge(t *testing.T) {
	t.Cleanup(terminal.Unlimited())
	f := newFx(t)
	l := lines[0]
	c := f.dial(t, l.id)
	f.mustSend(t, c, l.id, l.cfg)
	f.mustSend(t, c, l.id, "interface "+l.mgmtIf)
	before := f.typed(l.id)
	spentLater := func(ch map[string]any) {
		t.Helper()
		h, _ := hex.DecodeString(ch["h"].(string))
		_, _, err := f.cs.Confirm(context.Background(), ch["challenge_id"].(string), h, authz.Request{Ticket: f.ticket(t), Code: f.newCode(t)})
		if !errors.Is(err, authz.ErrDenied) {
			t.Fatalf("a dropped challenge confirms later: %v", err)
		}
	}
	ch := f.dangerous(t, c)
	c.do("keys", "\x03")
	spentLater(ch)
	ch = f.dangerous(t, c)
	if res := f.confirm(t, c, ch, "sw-other", f.newCode(t)); len(res) != 1 || res[0]["code"] != "device_name" {
		t.Fatalf("wrong name: %v", res)
	}
	spentLater(ch)
	if f.typed(l.id) != before {
		t.Fatal("a dropped dangerous line reached the device")
	}
}

/* Connections waiting for their auth frame are bounded per client address; an authenticated terminal no longer counts. */
func TestPreauthConnectionsAreBounded(t *testing.T) {
	f := newFx(t)
	c := f.dial(t, lines[0].id) /* authenticated: not waiting */
	for range terminal.MaxPreauthIP {
		ws, _, err := f.dialRaw(t, f.srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ws.CloseNow() })
	}
	if _, resp, err := f.dialRaw(t, f.srv.URL); err == nil || resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("over the pre-auth bound: %v", err)
	}
	f.mustSend(t, c, lines[0].id, "show running-config")
}

/* The recording gets a line's whole masked answer even when the browser's bound cuts it (M-4). */
func TestRecordingBeforeTheBrowserBounds(t *testing.T) {
	t.Cleanup(terminal.SetMaxOutput(16))
	f := newFx(t)
	l := lines[0]
	long := strings.Repeat("x", 200)
	f.terms[l.id].D.BeforeReply(func(string) (string, time.Duration) { return long, 0 })
	c := f.dial(t, l.id)
	res := c.do("keys", "show clock\r")
	if len(res) == 0 || res[0]["limited"] != true || len(res[0]["text"].(string)) > 16 {
		t.Fatalf("browser: %v", res)
	}
	f.rec.mu.Lock()
	defer f.rec.mu.Unlock()
	if len(f.rec.in) != 1 || f.rec.in[0] != "show clock" || len(f.rec.out) != 1 || !strings.Contains(f.rec.out[0], long) {
		t.Fatalf("recorded %q / %q", f.rec.in, f.rec.out)
	}
}
