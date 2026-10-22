package eventd

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/events/trap"
)

func TestEncodeVarbindsFitsAndTruncates(t *testing.T) {
	oid := strings.TrimSuffix(strings.Repeat("1.", trap.MaxOIDSubIDs), ".")
	mk := func(n int, val string) []trap.Varbind {
		vs := make([]trap.Varbind, n)
		for i := range vs {
			vs[i] = trap.Varbind{OID: oid, Type: "OctetString", Value: val}
		}
		return vs
	}
	/* small: everything is kept, no marker */
	out, dropped := encodeVarbinds(mk(3, "x"))
	var got []map[string]any
	if err := json.Unmarshal(out, &got); err != nil || len(got) != 3 || dropped != 0 {
		t.Fatalf("small: %v len=%d dropped=%d", err, len(got), dropped)
	}
	/* worst case of the limits: 128 varbinds, 128 sub-ids, 2 KiB values of characters that JSON escapes */
	for _, val := range []string{strings.Repeat("a", trap.MaxValueLen), strings.Repeat(`"`, trap.MaxValueLen), strings.Repeat("\t", trap.MaxValueLen), strings.Repeat("é", trap.MaxValueLen/2)} {
		out, dropped := encodeVarbinds(mk(trap.MaxVarbinds, val))
		if len(out) > maxVarbindsJSON {
			t.Fatalf("serialized %d bytes, limit %d", len(out), maxVarbindsJSON)
		}
		var arr []map[string]any
		if err := json.Unmarshal(out, &arr); err != nil {
			t.Fatalf("not JSON: %v", err)
		}
		if dropped == 0 {
			continue
		}
		last := arr[len(arr)-1]
		if int(last["truncated_varbinds"].(float64)) != dropped || len(arr)-1+dropped != trap.MaxVarbinds || last["oid"] != oid {
			t.Errorf("marker %v, kept %d, dropped %d", last, len(arr)-1, dropped)
		}
	}
}

func TestWorstCaseVarbindsPassTheTableCheck(t *testing.T) {
	h := newHarness(t)
	oid := strings.TrimSuffix(strings.Repeat("1.", trap.MaxOIDSubIDs), ".")
	vs := make([]trap.Varbind, trap.MaxVarbinds)
	for i := range vs {
		vs[i] = trap.Varbind{OID: oid, Type: "OctetString", Value: strings.Repeat(`"`, trap.MaxValueLen)}
	}
	vb, dropped := encodeVarbinds(vs)
	if dropped == 0 {
		t.Fatal("expected a truncation")
	}
	w := &writer{pool: h.pool, st: &stats{}, log: slog.New(slog.NewTextHandler(io.Discard, nil)), size: 10, wait: time.Second}
	w.write(context.Background(), []event{{kind: kindTrap, ts: time.Now(), dev: 1, version: 2, trapOID: "1.3.6.1.4.1.1", name: "x", varbinds: vb}})
	if n := h.count(`SELECT count(*) FROM events.trap`); n != 1 || w.st.rejected.Load() != 0 {
		t.Errorf("worst-case row: %d stored, %d rejected", n, w.st.rejected.Load())
	}
}

func TestOneBadRowNeverFailsTheBatch(t *testing.T) {
	h := newHarness(t)
	st := &stats{}
	w := &writer{pool: h.pool, st: st, log: slog.New(slog.NewTextHandler(io.Discard, nil)), size: 10, wait: time.Second}
	now := time.Now()
	ok := func(msg string) event {
		return event{kind: kindSyslog, ts: now, dev: 1, facility: 1, severity: 1, host: "h", app: "a", msg: msg, rawLen: 10}
	}
	bad := ok("nul \x00 byte") /* the text type cannot hold NUL */
	long := ok("fine")         /* breaks the CHECK on host */
	long.host = strings.Repeat("h", 1025)
	w.write(context.Background(), []event{ok("one"), bad, ok("two"), long, ok("three"),
		{kind: kindTrap, ts: now, dev: 1, version: 2, trapOID: "1", name: "n", varbinds: []byte(`[]`)},
		{kind: kindTrap, ts: now, dev: 1, version: 2, trapOID: "1", name: "bad json", varbinds: []byte(`{"a": "\u0000"}`)},
		{kind: kindStorm, ts: now, dev: 1, stormKind: "syslog", count: 5},
	})
	if n := h.count(`SELECT count(*) FROM events.syslog`); n != 3 {
		t.Errorf("%d syslog rows, want the 3 good ones", n)
	}
	if n := h.count(`SELECT count(*) FROM events.trap`); n != 1 {
		t.Errorf("%d trap rows, want 1", n)
	}
	if n := h.count(`SELECT count(*) FROM events.storm`); n != 1 {
		t.Errorf("%d storm rows, want 1", n)
	}
	if st.rejected.Load() != 3 || st.dropped.Load() != 3 {
		t.Errorf("rejected %d dropped %d, want 3 and 3", st.rejected.Load(), st.dropped.Load())
	}
}

/* The queue is bounded, never blocks the receivers, and hands over batches by size or time. */
func TestQueueBoundsAndBatches(t *testing.T) {
	q := newQueue(3)
	for i := range 3 {
		if !q.push(event{dev: int64(i)}) {
			t.Fatalf("push %d refused", i)
		}
	}
	if q.push(event{}) {
		t.Error("push into a full queue succeeded")
	}
	b, ok := q.next(2, time.Hour)
	if !ok || len(b) != 2 {
		t.Fatalf("batch of %d", len(b))
	}
	b, ok = q.next(10, 50*time.Millisecond)
	if !ok || len(b) != 1 {
		t.Fatalf("time-bounded batch of %d", len(b))
	}
	q.close()
	if _, ok := q.next(10, time.Second); ok {
		t.Error("closed empty queue returned a batch")
	}
}

func TestLimiterTokenBucket(t *testing.T) {
	l := newLimiter(200, 400)
	now := time.Now()
	n := 0
	for range 1000 {
		if l.allow(1, now) {
			n++
		}
	}
	if n != 400 {
		t.Errorf("burst allowed %d, want 400", n)
	}
	if !l.allow(2, now) {
		t.Error("another source shares the bucket")
	}
	if l.allow(1, now.Add(2*time.Millisecond)) { /* 0.4 token */
		t.Error("refilled too fast")
	}
	n = 0
	for range 1000 {
		if l.allow(1, now.Add(time.Second)) {
			n++
		}
	}
	if n < 199 || n > 201 {
		t.Errorf("refill allowed %d in a second, want 200", n)
	}
}

/*
eventd opens no outgoing connection of its own: the code has no dialer, HTTP
client or process execution. The database (pgx) and the INFORM acknowledgement
(a reply on the already open socket) are the only traffic out.
*/
func TestNoOutgoingConnectionsInCode(t *testing.T) {
	forbidden := map[string]map[string]bool{
		"net":        {"Dial": true, "DialTimeout": true, "DialTCP": true, "DialUDP": true, "DialIP": true, "DialUnix": true, "Dialer": true},
		"crypto/tls": {"Dial": true, "DialWithDialer": true, "Dialer": true},
	}
	bannedImports := []string{"net/http", "net/rpc", "net/smtp", "os/exec", "net/url"}
	var files []string
	for _, dir := range []string{".", filepath.Join("..", "..", "cmd", "eventd")} {
		m, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range m {
			if !strings.HasSuffix(f, "_test.go") {
				files = append(files, f)
			}
		}
	}
	if len(files) < 8 {
		t.Fatalf("only %d source files found", len(files))
	}
	for _, f := range files {
		src, err := os.ReadFile(f) // #nosec G304 -- fixed paths
		if err != nil {
			t.Fatal(err)
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		names := map[string]string{} /* local import name -> path */
		for _, imp := range af.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, b := range bannedImports {
				if p == b {
					t.Errorf("%s imports %s", f, p)
				}
			}
			n := p[strings.LastIndex(p, "/")+1:]
			if imp.Name != nil {
				n = imp.Name.Name
			}
			names[n] = p
		}
		ast.Inspect(af, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && forbidden[names[id.Name]][sel.Sel.Name] {
				t.Errorf("%s uses %s.%s", f, id.Name, sel.Sel.Name)
			}
			if strings.HasPrefix(sel.Sel.Name, "Dial") {
				t.Errorf("%s calls %s", f, sel.Sel.Name)
			}
			return true
		})
	}
}
