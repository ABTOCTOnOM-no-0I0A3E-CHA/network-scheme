package eventd

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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
	if out, _ := encodeVarbinds([]trap.Varbind{{OID: "1.3", Type: "OctetString", Value: "a<b>&c"}}); !strings.Contains(string(out), "a<b>&c") {
		t.Errorf("HTML characters escaped: %s", out)
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
	q := newQueue(3, 1<<20)
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
	/* datagrams are written only as the INFORM acknowledgement: exactly one call site */
	writes := 0
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
			if strings.HasPrefix(sel.Sel.Name, "WriteTo") || strings.HasPrefix(sel.Sel.Name, "WriteMsg") {
				writes++
				if filepath.Base(f) != "server.go" || sel.Sel.Name != "WriteToUDPAddrPort" {
					t.Errorf("%s: unexpected datagram write %s", f, sel.Sel.Name)
				}
			}
			return true
		})
	}
	if writes != 1 {
		t.Errorf("%d datagram write call sites, want exactly the INFORM reply", writes)
	}
}

func TestClassifyErrors(t *testing.T) {
	for err, want := range map[error]errClass{
		&pgconn.PgError{Code: "23514"}:         errData,
		&pgconn.PgError{Code: "22021"}:         errData,
		&pgconn.PgError{Code: "57P01"}:         errTransient,
		&pgconn.PgError{Code: "57014"}:         errUnknown,
		&pgconn.PgError{Code: "53300"}:         errTransient,
		context.DeadlineExceeded:               errTransient,
		io.ErrUnexpectedEOF:                    errTransient,
		&net.OpError{Op: "write", Err: io.EOF}: errTransient,
		errors.New("cannot encode chan int"):   errUnknown,
	} {
		if got := classify(err); got != want {
			t.Errorf("%v: class %d, want %d", err, got, want)
		}
	}
}

/* A deterministic client-side error does not hold the batch forever: retried a few times, then row by row. */
func TestDeterministicClientErrorFallsBackToRows(t *testing.T) {
	h := newHarness(t)
	st := &stats{}
	w := &writer{pool: h.pool, st: st, log: slog.New(slog.NewTextHandler(io.Discard, nil)), size: 10, wait: time.Second, retryBase: time.Millisecond}
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.table(context.Background(), "syslog", syslogCols, [][]any{
			{time.Now(), int64(1), int16(1), int16(1), "h", "a", make(chan int), int32(1)},
			{time.Now(), int64(1), int16(1), int16(1), "h", "a", "fine", int32(1)},
		})
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the batch is retried forever")
	}
	if n := h.count(`SELECT count(*) FROM events.syslog`); n != 1 || st.rejected.Load() != 1 {
		t.Errorf("%d rows stored, %d rejected, want 1 and 1", n, st.rejected.Load())
	}
}

/* A failed enqueue must not start the 30 s throttle; a successful one does; old entries are pruned. */
func TestPollTriggerThrottlesOnlyAfterSuccess(t *testing.T) {
	h := newHarness(t)
	clk := &clock{t: time.Now()}
	enq := &flakyEnq{failFirst: true, called: make(chan struct{}, 10)}
	p := newPollTrigger(enq, clk.now)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.run(ctx, h.pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	wait := func() {
		t.Helper()
		select {
		case <-enq.called:
		case <-time.After(5 * time.Second):
			t.Fatal("enqueue not called")
		}
	}
	p.request(7)
	wait() /* fails */
	eventually(t, 5*time.Second, "request settled", func() bool { p.mu.Lock(); defer p.mu.Unlock(); return !p.pending[7] })
	p.request(7)
	wait() /* not throttled by the failure; succeeds */
	eventually(t, 5*time.Second, "request settled", func() bool { p.mu.Lock(); defer p.mu.Unlock(); return !p.pending[7] && !p.last[7].IsZero() })
	p.request(7)
	select {
	case <-enq.called:
		t.Error("second request inside 30 s was queued")
	case <-time.After(300 * time.Millisecond):
	}
	clk.add(31 * time.Second)
	p.request(7)
	wait()
	eventually(t, 5*time.Second, "settled", func() bool { p.mu.Lock(); defer p.mu.Unlock(); return !p.pending[7] })
	clk.add(31 * time.Second)
	p.done(8, false) /* any completion prunes */
	p.mu.Lock()
	n := len(p.last)
	p.mu.Unlock()
	if n != 0 {
		t.Errorf("%d stale throttle entries", n)
	}
}

type flakyEnq struct {
	mu        sync.Mutex
	failFirst bool
	called    chan struct{}
}

func (f *flakyEnq) EnqueuePollNow(context.Context, pgx.Tx, int64) error {
	f.mu.Lock()
	fail := f.failFirst
	f.failFirst = false
	f.mu.Unlock()
	f.called <- struct{}{}
	if fail {
		return errors.New("boom")
	}
	return nil
}

/* A writer that never finishes and max-size traps cannot grow the queue past its byte budget, nor the heap past a bound. */
func TestQueueByteBudgetBoundsMemory(t *testing.T) {
	const budget = 8 << 20
	q := newQueue(10_000, budget)
	oid := strings.TrimSuffix(strings.Repeat("1.", trap.MaxOIDSubIDs), ".")
	vs := make([]trap.Varbind, trap.MaxVarbinds)
	for i := range vs {
		vs[i] = trap.Varbind{OID: oid, Type: "OctetString", Value: strings.Repeat("a", trap.MaxValueLen)}
	}
	vb, _ := encodeVarbinds(vs)
	if len(vb) > maxVarbindsJSON {
		t.Fatalf("serialized %d bytes, limit %d", len(vb), maxVarbindsJSON)
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	var kept [][]byte /* every event owns its bytes, as a decoded trap does */
	accepted, dropped := 0, 0
	for range 5_000 { /* 5000 x ~15 KiB = 75 MiB offered to an 8 MiB budget */
		own := append([]byte(nil), vb...)
		if q.push(event{kind: kindTrap, trapOID: "1.3.6.1.4.1.1", name: "x", varbinds: own}) {
			accepted++
			kept = append(kept, own)
		} else {
			dropped++
		}
		if q.usedBytes() > budget {
			t.Fatalf("queue holds %d bytes, budget %d", q.usedBytes(), budget)
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	if dropped == 0 || accepted == 0 || accepted*len(vb) > budget {
		t.Errorf("accepted %d dropped %d", accepted, dropped)
	}
	if grown := int64(after.HeapAlloc) - int64(before.HeapAlloc); grown > 2*budget {
		t.Errorf("heap grew by %d bytes, budget %d", grown, budget)
	}
	runtime.KeepAlive(kept)
	/* the batch in flight keeps its bytes until the writer releases it */
	batch, _ := q.next(100, time.Millisecond)
	if q.usedBytes() <= budget-int64(len(batch))*int64(len(vb)) {
		t.Errorf("bytes of the batch in flight were returned early: %d", q.usedBytes())
	}
	q.release(batch)
	if !q.push(event{kind: kindTrap, varbinds: vb}) {
		t.Error("released budget not reusable")
	}
}
