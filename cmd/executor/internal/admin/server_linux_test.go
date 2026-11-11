package admin

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"errors"
	"github.com/beekamai/network-scheme/internal/execadmin"
	"syscall"
)

/* serveOn starts a server on a fresh short socket path that accepts uid and returns the path. */
func serveOn(t *testing.T, uid int, handled *atomic.Int32, refused *atomic.Int32) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "exs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "admin.sock")
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{Path: path, UID: uid, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Handle: func(_ context.Context, req execadmin.Request) execadmin.Response {
			handled.Add(1)
			return execadmin.Response{OK: true, Text: req.Cmd}
		},
		Refused: func(string, int) { refused.Add(1) }}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil { /* a cancelled server returns nil */
			t.Errorf("Serve: %v", err)
		}
	})
	for range 100 {
		if _, err := os.Stat(path); err == nil {
			return path
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("socket not created")
	return ""
}

func call(t *testing.T, path string) execadmin.Response {
	t.Helper()
	line, err := Call(context.Background(), path, []byte(`{"v":1,"cmd":"registry-verify"}`+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	var resp execadmin.Response
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

/* The socket is 0600 and serves a peer of its own uid (SO_PEERCRED). */
func TestSocketServesItsOwnUID(t *testing.T) {
	var handled, refused atomic.Int32
	path := serveOn(t, os.Getuid(), &handled, &refused)
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 || st.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket mode %v %v", st.Mode(), err)
	}
	if resp := call(t, path); !resp.OK || resp.Text != "registry-verify" || handled.Load() != 1 || refused.Load() != 0 {
		t.Fatalf("resp %+v handled %d refused %d", resp, handled.Load(), refused.Load())
	}
}

/* A process of any other uid (root included) is refused before its request is read, and the refusal is reported for the audit. */
func TestSocketRefusesAnotherUID(t *testing.T) {
	var handled, refused atomic.Int32
	path := serveOn(t, os.Getuid()+1, &handled, &refused)
	/*
		The server closes a foreign peer's connection without reading: the client may see the refusal answer, or the
		closed socket while it still writes its request (broken pipe, reset) or reads (EOF). All of them are a refusal.
	*/
	line, err := Call(context.Background(), path, []byte(`{"v":1,"cmd":"registry-verify"}`+"\n"))
	switch {
	case err == nil:
		var resp execadmin.Response
		if jerr := json.Unmarshal(line, &resp); jerr != nil || resp.OK {
			t.Fatalf("answer %q (%v)", line, jerr)
		}
	case errors.Is(err, syscall.EPIPE), errors.Is(err, syscall.ECONNRESET), errors.Is(err, io.EOF):
	default:
		t.Fatalf("call: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for refused.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if handled.Load() != 0 || refused.Load() != 1 {
		t.Fatalf("handled %d refused %d", handled.Load(), refused.Load())
	}
}
