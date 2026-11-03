/*
Package admin is the executor's host-only administration: a unix socket in
the container's tmpfs (/run/executor/admin.sock, mode 0600 in a 0700
directory of uid 65533) that accepts a connection only from a process of
the executor's own uid (SO_PEERCRED), one JSON request line per connection
(execadmin), answered with one JSON response line. The only way to it is
docker compose exec -T executor /executor admin on the host (nmsctl
executor …): nothing listens on a network for it, the api and the gateway
have no route to it, and every command writes a row of the executor's audit
chain (security.md 4 TB6, 5.1a, 10).
*/
package admin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/beekamai/network-scheme/internal/execadmin"
)

/* SocketPath is where the daemon listens (tmpfs: /run/executor in compose). */
const SocketPath = "/run/executor/admin.sock"

/* ExecutorUID is the executor's uid (image and compose): the only peer the socket accepts. */
const ExecutorUID = 65533

/* Bounds of one connection: concurrent connections, the request line's wait, the command's run. */
const (
	maxConns       = 4
	requestTimeout = 30 * time.Second
	commandTimeout = 2 * time.Minute
)

/* Server serves the administration socket. */
type Server struct {
	Path   string /* socket path (SocketPath) */
	UID    int    /* the only peer uid accepted (ExecutorUID) */
	Handle func(ctx context.Context, req execadmin.Request) execadmin.Response
	Log    *slog.Logger
	/* Refused, if set, is called for a connection of a wrong uid or a request that cannot be read, for the audit. */
	Refused func(reason string, uid int)
}

/*
Serve listens on the socket until ctx ends. A stale socket file is
replaced; the socket is made 0600 before the first accept. Each connection
is served in its own goroutine, at most maxConns at once (more are refused
at once, without an audit row: only the log). Serve returns only after every
command in flight ended, so the caller may wipe the keys afterwards.
*/
func (s *Server) Serve(ctx context.Context) error {
	if err := os.Remove(s.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("admin socket: %w", err)
	}
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "unix", s.Path)
	if err != nil {
		return fmt.Errorf("admin socket: %w", err)
	}
	if err := os.Chmod(s.Path, 0o600); err != nil {
		_ = l.Close()
		return fmt.Errorf("admin socket: %w", err)
	}
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	slots := make(chan struct{}, maxConns)
	var running sync.WaitGroup
	defer running.Wait()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				_ = os.Remove(s.Path)
				return nil
			}
			s.Log.Error("admin socket: accept", slog.Any("err", err))
			time.Sleep(100 * time.Millisecond)
			continue
		}
		select {
		case slots <- struct{}{}:
			running.Go(func() {
				defer func() { <-slots }()
				s.serve(ctx, c)
			})
		default:
			s.Log.Warn("admin socket: too many connections")
			_ = c.SetWriteDeadline(time.Now().Add(time.Second))
			_ = writeResponse(c, execadmin.Response{Error: "too many administration connections"})
			_ = c.Close()
		}
	}
}

func (s *Server) refuse(c net.Conn, reason string, uid int) {
	s.Log.Warn("admin socket: connection refused", slog.String("reason", reason), slog.Int("uid", uid))
	if s.Refused != nil {
		s.Refused(reason, uid)
	}
	_ = c.SetWriteDeadline(time.Now().Add(time.Second))
	_ = writeResponse(c, execadmin.Response{Error: reason})
	_ = c.Close()
}

/* serve answers one connection: peer check, one request line, one response line. */
func (s *Server) serve(ctx context.Context, c net.Conn) {
	uid, err := peerUID(c)
	if err != nil || uid != s.UID {
		s.refuse(c, "the administration socket accepts only the executor's own uid (docker compose exec executor)", uid)
		return
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(requestTimeout))
	req, err := readRequest(c)
	if err != nil {
		s.Log.Warn("admin socket: bad request", slog.Any("err", err))
		if s.Refused != nil {
			s.Refused(err.Error(), uid)
		}
		_ = writeResponse(c, execadmin.Response{Error: err.Error()})
		return
	}
	cctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	_ = c.SetDeadline(time.Now().Add(commandTimeout + requestTimeout))
	resp := s.Handle(cctx, req)
	if err := writeResponse(c, resp); err != nil {
		s.Log.Error("admin socket: write response", slog.Any("err", err))
	}
}

/* readRequest reads one line of at most MaxRequest bytes and decodes it strictly (an unknown field is an error). */
func readRequest(r io.Reader) (execadmin.Request, error) {
	var req execadmin.Request
	line, err := bufio.NewReaderSize(io.LimitReader(r, execadmin.MaxRequest+1), execadmin.MaxRequest+1).ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) || len(line) > execadmin.MaxRequest {
			return req, errors.New("request too large")
		}
		return req, errors.New("request: one JSON line expected")
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.More() {
		return req, errors.New("request: malformed JSON")
	}
	return req, nil
}

func writeResponse(w io.Writer, resp execadmin.Response) error {
	b, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	if len(b) > execadmin.MaxResponse {
		b, _ = json.Marshal(execadmin.Response{Error: "response too large"})
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

/*
Call sends req to the socket at path and returns the response line as
received: the "executor admin" command run by docker compose exec, which
relays nmsctl's request from its stdin and the answer to its stdout.
*/
func Call(ctx context.Context, path string, req []byte) ([]byte, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("admin socket %s: %w (is the executor running?)", filepath.Base(path), err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(commandTimeout + 2*requestTimeout))
	if _, err := c.Write(req); err != nil {
		return nil, err
	}
	line, err := bufio.NewReaderSize(io.LimitReader(c, execadmin.MaxResponse+1), 64<<10).ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("admin socket: no response: %w", err)
	}
	return line, nil
}
