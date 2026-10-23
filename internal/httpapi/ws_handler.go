package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/beekamai/network-scheme/internal/auth"
	"github.com/beekamai/network-scheme/internal/notify"
	"github.com/beekamai/network-scheme/internal/rbac"
)

/* WebSocket limits. */
const (
	wsMaxInbound        = 1024 /* bytes per client frame */
	wsMaxPerSession     = 4
	wsMaxPerUser        = 16 /* across all sessions of one user */
	wsMaxFramesPerSec   = 10 /* inbound frames; more closes the socket */
	wsRevalidateTimeout = 10 * time.Second
	wsDefaultRecheck    = 30 * time.Second /* session and scope re-evaluation */
	wsDefaultHeartbeat  = 30 * time.Second /* server ping; no pong within twice this closes the socket */
	wsWriteTimeout      = 10 * time.Second
)

/* wsSeverityRank orders the severities for the client's severity_min preference. */
var wsSeverityRank = map[string]int{"info": 0, "warning": 1, "average": 2, "high": 3, "disaster": 4}

/* wsConns counts open sockets per session (keyed by the hash of the cookie token) and per user. */
type wsConns struct {
	mu     sync.Mutex
	n      map[[32]byte]int
	byUser map[int64]int
}

func (c *wsConns) acquire(token string, userID int64) (release func(), ok bool) {
	k := sha256.Sum256([]byte(token))
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n == nil {
		c.n, c.byUser = map[[32]byte]int{}, map[int64]int{}
	}
	if c.n[k] >= wsMaxPerSession || c.byUser[userID] >= wsMaxPerUser {
		return nil, false
	}
	c.n[k]++
	c.byUser[userID]++
	return func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.n[k]--; c.n[k] <= 0 {
			delete(c.n, k)
		}
		if c.byUser[userID]--; c.byUser[userID] <= 0 {
			delete(c.byUser, userID)
		}
	}, true
}

/* wsClientMsg is the only inbound shape: {"type":"ping"} or {"type":"subscribe","severity_min":"high"}. */
type wsClientMsg struct {
	Type        string  `json:"type"`
	SeverityMin *string `json:"severity_min"`
}

/* subsumedBy reports whether next shows at least everything g does: growth is allowed, any loss is not. */
func (g groupScope) subsumedBy(next groupScope) bool {
	if next.all {
		return true
	}
	if g.all {
		return false
	}
	for _, id := range g.ids {
		if !next.has(id) {
			return false
		}
	}
	return true
}

/*
ws serves GET /api/ws, the live problem feed. Authentication is the session
cookie (the route policy); the Origin must be present and equal the public
origin. The server only sends problems of devices in the caller's groups
(global bindings also get device-less system problems). The session and the
scope are re-checked every recheck interval and the socket is closed when the
session ended or visibility shrank.
*/
func (s *server) ws(w http.ResponseWriter, r *http.Request) {
	sc, _ := sessionFrom(r.Context()) /* the policy guarantees a live session */
	o := r.Header.Values("Origin")
	if len(o) != 1 || !s.originAllowed(o[0]) {
		writeError(w, errCSRF)
		return
	}
	pub, err := url.Parse(s.cfg.PublicOrigin)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	scope, err := s.scope(r, rbac.PermDevicesRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	release, ok := s.wsConns.acquire(sc.token, sc.sess.UserID)
	if !ok {
		writeError(w, errRateLimited)
		return
	}
	defer release()

	/* Subscribed before the handshake completes, so nothing published after the client sees the upgrade is missed. */
	cur := &atomic.Pointer[groupScope]{}
	cur.Store(&scope)
	var minRank atomic.Int32
	msgs, cancel := s.hub.Subscribe(func(p notify.ProblemSummary) bool {
		/* The severity preference filters before queueing, so a burst below it cannot fill the buffer and drop the socket. */
		if wsSeverityRank[p.Severity] < int(minRank.Load()) {
			return false
		}
		g := cur.Load()
		if p.GroupID == nil {
			return g.all
		}
		return g.has(*p.GroupID)
	})
	defer cancel()

	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns:  []string{pub.Host},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil { /* Accept answered */
		return
	}
	defer func() { _ = c.CloseNow() }()
	c.SetReadLimit(wsMaxInbound)

	ctx, stop := context.WithCancel(r.Context())
	defer stop()
	type closing struct {
		code   websocket.StatusCode
		reason string
	}
	end := make(chan closing, 2)
	finish := func(code websocket.StatusCode, reason string) {
		select {
		case end <- closing{code, reason}:
		default:
		}
	}
	send := func(v any) error {
		wctx, cancel := context.WithTimeout(ctx, wsWriteTimeout)
		defer cancel()
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		return c.Write(wctx, websocket.MessageText, b)
	}

	/* Reader: the only inbound traffic is ping and subscribe; anything else ends the socket. */
	go func() {
		/* Token bucket: wsMaxFramesPerSec per second with a burst of the same size. */
		tokens, last := float64(wsMaxFramesPerSec), time.Now()
		for {
			typ, data, err := c.Read(ctx)
			now := time.Now()
			tokens = min(float64(wsMaxFramesPerSec), tokens+now.Sub(last).Seconds()*wsMaxFramesPerSec) - 1
			last = now
			if err == nil && tokens < 0 {
				finish(websocket.StatusPolicyViolation, "too many messages")
				return
			}
			if err != nil {
				code := websocket.CloseStatus(err)
				if code == -1 {
					code = websocket.StatusGoingAway
				}
				finish(code, "")
				return
			}
			var m wsClientMsg
			dec := json.NewDecoder(bytes.NewReader(data))
			dec.DisallowUnknownFields()
			if typ != websocket.MessageText || dec.Decode(&m) != nil || dec.More() {
				finish(websocket.StatusPolicyViolation, "invalid message")
				return
			}
			switch {
			case m.Type == "ping" && m.SeverityMin == nil:
				if send(map[string]string{"type": "pong"}) != nil {
					finish(websocket.StatusGoingAway, "")
					return
				}
			case m.Type == "subscribe":
				rank := 0
				if m.SeverityMin != nil {
					var ok bool
					if rank, ok = wsSeverityRank[*m.SeverityMin]; !ok {
						finish(websocket.StatusPolicyViolation, "invalid severity_min")
						return
					}
				}
				minRank.Store(int32(rank))
				if send(map[string]any{"type": "subscribed", "severity_min": m.SeverityMin}) != nil {
					finish(websocket.StatusGoingAway, "")
					return
				}
			default:
				finish(websocket.StatusPolicyViolation, "unknown message type")
				return
			}
		}
	}()

	/* Heartbeat: a ping every beat; the peer must answer within two. */
	go func() {
		t := time.NewTicker(s.wsHeartbeat)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				pctx, cancel := context.WithTimeout(ctx, 2*s.wsHeartbeat)
				err := c.Ping(pctx)
				cancel()
				if err != nil {
					finish(websocket.StatusPolicyViolation, "heartbeat lost")
					return
				}
			}
		}
	}()

	recheck := time.NewTicker(s.wsRecheck)
	defer recheck.Stop()
	/* Close sends the close frame before ctx is cancelled: a cancelled Read would drop the connection first. */
	closeWith := func(code websocket.StatusCode, reason string) { _ = c.Close(code, reason) }
	for {
		select {
		case e := <-end:
			closeWith(e.code, e.reason)
			return
		case <-ctx.Done():
			return
		case <-s.shutdown:
			closeWith(websocket.StatusGoingAway, "server shutting down")
			return
		case m, ok := <-msgs:
			if !ok {
				closeWith(websocket.StatusTryAgainLater, "too slow")
				return
			}
			if send(m) != nil {
				return
			}
		case <-recheck.C:
			next, reason := s.wsRevalidate(ctx, sc, *cur.Load())
			if reason != "" {
				closeWith(websocket.StatusPolicyViolation, reason)
				return
			}
			cur.Store(&next)
		}
	}
}

/*
wsRevalidate re-evaluates the session and the caller's scope. A non-empty
reason means the socket must close: the session is gone or the scope lost
anything it had (including all device access). Errors close too, so a
failing check never leaves a stale grant open.
*/
func (s *server) wsRevalidate(ctx context.Context, sc sessionCtx, old groupScope) (groupScope, string) {
	ctx, cancel := context.WithTimeout(ctx, wsRevalidateTimeout)
	defer cancel()
	if err := s.auth.CheckSession(ctx, sc.token); err != nil {
		if !errors.Is(err, auth.ErrSessionExpired) {
			s.log.WarnContext(ctx, "ws session check failed", slog.String("error", err.Error()))
		}
		return old, "session ended"
	}
	subj, err := s.rbac.LoadSubject(ctx, sc.sess.UserID)
	if err != nil {
		s.log.WarnContext(ctx, "ws scope check failed", slog.String("error", err.Error()))
		return old, "scope check failed"
	}
	all, ids, err := s.rbac.VisibleGroups(ctx, subj, rbac.PermDevicesRead)
	if err != nil {
		s.log.WarnContext(ctx, "ws scope check failed", slog.String("error", err.Error()))
		return old, "scope check failed"
	}
	next := groupScope{all: all, ids: ids}
	if !next.all && len(next.ids) == 0 || !old.subsumedBy(next) {
		return old, "permissions changed"
	}
	return next, ""
}
