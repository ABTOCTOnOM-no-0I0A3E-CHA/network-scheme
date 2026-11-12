/*
Package terminal is the change session's line terminal: the WebSocket
/x/ws of the executor origin (security.md 5.3 "Строчный режим", plan 4c.3).

One connection is one device of an open session. Its first frame, within
authTime, is {type: auth, session_id, token, device_id}: the session's
bearer token (never in the URL, no cookie); the Origin must be the executor
origin (403 before the upgrade). The executor edits the line itself
(editor): the device gets only whole lines, each classified by the driver
session (Session.Classify, in the session's mode and context, after a fresh
look at the policy, the freeze and the device's registry row):

  - safe: sent (within the policy's max_config_lines_per_hour per user);
  - dangerous: never sent as typed. The executor shows Verdict.Line, the
    client asks for a challenge with a fresh ticket of the session's user
    (dangerous_issue: authz.Identify, then confirm.Store.Issue binding H to
    the device's registry address, port and id from the verified
    write_device row, its name, the line, the mode and the session), and
    the line goes only after dangerous_confirm with that challenge, the
    device's name typed exactly and a change TOTP code whose step is above
    the last one (confirm + authz), when Classify still gives the same line
    and the registry still gives the same address, port and write group;
  - control (save, commit, ...): the flows of session.Manager.Typed (the
    commit, or the save or rollback flow with its diff); the typed text is
    never sent;
  - denied or refused: the reason, nothing is sent.

Tab and '?' list the grammar's words (Complete) and never reach the device.
RULING R8: the device's name comes from core.device (the api's data): it is
shown and typed only as a guard against a mistaken device, never as what
binds the confirmation; the registry's address, port and id in H do. A
dropped, refused or abandoned dangerous line discards its challenge.

At most maxPreauth connections, maxPreauthIP per client address, may wait
for their auth frame (authTime), so unauthenticated clients cannot take the
terminals of the session's users.
A keys or paste frame with more than paste_confirm_lines line breaks waits
for paste_confirm, the text shown first (the server counts, not the
client). A line that is not sent stops the rest of its frame. What is being
typed when the connection ends is dropped. Device output is cleaned of
every escape and control (clean), masked (MaskSecrets) and bounded in
volume and rate. Every line is recorded (Recorder) before it is sent: a
recording that fails or is full refuses the line, nothing goes unrecorded.
*/
package terminal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/beekamai/network-scheme/cmd/executor/internal/audit"
	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/confirm"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
	"github.com/beekamai/network-scheme/cmd/executor/internal/policy"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/session"
	"github.com/beekamai/network-scheme/cmd/executor/internal/transport"
	"github.com/beekamai/network-scheme/internal/execadmin"
	"github.com/beekamai/network-scheme/internal/ticket"
)

/* LineAction is the confirm(H) action of a dangerous line; CommandAction the audit action of every classified line. */
const (
	LineAction    = "session.line"
	CommandAction = "session.command"
)

/* Bounds; variables for the tests. */
var (
	maxConns                    = 32               /* open terminals of the executor */
	maxPreauth                  = 8                /* of them, waiting for their auth frame ... */
	maxPreauthIP                = 2                /* ... from one client address */
	maxFrame              int64 = 64 << 10         /* bytes of one client frame */
	authTime                    = 10 * time.Second /* until the first frame */
	writeTime                   = 10 * time.Second
	frameRate, frameBurst       = 50.0, 200.0      /* client frames per second: more closes */
	authzRate, authzBurst       = 0.5, 10.0        /* Identify and Confirm calls per connection */
	outRate, outBurst           = 128e3, 1e6       /* bytes of device output per second to the browser */
	maxOutput                   = 256 << 10        /* bytes of one line's output */
	minIdle                     = 10 * time.Minute /* a connection with no frame for the policy's idle time (at least this) ends */
)

/* Sessions is what the terminal needs of session.Manager. */
type Sessions interface {
	Use(id, token string, fn func(*session.Session) error) error
}

/* Authorizer is what the terminal needs of authz.Authorizer. */
type Authorizer interface {
	Identify(ctx context.Context, req authz.Request) (authz.Decision, error)
	Record(ctx context.Context, ev audit.Event)
}

/* Confirmer is what the terminal needs of confirm.Store (the one /x/confirm uses). */
type Confirmer interface {
	Issue(user int64, need authz.Need, d confirm.Description) (confirm.Challenge, error)
	Confirm(ctx context.Context, id string, h []byte, req authz.Request) (confirm.Challenge, authz.Decision, error)
	Discard(id string)
}

/*
Recorder is the session recording (session.Manager, package recording):
every line before it is sent (an error: the line is not sent), the device's
whole answer and the confirmations, all already cleaned and masked
(MaskSecrets; the recording masks again).
*/
type Recorder interface {
	RecordInput(ctx context.Context, s *session.Session, deviceID int64, line string) error
	RecordOutput(ctx context.Context, s *session.Session, deviceID int64, text string) error
	RecordMark(ctx context.Context, s *session.Session, deviceID int64, label string) error
}

/* Config builds a Terminal; every field but Log and Now is required. */
type Config struct {
	Sessions Sessions
	Gate     session.Gate /* *freeze.Guard: the registry and the freeze before every decision */
	Auth     Authorizer
	Confirm  Confirmer
	Policy   func() policy.State
	/* Name is the device's name the user must type for a dangerous line (devices.Service.Panel: display and mistake guard only, R8). */
	Name   func(ctx context.Context, deviceID int64) (string, error)
	Origin string /* the executor origin: the only Origin accepted */
	/* Typed runs the flow of a typed control line (session.Manager.Typed, the session locked); nil: refused. */
	Typed  func(ctx context.Context, s *session.Session, device int64, v core.Verdict) (session.Flow, error)
	Record Recorder
	Log    *slog.Logger
	Now    func() time.Time
}

/* Terminal serves /x/ws. */
type Terminal struct {
	c      Config
	origin string /* host[:port] of the origin, for the upgrade's own check */
	lines  lineLimit

	mu      sync.Mutex
	conns   int
	preauth int              /* connections before their auth frame */
	waiting map[string]int   /* of them, per client address */
	live    map[string]*conn /* session/device: the one connection */
}

/* New returns a Terminal. */
func New(c Config) (*Terminal, error) {
	u, err := url.Parse(c.Origin)
	if err != nil || u.Host == "" || c.Sessions == nil || c.Gate == nil || c.Auth == nil || c.Confirm == nil || c.Policy == nil || c.Name == nil || c.Record == nil {
		return nil, errors.New("terminal: incomplete configuration")
	}
	if c.Log == nil {
		c.Log = slog.New(slog.DiscardHandler)
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return &Terminal{c: c, origin: u.Host, live: map[string]*conn{}, waiting: map[string]int{}, lines: lineLimit{users: map[int64]*[60]bucketMin{}}}, nil
}

func deny(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":{"code":%q}}`, code)
}

/*
Serve is GET /x/ws (after the web server's checks: Host, X-Forwarded-For,
rate limit, policy; ip is the client's address): the Origin must be the
executor origin, the connection count bounded; the server's read and write
timeouts give way to the terminal's own per frame.
*/
func (t *Terminal) Serve(w http.ResponseWriter, r *http.Request, ip string) {
	if o := r.Header.Values("Origin"); len(o) != 1 || o[0] != t.c.Origin {
		deny(w, http.StatusForbidden, "origin")
		return
	}
	client := clientKey(ip)
	t.mu.Lock()
	full := t.conns >= maxConns || t.preauth >= maxPreauth || t.waiting[client] >= maxPreauthIP
	if !full {
		t.conns++
		t.preauth++
		t.waiting[client]++
	}
	t.mu.Unlock()
	if full {
		deny(w, http.StatusServiceUnavailable, "too_many_terminals")
		return
	}
	authed := false
	authOver := func() {
		t.mu.Lock()
		if !authed {
			authed = true
			t.preauth--
			if t.waiting[client]--; t.waiting[client] == 0 {
				delete(t.waiting, client)
			}
		}
		t.mu.Unlock()
	}
	defer func() {
		authOver()
		t.mu.Lock()
		t.conns--
		t.mu.Unlock()
	}()
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})
	w.Header().Del("Content-Type")
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{t.origin}})
	if err != nil {
		return
	}
	defer func() { _ = ws.CloseNow() }()
	ws.SetReadLimit(maxFrame)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	now := time.Now() /* the rate buckets run on the monotonic clock */
	c := &conn{t: t, ws: ws, ip: ip, ua: r.UserAgent(), authOver: authOver,
		frames: bucket{rate: frameRate, burst: frameBurst, tokens: frameBurst, last: now},
		authz:  bucket{rate: authzRate, burst: authzBurst, tokens: authzBurst, last: now},
		out:    bucket{rate: outRate, burst: outBurst, tokens: outBurst, last: now}}
	code := c.run(ctx, cancel)
	_ = ws.Close(websocket.StatusNormalClosure, code)
}

/* clientKey is a client for the pre-auth bound: its address, an IPv6 one by its /64 (as the web server's limiter). */
func clientKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	if a = a.Unmap(); a.Is4() {
		return a.String()
	}
	return netip.PrefixFrom(a, 64).Masked().String()
}

/* frame is every client frame; which fields count depends on Type. */
type frame struct {
	Type        string `json:"type"`
	SessionID   string `json:"session_id,omitempty"`
	Token       string `json:"token,omitempty"`
	DeviceID    int64  `json:"device_id,omitempty"`
	Data        string `json:"data,omitempty"`
	Cols        int    `json:"cols,omitempty"`
	Rows        int    `json:"rows,omitempty"`
	Accept      bool   `json:"accept,omitempty"`
	Ticket      string `json:"ticket,omitempty"`
	ChallengeID string `json:"challenge_id,omitempty"`
	DeviceName  string `json:"device_name,omitempty"`
	TOTP        string `json:"totp,omitempty"`
}

/* pending is a dangerous line waiting for its confirmation. */
type pending struct {
	typed string
	v     core.Verdict
	mode  string
	ch    *confirm.Challenge
	name  string
	dev   target /* the registry's device the challenge was issued for */
}

type conn struct {
	t        *Terminal
	ws       *websocket.Conn
	ip, ua   string
	authOver func() /* the auth frame was handled: no longer counted as waiting */
	sid      string
	token    string
	dev      int64
	user     int64
	ed       editor
	paste    *string  /* a paste waiting for paste_confirm */
	danger   *pending /* a dangerous line waiting for its confirmation */
	prompt   string
	cancel   context.CancelFunc
	frames   bucket
	authz    bucket
	out      bucket
}

/* errStop ends the processing of a frame (a line was not sent); errEnded ends the connection. */
var (
	errStop  = errors.New("terminal: stop")
	errEnded = errors.New("terminal: ended")
)

/* read reads one client frame strictly (text, JSON, no unknown field, no trailing data). */
func (c *conn) read(ctx context.Context, d time.Duration) (frame, error) {
	rctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	typ, b, err := c.ws.Read(rctx)
	if err != nil {
		return frame{}, err
	}
	var f frame
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if typ != websocket.MessageText || dec.Decode(&f) != nil {
		return frame{}, errors.New("terminal: bad frame")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return frame{}, errors.New("terminal: trailing data")
	}
	return f, nil
}

func (c *conn) send(ctx context.Context, v map[string]any) error {
	wctx, cancel := context.WithTimeout(ctx, writeTime)
	defer cancel()
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.ws.Write(wctx, websocket.MessageText, b)
}

/* refuse tells the client why a line or a step was refused. */
func (c *conn) refuse(ctx context.Context, code string, extra map[string]any) {
	m := map[string]any{"type": "refused", "code": code}
	for k, v := range extra {
		m[k] = v
	}
	_ = c.send(ctx, m)
}

func (c *conn) edit(ctx context.Context) {
	_ = c.send(ctx, map[string]any{"type": "edit", "text": c.ed.text(), "cursor": c.ed.cur, "prompt": c.prompt})
}

func key(sid string, dev int64) string { return sid + "/" + strconv.FormatInt(dev, 10) }

/* run serves the connection and returns the close reason. */
func (c *conn) run(ctx context.Context, cancel context.CancelFunc) string {
	f, err := c.read(ctx, authTime)
	if err != nil || f.Type != "auth" || f.SessionID == "" || len(f.Token) > 128 || f.DeviceID <= 0 {
		return "auth"
	}
	defer c.dropDanger()
	var line string
	err = c.t.c.Sessions.Use(f.SessionID, f.Token, func(s *session.Session) error {
		for _, d := range s.Devices {
			if d.ID == f.DeviceID {
				line, c.user = string(d.Line), s.User
				return nil
			}
		}
		return session.ErrNoSession
	})
	if err != nil {
		_ = c.send(ctx, map[string]any{"type": "ended", "code": "no_session"})
		return "no_session"
	}
	c.authOver()
	c.sid, c.token, c.dev = f.SessionID, f.Token, f.DeviceID
	k := key(c.sid, c.dev)
	c.cancel = cancel
	c.t.mu.Lock()
	if old := c.t.live[k]; old != nil {
		old.cancel() /* a newer terminal of the same device replaces this one */
	}
	c.t.live[k] = c
	c.t.mu.Unlock()
	defer func() {
		c.t.mu.Lock()
		if c.t.live[k] == c {
			delete(c.t.live, k)
		}
		c.t.mu.Unlock()
	}()
	if c.send(ctx, map[string]any{"type": "ready", "device_id": c.dev, "line": line}) != nil {
		return "write"
	}
	for {
		idle := time.Duration(c.t.c.Policy().Policy.IdleMinutes) * time.Minute
		f, err := c.read(ctx, max(idle, minIdle))
		if err != nil {
			return "read"
		}
		if !c.frames.take(1, time.Now()) {
			return "rate_limited"
		}
		if err := c.handle(ctx, f); errors.Is(err, errEnded) {
			_ = c.send(ctx, map[string]any{"type": "ended"})
			return "ended"
		} else if err != nil && !errors.Is(err, errStop) {
			return err.Error()
		}
	}
}

/* breaks counts the line breaks of data as the editor reads them ("\r\n" is one). */
func breaks(data string) int {
	return strings.Count(strings.ReplaceAll(data, "\r\n", "\n"), "\n") + strings.Count(strings.ReplaceAll(data, "\r\n", ""), "\r")
}

/* pasted is a paste as it is shown and typed: line breaks as "\n", escapes and controls dropped, tabs as spaces. */
func pasted(data string) string {
	ls := strings.Split(strings.ReplaceAll(strings.ReplaceAll(data, "\r\n", "\n"), "\r", "\n"), "\n")
	for i, l := range ls {
		ls[i] = strings.ReplaceAll(clean(l), "\t", " ") /* per line: an unterminated sequence never eats a line break */
	}
	return strings.Join(ls, "\n")
}

func (c *conn) handle(ctx context.Context, f frame) error {
	/* every frame finds the session still open (and counts as its use) */
	if err := c.use(func(*session.Session, *session.Device) error { return nil }); err != nil {
		return err
	}
	switch f.Type {
	case "keys", "paste":
		if c.paste != nil || c.danger != nil {
			if f.Type == "keys" && strings.ContainsRune(f.Data, 0x03) { /* Ctrl-C drops what waits */
				c.paste = nil
				c.dropDanger()
				c.edit(ctx)
			}
			return nil
		}
		limit := c.t.c.Policy().Policy.PasteConfirmLines
		if breaks(f.Data) > limit {
			p := pasted(f.Data)
			c.paste = &p
			return c.send(ctx, map[string]any{"type": "paste_pending", "text": p, "lines": strings.Count(p, "\n")})
		}
		if f.Type == "paste" {
			return c.input(ctx, pasted(f.Data), true)
		}
		return c.input(ctx, f.Data, false)
	case "paste_confirm":
		if c.paste == nil {
			c.refuse(ctx, "nothing_pending", nil)
			return nil
		}
		p := *c.paste
		c.paste = nil
		if !f.Accept {
			c.edit(ctx)
			return nil
		}
		if err := c.use(func(s *session.Session, d *session.Device) error {
			return c.t.c.Record.RecordMark(ctx, s, d.ID, fmt.Sprintf("paste of %d lines confirmed", strings.Count(p, "\n")+1))
		}); err != nil {
			if errors.Is(err, errEnded) {
				return err
			}
			c.refuse(ctx, code(err), nil)
			c.edit(ctx)
			return nil
		}
		return c.input(ctx, p, true)
	case "resize":
		if f.Cols < 1 || f.Cols > 1000 || f.Rows < 1 || f.Rows > 1000 {
			return errors.New("bad_frame")
		}
		return nil /* line mode: the device's terminal size does not change */
	case "dangerous_issue":
		return c.issue(ctx, f)
	case "dangerous_confirm":
		err := c.confirm(ctx, f)
		c.edit(ctx)
		return err
	}
	return errors.New("bad_frame")
}

/* input runs data through the editor: the session acts on Enter, Tab, '?' and Ctrl-C. */
func (c *conn) input(ctx context.Context, data string, paste bool) error {
	for data != "" {
		ev, rest := c.ed.feed(data, paste)
		data = rest
		var err error
		switch ev {
		case evCancel:
			c.ed.clear()
		case evComplete, evHelp:
			err = c.complete(ctx, ev == evComplete)
		case evEnter:
			line := c.ed.take()
			c.edit(ctx)
			err = c.line(ctx, line)
		}
		switch {
		case errors.Is(err, errStop):
			if strings.TrimSpace(data) != "" {
				c.refuse(ctx, "rest_dropped", nil)
			}
			c.edit(ctx)
			return nil
		case err != nil:
			return err
		}
	}
	c.edit(ctx)
	return nil
}

/* use runs fn on the connection's device of the session (Manager.Use: the session locked, only while open). */
func (c *conn) use(fn func(s *session.Session, d *session.Device) error) error {
	err := c.t.c.Sessions.Use(c.sid, c.token, func(s *session.Session) error {
		for _, d := range s.Devices {
			if d.ID == c.dev && d.Session != nil {
				return fn(s, d)
			}
		}
		return session.ErrNoSession
	})
	if errors.Is(err, session.ErrNoSession) {
		return errEnded
	}
	return err
}

func (c *conn) complete(ctx context.Context, tab bool) error {
	var words []string
	err := c.use(func(_ *session.Session, d *session.Device) error {
		words = d.Driver.Complete(c.ed.prefix(), d.Session.Mode())
		return nil
	})
	if err != nil {
		return err
	}
	if tab && c.ed.complete(words) {
		return nil
	}
	return c.send(ctx, map[string]any{"type": "help", "words": words})
}

/* dropDanger drops the pending dangerous line and discards its challenge, if one was issued. */
func (c *conn) dropDanger() {
	if c.danger != nil && c.danger.ch != nil {
		c.t.c.Confirm.Discard(c.danger.ch.ID)
	}
	c.danger = nil
}

/* target is a device as the verified registry has it: what a dangerous line's H binds (R8) and the grant it needs. */
type target struct {
	address string /* address:port of the write_device row */
	group   string
}

/*
check looks again at what a decision on the device rests on: the policy
enables the executor, the registry verifies and is not frozen, the device's
write_device row is there with writes enabled. It returns its address, port
and write group.
*/
func (c *conn) check(ctx context.Context, dev int64) (target, error) {
	if !c.t.c.Policy().Enabled() {
		return target{}, authz.ErrDisabled
	}
	var tg target
	err := c.t.c.Gate.View(ctx, func(s *registry.Snapshot) error {
		r, ok := s.Get("write_device", dev)
		if !ok || r.Get("writes_enabled") != true {
			return session.ErrWritesDisabled
		}
		a, _ := r.Get("address").(netip.Addr)
		p, _ := r.Get("port").(int64)
		if !a.IsValid() || p < 1 || p > 65535 {
			return session.ErrWritesDisabled
		}
		tg.address = netip.AddrPortFrom(a, uint16(p)).String() // #nosec G115 -- checked above
		tg.group, _ = r.Get("write_group").(string)
		return nil
	})
	return tg, err
}

/* code is the client's code of a refusal (authz, confirm, session or the gate). */
func code(err error) string {
	var rf interface{ RefusalCode() string }
	switch {
	case errors.As(err, &rf):
		return rf.RefusalCode()
	case errors.Is(err, authz.ErrFrozen):
		return "frozen"
	case errors.Is(err, authz.ErrDisabled):
		return "disabled"
	case errors.Is(err, authz.ErrLocked):
		return "locked"
	case errors.Is(err, authz.ErrUnavailable):
		return "unavailable"
	case errors.Is(err, confirm.ErrTooMany):
		return "too_many_challenges"
	}
	return "denied"
}

/* line decides a typed line (see the package comment); errStop when it was not sent. */
func (c *conn) line(ctx context.Context, text string) error {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	return c.use(func(s *session.Session, d *session.Device) error {
		if _, err := c.check(ctx, d.ID); err != nil {
			c.refuse(ctx, code(err), nil)
			return errStop
		}
		v := d.Session.Classify(text)
		c.audit(ctx, s, d, v)
		switch v.Class {
		case core.Safe:
			return c.sendLine(ctx, s, d, v)
		case core.Dangerous:
			c.danger = &pending{typed: text, v: v, mode: d.Session.Mode().Name()}
			_ = c.send(ctx, map[string]any{"type": "dangerous", "line": v.Line, "reason": string(v.Reason)})
		case core.Control:
			c.control(ctx, s, d, v)
		default:
			c.refuse(ctx, "denied", map[string]any{"line": v.Line, "reason": string(v.Reason)})
		}
		return errStop
	})
}

/*
audit writes the executor audit row of a classified line (security.md 10:
every command with its class): the session, the device, the class and its
reason, the normalized line masked as the recording has it. A denied line
is a refusal of the policy (denied); the others are decided (ok): a safe
line goes to the device, a dangerous one waits for its confirmation (its
own row, confirm.session.line), a control line goes to its flow.
*/
func (c *conn) audit(ctx context.Context, s *session.Session, d *session.Device, v core.Verdict) {
	user, result := s.User, audit.OK
	if v.Class != core.Safe && v.Class != core.Dangerous && v.Class != core.Control {
		result = audit.Denied
	}
	c.t.c.Auth.Record(ctx, audit.Event{UserID: &user, IP: c.ip, UA: c.ua, Action: CommandAction, Object: "session:" + c.sid, Result: result,
		Details: map[string]any{"device_id": d.ID, "class": v.Class.String(), "reason": string(v.Reason), "line": d.Driver.MaskSecrets(v.Line)}})
}

/*
control hands a typed control line to its flow (4c.4): a typed commit is the
ESR commit with its health check; save, write, confirm and reload cancel
open the save flow with the diff; restore opens the rollback. The typed text
itself never reaches the device.
*/
func (c *conn) control(ctx context.Context, s *session.Session, d *session.Device, v core.Verdict) {
	if c.t.c.Typed == nil {
		c.refuse(ctx, "control", map[string]any{"line": v.Line, "control": int(v.Control)})
		return
	}
	f, err := c.t.c.Typed(ctx, s, d.ID, v)
	if err != nil {
		c.refuse(ctx, code(err), map[string]any{"line": v.Line})
		return
	}
	_ = c.send(ctx, map[string]any{"type": "flow", "flow": f.Kind, "diff": f.Diff})
}

/*
sendLine sends a classified line (within the hourly limit, recorded first:
a recording that failed or is full refuses it) and shows the device's
cleaned, masked, bounded answer. An answer that cannot be recorded stops
the frame (the recording then refuses every further line).
*/
func (c *conn) sendLine(ctx context.Context, s *session.Session, d *session.Device, v core.Verdict) error {
	if !c.t.lines.take(s.User, c.t.c.Policy().Policy.MaxConfigLinesPerHour, c.t.c.Now()) {
		c.refuse(ctx, "line_limit", nil)
		return errStop
	}
	if err := c.t.c.Record.RecordInput(ctx, s, d.ID, d.Driver.MaskSecrets(v.Line)); err != nil {
		c.t.c.Log.Warn("terminal: a line was not recorded, so not sent", slog.Int64("device", d.ID), slog.Any("err", err))
		c.refuse(ctx, code(err), nil)
		return errStop
	}
	out, err := d.Session.Send(ctx, v)
	text := d.Driver.MaskSecrets(clean(strings.Join(append(append([]string(nil), out.Async...), out.Lines...), "\n")))
	var recErr error
	if text != "" {
		recErr = c.t.c.Record.RecordOutput(ctx, s, d.ID, text+"\n") /* the whole answer: the browser's bounds below do not cut the recording */
	}
	limited := false
	if len(text) > maxOutput {
		text, limited = text[:maxOutput], true
	}
	if !c.out.take(float64(len(text)), time.Now()) {
		text, limited = "", true
	}
	c.prompt = clean(out.State.Prompt)
	_ = c.send(ctx, map[string]any{"type": "output", "sent": v.Line, "text": text, "limited": limited, "prompt": c.prompt})
	switch {
	case recErr != nil:
		c.refuse(ctx, code(recErr), nil)
		return errStop
	case err == nil:
		return nil
	case errors.Is(err, transport.ErrDevice):
		c.refuse(ctx, "device_error", nil) /* the device refused it: never retried */
		return errStop
	}
	c.t.c.Log.Warn("terminal: sending a line failed", slog.Int64("device", d.ID), slog.Any("err", err))
	c.refuse(ctx, "send_failed", nil)
	return errStop
}

/* field is a challenge field's value. */
func field(d confirm.Description, k string) string {
	for _, f := range d.Fields {
		if f.Key == k {
			return f.Value
		}
	}
	return ""
}

/*
issue issues the challenge of the pending dangerous line: only for a fresh
ticket of the session's own user (Identify spends its nonce), the line
classified again to the same Verdict.Line, H over the device's name and id,
that line, the mode and the session.
*/
func (c *conn) issue(ctx context.Context, f frame) error {
	p := c.danger
	if p == nil || p.ch != nil {
		c.refuse(ctx, "nothing_pending", nil)
		return nil
	}
	if len(f.Ticket) > ticket.MaxLen || !c.authz.take(1, time.Now()) {
		c.danger = nil
		c.refuse(ctx, "rate_limited", nil)
		return nil
	}
	return c.use(func(s *session.Session, d *session.Device) error {
		fail := func(code string) error {
			c.danger = nil
			c.refuse(ctx, code, nil)
			return nil
		}
		tg, err := c.check(ctx, d.ID)
		if err != nil {
			return fail(code(err))
		}
		if v := d.Session.Classify(p.typed); v.Class != core.Dangerous || v.Line != p.v.Line || d.Session.Mode().Name() != p.mode {
			return fail("changed")
		}
		by, err := c.t.c.Auth.Identify(ctx, authz.Request{Ticket: f.Ticket, Action: "confirm.issue", Object: LineAction,
			User: s.User, IP: c.ip, UA: c.ua})
		if err != nil {
			return fail(code(err))
		}
		name, err := c.t.c.Name(ctx, d.ID)
		if err != nil || name == "" {
			return fail("no_device_name")
		}
		desc := confirm.Description{Action: LineAction, Fields: []confirm.Field{{Key: "address", Value: tg.address},
			{Key: "device", Value: name}, {Key: "device_id", Value: strconv.FormatInt(d.ID, 10)}, {Key: "line", Value: p.v.Line},
			{Key: "mode", Value: p.mode}, {Key: "session", Value: session.IDString(s.ID)}}}
		ch, err := c.t.c.Confirm.Issue(by.UserID, authz.Need{Kind: execadmin.KindWrite, Groups: []string{tg.group}}, desc)
		if err != nil {
			return fail(code(err))
		}
		p.ch, p.name, p.dev = &ch, name, tg
		fields := make([]map[string]string, 0, len(desc.Fields))
		for _, f := range desc.Fields {
			fields = append(fields, map[string]string{"key": f.Key, "value": f.Value})
		}
		return c.send(ctx, map[string]any{"type": "challenge", "challenge_id": ch.ID, "action": ch.Action,
			"h": fmt.Sprintf("%x", ch.H[:]), "fields": fields, "expires": ch.Expires})
	})
}

/*
confirm sends the pending dangerous line after its confirmation: the
challenge it was issued, the device's name typed exactly, then confirm +
authz (ticket, change TOTP above the last step, the write grant), then a
fresh look at the gate and Classify giving the line H covers, in the mode H
covers, for the registry's same address, port and write group (a device
moved to another group was authorized for the old one: changed). Any
outcome spends the pending line and its challenge; nothing is retried.
*/
func (c *conn) confirm(ctx context.Context, f frame) error {
	p := c.danger
	if p == nil || p.ch == nil || f.ChallengeID != p.ch.ID {
		c.dropDanger()
		c.refuse(ctx, "nothing_pending", nil)
		return nil
	}
	c.danger = nil
	spent := false
	defer func() {
		if !spent {
			c.t.c.Confirm.Discard(p.ch.ID)
		}
	}()
	if f.DeviceName != p.name {
		user := c.user
		c.t.c.Auth.Record(ctx, audit.Event{UserID: &user, IP: c.ip, UA: c.ua, Action: "confirm." + LineAction, Object: "challenge",
			Result: audit.Denied, Details: map[string]any{"class": "device_name_mismatch", "challenge": p.ch.ID, "device_id": c.dev}})
		c.refuse(ctx, "device_name", nil)
		return nil
	}
	if len(f.Ticket) > ticket.MaxLen || len(f.TOTP) > 16 || !c.authz.take(1, time.Now()) {
		c.refuse(ctx, "rate_limited", nil)
		return nil
	}
	return c.use(func(s *session.Session, d *session.Device) error {
		spent = true
		_, by, err := c.t.c.Confirm.Confirm(ctx, p.ch.ID, p.ch.H[:], authz.Request{Ticket: f.Ticket, Code: f.TOTP, IP: c.ip, UA: c.ua,
			Object: "session:" + c.sid, Details: map[string]any{"device_id": d.ID}})
		if err == nil && by.UserID != s.User {
			err = authz.ErrDenied
		}
		if err != nil {
			c.refuse(ctx, code(err), nil)
			return errStop
		}
		tg, err := c.check(ctx, d.ID)
		if err != nil {
			c.refuse(ctx, code(err), nil)
			return errStop
		}
		v := d.Session.Classify(p.typed)
		if v.Class != core.Dangerous || v.Line != field(p.ch.Description, "line") || d.Session.Mode().Name() != field(p.ch.Description, "mode") ||
			tg != p.dev || tg.address != field(p.ch.Description, "address") {
			c.refuse(ctx, "changed", nil)
			return errStop
		}
		if err := c.t.c.Record.RecordMark(ctx, s, d.ID, "dangerous line confirmed (challenge "+p.ch.ID+")"); err != nil {
			c.refuse(ctx, code(err), nil)
			return errStop
		}
		return c.sendLine(ctx, s, d, v)
	})
}

/* bucket is a token bucket. */
type bucket struct {
	rate, burst, tokens float64
	last                time.Time
}

func (b *bucket) take(n float64, now time.Time) bool {
	b.tokens = min(b.burst, b.tokens+now.Sub(b.last).Seconds()*b.rate)
	b.last = now
	if b.tokens < n {
		return false
	}
	b.tokens -= n
	return true
}

/* bucketMin counts the lines one user sent in one minute. */
type bucketMin struct {
	minute int64
	n      int
}

/* lineLimit is max_config_lines_per_hour per user: lines sent to devices in the last 60 minutes, all sessions. */
type lineLimit struct {
	mu    sync.Mutex
	users map[int64]*[60]bucketMin
}

func (l *lineLimit) take(user int64, limit int, now time.Time) bool {
	m := now.Unix() / 60
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.users[user]
	if b == nil {
		b = &[60]bucketMin{}
		l.users[user] = b
	}
	sum := 0
	for _, x := range b {
		if x.minute > m-60 {
			sum += x.n
		}
	}
	if sum >= limit {
		return false
	}
	i := m % 60
	if b[i].minute != m {
		b[i] = bucketMin{minute: m}
	}
	b[i].n++
	return true
}
