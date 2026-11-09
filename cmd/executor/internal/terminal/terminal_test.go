package terminal_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode"

	"github.com/coder/websocket"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	gossh "golang.org/x/crypto/ssh"

	"github.com/beekamai/network-scheme/cmd/executor/internal/admin"
	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/confirm"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/drvtest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/esr"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/mes10"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/mes6"
	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/cmd/executor/internal/policy"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/session"
	"github.com/beekamai/network-scheme/cmd/executor/internal/strategy"
	"github.com/beekamai/network-scheme/cmd/executor/internal/terminal"
	"github.com/beekamai/network-scheme/internal/execadmin"
	"github.com/beekamai/network-scheme/internal/testdb"
	"github.com/beekamai/network-scheme/internal/ticket"
)

func TestMain(m *testing.M) { testdb.Main(m) }

var ticketKey = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

/* opener is a write driver that opens on the in-memory emulator. */
type opener interface {
	drivers.WriteDriver
	OpenShell(ctx context.Context, sh drivers.Shell, o drivers.Options) (drivers.Session, error)
}

/* fixture of one line: device id, driver, the configure command, the management interface (VLAN 99 too). */
var lines = []struct {
	id     int64
	name   string
	d      opener
	cfg    string
	mgmtIf string
}{
	{101, "mes6", mes6.New(), "configure", "gi1/0/24"},
	{102, "mes10", mes10.New(), "configure terminal", "gi0/24"},
	{103, "esr", esr.New(), "configure", "gi1/0/24"},
}

/* sessions is session.Manager.Use over one session built from driver sessions on emulators. */
type sessions struct {
	mu    sync.Mutex
	s     *session.Session
	token string
	ended bool
}

func (f *sessions) Use(id, token string, fn func(*session.Session) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ended || id != session.IDString(f.s.ID) || token != f.token {
		return session.ErrNoSession
	}
	return fn(f.s)
}

type who struct {
	id         int64
	name, totp string
}

/* fx: a registry, policy, authz and confirm on the test database, one session over mes6, mes10 and ESR emulators, /x/ws. */
type fx struct {
	env    *testdb.Env
	guard  *freeze.Guard
	pol    *policy.Holder
	polF   string
	az     *authz.Authorizer
	adm    *admin.Admin
	start  time.Time
	offset atomic.Int64
	u      who
	ss     *sessions
	terms  map[int64]*drvtest.Term
	names  map[int64]string
	srv    *httptest.Server
	code   string /* the last code used */
	cs     *confirm.Store
	rec    *recorder
	rows   map[int64]map[string]any /* the write_device rows */
}

/* recorder keeps what the terminal records. */
type recorder struct {
	mu      sync.Mutex
	in, out []string
}

func (r *recorder) Input(_ context.Context, _ *session.Session, _ int64, l string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.in = append(r.in, l)
}

func (r *recorder) Output(_ context.Context, _ *session.Session, _ int64, t string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.out = append(r.out, t)
}

func (f *fx) now() time.Time { return f.start.Add(time.Duration(f.offset.Load())) }

func newFx(t *testing.T) *fx {
	t.Helper()
	env := testdb.New(t)
	attacktest.Reset(t, env)
	ctx := context.Background()
	keys, err := seal.Derive(&[32]byte{6})
	if err != nil {
		t.Fatal(err)
	}
	f := &fx{env: env, start: time.Now(), terms: map[int64]*drvtest.Term{}, names: map[int64]string{},
		rec: &recorder{}, rows: map[int64]map[string]any{}}
	pool := env.Pool("nms_executor")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()
	reg := registry.New(pool, keys, filepath.Join(dir, "state"))
	f.guard = freeze.New(reg, pool, log)
	if err := f.guard.Start(ctx); err != nil {
		t.Fatal(err)
	}
	f.polF = filepath.Join(dir, "executor.yaml")
	f.pol = policy.New(f.polF)
	f.policy(t, "")
	if f.az, err = authz.New(authz.Config{Guard: f.guard, Reg: reg, Keys: keys, Policy: f.pol, Log: log, Now: f.now,
		TicketKey: ticketKey.Public().(ed25519.PublicKey), Started: f.start, GuardsFile: filepath.Join(dir, "guards")}); err != nil {
		t.Fatal(err)
	}
	f.adm = &admin.Admin{Guard: f.guard, Reg: reg, Keys: keys, Policy: f.pol, Log: log, Lockouts: f.az}
	f.u = f.user(t, "core")

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	hk, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	s := &session.Session{ID: [16]byte{0x4c, 3}, User: f.u.id, Username: f.u.name, Opened: f.now()}
	for i, l := range lines {
		f.rows[l.id] = map[string]any{"device_id": l.id, "address": netip.AddrFrom4([4]byte{192, 0, 2, byte(10 + i)}), "port": 22,
			"protocol": "ssh", "write_group": "core", "write_driver": l.name, "hostkey_algo": hk.Type(),
			"hostkey_fp": gossh.FingerprintSHA256(hk), "allow_ssh_rsa_sha1": false, "writes_enabled": true, "backup_via_executor": false}
		f.put(t, "write_device", f.rows[l.id])
		tm := drvtest.New(t, strategy.Line(l.name))
		a, ok1 := l.d.Targets("interface", l.mgmtIf)
		b, ok2 := l.d.Targets("vlan", "99")
		if !ok1 || !ok2 {
			t.Fatal("management targets")
		}
		ds, err := l.d.OpenShell(ctx, tm, drivers.Options{SessionID: "t1", Context: core.Context{Mgmt: append(a, b...)},
			Alert: (&drvtest.Alerts{}).Add})
		if err != nil {
			t.Fatalf("%s: open: %v", l.name, err)
		}
		s.Devices = append(s.Devices, &session.Device{ID: l.id, Line: strategy.Line(l.name), Driver: l.d, Session: ds})
		f.terms[l.id], f.names[l.id] = tm, "sw-"+l.name
	}
	f.ss = &sessions{s: s, token: "bearer-token-of-the-session"}
	f.srv = httptest.NewServer(nil)
	f.cs = confirm.New(f.az, f.now)
	term, err := terminal.New(terminal.Config{Sessions: f.ss, Gate: f.guard, Auth: f.az, Confirm: f.cs, Record: f.rec,
		Policy: f.pol.Current, Origin: f.srv.URL, Log: log, Now: f.now,
		Name: func(_ context.Context, id int64) (string, error) { return f.names[id], nil }})
	if err != nil {
		t.Fatal(err)
	}
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { term.Serve(w, r, "192.0.2.200") })
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fx) policy(t *testing.T, extra string) {
	t.Helper()
	if err := os.WriteFile(f.polF, []byte("enabled: true\n"+extra), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, cur, _ := f.pol.Reload(true); cur.Err != nil {
		t.Fatalf("policy: %v", cur.Err)
	}
}

func (f *fx) put(t *testing.T, table string, row map[string]any) {
	t.Helper()
	if err := f.guard.HostWrite(context.Background(), func(_ context.Context, _ *registry.Snapshot, tx *registry.Tx) error {
		return tx.Put(table, row)
	}); err != nil {
		t.Fatal(err)
	}
}

/* user is a panel user with a change TOTP and write grants on groups (nmsctl). */
func (f *fx) user(t *testing.T, groups ...string) who {
	t.Helper()
	name := fmt.Sprintf("term-%d", time.Now().UnixNano()%1e9)
	var u who
	if err := f.env.Pool("postgres").QueryRow(context.Background(),
		`INSERT INTO core."user" (username, password_phc) VALUES ($1, 'x') RETURNING id`, name).Scan(&u.id); err != nil {
		t.Fatal(err)
	}
	u.name = name
	reqs := []execadmin.Request{{Cmd: execadmin.CmdEnroll}}
	for _, g := range groups {
		reqs = append(reqs, execadmin.Request{Cmd: execadmin.CmdGrant, Kind: execadmin.KindWrite, Group: g})
	}
	for _, req := range reqs {
		req.User, req.V, req.Operator = name, execadmin.Version, "tester"
		resp := f.adm.Handle(context.Background(), req)
		if resp.OK && resp.Confirm != nil {
			req.UserID, req.UserCreated = resp.Confirm.ID, resp.Confirm.CreatedAt
			resp = f.adm.Handle(context.Background(), req)
		}
		if !resp.OK {
			t.Fatalf("%s: %s", req.Cmd, resp.Error)
		}
		if resp.Enrollment != nil {
			u.totp = resp.Enrollment.Secret
		}
	}
	return u
}

func (f *fx) ticket(t *testing.T) string {
	t.Helper()
	tok, _, err := ticket.Issue(ticketKey, f.u.id, f.u.name, f.now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

/* newCode is the change TOTP code of the next step. */
func (f *fx) newCode(t *testing.T) string {
	t.Helper()
	f.offset.Add(int64(30 * time.Second))
	c, err := totp.GenerateCodeCustom(f.u.totp, f.now(), totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	f.code = c
	return c
}

type client struct {
	t *testing.T
	c *websocket.Conn
}

func (f *fx) dialRaw(t *testing.T, origin string) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	h := http.Header{}
	if origin != "" {
		h.Set("Origin", origin)
	}
	return websocket.Dial(ctx, "ws"+strings.TrimPrefix(f.srv.URL, "http")+"/x/ws", &websocket.DialOptions{HTTPHeader: h})
}

/* dial opens the terminal of a device of the session. */
func (f *fx) dial(t *testing.T, dev int64) *client {
	t.Helper()
	ws, _, err := f.dialRaw(t, f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ws.SetReadLimit(4 << 20)
	c := &client{t: t, c: ws}
	t.Cleanup(func() { _ = ws.CloseNow() })
	c.send(map[string]any{"type": "auth", "session_id": session.IDString(f.ss.s.ID), "token": f.ss.token, "device_id": dev})
	if m := c.next(); m["type"] != "ready" {
		t.Fatalf("first answer %v", m)
	}
	return c
}

func (c *client) send(m map[string]any) {
	c.t.Helper()
	b, _ := json.Marshal(m)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.c.Write(ctx, websocket.MessageText, b); err != nil {
		c.t.Fatal(err)
	}
}

/* next reads one frame; every string in it must be free of controls (but \n, \t) and format characters. */
func (c *client) next() map[string]any {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, b, err := c.c.Read(ctx)
	if err != nil {
		c.t.Fatalf("read: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		c.t.Fatal(err)
	}
	var walk func(v any)
	walk = func(v any) {
		switch v := v.(type) {
		case string:
			for _, r := range v {
				if r != '\n' && r != '\t' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) {
					c.t.Fatalf("frame %s carries %U", b, r)
				}
			}
		case []any:
			for _, x := range v {
				walk(x)
			}
		case map[string]any:
			for _, x := range v {
				walk(x)
			}
		}
	}
	walk(m)
	return m
}

/* until reads frames up to an edit frame and returns the others. */
func (c *client) until() []map[string]any {
	c.t.Helper()
	var out []map[string]any
	for {
		m := c.next()
		if m["type"] == "edit" {
			return out
		}
		out = append(out, m)
	}
}

/* do sends a keys or paste frame that ends lines: the answers to its lines, up to the editor's state after them. */
func (c *client) do(typ, data string) []map[string]any {
	c.t.Helper()
	c.send(map[string]any{"type": typ, "data": data})
	var out []map[string]any
	for range strings.Count(data, "\n") + strings.Count(data, "\r") {
		out = append(out, c.until()...)
	}
	return append(out, c.until()...)
}

/* line types one line (keys, Enter) and returns the first answer. */
func (c *client) line(l string) map[string]any {
	c.t.Helper()
	res := c.do("keys", l+"\r")
	if len(res) == 0 {
		c.t.Fatalf("%q: no answer", l)
	}
	return res[0]
}

/* typed is how many lines the device got. */
func (f *fx) typed(dev int64) int { return len(f.terms[dev].Lines()) }

func (f *fx) mustSend(t *testing.T, c *client, dev int64, l string) {
	t.Helper()
	before := f.typed(dev)
	if res := c.do("keys", l+"\r"); len(res) != 1 || res[0]["type"] != "output" || f.typed(dev) != before+1 {
		t.Fatalf("%q: %v (device got %d lines)", l, res, f.typed(dev)-before)
	}
}

/*
C4 end to end: every dangerous command of every firmware line, in every
spelling the classifier test knows (abbreviations, case, spaces and tabs,
do), typed through /x/ws into a session on the emulator, is held for the
confirmation: the device gets nothing.
*/
func TestC4EveryDangerousSpellingIsHeld(t *testing.T) {
	t.Cleanup(terminal.Unlimited())
	f := newFx(t)
	for _, l := range lines {
		c := f.dial(t, l.id)
		var cur []string
		goTo := func(mode []string) {
			if slices.Equal(cur, mode) {
				return
			}
			if len(cur) > 0 {
				f.mustSend(t, c, l.id, "end")
			}
			for _, m := range mode {
				f.mustSend(t, c, l.id, m)
			}
			cur = mode
		}
		held := 0
		for _, p := range drvtest.Dangerous[l.name] {
			for _, v := range drvtest.Variants(p, l.cfg) {
				if v.Refused {
					continue /* control characters never enter the line (TestEditorKeys) */
				}
				goTo(v.Mode)
				before := f.typed(l.id)
				res := c.do("paste", v.Line+"\n")
				danger, denied := res[0]["type"] == "dangerous", res[0]["type"] == "refused" && res[0]["code"] == "denied"
				if len(res) != 1 || !danger && !denied {
					t.Fatalf("%s: %q in %v: %v", l.name, v.Line, v.Mode, res)
				}
				if res[0]["type"] == "dangerous" {
					held++
					c.do("keys", "\x03") /* not confirmed: dropped */
				}
				if n := f.typed(l.id) - before; n != 0 {
					t.Fatalf("%s: %q in %v reached the device (%d lines)", l.name, v.Line, v.Mode, n)
				}
			}
		}
		if held == 0 {
			t.Fatalf("%s: no line was held as dangerous", l.name)
		}
	}
}

/* issue asks for the challenge of the pending dangerous line. */
func (f *fx) issue(t *testing.T, c *client) map[string]any {
	t.Helper()
	c.send(map[string]any{"type": "dangerous_issue", "ticket": f.ticket(t)})
	m := c.next()
	if m["type"] != "challenge" {
		t.Fatalf("issue: %v", m)
	}
	return m
}

func (f *fx) confirm(t *testing.T, c *client, ch map[string]any, name, code string) []map[string]any {
	t.Helper()
	c.send(map[string]any{"type": "dangerous_confirm", "challenge_id": ch["challenge_id"], "device_name": name, "totp": code,
		"ticket": f.ticket(t)})
	return c.until()
}

/*
C4 end to end, the confirmation: a dangerous line goes to the device only
with the device's name typed exactly and a change TOTP code of a step above
the last one, bound to Verdict.Line through confirm(H); a wrong name or an
old code refuses it and the device gets nothing.
*/
func TestC4DangerousLineNeedsNameAndNewCode(t *testing.T) {
	t.Cleanup(terminal.Unlimited())
	f := newFx(t)
	for _, l := range lines {
		f.az.ResetUser(f.u.id)
		c := f.dial(t, l.id)
		f.mustSend(t, c, l.id, l.cfg)
		f.mustSend(t, c, l.id, "interface "+l.mgmtIf)
		typed := "DESCR  nms-test"
		dangerous := func() map[string]any {
			t.Helper()
			res := c.do("keys", typed+"\r")
			if len(res) != 1 || res[0]["type"] != "dangerous" {
				t.Fatalf("%s: %v", l.name, res)
			}
			ch := f.issue(t, c)
			fields := map[string]string{}
			var d confirm.Description
			d.Action = ch["action"].(string)
			for _, x := range ch["fields"].([]any) {
				m := x.(map[string]any)
				fields[m["key"].(string)] = m["value"].(string)
				d.Fields = append(d.Fields, confirm.Field{Key: m["key"].(string), Value: m["value"].(string)})
			}
			h, _ := d.Hash()
			/* H covers what is shown: the normalized line (Verdict.Line, not the typed text), the device, the session */
			/* R8: H binds the registry's address and port; the typed name only guards against a mistaken device */
			if ch["h"] != hex.EncodeToString(h[:]) || fields["line"] != res[0]["line"] || fields["line"] == typed ||
				fields["address"] != netip.AddrPortFrom(f.rows[l.id]["address"].(netip.Addr), 22).String() ||
				fields["device"] != f.names[l.id] || fields["device_id"] != fmt.Sprint(l.id) || fields["session"] != session.IDString(f.ss.s.ID) {
				t.Fatalf("%s: challenge %v for %v", l.name, ch, res[0])
			}
			return ch
		}
		before := f.typed(l.id)
		refused := func(res []map[string]any, code string) {
			t.Helper()
			if len(res) != 1 || res[0]["type"] != "refused" || res[0]["code"] != code || f.typed(l.id) != before {
				t.Fatalf("%s: %v, device got %d lines; want refused %s", l.name, res, f.typed(l.id)-before, code)
			}
		}
		/* a wrong name, another case of it, or none: refused before the code is looked at */
		for _, name := range []string{"sw-other", strings.ToUpper(f.names[l.id]), f.names[l.id] + " ", ""} {
			refused(f.confirm(t, c, dangerous(), name, f.newCode(t)), "device_name")
		}
		/* no challenge, or another one's id */
		c.send(map[string]any{"type": "dangerous_confirm", "challenge_id": "x", "device_name": f.names[l.id], "totp": f.newCode(t), "ticket": f.ticket(t)})
		refused(c.until(), "nothing_pending")
		/* the right name and a new code: sent, once */
		res := f.confirm(t, c, dangerous(), f.names[l.id], f.newCode(t))
		if len(res) != 1 || res[0]["type"] != "output" || f.typed(l.id) != before+1 {
			t.Fatalf("%s: confirmed: %v, device got %d lines", l.name, res, f.typed(l.id)-before)
		}
		sent := f.terms[l.id].Lines()[f.typed(l.id)-1]
		if sent != res[0]["sent"] || strings.EqualFold(sent, typed) {
			t.Fatalf("%s: device got %q, the challenge covered %q", l.name, sent, res[0]["sent"])
		}
		before++
		/* the same code again (its step is not above the last): refused, not sent */
		refused(f.confirm(t, c, dangerous(), f.names[l.id], f.code), "denied")
		/* a wrong code */
		refused(f.confirm(t, c, dangerous(), f.names[l.id], "000000"), "denied")
		f.mustSend(t, c, l.id, "end")
	}
}

/* More than paste_confirm_lines line breaks in one frame: nothing reaches the device without paste_confirm, the text is shown first. */
func TestPasteOverTheLimitWaitsForConfirmation(t *testing.T) {
	f := newFx(t)
	dev := lines[0].id
	c := f.dial(t, dev)
	six := "configure\nhostname a1\nhostname a2\nhostname a3\nhostname a4\nend\n"
	before := f.typed(dev)
	for _, frame := range []struct{ typ, data string }{{"paste", six}, {"keys", strings.ReplaceAll(six, "\n", "\r")}, {"paste", strings.ReplaceAll(six, "\n", "\r\n")}} {
		c.send(map[string]any{"type": frame.typ, "data": frame.data})
		m := c.next()
		if m["type"] != "paste_pending" || m["text"] != six || f.typed(dev) != before {
			t.Fatalf("%s: %v, device got %d lines", frame.typ, m, f.typed(dev)-before)
		}
		/* while it waits, more input is ignored; declining drops it */
		c.send(map[string]any{"type": "keys", "data": "hostname x\r"})
		c.send(map[string]any{"type": "paste_confirm", "accept": false})
		c.until()
		if f.typed(dev) != before {
			t.Fatalf("declined paste: device got %d lines", f.typed(dev)-before)
		}
	}
	/* at the limit: typed at once; accepted over it: typed */
	if res := c.do("paste", "configure\nhostname b1\nhostname b2\nhostname b3\nend\n"); len(res) != 5 || f.typed(dev) != before+5 {
		t.Fatalf("five lines: %v, device got %d", res, f.typed(dev)-before)
	}
	c.send(map[string]any{"type": "paste", "data": six})
	if m := c.next(); m["type"] != "paste_pending" {
		t.Fatal(m)
	}
	c.send(map[string]any{"type": "paste_confirm", "accept": true})
	for range 6 {
		c.until()
	}
	c.until()
	if f.typed(dev) != before+11 {
		t.Fatalf("accepted paste: device got %d lines", f.typed(dev)-before-5)
	}
}

/* A line being typed (or a dangerous line waiting) when the WebSocket drops is never sent. */
func TestPartialLineNotSentAtDisconnect(t *testing.T) {
	f := newFx(t)
	dev := lines[1].id
	c := f.dial(t, dev)
	before := f.typed(dev)
	c.send(map[string]any{"type": "keys", "data": "configure terminal"})
	c.until()
	_ = c.c.Close(websocket.StatusNormalClosure, "")
	c2 := f.dial(t, dev)
	c2.send(map[string]any{"type": "keys", "data": "reload"})
	c2.until()
	if res := c2.do("keys", "\r"); len(res) != 1 || res[0]["type"] != "dangerous" {
		t.Fatalf("reload: %v", res)
	}
	_ = c2.c.CloseNow()
	time.Sleep(300 * time.Millisecond)
	if n := f.typed(dev) - before; n != 0 {
		t.Fatalf("device got %d lines: %q", n, f.terms[dev].Lines()[before:])
	}
	/* a new terminal starts with an empty line */
	c3 := f.dial(t, dev)
	c3.send(map[string]any{"type": "keys", "data": "x"})
	if m := c3.next(); m["text"] != "x" {
		t.Fatalf("new terminal: %v", m)
	}
}

/* Escape sequences in the device's output (OSC 52 among them), and any control, never reach the browser. */
func TestDeviceEscapesNeverReachTheBrowser(t *testing.T) {
	f := newFx(t)
	for _, l := range lines {
		evil := "\x1b]52;c;ZXZpbA==\x07\x1b]52;c;ZXZpbA==\x1b\\\x1b[2J\x1b[31mred\x1b[0m\u009d52;c;eA==\u009c\x1bP+q\x1b\\\x07\x08\u202eok"
		f.terms[l.id].D.BeforeReply(func(string) (string, time.Duration) { return evil, 0 })
		c := f.dial(t, l.id)
		res := c.do("keys", "show clock\r")
		f.terms[l.id].D.BeforeReply(func(string) (string, time.Duration) { return "", 0 })
		if len(res) == 0 || res[0]["type"] != "output" {
			t.Fatalf("%s: %v", l.name, res)
		}
		text := res[0]["text"].(string)
		if !strings.Contains(text, "redok") || strings.Contains(text, "52;") || strings.Contains(text, "ZXZpbA") {
			t.Fatalf("%s: output %q", l.name, text)
		}
	}
}

/* Tab and '?' are answered from the grammar: the device gets nothing. */
func TestTabAndHelpNeverReachTheDevice(t *testing.T) {
	f := newFx(t)
	for _, l := range lines {
		c := f.dial(t, l.id)
		before := f.typed(l.id)
		c.send(map[string]any{"type": "keys", "data": "configu\t"})
		if m := c.next(); m["type"] != "edit" || m["text"] != "configure " {
			t.Fatalf("%s: tab: %v", l.name, m)
		}
		c.send(map[string]any{"type": "keys", "data": "\x15sh"})
		c.next()
		c.send(map[string]any{"type": "keys", "data": "?"})
		if m := c.next(); m["type"] != "help" || len(m["words"].([]any)) == 0 {
			t.Fatalf("%s: help: %v", l.name, m)
		}
		c.next()
		c.send(map[string]any{"type": "keys", "data": "\t\t?\x15"})
		for {
			if m := c.next(); m["type"] == "edit" && m["text"] == "" {
				break
			}
		}
		/* a '?' pasted into a line refuses the line */
		if res := c.do("paste", "show ?\n"); len(res) != 1 || res[0]["type"] != "refused" {
			t.Fatalf("%s: pasted ?: %v", l.name, res)
		}
		if n := f.typed(l.id) - before; n != 0 {
			t.Fatalf("%s: device got %d lines: %q", l.name, n, f.terms[l.id].Lines()[before:])
		}
	}
}

/* The Origin must be the executor's; the first frame must be the session's token; control lines are not sent; the hourly limit holds. */
func TestOriginTokenControlAndLimit(t *testing.T) {
	f := newFx(t)
	for _, origin := range []string{"", "https://panel.example", f.srv.URL + ".evil"} {
		if _, resp, err := f.dialRaw(t, origin); err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
			t.Errorf("origin %q: %v", origin, err)
		}
	}
	ws, _, err := f.dialRaw(t, f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c := &client{t: t, c: ws}
	c.send(map[string]any{"type": "auth", "session_id": session.IDString(f.ss.s.ID), "token": "wrong", "device_id": lines[0].id})
	if m := c.next(); m["type"] != "ended" {
		t.Fatalf("wrong token: %v", m)
	}
	dev := lines[0].id
	c = f.dial(t, dev)
	before := f.typed(dev)
	for _, l := range []string{"write", "copy running-config startup-config", "wr mem"} {
		if res := c.line(l); res["type"] != "refused" || res["code"] != "control" && res["code"] != "denied" {
			t.Fatalf("%q: %v", l, res)
		}
	}
	if f.typed(dev) != before {
		t.Fatal("a control line reached the device")
	}
	f.policy(t, "max_config_lines_per_hour: 2\n")
	f.mustSend(t, c, dev, "show running-config")
	f.mustSend(t, c, dev, "show running-config")
	if res := c.line("show running-config"); res["type"] != "refused" || res["code"] != "line_limit" || f.typed(dev) != before+2 {
		t.Fatalf("over the limit: %v", res)
	}
	/* the session ended: the terminal ends */
	f.ss.mu.Lock()
	f.ss.ended = true
	f.ss.mu.Unlock()
	c.send(map[string]any{"type": "keys", "data": "x"})
	if m := c.next(); m["type"] != "ended" {
		t.Fatalf("ended session: %v", m)
	}
}
