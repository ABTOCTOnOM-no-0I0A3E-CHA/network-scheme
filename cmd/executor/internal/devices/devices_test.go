package devices_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	gossh "golang.org/x/crypto/ssh"

	"github.com/beekamai/network-scheme/cmd/executor/internal/admin"
	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/confirm"
	"github.com/beekamai/network-scheme/cmd/executor/internal/devices"
	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/cmd/executor/internal/netguard"
	"github.com/beekamai/network-scheme/cmd/executor/internal/policy"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/transport"
	"github.com/beekamai/network-scheme/internal/execadmin"
	"github.com/beekamai/network-scheme/internal/secret"
	"github.com/beekamai/network-scheme/internal/testdb"
	"github.com/beekamai/network-scheme/internal/ticket"
	"github.com/beekamai/network-scheme/test/sim/devemu"
	"github.com/beekamai/network-scheme/test/sim/sshemu"
)

func TestMain(m *testing.M) { testdb.Main(m) }

var ticketKey = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

/* The stack's networks, and management subnets that cover the other classes: the deny rules must win. */
var stack = netguard.Stack{Core: netip.MustParsePrefix("172.30.0.0/24"), Devices: netip.MustParsePrefix("172.30.1.0/24"),
	Xnet: netip.MustParsePrefix("172.30.2.0/24"), Edge: netip.MustParsePrefix("172.30.3.0/24")}

var mgmt = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.30.1.0/24"),
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("224.0.0.0/8"),
	netip.MustParsePrefix("239.0.0.0/8"), netip.MustParsePrefix("240.0.0.0/8")}

/*
fx is one executor (registry, guard, authz, confirm store, administration
and the device service) over the test database. Device addresses are
management addresses; the network guard's dial seam routes the ones a test
set to emulators on loopback and records every connection.
*/
type fx struct {
	env   *testdb.Env
	guard *freeze.Guard
	az    *authz.Authorizer
	store *confirm.Store
	adm   *admin.Admin
	svc   *devices.Service
	acts  map[string]devices.Action
	ng    *netguard.Guard
	reads map[string]devices.Read

	mu     sync.Mutex
	routes map[string]netip.AddrPort
	dialed []string
	offset atomic.Int64 /* the fake clock: each change TOTP code is one step later */
	start  time.Time
}

func (f *fx) now() time.Time { return f.start.Add(time.Duration(f.offset.Load())) }

func newFx(t *testing.T) *fx {
	t.Helper()
	env := testdb.New(t)
	attacktest.Reset(t, env)
	ctx := context.Background()
	keys, err := seal.Derive(&[32]byte{9})
	if err != nil {
		t.Fatal(err)
	}
	f := &fx{env: env, routes: map[string]netip.AddrPort{}, start: time.Now()}
	pool := env.Pool("nms_executor")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()
	reg := registry.New(pool, keys, filepath.Join(dir, "state"))
	f.guard = freeze.New(reg, pool, log)
	if err := f.guard.Start(ctx); err != nil {
		t.Fatal(err)
	}
	polFile := filepath.Join(dir, "executor.yaml")
	if err := os.WriteFile(polFile, []byte("enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pol := policy.New(polFile)
	pol.Reload(true)
	if f.az, err = authz.New(authz.Config{Guard: f.guard, Reg: reg, Keys: keys, Policy: pol, Log: log, Now: f.now,
		TicketKey: ticketKey.Public().(ed25519.PublicKey), Started: f.start, GuardsFile: filepath.Join(dir, "guards")}); err != nil {
		t.Fatal(err)
	}
	f.store = confirm.New(f.az, f.now)
	ng, err := netguard.New(mgmt, stack, func(ctx context.Context, _, address string) (net.Conn, error) {
		f.mu.Lock()
		f.dialed = append(f.dialed, address)
		to, ok := f.routes[address]
		f.mu.Unlock()
		if !ok {
			return nil, fmt.Errorf("test: nothing at %s", address)
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", to.String())
	})
	if err != nil {
		t.Fatal(err)
	}
	f.svc, f.ng = devices.New(f.guard, reg, ng, log), ng
	f.acts = f.svc.Actions()
	f.reads = map[string]devices.Read{"list": f.svc.List(), "probe": f.svc.ProbeRead()}
	f.adm = &admin.Admin{Guard: f.guard, Reg: reg, Keys: keys, Policy: pol, Log: log, Lockouts: f.az, Devices: f.svc}
	return f
}

/* emulator serves a fresh device of line on loopback (password secret) behind the management address at. */
func (f *fx) emulator(t *testing.T, line, at string) (*devemu.Device, *sshemu.Log, gossh.PublicKey) {
	t.Helper()
	d := devemu.NewLine(t, line, devemu.Options{})
	addr, key, log := devemu.StartSSH(t, d, func(c *sshemu.Config) { c.Username, c.Password = "admin", "secret" })
	f.mu.Lock()
	f.routes[at+":22"] = addr
	f.mu.Unlock()
	return d, log, key
}

func (f *fx) dials(to string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, d := range f.dialed {
		if strings.HasPrefix(d, to+":") {
			n++
		}
	}
	return n
}

func (f *fx) anyDial() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.dialed)
}

/* mgmtAddr is a fresh management address (core.device is shared by the tests' database). */
func mgmtAddr() string {
	return fmt.Sprintf("10.%d.%d.%d", rand.IntN(250)+1, rand.IntN(250)+1, rand.IntN(250)+1)
}

/* panelDevice adds a core.device row at addr (as the api would) and returns its id. */
func (f *fx) panelDevice(t *testing.T, addr string) int64 {
	t.Helper()
	p := f.env.Pool("postgres")
	var gid, id int64
	if err := p.QueryRow(context.Background(), `INSERT INTO core.device_group (name) VALUES ('wd-' || gen_random_uuid()) RETURNING id`).Scan(&gid); err != nil {
		t.Fatal(err)
	}
	if err := p.QueryRow(context.Background(), `INSERT INTO core.device (name, address, group_id) VALUES ($1, $2, $3) RETURNING id`,
		"sw-"+addr, addr, gid).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

/* user is a panel user with a change TOTP and the given grants (nmsctl); it returns id, name and secret. */
func (f *fx) user(t *testing.T, prefix string, grants ...execadmin.Request) (int64, string, string) {
	t.Helper()
	name := fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()%1e9)
	var id int64
	if err := f.env.Pool("postgres").QueryRow(context.Background(),
		`INSERT INTO core."user" (username, password_phc) VALUES ($1, 'x') RETURNING id`, name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	var sec string
	for _, req := range append([]execadmin.Request{{Cmd: execadmin.CmdEnroll}}, grants...) {
		req.User = name
		resp := f.host(req)
		if resp.OK && resp.Confirm != nil {
			req.UserID, req.UserCreated = resp.Confirm.ID, resp.Confirm.CreatedAt
			resp = f.host(req)
		}
		if !resp.OK {
			t.Fatalf("%s: %s", req.Cmd, resp.Error)
		}
		if resp.Enrollment != nil {
			sec = resp.Enrollment.Secret
		}
	}
	return id, name, sec
}

var writeAdmin = execadmin.Request{Cmd: execadmin.CmdGrant, Kind: execadmin.KindWriteAdmin}

func (f *fx) host(req execadmin.Request) execadmin.Response {
	req.V, req.Operator = execadmin.Version, "tester"
	return f.adm.Handle(context.Background(), req)
}

type who struct {
	id         int64
	name, totp string
}

func (f *fx) ticket(t *testing.T, u who) string {
	t.Helper()
	s, _, err := ticket.Issue(ticketKey, u.id, u.name, f.now())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

/* describe is POST /x/confirm/issue of action: authz identifies the ticket's user, the action describes itself. */
func (f *fx) describe(t *testing.T, u who, action, params string) (confirm.Challenge, error) {
	t.Helper()
	ctx := context.Background()
	by, err := f.az.Identify(ctx, authz.Request{Ticket: f.ticket(t, u), Action: "confirm.issue", Object: action})
	if err != nil {
		return confirm.Challenge{}, err
	}
	need, d, err := f.acts[action].Describe(ctx, by, json.RawMessage(params))
	if err != nil {
		return confirm.Challenge{}, err
	}
	return f.store.Issue(by.UserID, need, d)
}

/* code is the user's next change TOTP code (one step later each time). */
func (f *fx) code(t *testing.T, u who) string {
	t.Helper()
	f.offset.Add(int64(30 * time.Second))
	c, err := totp.GenerateCodeCustom(u.totp, f.now(), totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

/* read is POST /x/devices[/probe] with code ("" for none): authz decides (ticket, TOTP, write-admin), then the read. */
func (f *fx) read(t *testing.T, u who, name, code, params string) (any, error) {
	t.Helper()
	rd := f.reads[name]
	by, err := f.az.Authorize(context.Background(), authz.Request{Ticket: f.ticket(t, u), Code: code, Need: rd.Need, Action: rd.Action})
	if err != nil {
		return nil, err
	}
	return rd.Run(context.Background(), by, json.RawMessage(params))
}

/* probe reads the host key the way the UI does (kind register or accept_hostkey) and returns the shown fields. */
func (f *fx) probe(t *testing.T, u who, kind, params string) map[string]string {
	t.Helper()
	p := `{"kind":"` + kind + `",` + strings.TrimPrefix(params, "{")
	res, err := f.read(t, u, "probe", f.code(t, u), p)
	if err != nil {
		t.Fatalf("probe %s: %v", p, err)
	}
	return res.(map[string]string)
}

/* withKey adds the probed key to issue params. */
func withKey(params string, shown map[string]string) string {
	return strings.TrimSuffix(params, "}") + fmt.Sprintf(`,"hostkey_algo":%q,"hostkey_fp":%q}`, shown["hostkey_algo"], shown["hostkey_fp"])
}

/* confirmRun is POST /x/confirm of ch with a fresh change TOTP code, then the action. */
func (f *fx) confirmRun(t *testing.T, u who, ch confirm.Challenge) error {
	t.Helper()
	c, by, err := f.store.Confirm(context.Background(), ch.ID, ch.H[:], authz.Request{Ticket: f.ticket(t, u), Code: f.code(t, u)})
	if err != nil {
		return err
	}
	_, err = f.acts[c.Action].Run(context.Background(), c, by)
	return err
}

/* do is the whole UI flow: for a key action the probe first, then describe and confirm; it fails the test on any error. */
func (f *fx) do(t *testing.T, u who, action, params string) confirm.Challenge {
	t.Helper()
	if kind, ok := map[string]string{devices.ActionRegister: "register", devices.ActionAccept: "accept_hostkey"}[action]; ok {
		params = withKey(params, f.probe(t, u, kind, params))
	}
	ch, err := f.describe(t, u, action, params)
	if err != nil {
		t.Fatalf("%s %s: %v", action, params, err)
	}
	if err := f.confirmRun(t, u, ch); err != nil {
		t.Fatalf("confirm %s: %v", action, err)
	}
	return ch
}

func field(ch confirm.Challenge, key string) string {
	for _, x := range ch.Description.Fields {
		if x.Key == key {
			return x.Value
		}
	}
	return ""
}

func (f *fx) device(t *testing.T, id int64) devices.Device {
	t.Helper()
	var d devices.Device
	var ok bool
	if err := f.guard.View(context.Background(), func(s *registry.Snapshot) error { d, ok = devices.Find(s, id); return nil }); err != nil || !ok {
		t.Fatalf("device %d: %v %v", id, ok, err)
	}
	return d
}

func (f *fx) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := f.env.Pool("postgres").QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

/* login connects as the executor does (package transport, read-only), alerts recorded in f. */
func (f *fx) login(ctx context.Context, id int64) error {
	sh, err := transport.Dial(ctx, transport.Config{DeviceID: id, Access: transport.ReadOnly, Registry: f.guard, Net: f.ng,
		Credential: transport.Credential{Username: "admin", Password: secret.New("secret")}, CommandTimeout: 5 * time.Second,
		Alert: func(context.Context, string, string, int64, string) error { return nil }})
	if err == nil {
		_ = sh.Close()
	}
	return err
}

/*
C2c: the api moves core.device to emulator B and to another group between
the probe, the description and the confirmation. Registration stores the
address the user confirmed (the panel's at probe time, marked as such in
H), the host key flow and the connection go to the registry's address, and
B is never contacted: no connection, nothing in its journal or auth log.
*/
func TestC2cAPIChangesAddressAndGroup(t *testing.T) {
	f := newFx(t)
	a, b := mgmtAddr(), mgmtAddr()
	_, logA, keyA := f.emulator(t, "mes10", a)
	devB, logB, _ := f.emulator(t, "mes10", b)
	id := f.panelDevice(t, a)
	uid, name, sec := f.user(t, "c2c", writeAdmin)
	u := who{uid, name, sec}
	api := attacktest.NewAttacker(f.env, ticketKey)
	ctx := context.Background()

	params := fmt.Sprintf(`{"device_id":%d,"write_group":"core","write_driver":"mes10"}`, id)
	shown := f.probe(t, u, "register", params)
	if shown["address"] != a || shown["address_source"] != devices.SourcePanel || shown["hostkey_fp"] != gossh.FingerprintSHA256(keyA) {
		t.Fatalf("probe %v", shown)
	}
	ch, err := f.describe(t, u, devices.ActionRegister, withKey(params, shown))
	if err != nil {
		t.Fatal(err)
	}
	if field(ch, "address") != a || field(ch, "address_source") != "panel" || field(ch, "panel_address") != a {
		t.Fatalf("description %+v", ch.Description)
	}
	var gid int64
	if err := f.env.Pool("postgres").QueryRow(ctx, `INSERT INTO core.device_group (name) VALUES ('lax-' || gen_random_uuid()) RETURNING id`).Scan(&gid); err != nil {
		t.Fatal(err)
	}
	if err := api.Exec(ctx, `UPDATE core.device SET address = $1, group_id = $2 WHERE id = $3`, b, gid, id); err != nil {
		t.Fatalf("api update: %v", err)
	}
	if err := f.confirmRun(t, u, ch); err != nil {
		t.Fatal(err)
	}
	if d := f.device(t, id); d.Address.String() != a || d.Group != "core" || d.FP != gossh.FingerprintSHA256(keyA) || d.Writes {
		t.Fatalf("registered %+v", d)
	}
	ch = f.do(t, u, devices.ActionAccept, fmt.Sprintf(`{"device_id":%d}`, id))
	if field(ch, "address") != a || field(ch, "write_group") != "core" || field(ch, "address_source") != devices.SourceRegistry {
		t.Fatalf("accept described %+v", ch.Description)
	}
	if n := len(logA.AuthAttempts()); n != 0 {
		t.Fatalf("probes sent %d authentications", n)
	}
	f.do(t, u, devices.ActionWrites, fmt.Sprintf(`{"device_id":%d,"enabled":true}`, id))
	if err := f.login(ctx, id); err != nil {
		t.Fatal(err)
	}
	if f.dials(b) != 0 || len(devB.Journal()) != 0 || len(logB.AuthAttempts()) != 0 {
		t.Fatalf("B contacted: %d dials, journal %v, auth %v", f.dials(b), devB.Journal(), logB.AuthAttempts())
	}
	/* register: probe + re-probe after TOTP; accept: the same; the login */
	if f.dials(a) != 5 || len(logA.AuthAttempts()) == 0 {
		t.Fatalf("A: %d dials, auth %v", f.dials(a), logA.AuthAttempts())
	}
	if resp := f.host(execadmin.Request{Cmd: execadmin.CmdDevice, Action: "accept-hostkey", DeviceID: id}); !resp.OK || resp.Device.Address != a {
		t.Fatalf("host preview %+v", resp)
	}
	if f.dials(b) != 0 {
		t.Fatal("host preview contacted B")
	}
}

/*
I1: issuing a challenge needs only a ticket, which a compromised api forges
for any write-admin: describing a registration or a host key acceptance
makes no connection at all, and the probe without the user's code is
refused by authz before any dial.
*/
func TestForgedTicketMakesNoConnection(t *testing.T) {
	f := newFx(t)
	a := mgmtAddr()
	f.emulator(t, "mes10", a)
	uid, name, sec := f.user(t, "i1", writeAdmin)
	u := who{uid, name, sec}
	f.do(t, u, devices.ActionRegister, fmt.Sprintf(`{"device_id":41,"address":%q,"write_group":"core","write_driver":"mes10"}`, a))
	before := f.anyDial()
	forged := who{uid, name, ""} /* the api signs tickets; it has no change TOTP */
	fp := `"hostkey_algo":"ssh-ed25519","hostkey_fp":"SHA256:` + strings.Repeat("A", 43) + `"`
	for _, x := range []struct{ action, params string }{
		{devices.ActionRegister, `{"device_id":42,"address":"10.200.0.1","write_group":"core","write_driver":"mes10",` + fp + `}`},
		{devices.ActionAccept, `{"device_id":41,"address":"10.200.0.2",` + fp + `}`},
	} {
		if _, err := f.describe(t, forged, x.action, x.params); err != nil {
			t.Fatalf("%s: %v", x.action, err)
		}
	}
	for _, kind := range []string{"register", "accept_hostkey"} {
		if _, err := f.read(t, forged, "probe", "", `{"kind":"`+kind+`","device_id":41,"address":"10.200.0.3","write_group":"core","write_driver":"mes10"}`); !errors.Is(err, authz.ErrDenied) {
			t.Fatalf("probe %s without a code: %v", kind, err)
		}
	}
	if n := f.anyDial() - before; n != 0 {
		t.Fatalf("%d connections from forged tickets", n)
	}
}

/*
C5 (registry side): the device is replaced at its address. The new key is
taken only through the same confirmation: the description carries the old
pin and the new key, Run reads the device again and refuses a key other
than the confirmed one, and the host cannot pin a fingerprint the device
does not present. The refusal of the old pin at connection time is
transport's (TestHostKeyStrategy, TestNoKeyOfThePinnedTypeIsAMismatch).
*/
func TestReplacedKeyOnlyThroughConfirmation(t *testing.T) {
	f := newFx(t)
	a := mgmtAddr()
	f.emulator(t, "mes10", a)
	id := f.panelDevice(t, a)
	uid, name, sec := f.user(t, "c5", writeAdmin)
	u := who{uid, name, sec}
	f.do(t, u, devices.ActionRegister, fmt.Sprintf(`{"device_id":%d,"write_group":"core","write_driver":"mes10"}`, id))
	pinned := f.device(t, id).FP
	params := fmt.Sprintf(`{"device_id":%d}`, id)
	shownOld := f.probe(t, u, "accept_hostkey", params)

	dev2, log2, key2 := f.emulator(t, "mes10", a) /* the device replaced (or an impostor) at the same address */
	if err := f.login(context.Background(), id); !errors.Is(err, transport.ErrHostKeyMismatch) {
		t.Fatalf("login to the replaced device: %v", err)
	}
	/* A challenge for the key shown before the replacement: Run reads the new key and refuses. */
	stale, err := f.describe(t, u, devices.ActionAccept, withKey(params, shownOld))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.confirmRun(t, u, stale); !devices.IsRefusal(err) || f.device(t, id).FP != pinned {
		t.Fatalf("accepting a key the device does not present: %v", err)
	}
	if resp := f.host(execadmin.Request{Cmd: execadmin.CmdDevice, Action: "accept-hostkey", DeviceID: id, Fingerprint: pinned}); resp.OK {
		t.Fatal("host accepted the old fingerprint for the new key")
	}
	ch := f.do(t, u, devices.ActionAccept, params)
	if field(ch, "pinned_fp") != pinned || field(ch, "hostkey_fp") != gossh.FingerprintSHA256(key2) {
		t.Fatalf("accept described %+v", ch.Description)
	}
	if n := len(log2.AuthAttempts()); n != 0 || len(dev2.Journal()) != 0 {
		t.Fatalf("probes reached the device beyond the key exchange: %v %v", log2.AuthAttempts(), dev2.Journal())
	}
	if err := f.login(context.Background(), id); err != nil {
		t.Fatalf("login after accepting: %v", err)
	}
}

/* A device that only has an ssh-rsa (SHA-1) host key is read only with allow_ssh_rsa_sha1 [R §9.10]. */
func TestSHA1HostKeyNeedsTheFlag(t *testing.T) {
	f := newFx(t)
	a := mgmtAddr()
	_, log, _ := f.emulator(t, "mes6", a)
	ctx := context.Background()
	t6 := devices.Target{ID: 6, Address: netip.MustParseAddr(a), Port: 22, Group: "core", Driver: "mes6"}
	if _, err := f.svc.Probe(ctx, t6); err == nil {
		t.Fatal("ssh-rsa host key read without allow_ssh_rsa_sha1")
	}
	t6.AllowSHA1 = true
	if k, err := f.svc.Probe(ctx, t6); err != nil || k.Algo != gossh.KeyAlgoRSA {
		t.Fatalf("probe with the flag: %+v %v", k, err)
	}
	if n := len(log.AuthAttempts()); n != 0 {
		t.Fatalf("probes sent %d authentications", n)
	}
}

/*
SSRF: the probe, the description and nmsctl refuse loopback, link-local,
multicast, reserved, unspecified, broadcast and the core, xnet, devices and
edge subnets (and anything outside the management subnets), entered or from
the panel's prefill, without a single dial.
*/
func TestSSRFAddressesRefused(t *testing.T) {
	f := newFx(t)
	uid, name, sec := f.user(t, "ssrf", writeAdmin)
	u := who{uid, name, sec}
	fp := `,"hostkey_algo":"ssh-ed25519","hostkey_fp":"SHA256:` + strings.Repeat("A", 43) + `"`
	for _, addr := range []string{"127.0.0.1", "169.254.169.254", "224.0.0.5", "239.1.1.1", "240.0.0.1", "0.0.0.0", "255.255.255.255",
		"172.30.0.10", "172.30.1.10", "172.30.2.10", "172.30.3.10", "192.168.9.9", "::1", "fe80::1", "10.0.0.0"} {
		params := fmt.Sprintf(`{"device_id":5,"address":%q,"write_group":"core","write_driver":"esr"`, addr)
		if _, err := f.read(t, u, "probe", f.code(t, u), `{"kind":"register",`+params[1:]+`}`); !devices.IsRefusal(err) {
			t.Errorf("/x probe %s: %v", addr, err)
		}
		if _, err := f.describe(t, u, devices.ActionRegister, params+fp+`}`); !devices.IsRefusal(err) {
			t.Errorf("/x register %s: %v", addr, err)
		}
		if resp := f.host(execadmin.Request{Cmd: execadmin.CmdDevice, Action: "add", DeviceID: 5, Address: addr, Group: "core", Driver: "esr"}); resp.OK {
			t.Errorf("nmsctl add %s accepted", addr)
		}
	}
	id := f.panelDevice(t, "172.30.3."+fmt.Sprint(rand.IntN(200)+10)) /* the api points a device at the edge subnet */
	if _, err := f.read(t, u, "probe", f.code(t, u), fmt.Sprintf(`{"kind":"register","device_id":%d,"write_group":"core","write_driver":"esr"}`, id)); !devices.IsRefusal(err) {
		t.Errorf("prefill into edge: %v", err)
	}
	a := mgmtAddr()
	f.emulator(t, "mes10", a)
	f.do(t, u, devices.ActionRegister, fmt.Sprintf(`{"device_id":9,"address":%q,"write_group":"core","write_driver":"mes10"}`, a))
	before := f.anyDial()
	if _, err := f.read(t, u, "probe", f.code(t, u), `{"kind":"accept_hostkey","device_id":9,"address":"172.30.2.2"}`); !devices.IsRefusal(err) {
		t.Errorf("accept into xnet: %v", err)
	}
	if n := f.anyDial(); n != before {
		t.Fatalf("%d refused addresses were dialed", n-before)
	}
}

/*
Without write-admin (a user with a write grant only) nothing is read from a
device and nothing changes: the probe and the description are refused (and
audited), and a challenge needing write-admin is refused even with a valid code.
*/
func TestWithoutWriteAdminRefused(t *testing.T) {
	f := newFx(t)
	a := mgmtAddr()
	f.emulator(t, "mes10", a)
	uid, name, sec := f.user(t, "nowa", execadmin.Request{Cmd: execadmin.CmdGrant, Kind: execadmin.KindWrite, Group: "core"})
	u := who{uid, name, sec}
	params := fmt.Sprintf(`{"device_id":3,"address":%q,"write_group":"core","write_driver":"mes10"`, a)
	if _, err := f.read(t, u, "probe", f.code(t, u), `{"kind":"register",`+params[1:]+`}`); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("probe without write-admin: %v", err)
	}
	_, err := f.describe(t, u, devices.ActionRegister, params+`,"hostkey_algo":"ssh-ed25519","hostkey_fp":"SHA256:`+strings.Repeat("A", 43)+`"}`)
	if !devices.IsRefusal(err) || f.anyDial() != 0 {
		t.Fatalf("describe without write-admin: %v, %d dials", err, f.anyDial())
	}
	if n := f.count(t, `SELECT count(*) FROM exec.audit_event WHERE action = 'device.register' AND result = 'denied' AND user_id = $1`, uid); n != 1 {
		t.Fatalf("%d denied audit rows", n)
	}
	d := confirm.Description{Action: devices.ActionWrites, Fields: []confirm.Field{{Key: "device", Value: "3"}}}
	ch, err := f.store.Issue(uid, authz.Need{Kind: execadmin.KindWriteAdmin}, d)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.confirmRun(t, u, ch); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("confirm without write-admin: %v", err)
	}
	if n := f.count(t, `SELECT count(*) FROM exec.write_device`); n != 0 {
		t.Fatalf("%d devices", n)
	}
}

/* Every change, through /x and nmsctl, is one audit row of its own in the change's transaction; refusals are rows too. */
func TestEveryChangeIsAudited(t *testing.T) {
	f := newFx(t)
	a := mgmtAddr()
	_, _, key := f.emulator(t, "mes10", a)
	uid, name, sec := f.user(t, "aud", writeAdmin)
	u := who{uid, name, sec}
	audits := func(action, result string) int {
		return f.count(t, `SELECT count(*) FROM exec.audit_event WHERE action = $1 AND result = $2`, action, result)
	}
	f.do(t, u, devices.ActionRegister, fmt.Sprintf(`{"device_id":11,"address":%q,"write_group":"core","write_driver":"mes10"}`, a))
	f.do(t, u, devices.ActionWrites, `{"device_id":11,"enabled":true}`)
	f.do(t, u, devices.ActionAccept, `{"device_id":11,"write_group":"edge-sw"}`)
	if d := f.device(t, 11); d.Group != "edge-sw" || d.Writes {
		t.Fatalf("accept with a new group must turn writes off: %+v", d)
	}
	fp := gossh.FingerprintSHA256(key)
	yes, no := true, false
	for _, req := range []execadmin.Request{
		{Cmd: execadmin.CmdDevice, Action: "add", DeviceID: 12, Address: a, Group: "core", Driver: "mes10", Backup: &yes, Fingerprint: fp},
		{Cmd: execadmin.CmdDevice, Action: "writes-on", DeviceID: 12},
		{Cmd: execadmin.CmdDevice, Action: "writes-off", DeviceID: 12},
		{Cmd: execadmin.CmdDevice, Action: "accept-hostkey", DeviceID: 12, Port: 22, Backup: &no, Fingerprint: fp},
	} {
		if resp := f.host(req); !resp.OK {
			t.Fatalf("%+v: %s", req, resp.Error)
		}
	}
	if f.device(t, 12).Backup {
		t.Fatal("nmsctl accept-hostkey --backup-via-executor=false left the flag on")
	}
	if resp := f.host(execadmin.Request{Cmd: execadmin.CmdDevice, Action: "add", DeviceID: 12, Address: a, Group: "core", Driver: "mes10", Fingerprint: fp}); resp.OK {
		t.Fatal("second add accepted")
	}
	for action, want := range map[string][2]int{
		"device.register": {1, 0}, "device.writes": {1, 0}, "device.accept_hostkey": {1, 0}, "device.probe": {2, 0},
		"confirm.device.register": {1, 0}, "confirm.device.writes": {1, 0}, "confirm.device.accept_hostkey": {1, 0},
		"admin.device.add": {1, 1}, "admin.device.writes-on": {1, 0}, "admin.device.writes-off": {1, 0}, "admin.device.accept-hostkey": {1, 0},
	} {
		if ok, denied := audits(action, "ok"), audits(action, "denied"); ok != want[0] || denied != want[1] {
			t.Errorf("%s: %d ok, %d denied; want %v", action, ok, denied, want)
		}
	}
	var payload []byte
	if err := f.env.Pool("postgres").QueryRow(context.Background(), `SELECT payload FROM exec.audit_event WHERE action = 'device.accept_hostkey'`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"write_group":"edge-sw"`, `"hostkey_fp":"` + fp, `"before":`, `"username":"` + name} {
		if !strings.Contains(string(payload), want) {
			t.Errorf("audit row lacks %s: %s", want, payload)
		}
	}
	if resp := f.host(execadmin.Request{Cmd: execadmin.CmdAuditVerify}); !resp.OK {
		t.Fatal(resp.Error)
	}
}

/*
I2: nmsctl accept-hostkey binds the row version of its preview: a device
changed between the preview and the confirmation (here: writes turned on
from /x) is refused, and so is a confirmation for a version that never was.
*/
func TestHostAcceptBindsThePreviewedRow(t *testing.T) {
	f := newFx(t)
	a := mgmtAddr()
	f.emulator(t, "mes10", a)
	uid, name, sec := f.user(t, "i2", writeAdmin)
	u := who{uid, name, sec}
	f.do(t, u, devices.ActionRegister, fmt.Sprintf(`{"device_id":51,"address":%q,"write_group":"core","write_driver":"mes10"}`, a))
	pre := f.host(execadmin.Request{Cmd: execadmin.CmdDevice, Action: "accept-hostkey", DeviceID: 51})
	if !pre.OK || pre.Device == nil || pre.Device.Version == 0 {
		t.Fatalf("preview %+v", pre)
	}
	f.do(t, u, devices.ActionWrites, `{"device_id":51,"enabled":true}`)
	v := pre.Device
	confirmReq := execadmin.Request{Cmd: execadmin.CmdDevice, Action: "accept-hostkey", DeviceID: 51, Address: v.Address, Port: v.Port,
		Group: v.Group, Driver: v.Driver, AllowSHA1: &v.AllowSHA1, Backup: &v.Backup, Fingerprint: v.Fingerprint, DeviceVersion: v.Version}
	if resp := f.host(confirmReq); resp.OK || !strings.Contains(resp.Error, "changed since the preview") {
		t.Fatalf("stale host confirmation: %+v", resp)
	}
	if !f.device(t, 51).Writes {
		t.Fatal("the refused confirmation changed the device")
	}
	cur := f.device(t, 51)
	confirmReq.DeviceVersion = cur.Version
	if resp := f.host(confirmReq); !resp.OK {
		t.Fatalf("fresh host confirmation: %s", resp.Error)
	}
}

/*
A device kept by a registry reset has no pinned key: it is listed as from
reset and unconfirmed, is never dialed, cannot get writes on, and becomes
usable only after its host key (and with it every routing field) is
accepted again; writes stay off until enabled anew.
*/
func TestResetDeviceUnusableUntilConfirmed(t *testing.T) {
	f := newFx(t)
	a := mgmtAddr()
	f.emulator(t, "mes10", a)
	uid, name, sec := f.user(t, "rst", writeAdmin)
	u := who{uid, name, sec}
	f.do(t, u, devices.ActionRegister, fmt.Sprintf(`{"device_id":21,"address":%q,"write_group":"core","write_driver":"mes10"}`, a))
	f.do(t, u, devices.ActionWrites, `{"device_id":21,"enabled":true}`)
	if resp := f.host(execadmin.Request{Cmd: execadmin.CmdRegistryReset, IUnderstand: true}); !resp.OK {
		t.Fatalf("reset: %s", resp.Error)
	}
	if d := f.device(t, 21); d.Pinned() || d.Writes || d.Status != devices.StatusUnconfirmed {
		t.Fatalf("after reset %+v", d)
	}
	if resp := f.host(execadmin.Request{Cmd: execadmin.CmdDevice, Action: "list"}); !resp.OK || !strings.Contains(resp.Text, "from reset, unconfirmed") {
		t.Fatalf("list %+v", resp)
	}
	before := f.anyDial()
	if err := f.login(context.Background(), 21); !errors.Is(err, transport.ErrNoHostKey) || f.anyDial() != before {
		t.Fatalf("dial of an unconfirmed device: %v", err)
	}
	if resp := f.host(execadmin.Request{Cmd: execadmin.CmdDevice, Action: "writes-on", DeviceID: 21}); resp.OK {
		t.Fatal("writes on for an unconfirmed device")
	}
	if resp := f.host(execadmin.Request{Cmd: execadmin.CmdDevice, Action: "writes-off", DeviceID: 21}); !resp.OK || f.device(t, 21).Pinned() {
		t.Fatalf("writes off for an unconfirmed device: %+v", resp)
	}
	uid, name, sec = f.user(t, "rst2", writeAdmin) /* the reset revoked the grants and TOTPs */
	u = who{uid, name, sec}
	if _, err := f.describe(t, u, devices.ActionWrites, `{"device_id":21,"enabled":true}`); !devices.IsRefusal(err) {
		t.Fatalf("/x writes on for an unconfirmed device: %v", err)
	}
	ch := f.do(t, u, devices.ActionAccept, `{"device_id":21}`)
	if field(ch, "status") != devices.StatusUnconfirmed || field(ch, "pinned_fp") != "none" || field(ch, "address") != a {
		t.Fatalf("accept described %+v", ch.Description)
	}
	if d := f.device(t, 21); !d.Pinned() || d.Writes {
		t.Fatalf("after accept %+v", d)
	}
	f.do(t, u, devices.ActionWrites, `{"device_id":21,"enabled":true}`)
	if err := f.login(context.Background(), 21); err != nil {
		t.Fatal(err)
	}
}

/* A confirmation shown for one version of a device is refused once the device changed (stale H). */
func TestStaleConfirmationRefused(t *testing.T) {
	f := newFx(t)
	a := mgmtAddr()
	f.emulator(t, "mes10", a)
	uid, name, sec := f.user(t, "stale", writeAdmin)
	u := who{uid, name, sec}
	f.do(t, u, devices.ActionRegister, fmt.Sprintf(`{"device_id":31,"address":%q,"write_group":"core","write_driver":"mes10"}`, a))
	on, err := f.describe(t, u, devices.ActionWrites, `{"device_id":31,"enabled":true}`)
	if err != nil {
		t.Fatal(err)
	}
	f.do(t, u, devices.ActionAccept, `{"device_id":31,"port":22,"backup_via_executor":true}`)
	if err := f.confirmRun(t, u, on); !devices.IsRefusal(err) {
		t.Fatalf("stale confirmation: %v", err)
	}
	if f.device(t, 31).Writes {
		t.Fatal("writes on from a stale confirmation")
	}
}

/* I3: an unknown outcome is not a refusal; /x answers it 503 outcome_unknown (package web's Refusal/HTTPStatus convention). */
func TestUnknownOutcomeIs503(t *testing.T) {
	var rc interface {
		RefusalCode() string
		HTTPStatus() int
	}
	err := fmt.Errorf("%w: commit ambiguous", devices.ErrUnknown)
	if !errors.As(err, &rc) || rc.RefusalCode() != "outcome_unknown" || rc.HTTPStatus() != 503 || devices.IsRefusal(err) {
		t.Fatalf("ErrUnknown: %v", err)
	}
}
