package changeset_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/nacl/box"
	gossh "golang.org/x/crypto/ssh"

	"github.com/beekamai/network-scheme/cmd/executor/internal/admin"
	"github.com/beekamai/network-scheme/cmd/executor/internal/approval"
	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/backups"
	"github.com/beekamai/network-scheme/cmd/executor/internal/changeset"
	_ "github.com/beekamai/network-scheme/cmd/executor/internal/drivers/esr" /* the write drivers register themselves */
	_ "github.com/beekamai/network-scheme/cmd/executor/internal/drivers/mes10"
	_ "github.com/beekamai/network-scheme/cmd/executor/internal/drivers/mes6"
	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/cmd/executor/internal/policy"
	"github.com/beekamai/network-scheme/cmd/executor/internal/pub"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/execadmin"
	"github.com/beekamai/network-scheme/internal/secret"
	"github.com/beekamai/network-scheme/internal/testdb"
	"github.com/beekamai/network-scheme/internal/ticket"
	"github.com/beekamai/network-scheme/test/sim/devemu"
	"github.com/beekamai/network-scheme/test/sim/sshemu"
)

const pw = "changeset-test-password-1"

var ticketKey = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

/*
lineOf is what an emulated line needs for the management context: the
registry address its fixture's interface carries, the default route
appended to its configuration, the next hop's ARP entry and MAC table row on
its uplink (as the session tests have them).
*/
var lineOf = map[string]struct {
	addr                netip.Addr
	gateway, arp, macs  string
	users, port, access string
}{
	"mes6": {netip.MustParseAddr("192.0.2.10"), "ip default-gateway 192.0.2.1\n",
		" vlan 99  gi1/0/1      192.0.2.1        a8:f9:4b:00:00:01   dynamic\n",
		"   99     a8:f9:4b:00:00:01     gi1/0/1    dynamic\n", "", "gigabitethernet1/0/2", "configure"},
	"mes10": {netip.MustParseAddr("192.0.2.20"), "ip default-gateway 192.0.2.1\n",
		" vlan 99  gi0/1      192.0.2.1        a8:f9:4b:00:00:01   dynamic\n",
		"   99     a8:f9:4b:00:00:01     gi0/1    dynamic\n", "", "gigabitethernet 0/2", "configure terminal"},
	"esr": {netip.MustParseAddr("192.0.2.1"), "ip route 0.0.0.0/0 192.0.2.254\n",
		"gi1/0/1     192.0.2.254    a8:f9:4b:00:00:01  reachable\n",
		"1     a8:f9:4b:00:00:01  gi1/0/1    dynamic\n",
		"SID  User  Timeout  Level  Protocol  Host\n*  1  admin  00:29:59  15  ssh  192.0.2.200", "gigabitethernet 1/0/2", "configure"},
}

/* dev is one registered, emulated device. */
type dev struct {
	id   int64
	line string
	d    *devemu.Device
	emu  netip.AddrPort
	log  *sshemu.Log
	row  map[string]any
}

/* fx is one executor (registry, guard, policy, authz, publisher, changesets) and its emulated devices. */
type fx struct {
	env     *testdb.Env
	guard   *freeze.Guard
	pol     *policy.Holder
	polF    string
	az      *authz.Authorizer
	adm     *admin.Admin
	pub     *pub.Publisher
	store   *changeset.Store
	locks   *backups.Locks
	bpub    *[32]byte /* the backup domain */
	bpriv   *[32]byte
	m       *changeset.Manager
	cfg     changeset.Config
	devs    []*dev
	byPort  sync.Map /* registry port -> emulator address */
	mu      sync.Mutex
	started []changeset.Started /* the runs Config.Start was given */
	offset  atomic.Int64
	start   time.Time
}

func (f *fx) now() time.Time { return f.start.Add(time.Duration(f.offset.Load())) }

type dialer struct{ f *fx }

func (d dialer) Dial(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
	e, ok := d.f.byPort.Load(ap.Port())
	if !ok {
		return nil, errors.New("test: no device at that port")
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", e.(netip.AddrPort).String())
}

/* newFx starts an executor with one emulated device per line given, in write group "core". */
func newFx(t *testing.T, lines ...string) *fx {
	t.Helper()
	env := testdb.New(t)
	attacktest.Reset(t, env)
	ctx := context.Background()
	keys, err := seal.Derive(&[32]byte{6})
	if err != nil {
		t.Fatal(err)
	}
	f := &fx{env: env, start: time.Now()}
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
	f.pub = pub.New(pool, log)
	for i, line := range lines {
		f.device(t, line, 2200+i, "core")
	}
	f.store = &changeset.Store{Pool: pool, MAC: keys.MAC(), Alert: f.pub.Alert, Log: log, Now: f.now}
	bpub, bpriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.bpub, f.bpriv = bpub, bpriv
	f.locks = &backups.Locks{}
	sched := backups.New(backups.Config{Registry: f.guard, Net: dialer{f}, Pool: pool, BackupPub: bpub, Locks: f.locks, Alert: f.pub.Alert, Log: log,
		Open: func(*registry.Snapshot, int64) (creds.Credential, error) {
			return creds.Credential{Username: "admin", Password: secret.New(pw)}, nil
		}})
	f.cfg = changeset.Config{Gate: f.guard, Auth: f.az, Policy: f.pol.Current, Store: f.store, Pub: f.pub, Log: log, Now: f.now,
		Locks: f.locks, Reader: sched, Approvals: approval.New(f.now), Start: func(_ context.Context, s changeset.Started) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.started = append(f.started, s)
			return nil
		}}
	f.m = changeset.New(f.cfg)
	return f
}

/* device registers an emulated device of line at registry port port in group. */
func (f *fx) device(t *testing.T, line string, port int, group string) *dev {
	t.Helper()
	lo := lineOf[line]
	dfx, err := devemu.LoadLine(line)
	if err != nil {
		t.Fatal(err)
	}
	dfx.Running = strings.TrimRight(dfx.Running, "\n") + "\n" + lo.gateway
	d := &dev{line: line, d: devemu.New(dfx, devemu.Options{})}
	d.d.SetShowLookup(func(cmd string) (string, bool) {
		switch cmd {
		case "show arp":
			return lo.arp, true
		case "show mac address-table":
			return lo.macs, true
		case "show users":
			return lo.users, lo.users != ""
		}
		return "", false
	})
	var key gossh.PublicKey
	d.emu, key, d.log = devemu.StartSSH(t, d.d, func(c *sshemu.Config) { c.Username, c.Password, c.HostKeyAlgorithms = "admin", pw, nil })
	f.byPort.Store(uint16(port), d.emu) // #nosec G115 -- test ports
	d.id = f.panelDevice(t)
	d.row = map[string]any{"device_id": d.id, "address": lo.addr, "port": port, "protocol": "ssh", "write_group": group,
		"write_driver": line, "hostkey_algo": key.Type(), "hostkey_fp": gossh.FingerprintSHA256(key),
		"allow_ssh_rsa_sha1": true, "writes_enabled": true, "backup_via_executor": false}
	f.put(t, "write_device", d.row)
	mp := map[string]any{"id": int64(len(f.devs) + 1), "write_driver": line, "model_re": "^(?:.*)$", "firmware_re": "^(?:.*)$",
		"strategies": json.RawMessage(`{}`), "note": "stand"}
	if !slices.ContainsFunc(f.devs, func(o *dev) bool { return o.line == line }) { /* one profile per line */
		f.put(t, "model_profile", mp)
	}
	f.put(t, "write_credential", map[string]any{"device_id": d.id, "kind": "ssh_write", "ciphertext": []byte{1},
		"created_at": time.Now(), "nonce": make([]byte, 16)})
	f.devs = append(f.devs, d)
	return d
}

/* policy writes the policy file (enabled, plus extra YAML) and reloads it. */
func (f *fx) policy(t *testing.T, extra string) {
	t.Helper()
	if err := os.WriteFile(f.polF, []byte("enabled: true\n"+extra), 0o600); err != nil {
		t.Fatal(err)
	}
	_, cur, _ := f.pol.Reload(true)
	if cur.Err != nil {
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

var names atomic.Int64

func (f *fx) panelDevice(t *testing.T) int64 {
	t.Helper()
	p := f.env.Pool("postgres")
	var gid, id int64
	if err := p.QueryRow(context.Background(), `INSERT INTO core.device_group (name) VALUES ('cs-' || gen_random_uuid()) RETURNING id`).Scan(&gid); err != nil {
		t.Fatal(err)
	}
	if err := p.QueryRow(context.Background(), `INSERT INTO core.device (name, address, group_id) VALUES ('cs-' || gen_random_uuid(), $1, $2) RETURNING id`,
		fmt.Sprintf("10.9.%d.%d", names.Add(1)%250, 1+time.Now().UnixNano()%250), gid).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *fx) host(req execadmin.Request) execadmin.Response {
	req.V, req.Operator = execadmin.Version, "tester"
	return f.adm.Handle(context.Background(), req)
}

type who struct {
	id         int64
	name, totp string
}

/* user is a panel user with a change TOTP and write grants on groups (nmsctl). */
func (f *fx) user(t *testing.T, groups ...string) who {
	t.Helper()
	name := fmt.Sprintf("cs-%d-%d", names.Add(1), time.Now().UnixNano()%1e6)
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
		req.User = name
		f.adminDo(t, req, func(resp execadmin.Response) {
			if resp.Enrollment != nil {
				u.totp = resp.Enrollment.Secret
			}
		})
	}
	return u
}

/* adminDo runs a host command, confirming the user it names. */
func (f *fx) adminDo(t *testing.T, req execadmin.Request, then func(execadmin.Response)) {
	t.Helper()
	resp := f.host(req)
	if resp.OK && resp.Confirm != nil {
		req.UserID, req.UserCreated = resp.Confirm.ID, resp.Confirm.CreatedAt
		resp = f.host(req)
	}
	if !resp.OK {
		t.Fatalf("%s: %s", req.Cmd, resp.Error)
	}
	if then != nil {
		then(resp)
	}
}

/* req is a request of u: a fresh ticket and the next change TOTP code. */
func (f *fx) req(t *testing.T, u who) authz.Request {
	t.Helper()
	tok, _, err := ticket.Issue(ticketKey, u.id, u.name, f.now())
	if err != nil {
		t.Fatal(err)
	}
	f.offset.Add(int64(30 * time.Second))
	c, err := totp.GenerateCodeCustom(u.totp, f.now(), totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return authz.Request{Ticket: tok, Code: c, IP: "192.0.2.200"}
}

/* open gives u a workspace token. */
func (f *fx) open(t *testing.T, u who) string {
	t.Helper()
	o, err := f.m.Open(context.Background(), f.req(t, u))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return o.Token
}

/* op runs a workspace route with params (any JSON value). */
func (f *fx) op(t *testing.T, token, op string, params any) (any, error) {
	t.Helper()
	b, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	return f.m.Op(ctx, token, op, b)
}

/* save stores content (a new changeset when id is empty) and fails the test on a refusal. */
func (f *fx) save(t *testing.T, token, id string, rev int, c changeset.Content) changeset.Saved {
	t.Helper()
	res, err := f.op(t, token, "save", map[string]any{"changeset_id": id, "revision": rev, "content": c})
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	return res.(changeset.Saved)
}

func (f *fx) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := f.env.Pool("postgres").QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

/* audits counts the executor's audit rows of action (and result). */
func (f *fx) audits(t *testing.T, action, result string) int {
	return f.count(t, `SELECT count(*) FROM exec.audit_event WHERE action = $1 AND result = $2`, action, result)
}

/* code is the refusal code of err ("" when it is not a changeset refusal). */
func code(err error) string {
	var r *changeset.Refusal
	if errors.As(err, &r) {
		return r.Code
	}
	return ""
}

/* lines is a lines content over devs: an interface description on the line's spare port. */
func (f *fx) lines(title string, devs ...*dev) changeset.Content {
	c := changeset.Content{Title: title, BatchSize: 1, Vars: map[int64]map[string]string{}}
	for _, d := range devs {
		c.Devices = append(c.Devices, d.id)
		c.Vars[d.id] = map[string]string{"cfg": lineOf[d.line].access, "port": lineOf[d.line].port}
	}
	c.Steps = []changeset.Step{{Line: "{{cfg}}"}, {Line: "interface {{port}}"}, {Line: "description nms-test"}, {Line: "end"}}
	return c
}
