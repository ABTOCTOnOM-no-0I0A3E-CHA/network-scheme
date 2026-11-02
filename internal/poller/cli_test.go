package poller

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/creds/credstest"
	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/drivers/eltexmes"
	"github.com/beekamai/network-scheme/internal/ssh"
	"github.com/beekamai/network-scheme/test/sim/sshemu"
)

/* countingListener counts the TCP connections the SSH emulator accepts. */
type countingListener struct {
	net.Listener
	n atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.n.Add(1)
	}
	return c, err
}

var cliPort atomic.Int64

/* cliEnv is a poller with one MES device on 127.0.0.1 whose SSH port is the emulator's, with a read credential. */
type cliEnv struct {
	*harness
	p     *Poller
	d     device
	cache *devCache
	drv   drivers.Driver
	ln    *countingListener
	log   *sshemu.Log
}

func newCLIEnv(t *testing.T) *cliEnv {
	t.Helper()
	h := newHarness(t, "")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e := &cliEnv{harness: h, ln: &countingListener{Listener: ln}, log: &sshemu.Log{}, cache: newDevCache(),
		drv: drivers.Default().ByName(eltexmes.Name)}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		_ = sshemu.Serve(e.ln, sshemu.Config{HostKey: sshemu.NewHostKey(t), Prompt: "sw1#", Username: "u", Password: "twelve-chars-x"}, e.log)
	}()
	id := h.device(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(20000+cliPort.Add(1))))
	owner := devices.Owner{Kind: devices.OwnerDevice, ID: id}
	h.profile(id, "ssh_read", credstest.Seal(h.pub, owner, "ssh_read", map[string]string{"username": "u", "password": "twelve-chars-x"}, time.Now().Add(-time.Minute)))
	e.p = h.poller(Intervals{Availability: time.Hour, Metrics: time.Hour, Inventory: time.Hour})
	e.p.sshPort = uint16(ln.Addr().(*net.TCPAddr).Port)
	devs, err := e.p.loadDevices(context.Background())
	if err != nil || len(devs) != 1 {
		t.Fatalf("devices %v, %v", devs, err)
	}
	e.d = devs[0]
	return e
}

/* busy marks the device as held by a change session, as the executor does (with the address it connects to). */
func (e *cliEnv) busy(on bool) {
	e.t.Helper()
	exe := e.env.Pool("nms_executor")
	if !on {
		if _, err := exe.Exec(context.Background(), `DELETE FROM execpub.device_busy WHERE device_id = $1`, e.d.ID); err != nil {
			e.t.Fatal(err)
		}
		return
	}
	if _, err := exe.Exec(context.Background(), `INSERT INTO execpub.device_busy (device_id, session_id, address) VALUES ($1, gen_random_uuid(), $2)`,
		e.d.ID, e.d.Addr.Addr()); err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() {
		_, _ = exe.Exec(context.Background(), `DELETE FROM execpub.device_busy WHERE device_id = $1`, e.d.ID)
	})
}

/* alias adds a device row of the api's with the given address text and SNMP port and a read credential, and returns it as the poller loads it. */
func (e *cliEnv) alias(address string, snmpPort int) (device, bool) {
	e.t.Helper()
	var id int64
	if err := e.env.Pool("nms_api").QueryRow(context.Background(), `INSERT INTO core.device (name, address, snmp_port, group_id, poller_id)
		VALUES ('alias-' || gen_random_uuid(), $1::inet, $2, $3, $4) RETURNING id`, address, snmpPort, e.group, e.pollerID).Scan(&id); err != nil {
		e.t.Logf("the api cannot add %s: %v", address, err)
		return device{}, false
	}
	owner := devices.Owner{Kind: devices.OwnerDevice, ID: id}
	e.profile(id, "ssh_read", credstest.Seal(e.pub, owner, "ssh_read", map[string]string{"username": "u", "password": "twelve-chars-x"}, time.Now().Add(-time.Minute)))
	devs, err := e.p.loadDevices(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	for _, d := range devs {
		if d.ID == id {
			return d, true
		}
	}
	e.t.Fatalf("alias %d not loaded", id)
	return device{}, false
}

/* allSites runs the three ways the poller opens a device's CLI and checks each refused with the change-session reason. */
func (e *cliEnv) allSites(what string) {
	e.t.Helper()
	ctx := context.Background()
	var bf *backupFail
	if _, err := e.p.sshFetch(ctx, e.d, e.cache, e.drv); !errors.As(err, &bf) || bf.text != errChangeSession || !errors.Is(err, errInSession) {
		e.t.Errorf("%s: backup fetch: %v", what, err)
	}
	var sf *showFailed
	if _, err := e.p.sshShow(ctx, e.d, e.cache, e.drv, ssh.ShowCommand{}); !errors.As(err, &sf) || sf.text != errShowInSession {
		e.t.Errorf("%s: show: %v", what, err)
	}
	if r := e.p.sshRunner(ctx, e.d, e.cache, e.drv); r != nil {
		_ = r.Close()
		e.t.Errorf("%s: inventory opened an SSH session", what)
	}
	time.Sleep(200 * time.Millisecond) /* a connection, had one been made, is accepted by now */
	if n := e.ln.n.Load(); n != 0 {
		e.t.Errorf("%s: %d SSH connections to the device", what, n)
	}
	if a := e.log.AuthAttempts(); len(a) != 0 {
		e.t.Errorf("%s: authentication attempts %v", what, a)
	}
}

/*
A device the executor holds in a change session gets no SSH connection from
the poller at any of its three CLI paths (backup, show, inventory); once it
is free, the same paths reach the emulator (the counter would see a dial).
*/
func TestBusyDeviceGetsNoSSH(t *testing.T) {
	e := newCLIEnv(t)
	e.busy(true)
	e.allSites("busy device")
	e.busy(false)
	_, _ = e.p.sshFetch(context.Background(), e.d, e.cache, e.drv)
	eventually(t, 5*time.Second, "an SSH connection to the free device", func() bool { return e.ln.n.Load() >= 1 })
}

/*
Fail closed: when execpub.device_busy cannot be read (here a lock held past
the check's deadline; the same for a database error or a lost grant), the
poller opens no SSH session either.
*/
func TestUnreadableBusyTableGetsNoSSH(t *testing.T) {
	e := newCLIEnv(t)
	old := busyCheckTimeout
	busyCheckTimeout = 300 * time.Millisecond
	t.Cleanup(func() { busyCheckTimeout = old })
	ctx := context.Background()
	tx, err := e.env.Pool("postgres").Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `LOCK TABLE execpub.device_busy IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	e.allSites("unreadable busy table")
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	/* SNMP is not gated: the availability path never asks. */
	if err := e.p.checkNotInSession(ctx, e.d.ID, e.d.Addr.Addr()); err != nil {
		t.Fatalf("check with the table readable again: %v", err)
	}
}

/*
I1: the api adds rows of its own for the address of a device in a change
session (another snmp_port, the IPv4-mapped form, leading zeros): none of
them gets an SSH connection, because the address about to be dialed is
checked too, in the form that is dialed.
*/
func TestAliasOfABusyDeviceGetsNoSSH(t *testing.T) {
	e := newCLIEnv(t)
	e.busy(true)
	busy := e.d
	for i, address := range []string{"127.0.0.1", "::ffff:127.0.0.1", "127.000.000.001", "0127.0.0.1"} {
		d, ok := e.alias(address, 30000+int(cliPort.Add(1)))
		if !ok {
			continue
		}
		if d.ID == busy.ID {
			t.Fatal("alias is the busy device")
		}
		e.d, e.cache = d, newDevCache()
		e.allSites(fmt.Sprintf("alias %d %s (loaded as %s)", i, address, d.Addr.Addr()))
	}
	/*
		dialSSH normalizes for itself, not only the loader (which unmaps today): a
		device handed to it with the IPv4-mapped form of the busy address gets
		no connection either.
	*/
	if d, ok := e.alias("127.0.0.1", 30000+int(cliPort.Add(1))); ok {
		d.Addr = netip.AddrPortFrom(netip.AddrFrom16(d.Addr.Addr().As16()), d.Addr.Port())
		if !d.Addr.Addr().Is4In6() {
			t.Fatal("test address not mapped")
		}
		e.d, e.cache = d, newDevCache()
		e.allSites("mapped address handed to dialSSH")
	}
	/* The busy device's own address freed: the alias reaches the emulator (the test would see a dial). */
	e.d = busy
	e.busy(false)
	d, _ := e.alias("127.0.0.1", 30000+int(cliPort.Add(1)))
	e.d, e.cache = d, newDevCache()
	_, _ = e.p.sshFetch(context.Background(), e.d, e.cache, e.drv)
	eventually(t, 5*time.Second, "an SSH connection once nothing is busy", func() bool { return e.ln.n.Load() >= 1 })
}

/*
cliDials lists, in one source file of the poller, every way to a device's
CLI other than the one ssh.Dial reference inside dialSSH (cli.go): a call or
a value (f := ssh.Dial) of internal/ssh's Dial, the x/crypto/ssh package
itself, and net's dialers.
*/
func cliDials(fset *token.FileSet, f *ast.File, name string) (inDialSSH int, bad []string) {
	alias := map[string]string{}
	for _, im := range f.Imports {
		path := strings.Trim(im.Path.Value, `"`)
		local := path[strings.LastIndex(path, "/")+1:]
		if im.Name != nil {
			local = im.Name.Name
		}
		switch path {
		case "github.com/beekamai/network-scheme/internal/ssh", "net":
			alias[local] = path
		case "golang.org/x/crypto/ssh":
			bad = append(bad, fmt.Sprintf("%s imports golang.org/x/crypto/ssh", name))
		}
	}
	for _, decl := range f.Decls {
		fn, _ := decl.(*ast.FuncDecl)
		ast.Inspect(decl, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			x, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			at := fset.Position(sel.Pos()).String()
			switch alias[x.Name] {
			case "github.com/beekamai/network-scheme/internal/ssh":
				if sel.Sel.Name != "Dial" {
					return true
				}
				if name == "cli.go" && fn != nil && fn.Name.Name == "dialSSH" {
					inDialSSH++
				} else {
					bad = append(bad, "ssh.Dial at "+at)
				}
			case "net":
				if strings.HasPrefix(sel.Sel.Name, "Dial") {
					bad = append(bad, "net."+sel.Sel.Name+" at "+at)
				}
			}
			return true
		})
	}
	return inDialSSH, bad
}

/* ssh.Dial is referenced once in the poller, inside dialSSH, and nothing else reaches a device's CLI, so no path skips the check. */
func TestOnlyDialSSHDialsSSH(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	n := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		in, bad := cliDials(fset, f, name)
		n += in
		for _, b := range bad {
			t.Errorf("%s: a way to a device's CLI outside dialSSH", b)
		}
	}
	if n != 1 {
		t.Fatalf("ssh.Dial referenced %d times in dialSSH, want once", n)
	}
}

/* The checker catches each bypass it is meant to catch, and lets dialSSH and SNMP through. */
func TestCLIDialsCatchesBypasses(t *testing.T) {
	head := "package poller\nimport (\n\t\"net\"\n\t\"net/netip\"\n\tx \"github.com/beekamai/network-scheme/internal/ssh\"\n\t\"github.com/beekamai/network-scheme/internal/ssh\"\n)\n"
	for _, src := range []string{
		"func f() { ssh.Dial(nil, netip.AddrPort{}, 0, c, nil, d) }",
		"func f() { g := ssh.Dial; g(nil, netip.AddrPort{}, 0, c, nil, d) }",
		"var g = ssh.Dial",
		"func f() { x.Dial(nil, netip.AddrPort{}, 0, c, nil, d) }",
		"func f() { net.Dial(\"tcp\", \"10.0.0.1:22\") }",
		"func f() { d := net.Dialer{}; _ = d }",
		"func f() { net.DialTimeout(\"tcp\", \"10.0.0.1:22\", 0) }",
		"func dialSSH() { ssh.Dial(nil, netip.AddrPort{}, 0, c, nil, d) } /* not in cli.go */",
	} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "worker.go", head+src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		if _, bad := cliDials(fset, f, "worker.go"); len(bad) == 0 {
			t.Errorf("not caught: %s", src)
		}
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "cli.go", "package poller\nimport \"github.com/beekamai/network-scheme/internal/ssh\"\nfunc dialSSH() { ssh.Dial(nil, a, 0, c, nil, d) }\nfunc g() { _ = ssh.Dialect{} }\n", parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	if in, bad := cliDials(fset, f, "cli.go"); in != 1 || len(bad) != 0 {
		t.Errorf("dialSSH itself: %d, %v", in, bad)
	}
	if _, bad := cliDials(fset, mustParse(t, fset, "package poller\nimport gossh \"golang.org/x/crypto/ssh\"\nvar _ = gossh.NewClientConn\n"), "show.go"); len(bad) == 0 {
		t.Error("x/crypto/ssh not caught")
	}
}

func mustParse(t *testing.T, fset *token.FileSet, src string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(fset, "x.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

/*
Drift after a change session: the configuration a session left (its
post_sha256, closed since the previous backup) is not drift; any other
change is, and so is putting an older session's result back outside a
session later.
*/
func TestNoDriftForTheConfigurationASessionLeft(t *testing.T) {
	e := newBackupEnv(t, "198.51.100.250:161")
	raw := readFixture(t, mesFixture+".txt")
	sum := func(s string) []byte {
		h := sha256.Sum256([]byte(e.drv.NormalizeConfig(s)))
		return h[:]
	}
	session := func(post []byte) {
		t.Helper()
		if _, err := e.env.Pool("nms_executor").Exec(context.Background(), `INSERT INTO execpub.session_summary
			(session_id, user_id, device_id, opened_at, closed_at, status, post_sha256)
			VALUES (gen_random_uuid(), 1, $1, now() - interval '1 minute', now(), 'closed', $2)`, e.dev, post); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = e.env.Pool("postgres").Exec(context.Background(), `DELETE FROM execpub.session_summary WHERE device_id = $1`, e.dev)
	})
	step := func(text string, wantDrift bool, what string) {
		t.Helper()
		time.Sleep(10 * time.Millisecond) /* the database clock moves between the session and the backup */
		e.cfg.Store(&fetched{text: text})
		if err := e.run(sourceSchedule); err != nil {
			t.Fatal(err)
		}
		vs := e.versions(e.dev)
		if last := vs[len(vs)-1]; last.drift != wantDrift {
			t.Fatalf("%s: drift %v, want %v", what, last.drift, wantDrift)
		}
	}
	step(raw, false, "baseline")
	withVLAN := func(v int) string { return raw + fmt.Sprintf("vlan %d\n", v) }
	session(sum(withVLAN(40)))
	step(withVLAN(40), false, "the session's configuration")
	step(withVLAN(41), true, "a change outside a session")
	step(withVLAN(40), true, "an older session's configuration put back outside a session")
	session(sum(withVLAN(42)))
	step(withVLAN(43), true, "a configuration other than the session left")
	/* An open session (no post hash yet, no end) excuses nothing. */
	if _, err := e.env.Pool("nms_executor").Exec(context.Background(), `INSERT INTO execpub.session_summary
		(session_id, user_id, device_id, opened_at, status, post_sha256) VALUES (gen_random_uuid(), 1, $1, now(), 'open', $2)`,
		e.dev, sum(withVLAN(44))); err != nil {
		t.Fatal(err)
	}
	step(withVLAN(44), true, "the hash of a session still open")
	if n := e.count(`SELECT count(*) FROM backups.config_version WHERE device_id = $1`, e.dev); n != 6 {
		t.Fatalf("%d versions", n)
	}
}
