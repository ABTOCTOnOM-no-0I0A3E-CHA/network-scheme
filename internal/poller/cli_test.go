package poller

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net"
	"net/netip"
	"os/exec"
	"path/filepath"
	"slices"
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
	gossh "golang.org/x/crypto/ssh"
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
	key   gossh.Signer /* the emulator's host key */
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
	e.key = sshemu.NewHostKey(t)
	go func() {
		_ = sshemu.Serve(e.ln, sshemu.Config{HostKey: e.key, Prompt: "sw1#", Username: "u", Password: "twelve-chars-x"}, e.log)
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
I1 (re-review): the api's device row for another address of a switch in a
change session (the emulator here answers on 127.0.0.1, the busy device is
registered at 10.254.0.1) passes the id and address checks, but the switch
presents the busy device's host key: the handshake is refused before any
credential (0 authentication attempts at all three CLI paths), no pin is
taken for the alias, and with the busy row gone the same path logs in.
*/
func TestOtherAddressOfABusyDeviceGetsNoLogin(t *testing.T) {
	e := newCLIEnv(t)
	ctx := context.Background()
	exe := e.env.Pool("nms_executor")
	fp := gossh.FingerprintSHA256(e.key.PublicKey())
	if _, err := exe.Exec(ctx, `INSERT INTO execpub.device_busy (device_id, session_id, address, hostkey_fp)
		VALUES (990001, gen_random_uuid(), '10.254.0.1', $1)`, fp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = exe.Exec(context.Background(), `DELETE FROM execpub.device_busy WHERE device_id = 990001`)
	})
	if err := e.p.checkNotInSession(ctx, e.d.ID, e.d.Addr.Addr()); err != nil {
		t.Fatalf("the first gate already refuses (the test needs another address): %v", err)
	}
	var bf *backupFail
	if _, err := e.p.sshFetch(ctx, e.d, e.cache, e.drv); !errors.As(err, &bf) || bf.text != errChangeSession {
		t.Errorf("backup fetch: %v", err)
	}
	var sf *showFailed
	if _, err := e.p.sshShow(ctx, e.d, e.cache, e.drv, ssh.ShowCommand{}); !errors.As(err, &sf) || sf.text != errShowInSession {
		t.Errorf("show: %v", err)
	}
	if r := e.p.sshRunner(ctx, e.d, e.cache, e.drv); r != nil {
		_ = r.Close()
		t.Error("inventory logged in")
	}
	if a := e.log.AuthAttempts(); len(a) != 0 {
		t.Fatalf("credentials sent to a device in a session: %v", a)
	}
	if n := e.count(`SELECT count(*) FROM ssh_hosts.host_key WHERE device_id = $1`, e.d.ID); n != 0 {
		t.Fatal("the busy device's key was pinned for the alias")
	}
	if _, err := exe.Exec(ctx, `DELETE FROM execpub.device_busy WHERE device_id = 990001`); err != nil {
		t.Fatal(err)
	}
	_, _ = e.p.sshFetch(ctx, e.d, e.cache, e.drv)
	if len(e.log.AuthAttempts()) == 0 {
		t.Fatal("no login with the busy row gone: the test cannot see a login")
	}
}

/*
cliDials lists, in one source file (path relative to the repository), every
way to a device's CLI other than the one ssh.Dial reference inside dialSSH
(internal/poller/cli.go): a call or a value (f := ssh.Dial) of internal/ssh's
Dial, a dot import of internal/ssh or net (their names would be unqualified),
the x/crypto/ssh package itself and net's dialers; in the poller (poller set)
also syscall, os/exec, golang.org/x/sys, unsafe, crypto/tls, os.StartProcess
and //go:linkname directives, raw ways to a socket, a program or another
package's unexported dialer. f must be parsed with comments.
*/
func cliDials(fset *token.FileSet, f *ast.File, path string, poller bool) (inDialSSH int, bad []string) {
	const internalSSH = "github.com/beekamai/network-scheme/internal/ssh"
	alias := map[string]string{}
	for _, im := range f.Imports {
		ip := strings.Trim(im.Path.Value, `"`)
		local := ip[strings.LastIndex(ip, "/")+1:]
		if im.Name != nil {
			local = im.Name.Name
		}
		switch {
		case ip == "golang.org/x/crypto/ssh" || strings.HasPrefix(ip, "golang.org/x/crypto/ssh/"):
			bad = append(bad, fmt.Sprintf("%s imports %s", path, ip))
		case (ip == internalSSH || ip == "net" || (poller && ip == "os")) && local == ".":
			bad = append(bad, fmt.Sprintf("%s dot-imports %s", path, ip))
		case ip == internalSSH || ip == "net" || (poller && ip == "os"):
			alias[local] = ip
		case poller && (ip == "syscall" || ip == "os/exec" || strings.HasPrefix(ip, "golang.org/x/sys/") || ip == "unsafe" || ip == "crypto/tls"):
			bad = append(bad, fmt.Sprintf("%s imports %s", path, ip))
		}
	}
	if poller {
		for _, g := range f.Comments {
			for _, c := range g.List {
				if strings.HasPrefix(c.Text, "//go:linkname") {
					bad = append(bad, "//go:linkname at "+fset.Position(c.Pos()).String())
				}
			}
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
			case internalSSH:
				if sel.Sel.Name != "Dial" {
					return true
				}
				if path == "internal/poller/cli.go" && fn != nil && fn.Name.Name == "dialSSH" {
					inDialSSH++
				} else {
					bad = append(bad, "ssh.Dial at "+at)
				}
			case "net":
				if strings.HasPrefix(sel.Sel.Name, "Dial") {
					bad = append(bad, "net."+sel.Sel.Name+" at "+at)
				}
			case "os":
				if sel.Sel.Name == "StartProcess" {
					bad = append(bad, "os.StartProcess at "+at)
				}
			}
			return true
		})
	}
	return inDialSSH, bad
}

/*
ssh.Dial is referenced once outside the executor, inside the poller's
dialSSH, and nothing else reaches a device's CLI: every package (but the
executor's and internal/ssh itself) that imports internal/ssh is checked,
the drivers that re-export its types included, so no path skips the check.
*/
func TestOnlyDialSSHDialsSSH(t *testing.T) {
	root := filepath.Join("..", "..")
	skip := map[string]bool{".git": true, ".claude": true, ".superpowers": true, "node_modules": true, "web": true}
	files := map[string][]string{} /* package directory -> its non-test files */
	importers := map[string]bool{"internal/poller": true}
	fset := token.NewFileSet()
	parsed := map[string]*ast.File{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if skip[d.Name()] || rel == "cmd/executor" || rel == "internal/ssh" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly|parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		dir := filepath.ToSlash(filepath.Dir(rel))
		files[dir] = append(files[dir], rel)
		for _, im := range f.Imports {
			if strings.Trim(im.Path.Value, `"`) == "github.com/beekamai/network-scheme/internal/ssh" {
				importers[dir] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(importers) < 3 {
		t.Fatalf("importers of internal/ssh: %v (truncated walk?)", importers)
	}
	n := 0
	for dir := range importers {
		for _, rel := range files[dir] {
			f, err := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(rel)), nil, parser.ParseComments|parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			parsed[rel] = f
			in, bad := cliDials(fset, f, rel, dir == "internal/poller")
			n += in
			for _, b := range bad {
				t.Errorf("%s: a way to a device's CLI outside dialSSH", b)
			}
		}
	}
	if parsed["internal/poller/cli.go"] == nil || n != 1 {
		t.Fatalf("ssh.Dial referenced %d times in dialSSH, want once", n)
	}
}

/* The checker catches each bypass it is meant to catch, and lets dialSSH and SNMP through. */
func TestCLIDialsCatchesBypasses(t *testing.T) {
	head := "package poller\nimport (\n\t\"net\"\n\t\"net/netip\"\n\tx \"github.com/beekamai/network-scheme/internal/ssh\"\n\t\"github.com/beekamai/network-scheme/internal/ssh\"\n)\n"
	for _, src := range []string{
		head + "func f() { ssh.Dial(nil, netip.AddrPort{}, 0, c, nil, d) }",
		head + "func f() { g := ssh.Dial; g(nil, netip.AddrPort{}, 0, c, nil, d) }",
		head + "var g = ssh.Dial",
		head + "func f() { x.Dial(nil, netip.AddrPort{}, 0, c, nil, d) }",
		head + "func f() { net.Dial(\"tcp\", \"10.0.0.1:22\") }",
		head + "func f() { d := net.Dialer{}; _ = d }",
		head + "func f() { net.DialTimeout(\"tcp\", \"10.0.0.1:22\", 0) }",
		head + "func dialSSH() { ssh.Dial(nil, netip.AddrPort{}, 0, c, nil, d) } /* not in cli.go */",
		"package poller\nimport . \"github.com/beekamai/network-scheme/internal/ssh\"\nfunc f() { Dial(nil, a, 0, c, nil, d) }\n",
		"package poller\nimport . \"net\"\nfunc f() { Dial(\"tcp\", \"10.0.0.1:22\") }\n",
		"package poller\nimport \"syscall\"\nfunc f() { syscall.Socket(2, 1, 0) }\n",
		"package poller\nimport \"os/exec\"\nfunc f() { exec.Command(\"ssh\", \"10.0.0.1\") }\n",
		"package poller\nimport \"golang.org/x/sys/unix\"\nfunc f() { unix.Socket(2, 1, 0) }\n",
		"package poller\nimport gossh \"golang.org/x/crypto/ssh\"\nvar _ = gossh.NewClientConn\n",
		"package poller\nimport \"unsafe\"\nvar _ = unsafe.Pointer(nil)\n",
		"package poller\n//go:linkname dial net.dialSerial\nfunc dial()\n",
		"package poller\nimport \"os\"\nfunc f() { os.StartProcess(\"/usr/bin/ssh\", nil, nil) }\n",
		"package poller\nimport o \"os\"\nvar g = o.StartProcess\n",
		"package poller\nimport . \"os\"\nfunc f() { StartProcess(\"/usr/bin/ssh\", nil, nil) }\n",
		"package poller\nimport \"crypto/tls\"\nfunc f() { tls.Dial(\"tcp\", \"10.0.0.1:22\", nil) }\n",
	} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "worker.go", src, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		if _, bad := cliDials(fset, f, "internal/poller/worker.go", true); len(bad) == 0 {
			t.Errorf("not caught: %s", src)
		}
	}
	/* A driver re-exporting internal/ssh is checked as well (a dial there is caught; syscall is the poller's rule only). */
	fset := token.NewFileSet()
	drv := mustParse(t, fset, "package eltexmes\nimport \"github.com/beekamai/network-scheme/internal/ssh\"\nvar Dial = ssh.Dial\n")
	if _, bad := cliDials(fset, drv, "internal/drivers/eltexmes/x.go", false); len(bad) == 0 {
		t.Error("a driver re-exporting ssh.Dial not caught")
	}
	f := mustParse(t, fset, "package poller\nimport (\n\t\"os\"\n\t\"github.com/beekamai/network-scheme/internal/ssh\"\n)\n"+
		"func dialSSH() { ssh.Dial(nil, a, 0, c, nil, d) }\nfunc g() { _ = ssh.Dialect{}; _, _ = os.ReadFile(\"x\") /* //go:linkname in prose */ }\n")
	if in, bad := cliDials(fset, f, "internal/poller/cli.go", true); in != 1 || len(bad) != 0 {
		t.Errorf("dialSSH itself: %d, %v", in, bad)
	}
}

/*
4a.7 minor (3): in the poller's whole dependency graph (go list -deps) only
internal/ssh and internal/creds import golang.org/x/crypto/ssh (outside its
own packages): no dependency, vendored or ours, reaches a device's SSH
server another way.
*/
func TestOnlyInternalSSHAndCredsLinkXCryptoSSH(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}{{range .Imports}} {{.}}{{end}}",
		"github.com/beekamai/network-scheme/cmd/poller").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	allowed := map[string]bool{"github.com/beekamai/network-scheme/internal/ssh": true, "github.com/beekamai/network-scheme/internal/creds": true}
	xssh := func(p string) bool {
		return p == "golang.org/x/crypto/ssh" || strings.HasPrefix(p, "golang.org/x/crypto/ssh/")
	}
	lines := strings.Split(strings.TrimSpace(strings.ReplaceAll(string(out), "\r", "")), "\n")
	var importers []string
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) == 0 || xssh(f[0]) {
			continue
		}
		if slices.ContainsFunc(f[1:], xssh) {
			importers = append(importers, f[0])
			if !allowed[f[0]] {
				t.Errorf("%s imports golang.org/x/crypto/ssh", f[0])
			}
		}
	}
	if len(lines) < 50 || !slices.Contains(importers, "github.com/beekamai/network-scheme/internal/ssh") {
		t.Fatalf("implausible dependency list (%d packages, importers %v)", len(lines), importers)
	}
}

func mustParse(t *testing.T, fset *token.FileSet, src string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(fset, "x.go", src, parser.ParseComments|parser.SkipObjectResolution)
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
