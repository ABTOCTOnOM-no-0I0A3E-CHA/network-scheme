package poller

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
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

/* busy marks the device as held by a change session, as the executor does. */
func (e *cliEnv) busy(on bool) {
	e.t.Helper()
	exe := e.env.Pool("nms_executor")
	if !on {
		if _, err := exe.Exec(context.Background(), `DELETE FROM execpub.device_busy WHERE device_id = $1`, e.d.ID); err != nil {
			e.t.Fatal(err)
		}
		return
	}
	if _, err := exe.Exec(context.Background(), `INSERT INTO execpub.device_busy (device_id, session_id) VALUES ($1, gen_random_uuid())`, e.d.ID); err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() {
		_, _ = exe.Exec(context.Background(), `DELETE FROM execpub.device_busy WHERE device_id = $1`, e.d.ID)
	})
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
	if err := e.p.checkNotInSession(ctx, e.d.ID); err != nil {
		t.Fatalf("check with the table readable again: %v", err)
	}
}

/* ssh.Dial is called in one place of the poller only (dialSSH), so no CLI path can skip the check. */
func TestOnlyDialSSHDialsSSH(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f) // #nosec G304 -- the package's own sources
		if err != nil {
			t.Fatal(err)
		}
		c := strings.Count(string(b), "ssh.Dial(")
		if c > 0 && f != "cli.go" {
			t.Errorf("%s calls ssh.Dial directly", f)
		}
		n += c
	}
	if n != 1 {
		t.Fatalf("ssh.Dial called %d times, want once (dialSSH)", n)
	}
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
