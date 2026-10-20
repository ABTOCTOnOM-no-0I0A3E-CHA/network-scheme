package snmp_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/secret"
	"github.com/beekamai/network-scheme/internal/snmp"
	"github.com/beekamai/network-scheme/test/sim/snmpsim/simtest"
)

const (
	sysObjectID = "1.3.6.1.2.1.1.2.0"
	sysName     = "1.3.6.1.2.1.1.5.0"
	ifTable     = "1.3.6.1.2.1.2.2"
	ifDescr     = "1.3.6.1.2.1.2.2.1.2"
	ifHCIn      = "1.3.6.1.2.1.31.1.1.1.6"
)

var fixture = simtest.Fixture("generic-switch.snmprec")

func dial(t *testing.T, addr netip.AddrPort, c creds.Credential, o snmp.Options) snmp.Reader {
	t.Helper()
	r, closer, err := snmp.Dial(context.Background(), addr, c, o)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = closer.Close() })
	return r
}

func TestGetSysObjectIDv2c(t *testing.T) {
	addr := simtest.Start(t, fixture)
	r := dial(t, addr, simtest.V2Cred("generic-switch"), snmp.Options{})
	vars, err := r.Get(context.Background(), sysObjectID, "."+sysName)
	if err != nil {
		t.Fatal(err)
	}
	if len(vars) != 2 {
		t.Fatalf("vars: %+v", vars)
	}
	if oid, ok := snmp.AsOID(vars[0]); !ok || oid != "1.3.6.1.4.1.32473.1.100" || vars[0].OID != sysObjectID {
		t.Fatalf("sysObjectID: %+v", vars[0])
	}
	if s, ok := snmp.AsString(vars[1]); !ok || s != "sim-sw1" {
		t.Fatalf("sysName: %+v", vars[1])
	}
}

func TestWalkIfTableV3(t *testing.T) {
	addr := simtest.Start(t, fixture)
	r := dial(t, addr, simtest.V3Cred(), snmp.Options{ContextName: "generic-switch"})
	n := 0
	descr := map[string]string{}
	err := r.Walk(context.Background(), ifTable, func(v snmp.Var) error {
		n++
		if strings.HasPrefix(v.OID, ifDescr+".") {
			s, _ := snmp.AsString(v)
			descr[v.OID] = s
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 45 { /* 15 columns x 3 ports */
		t.Fatalf("walked %d variables, want 45", n)
	}
	if len(descr) != 3 || descr[ifDescr+".2"] != "gi1/0/2" {
		t.Fatalf("ifDescr: %v", descr)
	}

	/* 64-bit counters; BulkGet returns the successor of each OID (GETNEXT semantics). */
	vars, err := r.BulkGet(context.Background(), []string{ifHCIn + ".1", ifHCIn + ".0"})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := snmp.AsUint64(vars[0]); !ok || got != 987654321012 {
		t.Fatalf("HC in: %+v", vars[0])
	}
	if got, ok := snmp.AsUint64(vars[1]); !ok || got != 18446744073709551000 {
		t.Fatalf("HC in (large): %+v", vars[1])
	}
}

func TestGetMissingObject(t *testing.T) {
	addr := simtest.Start(t, fixture)
	r := dial(t, addr, simtest.V2Cred("generic-switch"), snmp.Options{MaxOIDsPerRequest: 2})
	_, err := r.Get(context.Background(), "1.3.6.1.2.1.1.99.0")
	if !errors.Is(err, snmp.ErrNoSuchObject) {
		t.Fatalf("all missing: %v", err)
	}
	/* Three OIDs with a limit of two: split into two requests, partial miss is not an error. */
	vars, err := r.Get(context.Background(), sysName, "1.3.6.1.2.1.1.99.0", sysObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if len(vars) != 3 || (vars[1].Type != snmp.TypeNoSuchObject && vars[1].Type != snmp.TypeNoSuchInstance) {
		t.Fatalf("vars: %+v", vars)
	}
}

/* silentUDP returns the address of a UDP socket that never answers. */
func silentUDP(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

func TestTimeoutIsBounded(t *testing.T) {
	addr := silentUDP(t)
	o := snmp.Options{Timeout: 300 * time.Millisecond, Retries: 1}
	limit := o.Timeout*time.Duration(o.Retries+1) + 500*time.Millisecond
	for name, c := range map[string]creds.Credential{
		"v2c": simtest.V2Cred("public"),
		"v3":  simtest.V3Cred(),
	} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			r, closer, err := snmp.Dial(context.Background(), addr, c, o)
			if err == nil {
				defer func() { _ = closer.Close() }()
				_, err = r.Get(context.Background(), sysName)
			}
			if !errors.Is(err, snmp.ErrTimeout) {
				t.Fatalf("got %v, want ErrTimeout", err)
			}
			if d := time.Since(start); d > limit {
				t.Fatalf("took %v, limit %v", d, limit)
			}
		})
	}
}

func TestWrongCommunity(t *testing.T) {
	addr := simtest.Start(t, fixture)
	r := dial(t, addr, simtest.V2Cred("no-such-community"), snmp.Options{Timeout: 400 * time.Millisecond, Retries: 1})
	_, err := r.Get(context.Background(), sysName)
	if !errors.Is(err, snmp.ErrTimeout) && !errors.Is(err, snmp.ErrAuth) {
		t.Fatalf("got %v, want ErrTimeout or ErrAuth", err)
	}
}

func TestWrongV3KeyRejected(t *testing.T) {
	addr := simtest.Start(t, fixture)
	c := simtest.V3Cred()
	c.AuthKey = secret.New("a-different-auth-key-1234")
	o := snmp.Options{Timeout: 400 * time.Millisecond, Retries: 1, ContextName: "generic-switch"}
	r, closer, err := snmp.Dial(context.Background(), addr, c, o)
	if err == nil {
		defer func() { _ = closer.Close() }()
		_, err = r.Get(context.Background(), sysName)
	}
	if !errors.Is(err, snmp.ErrTimeout) && !errors.Is(err, snmp.ErrAuth) {
		t.Fatalf("got %v, want ErrTimeout or ErrAuth", err)
	}
}

func TestWalkStopsOnContextCancel(t *testing.T) {
	addr := simtest.Start(t, fixture)
	r := dial(t, addr, simtest.V2Cred("generic-switch"), snmp.Options{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n := 0
	err := r.Walk(ctx, ifTable, func(snmp.Var) error {
		n++
		if n == 3 {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
	if n != 3 {
		t.Fatalf("callback ran %d times after cancel, want 3", n)
	}
	/* an already-cancelled context never touches the network */
	if _, err := r.Get(ctx, sysName); !errors.Is(err, context.Canceled) {
		t.Fatalf("Get with cancelled ctx: %v", err)
	}
	/* the session stays usable with a fresh context */
	if _, err := r.Get(context.Background(), sysName); err != nil {
		t.Fatalf("session unusable after cancel: %v", err)
	}
}

func TestDialRejectsUnsupportedCredentials(t *testing.T) {
	addr := silentUDP(t)
	v3 := func(mut func(*creds.Credential)) creds.Credential {
		c := simtest.V3Cred()
		mut(&c)
		return c
	}
	cases := map[string]creds.Credential{
		"ssh kind":    {Kind: "ssh_read", Username: "u"},
		"empty comm":  {Kind: "snmp2c"},
		"sha1 auth":   v3(func(c *creds.Credential) { c.AuthProto = "SHA" }),
		"md5 auth":    v3(func(c *creds.Credential) { c.AuthProto = "MD5" }),
		"des priv":    v3(func(c *creds.Credential) { c.PrivProto = "DES" }),
		"no priv":     v3(func(c *creds.Credential) { c.PrivProto = "" }),
		"short key":   v3(func(c *creds.Credential) { c.PrivKey = secret.New("short") }),
		"empty user":  v3(func(c *creds.Credential) { c.User = "" }),
		"no auth key": v3(func(c *creds.Credential) { c.AuthKey = secret.Secret{} }),
	}
	for name, c := range cases {
		if _, _, err := snmp.Dial(context.Background(), addr, c, snmp.Options{}); err == nil {
			t.Errorf("%s: Dial accepted the credential", name)
		}
	}
}

func TestNoSetInCode(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	script, err := filepath.Abs("../../scripts/check-no-snmp-set.sh")
	if err != nil {
		t.Fatal(err)
	}
	fx := filepath.Join("..", "..", "test", "fixtures", "noset")
	run := func(names ...string) error {
		dir := t.TempDir()
		for _, n := range names {
			b, err := os.ReadFile(filepath.Join(fx, n+".go.txt"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, n+".go"), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return exec.Command(bash, script, dir).Run() // #nosec G204 -- fixed script path
	}

	var ee *exec.ExitError
	if err := run("bad"); !errors.As(err, &ee) || ee.ExitCode() != 1 {
		t.Fatalf("bad fixture: got %v, want exit 1", err)
	}
	if err := run("good", "unrelated"); err != nil {
		t.Fatalf("clean fixtures: %v", err)
	}
	/* the repository itself must be clean */
	if err := exec.Command(bash, script).Run(); err != nil { // #nosec G204 -- fixed script path
		t.Fatalf("repository: %v", err)
	}
}
