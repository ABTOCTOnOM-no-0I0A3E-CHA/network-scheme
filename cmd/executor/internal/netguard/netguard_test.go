package netguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var stack = Stack{
	Core:    netip.MustParsePrefix("172.30.0.0/24"),
	Devices: netip.MustParsePrefix("172.30.1.0/24"),
	Xnet:    netip.MustParsePrefix("172.30.2.0/24"),
	Edge:    netip.MustParsePrefix("172.30.3.0/24"),
}

/*
The management subnets cover every class below on purpose (the devices
subnet among them, as install allows): the deny rules win over them.
*/
var mgmt = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.30.1.0/24"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("224.0.0.0/8"), netip.MustParsePrefix("239.0.0.0/8"),
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("240.0.0.0/8"), netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("192.0.2.8/31"), netip.MustParsePrefix("172.31.0.0/16"),
}

func guard(t *testing.T, dial func(context.Context, string, string) (net.Conn, error)) *Guard {
	t.Helper()
	g, err := New(mgmt, stack, dial)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

/* SSRF: every class of address that is not a device in a management subnet is refused, and none is dialed. */
func TestSSRFAddressesRefused(t *testing.T) {
	dialed := 0
	g := guard(t, func(context.Context, string, string) (net.Conn, error) {
		dialed++
		return nil, errors.New("test: no network")
	})
	for addr, why := range map[string]string{
		"127.0.0.1": "loopback", "127.8.9.10": "loopback", "169.254.169.254": "link-local", "224.0.0.1": "link-local",
		"239.1.2.3": "multicast", "0.0.0.0": "unspecified", "0.1.2.3": "unspecified", "255.255.255.255": "broadcast", "240.1.2.3": "reserved",
		"172.30.0.5": "core subnet", "172.30.1.5": "devices subnet", "172.30.2.2": "xnet subnet", "172.30.3.2": "edge subnet",
		"10.0.0.0": "network or broadcast", "10.255.255.255": "network or broadcast", "192.168.1.1": "outside every management",
		"::1": "not IPv4", "fe80::1": "not IPv4", "2001:db8::1": "not IPv4", "::ffff:10.1.2.3": "canonical",
	} {
		a := netip.MustParseAddr(addr)
		err := g.Check(a)
		if !errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), why) {
			t.Errorf("%s: %v, want a refusal (%s)", addr, err, why)
		}
		if _, err := g.Dial(context.Background(), netip.AddrPortFrom(a, 22)); !errors.Is(err, ErrDenied) {
			t.Errorf("dial %s: %v", addr, err)
		}
	}
	if err := g.Check(netip.Addr{}); !errors.Is(err, ErrDenied) {
		t.Errorf("zero address: %v", err)
	}
	if dialed != 0 {
		t.Fatalf("%d refused addresses reached the dialer", dialed)
	}
	for _, ok := range []string{"10.1.2.3", "172.31.9.1", "192.0.2.8", "192.0.2.9"} {
		if err := g.Check(netip.MustParseAddr(ok)); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, p := range []uint16{0} {
		if _, err := g.Dial(context.Background(), netip.AddrPortFrom(netip.MustParseAddr("10.1.2.3"), p)); !errors.Is(err, ErrDenied) {
			t.Errorf("port %d: %v", p, err)
		}
	}
	if dialed != 0 {
		t.Fatal("port 0 reached the dialer")
	}
}

/* A management subnet wider than /8, or overlapping core, xnet or edge, is refused; the devices subnet may be one. */
func TestNewRefusesBadManagementSubnets(t *testing.T) {
	for _, p := range []string{"0.0.0.0/0", "10.0.0.0/7", "172.30.0.0/16", "172.30.0.128/25", "172.30.2.0/24", "172.30.3.7/32"} {
		if _, err := New([]netip.Prefix{netip.MustParsePrefix(p)}, stack, nil); err == nil {
			t.Errorf("management subnet %s accepted", p)
		}
	}
	if _, err := New([]netip.Prefix{netip.MustParsePrefix("172.30.1.0/24")}, stack, nil); err != nil {
		t.Errorf("devices subnet as a management subnet: %v", err)
	}
}

/*
The real dialer's Control hook (after any resolution, right before the
connect): another address or port than the checked one is refused, and the
checked one passes Check again.
*/
func TestControlRechecksTheConnectedAddress(t *testing.T) {
	g := guard(t, nil)
	ap := netip.MustParseAddrPort("10.1.2.3:22")
	ctl := g.control(ap)
	if err := ctl("tcp4", "10.1.2.3:22", nil); err != nil {
		t.Fatalf("the checked address: %v", err)
	}
	for _, other := range []string{"10.1.2.4:22", "10.1.2.3:23", "127.0.0.1:22", "[::1]:22", "not-an-address"} {
		if err := ctl("tcp4", other, nil); !errors.Is(err, ErrDenied) {
			t.Errorf("%s: %v", other, err)
		}
	}
	/* Even the checked address is refused if it would not pass Check (a guard built around a denied ap). */
	if err := g.control(netip.MustParseAddrPort("172.30.1.5:22"))("tcp4", "172.30.1.5:22", nil); !errors.Is(err, ErrDenied) {
		t.Errorf("denied address in Control: %v", err)
	}
}

/* The real dialer (no test seam) checks first too: a listener on loopback is never reached. */
func TestRealDialerChecksFirst(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	g, err := New(mgmt, stack, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Dial(context.Background(), netip.MustParseAddrPort(ln.Addr().String())); !errors.Is(err, ErrDenied) {
		t.Fatalf("loopback listener: %v", err)
	}
}

func TestLoadRequiresEveryNetwork(t *testing.T) {
	write := func(body string) string {
		p := filepath.Join(t.TempDir(), "egress.yaml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := "devices_subnet: 172.30.1.0/24\nmgmt_subnets:\n  - 10.0.0.0/8\n"
	g, err := Load(write(good), stack.Core, stack.Xnet, stack.Edge)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Check(netip.MustParseAddr("172.30.1.7")); !errors.Is(err, ErrDenied) {
		t.Fatalf("devices subnet from egress.yaml not denied: %v", err)
	}
	for name, c := range map[string]struct {
		body             string
		core, xnet, edge netip.Prefix
	}{
		"no devices subnet": {"mgmt_subnets: [10.0.0.0/8]\n", stack.Core, stack.Xnet, stack.Edge},
		"no mgmt subnets":   {"devices_subnet: 172.30.1.0/24\nmgmt_subnets: []\n", stack.Core, stack.Xnet, stack.Edge},
		"unknown field":     {good + "extra: 1\n", stack.Core, stack.Xnet, stack.Edge},
		"host bits":         {"devices_subnet: 172.30.1.1/24\nmgmt_subnets: [10.0.0.0/8]\n", stack.Core, stack.Xnet, stack.Edge},
		"ipv6 mgmt":         {"devices_subnet: 172.30.1.0/24\nmgmt_subnets: [fd00::/64]\n", stack.Core, stack.Xnet, stack.Edge},
		"no core":           {good, netip.Prefix{}, stack.Xnet, stack.Edge},
		"no xnet":           {good, stack.Core, netip.Prefix{}, stack.Edge},
		"no edge":           {good, stack.Core, stack.Xnet, netip.Prefix{}},
	} {
		if _, err := Load(write(c.body), c.core, c.xnet, c.edge); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml"), stack.Core, stack.Xnet, stack.Edge); err == nil {
		t.Error("missing file loaded")
	}
}
