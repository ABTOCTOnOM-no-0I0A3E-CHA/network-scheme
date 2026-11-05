/*
Package netguard decides where the executor may open a connection to a
device (security.md 5.1a, SSRF): only to an IPv4 host address inside a
management subnet of egress.yaml, never to loopback, link-local, multicast,
unspecified, broadcast or "this network" addresses, a subnet's own network
or broadcast address, nor into one of the stack's networks (core, xnet,
devices, edge), whatever the management subnets say. The address is an IP
(no DNS anywhere), and it is checked again at every dial, also on the
address the socket really connects to, so neither a changed registry row
nor a name that resolves differently later can lead the executor
elsewhere.
*/
package netguard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

/* ErrDenied is every refused address; the message says which rule. */
var ErrDenied = errors.New("netguard: address not allowed")

/* Stack is the stack's own networks: no device address may fall into them. */
type Stack struct {
	Core, Xnet, Devices, Edge netip.Prefix
}

/* Guard holds the management subnets and the stack's networks. */
type Guard struct {
	mgmt  []netip.Prefix
	stack []named
	/* dial is the connection after the check; nil: a net.Dialer that checks the connected address again. */
	dial func(ctx context.Context, network, address string) (net.Conn, error)
}

type named struct {
	name string
	p    netip.Prefix
}

/* DialTimeout bounds a TCP connect. */
const DialTimeout = 10 * time.Second

func ipv4Net(name string, p netip.Prefix) error {
	if !p.IsValid() || !p.Addr().Is4() || p != p.Masked() {
		return fmt.Errorf("netguard: %s is required as an IPv4 network address with prefix", name)
	}
	return nil
}

/*
New builds a guard over the management subnets and the stack's networks,
all required. A management subnet must be /8 or narrower and must not
overlap core, xnet or edge (install refuses the same; the devices subnet may
be one, devices are lab or simulator hosts there, and Check still denies
every address in it). dial, if not nil, replaces the real connection after
the check (tests: an emulator on loopback behind a management address).
*/
func New(mgmt []netip.Prefix, s Stack, dial func(ctx context.Context, network, address string) (net.Conn, error)) (*Guard, error) {
	g := &Guard{dial: dial}
	for _, n := range []named{{"core subnet", s.Core}, {"xnet subnet", s.Xnet}, {"devices subnet", s.Devices}, {"edge subnet", s.Edge}} {
		if err := ipv4Net(n.name, n.p); err != nil {
			return nil, err
		}
		g.stack = append(g.stack, n)
	}
	if len(mgmt) == 0 {
		return nil, errors.New("netguard: at least one management subnet is required")
	}
	for _, p := range mgmt {
		if err := ipv4Net("management subnet "+p.String(), p); err != nil {
			return nil, err
		}
		if p.Bits() < 8 {
			return nil, fmt.Errorf("netguard: management subnet %s is wider than /8", p)
		}
		for _, n := range g.stack {
			if n.name != "devices subnet" && n.p.Overlaps(p) {
				return nil, fmt.Errorf("netguard: management subnet %s overlaps the %s %s", p, n.name, n.p)
			}
		}
	}
	g.mgmt = append([]netip.Prefix(nil), mgmt...)
	return g, nil
}

/* egress is the part of egress.yaml (written by nmsctl install) the executor reads. */
type egress struct {
	DevicesSubnet netip.Prefix   `yaml:"devices_subnet"`
	MgmtSubnets   []netip.Prefix `yaml:"mgmt_subnets"`
}

/*
Load reads egress.yaml strictly (unknown fields are an error) for the
management subnets and the devices subnet, and builds the guard with core,
xnet and edge from executor.yaml. Any of them missing: an error, and the
executor does not start.
*/
func Load(path string, core, xnet, edge netip.Prefix) (*Guard, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- path from the executor configuration
	if err != nil {
		return nil, fmt.Errorf("netguard: %w", err)
	}
	var e egress
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&e); err != nil {
		return nil, fmt.Errorf("netguard: parse %s: %w", path, err)
	}
	return New(e.MgmtSubnets, Stack{Core: core, Xnet: xnet, Devices: e.DevicesSubnet, Edge: edge}, nil)
}

/* last is the broadcast address of an IPv4 prefix. */
func last(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	for i := p.Bits(); i < 32; i++ {
		a[i/8] |= 0x80 >> (i % 8)
	}
	return netip.AddrFrom4(a)
}

var (
	thisNetwork = netip.MustParsePrefix("0.0.0.0/8")
	reserved    = netip.MustParsePrefix("240.0.0.0/4") /* class E, 255.255.255.255 included */
)

/* Check reports whether a may be connected to (nil) or why not (ErrDenied). */
func (g *Guard) Check(a netip.Addr) error {
	deny := func(why string) error { return fmt.Errorf("%w: %s: %s", ErrDenied, a, why) }
	switch {
	case !a.IsValid():
		return fmt.Errorf("%w: no address", ErrDenied)
	case a.Zone() != "" || a.Is4In6():
		return deny("not a canonical IPv4 address")
	case !a.Is4():
		return deny("not IPv4 (the management subnets are IPv4)")
	case a.IsUnspecified() || thisNetwork.Contains(a):
		return deny("unspecified")
	case a.IsLoopback():
		return deny("loopback")
	case a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast():
		return deny("link-local")
	case a.IsMulticast() || a.IsInterfaceLocalMulticast():
		return deny("multicast")
	case a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return deny("broadcast")
	case reserved.Contains(a):
		return deny("reserved (240.0.0.0/4)")
	}
	for _, n := range g.stack {
		if n.p.Contains(a) {
			return deny("inside the " + n.name + " " + n.p.String())
		}
	}
	for _, m := range g.mgmt {
		if !m.Contains(a) {
			continue
		}
		if m.Bits() < 31 && (a == m.Addr() || a == last(m)) {
			return deny("network or broadcast address of " + m.String())
		}
		return nil
	}
	return deny("outside every management subnet")
}

/* CheckPort accepts 1..65535. */
func CheckPort(port int64) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("%w: port %d", ErrDenied, port)
	}
	return nil
}

/*
Dial connects to ap over TCP after checking it; the real dialer checks the
address the socket connects to once more (Control), so nothing but the
checked IP is ever reached.
*/
func (g *Guard) Dial(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
	if err := g.Check(ap.Addr()); err != nil {
		return nil, err
	}
	if err := CheckPort(int64(ap.Port())); err != nil {
		return nil, err
	}
	if g.dial != nil {
		return g.dial(ctx, "tcp4", ap.String())
	}
	d := net.Dialer{Timeout: DialTimeout, Control: g.control(ap)}
	return d.DialContext(ctx, "tcp4", ap.String())
}

/* control is the dialer's last check: the socket connects to exactly the checked ap, which passes Check again. */
func (g *Guard) control(ap netip.AddrPort) func(network, address string, _ syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		got, err := netip.ParseAddrPort(address)
		if err != nil || got != ap {
			return fmt.Errorf("%w: connecting to %s, checked %s", ErrDenied, address, ap)
		}
		return g.Check(got.Addr())
	}
}
