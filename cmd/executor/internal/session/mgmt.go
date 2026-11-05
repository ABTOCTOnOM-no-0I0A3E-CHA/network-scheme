package session

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
)

/* errMgmt: the management context cannot be determined; the session does not open (fail closed). */
var errMgmt = errors.New("session: the management interface of the device cannot be determined")

var (
	ifaceRe   = regexp.MustCompile(`^interface\s+(.+?)\s*$`)
	addrRe    = regexp.MustCompile(`^\s+ip address\s+(\S+)(?:\s+(\S+))?`)
	gatewayRe = regexp.MustCompile(`^\s*(?:ip default-gateway\s+(\S+)|ip route\s+(?:0\.0\.0\.0\s+0\.0\.0\.0|0\.0\.0\.0/0)\s+(\S+))\s*$`)
	vlanIfRe  = regexp.MustCompile(`^vlan\s*0*([0-9]{1,4})$`)
	macRe     = regexp.MustCompile(`^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$|^(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}$`)
)

/*
mgmtTargets is the management context of a session (security.md 5.3, [R §6
"Общее правило"]): the interface carrying the registry address (an SVI
"interface vlan N" names VLAN N) from the configuration just read, and the
physical uplink toward the executor: the next hop (the executor's own
address self when it is in that interface's subnet, else the default
gateway of the configuration), its ARP entry (any interface it names) and
the port the MAC address table learned its MAC on. Every input is device
text: only whole tokens are compared, and an interface is one only when
the driver resolves it. Anything not found refuses the session.
*/
func mgmtTargets(d drivers.WriteDriver, config string, device, self netip.Addr, arp, macs string) ([]core.Target, error) {
	ifname, prefix, gateway, err := mgmtInterface(config, device)
	if err != nil {
		return nil, err
	}
	var out []core.Target
	ts, ok := ifaceTargets(d, ifname)
	if !ok {
		return nil, fmt.Errorf("%w: interface %q", errMgmt, ifname)
	}
	out = append(out, ts...)
	hop := gateway
	if prefix.Contains(self) {
		hop = self
	}
	if !hop.IsValid() {
		return nil, fmt.Errorf("%w: no route toward the executor", errMgmt)
	}
	mac, ports := "", 0
	for _, l := range strings.Split(arp, "\n") {
		f := strings.Fields(l)
		if !hasAddr(f, hop) {
			continue
		}
		for _, t := range f {
			if macRe.MatchString(t) {
				mac = macKey(t)
			}
		}
		ts, n := lineTargets(d, f)
		out, ports = append(out, ts...), ports+n
	}
	if mac == "" {
		return nil, fmt.Errorf("%w: no ARP entry of %s", errMgmt, hop)
	}
	for _, l := range strings.Split(macs, "\n") {
		f := strings.Fields(l)
		for _, t := range f {
			if macRe.MatchString(t) && macKey(t) == mac {
				ts, n := lineTargets(d, f)
				out, ports = append(out, ts...), ports+n
				break
			}
		}
	}
	/* A routed management port is its own uplink; an SVI needs the physical port behind it. */
	if ports == 0 && vlanIfRe.MatchString(ifname) {
		return nil, fmt.Errorf("%w: no port of %s", errMgmt, mac)
	}
	return out, nil
}

/* mgmtInterface finds the interface whose "ip address" is device, its subnet, and the default gateway of the configuration. */
func mgmtInterface(config string, device netip.Addr) (string, netip.Prefix, netip.Addr, error) {
	var (
		cur, name string
		prefix    netip.Prefix
		gateway   netip.Addr
		found     int
	)
	for _, l := range strings.Split(strings.ReplaceAll(config, "\r", ""), "\n") {
		if m := gatewayRe.FindStringSubmatch(l); m != nil {
			if a, err := netip.ParseAddr(m[1] + m[2]); err == nil {
				gateway = a
			}
			continue
		}
		if m := ifaceRe.FindStringSubmatch(l); m != nil {
			cur = m[1]
			continue
		}
		if l != "" && l[0] != ' ' {
			cur = ""
			continue
		}
		if m := addrRe.FindStringSubmatch(l); m != nil && cur != "" {
			if p, ok := ifacePrefix(m[1], m[2]); ok && p.Addr() == device {
				name, prefix, found = cur, p.Masked(), found+1
			}
		}
	}
	if found != 1 {
		return "", netip.Prefix{}, netip.Addr{}, fmt.Errorf("%w: %d interfaces carry %s", errMgmt, found, device)
	}
	return name, prefix, gateway, nil
}

/* ifacePrefix reads "A/L" or "A M" (a dotted mask). */
func ifacePrefix(a, mask string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(a); err == nil {
		return p, true
	}
	addr, err := netip.ParseAddr(a)
	m, err2 := netip.ParseAddr(mask)
	if err != nil || err2 != nil || !addr.Is4() || !m.Is4() {
		return netip.Prefix{}, false
	}
	b := m.As4()
	bits, v := 0, uint32(b[0])<<24|uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3])
	for v&(1<<31) != 0 {
		bits, v = bits+1, v<<1
	}
	if v != 0 {
		return netip.Prefix{}, false /* not a contiguous mask */
	}
	return netip.PrefixFrom(addr, bits), true
}

/* ifaceTargets resolves an interface name of the configuration: "vlan N" is VLAN N. */
func ifaceTargets(d drivers.WriteDriver, name string) ([]core.Target, bool) {
	if m := vlanIfRe.FindStringSubmatch(name); m != nil {
		return d.Targets("vlan", m[1])
	}
	return d.Targets("interface", name)
}

/* lineTargets are the interfaces a line of device output names: single tokens, and "vlan N" pairs; ports counts the interfaces. */
func lineTargets(d drivers.WriteDriver, f []string) (out []core.Target, ports int) {
	for i, t := range f {
		if ts, ok := d.Targets("interface", t); ok {
			out, ports = append(out, ts...), ports+len(ts)
		}
		if strings.EqualFold(t, "vlan") && i+1 < len(f) {
			if _, err := strconv.Atoi(f[i+1]); err == nil {
				if ts, ok := d.Targets("vlan", f[i+1]); ok {
					out = append(out, ts...)
				}
			}
		}
	}
	return out, ports
}

func hasAddr(f []string, a netip.Addr) bool {
	for _, t := range f {
		if x, err := netip.ParseAddr(t); err == nil && x.Unmap() == a {
			return true
		}
	}
	return false
}

/* macKey is a MAC address token as twelve lower-case hex digits. */
func macKey(t string) string {
	return strings.ToLower(strings.NewReplacer(":", "", "-", "", ".", "").Replace(t))
}
