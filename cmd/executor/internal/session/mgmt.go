package session

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
)

/* errMgmt: the management context cannot be determined; the session does not open (fail closed). */
var errMgmt = errors.New("session: the management interface of the device cannot be determined")

var (
	ifaceRe    = regexp.MustCompile(`^interface\s+(.+?)\s*$`)
	addrRe     = regexp.MustCompile(`^\s+ip address\s+(\S+)(?:\s+(\S+))?`)
	gatewayRe  = regexp.MustCompile(`^\s*(?:ip default-gateway\s+(\S+)|ip route\s+(?:0\.0\.0\.0\s+0\.0\.0\.0|0\.0\.0\.0/0)\s+(\S+))\s*$`)
	vlanIfRe   = regexp.MustCompile(`^vlan\s*0*([0-9]{1,4})$`)
	loopbackRe = regexp.MustCompile(`(?i)^loopback\s*[0-9]{1,4}$`)
	macRe      = regexp.MustCompile(`^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$|^(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}$`)
)

/*
MgmtTargets is mgmtTargets for a changeset's dry-run (Phase 5): the same
management context a session would have on the device.
*/
func MgmtTargets(d drivers.WriteDriver, config string, device, self netip.Addr, arp, macs string) ([]core.Target, error) {
	return mgmtTargets(d, config, device, self, arp, macs)
}

/*
mgmtTargets is the management context of a session (security.md 5.3, [R §6
"Общее правило"]), from the configuration just read and the device's tables:
  - the interface carrying the registry address (an SVI "interface vlan N"
    names VLAN N; a loopback the grammar has no type for is left to the
    grammar, which treats its commands as unknown, i.e. dangerous);
  - the physical uplink toward the executor: the next hop (the executor's
    own address self when it is in that interface's subnet, else the
    default gateway of the configuration), every interface its ARP entry
    names and the port the MAC address table learned its MAC on. An entry
    through an SVI, an SVI or a loopback management interface needs a
    physical port;
  - every port whose configuration carries a management VLAN (access,
    native, PVID, an allowed list including it, a trunk without an allowed
    list: the safe side);
  - every member (channel-group N) of a port-channel in the context.

Every input is device text: only whole tokens are compared, and an
interface is one only when the driver resolves it. Anything not found
refuses the session.
*/
func mgmtTargets(d drivers.WriteDriver, config string, device, self netip.Addr, arp, macs string) ([]core.Target, error) {
	ifname, prefix, gateway, err := mgmtInterface(config, device)
	if err != nil {
		return nil, err
	}
	var out []core.Target
	ts, ok := ifaceTargets(d, ifname)
	loopback := loopbackRe.MatchString(ifname)
	if !ok && !loopback {
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
	mac, ports, viaSVI := "", 0, vlanIfRe.MatchString(ifname) || loopback
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
		viaSVI = viaSVI || slices.ContainsFunc(ts, func(t core.Target) bool { return t.Kind == vlanKind(d) })
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
	if ports == 0 && viaSVI {
		return nil, fmt.Errorf("%w: no port of %s", errMgmt, mac)
	}
	blocks := ifaceBlocks(config)
	out = append(out, vlanPorts(d, blocks, out)...)
	return append(out, lagMembers(d, blocks, out)...), nil
}

/* block is one interface of the configuration: its name and body lines (trimmed). */
type block struct {
	name string
	body []string
}

/* ifaceBlocks splits the configuration into its interface blocks; an unindented line ends a block. */
func ifaceBlocks(config string) []block {
	var out []block
	in := false
	for _, l := range strings.Split(strings.ReplaceAll(config, "\r", ""), "\n") {
		switch m := ifaceRe.FindStringSubmatch(l); {
		case m != nil:
			out, in = append(out, block{name: m[1]}), true
		case in && l != "" && l[0] == ' ':
			out[len(out)-1].body = append(out[len(out)-1].body, strings.TrimSpace(l))
		case l != "":
			in = false
		}
	}
	return out
}

/* vlanKind is the target kind of a VLAN of the driver's grammar. */
func vlanKind(d drivers.WriteDriver) string {
	if ts, ok := d.Targets("vlan", "1"); ok && len(ts) > 0 {
		return ts[0].Kind
	}
	return "vlan"
}

/* vlanPorts are the interfaces whose configuration carries a VLAN of ctx. */
func vlanPorts(d drivers.WriteDriver, blocks []block, ctx []core.Target) []core.Target {
	kind := vlanKind(d)
	var vlans []int
	for _, t := range ctx {
		if n, err := strconv.Atoi(t.Name); t.Kind == kind && err == nil {
			vlans = append(vlans, n)
		}
	}
	if len(vlans) == 0 {
		return nil
	}
	var out []core.Target
	for _, b := range blocks {
		trunk, allowed, carries := false, false, false
		for _, l := range b.body {
			f := strings.Fields(strings.ToLower(l))
			if len(f) == 0 || f[0] != "switchport" {
				continue
			}
			if strings.Join(f, " ") == "switchport mode trunk" {
				trunk = true
			}
			for i, w := range f {
				if w == "allowed" {
					allowed = true
				}
				if (w == "vlan" || w == "pvid") && i+1 < len(f) {
					for _, list := range f[i+1:] {
						carries = carries || listHas(list, vlans)
					}
				}
			}
		}
		if carries || (trunk && !allowed) {
			if ts, ok := ifaceTargets(d, b.name); ok {
				out = append(out, ts...)
			}
		}
	}
	return out
}

/* listHas reads a VLAN list ("10,20-30") and reports whether it holds one of vlans. */
func listHas(list string, vlans []int) bool {
	for _, item := range strings.Split(list, ",") {
		lo, hi, rng := strings.Cut(item, "-")
		a, err := strconv.Atoi(lo)
		if err != nil {
			continue
		}
		b := a
		if rng {
			if b, err = strconv.Atoi(hi); err != nil {
				continue
			}
		}
		if slices.ContainsFunc(vlans, func(v int) bool { return v >= a && v <= b }) {
			return true
		}
	}
	return false
}

var channelRe = regexp.MustCompile(`^channel-group\s+0*([0-9]{1,4})\b`)

/* lagMembers are the interfaces with "channel-group N" whose port-channel N is in ctx. */
func lagMembers(d drivers.WriteDriver, blocks []block, ctx []core.Target) []core.Target {
	var out []core.Target
	for _, b := range blocks {
		for _, l := range b.body {
			m := channelRe.FindStringSubmatch(strings.ToLower(l))
			if m == nil {
				continue
			}
			po, ok := d.Targets("interface", "port-channel"+m[1])
			if !ok || !slices.ContainsFunc(po, func(t core.Target) bool { return slices.Contains(ctx, t) }) {
				continue
			}
			if ts, ok := ifaceTargets(d, b.name); ok {
				out = append(out, ts...)
			}
		}
	}
	return out
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

/* ifaceTargets resolves an interface name of the configuration: "vlan N" is VLAN N; "port-channel 1" is read glued too. */
func ifaceTargets(d drivers.WriteDriver, name string) ([]core.Target, bool) {
	if m := vlanIfRe.FindStringSubmatch(name); m != nil {
		return d.Targets("vlan", m[1])
	}
	if ts, ok := d.Targets("interface", name); ok {
		return ts, true
	}
	return d.Targets("interface", strings.Join(strings.Fields(name), ""))
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
