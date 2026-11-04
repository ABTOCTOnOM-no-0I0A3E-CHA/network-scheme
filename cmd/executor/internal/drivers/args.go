package drivers

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
)

/*
IfType is an interface type of a firmware line: its full name as the
running configuration prints it and the number of port components ("1/0/1"
has 3, "0/1" has 2, a port-channel 1, "oob" none). Sub allows ESR
sub-interfaces ("1/0/1.100").
*/
type IfType struct {
	Name  string
	Comps int
	Sub   bool
}

/* maxPortNum bounds one port component; maxItems the items of one list argument. */
const (
	maxPortNum = 9999
	maxItems   = 512
)

var digitsRe = regexp.MustCompile(`^[0-9]{1,4}$`)

/* port is a parsed port: its components, the end of a range on the last one (== last without a range), the sub-interface (-1: none). */
type port struct {
	comps []int
	hi    int
	sub   int
}

func num(s string) (int, bool) {
	if !digitsRe.MatchString(s) {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	return n, err == nil && n <= maxPortNum
}

/* parsePort reads "1/0/1", "1/0/1-4" (rng), "1/0/1.100" (t.Sub); leading zeros are allowed. */
func parsePort(s string, t IfType, rng bool) (port, bool) {
	p := port{sub: -1}
	if t.Comps == 0 {
		return p, s == ""
	}
	if t.Sub {
		if base, sub, ok := strings.Cut(s, "."); ok {
			n, ok := num(sub)
			if !ok || rng {
				return p, false
			}
			s, p.sub = base, n
		}
	}
	parts := strings.Split(s, "/")
	if len(parts) != t.Comps {
		return p, false
	}
	for i, c := range parts {
		if i == len(parts)-1 && rng {
			if lo, hi, ok := strings.Cut(c, "-"); ok {
				a, ok1 := num(lo)
				b, ok2 := num(hi)
				if !ok1 || !ok2 {
					return p, false
				}
				p.comps, p.hi = append(p.comps, a), b
				return p, true
			}
		}
		n, ok := num(c)
		if !ok {
			return p, false
		}
		p.comps = append(p.comps, n)
	}
	p.hi = p.comps[len(p.comps)-1]
	return p, true
}

/* count is the number of interfaces p names (0: an empty or reversed range). */
func (p port) count() int {
	if len(p.comps) == 0 {
		return 1
	}
	return max(0, p.hi-p.comps[len(p.comps)-1]+1)
}

/* names appends the canonical names of p: type name, components without leading zeros, ".sub". */
func (p port) names(t IfType, out []string, parent bool) []string {
	if len(p.comps) == 0 {
		return append(out, t.Name)
	}
	head := make([]string, len(p.comps)-1)
	for i, c := range p.comps[:len(p.comps)-1] {
		head[i] = strconv.Itoa(c)
	}
	prefix := t.Name + strings.Join(append(head, ""), "/")
	for n := p.comps[len(p.comps)-1]; n <= p.hi; n++ {
		name := prefix + strconv.Itoa(n)
		if p.sub >= 0 {
			out = append(out, name+"."+strconv.Itoa(p.sub))
			if !parent {
				continue
			}
		}
		out = append(out, name)
	}
	return out
}

/*
splitType splits a glued interface token ("Gi1/0/1", "port-channel2", "oob")
into its type, found by a unique prefix among all (lower case), and the port
text. only, when set, is the one type the argument accepts.
*/
func splitType(tok string, all []IfType, only string) (IfType, string, bool) {
	low := strings.ToLower(tok)
	i := strings.IndexFunc(low, func(r rune) bool { return (r < 'a' || r > 'z') && r != '-' })
	if i < 0 {
		i = len(low)
	}
	pre, rest := low[:i], low[i:]
	if pre == "" {
		return IfType{}, "", false
	}
	var hit IfType
	n := 0
	for _, t := range all {
		if strings.HasPrefix(t.Name, pre) {
			hit, n = t, n+1
		}
	}
	if n != 1 || only != "" && hit.Name != only {
		return IfType{}, "", false
	}
	return hit, rest, true
}

/*
Iface is a glued interface name of the types all (of one type when only is
set): "gi1/0/1", "GigabitEthernet01/0/01", "te1/0/2", "po1", "oob". Kind is
"interface" and every spelling has one canonical name, the type's full name
and the components without leading zeros. A sub-interface also names its
parent, so a management sub-interface protects the port it rides on.
*/
func Iface(all []IfType, only string) core.ArgType {
	parse := func(tok string) (IfType, port, bool) {
		t, rest, ok := splitType(tok, all, only)
		if !ok {
			return t, port{}, false
		}
		p, ok := parsePort(rest, t, false)
		return t, p, ok
	}
	return core.ArgType{
		Match: func(tok string) bool { _, _, ok := parse(tok); return ok },
		Kind:  "interface",
		Names: func(tok string, limit int) ([]string, bool) {
			t, p, ok := parse(tok)
			need := 1
			if p.sub >= 0 {
				need = 2
			}
			if !ok || need > limit {
				return nil, false
			}
			return p.names(t, make([]string, 0, need), true), true
		},
	}
}

/* Port is the port of a spaced interface name ("gigabitethernet 1/0/1"): Names adds the type. */
func Port(t IfType) core.ArgType {
	return core.ArgType{
		Match: func(tok string) bool { _, ok := parsePort(tok, t, false); return ok && t.Comps > 0 },
		Kind:  "interface",
		Names: func(tok string, limit int) ([]string, bool) {
			p, ok := parsePort(tok, t, false)
			need := 1
			if p.sub >= 0 {
				need = 2
			}
			if !ok || t.Comps == 0 || need > limit {
				return nil, false
			}
			return p.names(t, make([]string, 0, need), true), true
		},
	}
}

/* rangeItems reads a comma list of ports with ranges; a glued item sets the type for the bare items after it. */
func rangeItems(tok string, all []IfType, fixed *IfType) ([]IfType, []port, bool) {
	items := strings.Split(tok, ",")
	if len(items) > maxItems {
		return nil, nil, false
	}
	ts, ps := make([]IfType, 0, len(items)), make([]port, 0, len(items))
	var cur IfType
	have := fixed != nil
	if have {
		cur = *fixed
	}
	for _, it := range items {
		rest := it
		if fixed == nil && it != "" && (it[0] < '0' || it[0] > '9') {
			t, r, ok := splitType(it, all, "")
			if !ok {
				return nil, nil, false
			}
			cur, rest, have = t, r, true
		}
		if !have || cur.Comps == 0 {
			return nil, nil, false
		}
		p, ok := parsePort(rest, cur, true)
		if !ok || p.count() == 0 {
			return nil, nil, false
		}
		ts, ps = append(ts, cur), append(ps, p)
	}
	return ts, ps, true
}

func rangeType(all []IfType, fixed *IfType) core.ArgType {
	return core.ArgType{
		Match: func(tok string) bool { _, _, ok := rangeItems(tok, all, fixed); return ok },
		Kind:  "interface",
		Names: func(tok string, limit int) ([]string, bool) {
			ts, ps, ok := rangeItems(tok, all, fixed)
			if !ok {
				return nil, false
			}
			need := 0
			for _, p := range ps {
				if need += p.count(); need > limit {
					return nil, false /* counted before anything is allocated */
				}
			}
			out := make([]string, 0, need)
			for i, p := range ps {
				out = p.names(ts[i], out, true)
			}
			return out, true
		},
	}
}

/* IfRange is an interface list of "interface range": "gi1/0/1-4,gi1/0/7", "gi1/0/1-2,1/0/5" (the type carries over). */
func IfRange(all []IfType) core.ArgType { return rangeType(all, nil) }

/* PortRange is the port list of a spaced "interface range gigabitethernet 1/0/1-4,1/0/7". */
func PortRange(t IfType) core.ArgType { return rangeType(nil, &t) }

/* vlanItems reads "10", "10,20-30": every VLAN in 1..4094, ranges not reversed. */
func vlanItems(tok string) ([][2]int, bool) {
	items := strings.Split(tok, ",")
	if len(items) > maxItems {
		return nil, false
	}
	out := make([][2]int, 0, len(items))
	for _, it := range items {
		lo, hi, rng := strings.Cut(it, "-")
		a, ok1 := num(lo)
		b, ok2 := a, true
		if rng {
			b, ok2 = num(hi)
		}
		if !ok1 || !ok2 || a < 1 || b > 4094 || b < a {
			return nil, false
		}
		out = append(out, [2]int{a, b})
	}
	return out, true
}

/* VLANs is a VLAN list ("10,20-30"); Kind "vlan", every member named, as core.Uint(1, 4094, "vlan") names one. */
func VLANs() core.ArgType {
	return core.ArgType{
		Match: func(tok string) bool { _, ok := vlanItems(tok); return ok },
		Kind:  "vlan",
		Names: func(tok string, limit int) ([]string, bool) {
			rs, ok := vlanItems(tok)
			if !ok {
				return nil, false
			}
			need := 0
			for _, r := range rs {
				if need += r[1] - r[0] + 1; need > limit {
					return nil, false
				}
			}
			out := make([]string, 0, need)
			for _, r := range rs {
				for v := r[0]; v <= r[1]; v++ {
					out = append(out, strconv.Itoa(v))
				}
			}
			return out, true
		},
	}
}

/* ExpandVLANs returns the members of a VLAN list (at most MaxTargets). */
func ExpandVLANs(tok string) ([]int, bool) {
	names, ok := VLANs().Names(tok, core.MaxTargets)
	if !ok {
		return nil, false
	}
	out := make([]int, len(names))
	for i, n := range names {
		out[i], _ = strconv.Atoi(n)
	}
	return out, true
}

var (
	hostnameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,57}$`)
	vnameRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$`)
)

/* Typed argument types shared by the lines. */
var (
	/* Hostname: what the prompt pattern accepts (strategy.Set.Prompt), shorter. */
	Hostname = core.ArgType{Match: hostnameRe.MatchString}
	/* IPv4: a dotted quad without leading zeros. */
	IPv4 = core.ArgType{Match: func(t string) bool { a, err := netip.ParseAddr(t); return err == nil && a.Is4() }}
	/* VName: a VLAN name, one word. */
	VName = core.ArgType{Match: vnameRe.MatchString}
	/* Desc: the rest of a description or location line (pure tokens only: no Text). */
	Desc = core.ArgType{Match: func(string) bool { return true }}
	/* Filter: the pattern of a show filter, rest of the line (pure tokens only). */
	Filter = core.ArgType{Match: func(string) bool { return true }}
	/* VLAN is one VLAN ID. */
	VLAN = core.Uint(1, 4094, "vlan")
)

/* Nav are the navigation commands of every configuration sub-mode. */
func Nav() []core.Cmd {
	return []core.Cmd{{Pattern: "exit", Class: core.Safe, Nav: core.Exit}, {Pattern: "end", Class: core.Safe, Nav: core.End}}
}

/* Sub is a configuration mode below parent with `do` and the navigation commands. */
func Sub(name, parent string, cmds ...core.Cmd) core.ModeSpec {
	return core.ModeSpec{Name: name, Parent: parent, Do: true, Cmds: append(cmds, Nav()...)}
}

/* Safe is a safe command. */
func Safe(p string) core.Cmd { return core.Cmd{Pattern: p, Class: core.Safe} }

/* Enter is a safe command that enters mode. */
func Enter(p, mode string) core.Cmd { return core.Cmd{Pattern: p, Class: core.Safe, Enter: mode} }

/* Danger is a dangerous command. */
func Danger(p string) core.Cmd { return core.Cmd{Pattern: p, Class: core.Dangerous} }

/* Ctl is a session-control command of kind k. */
func Ctl(p string, k core.ControlKind) core.Cmd {
	return core.Cmd{Pattern: p, Class: core.Control, Control: k}
}

/* Dangers makes a dangerous command of each pattern. */
func Dangers(ps ...string) []core.Cmd {
	out := make([]core.Cmd, len(ps))
	for i, p := range ps {
		out[i] = Danger(p)
	}
	return out
}

/* SplitIface cuts the one canonical name of ts into its type and port ("gigabitethernet1/0/1" -> "gigabitethernet", "1/0/1"). */
func SplitIface(types []IfType, ts []core.Target) (string, string, bool) {
	if len(ts) != 1 {
		return "", "", false
	}
	for _, t := range types {
		if p, ok := strings.CutPrefix(ts[0].Name, t.Name); ok && p != "" && p[0] >= '0' && p[0] <= '9' {
			return t.Name, p, true
		}
	}
	return "", "", false
}
