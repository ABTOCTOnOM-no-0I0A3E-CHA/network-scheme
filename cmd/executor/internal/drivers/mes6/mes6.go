/*
Package mes6 is the write driver of the Eltex MES 6.x line (MES23xx, 33xx,
35xx, 53xx, 54xx, 5500): immediate apply, save by write + Y [R §2a]. Syntax
from .superpowers/research/eltex-cli.md [R] §2a, §5, §6, §7; what [R] does
not show is marked "guess". Unverified until a stand run.
*/
package mes6

import (
	"fmt"
	"strconv"

	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
	"github.com/beekamai/network-scheme/cmd/executor/internal/strategy"
)

/* Interface types: gigabitethernet1/0/1 as the running configuration prints it [R §5 prompts, fixture]; oob [R §6]. */
var (
	gi    = drivers.IfType{Name: "gigabitethernet", Comps: 3}
	te    = drivers.IfType{Name: "tengigabitethernet", Comps: 3}
	po    = drivers.IfType{Name: "port-channel", Comps: 1}
	oob   = drivers.IfType{Name: "oob"}
	types = []drivers.IfType{gi, te, po, oob}
)

/* saveDst are the startup-config spellings a copy may name; every one is the Save flow. */
var saveDst = []string{"startup-config", "flash:startup-config", "flash://startup-config", "nvram:startup-config", "system:startup-config"}

func execCmds() []core.Cmd {
	cmds := []core.Cmd{
		drivers.Enter("configure", "config"), /* [R §5] configure [terminal] */
		drivers.Enter("configure terminal", "config"),
		drivers.Ctl("write", core.Save), /* [R §2a] write [memory] */
		drivers.Ctl("write memory", core.Save),
		drivers.Ctl("write startup-config", core.Save), /* the 10.x spelling: never sent either */
		drivers.Ctl("reload cancel", core.ReloadCancel),
	}
	for _, src := range []string{"running-config", "system:running-config", "flash://running-config"} {
		for _, dst := range saveDst {
			cmds = append(cmds, drivers.Ctl("copy "+src+" "+dst, core.Save))
		}
	}
	cmds = append(cmds, drivers.Show("include", "exclude", "begin")...)
	cmds = append(cmds, drivers.Safe("show startup-config"), drivers.Safe("show interfaces status <iface>"),
		drivers.Safe("show interfaces counters <iface>"))
	/* [R §6] MES 6.x: reload, erase and replace, firmware, keys; TDR and other tests take links down */
	return append(cmds, drivers.Dangers("reload", "reload <word...>", "copy <word...>", "delete <word...>",
		"boot <word...>", "rename <word...>", "test <word...>", "crypto <word...>", "clear <word...>")...)
}

func configCmds() []core.Cmd {
	cmds := []core.Cmd{
		drivers.Safe("hostname <hostname>"), drivers.Safe("no hostname"),
		drivers.Safe("logging host <ipv4>"), drivers.Safe("no logging host <ipv4>"), /* guess (Cisco SMB) */
		drivers.Safe("sntp server <ipv4>"), drivers.Safe("no sntp server <ipv4>"), /* guess: [R §7] names sntp */
		drivers.Safe("snmp-server location <desc...>"), drivers.Safe("no snmp-server location"), /* guess */
		drivers.Safe("snmp-server contact <desc...>"), drivers.Safe("no snmp-server contact"),
		drivers.Enter("vlan database", "config-vlan"), /* [R §5] console(config-vlan)# */
		drivers.Safe("no interface vlan <vlan>"),      /* guess */
	}
	cmds = append(cmds, ifEnter()...)
	/* [R §6] MES 6.x users, AAA, SSH, management plane, stack, hardware; [R §7] encrypted forms */
	return append(cmds, drivers.Dangers("username <word...>", "no username <word...>", "enable <word...>",
		"no enable <word...>", "aaa <word...>", "no aaa <word...>", "privilege <word...>", "ip <word...>",
		"no ip <word...>", "crypto <word...>", "no crypto <word...>", "management <word...>",
		"no management <word...>", "radius-server <word...>", "tacacs-server <word...>", "passwords <word...>",
		"service <word...>", "no service <word...>", "reset-button <word...>", "system <word...>",
		"stack <word...>", "snmp-server <word...>", "no snmp-server <word...>", "encrypted <word...>",
		"spanning-tree <word...>", "no spanning-tree <word...>", "line <word...>")...)
}

/* ifEnter enters an interface: glued, spaced, interface vlan, interface range [R §5, §6]. */
func ifEnter() []core.Cmd {
	cmds := []core.Cmd{
		drivers.Enter("interface <iface>", "config-if"),
		drivers.Enter("interface vlan <vlan>", "config-if"),
		drivers.Enter("interface range <iface-range>", "config-if-range"), /* guess: mode name */
	}
	for _, t := range types[:3] {
		cmds = append(cmds, drivers.Enter("interface "+t.Name+" <port-"+t.Name+">", "config-if"),
			drivers.Enter("interface range "+t.Name+" <ports-"+t.Name+">", "config-if-range"))
	}
	return cmds
}

func portCmds() []core.Cmd {
	return []core.Cmd{
		drivers.Safe("description <desc...>"), drivers.Safe("no description"),
		drivers.Safe("shutdown"), drivers.Safe("no shutdown"),
		drivers.Safe("switchport access vlan <vlan>"), drivers.Safe("no switchport access vlan"),
		drivers.Danger("ip address <word...>"), drivers.Danger("no ip address"), drivers.Danger("switchport <word...>"),
		drivers.Danger("spanning-tree <word...>"),
	}
}

func spec() core.Spec {
	args := map[string]core.ArgType{
		"iface": drivers.Iface(types, ""), "iface-range": drivers.IfRange(types),
		"vlan": drivers.VLAN, "vlans": drivers.VLANs(), "hostname": drivers.Hostname, "ipv4": drivers.IPv4,
		"desc": drivers.Desc, "vname": drivers.VName, "filter": drivers.Filter,
	}
	for _, t := range types[:3] {
		args["port-"+t.Name], args["ports-"+t.Name] = drivers.Port(t), drivers.PortRange(t)
	}
	ifc := append(portCmds(), drivers.Safe("name <vname>"), drivers.Safe("no name")) /* guess: VLAN name in interface vlan */
	return core.Spec{Args: args, Modes: []core.ModeSpec{
		{Name: "exec", Cmds: execCmds()},
		drivers.Sub("config", "exec", configCmds()...),
		drivers.Sub("config-if", "config", append(ifc, ifEnter()...)...),
		drivers.Sub("config-if-range", "config", append(portCmds(), ifEnter()...)...),
		drivers.Sub("config-vlan", "config", drivers.Safe("vlan <vlans>"), drivers.Safe("no vlan <vlans>")),
	}}
}

/* Driver is the MES 6.x write driver. */
type Driver struct{ drivers.Base }

/* New returns the driver. */
func New() Driver {
	return Driver{drivers.Base{L: strategy.MES6, G: drivers.MustGrammar(spec()), Ifs: []string{"iface"}, VLANT: "vlan", SaveCopy: true,
		S: drivers.Strategies{Apply: "immediate", SafetyNet: "none", ReloadMinutes: 10, Save: "write", Rollback: "inverse", Mask: "always"}}}
}

func init() { drivers.Register(New()) }

/* ifLine is the context line of one interface as the running configuration prints it: "interface gigabitethernet1/0/1". */
func (d Driver) ifLine(name string) (string, error) {
	ts, ok := d.G.Targets("iface", name)
	if !ok || len(ts) != 1 {
		return "", fmt.Errorf("%w: interface %q", drivers.ErrForm, name)
	}
	return "interface " + ts[0].Name, nil
}

/* RenderForm renders a form as lines from the privileged prompt. */
func (d Driver) RenderForm(f drivers.Form) ([]string, error) {
	if err := f.Check(64, true); err != nil {
		return nil, err
	}
	v := strconv.Itoa(f.VLAN)
	var ctx string
	var body []string
	switch f.Kind {
	case drivers.FormDescription, drivers.FormState, drivers.FormAccessVLAN:
		l, err := d.ifLine(f.Interface)
		if err != nil {
			return nil, err
		}
		ctx, body = l, f.PortLines()
	case drivers.FormVLANCreate:
		ctx, body = "vlan database", []string{"vlan " + v}
	case drivers.FormVLANDelete:
		ctx, body = "vlan database", []string{"no vlan " + v}
	case drivers.FormVLANName:
		ctx, body = "interface vlan "+v, []string{"name " + f.Name}
	default:
		return nil, drivers.ErrForm
	}
	return append(append([]string{"configure", ctx}, body...), "end"), nil
}
