/*
Package mes10 is the write driver of the Eltex MES 10.x line (MES14xx, 24xx,
3400, 37xx): configure terminal, write startup-config, replace
running-config [R §2b]. Syntax from .superpowers/research/eltex-cli.md [R]
§2b, §5, §6, §7; what [R] does not show is marked "guess". Unverified until
a stand run.
*/
package mes10

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
	"github.com/beekamai/network-scheme/cmd/executor/internal/strategy"
	"github.com/beekamai/network-scheme/cmd/executor/internal/transport"
)

/* Interface types: "gigabitethernet 0/1" [fixture, R §5]; slot/port. */
var (
	gi    = drivers.IfType{Name: "gigabitethernet", Comps: 2}
	te    = drivers.IfType{Name: "tengigabitethernet", Comps: 2}
	po    = drivers.IfType{Name: "port-channel", Comps: 1}
	types = []drivers.IfType{gi, te, po}
)

var saveDst = []string{"startup-config", "flash:startup-config", "flash://startup-config", "nvram:startup-config", "system:startup-config"}

func execCmds() []core.Cmd {
	cmds := []core.Cmd{
		drivers.Enter("configure terminal", "config"), /* [R §2b]: "configure" alone is incomplete */
		drivers.Ctl("write", core.Save),
		drivers.Ctl("write startup-config", core.Save), /* [R §2b] */
		drivers.Ctl("write memory", core.Save),
		drivers.Ctl("reload cancel", core.ReloadCancel),
	}
	for _, src := range []string{"running-config", "system:running-config", "flash://running-config"} {
		for _, dst := range saveDst {
			cmds = append(cmds, drivers.Ctl("copy "+src+" "+dst, core.Save))
		}
	}
	cmds = append(cmds, drivers.Show("grep")...) /* [R §5] "| grep" */
	cmds = append(cmds, drivers.Safe("show startup-config"), drivers.Safe("show reload"),
		drivers.Safe("show interfaces status <iface>"))
	/* [R §6] MES 10.x */
	return append(cmds, drivers.Dangers("reload", "reload <word...>", "erase <word...>", "delete <word...>",
		"replace <word...>", "clear running-config", "clear <word...>", "copy <word...>", "boot <word...>",
		"test <word...>", "crypto <word...>", "set <word...>")...)
}

func ifEnter() []core.Cmd {
	cmds := []core.Cmd{drivers.Enter("interface <iface>", "config-if"), drivers.Enter("interface vlan <vlan>", "config-if")}
	for _, t := range types {
		cmds = append(cmds, drivers.Enter("interface "+t.Name+" <port-"+t.Name+">", "config-if"))
	}
	return cmds
}

func configCmds() []core.Cmd {
	cmds := []core.Cmd{
		drivers.Safe("hostname <hostname>"), drivers.Safe("no hostname"),
		drivers.Enter("vlan <vlan>", "config-vlan"), /* guess: "vlan 99" opens a context [fixture] */
		drivers.Safe("no vlan <vlans>"),
		drivers.Safe("logging host <ipv4>"), drivers.Safe("no logging host <ipv4>"), /* guess */
	}
	cmds = append(cmds, ifEnter()...)
	return append(cmds, drivers.Dangers("username <word...>", "no username <word...>", "aaa <word...>",
		"no aaa <word...>", "ssh <word...>", "no ssh <word...>", "ip <word...>", "no ip <word...>",
		"crypto <word...>", "line <word...>", "stack <word...>", "ztp <word...>", "snmp <word...>",
		"no snmp <word...>", "radius-server <word...>", "tacacs-server <word...>", "spanning-tree <word...>")...)
}

func spec() core.Spec {
	args := map[string]core.ArgType{
		"iface": drivers.Iface(types, ""), "vlan": drivers.VLAN, "vlans": drivers.VLANs(),
		"hostname": drivers.Hostname, "ipv4": drivers.IPv4, "desc": drivers.Desc, "vname": drivers.VName, "filter": drivers.Filter,
	}
	for _, t := range types {
		args["port-"+t.Name] = drivers.Port(t)
	}
	port := []core.Cmd{
		drivers.Safe("description <desc...>"), drivers.Safe("no description"),
		drivers.Safe("shutdown"), drivers.Safe("no shutdown"),
		drivers.Safe("switchport access vlan <vlan>"), drivers.Safe("no switchport access vlan"),
		drivers.Danger("ip address <word...>"), drivers.Danger("no ip address"), drivers.Danger("switchport <word...>"),
		drivers.Danger("spanning-tree <word...>"),
	}
	return core.Spec{Args: args, Modes: []core.ModeSpec{
		{Name: "exec", Cmds: execCmds()},
		drivers.Sub("config", "exec", configCmds()...),
		drivers.Sub("config-if", "config", append(port, ifEnter()...)...),
		drivers.Sub("config-vlan", "config", drivers.Safe("name <vname>"), drivers.Safe("no name")),
	}}
}

/* Driver is the MES 10.x write driver. */
type Driver struct{ drivers.Base }

/* New returns the driver. */
func New() Driver {
	return Driver{drivers.Base{L: strategy.MES10, G: drivers.MustGrammar(spec()), Ifs: []string{"iface"}, VLANT: "vlan", SaveCopy: true,
		S: drivers.Strategies{SafetyNet: "none", ReloadMinutes: 10, Save: "write-startup", Rollback: "replace", Mask: "always"}}}
}

func init() { drivers.Register(New()) }

/* RenderForm renders a form as lines from the privileged prompt ("interface gigabitethernet 0/1"). */
func (d Driver) RenderForm(f drivers.Form) ([]string, error) {
	if err := f.Check(64, true); err != nil {
		return nil, err
	}
	v := strconv.Itoa(f.VLAN)
	var body []string
	switch f.Kind {
	case drivers.FormDescription, drivers.FormState, drivers.FormAccessVLAN:
		ts, _ := d.G.Targets("iface", f.Interface)
		t, p, ok := drivers.SplitIface(types, ts)
		if !ok {
			return nil, fmt.Errorf("%w: interface %q", drivers.ErrForm, f.Interface)
		}
		body = append([]string{"interface " + t + " " + p}, f.PortLines()...)
	case drivers.FormVLANCreate:
		body = []string{"vlan " + v}
	case drivers.FormVLANName:
		body = []string{"vlan " + v, "name " + f.Name}
	case drivers.FormVLANDelete:
		body = []string{"no vlan " + v}
	default:
		return nil, drivers.ErrForm
	}
	return append(append([]string{"configure terminal"}, body...), "end"), nil
}

type session struct {
	*drivers.Core
	armed bool
}

func (s *session) Pre() drivers.Config { return s.Core.Pre }

/*
Open reads the pre-session snapshot and copies the running configuration to
flash:nms-pre-<sid> for Rollback [R §2b, §9.3]; with the reload-in safety
net it arms "reload in <hours> <minutes>".
*/
func (d Driver) Open(ctx context.Context, sh *transport.Shell, o drivers.Options) (drivers.Session, error) {
	return d.open(ctx, sh, o)
}

/* OpenShell opens a session on any drivers.Shell (the in-memory emulator of other packages' tests); the executor opens through Open. */
func (d Driver) OpenShell(ctx context.Context, sh drivers.Shell, o drivers.Options) (drivers.Session, error) {
	s, err := d.open(ctx, sh, o)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (d Driver) open(ctx context.Context, sh drivers.Shell, o drivers.Options) (*session, error) {
	o, err := drivers.Prepare(d.L, d.S, o)
	if err != nil {
		return nil, err
	}
	c, err := drivers.NewCore(ctx, sh, d, d.G, o)
	if err != nil {
		return nil, err
	}
	s := &session{Core: c}
	if _, err := s.System(ctx, "copy running-config "+s.SnapshotFile("flash:")); err != nil {
		return nil, err
	}
	if m := o.Strategies.ReloadMinutes; o.Strategies.SafetyNet == "reload-in" {
		if _, err := s.System(ctx, fmt.Sprintf("reload in %d %d", m/60, m%60)); err != nil {
			return nil, errors.Join(err, s.DropSnapshot(ctx, s.SnapshotFile("flash:"))) /* its own Open failed: no file left behind */
		}
		s.armed = true
	}
	return s, nil
}

/* Save writes the startup configuration [R §2b]. */
func (s *session) Save(ctx context.Context) error {
	if err := s.ToRoot(ctx); err != nil {
		return err
	}
	if _, err := s.System(ctx, "write startup-config"); err != nil {
		return err
	}
	return s.disarm(ctx)
}

func (s *session) disarm(ctx context.Context) error {
	if !s.armed {
		return nil
	}
	if _, err := s.System(ctx, "reload cancel"); err != nil {
		return err
	}
	s.armed = false
	return nil
}

func (*session) Commit(context.Context, time.Duration) error { return drivers.ErrNotApplicable }

/* Rollback replaces running-config with the snapshot copied at Open, then checks the hash [R §2b]. */
func (s *session) Rollback(ctx context.Context, to drivers.Config) error {
	if err := s.CheckTarget(to); err != nil {
		return err
	}
	if err := s.ToRoot(ctx); err != nil {
		return err
	}
	if _, err := s.System(ctx, "replace running-config "+s.SnapshotFile("flash:")); err != nil {
		return s.Fail(ctx, err)
	}
	return s.Verify(ctx, to)
}

/* Close leaves the configuration, cancels the safety net and deletes the snapshot file. */
func (s *session) Close(ctx context.Context) error {
	if err := s.ToRoot(ctx); err != nil {
		return err
	}
	if err := s.disarm(ctx); err != nil {
		return err
	}
	return s.DropSnapshot(ctx, s.SnapshotFile("flash:"))
}
