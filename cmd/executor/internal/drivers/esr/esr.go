/*
Package esr is the write driver of Eltex ESR routers: a shared candidate,
commit with a confirm timer (it also writes flash), confirm, restore [R §1].
Syntax from .superpowers/research/eltex-cli.md [R] §1, §5, §6, §7; what [R]
does not show is marked "guess". Unverified until a stand run.
*/
package esr

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
	"github.com/beekamai/network-scheme/cmd/executor/internal/strategy"
	"github.com/beekamai/network-scheme/cmd/executor/internal/transport"
)

/* Interface types: "gigabitethernet 1/0/1" [R §5 prompts, fixture], sub-interfaces "1/0/1.100" (guess). */
var (
	gi    = drivers.IfType{Name: "gigabitethernet", Comps: 3, Sub: true}
	te    = drivers.IfType{Name: "tengigabitethernet", Comps: 3, Sub: true}
	po    = drivers.IfType{Name: "port-channel", Comps: 1}
	types = []drivers.IfType{gi, te, po}
	/* modes of the interface types: config-if-gi [R §5], the others by analogy (guess) */
	modes = map[string]string{gi.Name: "config-if-gi", te.Name: "config-if-te", po.Name: "config-port-channel"}
	short = map[string]string{gi.Name: "gi", te.Name: "te", po.Name: "po"}
)

func execCmds() []core.Cmd {
	cmds := []core.Cmd{
		drivers.Enter("configure", "config"), /* [R §5] configure [terminal] */
		drivers.Enter("configure terminal", "config"),
		/* [R §1]: every commit, confirm, restore and save is a session flow */
		drivers.Ctl("commit", core.Commit),
		drivers.Ctl("commit <word...>", core.Commit),
		drivers.Ctl("confirm", core.Confirm),
		drivers.Ctl("restore", core.Restore),
		drivers.Ctl("save", core.Save),
		drivers.Ctl("reload cancel", core.ReloadCancel),
		drivers.Safe("show candidate-config"), drivers.Safe("show configuration changes"),
	}
	cmds = append(cmds, drivers.Show("include", "exclude", "begin")...) /* [R §5] filters */
	/* [R §6] ESR: reload, replace and reset, firmware and boot, storage, SSH host key */
	return append(cmds, drivers.Dangers("reload <word...>", "copy <word...>", "rollback", "rollback <word...>",
		"delete <word...>", "boot <word...>", "clear <word...>", "update <word...>", "terminal <word...>")...)
}

func ifEnter() []core.Cmd {
	var cmds []core.Cmd
	for _, t := range types {
		cmds = append(cmds, drivers.Enter("interface <iface-"+short[t.Name]+">", modes[t.Name]),
			drivers.Enter("interface "+t.Name+" <port-"+t.Name+">", modes[t.Name]))
	}
	return cmds
}

func configCmds() []core.Cmd {
	cmds := []core.Cmd{
		drivers.Safe("hostname <hostname>"), drivers.Safe("no hostname"),
		drivers.Enter("vlan <vlan>", "config-vlan"), drivers.Safe("no vlan <vlans>"), /* guess */
	}
	cmds = append(cmds, ifEnter()...)
	/* [R §6] ESR: users and AAA, SSH, management plane, confirm timer, archive */
	return append(cmds, drivers.Dangers("username <word...>", "no username <word...>", "enable <word...>",
		"no enable <word...>", "aaa <word...>", "no aaa <word...>", "privilege <word...>", "ip <word...>",
		"no ip <word...>", "security <word...>", "no security <word...>", "system <word...>", "no system <word...>",
		"archive", "line <word...>", "snmp-server <word...>", "no snmp-server <word...>", "crypto <word...>",
		"object-group <word...>", "bridge <word...>")...)
}

func spec() core.Spec {
	args := map[string]core.ArgType{
		"vlan": drivers.VLAN, "vlans": drivers.VLANs(), "hostname": drivers.Hostname,
		"desc": drivers.Desc, "vname": drivers.VName, "filter": drivers.Filter,
	}
	for _, t := range types {
		args["iface-"+short[t.Name]], args["port-"+t.Name] = drivers.Iface(types, t.Name), drivers.Port(t)
	}
	port := append([]core.Cmd{
		drivers.Safe("description <desc...>"), drivers.Safe("no description"),
		drivers.Safe("shutdown"), drivers.Safe("no shutdown"),
		drivers.Safe("switchport access vlan <vlan>"), drivers.Safe("no switchport access vlan"), /* guess */
		drivers.Danger("ip <word...>"), drivers.Danger("no ip <word...>"), drivers.Danger("security-zone <word...>"),
		drivers.Danger("mode <word...>"),
	}, ifEnter()...)
	ms := []core.ModeSpec{{Name: "exec", Cmds: execCmds()}, drivers.Sub("config", "exec", configCmds()...)}
	for _, t := range types {
		ms = append(ms, drivers.Sub(modes[t.Name], "config", port...))
	}
	ms = append(ms, drivers.Sub("config-vlan", "config", drivers.Safe("name <vname>"), drivers.Safe("no name")))
	return core.Spec{Args: args, Modes: ms}
}

/* Driver is the ESR write driver. */
type Driver struct{ drivers.Base }

/* New returns the driver. */
func New() Driver {
	return Driver{drivers.Base{L: strategy.ESR, G: drivers.MustGrammar(spec()), Ifs: []string{"iface-gi", "iface-te", "iface-po"},
		VLANT: "vlan", S: drivers.Strategies{SafetyNet: "none", Save: "confirm", Commit: "end", Close: "restore",
			Rollback: "restore-snapshot", Mask: "always"}}}
}

func init() { drivers.Register(New()) }

/* RenderForm renders a form as lines from the privileged prompt; descriptions are one word (no quotes are ever rendered). */
func (d Driver) RenderForm(f drivers.Form) ([]string, error) {
	if err := f.Check(255, false); err != nil {
		return nil, err
	}
	v := strconv.Itoa(f.VLAN)
	var body []string
	switch f.Kind {
	case drivers.FormDescription, drivers.FormState, drivers.FormAccessVLAN:
		ts, _ := d.Targets("interface", f.Interface)
		typ, port, ok := drivers.SplitIface(types, ts)
		if !ok {
			return nil, fmt.Errorf("%w: interface %q", drivers.ErrForm, f.Interface)
		}
		body = append([]string{"interface " + typ + " " + port}, f.PortLines()...)
	case drivers.FormVLANCreate:
		body = []string{"vlan " + v}
	case drivers.FormVLANName:
		body = []string{"vlan " + v, "name " + f.Name}
	case drivers.FormVLANDelete:
		body = []string{"no vlan " + v}
	default:
		return nil, drivers.ErrForm
	}
	return append(append([]string{"configure"}, body...), "end"), nil
}

type session struct {
	*drivers.Core
	pending   bool /* a commit waits for confirm */
	confirmed bool /* this session confirmed a commit */
}

func (s *session) Pre() drivers.Config { return s.Core.Pre }

/*
Open reads the pre-session snapshot and copies the running configuration to
flash:data/nms-pre-<sid> (guess: the flash path) for a rollback after
confirm [R §1: copy <src> system:candidate-config]. The transport already
refused a non-empty candidate or another session (concurrency exclusive).
*/
func (d Driver) Open(ctx context.Context, sh *transport.Shell, o drivers.Options) (drivers.Session, error) {
	return d.open(ctx, sh, o)
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
	if _, err := s.System(ctx, "copy system:running-config "+s.SnapshotFile("flash:data/")); err != nil {
		return nil, err
	}
	return s, nil
}

/* commit applies the candidate with a confirm timer: end + commit (or do commit) [R §1, §9.8]. */
func (s *session) commit(ctx context.Context, secs int) error {
	cmd := "commit confirm-timeout " + strconv.Itoa(secs)
	if s.Opt.Strategies.Commit == "end" {
		if err := s.ToRoot(ctx); err != nil {
			return err
		}
	} else if st := s.Sh.State().Mode; st == transport.ModeConfig || st == transport.ModeSub {
		cmd = "do " + cmd
	}
	if _, err := s.System(ctx, cmd); err != nil {
		return err
	}
	s.pending = true
	return nil
}

/* Commit is the typed commit: the candidate goes to running and flash, the device reverts without confirm. */
func (s *session) Commit(ctx context.Context, timeout time.Duration) error {
	secs, err := drivers.CommitSeconds(timeout)
	if err != nil {
		return err
	}
	return s.commit(ctx, secs)
}

/* Save is confirm (irreversible [R §1]); with ExtraSave a save after it. */
func (s *session) Save(ctx context.Context) error {
	if !s.pending {
		return drivers.ErrNothingToConfirm
	}
	if err := s.ToRoot(ctx); err != nil {
		return err
	}
	if _, err := s.System(ctx, "confirm"); err != nil {
		return err
	}
	s.pending, s.confirmed = false, true
	if s.Opt.Strategies.ExtraSave {
		_, err := s.System(ctx, "save")
		return err
	}
	return nil
}

/* drop discards an unconfirmed commit (restore) and the uncommitted candidate (rollback) [R §1]. */
func (s *session) drop(ctx context.Context, restore bool) error {
	if err := s.ToRoot(ctx); err != nil {
		return err
	}
	if s.pending && restore {
		if _, err := s.System(ctx, "restore"); err != nil {
			return err
		}
		s.pending = false
	}
	_, err := s.System(ctx, "rollback")
	return err
}

/*
Rollback before confirm is restore + rollback; after a confirm it copies the
snapshot of Open into the candidate, commits it with the policy's timer,
checks the hash and only then confirms (a mismatch restores instead) [R §1].
*/
func (s *session) Rollback(ctx context.Context, to drivers.Config) error {
	if err := s.CheckTarget(to); err != nil {
		return err
	}
	secs, err := drivers.CommitSeconds(s.Opt.CommitTimeout)
	if err != nil {
		return err
	}
	if err := s.drop(ctx, true); err != nil {
		return s.Fail(ctx, err)
	}
	if !s.confirmed {
		return s.Verify(ctx, to)
	}
	if _, err := s.System(ctx, "copy "+s.SnapshotFile("flash:data/")+" system:candidate-config"); err != nil {
		return s.Fail(ctx, err)
	}
	if err := s.commit(ctx, secs); err != nil {
		_ = s.drop(ctx, true)
		return s.Fail(ctx, err)
	}
	if err := s.Verify(ctx, to); err != nil {
		_ = s.drop(ctx, true)
		return err
	}
	if _, err := s.System(ctx, "confirm"); err != nil {
		return s.Fail(ctx, err)
	}
	s.pending = false
	return nil
}

/* Close restores an unconfirmed commit (or leaves it to the timer), drops the uncommitted candidate and deletes the snapshot file. */
func (s *session) Close(ctx context.Context) error {
	if err := s.drop(ctx, s.Opt.Strategies.Close == "restore"); err != nil {
		return err
	}
	return s.DropSnapshot(ctx, s.SnapshotFile("flash:data/"))
}
