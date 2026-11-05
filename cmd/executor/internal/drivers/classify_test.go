package drivers_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/esr"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/mes10"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/mes6"
	"github.com/beekamai/network-scheme/cmd/executor/internal/strategy"
)

/* fixture is one line's driver and its management targets: the executor reaches the device through mgmtIf in VLAN 99. */
type fixture struct {
	d      drivers.WriteDriver
	cfg    string /* the configure command */
	mgmtIf string
	other  string /* a non-management interface */
}

var lines = map[string]fixture{
	"mes6":  {mes6.New(), "configure", "gi1/0/24", "gi1/0/23"},
	"mes10": {mes10.New(), "configure terminal", "gi0/24", "gi0/23"},
	"esr":   {esr.New(), "configure", "gi1/0/24", "gi1/0/23"},
}

func (f fixture) ctx(t testing.TB) core.Context {
	t.Helper()
	a, ok1 := f.d.Targets("interface", f.mgmtIf)
	b, ok2 := f.d.Targets("vlan", "99")
	if !ok1 || !ok2 {
		t.Fatal("management targets")
	}
	return core.Context{Mgmt: append(a, b...)}
}

/* walk feeds lines through Next from the root, as the device accepted them. */
func walk(g *core.Grammar, ls ...string) core.Mode {
	m := g.Root()
	for _, l := range ls {
		m = g.Next(l, m)
	}
	return m
}

func r(rs ...rune) string { return string(rs) }

/* pat is a line typed after the mode lines; words with a leading '@' are arguments (kept as typed). */
type pat struct {
	mode []string
	line string
}

func (p pat) words() (ws []string, kw []bool) {
	for _, w := range strings.Fields(p.line) {
		a, isArg := strings.CutPrefix(w, "@")
		ws, kw = append(ws, a), append(kw, !isArg)
	}
	return ws, kw
}

func (p pat) plain() string { ws, _ := p.words(); return strings.Join(ws, " ") }

var (
	cfg6   = []string{"configure"}
	cfg10  = []string{"configure terminal"}
	cfgE   = []string{"configure"}
	if6    = []string{"configure", "interface gi1/0/24"}
	vif6   = []string{"configure", "interface vlan 99"}
	vdb6   = []string{"configure", "vlan database"}
	port6  = []string{"configure", "interface gi1/0/1"}
	if10   = []string{"configure terminal", "interface gi0/24"}
	vif10  = []string{"configure terminal", "interface vlan 99"}
	port10 = []string{"configure terminal", "interface gi0/1"}
	ifE    = []string{"configure", "interface gi1/0/24"}
	portE  = []string{"configure", "interface gi1/0/1"}
)

/* dangerous is the C4 table: every dangerous command of security.md 5.3 and [R §6] per line, in its mode. */
var dangerous = map[string][]pat{
	"mes6": {
		{nil, "reload"}, {nil, "reload in @10"}, {nil, "reload in @01:30"}, {nil, "reload at @12:00"}, {nil, "reload unit @1"},
		{nil, "delete startup-config"}, {nil, "delete @flash:test"}, {nil, "delete candidate-config"},
		{nil, "boot config @tftp://192.0.2.1/a.cfg"}, {nil, "boot system @tftp://192.0.2.1/i.bin"}, {nil, "boot system inactive-image"},
		{nil, "boot license @x"}, {nil, "boot password @x"},
		{nil, "copy @tftp://192.0.2.1/a.cfg running-config"},
		{nil, "copy @tftp://192.0.2.1/a.cfg candidate-config"}, {nil, "copy running-config @tftp://192.0.2.1/x"},
		{nil, "rename @flash:a @flash:b"}, {nil, "crypto key generate rsa"},
		{nil, "test cable-diagnostics tdr interface @gi1/0/1"}, {nil, "clear mac address-table"},
		{cfg6, "username @bob password @Secr3t privilege @15"}, {cfg6, "no username @bob"}, {cfg6, "enable password @x"},
		{cfg6, "aaa authentication login @default @local"}, {cfg6, "aaa authorization commands @x"},
		{cfg6, "privilege exec @15 @show"}, {cfg6, "no ip ssh server"}, {cfg6, "ip ssh port @2222"},
		{cfg6, "no ip ssh password-auth"}, {cfg6, "ip ssh pubkey-auth"}, {cfg6, "ip ssh cipher @aes"}, {cfg6, "ip ssh kex @x"},
		{cfg6, "crypto key generate rsa"}, {cfg6, "crypto key import rsa"}, {cfg6, "crypto key pubkey-chain ssh"},
		{cfg6, "management access-list @m"}, {cfg6, "management access-class console-only"},
		{cfg6, "no ip default-gateway"}, {cfg6, "ip default-gateway @192.0.2.1"}, {cfg6, "radius-server host @192.0.2.5 key @k"},
		{cfg6, "tacacs-server key @k"}, {cfg6, "passwords aging @180"}, {cfg6, "passwords lockout @3"},
		{cfg6, "service password-recovery"}, {cfg6, "no service password-recovery"}, {cfg6, "reset-button disable"},
		{cfg6, "system forwarding resources @x"}, {cfg6, "stack configuration @x"}, {cfg6, "stack unit @1"},
		{cfg6, "ip telnet server"}, {cfg6, "ip http server"}, {cfg6, "snmp-server community @public ro"},
		{cfg6, "snmp-server user @u @g v3"}, {cfg6, "no snmp-server community @public"}, {cfg6, "line ssh"},
		{cfg6, "encrypted radius-server host @192.0.2.5 key @x"}, {cfg6, "spanning-tree disable"},
		{cfg6, "no interface vlan @99"}, {vdb6, "no vlan @99"}, {vdb6, "no vlan @90-100"}, {vdb6, "no vlan @1,99"},
		{if6, "shutdown"}, {if6, "no shutdown"}, {if6, "description @x"}, {if6, "switchport access vlan @20"},
		{if6, "ip address @192.0.2.9 @255.255.255.0"}, {if6, "spanning-tree disable"},
		{vif6, "shutdown"}, {vif6, "no ip address"}, {vif6, "ip address @192.0.2.9 @255.255.255.0"}, {vif6, "name @x"},
		{port6, "ip address @10.0.0.1 @255.0.0.0"}, {port6, "switchport mode trunk"}, {port6, "switchport access vlan @99"},
	},
	"mes10": {
		{nil, "reload"}, {nil, "reload in @1 @0"}, {nil, "reload at @12:00:00"}, {nil, "erase startup-config"}, {nil, "erase nvram:"},
		{nil, "delete startup-config"}, {nil, "replace running-config @flash:x.conf"}, {nil, "clear running-config"},
		{nil, "copy @tftp://192.0.2.1/a.conf running-config"},
		{nil, "copy @tftp://192.0.2.1/i image"}, {nil, "copy @tftp://192.0.2.1/b boot"}, {nil, "boot system inactive"},
		{nil, "test cable-diagnostics tdr interface @gi0/1"}, {nil, "set cli pagination on"}, {nil, "crypto key generate rsa"},
		{cfg10, "ssh disable"}, {cfg10, "no ssh enable"}, {cfg10, "ip ssh cipher @x"}, {cfg10, "ip ssh mac @x"},
		{cfg10, "ip ssh kex @x"}, {cfg10, "ip ssh auth-type @x"}, {cfg10, "ip ssh authorized-key @k"},
		{cfg10, "crypto key generate rsa"}, {cfg10, "username @u password @p privilege @15"}, {cfg10, "aaa @x"},
		{cfg10, "line @ssh"}, {cfg10, "stack configuration @x"}, {cfg10, "ztp enable"},
		{cfg10, "snmp community index @1 name @x"}, {cfg10, "no vlan @99"}, {cfg10, "no vlan @98-100"},
		{if10, "shutdown"}, {if10, "no shutdown"}, {if10, "description @x"}, {if10, "ip address @192.0.2.9 @255.255.255.0"},
		{vif10, "shutdown"}, {vif10, "no ip address"}, {port10, "switchport access vlan @99"}, {port10, "switchport mode trunk"},
	},
	"esr": {
		{nil, "reload system"}, {nil, "reload system in @10"}, {nil, "reload system with-configuration @f at @t @d"},
		{nil, "copy @tftp://192.0.2.1/a.cfg system:candidate-config"}, {nil, "copy system:default-config system:candidate-config"},
		{nil, "copy system:factory-config system:candidate-config"}, {nil, "rollback to-backup @f"}, {nil, "rollback"},
		{nil, "copy @tftp://192.0.2.1/f system:firmware"}, {nil, "copy @tftp://192.0.2.1/b system:boot-1"},
		{nil, "copy @tftp://192.0.2.1/l system:licence"}, {nil, "boot system image-2"}, {nil, "boot system inactive"},
		{nil, "clear storage-device @usb://x"}, {nil, "delete @flash:backup/x"}, {nil, "update ssh-host-key rsa"},
		{nil, "terminal mode human"},
		{cfgE, "no ip ssh server"}, {cfgE, "ip ssh port @2222"}, {cfgE, "ip ssh access-addresses @x"},
		{cfgE, "ip ssh host-key algorithm @rsa disable"}, {cfgE, "username @u"}, {cfgE, "no username @u"}, {cfgE, "no username all"},
		{cfgE, "privilege @root level @15 @show"}, {cfgE, "enable password @x"}, {cfgE, "aaa @x"},
		{cfgE, "security passwords lifetime @1"}, {cfgE, "security passwords default-expired"},
		{cfgE, "system configuration-exclusively"}, {cfgE, "line ssh"}, {cfgE, "ip firewall disable"},
		{cfgE, "security zone @trusted"}, {cfgE, "security zone-pair @a @b"}, {cfgE, "ip route @0.0.0.0/0 @192.0.2.1"},
		{cfgE, "no ip route @0.0.0.0/0"}, {cfgE, "ip telnet server"}, {cfgE, "system config-confirm timeout @1200"},
		{cfgE, "archive"}, {cfgE, "snmp-server community @x ro"}, {cfgE, "no vlan @99"},
		{ifE, "shutdown"}, {ifE, "no shutdown"}, {ifE, "description @x"}, {ifE, "ip address @192.0.2.9/24"},
		{ifE, "no ip address"}, {ifE, "ip firewall disable"}, {ifE, "security-zone @untrusted"},
		{portE, "ip address @10.0.0.1/8"}, {portE, "switchport access vlan @99"},
	},
}

/* ctrl: C0, ESC, CR/LF, DEL, C1, zero-width, bidi, line separator, BOM, NBSP, invalid UTF-8, '?'. */
var ctrl = []string{r(0), r(3), r(0x1b) + "[D", r(13), r(10), r(0x7f), r(0x85), r(0x200b), r(0x202e), r(0x2028), r(0xfeff), r(0xa0),
	string([]byte{0xc0, 0xaf}), "?"}

/* variant is a spelling of a pattern and the mode it is typed in. */
type variant struct {
	mode    []string
	line    string
	refused bool /* a forbidden character was inserted */
}

func caseFlip(s string) string {
	b := []byte(s)
	for i, c := range b {
		if i%2 == 0 && 'a' <= c && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}

/* variants: full form, abbreviations, case, spaces and tabs, quoted keyword, do (root commands from config), control characters. */
func variants(p pat, cfg string) []variant {
	ws, kw := p.words()
	join := func(f func(i int, w string) string, sep string) string {
		out := make([]string, len(ws))
		for i, w := range ws {
			out[i] = f(i, w)
		}
		return strings.Join(out, sep)
	}
	abbr := func(n int) func(int, string) string {
		return func(i int, w string) string {
			if kw[i] && len(w) > n {
				return w[:n]
			}
			return w
		}
	}
	id := func(_ int, w string) string { return w }
	vs := []variant{
		{p.mode, join(id, " "), false},
		{p.mode, join(abbr(1), " "), false},
		{p.mode, join(abbr(3), " "), false},
		{p.mode, strings.ToUpper(join(id, " ")), false},
		{p.mode, join(func(_ int, w string) string { return caseFlip(w) }, " "), false},
		{p.mode, " \t" + join(id, " \t  ") + "\t ", false},
		{p.mode, join(id, "\t"), false},
	}
	if len(p.mode) == 0 {
		vs = append(vs, variant{[]string{cfg}, "do " + join(id, " "), false}, variant{[]string{cfg}, "DO\t" + join(abbr(3), "  "), false})
	}
	full := join(id, " ")
	for _, c := range ctrl {
		vs = append(vs, variant{p.mode, c + full, true}, variant{p.mode, full + c, true})
		if i := strings.Index(full, " "); i > 0 {
			vs = append(vs, variant{p.mode, full[:i] + c + full[i:], true})
		}
	}
	return vs
}

/* C4: no spelling of a dangerous command is safe or control; a forbidden character refuses the line. */
func TestC4DangerousCommands(t *testing.T) {
	for name, f := range lines {
		g, ctx := f.d.Grammar(), f.ctx(t)
		for _, p := range dangerous[name] {
			if v := f.d.Classify(p.plain(), walk(g, p.mode...), ctx); v.Class != core.Dangerous {
				t.Errorf("%s: %q in %v = %v (%s), want dangerous", name, p.plain(), p.mode, v.Class, v.Reason)
			}
			for _, x := range variants(p, f.cfg) {
				v := f.d.Classify(x.line, walk(g, x.mode...), ctx)
				switch {
				case v.Class == core.Safe || v.Class == core.Control:
					t.Errorf("%s: %q in %v = %v (%s)", name, x.line, x.mode, v.Class, v.Reason)
				case x.refused && (v.Class != core.Denied || v.Reason != core.ReasonRefused || v.Line != ""):
					t.Errorf("%s: %q = %+v, want refused", name, x.line, v)
				}
			}
		}
	}
}

/* mgmtSpellings enter the management interface or VLAN, in every spelling the line accepts. */
var mgmtSpellings = map[string][]string{
	"mes6": {"interface gi1/0/24", "interface GigabitEthernet1/0/24", "interface gigabitethernet 1/0/24", "int g 01/00/024",
		"INT GI 1/0/024", "interface range gi1/0/20-30", "interface range gi1/0/1,gi1/0/24", "interface range gi1/0/1-2,1/0/24",
		"interface range gigabitethernet 1/0/23-24", "interface range gi1/0/1-9999", "interface vlan 99", "interface vlan 099", "int vl 99"},
	"mes10": {"interface gi0/24", "interface GigabitEthernet0/24", "interface gigabitethernet 0/24", "int g 00/024",
		"interface vlan 99", "int vlan 0099"},
	"esr": {"interface gi1/0/24", "interface GigabitEthernet1/0/24", "interface gigabitethernet 1/0/24", "int g 1/0/0024",
		"interface gi1/0/24.100", "interface gigabitethernet 1/0/24.7"},
}

/* Every spelling of the management interface or VLAN is one target: shutdown and the rest are dangerous there, not elsewhere. */
func TestManagementContextEverySpelling(t *testing.T) {
	for name, f := range lines {
		g, ctx := f.d.Grammar(), f.ctx(t)
		for _, enter := range mgmtSpellings[name] {
			m := walk(g, f.cfg, enter)
			if m.Name() == "config" {
				t.Fatalf("%s: %q did not enter an interface mode", name, enter)
			}
			reason := core.ReasonMgmt
			if m.Unsure() { /* a range over the target limit: the context is unknown, every line dangerous */
				reason = core.ReasonUnsure
			}
			for _, l := range []string{"shutdown", "no shutdown", "description x"} {
				if v := f.d.Classify(l, m, ctx); v.Class != core.Dangerous || v.Reason != reason {
					t.Errorf("%s: %q after %q = %v (%s)", name, l, enter, v.Class, v.Reason)
				}
			}
			if v := f.d.Classify(enter, walk(g, f.cfg), ctx); v.Class != core.Safe {
				t.Errorf("%s: entering %q = %v (%s): entering the mode only is safe", name, enter, v.Class, v.Reason)
			}
		}
		other := walk(g, f.cfg, "interface "+f.other)
		for _, l := range []string{"shutdown", "no shutdown", "description uplink to core", "switchport access vlan 20"} {
			if v := f.d.Classify(l, other, ctx); v.Class != core.Safe {
				t.Errorf("%s: %q on %s = %v (%s), want safe", name, l, f.other, v.Class, v.Reason)
			}
		}
	}
	/* the same canonical target for every spelling */
	want, _ := lines["mes6"].d.Targets("interface", "gi1/0/24")
	for _, s := range []string{"GigabitEthernet1/0/24", "g01/0/024", "GIGABITETHERNET1/00/24"} {
		if got, ok := lines["mes6"].d.Targets("interface", s); !ok || !slices.Equal(got, want) {
			t.Errorf("Targets(%q) = %v, want %v", s, got, want)
		}
	}
	vl, _ := lines["mes6"].d.Targets("vlan", "099")
	if !slices.Equal(vl, []core.Target{{Kind: "vlan", Name: "99"}}) {
		t.Errorf("vlan 099 = %v", vl)
	}
	sub, _ := lines["esr"].d.Targets("interface", "gi1/0/24.100")
	if !slices.Contains(sub, core.Target{Kind: "interface", Name: "gigabitethernet1/0/24"}) {
		t.Errorf("a sub-interface does not name its port: %v", sub)
	}
}

/* Names counts a range before it allocates anything for it and refuses one over the limit. */
func TestNamesCappedBeforeAllocation(t *testing.T) {
	types := []drivers.IfType{{Name: "gigabitethernet", Comps: 3}}
	rng, vl := drivers.IfRange(types), drivers.VLANs()
	big := "gi1/0/1-9999,gi1/0/1-9999,gi1/0/1-9999"
	if _, ok := rng.Names(big, core.MaxTargets); ok {
		t.Fatal("range over the limit resolved")
	}
	if _, ok := vl.Names("1-4094,1-4094", core.MaxTargets); ok {
		t.Fatal("vlan list over the limit resolved")
	}
	if a := testing.AllocsPerRun(20, func() { rng.Names(big, core.MaxTargets) }); a > 16 && !raceEnabled {
		t.Fatalf("Names allocates %v times for a refused range", a)
	}
	if ns, ok := rng.Names("gi1/0/1-3,1/0/7", 10); !ok || !slices.Equal(ns, []string{"gigabitethernet1/0/1", "gigabitethernet1/0/2", "gigabitethernet1/0/3", "gigabitethernet1/0/7"}) {
		t.Fatalf("range = %v %v", ns, ok)
	}
	for _, bad := range []string{"gi1/0/5-1", "1/0/1", "gi1/0", "gi1/0/1-", "x1/0/1", "gi1/0/1,,2"} {
		if rng.Match(bad) {
			t.Errorf("range %q matched", bad)
		}
	}
}

/* controls: every save, commit, confirm, restore and reload-cancel alias per line, and its flow. */
var controls = map[string]map[string]core.ControlKind{
	"mes6": {"write": core.Save, "write memory": core.Save, "wr": core.Save, "wr mem": core.Save, "write startup-config": core.Save,
		"copy running-config startup-config": core.Save, "copy running-config flash:startup-config": core.Save,
		"copy running-config flash://startup-config": core.Save, "copy running-config nvram:startup-config": core.Save,
		"copy running-config system:startup-config": core.Save, "copy system:running-config startup-config": core.Save,
		"COPY Running-Config Flash://Startup-Config": core.Save, "copy running-config flash:/startup-config": core.Save, "copy running-config FLASH:///Startup-Config": core.Save, "copy running-config //nvram://startup-config": core.Save, "copy flash:/running-config system:/startup-config": core.Save, "copy tftp://192.0.2.1/a.cfg startup-config": core.Save, "copy sftp://192.0.2.1/a.cfg Flash:Startup-Config": core.Save,
		"reload cancel": core.ReloadCancel},
	"mes10": {"write startup-config": core.Save, "write": core.Save, "write memory": core.Save, "wr startup": core.Save,
		"copy running-config startup-config": core.Save, "copy running-config nvram:startup-config": core.Save,
		"copy running-config flash:startup-config": core.Save, "copy flash://running-config flash://startup-config": core.Save,
		"copy running-config flash:/startup-config": core.Save, "copy running-config FLASH:///Startup-Config": core.Save, "copy running-config //nvram://startup-config": core.Save, "copy flash:/running-config system:/startup-config": core.Save, "copy tftp://192.0.2.1/a.cfg startup-config": core.Save, "copy sftp://192.0.2.1/a.cfg Flash:Startup-Config": core.Save,
		"reload cancel": core.ReloadCancel},
	"esr": {"commit": core.Commit, "commit confirm-timeout 600": core.Commit, "commit comment x": core.Commit, "commit check": core.Commit,
		"confirm": core.Confirm, "restore": core.Restore, "save": core.Save, "reload cancel": core.ReloadCancel},
}

/* Every save alias is Control: in the root, through do from a configuration mode, in any case. */
func TestEverySaveAliasIsControl(t *testing.T) {
	for name, f := range lines {
		g, ctx := f.d.Grammar(), f.ctx(t)
		for l, kind := range controls[name] {
			for _, x := range []variant{{nil, l, false}, {[]string{f.cfg}, "do " + l, false}, {[]string{f.cfg, "interface " + f.other}, "do " + strings.ToUpper(l), false}} {
				if v := f.d.Classify(x.line, walk(g, x.mode...), ctx); v.Class != core.Control || v.Control != kind {
					t.Errorf("%s: %q in %v = %v/%d (%s), want control %d", name, x.line, x.mode, v.Class, v.Control, v.Reason, kind)
				}
			}
		}
	}
	/* abbreviations the grammar cannot expand, quotes and extra words are refused as control, never sent */
	for name, ls := range map[string][]string{
		"mes6": {"copy run start", "copy r s", `"write"`, "write x", "copy running-config startup-config now", "do do write", "co ru sta",
			"co run flash:/startup-config", "copy x flash:/sta", "copy x startup-config now", "do co x nvram:/startup-config", "c x //Startup-Config", `copy running-config "startup-config"`},
		"mes10": {"wr st", "copy run start", "write startup-config now", "cop x flash:///startup-config", "copy x st", "copy flash:/ru sy", "copy x fla", "copy x NVRAM:/", "copy running-config /", "copy x nvram:startup-config y", `copy x 'flash:startup-config'`},
		"esr":   {"co", "conf", "com", "res", `"commit"`, "confirm now", "restore x"},
	} {
		g, ctx := lines[name].d.Grammar(), lines[name].ctx(t)
		for _, l := range ls {
			if v := lines[name].d.Classify(l, g.Root(), ctx); v.Class != core.Denied && v.Class != core.Control {
				t.Errorf("%s: %q = %v (%s): a control command could be sent", name, l, v.Class, v.Reason)
			}
		}
	}
}

/* Safe common configuration stays safe, so the grammar is usable (and the classes are not all dangerous by accident). */
func TestCommonConfigurationIsSafe(t *testing.T) {
	safe := map[string][]pat{
		"mes6": {{nil, "show running-config"}, {nil, "sh run | inc vlan"}, {nil, "show interfaces status gi1/0/1"},
			{cfg6, "hostname core-sw1"}, {cfg6, "logging host 192.0.2.50"}, {cfg6, "sntp server 192.0.2.51"},
			{cfg6, "snmp-server location rack 4"}, {vdb6, "vlan 20,30-35"}, {vdb6, "no vlan 20"}, {port6, "do show vlan"}},
		"mes10": {{nil, "show running-config | grep vlan"}, {cfg10, "hostname sw10"}, {cfg10, "vlan 20"}, {cfg10, "no vlan 20-30"},
			{[]string{"configure terminal", "vlan 20"}, "name users"}, {port10, "switchport access vlan 20"}},
		"esr": {{nil, "show configuration changes"}, {nil, "sh run | include ip"}, {cfgE, "hostname esr1"},
			{portE, `description "uplink to core"`}, {[]string{"configure", "vlan 20"}, "name users"}, {cfgE, "no vlan 20"}},
	}
	for name, ps := range safe {
		g, ctx := lines[name].d.Grammar(), lines[name].ctx(t)
		for _, p := range ps {
			if v := lines[name].d.Classify(p.line, walk(g, p.mode...), ctx); v.Class != core.Safe {
				t.Errorf("%s: %q in %v = %v (%s), want safe", name, p.line, p.mode, v.Class, v.Reason)
			}
		}
	}
}

func TestDriversRegisteredUnverified(t *testing.T) {
	for _, l := range strategy.Lines() {
		d, ok := drivers.For(l)
		if !ok || d.Line() != l || d.Verified() || d.Strategies().Check(l) != nil {
			t.Errorf("driver %s: registered %v, verified %v, strategies %v", l, ok, ok && d.Verified(), d.Strategies().Check(l))
		}
	}
}

/* I3: a show filter is one plain token; redirection, shell and history syntax after it is dangerous, never safe. */
func TestShowFilterIsOneToken(t *testing.T) {
	for name, kw := range map[string]string{"mes6": "include", "mes10": "grep", "esr": "include"} {
		d, ctx := lines[name].d, lines[name].ctx(t)
		if v := d.Classify("show running-config | "+kw+" vlan.*10$", d.Grammar().Root(), ctx); v.Class != core.Safe {
			t.Errorf("%s: plain filter = %v (%s)", name, v.Class, v.Reason)
		}
		for _, f := range []string{"> flash:x", ">flash:x", "<", "a < b", "`reload`", "$(reload)", "a&b", "&", "{}", "a{1}",
			"!reload", "x y", "x >> flash:y", strings.Repeat("a", 65)} {
			l := "show running-config | " + kw + " " + f
			if v := d.Classify(l, d.Grammar().Root(), ctx); v.Class == core.Safe || v.Class == core.Control {
				t.Errorf("%s: %q = %v (%s)", name, l, v.Class, v.Reason)
			}
		}
	}
}
