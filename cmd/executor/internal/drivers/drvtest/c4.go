package drvtest

import "strings"

/* Pat is a line typed after the mode lines; words with a leading '@' are arguments (kept as typed). */
type Pat struct {
	Mode []string
	Line string
}

/* Words are the pattern's words, and which of them are keywords. */
func (p Pat) Words() (ws []string, kw []bool) {
	for _, w := range strings.Fields(p.Line) {
		a, isArg := strings.CutPrefix(w, "@")
		ws, kw = append(ws, a), append(kw, !isArg)
	}
	return ws, kw
}

/* Plain is the pattern as typed in full. */
func (p Pat) Plain() string { ws, _ := p.Words(); return strings.Join(ws, " ") }

func r(rs ...rune) string { return string(rs) }

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

/* Dangerous is the C4 table: every dangerous command of security.md 5.3 and [R §6] per line, in its mode. */
var Dangerous = map[string][]Pat{
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

/* Ctrl are the characters that refuse a line: C0, ESC, CR/LF, DEL, C1, zero-width, bidi, line separator, BOM, NBSP, invalid UTF-8, '?'. */
var Ctrl = []string{r(0), r(3), r(0x1b) + "[D", r(13), r(10), r(0x7f), r(0x85), r(0x200b), r(0x202e), r(0x2028), r(0xfeff), r(0xa0),
	string([]byte{0xc0, 0xaf}), "?"}

/* Variant is a spelling of a pattern and the mode it is typed in. */
type Variant struct {
	Mode    []string
	Line    string
	Refused bool /* a forbidden character was inserted */
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

/* Variants are the spellings of a pattern: full form, abbreviations, case, spaces and tabs, quoted keyword, do (root commands from config), control characters. */
func Variants(p Pat, cfg string) []Variant {
	ws, kw := p.Words()
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
	vs := []Variant{
		{p.Mode, join(id, " "), false},
		{p.Mode, join(abbr(1), " "), false},
		{p.Mode, join(abbr(3), " "), false},
		{p.Mode, strings.ToUpper(join(id, " ")), false},
		{p.Mode, join(func(_ int, w string) string { return caseFlip(w) }, " "), false},
		{p.Mode, " \t" + join(id, " \t  ") + "\t ", false},
		{p.Mode, join(id, "\t"), false},
	}
	if len(p.Mode) == 0 {
		vs = append(vs, Variant{[]string{cfg}, "do " + join(id, " "), false}, Variant{[]string{cfg}, "DO\t" + join(abbr(3), "  "), false})
	}
	full := join(id, " ")
	for _, c := range Ctrl {
		vs = append(vs, Variant{p.Mode, c + full, true}, Variant{p.Mode, full + c, true})
		if i := strings.Index(full, " "); i > 0 {
			vs = append(vs, Variant{p.Mode, full[:i] + c + full[i:], true})
		}
	}
	return vs
}
