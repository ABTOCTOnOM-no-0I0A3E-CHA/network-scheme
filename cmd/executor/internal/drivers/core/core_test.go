package core

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/internal/execpolicy"
)

/* ifaceRe: test interface names, gi1/0/1 or a range gi1/0/1-4. */
var ifaceRe = regexp.MustCompile(`^(gi|te)([0-9]+/[0-9]+/)([0-9]+)(?:-([0-9]+))?$`)

var iface = ArgType{
	Match: func(tok string) bool { return ifaceRe.MatchString(asciiLower(tok)) },
	Kind:  "interface",
	Names: func(tok string) ([]string, bool) {
		m := ifaceRe.FindStringSubmatch(asciiLower(tok))
		lo, err := strconv.Atoi(m[3])
		hi := lo
		if err == nil && m[4] != "" {
			hi, err = strconv.Atoi(m[4])
		}
		if err != nil || hi < lo || hi-lo > 64 {
			return nil, false
		}
		var out []string
		for i := lo; i <= hi; i++ {
			out = append(out, m[1]+m[2]+strconv.Itoa(i))
		}
		return out, true
	},
}

func sub(name, parent string, cmds ...Cmd) ModeSpec {
	nav := []Cmd{{Pattern: "exit", Class: Safe, Nav: Exit}, {Pattern: "end", Class: Safe, Nav: End}}
	return ModeSpec{Name: name, Parent: parent, Do: true, Cmds: append(cmds, nav...)}
}

/* testSpec is a small MES/ESR-like grammar: exec, config (with ESR candidate commands), interface, VLAN and line modes. */
var testSpec = Spec{
	Args: map[string]ArgType{"iface": iface, "vlan": Uint(1, 4094, "vlan"), "int": Uint(0, 65535, "")},
	Modes: []ModeSpec{
		{Name: "exec", Cmds: []Cmd{
			{Pattern: "configure", Class: Safe, Enter: "config"},
			{Pattern: "configure terminal", Class: Safe, Enter: "config"},
			{Pattern: "show running-config", Class: Safe},
			{Pattern: "show version", Class: Safe},
			{Pattern: "show interfaces <iface>", Class: Safe},
			{Pattern: "clear counters", Class: Safe},
			{Pattern: "reload", Class: Dangerous},
			{Pattern: "reload in <int>", Class: Dangerous},
			{Pattern: "reload cancel", Class: Control, Control: ReloadCancel},
			{Pattern: "write", Class: Control, Control: Save},
			{Pattern: "copy running-config startup-config", Class: Control, Control: Save},
			{Pattern: "copy <word> startup-config", Class: Dangerous},
			{Pattern: "copy <word> <word>", Class: Dangerous},
		}},
		sub("config", "exec",
			Cmd{Pattern: "hostname <word>", Class: Safe},
			Cmd{Pattern: "interface <iface>", Class: Safe, Enter: "config-if"},
			Cmd{Pattern: "vlan <vlan>", Class: Safe, Enter: "config-vlan"},
			Cmd{Pattern: "no vlan <vlan>", Class: Safe},
			Cmd{Pattern: "line console", Class: Safe, Enter: "config-line"},
			Cmd{Pattern: "line ssh", Class: Safe, Enter: "config-line"},
			Cmd{Pattern: "username <word> password <word>", Class: Dangerous},
			Cmd{Pattern: "no username <word>", Class: Dangerous},
			Cmd{Pattern: "ip ssh server", Class: Safe},
			Cmd{Pattern: "no ip ssh server", Class: Dangerous},
			Cmd{Pattern: "commit", Class: Control, Control: Commit},
			Cmd{Pattern: "commit confirm-timeout <int>", Class: Control, Control: Commit},
			Cmd{Pattern: "confirm", Class: Control, Control: Confirm},
			Cmd{Pattern: "restore", Class: Control, Control: Restore},
			Cmd{Pattern: "rollback", Class: Safe},
		),
		sub("config-if", "config",
			Cmd{Pattern: "description <word...>", Class: Safe},
			Cmd{Pattern: "duplex full", Class: Safe},
			Cmd{Pattern: "shutdown", Class: Safe},
			Cmd{Pattern: "no shutdown", Class: Safe},
			Cmd{Pattern: "ip address <word> <word>", Class: Safe},
			Cmd{Pattern: "no ip address", Class: Safe},
			Cmd{Pattern: "switchport access vlan <vlan>", Class: Safe},
			Cmd{Pattern: "interface <iface>", Class: Safe, Enter: "config-if"},
		),
		sub("config-vlan", "config", Cmd{Pattern: "name <word>", Class: Safe}),
		sub("config-line", "config",
			Cmd{Pattern: "exec-timeout <int>", Class: Dangerous},
			Cmd{Pattern: "history size <int>", Class: Safe},
		),
	},
}

func testGrammar(t testing.TB) *Grammar {
	t.Helper()
	g, err := NewGrammar(testSpec)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

/* mgmtCtx: the executor reaches the device through gi1/0/24 in VLAN 10. */
func mgmtCtx(t testing.TB, g *Grammar) Context {
	t.Helper()
	a, ok1 := g.Targets("iface", "gi1/0/24")
	b, ok2 := g.Targets("vlan", "10")
	if !ok1 || !ok2 {
		t.Fatal("targets")
	}
	return Context{Mgmt: append(a, b...)}
}

/* walk feeds lines through Next from the root, as accepted by the device. */
func walk(g *Grammar, lines ...string) Mode {
	m := g.Root()
	for _, l := range lines {
		m = g.Next(l, m)
	}
	return m
}

func TestNormalize(t *testing.T) {
	g := testGrammar(t)
	cfg := walk(g, "conf t")
	for _, c := range []struct {
		m        Mode
		in, want string
	}{
		{g.Root(), "  RELOAD   ", "reload"},
		{g.Root(), "rel\tin  5", "reload in 5"},
		{g.Root(), "sh ver", "show version"},
		{g.Root(), "copy run start", "copy run start"}, /* "run" fits <word>: ambiguous, kept as typed */
		{g.Root(), "copy running-config START", "copy running-config startup-config"},
		{cfg, "HOST Core-SW1", "hostname Core-SW1"},
		{cfg, "do sh ver", "do show version"},
		{cfg, "frob  NICATE", "frob NICATE"},
		{walk(g, "conf t", "int gi1/0/1"), `desc "Uplink  to   core"  x`, `description "Uplink  to   core" x`},
		{walk(g, "conf t", "int gi1/0/1"), "desc a b  c", "description a b c"},
	} {
		got, err := g.Normalize(c.in, c.m)
		if err != nil || got != c.want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
}

func TestControlCharRefusesLine(t *testing.T) {
	g := testGrammar(t)
	cfg := walk(g, "configure terminal")
	bad := []string{"\x00", "\x01", "\x1b", "\r", "\n", "\x7f", "\u0085", "\u009b", "\u00ad", "\u200b", "\u200e", "\u202e", "\u2066", "\u2028", "\u2029", "\ufeff", "\u00a0", "\u3000", "\ufffe", "\xff", "?"}
	base := "hostname sw1"
	for _, b := range bad {
		for i := 0; i <= len(base); i++ {
			line := base[:i] + b + base[i:]
			if v := g.Classify(line, cfg, Context{}); v.Class != Denied || v.Reason != ReasonRefused || v.Line != "" {
				t.Errorf("Classify(%q) = %+v, want refused", line, v)
			}
			if _, err := g.Normalize(line, cfg); err == nil {
				t.Errorf("Normalize(%q) accepted", line)
			}
		}
	}
	if v := g.Classify(base+" \t", cfg, Context{}); v.Class != Safe {
		t.Errorf("tab as space: %+v", v)
	}
	if v := g.Classify("hostname \"a", cfg, Context{}); !errors.Is(v.Err, ErrQuote) {
		t.Errorf("unterminated quote: %+v", v)
	}
	if v := g.Classify(strings.Repeat("a", MaxLine+1), cfg, Context{}); !errors.Is(v.Err, ErrTooLong) {
		t.Errorf("long line: %+v", v)
	}
	if v := g.Classify(strings.Repeat("c ", MaxTokens+1), cfg, Context{}); !errors.Is(v.Err, ErrTooLong) {
		t.Errorf("many tokens: %+v", v)
	}
}

func TestClassify(t *testing.T) {
	g := testGrammar(t)
	ctx := mgmtCtx(t, g)
	exec, cfg := g.Root(), walk(g, "configure terminal")
	ifMgmt, ifOther := walk(g, "conf", "interface GI1/0/24"), walk(g, "conf", "int gi1/0/1")
	cases := []struct {
		name   string
		m      Mode
		line   string
		class  Class
		reason Reason
	}{
		{"empty", cfg, "   ", Safe, ReasonEmpty},
		{"show", exec, "sh run", Safe, ReasonGrammar},
		{"reload", exec, "RELOAD", Dangerous, ReasonGrammar},
		{"reload in", exec, "rel in 5", Dangerous, ReasonGrammar},
		{"copy to startup", exec, "copy tftp://x/a startup-config", Dangerous, ReasonGrammar},
		{"unknown exec", exec, "frobnicate", Dangerous, ReasonUnknown},
		{"unknown trailing", exec, "show version now", Dangerous, ReasonUnknown},
		{"ambiguous exec", exec, "c", Dangerous, ReasonAmbiguous},
		{"incomplete", exec, "show", Dangerous, ReasonIncomplete},
		{"no mode", Mode{}, "show version", Dangerous, ReasonMode},
		{"unknown config", cfg, "frobnicate", Dangerous, ReasonUnknown},
		{"unknown config 2", cfg, "ip route 0.0.0.0/0 1.2.3.4", Dangerous, ReasonUnknown},
		{"ambiguous config", cfg, "r", Dangerous, ReasonAmbiguous},
		{"abbreviated no", cfg, "no ip ssh s", Dangerous, ReasonGrammar},
		{"keyword or arg", cfg, "username a password b", Dangerous, ReasonGrammar},
		{"quoted keyword", cfg, `"hostname" x`, Dangerous, ReasonUnknown},
		{"do in exec", exec, "do show version", Dangerous, ReasonUnknown},
		{"do do", cfg, "do do reload", Dangerous, ReasonUnknown},
		{"do alone", cfg, "do", Dangerous, ReasonIncomplete},
		{"do reload", cfg, "DO RELOAD", Dangerous, ReasonGrammar},
		{"do show", ifMgmt, "do show version", Safe, ReasonGrammar},
		{"ssh off", cfg, "no ip ssh serv", Dangerous, ReasonGrammar},
		{"ssh on", cfg, "ip ssh server", Safe, ReasonGrammar},
		{"line timeout", walk(g, "conf", "line ssh"), "exec-timeout 1", Dangerous, ReasonGrammar},
		{"shutdown other", ifOther, "shutdown", Safe, ReasonGrammar},
		{"shutdown mgmt", ifMgmt, "shut", Dangerous, ReasonMgmt},
		{"no ip address mgmt", ifMgmt, "no ip addr", Dangerous, ReasonMgmt},
		{"ip address mgmt", ifMgmt, "ip address 10.0.0.9 255.255.255.0", Dangerous, ReasonMgmt},
		{"description mgmt", ifMgmt, "description x", Dangerous, ReasonMgmt},
		{"exit mgmt", ifMgmt, "exit", Safe, ReasonGrammar},
		{"enter mgmt", cfg, "interface gi1/0/24", Safe, ReasonGrammar},
		{"leave mgmt", ifMgmt, "interface gi1/0/1", Safe, ReasonGrammar},
		{"range mgmt", walk(g, "conf", "int gi1/0/20-30"), "shutdown", Dangerous, ReasonMgmt},
		{"range bad", walk(g, "conf", "int gi1/0/9-1"), "shutdown", Dangerous, ReasonUnsure},
		{"vlan mgmt", walk(g, "conf", "vlan 010"), "name x", Dangerous, ReasonMgmt},
		{"vlan other", walk(g, "conf", "vlan 20"), "name x", Safe, ReasonGrammar},
		{"no vlan mgmt", cfg, "no vlan 10", Dangerous, ReasonMgmt},
		{"no vlan other", cfg, "no vlan 20", Safe, ReasonGrammar},
		{"access vlan mgmt", ifOther, "switchport access vlan 10", Dangerous, ReasonMgmt},
		{"show mgmt", exec, "show interfaces gi1/0/24", Safe, ReasonGrammar},
		{"unsure", walk(g, "conf", "int gi1/0/1", "frobnicate"), "shutdown", Dangerous, ReasonUnsure},
		{"unsure exit", walk(g, "conf", "int gi1/0/1", "frobnicate", "exit"), "hostname x", Dangerous, ReasonUnsure},
		{"unsure end", walk(g, "conf", "int gi1/0/1", "frobnicate", "end", "conf"), "hostname x", Safe, ReasonGrammar},
		{"exec unknown accepted", walk(g, "frobnicate", "conf"), "hostname x", Safe, ReasonGrammar},
		{"esr rollback", cfg, "rollback", Safe, ReasonGrammar},
	}
	for _, c := range cases {
		if v := g.Classify(c.line, c.m, ctx); v.Class != c.class || v.Reason != c.reason {
			t.Errorf("%s: Classify(%q in %s) = %v/%s, want %v/%s", c.name, c.line, c.m.Name(), v.Class, v.Reason, c.class, c.reason)
		}
	}
}

func TestControlCommands(t *testing.T) {
	g := testGrammar(t)
	exec, cfg := g.Root(), walk(g, "configure")
	ifMgmt := walk(g, "conf", "int gi1/0/24")
	for _, c := range []struct {
		m    Mode
		line string
		kind ControlKind
		want string
	}{
		{exec, "write", Save, "write"},
		{exec, "WR", Save, "write"},
		{exec, "copy running-config startup-config", Save, "copy running-config startup-config"},
		{exec, "copy running-config STARTUP", Save, "copy running-config startup-config"},
		{exec, "reload cancel", ReloadCancel, "reload cancel"},
		{exec, "rel can", ReloadCancel, "reload cancel"},
		{cfg, "confirm", Confirm, "confirm"},
		{cfg, "commit", Commit, "commit"},
		{cfg, "comm confirm-timeout 600", Commit, "commit confirm-timeout 600"},
		{cfg, "restore", Restore, "restore"},
		{cfg, "do write", Save, "do write"},
		{cfg, "do copy running-config startup-config", Save, "do copy running-config startup-config"},
		{ifMgmt, "do wr", Save, "do write"},
	} {
		v := g.Classify(c.line, c.m, mgmtCtx(t, g))
		if v.Class != Control || v.Control != c.kind || v.Line != c.want {
			t.Errorf("Classify(%q) = %+v, want control %d %q", c.line, v, c.kind, c.want)
		}
		if n := g.Next(c.line, c.m); n.Name() != c.m.Name() || n.Unsure() {
			t.Errorf("Next(%q) moved to %s", c.line, n.Name())
		}
	}
	/* Not control: a copy from elsewhere into startup, a reload, a commit with a stray word. */
	for _, line := range []string{"copy tftp://h/f startup-config", "copy run startup-config", "reload", "reload cancel now"} {
		if v := g.Classify(line, exec, Context{}); v.Class != Dangerous {
			t.Errorf("Classify(%q) = %+v, want dangerous", line, v)
		}
	}
}

func TestPolicyRules(t *testing.T) {
	g := testGrammar(t)
	exec, cfg := g.Root(), walk(g, "conf")
	r, err := NewRules("mes6", []execpolicy.ClassOverride{
		{Driver: "any", Command: "reload", Class: "denied"},
		{Driver: "mes6", Command: "clear counters", Class: "dangerous"},
		{Driver: "esr", Command: "show version", Class: "denied"},
		{Driver: "any", Command: "hostname", Class: "dangerous"},
		{Driver: "mes6", Command: "hostname core1", Class: "safe"},
		{Driver: "any", Command: "no username", Class: "safe"},
		{Driver: "any", Command: "frobnicate", Class: "safe"},
		{Driver: "any", Command: "write", Class: "denied"},
		{Driver: "any", Command: "copy", Class: "denied"},
		{Driver: "any", Command: "copy x y", Class: "safe"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := Context{Rules: r}
	for _, c := range []struct {
		m     Mode
		line  string
		class Class
	}{
		{exec, "rel", Denied},
		{exec, "reload in 5", Denied},
		{cfg, "do reload", Denied},
		{exec, "RE", Denied},
		{exec, `"reload"`, Denied},
		{exec, `'rel' in 5`, Denied},
		{walk(g, "conf", "int gi1/0/1"), "d reload", Denied}, /* "d": description, do, duplex */
		{exec, `""`, Dangerous},
		{exec, "clear counters", Dangerous},
		{exec, "show version", Safe}, /* esr only */
		{cfg, "hostname x", Dangerous},
		{cfg, "hostname core1", Safe},
		{cfg, "hostname core1x", Dangerous},
		{cfg, "no username bob", Dangerous}, /* safe never relaxes the grammar */
		{cfg, "frobnicate", Dangerous},      /* nor an unknown line */
		{exec, "write", Control},            /* control lines are UI flows */
		{exec, "copy x y", Dangerous},       /* the carve-out goes back to the grammar's class */
		{exec, "copy x z", Denied},
	} {
		if v := g.Classify(c.line, c.m, ctx); v.Class != c.class {
			t.Errorf("Classify(%q) = %+v, want %v", c.line, v, c.class)
		}
	}
	if _, err := NewRules("mes6", []execpolicy.ClassOverride{{Driver: "any", Command: "x", Class: "control"}}); err == nil {
		t.Error("NewRules accepted a bad class")
	}
}

func TestNext(t *testing.T) {
	g := testGrammar(t)
	for _, c := range []struct {
		lines []string
		want  string
	}{
		{[]string{"conf t"}, "config"},
		{[]string{"conf", "int gi1/0/1"}, "config-if"},
		{[]string{"conf", "int gi1/0/1", "int gi1/0/2"}, "config-if"},
		{[]string{"conf", "int gi1/0/1", "exit"}, "config"},
		{[]string{"conf", "int gi1/0/1", "end"}, "exec"},
		{[]string{"conf", "int gi1/0/1", "do show version"}, "config-if"},
		{[]string{"conf", "vlan 5", "exit", "line ssh"}, "config-line"},
		{[]string{"exit"}, "exec"},
	} {
		if m := walk(g, c.lines...); m.Name() != c.want || m.Unsure() {
			t.Errorf("%q -> %s (unsure %v), want %s", c.lines, m.Name(), m.Unsure(), c.want)
		}
	}
	/* Switching from the management interface to another drops its context. */
	ctx := mgmtCtx(t, g)
	m := walk(g, "conf", "int gi1/0/24", "int gi1/0/1")
	if v := g.Classify("shutdown", m, ctx); v.Class != Safe {
		t.Errorf("after switching: %+v", v)
	}
	/* The prompt disagrees: unsure until the root. */
	m = g.Reconcile(walk(g, "conf"), "config-if")
	if !m.Unsure() || g.Classify("shutdown", m, ctx).Class != Dangerous {
		t.Error("Reconcile mismatch is not unsure")
	}
	if m = g.Reconcile(m, "exec"); m.Unsure() || m.Name() != "exec" {
		t.Error("Reconcile to root")
	}
	if m = walk(g, "conf"); g.Reconcile(m, "config").Unsure() {
		t.Error("Reconcile match")
	}
}

func TestComplete(t *testing.T) {
	g := testGrammar(t)
	exec, cfg := g.Root(), walk(g, "conf")
	ifm := walk(g, "conf", "int gi1/0/1")
	for _, c := range []struct {
		m      Mode
		prefix string
		want   []string
	}{
		{exec, "", []string{"clear", "configure", "copy", "reload", "show", "write"}},
		{exec, "co", []string{"configure", "copy"}},
		{exec, "SH", []string{"show"}},
		{exec, "sh ", []string{"interfaces", "running-config", "version"}},
		{exec, "copy ", []string{"<word>", "running-config"}},
		{exec, "copy running-config ", []string{"startup-config"}},
		{exec, "rel\t", []string{"cancel", "in"}},
		{cfg, "do sh", []string{"show"}},
		{cfg, "d", []string{"do"}},
		{ifm, "d", []string{"description", "do", "duplex"}},
		{ifm, "description ", []string{"<word...>"}},
		{ifm, "description secret-from-device ", nil},
		{ifm, "ip address 10.0.0.1", []string{"<word>"}},
		{exec, "frob ", nil},
		{exec, "x\x1b", nil},
		{Mode{}, "", nil},
	} {
		if got := g.Complete(c.prefix, c.m); !slices.Equal(got, c.want) {
			t.Errorf("Complete(%q) = %q, want %q", c.prefix, got, c.want)
		}
	}
}

/* TestCompleteOnlyGrammarWords: whatever the prefix, every word is a keyword or a placeholder of the grammar. */
func TestCompleteOnlyGrammarWords(t *testing.T) {
	g := testGrammar(t)
	words := grammarWords(g)
	modes := testModes(g)
	for _, prefix := range []string{"", "s", "show ", "conf", "interface ", "interface gi1/0/1 ", "hostname evil", "do ", "do sh ", "description x", `"q`, "no ", "no vlan 10 ", "username bob "} {
		for _, m := range modes {
			got := g.Complete(prefix, m)
			if len(got) > MaxComplete {
				t.Errorf("Complete(%q) returned %d words", prefix, len(got))
			}
			for _, w := range got {
				if !words[w] {
					t.Errorf("Complete(%q in %s) = %q: not a grammar word", prefix, m.Name(), w)
				}
			}
		}
	}
}

func TestNewGrammarRejects(t *testing.T) {
	base := func(cmds ...Cmd) Spec {
		return Spec{Modes: []ModeSpec{{Name: "exec", Cmds: cmds}, {Name: "config", Parent: "exec", Do: true}}}
	}
	for i, s := range []Spec{
		{},
		base(Cmd{Pattern: "reload", Class: Denied}),
		base(Cmd{Pattern: "reload"}),
		base(Cmd{Pattern: "write", Class: Control}),
		base(Cmd{Pattern: "write", Class: Safe, Control: Save}),
		base(Cmd{Pattern: "exit", Class: Dangerous, Nav: Exit}),
		base(Cmd{Pattern: "x", Class: Safe, Enter: "nowhere"}),
		base(Cmd{Pattern: "x", Class: Safe, Enter: "exec"}),
		base(Cmd{Pattern: "Reload", Class: Safe}),
		base(Cmd{Pattern: "a <nosuch>", Class: Safe}),
		base(Cmd{Pattern: "a <word...> b", Class: Safe}),
		base(Cmd{Pattern: "a", Class: Safe}, Cmd{Pattern: "a", Class: Dangerous}),
		base(Cmd{Pattern: " ", Class: Safe}),
		{Modes: []ModeSpec{{Name: "exec", Do: true}}},
		{Modes: []ModeSpec{{Name: "exec"}, {Name: "config"}}},
		{Modes: []ModeSpec{{Name: "exec"}, {Name: "config", Parent: "nowhere"}}},
		{Modes: []ModeSpec{{Name: "exec"}, {Name: "config", Parent: "exec", Do: true, Cmds: []Cmd{{Pattern: "do x", Class: Safe}}}}},
		{Args: map[string]ArgType{"Bad": Word}, Modes: []ModeSpec{{Name: "exec"}}},
		{Args: map[string]ArgType{"x": {}}, Modes: []ModeSpec{{Name: "exec"}}},
	} {
		if _, err := NewGrammar(s); err == nil {
			t.Errorf("spec %d accepted", i)
		}
	}
}

/* grammarWords is every keyword and argument placeholder of g. */
func grammarWords(g *Grammar) map[string]bool {
	words := map[string]bool{}
	var visit func(n *node)
	visit = func(n *node) {
		for k, nx := range n.kw {
			words[k] = true
			visit(nx)
		}
		for _, e := range n.args {
			words["<"+e.typ+">"], words["<"+e.typ+"...>"] = true, true
			visit(e.next)
		}
	}
	for _, md := range g.modes {
		visit(md.top)
	}
	return words
}

/* testModes is one Mode per grammar mode, plus the management contexts and an unsure one. */
func testModes(g *Grammar) []Mode {
	return []Mode{
		g.Root(), walk(g, "conf"), walk(g, "conf", "int gi1/0/1"), walk(g, "conf", "int gi1/0/24"),
		walk(g, "conf", "vlan 10"), walk(g, "conf", "line ssh"), walk(g, "conf", "int gi1/0/1", "zz"), {},
	}
}

func ExampleGrammar_Classify() {
	g, _ := NewGrammar(testSpec)
	m := g.Next("configure terminal", g.Root())
	v := g.Classify("do RELOAD", m, Context{})
	fmt.Println(v.Class, v.Line)
	// Output: dangerous do reload
}
