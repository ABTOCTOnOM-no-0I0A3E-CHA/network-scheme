package core

import (
	"errors"
	"testing"

	"github.com/beekamai/network-scheme/internal/execpolicy"
)

/* r makes a string of runes: no escapes in the source for the editors to mangle. */
func r(rs ...rune) string { return string(rs) }

/* I1: metacharacters, stray quotes and non-ASCII outside a Text argument refuse the line. */
func TestImpureTokensRefused(t *testing.T) {
	g := testGrammar(t)
	ctx := mgmtCtx(t, g)
	cfg, ifo := walk(g, "conf"), walk(g, "conf", "int gi1/0/1")
	for _, c := range []struct {
		m    Mode
		line string
	}{
		{cfg, "hostname a;reload"},
		{cfg, "hostname a|reload"},
		{cfg, `hostname a\`},
		{cfg, "hostname it's"},
		{cfg, "hostname " + r(0x45b)},
		{cfg, "hostname a" + r(0x430)}, /* Cyrillic a */
		{ifo, "description x ; reload"},
		{ifo, "description x;reload"},
		{ifo, `description "x;y"`},
		{ifo, `description "it's"`},
		{ifo, `description "a"b`},
		{cfg, "frobnicate a;b"},
		{cfg, `"hostname";x`},
		{g.Root(), "show running-config |include x"},
		{g.Root(), "show running-config | include a|b"},
		{Mode{}, "x;y"},
	} {
		v := g.Classify(c.line, c.m, ctx)
		if v.Class != Denied || v.Reason != ReasonRefused || !errors.Is(v.Err, ErrImpure) || v.Line != "" {
			t.Errorf("Classify(%q) = %+v, want refused as impure", c.line, v)
		}
		if _, err := g.Normalize(c.line, c.m); !errors.Is(err, ErrImpure) {
			t.Errorf("Normalize(%q) = %v", c.line, err)
		}
	}
	/* The pipe is a keyword; a Text argument opts back in. */
	for _, c := range []struct {
		m          Mode
		line, want string
	}{
		{g.Root(), "sh run | inc Gi1", "show running-config | include Gi1"},
		{cfg, "banner " + r(0x41f, 0x440, 0x438) + "; a|b\\c it's", "banner " + r(0x41f, 0x440, 0x438) + "; a|b\\c it's"},
		{ifo, `description "a b"`, `description "a b"`},
	} {
		if v := g.Classify(c.line, c.m, ctx); v.Class != Safe || v.Line != c.want {
			t.Errorf("Classify(%q) = %+v, want safe %q", c.line, v, c.want)
		}
	}
}

/* M1: a tab inside quotes refuses the line; outside it is a space. */
func TestTabInQuotes(t *testing.T) {
	g := testGrammar(t)
	ifo := walk(g, "conf", "int gi1/0/1")
	tab := r(9)
	if v := g.Classify(`description "a`+tab+`b"`, ifo, Context{}); !errors.Is(v.Err, ErrQuote) {
		t.Errorf("tab in quotes: %+v", v)
	}
	if v := g.Classify("description"+tab+"a"+tab+tab+"b", ifo, Context{}); v.Class != Safe || v.Line != "description a b" {
		t.Errorf("tabs outside quotes: %+v", v)
	}
}

/* I2: do after do, abbreviated or quoted, refuses the line. */
func TestNestedDoRefused(t *testing.T) {
	g := testGrammar(t)
	for _, m := range []Mode{g.Root(), walk(g, "conf"), walk(g, "conf", "int gi1/0/1")} {
		for _, line := range []string{"do do reload", "do d reload", "d do reload", `do "do" reload`, `DO 'D' reload`, "d d", `"do" do show version`} {
			if v := g.Classify(line, m, Context{}); v.Class != Denied || !errors.Is(v.Err, ErrNestedDo) {
				t.Errorf("Classify(%q in %s) = %+v, want refused", line, m.Name(), v)
			}
		}
	}
}

/* I3: rule commands are spelled out by the grammar; ambiguous or unknown ones refuse the policy. */
func TestRulesNormalizedByGrammar(t *testing.T) {
	g := testGrammar(t)
	exec, cfg := g.Root(), walk(g, "conf")
	rules := func(os ...execpolicy.ClassOverride) Context {
		t.Helper()
		rs, err := NewRules(g, "mes10", os)
		if err != nil {
			t.Fatal(err)
		}
		return Context{Rules: rs}
	}
	deny := func(cmd string) execpolicy.ClassOverride {
		return execpolicy.ClassOverride{Driver: "any", Command: cmd, Class: "denied"}
	}
	for _, c := range []struct {
		ctx   Context
		m     Mode
		line  string
		class Class
	}{
		{rules(deny("rel")), exec, "reload", Denied},
		{rules(deny("rel")), exec, "reload in 5", Denied},
		{rules(deny("conf t")), exec, "configure terminal", Denied},
		{rules(deny("conf t")), exec, "conf t", Denied},
		{rules(deny("conf t")), exec, "configure", Safe},
		{rules(deny("copy"), execpolicy.ClassOverride{Driver: "any", Command: "copy x y", Class: "safe"}), exec, "copy X Y", Denied},
		{rules(deny("copy"), execpolicy.ClassOverride{Driver: "any", Command: "copy x y", Class: "safe"}), exec, `copy "x" y`, Denied},
		{rules(deny("copy"), execpolicy.ClassOverride{Driver: "any", Command: "copy x y", Class: "safe"}), exec, "copy x y", Dangerous},
		{rules(deny("reload")), cfg, `"do" reload`, Denied},
		{rules(deny("reload")), cfg, `do "reload"`, Denied},
		{rules(deny("hostname core1")), cfg, "hostname CORE1", Denied},
		{rules(deny("hostname core1")), cfg, "hostname core10", Safe},
		{rules(deny("write")), exec, "write memory", Denied},
		{rules(deny("write")), exec, "write", Control}, /* M6: the Save flow is mandatory */
		{rules(deny("do reload")), cfg, "do rel", Denied},
	} {
		if v := g.Classify(c.line, c.m, c.ctx); v.Class != c.class {
			t.Errorf("Classify(%q) = %+v, want %v", c.line, v, c.class)
		}
	}
	for _, cmd := range []string{"frobnicate", "i", "c", "show frob", "copy run"} {
		if _, err := NewRules(g, "mes10", []execpolicy.ClassOverride{deny(cmd)}); err == nil {
			t.Errorf("NewRules accepted %q", cmd)
		}
	}
	/* Another line's overrides are not read (they need not fit this grammar). */
	if _, err := NewRules(g, "mes10", []execpolicy.ClassOverride{{Driver: "esr", Command: "frobnicate", Class: "denied"}}); err != nil {
		t.Error(err)
	}
}

/* I4: what the device may read as a session-control command is Denied, never sent. */
func TestControlShadowsDenied(t *testing.T) {
	g := testGrammar(t)
	exec, cfg := g.Root(), walk(g, "conf")
	for _, c := range []struct {
		m    Mode
		line string
	}{
		{exec, "copy run start"},
		{exec, "copy run startup-config"},
		{exec, "write memory"},
		{exec, "wr mem"},
		{exec, `copy "running-config" startup-config`},
		{exec, `copy 'running-config' "startup-config"`},
		{exec, "reload cancel now"},
		{exec, `"write"`},
		{exec, "do write"},
		{exec, "restore"},
		{cfg, "commit 600"},
		{cfg, "confirm x"},
		{cfg, "restore now"},
		{cfg, "do wr mem"},
		{cfg, "do commit"},
		{cfg, "c"},
		{walk(g, "conf", "int gi1/0/24"), "do copy run start"},
	} {
		if v := g.Classify(c.line, c.m, Context{}); v.Class != Denied || v.Reason != ReasonControl {
			t.Errorf("Classify(%q in %s) = %+v, want denied: use the Save/Commit button", c.line, c.m.Name(), v)
		}
	}
	/* Not shadows: other copies and reloads stay dangerous. */
	for _, line := range []string{"copy tftp://h/f startup-config", "copy flash:a flash:b", "reload in 5", "reload"} {
		if v := g.Classify(line, exec, Context{}); v.Class != Dangerous {
			t.Errorf("Classify(%q) = %+v, want dangerous", line, v)
		}
	}
}

/* I5: mode drift. */
func TestModeDrift(t *testing.T) {
	g := testGrammar(t)
	ctx := mgmtCtx(t, g)
	/* An unknown line that may have entered a device mode: exit does not clear it. */
	m := walk(g, "conf", "interface range gi1/0/24")
	if !m.Unsure() {
		t.Fatal("unknown line is not unsure")
	}
	if g.Classify("hostname x", m, ctx).Reason != ReasonUnsure {
		t.Error("unsure config line not dangerous")
	}
	/* The grammar pushed no frame, the device may have: exit lands at the root by the grammar, still unsure. */
	m = g.Next("exit", m)
	if !m.Unsure() || m.Name() != "exec" || g.Classify("configure", m, ctx).Reason != ReasonUnsure {
		t.Errorf("exit cleared unsure: %s %v", m.Name(), m.Unsure())
	}
	if m = g.Reconcile(m, "exec"); m.Unsure() {
		t.Error("root prompt did not clear unsure")
	}
	if m = g.Reconcile(walk(g, "conf", "frob"), "config"); !m.Unsure() {
		t.Error("matching non-root prompt cleared unsure")
	}
	/* The root too. */
	if m = walk(g, "frobnicate"); !m.Unsure() || g.Classify("configure", m, ctx).Class != Dangerous {
		t.Error("unknown root line is not unsure")
	}
	/* End clears it. */
	if m = walk(g, "conf", "int gi1/0/1", "frob", "end"); m.Unsure() || m.Name() != "exec" {
		t.Error("end did not clear unsure")
	}
	/* do of a mode change: dangerous, and the session no longer knows its mode. */
	ifo := walk(g, "conf", "int gi1/0/1")
	if v := g.Classify("do configure", ifo, ctx); v.Class != Dangerous || v.Reason != ReasonDoMode {
		t.Errorf("do configure: %+v", v)
	}
	if v := g.Classify("do conf t", walk(g, "conf"), ctx); v.Class != Dangerous || v.Reason != ReasonDoMode {
		t.Errorf("do conf t: %+v", v)
	}
	if m = g.Next("do configure", ifo); !m.Unsure() {
		t.Error("do configure did not make the session unsure")
	}
	if m = g.Next("do show version", ifo); m.Unsure() || m.Name() != "config-if" {
		t.Error("do show changed the mode")
	}
	if m = g.Next("do configure", walk(g, "conf", "int gi1/0/24")); g.Classify("description x", m, ctx).Class != Dangerous {
		t.Error("after do configure on the management interface")
	}
}

/* M3: Names gets its cap; a type that ignores it still cannot exceed MaxTargets. */
func TestNamesCap(t *testing.T) {
	g := testGrammar(t)
	if ts, ok := g.Targets("iface", "gi1/0/1-4"); !ok || len(ts) != 4 {
		t.Errorf("range: %v %v", ts, ok)
	}
	greedy := ArgType{Match: func(string) bool { return true }, Kind: "interface", Names: func(string, int) ([]string, bool) {
		return make([]string, MaxTargets+1), true
	}}
	if _, ok := targets([]hit{{greedy, "x"}}); ok {
		t.Error("over MaxTargets accepted")
	}
	var got int
	capped := ArgType{Match: func(string) bool { return true }, Kind: "vlan", Names: func(_ string, limit int) ([]string, bool) {
		got = limit
		return nil, false
	}}
	if _, ok := targets([]hit{{capped, "x"}}); ok || got != MaxTargets {
		t.Errorf("max passed %d", got)
	}
}
