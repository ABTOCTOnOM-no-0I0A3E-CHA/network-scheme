package core

import (
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/internal/execpolicy"
)

/* pattern is a line of the test grammar: lines walked to its mode, its tokens, which tokens are keywords. */
type pattern struct {
	mode []string
	toks []string
	kw   []bool
}

func pat(mode []string, line string, args ...int) pattern {
	toks := strings.Fields(line)
	kw := make([]bool, len(toks))
	for i := range kw {
		kw[i] = true
	}
	for _, a := range args {
		kw[a] = false
	}
	return pattern{mode, toks, kw}
}

var (
	cfgM    = []string{"configure terminal"}
	ifMgmtM = []string{"configure terminal", "interface gi1/0/24"}
	vlMgmtM = []string{"configure terminal", "vlan 10"}
)

/* dangerous is every dangerous pattern of the test grammar (argument positions after the line). */
var dangerous = []pattern{
	pat(nil, "reload"),
	pat(nil, "reload in 5", 2),
	pat(nil, "copy tftp://h/f startup-config", 1),
	pat(nil, "copy flash:a flash:b", 1, 2),
	pat(nil, "frobnicate now", 0, 1),
	pat(cfgM, "username bob password secret", 1, 3),
	pat(cfgM, "no username bob", 2),
	pat(cfgM, "no ip ssh server"),
	pat(cfgM, "no vlan 10", 2),
	pat(cfgM, "frobnicate", 0),
	pat(cfgM, "ip route 0.0.0.0/0 10.0.0.1", 2, 3),
	pat([]string{"configure terminal", "line ssh"}, "exec-timeout 1", 1),
	pat(ifMgmtM, "shutdown"),
	pat(ifMgmtM, "no shutdown"),
	pat(ifMgmtM, "no ip address"),
	pat(ifMgmtM, "ip address 10.0.0.9 255.255.255.0", 2, 3),
	pat(ifMgmtM, "description x", 1),
	pat(ifMgmtM, "switchport access vlan 20", 3),
	pat([]string{"configure terminal", "interface gi1/0/1"}, "switchport access vlan 10", 3),
	pat(vlMgmtM, "name x", 1),
}

/* controls is every session-control command of the test grammar. */
var controls = []pattern{
	pat(nil, "write"),
	pat(nil, "copy running-config startup-config"),
	pat(nil, "reload cancel"),
	pat(cfgM, "commit"),
	pat(cfgM, "commit confirm-timeout 600", 2),
	pat(cfgM, "confirm"),
	pat(cfgM, "restore"),
}

/* fuzzBytes hands out the fuzzer's bytes as mutation choices (zero once used up). */
type fuzzBytes []byte

func (b *fuzzBytes) next() byte {
	if len(*b) == 0 {
		return 0
	}
	c := (*b)[0]
	*b = (*b)[1:]
	return c
}

func (b *fuzzBytes) pick(n int) int { return int(b.next()) % n }

var (
	tab    = r(9)
	spaces = []string{" ", "  ", tab, " " + tab + " ", tab + tab}
	/* ctrl: C0, ESC sequences, CR/LF, DEL, C1, soft hyphen, zero-width, bidi, line separator, BOM, NBSP, invalid UTF-8, '?'. */
	ctrl = []string{r(0), r(3), r(8), r(0x15), r(0x1b), r(0x1b) + "[D", r(13), r(10), r(0x7f), r(0x85), r(0x9b),
		r(0xad), r(0x200b), r(0x200d), r(0x202e), r(0x2066), r(0x2028), r(0xfeff), r(0xa0), string([]byte{0xc0, 0xaf}), "?"}
	/* meta: refused outside a Text argument wherever they land. */
	meta   = []string{";", "|", `\`, r(0x430), r(0x45b), r(0x41a), r(0xe9)}
	quotes = []string{`"`, `'`}
	dos    = []string{"do", "DO", "d", `"do"`, `'Do'`, "do do", "do d", "d do", `do "do"`}
)

/* insert kinds a mutation may add. */
const (
	insNone = iota
	insCtrl
	insMeta
	insQuote
)

/*
mutate builds a variant of p: `do` (nested too), abbreviated and quoted
keywords, case, spaces and tabs, an extra word (with extra), an inserted
character. Without doAny a single `do` is added only to root-mode patterns:
elsewhere it would make another command ("do re" is reload, not restore).
*/
func mutate(p pattern, b *fuzzBytes, extra, doAny bool) (string, int) {
	var toks []string
	if c := b.next(); c%3 == 0 && (doAny || len(p.mode) == 0) {
		toks = append(toks, dos[b.pick(len(dos))])
	} else if c%3 == 1 && !doAny {
		toks = append(toks, dos[5+b.pick(len(dos)-5)]) /* nested: refused */
	}
	for i, t := range p.toks {
		if p.kw[i] {
			if n := b.pick(len(t) + 2); n >= 1 && n < len(t) {
				t = t[:n] /* a prefix: unique, ambiguous or the whole word */
			}
			if b.next()%8 == 0 {
				q := quotes[b.pick(2)]
				t = q + t + q
			}
		}
		if c := b.next(); c%2 == 1 {
			rb := []byte(t)
			for j := range rb {
				if c>>(1+j%7)&1 == 1 && 'a' <= rb[j] && rb[j] <= 'z' {
					rb[j] -= 'a' - 'A'
				}
			}
			t = string(rb)
		}
		toks = append(toks, t)
	}
	if extra && b.next()%3 == 0 {
		toks = append(toks, []string{"x", "memory", "600", "now"}[b.pick(4)])
	}
	var s strings.Builder
	s.WriteString(spaces[b.pick(len(spaces))][:b.pick(2)])
	for i, t := range toks {
		if i > 0 {
			s.WriteString(spaces[b.pick(len(spaces))])
		}
		s.WriteString(t)
	}
	s.WriteString(spaces[b.pick(len(spaces))][:b.pick(2)])
	line := s.String()
	kind := insNone
	var ins string
	switch b.next() % 8 {
	case 0, 1:
		kind, ins = insCtrl, ctrl[b.pick(len(ctrl))]
	case 2:
		kind, ins = insMeta, meta[b.pick(len(meta))]
	case 3:
		kind, ins = insQuote, quotes[b.pick(2)]
	default:
		return line, insNone
	}
	at := b.pick(len(line) + 1)
	return line[:at] + ins + line[at:], kind
}

/* FuzzClassify: no mutation of a dangerous line is ever safe, and none of a line the policy denies is less than denied. */
func FuzzClassify(f *testing.F) {
	g := testGrammar(f)
	ctx := mgmtCtx(f, g)
	deny := ctx
	var err error
	if deny.Rules, err = NewRules(g, "esr", []execpolicy.ClassOverride{{Driver: "any", Command: "reload", Class: "denied"}}); err != nil {
		f.Fatal(err)
	}
	for i := range dangerous {
		f.Add(uint8(i), []byte{})
		f.Add(uint8(i), []byte{0, 1, 2, 255, 3, 4, 0, 1, 1, 5, 0, 7})
		f.Add(uint8(i), []byte{0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3})
	}
	f.Fuzz(func(t *testing.T, which uint8, choices []byte) {
		p := dangerous[int(which)%len(dangerous)]
		b := fuzzBytes(choices)
		line, ins := mutate(p, &b, false, true)
		m := walk(g, p.mode...)
		v := g.Classify(line, m, ctx)
		switch {
		case v.Class == Safe || v.Class == Control:
			t.Fatalf("Classify(%q in %s) = %v (%s)", line, m.Name(), v.Class, v.Reason)
		case (ins == insCtrl || ins == insMeta) && (v.Class != Denied || v.Reason != ReasonRefused || v.Line != ""):
			t.Fatalf("Classify(%q) = %+v with an inserted forbidden character", line, v)
		}
		if p.toks[0] == "reload" {
			if v := g.Classify(line, m, deny); v.Class != Denied {
				t.Fatalf("Classify(%q) with reload denied = %+v", line, v)
			}
		}
	})
}

/* FuzzControl: a session-control command, however typed, is Control or Denied: never sent. */
func FuzzControl(f *testing.F) {
	g := testGrammar(f)
	ctx := mgmtCtx(f, g)
	for i := range controls {
		f.Add(uint8(i), []byte{})
		f.Add(uint8(i), []byte{0, 1, 2, 255, 3, 4, 0, 1, 1, 5, 0, 7, 0})
	}
	f.Fuzz(func(t *testing.T, which uint8, choices []byte) {
		p := controls[int(which)%len(controls)]
		b := fuzzBytes(choices)
		line, _ := mutate(p, &b, true, false)
		m := walk(g, p.mode...)
		if v := g.Classify(line, m, ctx); v.Class != Control && v.Class != Denied {
			t.Fatalf("Classify(%q in %s) = %+v: a control command would be sent", line, m.Name(), v)
		}
	})
}

/* ruleVocab is what a random policy may override (a few of them refused by NewRules). */
var ruleVocab = []string{
	"reload", "rel", "reload in", "copy", "copy x y", "copy running-config", "conf t", "configure", "hostname",
	"hostname core1", "no", "no vlan", "no vlan 10", "interface", "show", "show version", "clear counters", "username",
	"no ip ssh server", "ip ssh", "description", "shutdown", "no shutdown", "exec-timeout", "do reload", "write",
	"commit", "i", "frobnicate", "vlan", "name", "ip address",
}

/* FuzzRules: with any policy NewRules accepts, a line is at least as strict as the grammar's class, Control stays Control, and a denied prefix stays denied unless a longer safe rule carves the line out. */
func FuzzRules(f *testing.F) {
	g := testGrammar(f)
	ctx := mgmtCtx(f, g)
	modes := testModes(g)
	for _, s := range []string{"reload", "rel in 5", "copy x y", "copy X Y", "do reload", `"do" rel`, "hostname core1", "conf t", "no vlan 10", "write", "description x"} {
		f.Add([]byte{0, 2, 1, 0, 4, 2}, s, uint8(0))
		f.Add([]byte{3, 1, 8, 2, 9, 0}, s, uint8(1))
	}
	classes := []string{execpolicy.ClassSafe, execpolicy.ClassDangerous, execpolicy.ClassDenied}
	f.Fuzz(func(t *testing.T, spec []byte, line string, which uint8) {
		var os []execpolicy.ClassOverride
		for i := 0; i+1 < len(spec) && len(os) < 8; i += 2 {
			os = append(os, execpolicy.ClassOverride{Driver: "any", Command: ruleVocab[int(spec[i])%len(ruleVocab)], Class: classes[int(spec[i+1])%3]})
		}
		rs, err := NewRules(g, "mes6", os)
		if err != nil {
			return
		}
		m := modes[int(which)%len(modes)]
		v0 := g.Classify(line, m, ctx)
		pc := ctx
		pc.Rules = rs
		v := g.Classify(line, m, pc)
		switch {
		case v0.Class == Control:
			if v.Class != Control {
				t.Fatalf("Classify(%q) = %v with a policy, control without", line, v.Class)
			}
			return
		case v.Class < v0.Class:
			t.Fatalf("Classify(%q) = %v with a policy, %v without", line, v.Class, v0.Class)
		case v0.Reason == ReasonRefused || v0.Class == Safe && v0.Reason == ReasonEmpty:
			return
		}
		toks, _ := tokenize(v.Line)
		cands := [][]string{toks}
		if len(toks) > 1 && doLike(toks[0]) {
			cands = append(cands, toks[1:])
		}
		for _, ws := range cands {
			denied, carved := 0, 0
			for _, ru := range rs.rules {
				if len(ru.words) > len(ws) || !ru.covers(ws) {
					continue
				}
				switch ru.class {
				case Denied:
					denied = max(denied, len(ru.words))
				case Safe:
					carved = max(carved, len(ru.words)) /* only an explicit longer safe rule carves the line out */
				}
			}
			if denied > 0 && carved <= denied && v.Class != Denied {
				t.Fatalf("Classify(%q) = %v, a denied rule covers it", line, v.Class)
			}
		}
	})
}

/* FuzzNormalize: no panic; Normalize is idempotent; the normalized line classifies like the typed one and is well formed. */
func FuzzNormalize(f *testing.F) {
	g := testGrammar(f)
	ctx := mgmtCtx(f, g)
	modes := testModes(g)
	for _, s := range []string{"", "conf t", "do sh ver", `desc "a  b" c`, "int GI1/0/24", "copy run start", "no ip ssh s",
		"x" + r(0) + "y", "'a b' c", `"a\" b"`, tab + " r " + tab, "do do reload", `do "do" x`, "hostname a;b", "banner " + r(0x45b) + ";x",
		`"reload"`, "sh run | inc x", "wr mem", "commit 600", `"a"b`, "it's"} {
		f.Add(s, uint8(0))
		f.Add(s, uint8(2))
	}
	f.Fuzz(func(t *testing.T, line string, which uint8) {
		m := modes[int(which)%len(modes)]
		out, err := g.Normalize(line, m)
		v := g.Classify(line, m, ctx)
		_ = g.Complete(line, m)
		_ = g.Next(line, m)
		if err != nil {
			if v.Class != Denied || v.Reason != ReasonRefused || v.Line != "" {
				t.Fatalf("Normalize(%q) refused but Classify = %+v", line, v)
			}
			return
		}
		again, err := g.Normalize(out, m)
		if err != nil || again != out {
			t.Fatalf("Normalize(%q) = %q, then %q, %v", line, out, again, err)
		}
		toks, err := tokenize(out)
		if checkLine(out) != nil || err != nil || strings.Contains(out, tab) || strings.Join(toks, " ") != out {
			t.Fatalf("Normalize(%q) = %q: not a well-formed line", line, out)
		}
		if v.Line != out && v.Reason != ReasonEmpty {
			t.Fatalf("Classify(%q).Line = %q, Normalize = %q", line, v.Line, out)
		}
		if w := g.Classify(out, m, ctx); w.Class != v.Class || w.Control != v.Control || w.Reason != v.Reason {
			t.Fatalf("Classify(%q) = %v/%s, Classify(%q) = %v/%s", line, v.Class, v.Reason, out, w.Class, w.Reason)
		}
	})
}
