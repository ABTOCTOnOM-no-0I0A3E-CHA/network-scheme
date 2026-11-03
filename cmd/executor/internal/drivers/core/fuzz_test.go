package core

import (
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/internal/execpolicy"
)

/* pattern is a dangerous line of the test grammar: lines walked to its mode, its tokens, which tokens are keywords. */
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

var (
	spaces = []string{" ", "  ", "\t", " \t ", "\t\t"}
	ctrl   = []string{"\x00", "\x03", "\x08", "\x15", "\x1b", "\x1b[D", "\r", "\n", "\x7f", "\u0085", "\u009b", "\u00ad", "\u200b", "\u200d", "\u202e", "\u2066", "\u2028", "\ufeff", "\u00a0", "\xc0\xaf", "?"}
)

/* mutate builds a variant of p: abbreviated keywords, case, spaces and tabs, `do`, a control character. */
func mutate(p pattern, b *fuzzBytes) (string, bool) {
	var toks []string
	if b.next()%3 == 0 {
		toks = append(toks, []string{"do", "DO", "Do"}[b.next()%3])
	}
	for i, t := range p.toks {
		if p.kw[i] {
			if n := int(b.next()) % (len(t) + 2); n >= 1 && n < len(t) {
				t = t[:n] /* a prefix: unique, ambiguous or the whole word */
			}
		}
		if c := b.next(); c%2 == 1 {
			r := []byte(t)
			for j := range r {
				if c>>(1+j%7)&1 == 1 && 'a' <= r[j] && r[j] <= 'z' {
					r[j] -= 'a' - 'A'
				}
			}
			t = string(r)
		}
		toks = append(toks, t)
	}
	var s strings.Builder
	s.WriteString(spaces[int(b.next())%len(spaces)][:int(b.next())%2])
	for i, t := range toks {
		if i > 0 {
			s.WriteString(spaces[int(b.next())%len(spaces)])
		}
		s.WriteString(t)
	}
	s.WriteString(spaces[int(b.next())%len(spaces)][:int(b.next())%2])
	line := s.String()
	if c := b.next(); c%4 == 0 {
		at := int(b.next()) % (len(line) + 1)
		return line[:at] + ctrl[int(b.next())%len(ctrl)] + line[at:], true
	}
	return line, false
}

/* FuzzClassify: no mutation of a dangerous line is ever safe, and none of a line the policy denies is less than denied. */
func FuzzClassify(f *testing.F) {
	g := testGrammar(f)
	ctx := mgmtCtx(f, g)
	deny := ctx
	var err error
	if deny.Rules, err = NewRules("esr", []execpolicy.ClassOverride{{Driver: "any", Command: "reload", Class: "denied"}}); err != nil {
		f.Fatal(err)
	}
	for i := range dangerous {
		f.Add(uint8(i), []byte{})
		f.Add(uint8(i), []byte{0, 1, 2, 255, 3, 4, 0, 1, 1, 5, 0, 7})
	}
	f.Fuzz(func(t *testing.T, which uint8, choices []byte) {
		p := dangerous[int(which)%len(dangerous)]
		b := fuzzBytes(choices)
		line, bad := mutate(p, &b)
		m := walk(g, p.mode...)
		v := g.Classify(line, m, ctx)
		if v.Class == Safe {
			t.Fatalf("Classify(%q in %s) = safe (%s)", line, m.Name(), v.Reason)
		}
		if bad && (v.Class != Denied || v.Reason != ReasonRefused || v.Line != "") {
			t.Fatalf("Classify(%q) = %+v with a control character", line, v)
		}
		if p.toks[0] == "reload" {
			if v := g.Classify(line, m, deny); v.Class != Denied {
				t.Fatalf("Classify(%q) with reload denied = %+v", line, v)
			}
		}
	})
}

/* FuzzNormalize: no panic; Normalize is idempotent; the normalized line classifies like the typed one. */
func FuzzNormalize(f *testing.F) {
	g := testGrammar(f)
	ctx := mgmtCtx(f, g)
	modes := testModes(g)
	for _, s := range []string{"", "conf t", "do sh ver", `desc "a  b" c`, "int GI1/0/24", "copy run start", "no ip ssh s", "x\x00y", "'a b' c", `"a\" b"`, "\t r \t"} {
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
			if v.Class != Denied || v.Reason != ReasonRefused {
				t.Fatalf("Normalize(%q) refused but Classify = %+v", line, v)
			}
			return
		}
		again, err := g.Normalize(out, m)
		if err != nil || again != out {
			t.Fatalf("Normalize(%q) = %q, then %q, %v", line, out, again, err)
		}
		if v.Class != Control && v.Class != Safe && v.Line != out || v.Class == Safe && v.Reason != ReasonEmpty && v.Line != out {
			t.Fatalf("Classify(%q).Line = %q, Normalize = %q", line, v.Line, out)
		}
		if w := g.Classify(out, m, ctx); w.Class != v.Class || w.Control != v.Control {
			t.Fatalf("Classify(%q) = %v, Classify(%q) = %v", line, v.Class, out, w.Class)
		}
	})
}
