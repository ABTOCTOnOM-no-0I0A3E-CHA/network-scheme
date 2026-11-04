package drivers_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
)

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
	spaces = []string{" ", "  ", "\t", " \t ", "\t\t"}
	dos    = []string{"do", "DO", `"do"`, "do do", `do "do"`, "d do"}
	quotes = []string{`"`, `'`}
	extras = []string{"x", "memory", "600", "now", "startup-config"}
)

/* mutate spells p differently: keyword prefixes, quotes, case, spaces and tabs, a do, an extra word, an inserted character. */
func mutate(p pat, b *fuzzBytes, extra, doAny bool) (string, bool) {
	ws, kw := p.words()
	var toks []string
	if c := b.next(); c%3 == 0 && (doAny || len(p.mode) == 0) {
		toks = append(toks, dos[b.pick(3)])
	} else if c%3 == 1 && !doAny {
		toks = append(toks, dos[3+b.pick(3)])
	}
	for i, w := range ws {
		if kw[i] {
			if n := b.pick(len(w) + 2); n >= 1 && n < len(w) {
				w = w[:n]
			}
			if b.next()%8 == 0 {
				q := quotes[b.pick(2)]
				w = q + w + q
			}
		}
		if b.next()%2 == 1 {
			w = strings.ToUpper(w)
		}
		toks = append(toks, w)
	}
	if extra && b.next()%3 == 0 {
		toks = append(toks, extras[b.pick(len(extras))])
	}
	var s strings.Builder
	for i, t := range toks {
		if i > 0 {
			s.WriteString(spaces[b.pick(len(spaces))])
		}
		s.WriteString(t)
	}
	line := s.String()
	if b.next()%4 == 0 {
		ins := ctrl[b.pick(len(ctrl))]
		at := b.pick(len(line) + 1)
		return line[:at] + ins + line[at:], true
	}
	return line, false
}

func names() []string {
	ns := make([]string, 0, len(lines))
	for n := range lines {
		ns = append(ns, n)
	}
	sort.Strings(ns)
	return ns
}

/* FuzzClassify: no mutation of a dangerous pattern of any line is safe or control. */
func FuzzClassify(f *testing.F) {
	for li := range lines {
		for i := range dangerous[li] {
			f.Add(uint8(len(li)), uint16(i), []byte{})
			f.Add(uint8(len(li)), uint16(i), []byte{0, 1, 2, 255, 3, 4, 0, 1, 1, 5, 0, 7})
		}
	}
	ns := names()
	f.Fuzz(func(t *testing.T, which uint8, i uint16, choices []byte) {
		fx := lines[ns[int(which)%len(ns)]]
		ps := dangerous[string(fx.d.Line())]
		p := ps[int(i)%len(ps)]
		b := fuzzBytes(choices)
		line, ins := mutate(p, &b, false, true)
		g := fx.d.Grammar()
		mode := p.mode
		v := fx.d.Classify(line, walk(g, mode...), fx.ctx(t))
		if v.Class == core.Safe || v.Class == core.Control || ins && v.Class != core.Denied {
			t.Fatalf("%s: Classify(%q in %v) = %v (%s)", fx.d.Line(), line, mode, v.Class, v.Reason)
		}
	})
}

/* FuzzControl: no mutation of a save, commit or confirm alias of any line is ever sent (Control or Denied). */
func FuzzControl(f *testing.F) {
	type cp struct{ line, alias string }
	var all []cp
	for _, li := range names() {
		var as []string
		for a := range controls[li] {
			as = append(as, a)
		}
		sort.Strings(as)
		for _, a := range as {
			all = append(all, cp{li, a})
		}
	}
	for i := range all {
		f.Add(uint16(i), []byte{})
		f.Add(uint16(i), []byte{0, 1, 2, 255, 3, 4, 0, 1, 1, 5, 0, 7, 0})
	}
	f.Fuzz(func(t *testing.T, i uint16, choices []byte) {
		c := all[int(i)%len(all)]
		fx := lines[c.line]
		b := fuzzBytes(choices)
		line, _ := mutate(pat{line: c.alias}, &b, true, false)
		g := fx.d.Grammar()
		for _, m := range []core.Mode{g.Root(), walk(g, fx.cfg)} {
			l := line
			if m.Name() == "config" {
				l = "do " + line
			}
			if v := fx.d.Classify(l, m, fx.ctx(t)); v.Class != core.Control && v.Class != core.Denied {
				t.Fatalf("%s: Classify(%q in %s) = %+v: a session-control command would be sent", c.line, l, m.Name(), v)
			}
		}
	})
}
