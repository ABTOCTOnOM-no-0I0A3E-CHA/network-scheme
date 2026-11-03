package core

import (
	"fmt"
	"slices"
	"strings"

	"github.com/beekamai/network-scheme/internal/execpolicy"
)

/*
Mode is where a session's CLI is: the stack of modes from the root, with the
management targets each entered mode addresses. The zero Mode is no mode
(every line dangerous). Unsure means the session lost track of the context
(the device accepted a line the grammar could not parse, or the prompt
disagreed): every line but navigation and `do` is dangerous until the root.
*/
type Mode struct {
	frames []frame
	unsure bool
}

type frame struct {
	name    string
	targets []Target
}

/* Name is the current mode ("" for the zero Mode). */
func (m Mode) Name() string {
	if len(m.frames) == 0 {
		return ""
	}
	return m.frames[len(m.frames)-1].name
}

/* Unsure reports whether the context is unknown. */
func (m Mode) Unsure() bool { return m.unsure }

/* Root is the mode a session starts in after login. */
func (g *Grammar) Root() Mode { return Mode{frames: []frame{{name: g.root}}} }

/*
Next is the mode after the device accepted line in m (the session calls it
only then). A line the grammar cannot parse makes the mode Unsure; Control
lines leave m alone (their flows set the mode they leave the device in).
*/
func (g *Grammar) Next(line string, m Mode) Mode {
	r, _, err := g.analyze(line, m)
	switch {
	case err == nil && len(r.toks) == 0:
		return m
	case err != nil || r.st != parsed:
		if len(m.frames) > 1 {
			m.unsure = true
		}
		return m
	case r.do || r.cmd.Control != NoControl:
		return m
	case r.cmd.Nav == End:
		return g.Root()
	case r.cmd.Nav == Exit:
		if len(m.frames) <= 1 {
			return m
		}
		return Mode{frames: m.frames[: len(m.frames)-1 : len(m.frames)-1], unsure: m.unsure && len(m.frames) > 2}
	case r.cmd.Enter != "":
		kept, found := g.enterBase(m, r.cmd.Enter)
		ts, ok := targets(r.hits)
		return Mode{frames: append(kept, frame{r.cmd.Enter, ts}), unsure: m.unsure || !found || !ok}
	}
	return m
}

/* enterBase is the part of m's stack that entering mode name keeps: up to its parent. */
func (g *Grammar) enterBase(m Mode, name string) ([]frame, bool) {
	parent := g.modes[name].parent
	for j := len(m.frames) - 1; j >= 0; j-- {
		if m.frames[j].name == parent {
			return slices.Clone(m.frames[:j+1]), true
		}
	}
	return slices.Clone(m.frames), false
}

/*
Reconcile checks m against the mode the device's prompt shows (as a grammar
mode name): a mismatch makes the session Unsure in that mode, the root
excepted.
*/
func (g *Grammar) Reconcile(m Mode, name string) Mode {
	switch name {
	case m.Name():
		return m
	case g.root:
		return g.Root()
	}
	return Mode{frames: []frame{{name: g.root}, {name: name}}, unsure: true}
}

/* Context is what Classify knows of the session: the management targets and the policy's overrides. */
type Context struct {
	Mgmt  []Target
	Rules Rules
}

func (c Context) mgmt(ts []Target) bool {
	for _, t := range ts {
		if slices.Contains(c.Mgmt, t) {
			return true
		}
	}
	return false
}

/* Normalize spells out keywords and collapses spaces; it refuses a line with a forbidden character. It is idempotent. */
func (g *Grammar) Normalize(line string, m Mode) (string, error) {
	_, out, err := g.analyze(line, m)
	return out, err
}

/* Classify classifies one line typed in m. Send only Verdict.Line, and only when the class allows it. */
func (g *Grammar) Classify(line string, m Mode, c Context) Verdict {
	r, out, err := g.analyze(line, m)
	if err != nil {
		return Verdict{Class: Denied, Reason: ReasonRefused, Err: err}
	}
	v := Verdict{Class: Dangerous, Line: out}
	switch r.st {
	case unknown:
		v.Reason = ReasonUnknown
	case ambiguous:
		v.Reason = ReasonAmbiguous
	case incomplete:
		v.Reason = ReasonIncomplete
	case badMode:
		v.Reason = ReasonMode
	}
	switch {
	case len(r.toks) == 0:
		return Verdict{Class: Safe, Reason: ReasonEmpty}
	case r.st != parsed:
	case r.cmd.Control != NoControl:
		return Verdict{Class: Control, Control: r.cmd.Control, Line: v.Line, Reason: ReasonGrammar}
	default:
		v.Class, v.Reason = r.class, ReasonGrammar
		if !r.do && r.cmd.Nav == NoNav && v.Class == Safe {
			v.Class, v.Reason = g.context(r, m, c)
		}
	}
	/* Also without a leading `do` or what may be one: the device may resolve "d" as do where the grammar finds it ambiguous. */
	words := r.toks
	if len(words) > 1 && strings.HasPrefix("do", asciiLower(words[0])) {
		words = words[1:]
	}
	for _, ws := range [][]string{r.toks, words} {
		if cl, ok := c.Rules.match(ws); ok && cl > v.Class {
			v.Class, v.Reason = cl, ReasonPolicy
		}
	}
	return v
}

/*
context raises a parsed Safe line that touches the management interface or
VLAN: any line inside a mode entered for one, and a configuration line that
names one (exec lines change nothing by naming it; their dangers are the
grammar's).
*/
func (g *Grammar) context(r result, m Mode, c Context) (Class, Reason) {
	if m.unsure {
		return Dangerous, ReasonUnsure
	}
	frames := m.frames
	if r.cmd.Enter != "" {
		frames, _ = g.enterBase(m, r.cmd.Enter)
	}
	for _, f := range frames {
		if c.mgmt(f.targets) {
			return Dangerous, ReasonMgmt
		}
	}
	if r.cmd.Enter == "" && len(m.frames) > 1 {
		if ts, ok := targets(r.hits); !ok || c.mgmt(ts) {
			return Dangerous, ReasonMgmt
		}
	}
	return Safe, ReasonGrammar
}

/*
Complete lists the grammar words that may follow prefix in m: keywords, and
<type> for arguments. It never returns text from the line or the device, and
at most MaxComplete words.
*/
func (g *Grammar) Complete(prefix string, m Mode) []string {
	md := g.modes[m.Name()]
	if md == nil || checkLine(prefix) != nil {
		return nil
	}
	toks, err := tokenize(prefix)
	if err != nil {
		return nil
	}
	partial := ""
	if last := strings.ReplaceAll(prefix, "\t", " "); len(toks) > 0 && !strings.HasSuffix(last, " ") {
		partial, toks = toks[len(toks)-1], toks[:len(toks)-1]
	}
	n := md.top
	for _, tok := range toks {
		nx, _, e, st := step(n, tok)
		switch {
		case st != parsed || e != nil && e.rest:
			return nil
		case nx == doNode:
			n = g.modes[g.root].top
		default:
			n = nx
		}
	}
	var out []string
	if partial == "" || partial[0] != '"' && partial[0] != '\'' {
		low := asciiLower(partial)
		for k := range n.kw {
			if strings.HasPrefix(k, low) {
				out = append(out, k)
			}
		}
	}
	for _, e := range n.args {
		if partial == "" || e.t.Match(partial) {
			w := "<" + e.typ + ">"
			if e.rest {
				w = "<" + e.typ + "...>"
			}
			out = append(out, w)
		}
	}
	slices.Sort(out)
	out = slices.Compact(out)
	return out[:min(len(out), MaxComplete)]
}

/*
Rules are the policy's class overrides for one driver line. The override
with the longest matching command prefix wins (the stricter on a tie); the
line's class is then the stricter of it and the grammar's, so `safe` only
carves an exception out of a broader policy override and never relaxes the
grammar (security.md 5.3: unknown, ambiguous and the built-in dangerous
commands stay dangerous). A dangerous or denied override also matches the
line's words by prefix ("rel" for "reload"), quoted or not, with or without a
leading `do`; a safe one only by whole words.
*/
type Rules struct{ rules []rule }

type rule struct {
	words []string
	class Class
}

/* NewRules takes the overrides of line (and of "any") from a validated policy. */
func NewRules(line string, overrides []execpolicy.ClassOverride) (Rules, error) {
	var r Rules
	for _, o := range overrides {
		if o.Driver != line && o.Driver != "any" {
			continue
		}
		var cl Class
		switch o.Class {
		case execpolicy.ClassSafe:
			cl = Safe
		case execpolicy.ClassDangerous:
			cl = Dangerous
		case execpolicy.ClassDenied:
			cl = Denied
		default:
			return Rules{}, fmt.Errorf("core: override %q: class %q", o.Command, o.Class)
		}
		words := strings.Fields(asciiLower(o.Command))
		if len(words) == 0 {
			return Rules{}, fmt.Errorf("core: empty override command")
		}
		r.rules = append(r.rules, rule{words, cl})
	}
	return r, nil
}

func (r Rules) match(toks []string) (Class, bool) {
	var best Class
	n := 0
	for _, ru := range r.rules {
		if len(ru.words) > len(toks) || len(ru.words) < n || !ru.covers(toks) {
			continue
		}
		if len(ru.words) > n || ru.class > best {
			best, n = ru.class, len(ru.words)
		}
	}
	return best, n > 0
}

func (ru rule) covers(toks []string) bool {
	for i, w := range ru.words {
		t := asciiLower(toks[i])
		if ru.class != Safe {
			t = strings.Trim(t, `"'`) /* a quoted keyword the device may still take as the keyword */
		}
		if t != w && (ru.class == Safe || t == "" || !strings.HasPrefix(w, t)) {
			return false
		}
	}
	return true
}
