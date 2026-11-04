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
(the device accepted a line the grammar could not parse, a `do` that may
change the mode, or the prompt disagreed): every line but navigation and
`do` is dangerous until End or a root prompt (Reconcile) clears it.
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
only then, and Reconcile with the prompt right after). A line the grammar
cannot parse, or a `do` of a command that enters or leaves a mode, makes the
mode Unsure, in the root too; only End clears it. Control lines leave m alone
(their flows set the mode they leave the device in).
*/
func (g *Grammar) Next(line string, m Mode) Mode {
	r, _, err := g.analyze(line, m)
	switch {
	case err == nil && len(r.toks) == 0:
		return m
	case err != nil || r.st != parsed:
		m.unsure = true
		return m
	case r.cmd.Control != NoControl:
		return m
	case r.do:
		if r.cmd.Enter != "" || r.cmd.Nav != NoNav {
			m.unsure = true
		}
		return m
	case r.cmd.Nav == End:
		return g.Root()
	case r.cmd.Nav == Exit:
		if len(m.frames) <= 1 {
			return m
		}
		return Mode{frames: m.frames[: len(m.frames)-1 : len(m.frames)-1], unsure: m.unsure}
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
mode name). The root prompt resets the session to Root (the only way besides
End to clear Unsure); a mismatch makes the session Unsure in the prompt's mode.
*/
func (g *Grammar) Reconcile(m Mode, name string) Mode {
	switch name {
	case g.root:
		return g.Root()
	case m.Name():
		return m
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

/* Normalize spells out keywords and collapses spaces; it refuses a line Classify refuses. It is idempotent. */
func (g *Grammar) Normalize(line string, m Mode) (string, error) {
	_, out, err := g.analyze(line, m)
	return out, err
}

/* Classify classifies one line typed in m. Send only Verdict.Line, and only when the class is Safe or Dangerous. */
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
		return Verdict{Class: Control, Control: r.cmd.Control, Line: out, Reason: ReasonGrammar}
	case r.do && (r.cmd.Enter != "" || r.cmd.Nav != NoNav):
		v.Reason = ReasonDoMode
	default:
		v.Class, v.Reason = r.class, ReasonGrammar
		if !r.do && r.cmd.Nav == NoNav && v.Class == Safe {
			v.Class, v.Reason = g.context(r, m, c)
		}
	}
	if v.Class == Dangerous && g.shadows(r.toks) {
		return Verdict{Class: Denied, Line: out, Reason: ReasonControl}
	}
	if cl, ok := c.Rules.match(r.toks); ok && cl > v.Class {
		v.Class, v.Reason = cl, ReasonPolicy
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
	if len(toks) > 0 && !isSpace(prefix[len(prefix)-1]) {
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
Rules are the policy's class overrides for one driver line, their commands
normalized by the line's grammar (NewRules). The override with the longest
matching command prefix wins (the stricter on a tie); the line's class is
then the stricter of it and the grammar's, so `safe` only carves an exception
out of a broader policy override and never relaxes the grammar (security.md
5.3: unknown, ambiguous and the built-in dangerous commands stay dangerous),
and nothing changes Control. A dangerous or denied override matches keywords
by prefix ("rel" for "reload", for lines the grammar could not expand) and
arguments case-insensitively, quoted or not, with or without a leading `do`;
a safe one only matches whole keywords and arguments exactly (case included).
*/
type Rules struct{ rules []rule }

type rule struct {
	words []rword
	class Class
}

type rword struct {
	w  string
	kw bool
}

/*
NewRules takes the overrides of line (and of "any") from a validated policy
and spells their commands out with g: each word a full keyword or an
argument, in every mode where the command parses. A word that is ambiguous in
some mode, or a command that parses in no mode, is an error: the session must
then refuse to open (fail closed).
*/
func NewRules(g *Grammar, line string, overrides []execpolicy.ClassOverride) (Rules, error) {
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
		forms, err := g.ruleForms(strings.Fields(o.Command))
		if err != nil {
			return Rules{}, fmt.Errorf("core: override %q: %w", o.Command, err)
		}
		for _, ws := range forms {
			r.rules = append(r.rules, rule{ws, cl})
		}
	}
	return r, nil
}

/* ruleForms spells a command prefix out in every mode where it parses. */
func (g *Grammar) ruleForms(raw []string) ([][]rword, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	var forms [][]rword
	for _, md := range g.modes {
		ws, st := g.ruleForm(md.top, raw)
		switch {
		case st == ambiguous:
			return nil, fmt.Errorf("ambiguous word")
		case st == parsed && !slices.ContainsFunc(forms, func(f []rword) bool { return slices.Equal(f, ws) }):
			forms = append(forms, ws)
		}
	}
	if len(forms) == 0 {
		return nil, fmt.Errorf("not a command of the grammar")
	}
	return forms, nil
}

func (g *Grammar) ruleForm(n *node, raw []string) ([]rword, status) {
	var out []rword
	for i := 0; i < len(raw); i++ {
		if n == doNode {
			n = g.modes[g.root].top
		}
		nx, word, e, st := step(n, raw[i])
		switch {
		case st != parsed:
			return nil, st
		case e == nil:
			out = append(out, rword{word, true})
		case e.rest:
			for _, w := range raw[i:] {
				out = append(out, rword{w, false})
			}
			return out, parsed
		default:
			out = append(out, rword{raw[i], false})
		}
		n = nx
	}
	return out, parsed
}

/* match is the class of the best rule covering toks, also without a leading `do` or what may be one. */
func (r Rules) match(toks []string) (Class, bool) {
	cands := [][]string{toks}
	if len(toks) > 1 && doLike(toks[0]) {
		cands = append(cands, toks[1:])
	}
	var best Class
	for _, ws := range cands {
		if cl, ok := r.match1(ws); ok && cl > best {
			best = cl
		}
	}
	return best, best != 0
}

func (r Rules) match1(toks []string) (Class, bool) {
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
		if ru.class == Safe {
			if toks[i] != w.w {
				return false
			}
			continue
		}
		t, lw := unquote(asciiLower(toks[i])), asciiLower(w.w)
		if w.kw && (t == "" || !strings.HasPrefix(lw, t)) || !w.kw && t != unquote(lw) {
			return false
		}
	}
	return true
}
