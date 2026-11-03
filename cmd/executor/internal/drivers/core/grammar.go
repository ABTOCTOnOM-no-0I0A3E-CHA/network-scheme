package core

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

/* Nav marks a navigation command: allowed in any context, it only moves between modes. */
type Nav uint8

/* Navigation kinds. */
const (
	NoNav Nav = iota
	Exit      /* one mode up */
	End       /* back to the root mode */
)

/*
Cmd is one command of a mode. Pattern is space-separated: lowercase keywords,
<type> for one argument of a Spec.Args type, <type...> (last only) for the
rest of the line. Class is Safe, Dangerous or Control (with Control set);
Denied comes from the policy only. Enter names the mode the command enters;
Nav commands are Safe.
*/
type Cmd struct {
	Pattern string
	Class   Class
	Control ControlKind
	Enter   string
	Nav     Nav
}

/* ModeSpec is one CLI mode. Parent is the mode it sits in (empty for the root); Do allows `do <root command>`. */
type ModeSpec struct {
	Name   string
	Parent string
	Do     bool
	Cmds   []Cmd
}

/*
ArgType is an argument type. Match says whether a token fits. Kind, when
set, makes the argument name management targets of that kind ("interface",
"vlan", ...): Names gives their canonical names (nil: the token in ASCII
lower case); false means the token cannot be resolved and counts as naming a
management target.
*/
type ArgType struct {
	Match func(tok string) bool
	Kind  string
	Names func(tok string) ([]string, bool)
}

/* Spec is a grammar: the argument types and the modes, Modes[0] being the root (exec). */
type Spec struct {
	Args  map[string]ArgType
	Modes []ModeSpec
}

/* Word matches any token. Every grammar has it as <word>. */
var Word = ArgType{Match: func(string) bool { return true }}

/* Uint matches a decimal number in [lo, hi]; its canonical name is the number without leading zeros. */
func Uint(lo, hi uint64, kind string) ArgType {
	parse := func(tok string) (uint64, bool) {
		if len(tok) == 0 || len(tok) > 20 || strings.Trim(tok, "0123456789") != "" {
			return 0, false
		}
		v, err := strconv.ParseUint(tok, 10, 64)
		return v, err == nil && lo <= v && v <= hi
	}
	t := ArgType{Match: func(tok string) bool { _, ok := parse(tok); return ok }, Kind: kind}
	if kind != "" {
		t.Names = func(tok string) ([]string, bool) {
			v, ok := parse(tok)
			return []string{strconv.FormatUint(v, 10)}, ok
		}
	}
	return t
}

/* Target is a management interface or VLAN as the grammar's argument types name it. */
type Target struct{ Kind, Name string }

/* Grammar is a compiled Spec. It is immutable and safe for concurrent use. */
type Grammar struct {
	root  string
	args  map[string]ArgType
	modes map[string]*mode
}

type mode struct {
	parent string
	top    *node
}

type node struct {
	kw   map[string]*node
	args []*edge
	cmd  *Cmd
}

type edge struct {
	typ  string
	t    ArgType
	rest bool
	next *node
}

/* doNode is the `do` keyword at the top of a Do mode: the rest is a root-mode line. */
var doNode = &node{}

var (
	keywordRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:/-]*$`)
	typeRe    = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
)

/* NewGrammar compiles and checks a Spec. */
func NewGrammar(s Spec) (*Grammar, error) {
	if len(s.Modes) == 0 {
		return nil, fmt.Errorf("core: no modes")
	}
	g := &Grammar{root: s.Modes[0].Name, args: map[string]ArgType{"word": Word}, modes: map[string]*mode{}}
	for name, t := range s.Args {
		if !typeRe.MatchString(name) || name == "word" || t.Match == nil || (t.Names != nil && t.Kind == "") {
			return nil, fmt.Errorf("core: bad argument type %q", name)
		}
		g.args[name] = t
	}
	for i, ms := range s.Modes {
		if ms.Name == "" || g.modes[ms.Name] != nil || (i == 0) != (ms.Parent == "") || (i == 0 && ms.Do) {
			return nil, fmt.Errorf("core: bad mode %q", ms.Name)
		}
		g.modes[ms.Name] = &mode{parent: ms.Parent, top: &node{}}
	}
	for _, ms := range s.Modes {
		md := g.modes[ms.Name]
		if p := g.modes[ms.Parent]; ms.Parent != "" && (p == nil || ms.Parent == ms.Name) {
			return nil, fmt.Errorf("core: mode %q: bad parent %q", ms.Name, ms.Parent)
		}
		if ms.Do {
			md.top.kw = map[string]*node{"do": doNode}
		}
		for _, c := range ms.Cmds {
			if err := g.add(md.top, c); err != nil {
				return nil, fmt.Errorf("core: mode %q: %q: %w", ms.Name, c.Pattern, err)
			}
		}
	}
	return g, nil
}

func (g *Grammar) add(n *node, c Cmd) error {
	switch {
	case c.Class == Denied:
		return fmt.Errorf("denied comes from the policy only")
	case c.Class != Safe && c.Class != Dangerous && c.Class != Control:
		return fmt.Errorf("no class")
	case (c.Class == Control) != (c.Control != NoControl):
		return fmt.Errorf("control class without kind or kind without control class")
	case c.Nav != NoNav && (c.Class != Safe || c.Enter != ""):
		return fmt.Errorf("navigation must be safe and enter nothing")
	case c.Enter != "" && (g.modes[c.Enter] == nil || c.Enter == g.root || c.Class == Control):
		return fmt.Errorf("bad mode to enter %q", c.Enter)
	}
	words := strings.Fields(c.Pattern)
	if len(words) == 0 {
		return fmt.Errorf("empty pattern")
	}
	for i, w := range words {
		if !strings.HasPrefix(w, "<") {
			if !keywordRe.MatchString(w) || n.kw["do"] == doNode && w == "do" {
				return fmt.Errorf("bad keyword %q", w)
			}
			if n.kw == nil {
				n.kw = map[string]*node{}
			}
			if n.kw[w] == nil {
				n.kw[w] = &node{}
			}
			n = n.kw[w]
			continue
		}
		name, ok := strings.CutSuffix(w, ">")
		name, rest := strings.CutSuffix(strings.TrimPrefix(name, "<"), "...")
		t, known := g.args[name]
		if !ok || !known || rest && i != len(words)-1 {
			return fmt.Errorf("bad argument %q", w)
		}
		var e *edge
		for _, x := range n.args {
			if x.typ == name && x.rest == rest {
				e = x
			}
		}
		if e == nil {
			e = &edge{typ: name, t: t, rest: rest, next: &node{}}
			n.args = append(n.args, e)
		}
		n = e.next
	}
	if n.cmd != nil {
		return fmt.Errorf("repeated pattern")
	}
	n.cmd = &c
	return nil
}

/* status of a parse. */
type status uint8

const (
	parsed status = iota
	unknown
	ambiguous
	incomplete
	badMode
)

type hit struct {
	t   ArgType
	tok string
}

/* result of parsing one line in one mode. */
type result struct {
	toks  []string /* normalized */
	st    status
	cmd   *Cmd  /* when parsed */
	class Class /* Dangerous when any command on the path is */
	hits  []hit
	do    bool
}

/* step matches one token at n: a keyword (exact, else unique prefix) or else one argument edge. */
func step(n *node, tok string) (*node, string, *edge, status) {
	var args []*edge
	for _, e := range n.args {
		if e.t.Match(tok) {
			args = append(args, e)
		}
	}
	if tok[0] != '"' && tok[0] != '\'' {
		low := asciiLower(tok)
		if nx := n.kw[low]; nx != nil {
			return nx, low, nil, parsed
		}
		var word string
		hits := 0
		for k := range n.kw {
			if strings.HasPrefix(k, low) {
				word, hits = k, hits+1
			}
		}
		switch {
		case hits > 1 || hits == 1 && len(args) > 0:
			return nil, "", nil, ambiguous
		case hits == 1:
			return n.kw[word], word, nil, parsed
		}
	}
	switch len(args) {
	case 0:
		return nil, "", nil, unknown
	case 1:
		return args[0].next, "", args[0], parsed
	}
	return nil, "", nil, ambiguous
}

/* parse walks the tokens of a line in the named mode. */
func (g *Grammar) parse(toks []string, modeName string) result {
	md := g.modes[modeName]
	if md == nil {
		return result{toks: toks, st: badMode}
	}
	r := result{class: Safe}
	n := md.top
	for i := 0; i < len(toks); i++ {
		nx, word, e, st := step(n, toks[i])
		if st != parsed {
			r.toks, r.st = append(r.toks, toks[i:]...), st
			return r
		}
		switch {
		case nx == doNode:
			in := g.parse(toks[i+1:], g.root)
			in.toks, in.do = append([]string{"do"}, in.toks...), true
			return in
		case e != nil && e.rest:
			r.toks = append(r.toks, toks[i:]...)
			r.hits = append(r.hits, hit{e.t, strings.Join(toks[i:], " ")})
			i = len(toks)
		case e != nil:
			r.toks = append(r.toks, toks[i])
			r.hits = append(r.hits, hit{e.t, toks[i]})
		default:
			r.toks = append(r.toks, word)
		}
		if n = nx; n.cmd != nil && n.cmd.Class == Dangerous {
			r.class = Dangerous
		}
	}
	if n.cmd == nil {
		r.st = incomplete
		return r
	}
	r.cmd = n.cmd
	return r
}

/* analyze checks, splits and parses a line in m; the normalized line must fit MaxLine too (idempotence). */
func (g *Grammar) analyze(line string, m Mode) (result, string, error) {
	if err := checkLine(line); err != nil {
		return result{}, "", err
	}
	toks, err := tokenize(line)
	if err != nil {
		return result{}, "", err
	}
	r := g.parse(toks, m.Name())
	out := strings.Join(r.toks, " ")
	if len(out) > MaxLine {
		return result{}, "", ErrTooLong
	}
	return r, out, nil
}

/* targets resolves the management-relevant arguments of a line. */
func targets(hits []hit) ([]Target, bool) {
	var out []Target
	for _, h := range hits {
		if h.t.Kind == "" {
			continue
		}
		names, ok := []string{asciiLower(h.tok)}, true
		if h.t.Names != nil {
			names, ok = h.t.Names(h.tok)
		}
		if !ok || len(names) > MaxTargets-len(out) {
			return nil, false
		}
		for _, nm := range names {
			out = append(out, Target{h.t.Kind, nm})
		}
	}
	return out, true
}

/*
Targets resolves a token of argument type typ into targets, the way a line
naming it would: the session builds Context.Mgmt with it from what it learns
of the registry address at session start.
*/
func (g *Grammar) Targets(typ, tok string) ([]Target, bool) {
	t, ok := g.args[typ]
	if !ok || t.Kind == "" || tok == "" || !t.Match(tok) {
		return nil, false
	}
	return targets([]hit{{t, tok}})
}
