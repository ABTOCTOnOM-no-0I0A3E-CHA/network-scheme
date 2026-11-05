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
Cmd is one command of a mode. Pattern is space-separated: lowercase keywords
(or "|" for a pipe filter: filters are keywords, never part of a free
argument), <type> for one argument of a Spec.Args type, <type...> (last only)
for the rest of the line. Class is Safe, Dangerous or Control (with Control
set); Denied comes from the policy only. A Safe command never takes the
built-in <word>: it names a typed argument. Enter names the mode the command
enters; Nav commands are Safe.
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
ArgType is an argument type. Match says whether a token fits.

Text marks free text the device takes literally (a description, say): its
tokens may hold '|', '\' (not at a token's end), quotes and non-ASCII
letters, never ';'. It is off by default, only for a final <type...>
argument and never with Kind; set it only where the line's syntax is
confirmed for the firmware.

Kind, when set, makes the argument name management targets of that kind
("interface", "vlan", ...). Names gives their canonical names (nil: the token
in ASCII lower case). Contract for the drivers:
  - Every spelling the device accepts for one interface or VLAN (abbreviated
    or full type name, case, leading zeros, a type keyword followed by a
    separate port argument) yields the same canonical Target, and the session
    builds Context.Mgmt through Grammar.Targets with the same types. A
    spelling split over several tokens ("gigabitethernet 1/0/1") needs a
    keyword per interface type, each followed by a port type whose Names adds
    the type.
  - Ranges and lists ("gi1/0/1-4", "1,10-20") expand to every member.
  - Names returns false when it cannot resolve the token or when it would
    return more than limit names; it checks the count before allocating them.
    False counts as naming a management target.
*/
type ArgType struct {
	Match func(tok string) bool
	Text  bool
	Kind  string
	Names func(tok string, limit int) ([]string, bool)
}

/* Spec is a grammar: the argument types and the modes, Modes[0] being the root (exec). */
type Spec struct {
	Args  map[string]ArgType
	Modes []ModeSpec
}

/* Word matches any pure token. Every grammar has it as <word>, for dangerous commands only. */
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
		t.Names = func(tok string, limit int) ([]string, bool) {
			v, ok := parse(tok)
			if !ok || limit < 1 {
				return nil, false
			}
			return []string{strconv.FormatUint(v, 10)}, true
		}
	}
	return t
}

/* Target is a management interface or VLAN as the grammar's argument types name it. */
type Target struct{ Kind, Name string }

/* Grammar is a compiled Spec. It is immutable and safe for concurrent use. */
type Grammar struct {
	root     string
	args     map[string]ArgType
	modes    map[string]*mode
	controls [][]string /* the Control patterns of every mode; "" for an argument */
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
	keywordRe = regexp.MustCompile(`^(?:[a-z0-9][a-z0-9_.:/-]*|\|)$`)
	typeRe    = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
)

/* NewGrammar compiles and checks a Spec. */
func NewGrammar(s Spec) (*Grammar, error) {
	if len(s.Modes) == 0 {
		return nil, fmt.Errorf("core: no modes")
	}
	g := &Grammar{root: s.Modes[0].Name, args: map[string]ArgType{"word": Word}, modes: map[string]*mode{}}
	for name, t := range s.Args {
		if !typeRe.MatchString(name) || name == "word" || t.Match == nil || (t.Names != nil && t.Kind == "") || (t.Text && t.Kind != "") {
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
	var ctl []string
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
			n, ctl = n.kw[w], append(ctl, w)
			continue
		}
		name, ok := strings.CutSuffix(w, ">")
		name, rest := strings.CutSuffix(strings.TrimPrefix(name, "<"), "...")
		t, known := g.args[name]
		switch {
		case !ok || !known || rest && i != len(words)-1:
			return fmt.Errorf("bad argument %q", w)
		case name == "word" && c.Class == Safe:
			return fmt.Errorf("a safe command takes a typed argument, not <word>")
		case t.Text && !rest:
			return fmt.Errorf("a text argument is a final <type...>")
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
		n, ctl = e.next, append(ctl, "")
	}
	if n.cmd != nil {
		return fmt.Errorf("repeated pattern")
	}
	n.cmd = &c
	if c.Class == Control {
		g.controls = append(g.controls, ctl)
	}
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
	abbreviated /* a policy rule's keyword not typed in full */
)

type hit struct {
	t   ArgType
	tok string
}

/* result of parsing one line in one mode. */
type result struct {
	toks   []string /* normalized */
	st     status
	cmd    *Cmd  /* when parsed */
	class  Class /* Dangerous when any command on the path is */
	hits   []hit
	do     bool
	impure bool /* an impure token outside a keyword or a Text argument */
}

/*
step matches one token at n: a keyword (exact, else unique prefix) or else one
argument edge. A quoted token is never a keyword; an impure one is only an
exact keyword or a Text argument.
*/
func step(n *node, tok string) (*node, string, *edge, status) {
	ok := pure(tok)
	var args []*edge
	for _, e := range n.args {
		if (ok || e.t.Text && textOK(tok)) && e.t.Match(tok) {
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
			if ok && strings.HasPrefix(k, low) {
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

/* textOK: what even a Text argument refuses: ';' and a trailing backslash. */
func textOK(tok string) bool { return !strings.Contains(tok, ";") && !strings.HasSuffix(tok, `\`) }

/* restBad reports whether the rest of a line may not be taken by an argument of type t. */
func restBad(t ArgType, toks []string) bool {
	for _, tok := range toks {
		if !pure(tok) && (!t.Text || !textOK(tok)) {
			return true
		}
	}
	return false
}

func anyImpure(toks []string) bool {
	for _, t := range toks {
		if !pure(t) {
			return true
		}
	}
	return false
}

/* parse walks the tokens of a line in the named mode. */
func (g *Grammar) parse(toks []string, modeName string) result {
	md := g.modes[modeName]
	if md == nil {
		return result{toks: toks, st: badMode, impure: anyImpure(toks)}
	}
	r := result{class: Safe}
	n := md.top
	for i := 0; i < len(toks); i++ {
		nx, word, e, st := step(n, toks[i])
		if st != parsed {
			r.toks, r.st, r.impure = append(r.toks, toks[i:]...), st, anyImpure(toks[i:])
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
			r.impure = restBad(e.t, toks[i:])
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
	if len(toks) > 1 && doLike(toks[0]) && doLike(toks[1]) {
		return result{}, "", ErrNestedDo
	}
	r := g.parse(toks, m.Name())
	if r.impure {
		return result{}, "", ErrImpure
	}
	out := strings.Join(r.toks, " ")
	if len(out) > MaxLine {
		return result{}, "", ErrTooLong
	}
	return r, out, nil
}

/*
shadows reports whether toks could be a session-control command as the
device reads it: each token a prefix of the pattern's keyword (any case,
quotes stripped), extra words after it, with or without a leading `do`.
*/
func (g *Grammar) shadows(toks []string) bool {
	cands := [][]string{toks}
	if len(toks) > 1 && doLike(toks[0]) {
		cands = append(cands, toks[1:])
	}
	for _, ws := range cands {
	next:
		for _, p := range g.controls {
			if len(ws) < len(p) {
				continue
			}
			for i, w := range p {
				if t := unquote(asciiLower(ws[i])); w != "" && (t == "" || !strings.HasPrefix(w, t)) {
					continue next
				}
			}
			return true
		}
	}
	return false
}

/* targets resolves the management-relevant arguments of a line. */
func targets(hits []hit) ([]Target, bool) {
	var out []Target
	for _, h := range hits {
		if h.t.Kind == "" {
			continue
		}
		left := MaxTargets - len(out)
		names, ok := []string{asciiLower(h.tok)}, left > 0
		if h.t.Names != nil {
			names, ok = h.t.Names(h.tok, left)
		}
		if !ok || len(names) > left {
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
