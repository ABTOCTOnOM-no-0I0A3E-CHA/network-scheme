package drivers

import (
	"slices"
	"strings"

	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
	"github.com/beekamai/network-scheme/cmd/executor/internal/strategy"
)

/*
Planner turns one configuration into another with typed lines (Phase 5,
task 5.6: restoring a backup version through a changeset): Plan(from, to)
is the lines, from the privileged prompt, that change from's running
configuration into to's. It knows only the shape every line shares: root
lines and context blocks (a line and its indented body). A difference it
cannot express is still planned literally ("no <line>" for a line to drop),
and the dry-run's grammar walk refuses what the line's grammar does not
know as safe: a restore then fails closed and lists what it cannot restore.
*/
type Planner interface {
	Plan(from, to Config) ([]string, error)
}

/* block is a context line and its body (trimmed lines). */
type block struct {
	head string
	body []string
}

/* blocks reads a configuration's root lines and context blocks; comments, blank lines and exit/end lines are not configuration. */
func blocks(text string) (root []string, ctxs []block) {
	for _, l := range strings.Split(strings.ReplaceAll(text, "\r", ""), "\n") {
		t := strings.TrimSpace(l)
		switch {
		case t == "" || strings.HasPrefix(t, "!") || strings.HasPrefix(t, "#") || t == "exit" || t == "end":
		case (l[0] == ' ' || l[0] == '\t') && len(ctxs) > 0:
			ctxs[len(ctxs)-1].body = append(ctxs[len(ctxs)-1].body, t)
		default:
			ctxs = append(ctxs, block{head: t})
		}
	}
	/* a line without a body is a root line */
	var out []block
	for _, b := range ctxs {
		if len(b.body) == 0 {
			root = append(root, b.head)
		} else {
			out = append(out, b)
		}
	}
	return root, out
}

func firstWord(l string) string {
	w, _, _ := strings.Cut(strings.TrimPrefix(l, "no "), " ")
	return w
}

/*
negate is the line that drops l in mode m: "no" and the longest prefix of
l the grammar knows as a command ("description x" -> "no description"),
else "no <l>" (which the dry-run's walk then refuses as unknown).
*/
func (b Base) negate(l string, m core.Mode) string {
	if n, ok := strings.CutPrefix(l, "no "); ok {
		return n
	}
	ws := strings.Fields(l)
	for k := len(ws); k >= 1; k-- {
		c := "no " + strings.Join(ws[:k], " ")
		if v := b.G.Classify(c, m, core.Context{}); v.Reason == core.ReasonGrammar && (v.Class == core.Safe || v.Class == core.Dangerous) {
			return c
		}
	}
	return "no " + l
}

/* diff is the lines that turn have into want in mode m: removals first (unless want sets the same first word again), then additions. */
func (b Base) diff(have, want []string, m core.Mode) []string {
	var out []string
	for _, l := range have {
		if !slices.Contains(want, l) && !slices.ContainsFunc(want, func(w string) bool { return firstWord(w) == firstWord(l) }) {
			out = append(out, b.negate(l, m))
		}
	}
	for _, l := range want {
		if !slices.Contains(have, l) {
			out = append(out, l)
		}
	}
	return out
}

/* Plan is the Planner of every line (see Planner). */
func (b Base) Plan(from, to Config) ([]string, error) {
	cfg := "configure"
	if b.L == strategy.MES10 {
		cfg = "configure terminal"
	}
	conf := b.G.Next(cfg, b.G.Root())
	fr, fc := blocks(from.Text)
	tr, tc := blocks(to.Text)
	body := b.diff(fr, tr, conf)
	find := func(bs []block, head string) (block, bool) {
		i := slices.IndexFunc(bs, func(x block) bool { return x.head == head })
		if i < 0 {
			return block{}, false
		}
		return bs[i], true
	}
	for _, t := range tc {
		f, _ := find(fc, t.head)
		if d := b.diff(f.body, t.body, b.G.Next(t.head, conf)); len(d) > 0 {
			body = append(append(append(body, t.head), d...), "exit")
		}
	}
	for _, f := range fc {
		if _, ok := find(tc, f.head); !ok {
			body = append(body, b.negate(f.head, conf))
		}
	}
	if len(body) == 0 {
		return nil, nil
	}
	return append(append([]string{cfg}, body...), "end"), nil
}
