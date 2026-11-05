package devemu

import (
	"fmt"
	"strings"
)

/*
node is one configuration line. A context line (one that opens a sub-mode)
has children and an exit line; the root has neither. raw keeps the line as it
was read or typed with its indentation, so an unchanged configuration prints
exactly as the fixture.
*/
type node struct {
	text     string /* trimmed line */
	raw      string /* printed line; empty for the root */
	mode     string /* sub-mode of a context line; "" for a plain line */
	children []*node
	exitRaw  string /* printed exit line; empty: the profile's */
}

/* parseConfig reads a configuration: context lines open sub-modes, the profile's exit line closes them. */
func parseConfig(p *Profile, text string) (*node, error) {
	root := &node{mode: "config"}
	stack := []*node{root}
	for _, raw := range strings.Split(strings.TrimRight(normalizeNL(text), "\n"), "\n") {
		t := strings.TrimSpace(raw)
		top := stack[len(stack)-1]
		switch {
		case t == p.Config.Exit.Text && len(stack) > 1:
			top.exitRaw = raw
			stack = stack[:len(stack)-1]
		case t == "" || len(stack) == 1 && p.comment(t):
			root.children = append(root.children, &node{text: t, raw: raw})
		default:
			n := &node{text: t, raw: raw, mode: p.context(t)}
			top.children = append(top.children, n)
			if n.mode != "" {
				stack = append(stack, n)
			}
		}
	}
	if len(stack) > 1 {
		return nil, fmt.Errorf("context %q is not closed by %q", stack[len(stack)-1].text, p.Config.Exit.Text)
	}
	return root, nil
}

func (p *Profile) comment(t string) bool {
	for _, c := range strings.Fields(p.Config.Comment.Text) {
		if strings.HasPrefix(t, c) {
			return true
		}
	}
	return false
}

/* render prints the configuration. */
func (p *Profile) render(root *node) string {
	var b strings.Builder
	var walk func(n *node, depth int)
	walk = func(n *node, depth int) {
		for _, c := range n.children {
			raw := c.raw
			if raw == "" {
				raw = strings.Repeat(p.Config.Indent.Text, depth) + c.text
			}
			b.WriteString(raw + "\n")
			if c.mode == "" {
				continue
			}
			walk(c, depth+1)
			ex := c.exitRaw
			if ex == "" {
				d := depth
				if p.Config.ExitIndent == "child" {
					d++
				}
				ex = strings.Repeat(p.Config.Indent.Text, d) + p.Config.Exit.Text
			}
			b.WriteString(ex + "\n")
		}
	}
	walk(root, 0)
	return strings.TrimRight(b.String(), "\n")
}

func (n *node) clone() *node {
	c := *n
	c.children = make([]*node, len(n.children))
	for i, ch := range n.children {
		c.children[i] = ch.clone()
	}
	return &c
}

/* find returns the child context with exactly this line. */
func (n *node) find(text string) *node {
	for _, c := range n.children {
		if c.mode != "" && c.text == text {
			return c
		}
	}
	return nil
}

/* enter returns the child context for line, creating it. */
func (n *node) enter(text, mode string) *node {
	if c := n.find(text); c != nil {
		return c
	}
	c := &node{text: text, mode: mode}
	n.children = append(n.children, c)
	return c
}

/*
set adds a plain line. A line that shares all but its last word with an
existing plain line replaces it ("description b" replaces "description a");
an identical line is kept once. This approximates single-valued settings;
real devices also merge list values, which the emulator does not model.
*/
func (n *node) set(text string) {
	w := strings.Fields(text)
	for _, c := range n.children {
		if c.mode != "" {
			continue
		}
		if c.text == text {
			return
		}
		cw := strings.Fields(c.text)
		if len(w) > 1 && len(cw) == len(w) && strings.Join(cw[:len(cw)-1], " ") == strings.Join(w[:len(w)-1], " ") {
			c.text, c.raw = text, ""
			return
		}
	}
	n.children = append(n.children, &node{text: text})
}

/*
remove handles "no <text>": a context with exactly this line goes with its
subtree; otherwise every plain line whose words start with text's words goes.
It reports whether anything was removed.
*/
func (n *node) remove(text string) bool {
	w := strings.Fields(text)
	kept := n.children[:0]
	removed := false
	for _, c := range n.children {
		cw := strings.Fields(c.text)
		hit := c.text == text || c.mode == "" && len(cw) >= len(w) && strings.Join(cw[:len(w)], " ") == strings.Join(w, " ")
		if hit && len(w) > 0 {
			removed = true
			continue
		}
		kept = append(kept, c)
	}
	n.children = kept
	return removed
}

/* path returns the node at the context path (lines from the root), or nil. */
func (n *node) path(lines []string) *node {
	cur := n
	for _, l := range lines {
		if cur = cur.find(l); cur == nil {
			return nil
		}
	}
	return cur
}

/* diff prints the lines of b missing from a with "+" and of a missing from b with "-" (ESR "show configuration changes"). */
func (p *Profile) diff(a, b *node) string {
	al, bl := strings.Split(p.render(a), "\n"), strings.Split(p.render(b), "\n")
	in := func(s string, l []string) bool {
		for _, x := range l {
			if x == s {
				return true
			}
		}
		return false
	}
	var out []string
	for _, l := range al {
		if !in(l, bl) && strings.TrimSpace(l) != p.Config.Exit.Text {
			out = append(out, "-"+l)
		}
	}
	for _, l := range bl {
		if !in(l, al) && strings.TrimSpace(l) != p.Config.Exit.Text {
			out = append(out, "+"+l)
		}
	}
	return strings.Join(out, "\n")
}
