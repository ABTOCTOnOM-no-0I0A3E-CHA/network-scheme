// Package textdiff computes a unified diff of two texts line by line (Myers' algorithm) with a bound on the work done.
package textdiff

import (
	"errors"
	"strconv"
	"strings"
)

// ErrTooLarge means the texts have more lines or differ in more lines than allowed.
var ErrTooLarge = errors.New("textdiff: texts too large or too different")

// MaxLines is the most lines either text may have; a longer one is ErrTooLarge before any line is split.
const MaxLines = 200_000

/* noEOL follows a line that ends its text without a newline (as diff(1) writes it). */
const noEOL = "\\ No newline at end of file\n"

const (
	opDelete = iota + 1
	opInsert
)

/*
op is one edit: a delete of line ai of a at b position bi, or an insert of
line bi of b at a position ai.
*/
type op struct {
	kind   uint8
	ai, bi int
}

/* text is one side split into lines; eol tells whether the text ends with a newline. */
type text struct {
	lines []string
	eol   bool
}

/*
Unified returns the unified diff of a and b with the given number of context
lines ("" when the texts are equal). nameA and nameB are the header labels.
A text with more than MaxLines lines, or more than maxEdits inserted plus
deleted lines, is ErrTooLarge; that bounds the work to the size of the texts
plus about maxEdits^2 * 2 bytes. Only the edits are kept, not one entry per
line. A missing final newline is a difference of its own and is marked
"\ No newline at end of file".
*/
func Unified(nameA, nameB, a, b string, context, maxEdits int) (string, error) {
	if lineCount(a) > MaxLines || lineCount(b) > MaxLines {
		return "", ErrTooLarge
	}
	ta, tb := split(a), split(b)
	/* A last line without a newline gets an id of its own: "x" and "x\n" differ. */
	ids, last := map[string]int32{}, map[string]int32{}
	toIDs := func(t text) []int32 {
		out := make([]int32, len(t.lines))
		for i, l := range t.lines {
			m := ids
			if i == len(t.lines)-1 && !t.eol {
				m = last
			}
			id, ok := m[l]
			if !ok {
				id = int32(len(ids) + len(last)) //nolint:gosec // at most MaxLines*2 ids
				m[l] = id
			}
			out[i] = id
		}
		return out
	}
	ia, ib := toIDs(ta), toIDs(tb)

	pre := 0
	for pre < len(ia) && pre < len(ib) && ia[pre] == ib[pre] {
		pre++
	}
	suf := 0
	for suf < len(ia)-pre && suf < len(ib)-pre && ia[len(ia)-1-suf] == ib[len(ib)-1-suf] {
		suf++
	}
	edits, err := myers(ia[pre:len(ia)-suf], ib[pre:len(ib)-suf], maxEdits)
	if err != nil || len(edits) == 0 {
		return "", err
	}
	for i := range edits {
		edits[i].ai += pre
		edits[i].bi += pre
	}
	return format(nameA, nameB, ta, tb, edits, context), nil
}

/* lineCount is the number of lines split returns, without splitting. */
func lineCount(s string) int {
	n := strings.Count(s, "\n")
	if s != "" && !strings.HasSuffix(s, "\n") {
		n++
	}
	return n
}

/* split splits on \n; a final newline does not start another line. */
func split(s string) text {
	if s == "" {
		return text{eol: true}
	}
	eol := strings.HasSuffix(s, "\n")
	return text{strings.Split(strings.TrimSuffix(s, "\n"), "\n"), eol}
}

/* myers returns the edit script (deletes and inserts only) turning a into b, or ErrTooLarge. */
func myers(a, b []int32, maxD int) ([]op, error) {
	n, m := len(a), len(b)
	if n == 0 && m == 0 {
		return nil, nil
	}
	limit := min(n+m, maxD)
	off := limit + 1
	v := make([]int, 2*limit+3)
	/* trace[d] is v before round d, for k in [-d-1, d+1] */
	trace := make([][]int32, 0, 64)
	found := false
	for d := 0; d <= limit && !found; d++ {
		w := make([]int32, 2*d+3)
		for k := -d - 1; k <= d+1; k++ {
			w[k+d+1] = int32(v[off+k]) //nolint:gosec // a line index
		}
		trace = append(trace, w)
		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || (k != d && v[off+k-1] < v[off+k+1]) {
				x = v[off+k+1]
			} else {
				x = v[off+k-1] + 1
			}
			y := x - k
			for x < n && y < m && a[x] == b[y] {
				x++
				y++
			}
			v[off+k] = x
			if x >= n && y >= m {
				found = true
				break
			}
		}
	}
	if !found {
		return nil, ErrTooLarge
	}
	var rev []op
	x, y := n, m
	for d := len(trace) - 1; d >= 0; d-- {
		w := trace[d]
		k := x - y
		var pk int
		if k == -d || (k != d && w[k-1+d+1] < w[k+1+d+1]) {
			pk = k + 1
		} else {
			pk = k - 1
		}
		px := int(w[pk+d+1])
		py := px - pk
		for x > px && y > py {
			x--
			y--
		}
		if d > 0 {
			if x == px {
				y--
				rev = append(rev, op{opInsert, x, y})
			} else {
				x--
				rev = append(rev, op{opDelete, x, y})
			}
		}
		x, y = px, py
	}
	out := make([]op, len(rev))
	for i, o := range rev {
		out[len(rev)-1-i] = o
	}
	return out, nil
}

/* after returns the a and b positions just past edit o. */
func after(o op) (int, int) {
	if o.kind == opDelete {
		return o.ai + 1, o.bi
	}
	return o.ai, o.bi + 1
}

/* format renders the edits as unified hunks; the equal lines between them are read from the texts. */
func format(nameA, nameB string, ta, tb text, edits []op, context int) string {
	var sb strings.Builder
	sb.WriteString("--- " + nameA + "\n+++ " + nameB + "\n")
	line := func(prefix byte, t text, i int) {
		sb.WriteByte(prefix)
		sb.WriteString(t.lines[i])
		sb.WriteByte('\n')
		if i == len(t.lines)-1 && !t.eol {
			sb.WriteString(noEOL)
		}
	}
	for i := 0; i < len(edits); {
		/* the hunk takes edits[i:j]: the next edit joins while at most 2*context equal lines separate them */
		j := i + 1
		for j < len(edits) {
			pa, _ := after(edits[j-1])
			if edits[j].ai-pa > 2*context {
				break
			}
			j++
		}
		first := edits[i]
		aStart := max(first.ai-context, 0)
		bStart := first.bi - (first.ai - aStart)
		la, lb := after(edits[j-1])
		aEnd := min(la+context, len(ta.lines))
		bEnd := lb + (aEnd - la)
		sb.WriteString("@@ -" + rng(aStart, aEnd-aStart) + " +" + rng(bStart, bEnd-bStart) + " @@\n")
		ac, bc := aStart, bStart
		for _, o := range edits[i:j] {
			for ac < o.ai {
				line(' ', ta, ac)
				ac++
				bc++
			}
			if o.kind == opDelete {
				line('-', ta, ac)
				ac++
			} else {
				line('+', tb, bc)
				bc++
			}
		}
		for ac < aEnd {
			line(' ', ta, ac)
			ac++
		}
		i = j
	}
	return sb.String()
}

/* rng renders a unified range: 1-based start, count omitted when 1; an empty range starts before the line. */
func rng(start, count int) string {
	switch count {
	case 0:
		return strconv.Itoa(start) + ",0"
	case 1:
		return strconv.Itoa(start + 1)
	}
	return strconv.Itoa(start+1) + "," + strconv.Itoa(count)
}
