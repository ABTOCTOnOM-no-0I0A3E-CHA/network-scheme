// Package textdiff computes a unified diff of two texts line by line (Myers' algorithm) with a bound on the work done.
package textdiff

import (
	"errors"
	"strconv"
	"strings"
)

// ErrTooLarge means the texts differ in more lines than the caller allows.
var ErrTooLarge = errors.New("textdiff: too many differing lines")

const (
	opEqual = iota
	opDelete
	opInsert
)

type op struct {
	kind   uint8
	ai, bi int /* line index in a (equal, delete) and in b (equal, insert) */
}

/*
Unified returns the unified diff of a and b with the given number of context
lines ("" when the texts are equal). nameA and nameB are the header labels.
At most maxEdits inserted plus deleted lines are computed; beyond that the
result is ErrTooLarge, which bounds time and memory (about maxEdits^2 * 4
bytes in the worst case).
*/
func Unified(nameA, nameB, a, b string, context, maxEdits int) (string, error) {
	la, lb := lines(a), lines(b)
	ids := map[string]int32{}
	toIDs := func(ls []string) []int32 {
		out := make([]int32, len(ls))
		for i, l := range ls {
			id, ok := ids[l]
			if !ok {
				id = int32(len(ids)) //nolint:gosec // at most one id per line of a text of a few MiB
				ids[l] = id
			}
			out[i] = id
		}
		return out
	}
	ia, ib := toIDs(la), toIDs(lb)

	pre := 0
	for pre < len(ia) && pre < len(ib) && ia[pre] == ib[pre] {
		pre++
	}
	suf := 0
	for suf < len(ia)-pre && suf < len(ib)-pre && ia[len(ia)-1-suf] == ib[len(ib)-1-suf] {
		suf++
	}
	mid, err := myers(ia[pre:len(ia)-suf], ib[pre:len(ib)-suf], maxEdits)
	if err != nil {
		return "", err
	}
	if len(mid) == 0 {
		return "", nil
	}
	/* Fill the untouched lines between the edits (and around them) with equal ops. */
	ops := make([]op, 0, len(ia)+len(mid))
	ai, bi := 0, 0
	for _, o := range mid {
		o.ai += pre
		for ai < o.ai {
			ops = append(ops, op{opEqual, ai, bi})
			ai++
			bi++
		}
		if o.kind == opDelete {
			o.bi = bi
			ai++
		} else {
			o.bi += pre
			bi++
		}
		ops = append(ops, o)
	}
	for ai < len(ia) {
		ops = append(ops, op{opEqual, ai, bi})
		ai++
		bi++
	}
	return format(nameA, nameB, la, lb, ops, context), nil
}

/* lines splits on \n; a final newline does not start another line. */
func lines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
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

/* format renders ops as unified hunks. */
func format(nameA, nameB string, la, lb []string, ops []op, context int) string {
	var sb strings.Builder
	sb.WriteString("--- " + nameA + "\n+++ " + nameB + "\n")
	i := 0
	for i < len(ops) {
		for i < len(ops) && ops[i].kind == opEqual {
			i++
		}
		if i == len(ops) {
			break
		}
		start := max(i-context, 0)
		/* extend the hunk while the next change is within 2*context equal lines */
		end := i
		for end < len(ops) {
			j := end
			for j < len(ops) && ops[j].kind != opEqual {
				j++
			}
			end = j
			k := j
			for k < len(ops) && ops[k].kind == opEqual {
				k++
			}
			if k == len(ops) || k-j > 2*context {
				end = min(j+context, len(ops))
				break
			}
			end = k
		}
		hunk := ops[start:end]
		aStart, bStart, aCount, bCount := hunk[0].ai, hunk[0].bi, 0, 0
		for _, o := range hunk {
			if o.kind != opInsert {
				aCount++
			}
			if o.kind != opDelete {
				bCount++
			}
		}
		sb.WriteString("@@ -" + rng(aStart, aCount) + " +" + rng(bStart, bCount) + " @@\n")
		for _, o := range hunk {
			switch o.kind {
			case opEqual:
				sb.WriteString(" " + la[o.ai] + "\n")
			case opDelete:
				sb.WriteString("-" + la[o.ai] + "\n")
			default:
				sb.WriteString("+" + lb[o.bi] + "\n")
			}
		}
		i = end
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
