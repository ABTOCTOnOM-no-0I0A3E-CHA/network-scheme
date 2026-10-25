package textdiff

import (
	"context"
	"errors"
	"math/rand"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestUnifiedGolden(t *testing.T) {
	a := "l1\nl2\nl3\nl4\nl5\nl6\nl7\nl8\nl9\nl10\nl11\nl12\n"
	b := "l1\nl2\nL3\nl4\nl5\nl6\nl7\nl8\nl9\nl10\nl11\nl12\nl13\n"
	got, err := Unified(context.Background(), "a", "b", a, b, 2, 100)
	if err != nil {
		t.Fatal(err)
	}
	want := "--- a\n+++ b\n" +
		"@@ -1,5 +1,5 @@\n l1\n l2\n-l3\n+L3\n l4\n l5\n" +
		"@@ -11,2 +11,3 @@\n l11\n l12\n+l13\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestUnifiedEqualAndEmpty(t *testing.T) {
	for _, c := range [][2]string{{"", ""}, {"x\ny\n", "x\ny\n"}} {
		if d, err := Unified(context.Background(), "a", "b", c[0], c[1], 3, 10); err != nil || d != "" {
			t.Errorf("%q vs %q: %q, %v", c[0], c[1], d, err)
		}
	}
	d, err := Unified(context.Background(), "a", "b", "", "x\n", 3, 10)
	if err != nil || d != "--- a\n+++ b\n@@ -0,0 +1 @@\n+x\n" {
		t.Errorf("from empty: %q, %v", d, err)
	}
	d, err = Unified(context.Background(), "a", "b", "x\n", "", 3, 10)
	if err != nil || d != "--- a\n+++ b\n@@ -1 +0,0 @@\n-x\n" {
		t.Errorf("to empty: %q, %v", d, err)
	}
}

/* lcs is the reference: the length of the longest common subsequence. */
func lcs(a, b []int32) int {
	dp := make([][]int, len(a)+1)
	for i := range dp {
		dp[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else {
				dp[i][j] = max(dp[i+1][j], dp[i][j+1])
			}
		}
	}
	return dp[0][0]
}

/* TestMyersMinimalAndValid: the script rebuilds b from a and has the minimal number of edits. */
func TestMyersMinimalAndValid(t *testing.T) {
	rnd := rand.New(rand.NewSource(1))
	for i := 0; i < 500; i++ {
		a := make([]int32, rnd.Intn(30))
		b := make([]int32, rnd.Intn(30))
		for j := range a {
			a[j] = int32(rnd.Intn(4))
		}
		for j := range b {
			b[j] = int32(rnd.Intn(4))
		}
		ops, err := myers(context.Background(), a, b, 100)
		if err != nil {
			t.Fatal(err)
		}
		var out []int32
		edits := len(ops)
		/* Interleave the untouched lines of a: replay the script against a. */
		ai := 0
		for _, o := range ops {
			for ai < o.ai {
				out = append(out, a[ai])
				ai++
			}
			if o.kind == opDelete {
				ai++
			} else {
				out = append(out, b[o.bi])
			}
		}
		out = append(out, a[ai:]...)
		if len(out) != len(b) {
			t.Fatalf("rebuilt %v from %v, want %v", out, a, b)
		}
		for j := range out {
			if out[j] != b[j] {
				t.Fatalf("rebuilt %v from %v, want %v", out, a, b)
			}
		}
		if want := len(a) + len(b) - 2*lcs(a, b); edits != want {
			t.Fatalf("%d edits, minimal %d for %v -> %v", edits, want, a, b)
		}
	}
}

func TestUnifiedTooManyEdits(t *testing.T) {
	var a, b strings.Builder
	for i := 0; i < 200; i++ {
		a.WriteString("a" + strings.Repeat("x", i) + "\n")
		b.WriteString("b" + strings.Repeat("y", i) + "\n")
	}
	if _, err := Unified(context.Background(), "a", "b", a.String(), b.String(), 3, 100); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if _, err := Unified(context.Background(), "a", "b", a.String(), b.String(), 3, 400); err != nil {
		t.Fatal(err)
	}
}

/* TestUnifiedNoNewlineAtEOF: a missing final newline is a change of its own, marked as diff(1) does. */
func TestUnifiedNoNewlineAtEOF(t *testing.T) {
	for _, c := range []struct{ a, b, want string }{
		{"a", "a\n", "--- a\n+++ b\n@@ -1 +1 @@\n-a\n" + noEOL + "+a\n"},
		{"a\n", "a", "--- a\n+++ b\n@@ -1 +1 @@\n-a\n+a\n" + noEOL},
		{"x\na", "y\na", "--- a\n+++ b\n@@ -1,2 +1,2 @@\n-x\n+y\n a\n" + noEOL},
	} {
		got, err := Unified(context.Background(), "a", "b", c.a, c.b, 3, 10)
		if err != nil || got != c.want {
			t.Errorf("%q vs %q:\n%s(%v)\nwant:\n%s", c.a, c.b, got, err, c.want)
		}
	}
	if d, err := Unified(context.Background(), "a", "b", "a", "a", 3, 10); err != nil || d != "" {
		t.Errorf("equal without newline: %q, %v", d, err)
	}
}

func TestUnifiedTooManyLines(t *testing.T) {
	long := strings.Repeat("\n", MaxLines+1)
	if _, err := Unified(context.Background(), "a", "b", long, "x\n", 3, 10); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
	at := strings.Repeat("\n", MaxLines)
	if d, err := Unified(context.Background(), "a", "b", at, at[1:]+"x", 3, 10); err != nil || !strings.HasSuffix(d, "+x\n"+noEOL) {
		t.Fatalf("at the cap: %q, %v", d, err)
	}
}

/* allocated returns the bytes f allocates. */
func allocated(f func()) uint64 {
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	f()
	runtime.ReadMemStats(&m1)
	return m1.TotalAlloc - m0.TotalAlloc
}

/*
TestUnifiedAllocationBound: a 2 MiB blank-line pair is refused without
splitting, and a text at the line cap with one change allocates in
proportion to its size (not one op per line, no full copy of the output).
*/
func TestUnifiedAllocationBound(t *testing.T) {
	blank := strings.Repeat("\n", 2<<20)
	other := blank[1:] + "x\n"
	if n := allocated(func() {
		if _, err := Unified(context.Background(), "a", "b", blank, other, 3, 2500); !errors.Is(err, ErrTooLarge) {
			t.Errorf("2 MiB blank pair: %v", err)
		}
	}); n > 64<<10 {
		t.Errorf("2 MiB blank pair allocated %d bytes", n)
	}
	a := strings.Repeat("\n", MaxLines-1)
	b := a[:MaxLines/2] + "x\n" + a[MaxLines/2:]
	var d string
	n := allocated(func() {
		var err error
		if d, err = Unified(context.Background(), "a", "b", a, b, 3, 2500); err != nil {
			t.Error(err)
		}
	})
	if !strings.Contains(d, "\n+x\n") || len(d) > 200 {
		t.Errorf("diff %q", d)
	}
	/* two line slices (16 B per line each) and two id slices (4 B per line each) */
	if limit := uint64(MaxLines * 48); n > limit {
		t.Errorf("allocated %d bytes, want at most %d", n, limit)
	}
}

/* apply applies a unified diff made by Unified to a, checking every context and deleted line. */
func apply(t *testing.T, a, d string) string {
	t.Helper()
	if d == "" {
		return a
	}
	src := split(a).lines
	var out []string
	ai, eol := 0, strings.HasSuffix(a, "\n") || a == ""
	ls := strings.Split(strings.TrimSuffix(d, "\n"), "\n")[2:]
	for i := 0; i < len(ls); i++ {
		l := ls[i]
		if strings.HasPrefix(l, "@@ ") {
			var as, ac, bs, bc int
			f := strings.Fields(l)
			parse := func(s string) (int, int) {
				p := strings.SplitN(s[1:], ",", 2)
				start, _ := strconv.Atoi(p[0])
				if len(p) == 1 {
					return start - 1, 1
				}
				n, _ := strconv.Atoi(p[1])
				if n == 0 {
					return start, 0
				}
				return start - 1, n
			}
			as, ac = parse(f[1])
			bs, bc = parse(f[2])
			_, _ = ac, bc
			if bs != len(out)+(as-ai) {
				t.Fatalf("hunk %q starts at b %d, have %d", l, bs, len(out)+(as-ai))
			}
			if as > ai {
				out = append(out, src[ai:as]...)
				eol = as < len(src) || strings.HasSuffix(a, "\n")
			}
			ai = as
			continue
		}
		noeol := i+1 < len(ls) && ls[i+1] == strings.TrimSuffix(noEOL, "\n")
		if noeol {
			i++
		}
		switch l[0] {
		case ' ', '-':
			if src[ai] != l[1:] {
				t.Fatalf("line %d is %q, diff says %q", ai, src[ai], l)
			}
			if l[0] == ' ' {
				out = append(out, l[1:])
				eol = !noeol
			}
			ai++
		case '+':
			out = append(out, l[1:])
			eol = !noeol
		}
	}
	if ai < len(src) {
		out = append(out, src[ai:]...)
		eol = strings.HasSuffix(a, "\n")
	}
	s := strings.Join(out, "\n")
	if len(out) > 0 && eol {
		s += "\n"
	}
	return s
}

/* TestUnifiedApplies: random texts (with and without a final newline) diff into hunks that rebuild b from a. */
func TestUnifiedApplies(t *testing.T) {
	rnd := rand.New(rand.NewSource(2))
	text := func() string {
		var sb strings.Builder
		n := rnd.Intn(40)
		for i := 0; i < n; i++ {
			sb.WriteString(string(rune('a' + rnd.Intn(3))))
			if i < n-1 || rnd.Intn(2) == 0 {
				sb.WriteByte('\n')
			}
		}
		return sb.String()
	}
	for i := 0; i < 2000; i++ {
		a, b := text(), text()
		ctx := rnd.Intn(4)
		d, err := Unified(context.Background(), "a", "b", a, b, ctx, 200)
		if err != nil {
			t.Fatal(err)
		}
		if got := apply(t, a, d); got != b {
			t.Fatalf("context %d: %q -> %q\n%s\nrebuilt %q", ctx, a, b, d, got)
		}
	}
}

/* A cancelled context stops the search with the context's error. */
func TestUnifiedCancelled(t *testing.T) {
	var a, b strings.Builder
	for i := range 1000 {
		a.WriteString("a" + strconv.Itoa(i) + "\n")
		b.WriteString("b" + strconv.Itoa(i) + "\n")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Unified(ctx, "a", "b", a.String(), b.String(), 3, 2500); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
}
