package textdiff

import (
	"errors"
	"math/rand"
	"strings"
	"testing"
)

func TestUnifiedGolden(t *testing.T) {
	a := "l1\nl2\nl3\nl4\nl5\nl6\nl7\nl8\nl9\nl10\nl11\nl12\n"
	b := "l1\nl2\nL3\nl4\nl5\nl6\nl7\nl8\nl9\nl10\nl11\nl12\nl13\n"
	got, err := Unified("a", "b", a, b, 2, 100)
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
		if d, err := Unified("a", "b", c[0], c[1], 3, 10); err != nil || d != "" {
			t.Errorf("%q vs %q: %q, %v", c[0], c[1], d, err)
		}
	}
	d, err := Unified("a", "b", "", "x\n", 3, 10)
	if err != nil || d != "--- a\n+++ b\n@@ -0,0 +1 @@\n+x\n" {
		t.Errorf("from empty: %q, %v", d, err)
	}
	d, err = Unified("a", "b", "x\n", "", 3, 10)
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
		ops, err := myers(a, b, 100)
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
	if _, err := Unified("a", "b", a.String(), b.String(), 3, 100); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if _, err := Unified("a", "b", a.String(), b.String(), 3, 400); err != nil {
		t.Fatal(err)
	}
}
