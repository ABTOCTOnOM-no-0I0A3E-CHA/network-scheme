package testdb

import (
	"errors"
	"fmt"
	"runtime"
	"testing"
)

/* recorder stands in for a test: Skipf and Fatalf record how it ended and stop its goroutine, as the real ones do. */
type recorder struct {
	testing.TB
	ended string
}

func (r *recorder) Helper() {}

func (r *recorder) Skipf(string, ...any) { r.ended = "skip"; runtime.Goexit() }

func (r *recorder) Fatalf(string, ...any) { r.ended = "fail"; runtime.Goexit() }

func ending(ci bool, err error) string {
	r := &recorder{}
	done := make(chan struct{})
	go func() { defer close(done); unavailable(r, ci, err) }()
	<-done
	return r.ended
}

/* Without Docker a test is skipped locally but fails in CI; any other start error always fails. */
func TestUnavailableFailsInCI(t *testing.T) {
	noDocker := fmt.Errorf("%w: refused", errNoDocker)
	for _, c := range []struct {
		ci   bool
		err  error
		want string
	}{
		{false, noDocker, "skip"},
		{true, noDocker, "fail"},
		{false, errors.New("migrations failed"), "fail"},
		{true, errors.New("migrations failed"), "fail"},
	} {
		if got := ending(c.ci, c.err); got != c.want {
			t.Errorf("ci=%v err=%v: %s, want %s", c.ci, c.err, got, c.want)
		}
	}
}
