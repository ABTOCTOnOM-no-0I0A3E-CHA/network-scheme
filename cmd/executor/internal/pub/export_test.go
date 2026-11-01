package pub

import (
	"context"
	"time"
)

/* ConsumeRequest is the appender of a freeze request, for the crash test. */
var ConsumeRequest = consumeRequest

/* Consume runs one consumption of c (errNoRequest when none is pending). */
func (c *Consumer) Consume(ctx context.Context) error { return c.consume(ctx) }

/* ErrNoRequest is errNoRequest. */
var ErrNoRequest = errNoRequest

/* SetPace sets Run's pace for a test and returns the restore function. */
func SetPace(poll, frozen time.Duration) (restore func()) {
	op, of := pollEvery, frozenEvery
	pollEvery, frozenEvery = poll, frozen
	return func() { pollEvery, frozenEvery = op, of }
}
