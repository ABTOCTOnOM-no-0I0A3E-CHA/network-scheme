package triggers

import (
	"context"
	"maps"
)

/* StepAll runs one full evaluation round (every stream, configuration reload and system checks). */
func (e *Engine) StepAll(ctx context.Context) error { return e.cycle(ctx, cycleAll) }

/* StepFast runs a round of the 5-second kind only (availability and events, no configuration reload). */
func (e *Engine) StepFast(ctx context.Context) error { return e.cycle(ctx, cycleFast) }

/* LockKey exposes the advisory lock key to the lock test. */
const LockKey = lockKey

/* SetPaging shrinks the read sizes; it returns a function that restores them. */
func SetPaging(samplePageN, samplePagesN, seqRangeN, maxRangesN int) func() {
	a, b, c, d := samplePage, samplePages, seqRange, maxRanges
	samplePage, samplePages, seqRange, maxRanges = samplePageN, samplePagesN, seqRangeN, maxRangesN
	return func() { samplePage, samplePages, seqRange, maxRanges = a, b, c, d }
}

/* ExecutorSeverity is the fixed severity of each executor alert kind with a problem kind of its own. */
func ExecutorSeverity() map[string]string { return maps.Clone(executorSeverity) }

/* AfterLoad installs a hook that runs after a round loaded the open problems (to interleave another engine). */
func (e *Engine) AfterLoad(f func()) { e.afterLoad = f }
