package triggers

import "context"

/* StepAll runs one full evaluation round (every stream, configuration reload and system checks). */
func (e *Engine) StepAll(ctx context.Context) error { return e.cycle(ctx, cycleAll) }

/* StepFast runs a round of the 5-second kind only (availability and events, no configuration reload). */
func (e *Engine) StepFast(ctx context.Context) error { return e.cycle(ctx, cycleFast) }

/* LockKey exposes the advisory lock key to the lock test. */
const LockKey = lockKey
