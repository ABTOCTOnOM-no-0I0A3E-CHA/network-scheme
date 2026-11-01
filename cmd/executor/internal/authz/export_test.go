package authz

import "time"

/* SetAbortWrite makes every decision's write fail (not committed) with what f returns, after the outcome was declared. */
func SetAbortWrite(a *Authorizer, f func() error) { a.abortWrite = f }

/* SetAfterWrite replaces the result of every decision's write (an error after a COMMIT: outcome unknown). */
func SetAfterWrite(a *Authorizer, f func(error) error) { a.afterWrite = f }

/* SetBeforeDecide runs f in every decision once it holds the decision lock, before the registry write. */
func SetBeforeDecide(a *Authorizer, f func()) { a.beforeDecide = f }

/* SetNoTrigger skips the freeze after a tripped window (as a crash right after the COMMIT would). */
func SetNoTrigger(a *Authorizer, on bool) { a.noTrigger = on }

/* SetMono replaces the monotonic clock of the nonce cache. */
func SetMono(a *Authorizer, f func() time.Duration) { a.mono = f }

/* SetNonceCap shrinks the nonce cache. */
func SetNonceCap(a *Authorizer, n int) { a.nonceCap = n }
