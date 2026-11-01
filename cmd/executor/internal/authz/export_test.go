package authz

/* SetAbortWrite makes every decision's write fail (not committed) with what f returns, after the outcome was declared. */
func SetAbortWrite(a *Authorizer, f func() error) { a.abortWrite = f }

/* SetAfterWrite replaces the result of every decision's write (an error after a COMMIT: outcome unknown). */
func SetAfterWrite(a *Authorizer, f func(error) error) { a.afterWrite = f }
