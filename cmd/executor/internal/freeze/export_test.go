package freeze

import "time"

/* SetAlertRetryEvery shortens the alert retry interval for a test and returns the restore function. */
func SetAlertRetryEvery(d time.Duration) (restore func()) {
	old := alertRetryEvery
	alertRetryEvery = d
	return func() { alertRetryEvery = old }
}

/* Latch sets the latch alone (no alert, no record), as a concurrent freeze would first. */
func Latch(g *Guard, reason string) { g.latch(reason) }
