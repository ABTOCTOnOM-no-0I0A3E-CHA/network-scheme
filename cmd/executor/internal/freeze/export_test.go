package freeze

import "time"

/* SetAlertRetryEvery shortens the alert retry interval for a test and returns the restore function. */
func SetAlertRetryEvery(d time.Duration) (restore func()) {
	old := alertRetryEvery
	alertRetryEvery = d
	return func() { alertRetryEvery = old }
}
