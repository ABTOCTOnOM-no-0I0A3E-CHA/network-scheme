package httpapi

import "time"

/* SetBeforeBackgroundBody installs a hook run before the first chunk of a background download; nil removes it. */
func SetBeforeBackgroundBody(f func()) { beforeBackgroundBody = f }

/* SetExportTimeout sets the statement limit of inventory exports and returns a function restoring the previous one. */
func SetExportTimeout(d time.Duration) (restore func()) {
	prev := exportTimeout
	exportTimeout = d
	return func() { exportTimeout = prev }
}
