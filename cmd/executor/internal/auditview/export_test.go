package auditview

/* SetViewsPerHour sets the hourly bound of views for a test and returns its restore. */
func SetViewsPerHour(n int) (restore func()) {
	old := viewsPerHour
	viewsPerHour = n
	return func() { viewsPerHour = old }
}
