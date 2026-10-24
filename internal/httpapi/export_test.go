package httpapi

/* SetBeforeBackgroundBody installs a hook run before the first chunk of a background download; nil removes it. */
func SetBeforeBackgroundBody(f func()) { beforeBackgroundBody = f }
