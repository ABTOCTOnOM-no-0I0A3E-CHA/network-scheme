package admin

/* SetWriteHook replaces the result of every host registry write of a (an error after a COMMIT, for the tests). */
func SetWriteHook(a *Admin, h func(error) error) { a.writeHook = h }
