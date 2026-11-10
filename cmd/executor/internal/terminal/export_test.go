package terminal

/* Unlimited lifts the frame and authz rates for a test that types thousands of lines (the limits have their own test). */
func Unlimited() func() {
	fr, fb, ar, ab := frameRate, frameBurst, authzRate, authzBurst
	frameRate, frameBurst, authzRate, authzBurst = 1e6, 1e6, 1e6, 1e6
	return func() { frameRate, frameBurst, authzRate, authzBurst = fr, fb, ar, ab }
}

/* SetMaxOutput bounds one line's output to the browser. */
func SetMaxOutput(n int) (restore func()) {
	old := maxOutput
	maxOutput = n
	return func() { maxOutput = old }
}

/* MaxPreauth is how many connections may wait for their auth frame. */
var MaxPreauth = maxPreauth

/* MaxPreauthIP is how many of them may come from one client address. */
var MaxPreauthIP = maxPreauthIP

/* ClientKey is the pre-auth bound's client key. */
var ClientKey = clientKey
