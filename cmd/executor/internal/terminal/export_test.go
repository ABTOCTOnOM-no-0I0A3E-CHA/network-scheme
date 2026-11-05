package terminal

/* Unlimited lifts the frame and authz rates for a test that types thousands of lines (the limits have their own test). */
func Unlimited() func() {
	fr, fb, ar, ab := frameRate, frameBurst, authzRate, authzBurst
	frameRate, frameBurst, authzRate, authzBurst = 1e6, 1e6, 1e6, 1e6
	return func() { frameRate, frameBurst, authzRate, authzBurst = fr, fb, ar, ab }
}
