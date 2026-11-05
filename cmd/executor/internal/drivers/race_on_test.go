//go:build race

package drivers_test

/* raceEnabled: the race detector instruments allocations, so allocation counts are not meaningful under -race. */
const raceEnabled = true
