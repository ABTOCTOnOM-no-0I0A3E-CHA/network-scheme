package all

import (
	"slices"
	"testing"

	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/test/sim/snmpsim/simtest"
)

func TestDefaultHasGenericFallback(t *testing.T) {
	d := drivers.Default().Select("1.3.6.1.4.1.32473.99", "Unknown device")
	if d == nil || d.Name() != drivers.GenericName {
		t.Fatalf("selected %v", d)
	}
}

func TestDefaultSelectsByFixture(t *testing.T) {
	for f, want := range map[string]string{
		"eltex-esr.snmprec":      "eltex-esr",
		"eltex-mes.snmprec":      "eltex-mes",
		"generic-switch.snmprec": drivers.GenericName,
		"generic-router.snmprec": drivers.GenericName,
	} {
		if got := drivers.Default().Select(simtest.FixtureSys(t, f)).Name(); got != want {
			t.Errorf("%s selected %s, want %s", f, got, want)
		}
	}
}

func TestUnverifiedEltexDrivers(t *testing.T) {
	if got := drivers.Unverified(); !slices.Equal(got, []string{"eltex-esr", "eltex-mes"}) {
		t.Fatalf("Unverified() = %v", got)
	}
}
