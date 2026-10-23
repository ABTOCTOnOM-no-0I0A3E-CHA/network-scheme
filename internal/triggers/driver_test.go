package triggers

import (
	"testing"

	"github.com/beekamai/network-scheme/internal/drivers"
)

func TestFallbackDriverName(t *testing.T) {
	if fallbackDriver != drivers.GenericName {
		t.Fatalf("fallbackDriver %q, drivers.GenericName %q", fallbackDriver, drivers.GenericName)
	}
	for in, want := range map[string]string{"auto": drivers.GenericName, "": drivers.GenericName, "eltex-mes": "eltex-mes"} {
		if got := effectiveDriver(in); got != want {
			t.Errorf("effectiveDriver(%q) = %q, want %q", in, got, want)
		}
	}
}
