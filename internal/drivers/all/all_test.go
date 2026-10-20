package all

import (
	"testing"

	"github.com/beekamai/network-scheme/internal/drivers"
)

func TestDefaultHasGenericFallback(t *testing.T) {
	d := drivers.Default().Select("1.3.6.1.4.1.32473.99", "Unknown device")
	if d == nil || d.Name() != drivers.GenericName {
		t.Fatalf("selected %v", d)
	}
}
