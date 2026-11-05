package eltexmes

import (
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/internal/drivers"
)

func TestLineOf(t *testing.T) {
	for _, c := range []struct {
		model, firmware string
		want            Line
	}{
		{"MES2324", "6.6.2", LineMES6},
		{"MES2324P", "", LineMES6},
		{"MES5324", "6.6.10", LineMES6},
		{"MES-3324F", "", LineMES6},
		{"MES5500-32", "", LineMES6},
		{"MES2424", "10.4.5.2", LineMES10},
		{"MES3710P", "", LineMES10},
		{"MES1428", "", LineMES10},
		{"MES3400-24", "10.2.1", LineMES10},
		{"", "10.4.5.2", LineMES10},
		{"", "6.6.2", LineMES6},
		/* conservative: disagreement, other versions, unknown series and odd text give no line */
		{"MES2324", "10.4.5.2", LineUnknown},
		{"MES2424", "6.6.2", LineUnknown},
		{"MES2324", "4.0.22", LineUnknown},
		{"MES2424", "2.5.48", LineUnknown},
		{"MES2324", "v6.6.2", LineUnknown},
		{"MES3124F", "", LineUnknown},
		{"MES3124F", "6.6.2", LineMES6},
		{"mes2424", "", LineUnknown},
		{" MES2424", "", LineUnknown},
		{"ESR-20", "", LineUnknown},
		{"", "1.24.0", LineUnknown},
		{"", "61.0", LineUnknown},
		{"", "100.1", LineUnknown},
		{"", " 10.4", LineUnknown},
		{"", "", LineUnknown},
		{"MES2424" + strings.Repeat("x", 300), "", LineUnknown},
		{"", "10.4" + strings.Repeat("x", 300), LineUnknown},
	} {
		if got := lineOf(drivers.Identity{Model: c.model, Firmware: c.firmware}); got != c.want {
			t.Errorf("lineOf(%.20q, %.20q) = %q, want %q", c.model, c.firmware, got, c.want)
		}
	}
}

func TestForIdentityKeepsTheDriver(t *testing.T) {
	d, ok := drivers.ForIdentity(New(), drivers.Identity{Model: "MES2424", Firmware: "10.4.5.2"}).(Driver)
	if !ok || d.line != LineMES10 || d.Name() != Name || d.Verified() {
		t.Fatalf("specialised driver %+v", d)
	}
	/* the registered driver is not changed by narrowing a copy */
	if New().line != LineUnknown || drivers.Default().ByName(Name).(Driver).line != LineUnknown {
		t.Fatal("registered driver has a line")
	}
	/* identification read again narrows again */
	if d2 := d.ForIdentity(drivers.Identity{Model: "MES2324", Firmware: "6.6.2"}).(Driver); d2.line != LineMES6 {
		t.Fatalf("line = %q", d2.line)
	}
}
