package all

import (
	"testing"

	"github.com/beekamai/network-scheme/internal/drivers/eltexesr"
	"github.com/beekamai/network-scheme/internal/drivers/eltexmes"
	"github.com/beekamai/network-scheme/internal/drivers/generic"
	"github.com/beekamai/network-scheme/internal/events/trap"
)

/*
MapTrap takes only the decoded trap, so it cannot reach the network; the
write-isolation check (go list -deps) covers the imports. Fixture OIDs below
are derived from the CISCO-ENVMON-MIB definition (see eltexesr.MapTrap), not
captured from Eltex hardware.
*/
func TestMapTrap(t *testing.T) {
	std := trap.Trap{Version: 2, OID: "1.3.6.1.6.3.1.1.5.3"}
	fan := trap.Trap{Version: 2, OID: "1.3.6.1.4.1.9.9.13.3.0.4"}
	unknown := trap.Trap{Version: 2, OID: "1.3.6.1.4.1.35265.99.0.1"}

	for _, d := range []trap.Mapper{generic.New(), eltexmes.New(), eltexesr.New()} {
		if _, ok := d.MapTrap(std); ok {
			t.Fatalf("%T maps a standard trap; trap.Standard owns those", d)
		}
		if _, ok := d.MapTrap(unknown); ok {
			t.Fatalf("%T maps an unknown trap", d)
		}
		if _, ok := d.MapTrap(trap.Trap{}); ok {
			t.Fatalf("%T maps an empty trap", d)
		}
	}
	if _, ok := generic.New().MapTrap(fan); ok {
		t.Fatal("generic-snmp maps a vendor trap")
	}
	if _, ok := eltexmes.New().MapTrap(fan); ok {
		t.Fatal("eltex-mes maps an undocumented trap")
	}
	m, ok := eltexesr.New().MapTrap(fan)
	if !ok || m.Name != "envMonFanAlarm" || m.Severity != trap.SevHigh {
		t.Fatalf("eltex-esr fan: %+v %v", m, ok)
	}
	if got, ok := trap.Map(eltexesr.New(), fan, nil); !ok || got != m {
		t.Fatalf("Map via driver: %+v %v", got, ok)
	}
}
