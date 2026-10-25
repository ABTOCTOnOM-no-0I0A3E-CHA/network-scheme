package generic

import (
	"testing"

	"github.com/beekamai/network-scheme/internal/drivers"
)

func TestPortKind(t *testing.T) {
	for _, c := range []struct {
		ifType uint64
		name   string
		speed  uint64
		want   drivers.PortKind
	}{
		{6, "gi1/0/1", 1e9, drivers.PortRJ45},
		{6, "Gi1/0/1", 1e8, drivers.PortRJ45},
		{6, "te1/0/1", 1e9, drivers.PortSFP},
		{6, "tengigabitethernet 1/0/1", 0, drivers.PortSFP},
		{6, "gi1/0/25", 10_000_000_000, drivers.PortSFP},
		{6, "SFP+ port 3", 0, drivers.PortSFP},
		{117, "ge0", 1e9, drivers.PortRJ45},
		{53, "vlan10", 0, drivers.PortOther},
		{24, "lo", 0, drivers.PortOther},
		{0, "gi1/0/1", 1e9, drivers.PortOther},
	} {
		if got := portKind(c.ifType, c.name, c.speed); got != c.want {
			t.Errorf("portKind(%d, %q, %d) = %q, want %q", c.ifType, c.name, c.speed, got, c.want)
		}
	}
}
