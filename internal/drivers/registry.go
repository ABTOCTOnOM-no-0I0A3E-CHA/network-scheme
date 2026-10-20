package drivers

import (
	"slices"
	"strings"
	"sync"
)

/* GenericName is the name of the fallback driver, which matches every device. */
const GenericName = "generic-snmp"

/* rank fixes the selection order: specific drivers first, the fallback last. */
var rank = map[string]int{"eltex-esr": 0, "eltex-mes": 1, GenericName: 1 << 30}

const otherRank = 1 << 20

var (
	regMu      sync.Mutex
	registered []Driver
)

/*
Register adds d to the drivers returned by Default. Driver packages call it
from init, so a binary gets the drivers it imports. It panics on a nil driver
or a duplicate name.
*/
func Register(d Driver) {
	regMu.Lock()
	defer regMu.Unlock()
	if d == nil {
		panic("drivers: Register(nil)")
	}
	for _, x := range registered {
		if x.Name() == d.Name() {
			panic("drivers: duplicate driver " + d.Name())
		}
	}
	registered = append(registered, d)
}

/* Registry selects a driver for a device. */
type Registry struct{ drivers []Driver }

/* NewRegistry returns a registry that tries ds in the given order. */
func NewRegistry(ds ...Driver) *Registry { return &Registry{drivers: slices.Clone(ds)} }

/*
Default returns a registry of every registered driver ordered eltex-esr,
eltex-mes, other drivers by name, then generic-snmp.
*/
func Default() *Registry {
	regMu.Lock()
	ds := slices.Clone(registered)
	regMu.Unlock()
	r := func(d Driver) int {
		if v, ok := rank[d.Name()]; ok {
			return v
		}
		return otherRank
	}
	slices.SortStableFunc(ds, func(a, b Driver) int {
		if ra, rb := r(a), r(b); ra != rb {
			return ra - rb
		}
		return strings.Compare(a.Name(), b.Name())
	})
	return NewRegistry(ds...)
}

/* Select returns the first driver that matches, or nil when none does. */
func (r *Registry) Select(sysObjectID, sysDescr string) Driver {
	for _, d := range r.drivers {
		if d.Match(sysObjectID, sysDescr) {
			return d
		}
	}
	return nil
}
