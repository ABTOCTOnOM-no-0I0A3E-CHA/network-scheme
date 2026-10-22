package trap

import (
	"strconv"
	"strings"
)

/* Severities, matching the CHECK on events.trap and events.trap_rule. */
const (
	SevInfo     = "info"
	SevWarning  = "warning"
	SevAverage  = "average"
	SevHigh     = "high"
	SevDisaster = "disaster"
)

/*
Mapped is the named event a trap stands for; IfIndex is 0 when not applicable.
Severity == "" means unknown (unidentified trap) and is stored as SQL NULL.
Name is at most 1024 bytes for traps produced by Normalize (OID bound).
*/
type Mapped struct {
	Name, Severity string
	AffectsState   bool
	IfIndex        int
}

/* Rule is an operator-defined name and severity for a trap OID (events.trap_rule). */
type Rule struct {
	Name, Severity string
}

/* Mapper is implemented by drivers (drivers.Driver); it keeps this package free of a drivers import. */
type Mapper interface {
	MapTrap(Trap) (Mapped, bool)
}

const oidIfIndex = "1.3.6.1.2.1.2.2.1.1."

var standard = map[string]Mapped{
	/* SNMPv2-MIB snmpTraps */
	"1.3.6.1.6.3.1.1.5.1": {Name: "coldStart", Severity: SevWarning, AffectsState: true},
	"1.3.6.1.6.3.1.1.5.2": {Name: "warmStart", Severity: SevInfo, AffectsState: true},
	"1.3.6.1.6.3.1.1.5.3": {Name: "linkDown", Severity: SevAverage, AffectsState: true},
	"1.3.6.1.6.3.1.1.5.4": {Name: "linkUp", Severity: SevInfo, AffectsState: true},
	"1.3.6.1.6.3.1.1.5.5": {Name: "authenticationFailure", Severity: SevWarning},
	/* LLDP-MIB lldpRemTablesChange */
	"1.0.8802.1.1.2.0.0.1": {Name: "lldpRemTablesChange", Severity: SevInfo},
	/* ENTITY-MIB entConfigChange */
	"1.3.6.1.2.1.47.2.0.1": {Name: "entConfigChange", Severity: SevInfo},
	/*
		ENTITY-STATE-MIB (RFC 4268). ENTITY-SENSOR-MIB defines no
		notifications, so power, fan and temperature alarms are vendor traps.
	*/
	"1.3.6.1.2.1.131.0.1": {Name: "entStateOperEnabled", Severity: SevInfo, AffectsState: true},
	"1.3.6.1.2.1.131.0.2": {Name: "entStateOperDisabled", Severity: SevHigh, AffectsState: true},
}

/* Standard maps the traps of standard MIBs; linkUp and linkDown carry ifIndex. */
func Standard(t Trap) (Mapped, bool) {
	m, ok := standard[t.OID]
	if !ok {
		return Mapped{}, false
	}
	if m.Name == "linkUp" || m.Name == "linkDown" {
		m.IfIndex = ifIndex(t)
	}
	return m, true
}

func ifIndex(t Trap) int {
	for _, v := range t.Varbinds {
		if !strings.HasPrefix(v.OID, oidIfIndex) || v.Type != "Integer" {
			continue
		}
		if n, err := strconv.Atoi(v.Value); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

func validSeverity(s string) bool {
	switch s {
	case SevInfo, SevWarning, SevAverage, SevHigh, SevDisaster:
		return true
	}
	return false
}

/*
Map identifies a trap: the driver first, then the standard MIBs, then the
operator rule for the trap OID. A rule never overrides a driver or standard
mapping. An unidentified trap is returned with its OID as Name, no severity
and identified == false. d may be nil.
*/
func Map(d Mapper, t Trap, rules map[string]Rule) (Mapped, bool) {
	if d != nil {
		if m, ok := d.MapTrap(t); ok {
			return m, true
		}
	}
	if m, ok := Standard(t); ok {
		return m, true
	}
	if r, ok := rules[t.OID]; ok && r.Name != "" && validSeverity(r.Severity) {
		return Mapped{Name: r.Name, Severity: r.Severity}, true
	}
	return Mapped{Name: t.OID}, false
}
