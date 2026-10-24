/*
Package eltexesr is the "eltex-esr" read-only driver for Eltex ESR service
routers. It embeds the generic-snmp driver (interfaces, ARP, routes and the
other standard tables) and adds the resource objects and CLI dialect described
in Eltex's public documentation. Nothing here has been verified on real
hardware yet (see Verified).

Sources (cited per value below):
  - [SMI] ELTEX-SMI-ACTUAL MIB (Eltex, LAST-UPDATED 2012-05-29), as published
    at https://mibs.observium.org/mib/ELTEX-SMI-ACTUAL/
  - [MON] ESR-series Documentation 1.23, "Мониторинг системных параметров"
    (system parameter monitoring over SNMP),
    https://docs.eltex-co.ru/pages/viewpage.action?pageId=485130258
  - [CLI] ESR-Series Documentation 1.11.6, "Правила пользования командной
    строкой" https://docs.eltex-co.ru/pages/viewpage.action?pageId=95420876
    and "Команды пользовательского интерфейса"
    https://docs.eltex-co.ru/pages/viewpage.action?pageId=95420879
*/
package eltexesr

import (
	"context"
	"regexp"
	"strings"

	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/drivers/generic"
	"github.com/beekamai/network-scheme/internal/events/trap"
	"github.com/beekamai/network-scheme/internal/snmp"
	"github.com/beekamai/network-scheme/internal/ssh"
)

const (
	/* Name is the driver name. */
	Name = "eltex-esr"
	/* Verified reports whether OIDs, prompt and commands were checked on a real ESR; not yet. */
	Verified = false
)

const (
	/*
		elHardware, "the root of eltex hardware OIDs". Source: [SMI].
		No Eltex document found lists the ESR sysObjectIDs, so the model is
		recognised by sysDescr (below) under this arc. Not verified on hardware.
	*/
	elHardware = "1.3.6.1.4.1.35265.1"
	/*
		sysDescr starts with "Eltex ESR-<model> Service Router <version>".
		Source: [MON] section "Системные параметры", sysDescr example
		"Eltex ESR-100 Service Router 1.24.x build 53 …". Not verified on hardware.
	*/
	sysDescrPrefix = "Eltex ESR-"

	/*
		cpmCPUTotal1min (CISCO-PROCESS-MIB), CPU load per core over the last
		minute, %, one row per core. Source: [MON] section "CPU". Not verified
		on hardware.
	*/
	cpuTotal1min = "1.3.6.1.4.1.9.9.109.1.1.1.1.4"

	/*
		ciscoMemoryPoolValid (true 1), ciscoMemoryPoolUsed and
		ciscoMemoryPoolFree in bytes (CISCO-MEMORY-POOL-MIB).
		Source: [MON] section "RAM". Not verified on hardware.
	*/
	memPoolValid = "1.3.6.1.4.1.9.9.48.1.1.1.4"
	memPoolUsed  = "1.3.6.1.4.1.9.9.48.1.1.1.5"
	memPoolFree  = "1.3.6.1.4.1.9.9.48.1.1.1.6"
	truthTrue    = 1

	/* rlPhdUnitEnvParamEntry (rlphysdescription.mib); temperature columns below. */
	envParamEntry = "1.3.6.1.4.1.89.53.15.1"
	sensorOK      = 1

	/*
		Power supply: [MON] gives no OID (only the entity name "Main Power
		Supply" in entPhysicalName), so PSUOk stays nil.
	*/

	maxResourceRows = 256
)

/*
tempSensors are rlPhdUnitEnvParamEntry (value, status) column pairs in °C with
status ok(1), unavailable(2), nonoperational(3). Source: [MON] section "CPU":
TempSensorValue/Status 9/10 (all models except ESR-1700), TempSensor4 16/17
and TempSensor5 18/19 (ESR-1700 CPUs 1 and 2). Not verified on hardware.
*/
var tempSensors = [][2]string{{"9", "10"}, {"16", "17"}, {"18", "19"}}

/*
execPrompt is the privileged prompt: host name followed by '#', e.g. "esr#",
"esr-100#"; configuration modes show "esr(config)#". Source: [CLI] "Правила
пользования командной строкой" and the [MON] examples. The runner anchors it
to the whole line. Not verified on hardware.
*/
var execPrompt = regexp.MustCompile(`^[\w.-]+# ?$`)

/* Driver is the Eltex ESR driver; the generic driver supplies everything it does not override. */
type Driver struct{ generic.Driver }

/* New returns the ESR driver. */
func New() Driver { return Driver{generic.New()} }

func init() { drivers.Register(New()) }

/* Name returns "eltex-esr". */
func (Driver) Name() string { return Name }

/* Verified reports the package constant Verified; see drivers.Unverified. */
func (Driver) Verified() bool { return Verified }

/* Match accepts an Eltex hardware sysObjectID whose sysDescr names an ESR router. */
func (Driver) Match(sysObjectID, sysDescr string) bool {
	return strings.HasPrefix(sysObjectID, elHardware+".") && strings.HasPrefix(sysDescr, sysDescrPrefix)
}

/*
Dialect returns the ESR CLI dialect.
PagerOff: "terminal datadump" disables paged output for the current session;
source: [CLI] both pages ("для текущей сессии"). Allowlist: "show version" and
"show system"; source: [MON] CLI examples ("esr-100# show system",
"esr-100# show version"). Not verified on hardware.
*/
func (Driver) Dialect() ssh.Dialect {
	return ssh.Dialect{
		ExecPrompt: execPrompt,
		PagerOff:   []string{"terminal datadump"},
		Allowlist:  append(drivers.Allowlist(showDefs), ssh.ShowCommand{Name: runningConfig}),
	}
}

/*
Collect runs the generic collection and replaces CPU, RAM and temperature
with the documented ESR objects when the device returns them.
*/
func (d Driver) Collect(ctx context.Context, r snmp.Reader) (drivers.Sample, error) {
	s, err := d.Driver.Collect(ctx, r)
	if err != nil {
		return s, err
	}
	if v := cpu(ctx, r); v != nil {
		s.System.CPUPct = v
	}
	if v := mem(ctx, r); v != nil {
		s.System.MemUsedPct = v
	}
	if v := temp(ctx, r); v != nil {
		s.System.TempC = v
	}
	return s, ctx.Err()
}

/* cpu is the mean one-minute load over all cores with a value in 0..100. */
func cpu(ctx context.Context, r snmp.Reader) *float64 {
	vals, err := column(ctx, r, cpuTotal1min)
	if err != nil {
		return nil
	}
	var sum float64
	n := 0
	for _, v := range vals {
		if v >= 0 && v <= 100 {
			sum += float64(v)
			n++
		}
	}
	if n == 0 {
		return nil
	}
	return ptr(sum / float64(n))
}

/* mem is used / (used + free) over valid memory pools, in %. */
func mem(ctx context.Context, r snmp.Reader) *float64 {
	valid, err1 := column(ctx, r, memPoolValid)
	used, err2 := column(ctx, r, memPoolUsed)
	free, err3 := column(ctx, r, memPoolFree)
	if err1 != nil || err2 != nil || err3 != nil {
		return nil
	}
	var u, total float64
	for i, ok := range valid {
		uv, hasU := used[i]
		fv, hasF := free[i]
		if ok != truthTrue || !hasU || !hasF || uv < 0 || fv < 0 {
			continue
		}
		u += float64(uv)
		total += float64(uv + fv)
	}
	if total == 0 {
		return nil
	}
	return ptr(u / total * 100)
}

/* temp is the highest plausible (-60..200 °C) reading among sensors with status ok. */
func temp(ctx context.Context, r snmp.Reader) *float64 {
	var best *float64
	for _, p := range tempSensors {
		vals, err1 := column(ctx, r, envParamEntry+"."+p[0])
		status, err2 := column(ctx, r, envParamEntry+"."+p[1])
		if err1 != nil || err2 != nil {
			continue
		}
		for i, v := range vals {
			t := float64(v)
			if st, ok := status[i]; ok && st == sensorOK && t >= -60 && t <= 200 && (best == nil || t > *best) {
				best = ptr(t)
			}
		}
	}
	return best
}

/* column walks an integer column and returns its values keyed by index suffix; bad rows are skipped. */
func column(ctx context.Context, r snmp.Reader, oid string) (map[string]int64, error) {
	out := map[string]int64{}
	_, err := drivers.WalkColumn(ctx, r, oid, maxResourceRows, func(idx []uint32, v snmp.Var) {
		if n, ok := integer(v); ok && idx != nil {
			out[strings.TrimPrefix(v.OID, oid+".")] = n
		}
	})
	return out, err
}

/* integer returns an INTEGER or Gauge32 value. */
func integer(v snmp.Var) (int64, bool) {
	switch x := v.Value.(type) {
	case int64:
		return x, v.Type == snmp.TypeInteger
	case uint64:
		return int64(x), v.Type == snmp.TypeGauge32 && x <= 1<<32 //nolint:gosec // Gauge32 fits int64
	}
	return 0, false
}

func ptr[T any](v T) *T { return &v }

/*
envMonTraps are the CISCO-ENVMON-MIB notifications (ciscoEnvMonMIBNotifPrefix
1.3.6.1.4.1.9.9.13.3.0). The ESR documentation [MON] polls Cisco MIB objects
for system parameters (CISCO-PROCESS-MIB above), so the Cisco environmental
notifications are the traps assumed here for power supply, fan, temperature
and voltage alarms. No Eltex document found lists ESR trap OIDs and Eltex's
own enterprise arc (1.3.6.1.4.1.35265) has no documented notifications, so
nothing else is mapped. Not verified on hardware.
*/
var envMonTraps = map[string]trap.Mapped{
	"1.3.6.1.4.1.9.9.13.3.0.1": {Name: "envMonShutdown", Severity: trap.SevDisaster},
	"1.3.6.1.4.1.9.9.13.3.0.2": {Name: "envMonVoltageAlarm", Severity: trap.SevHigh},
	"1.3.6.1.4.1.9.9.13.3.0.3": {Name: "envMonTemperatureAlarm", Severity: trap.SevHigh},
	"1.3.6.1.4.1.9.9.13.3.0.4": {Name: "envMonFanAlarm", Severity: trap.SevHigh},
	"1.3.6.1.4.1.9.9.13.3.0.5": {Name: "envMonRedundantSupplyAlarm", Severity: trap.SevAverage},
}

/* MapTrap names the environmental traps in envMonTraps; it reads no device state. */
func (Driver) MapTrap(t trap.Trap) (trap.Mapped, bool) {
	m, ok := envMonTraps[t.OID]
	return m, ok
}
