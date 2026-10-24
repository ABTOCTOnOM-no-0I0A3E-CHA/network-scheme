/*
Package eltexmes is the "eltex-mes" read-only driver for Eltex MES switches.
It embeds the generic-snmp driver and adds the Eltex/RADLAN resource objects
and the CLI dialect described in Eltex's public documentation. Nothing here
has been verified on real hardware yet (see Verified).

Sources (cited per value below):
  - [SMI] ELTEX-SMI-ACTUAL MIB (Eltex, LAST-UPDATED 2012-05-29), as published
    at https://mibs.observium.org/mib/ELTEX-SMI-ACTUAL/
  - [SNMP] "MES Ethernet switches monitoring and configuration via SNMP",
    firmware 6.6.2 (Eltex),
    https://old.eltex-co.com/upload/iblock/748/ofglla3dtzxa56jrtet7gtmr2olvbfuf/MES_configuration_and_monitoring_via_SNMP_6.6.2(en).pdf
    (same OIDs in the Russian edition for firmware 6.6.11.3, document v1.25)
  - [UM] "Ethernet Switches MES23xx, MES33xx, MES35xx, MES5324. User Manual,
    firmware version 4.0.22" (Eltex),
    https://eltex.ru/storage/upload_center/files/35/MES_Series_user_manual_4.0.22_en.pdf
*/
package eltexmes

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
	Name = "eltex-mes"
	/* Verified reports whether OIDs, prompt and commands were checked on a real MES; not yet. */
	Verified = false
)

const (
	/*
		elHardware, "the root of eltex hardware OIDs" (sysObjectID values).
		Source: [SMI] node elHardware. Not verified on hardware.
		No Eltex document found lists the per-model MES sysObjectIDs, so
		Match accepts the whole arc; eltex-esr is tried first.
	*/
	elHardware = "1.3.6.1.4.1.35265.1"

	/*
		rlCpuUtilDuringLastMinute (rlmng.mib), CPU load over the last minute, %.
		Source: [SNMP] §4.1 "System resources", CPU load monitoring.
		Not verified on hardware.
	*/
	cpuLastMinute = "1.3.6.1.4.1.89.1.8.0"

	/*
		rlPhdUnitEnvParamTable (rlphysdescription.mib), column for the primary
		and redundant power supply of each stack unit; states normal(1),
		warning(2), critical(3), shutdown(4), notPresent(5), notFunctioning(6).
		Source: [SNMP] §4.2 "System parameters", power supply units state
		control. Not verified on hardware.
	*/
	psuMain      = "1.3.6.1.4.1.89.53.15.1.2"
	psuRedundant = "1.3.6.1.4.1.89.53.15.1.3"
	psNormal     = 1
	psNotPresent = 5

	/*
		rlEnv (RADLAN-MIB) temperature sensor readings, CLI "show system
		sensors". Source: [SNMP] §4.2, temperature sensor readings monitoring.
		The guide states no unit; degrees Celsius is taken from [UM] §5
		(temperature sensor thresholds are set in °C). Not verified on hardware.
	*/
	tempReadings = "1.3.6.1.4.1.89.83.2.1.1.1.4"

	/*
		RAM is not read from a vendor object: [SNMP] §4.1 gives the
		eltexProcessMemoryEntry column per model (3/7 or 5/9) and lists only
		some models, so MemUsedPct comes from HOST-RESOURCES-MIB via the
		generic driver or stays nil.
	*/

	maxResourceRows = 256
)

/*
execPrompt is the privileged EXEC prompt: host name followed by '#'.
Source: [UM] §5 "Device management. Command line interface" (privileged
EXEC prompt "console#"; configuration modes add "(config…)"). The runner
anchors it to the whole line. Not verified on hardware.
*/
var execPrompt = regexp.MustCompile(`^[\w.-]+# ?$`)

/* Driver is the Eltex MES driver; the generic driver supplies everything it does not override. */
type Driver struct{ generic.Driver }

/* New returns the MES driver. */
func New() Driver { return Driver{generic.New()} }

func init() { drivers.Register(New()) }

/* Name returns "eltex-mes". */
func (Driver) Name() string { return Name }

/* Verified reports the package constant Verified; see drivers.Unverified. */
func (Driver) Verified() bool { return Verified }

/* Match accepts sysObjectIDs under the Eltex hardware arc. */
func (Driver) Match(sysObjectID, _ string) bool {
	return strings.HasPrefix(sysObjectID, elHardware+".")
}

/*
Dialect returns the MES CLI dialect.
PagerOff: "terminal datadump" shows output without splitting into pages for
the current terminal session; source: [UM] §5.1 "Basic commands", Table 33
(EXEC mode). Allowlist: "show version" (current firmware version) and "show
system" (system information); source: [UM] §5.1, EXEC/privileged EXEC
command tables. Not verified on hardware.
*/
func (Driver) Dialect() ssh.Dialect {
	return ssh.Dialect{
		ExecPrompt: execPrompt,
		PagerOff:   []string{"terminal datadump"},
		Allowlist:  append(drivers.Allowlist(showDefs), ssh.ShowCommand{Name: runningConfig}),
	}
}

/*
Collect runs the generic collection and replaces CPU and temperature with the
MES objects when the device returns them; PSUOk comes only from the MES power
supply table and stays nil when it is absent.
*/
func (d Driver) Collect(ctx context.Context, r snmp.Reader) (drivers.Sample, error) {
	s, err := d.Driver.Collect(ctx, r)
	if err != nil {
		return s, err
	}
	if v := cpu(ctx, r); v != nil {
		s.System.CPUPct = v
	}
	if v := temp(ctx, r); v != nil {
		s.System.TempC = v
	}
	s.System.PSUOk = psu(ctx, r)
	return s, ctx.Err()
}

/* cpu returns rlCpuUtilDuringLastMinute when it is a percentage 0..100. */
func cpu(ctx context.Context, r snmp.Reader) *float64 {
	vs, err := r.Get(ctx, cpuLastMinute)
	if err != nil || len(vs) != 1 {
		return nil
	}
	if n, ok := integer(vs[0]); ok && n >= 0 && n <= 100 {
		f := float64(n)
		return &f
	}
	return nil
}

/* temp returns the highest plausible (-60..200 °C) rlEnv reading. */
func temp(ctx context.Context, r snmp.Reader) *float64 {
	vals, err := column(ctx, r, tempReadings)
	if err != nil {
		return nil
	}
	var best *float64
	for _, v := range vals {
		t := float64(v)
		if t >= -60 && t <= 200 && (best == nil || t > *best) {
			best = &t
		}
	}
	return best
}

/*
psu reports whether every stack unit's primary supply is normal and every
redundant supply is normal or not installed. nil when the table is absent.
*/
func psu(ctx context.Context, r snmp.Reader) *bool {
	main, err := column(ctx, r, psuMain)
	if err != nil || len(main) == 0 {
		return nil
	}
	red, err := column(ctx, r, psuRedundant)
	if err != nil {
		return nil
	}
	ok := true
	for _, v := range main {
		ok = ok && v == psNormal
	}
	for _, v := range red {
		ok = ok && (v == psNormal || v == psNotPresent)
	}
	return &ok
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

/*
MapTrap names no trap yet. [SNMP] describes polling only, and no Eltex MES
document found lists trap OIDs (the Eltex arc 1.3.6.1.4.1.35265 and the
RADLAN arc 1.3.6.1.4.1.89 are not documented as notification sources), so
inventing OIDs would mislabel events. Standard traps (linkDown, ...) are
mapped by trap.Standard; operators can add trap rules for the rest. Not
verified on hardware.
*/
func (Driver) MapTrap(trap.Trap) (trap.Mapped, bool) { return trap.Mapped{}, false }
