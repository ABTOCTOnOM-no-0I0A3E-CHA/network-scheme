/*
Package drivers defines the read-only device driver interface used by the
poller, the shared result types and the driver registry. Drivers only read:
SNMP through snmp.Reader (no SET exists) and SSH through ShowRunner, which
runs only commands from the driver's own allowlist.
*/
package drivers

import (
	"context"
	"net/netip"
	"time"

	"github.com/beekamai/network-scheme/internal/drivers/showspec"
	"github.com/beekamai/network-scheme/internal/events/trap"
	"github.com/beekamai/network-scheme/internal/snmp"
	"github.com/beekamai/network-scheme/internal/ssh"
)

/*
Driver supports one device family. Implementations must treat everything read
from the device as untrusted: bound and sanitise strings, validate addresses
and skip malformed rows instead of failing a whole table.
*/
type Driver interface {
	/* Name is the stable driver identifier stored with the device, e.g. "generic-snmp". */
	Name() string
	/* Match reports whether the driver supports a device with these system values. */
	Match(sysObjectID, sysDescr string) bool
	/* Dialect is the SSH read dialect; the zero value means the driver needs no SSH. */
	Dialect() ssh.Dialect
	/* Identify reads model, firmware and serial number. */
	Identify(ctx context.Context, r snmp.Reader) (Identity, error)
	/* Collect reads interface counters and system resources. */
	Collect(ctx context.Context, r snmp.Reader) (Sample, error)
	/*
		Inventory reads the inventory tables. sh is nil when the device has no
		SSH read profile. Table errors are reported per table in the result;
		the returned error is non-nil only when ctx ended.
	*/
	Inventory(ctx context.Context, r snmp.Reader, sh ShowRunner) (Inventory, error)
	/*
		MapTrap names a vendor-specific trap. It is a pure function of the
		already decoded trap (no network, no state) and reports false for
		traps the driver does not know; standard traps are mapped by trap.Standard.
	*/
	MapTrap(t trap.Trap) (trap.Mapped, bool)

	/*
		FetchConfig reads the running configuration over SSH using only a
		command from the dialect's allowlist. It returns ErrNotSupported for
		drivers without a config reader and never returns partial text.
	*/
	FetchConfig(ctx context.Context, sh ShowRunner) (string, error)
	/*
		NormalizeConfig drops volatile lines (timestamps, uptime) and unifies line ends;
		idempotent. Its result is used ONLY to compute the SHA-256 that deduplicates
		versions: the stored encrypted full copy and the masked copy are made from the
		raw text returned by FetchConfig, never from the normalized one.
	*/
	NormalizeConfig(cfg string) string
	/* MaskSecrets replaces secret values with "***"; idempotent. */
	MaskSecrets(cfg string) string
	/* ConfigSections splits a masked configuration into named sections (stable keys). */
	ConfigSections(masked string) []Section
	/*
		ConfigNeedsWrite reports that reading the configuration requires an
		account with write rights; such devices are not backed up before Phase 4.
	*/
	ConfigNeedsWrite() bool
	/* ShowCommands lists the on-demand show commands (never a configuration dump). */
	ShowCommands() []showspec.Spec
	/*
		ShowCommand maps a ShowCommands key and its arguments to the allowlisted
		command. It accepts only ShowCommands keys and can never resolve to the
		configuration read (which is also in the dialect allowlist); callers must
		not build an ssh.ShowCommand from api-supplied text. Interface names must
		come from the device inventory (checked by the caller).
	*/
	ShowCommand(key string, args []string) (ssh.ShowCommand, error)
}

/* ShowRunner runs an allowlisted show command over SSH; *ssh.Runner implements it. */
type ShowRunner interface {
	Run(ctx context.Context, cmd ssh.ShowCommand) (string, error)
}

/* Identity describes a device. Empty strings mean "not reported". */
type Identity struct {
	SysObjectID string
	SysDescr    string
	SysName     string
	Model       string
	Firmware    string
	Serial      string
}

/*
Sample is one metrics poll. Incomplete counts interfaces dropped because their
in and out octet counters were not both read from the same counter family.
*/
type Sample struct {
	SysUpTime  time.Duration
	Interfaces []IfCounters
	System     SysMetrics
	Incomplete int
}

/*
IfCounters holds raw interface counters. InOctets and OutOctets are always
read in the same poll from one counter family: HC is true when both are the
64-bit ifHC* objects, false when both are 32-bit (may wrap); a row that cannot
meet this is not emitted. The family is chosen per interface and per poll, so
HC can change between polls for the same interface (e.g. a failed ifXTable
walk); a rate calculator must skip the point when it does. Error and discard counters are nil when the device
did not return them in this poll; nil is never the same as zero.
*/
type IfCounters struct {
	Index                   int
	Name, Alias             string
	OperUp                  bool
	SpeedBps                uint64
	InOctets, OutOctets     uint64
	InErrors, OutErrors     *uint64
	InDiscards, OutDiscards *uint64
	HC                      bool
}

/* SysMetrics holds system resources; nil means the device does not report the value. */
type SysMetrics struct {
	CPUPct     *float64
	MemUsedPct *float64
	TempC      *float64
	PSUOk      *bool
}

/* Table names an inventory table. */
type Table string

/* Inventory tables. */
const (
	TableInterfaces Table = "interfaces"
	TableARP        Table = "arp"
	TableMAC        Table = "mac"
	TableVLANs      Table = "vlans"
	TableLLDP       Table = "lldp"
	TableEntities   Table = "entities"
	TableRoutes     Table = "routes"
)

/*
Inventory is one inventory poll. Complete[t] is true only when table t was
walked to the end; rows of an incomplete table are a partial view, so stored
rows must not be deleted for it. Malformed counts rows dropped as invalid and
Errors holds the error that left a table incomplete.
*/
type Inventory struct {
	Complete  map[Table]bool
	Malformed map[Table]int
	Errors    map[Table]error

	Interfaces []Interface
	ARP        []ARPEntry
	MAC        []MACEntry
	VLANs      []VLAN
	LLDP       []LLDPNeighbor
	Entities   []Entity
	Routes     []Route
}

/* NewInventory returns an Inventory with its maps allocated and nothing complete. */
func NewInventory() Inventory {
	return Inventory{Complete: map[Table]bool{}, Malformed: map[Table]int{}, Errors: map[Table]error{}}
}

/* Interface is an interface inventory row. MAC is "aa:bb:cc:dd:ee:ff" or empty. */
type Interface struct {
	Index    int
	Name     string
	Alias    string
	SpeedBps uint64
	OperUp   bool
	MAC      string
	/* PortKind is the physical port kind; empty is stored as PortOther. */
	PortKind PortKind
}

/* PortKind is the physical kind of an interface. */
type PortKind string

/* Port kinds, as stored in inventory.interface.port_kind. */
const (
	PortRJ45  PortKind = "rj45"
	PortSFP   PortKind = "sfp"
	PortOther PortKind = "other"
)

/* ARPEntry is an IP-to-MAC mapping. */
type ARPEntry struct {
	IP      netip.Addr
	MAC     string
	IfIndex int
}

/* MACEntry is a forwarding database row; VLAN is 0 when unknown. */
type MACEntry struct {
	MAC     string
	VLAN    int
	IfIndex int
}

/* VLAN is a configured VLAN. */
type VLAN struct {
	ID   int
	Name string
}

/*
LLDPNeighbor is a remote LLDP system seen on a local port. MgmtAddr is the
zero Addr when the neighbor advertised no IP management address.
LocalPortResolved is true when LocalIfIndex was tied to an interface by name
(lldpLocPortId), false when the LLDP port number is passed through unchecked.
*/
type LLDPNeighbor struct {
	LocalIfIndex      int
	LocalPortResolved bool
	ChassisID         string
	PortID            string
	PortDescr         string
	SysName           string
	MgmtAddr          netip.Addr
}

/* Entity is a physical component (ENTITY-MIB); Class is the MIB enum name. */
type Entity struct {
	Index       int
	Class       string
	Name        string
	Descr       string
	Model       string
	Serial      string
	FirmwareRev string
	SoftwareRev string
}

/* Route is a forwarding table row. NextHop is the zero Addr when unknown; Proto is the MIB enum name. */
type Route struct {
	Dest    netip.Prefix
	NextHop netip.Addr
	IfIndex int
	Proto   string
}

/* Budget limits the work of one inventory poll. */
type Budget struct {
	/* SkipHeavy skips the forwarding database (left incomplete), e.g. while device CPU is high. */
	SkipHeavy bool
}

type budgetKey struct{}

/* WithBudget attaches b to ctx for Inventory. */
func WithBudget(ctx context.Context, b Budget) context.Context {
	return context.WithValue(ctx, budgetKey{}, b)
}

/* BudgetFrom returns the Budget attached to ctx, or the zero Budget. */
func BudgetFrom(ctx context.Context) Budget {
	b, _ := ctx.Value(budgetKey{}).(Budget)
	return b
}
