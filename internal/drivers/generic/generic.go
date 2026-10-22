/*
Package generic is the "generic-snmp" driver: it reads standard MIBs only
(SNMPv2-MIB, IF-MIB, HOST-RESOURCES-MIB, ENTITY-MIB, ENTITY-SENSOR-MIB, IP-MIB,
BRIDGE-MIB, Q-BRIDGE-MIB, LLDP-MIB, IP-FORWARD-MIB), matches every device and
needs no SSH. Vendor drivers embed Driver and override what differs.
*/
package generic

import (
	"context"
	"math"
	"net/netip"
	"strconv"

	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/events/trap"
	"github.com/beekamai/network-scheme/internal/snmp"
	"github.com/beekamai/network-scheme/internal/ssh"
)

const (
	oidSysDescr    = "1.3.6.1.2.1.1.1.0"
	oidSysObjectID = "1.3.6.1.2.1.1.2.0"
	oidSysUpTime   = "1.3.6.1.2.1.1.3.0"
	oidSysName     = "1.3.6.1.2.1.1.5.0"

	/* ENTITY-MIB entPhysicalEntry */
	entPhysicalEntry = "1.3.6.1.2.1.47.1.1.1.1"
	entClassChassis  = 3
)

/* Driver is the generic SNMP driver. The zero value is usable. */
type Driver struct {
	maxRows int /* per-column walk cap; 0 means drivers.MaxRows */
}

/* New returns the generic driver. */
func New() Driver { return Driver{} }

func init() { drivers.Register(New()) }

/* Name returns drivers.GenericName. */
func (Driver) Name() string { return drivers.GenericName }

/* Match always reports true: the generic driver is the fallback. */
func (Driver) Match(string, string) bool { return true }

/* Dialect returns the zero dialect: the generic driver uses no SSH. */
func (Driver) Dialect() ssh.Dialect { return ssh.Dialect{} }

/* MapTrap always reports false: standard traps are mapped by trap.Standard. */
func (Driver) MapTrap(trap.Trap) (trap.Mapped, bool) { return trap.Mapped{}, false }

func (d Driver) limit() int {
	if d.maxRows <= 0 {
		return drivers.MaxRows
	}
	return d.maxRows
}

/*
Identify reads the system group and the model, serial number and software
revision of the first chassis in entPhysicalTable. Missing entity data leaves
those fields empty; only a system-group failure or an ended ctx is an error.
*/
func (d Driver) Identify(ctx context.Context, r snmp.Reader) (drivers.Identity, error) {
	var id drivers.Identity
	vs, err := r.Get(ctx, oidSysDescr, oidSysObjectID, oidSysName)
	if err != nil {
		return id, err
	}
	for _, v := range vs {
		switch v.OID {
		case oidSysDescr:
			id.SysDescr = str(v)
		case oidSysObjectID:
			if o, ok := snmp.AsOID(v); ok && len(o) <= drivers.MaxTextLen {
				id.SysObjectID = o
			}
		case oidSysName:
			id.SysName = str(v)
		}
	}

	var chassis uint32
	_, err = drivers.WalkColumn(ctx, r, entPhysicalEntry+".5", d.limit(), func(idx []uint32, v snmp.Var) {
		if c, ok := intVal(v); ok && c == entClassChassis && chassis == 0 && len(idx) == 1 && validIndex(idx[0]) {
			chassis = idx[0]
		}
	})
	if err != nil || chassis == 0 {
		return id, ctx.Err()
	}
	col := func(c string) string {
		return entPhysicalEntry + "." + c + "." + strconv.FormatUint(uint64(chassis), 10)
	}
	vs, err = r.Get(ctx, col("9"), col("10"), col("11"), col("13"))
	if err != nil {
		return id, ctx.Err()
	}
	var fw string
	for _, v := range vs {
		switch v.OID {
		case col("9"):
			fw = str(v)
		case col("10"):
			id.Firmware = str(v)
		case col("11"):
			id.Serial = str(v)
		case col("13"):
			id.Model = str(v)
		}
	}
	if id.Firmware == "" {
		id.Firmware = fw
	}
	return id, nil
}

/* str returns an OctetString value as sanitised text, or "" for other types. */
func str(v snmp.Var) string {
	b, ok := v.Value.([]byte)
	if !ok || v.Type != snmp.TypeOctetString {
		return ""
	}
	return drivers.CleanText(b)
}

/* intVal returns an INTEGER value. */
func intVal(v snmp.Var) (int64, bool) {
	x, ok := v.Value.(int64)
	return x, ok && v.Type == snmp.TypeInteger
}

/* validIndex reports whether an index sub-identifier is a usable ifIndex/entity index. */
func validIndex(i uint32) bool { return i >= 1 && i <= math.MaxInt32 }

/* octets converts index sub-identifiers to bytes; each must be <= 255. */
func octets(s []uint32) ([]byte, bool) {
	b := make([]byte, len(s))
	for i, x := range s {
		if x > 255 {
			return nil, false
		}
		b[i] = byte(x)
	}
	return b, true
}

/*
inetAddr decodes a length-prefixed InetAddress index part of type typ
(1 = ipv4, 2 = ipv6) and returns the remaining sub-identifiers.
*/
func inetAddr(typ uint32, s []uint32) (netip.Addr, []uint32, bool) {
	want := map[uint32]uint32{1: 4, 2: 16}[typ]
	if want == 0 || len(s) < 1 || s[0] != want || len(s)-1 < int(want) {
		return netip.Addr{}, nil, false
	}
	b, ok := octets(s[1 : 1+want])
	if !ok {
		return netip.Addr{}, nil, false
	}
	if want == 4 {
		return netip.AddrFrom4([4]byte(b)), s[1+want:], true
	}
	return netip.AddrFrom16([16]byte(b)), s[1+want:], true
}
