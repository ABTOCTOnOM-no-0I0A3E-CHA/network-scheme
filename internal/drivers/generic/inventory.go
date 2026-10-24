package generic

import (
	"context"
	"encoding/hex"
	"math"
	"math/bits"
	"net/netip"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/snmp"
)

const (
	ipNetToPhysicalPhysAddress = "1.3.6.1.2.1.4.35.1.4" /* IP-MIB */
	ipNetToMediaPhysAddress    = "1.3.6.1.2.1.4.22.1.2"
	dot1dBasePortIfIndex       = "1.3.6.1.2.1.17.1.4.1.2"     /* BRIDGE-MIB */
	dot1dTpFdbPort             = "1.3.6.1.2.1.17.4.3.1.2"     /* BRIDGE-MIB */
	dot1qTpFdbPort             = "1.3.6.1.2.1.17.7.1.2.2.1.2" /* Q-BRIDGE-MIB */
	dot1qVlanStaticName        = "1.3.6.1.2.1.17.7.1.4.3.1.1"
	dot1qVlanFdbID             = "1.3.6.1.2.1.17.7.1.4.2.1.3"
	lldpLocPortEntry           = "1.0.8802.1.1.2.1.3.7.1" /* lldpLocPortTable */
	lldpRemEntry               = "1.0.8802.1.1.2.1.4.1.1" /* LLDP-MIB */
	lldpRemManAddrIfSubtype    = "1.0.8802.1.1.2.1.4.2.1.3"
	inetCidrRouteEntry         = "1.3.6.1.2.1.4.24.7.1" /* IP-FORWARD-MIB */
	ipCidrRouteEntry           = "1.3.6.1.2.1.4.24.4.1"
)

type tableFunc func(context.Context, snmp.Reader, *drivers.Inventory) (malformed int, err error)

/*
Inventory walks every inventory table. A table is Complete only when all its
walks finished without error; a failed table does not stop the others. The
forwarding database is skipped (left incomplete) under Budget.SkipHeavy. sh is
not used. The error is non-nil only when ctx ended.
*/
func (d Driver) Inventory(ctx context.Context, r snmp.Reader, _ drivers.ShowRunner) (drivers.Inventory, error) {
	inv := drivers.NewInventory()
	skipHeavy := drivers.BudgetFrom(ctx).SkipHeavy
	for _, t := range []struct {
		table drivers.Table
		fn    tableFunc
	}{
		{drivers.TableInterfaces, d.interfaces},
		{drivers.TableARP, d.arp},
		{drivers.TableMAC, d.fdb},
		{drivers.TableVLANs, d.vlans},
		{drivers.TableLLDP, d.lldp},
		{drivers.TableEntities, d.entities},
		{drivers.TableRoutes, d.routes},
	} {
		if err := ctx.Err(); err != nil {
			return inv, err
		}
		if t.table == drivers.TableMAC && skipHeavy {
			continue
		}
		bad, err := t.fn(ctx, r, &inv)
		if bad > 0 {
			inv.Malformed[t.table] = bad
		}
		if err != nil {
			inv.Errors[t.table] = err
			continue
		}
		inv.Complete[t.table] = true
	}
	return inv, ctx.Err()
}

func (d Driver) interfaces(ctx context.Context, r snmp.Reader, inv *drivers.Inventory) (int, error) {
	rows, keys, bad, err := d.walkInterfaces(ctx, r, inventoryColumns)
	for _, i := range keys {
		row := rows[i]
		inv.Interfaces = append(inv.Interfaces, drivers.Interface{
			Index: i, Name: row.displayName(), Alias: row.alias, SpeedBps: row.speedBps(), OperUp: row.operUp, MAC: row.mac,
		})
	}
	return bad, err
}

/* macValue returns a PhysAddress value; empty means "no address" (not malformed). */
func macValue(v snmp.Var) (mac string, empty, ok bool) {
	b, isBytes := v.Value.([]byte)
	if !isBytes || v.Type != snmp.TypeOctetString {
		return "", false, false
	}
	if len(b) == 0 {
		return "", true, true
	}
	mac, ok = drivers.FormatMAC(b)
	return mac, false, ok
}

/* arp walks ipNetToPhysicalTable, or ipNetToMediaTable when the former is empty. */
func (d Driver) arp(ctx context.Context, r snmp.Reader, inv *drivers.Inventory) (int, error) {
	bad := 0
	add := func(ifIndex uint32, ip netip.Addr, v snmp.Var) {
		mac, empty, ok := macValue(v)
		switch {
		case !ok:
			bad++
		case !empty:
			inv.ARP = append(inv.ARP, drivers.ARPEntry{IP: ip, MAC: mac, IfIndex: int(ifIndex)})
		}
	}
	/* index: ifIndex, addressType, length-prefixed address */
	n, err := drivers.WalkColumn(ctx, r, ipNetToPhysicalPhysAddress, d.limit(), func(idx []uint32, v snmp.Var) {
		if len(idx) < 3 || !validIndex(idx[0]) {
			bad++
			return
		}
		ip, rest, ok := inetAddr(idx[1], idx[2:])
		if !ok || len(rest) != 0 {
			bad++
			return
		}
		add(idx[0], ip, v)
	})
	if err != nil || n > 0 {
		return bad, err
	}
	/* index: ifIndex, IpAddress */
	_, err = drivers.WalkColumn(ctx, r, ipNetToMediaPhysAddress, d.limit(), func(idx []uint32, v snmp.Var) {
		b, ok := octets(idx[min(1, len(idx)):])
		if len(idx) != 5 || !validIndex(idx[0]) || !ok {
			bad++
			return
		}
		add(idx[0], netip.AddrFrom4([4]byte(b)), v)
	})
	return bad, err
}

/*
fdb walks dot1qTpFdbTable, or dot1dTpFdbTable when the former is empty. The
VLAN of an entry is the one dot1qVlanFdbId maps its FDB id to (none when the id
is shared by several VLANs); an id absent from that table is taken as the VLAN
itself when it is 1..4094. Bridge ports are mapped to ifIndex
through dot1dBasePortIfIndex; without that table the port is taken as ifIndex.
*/
func (d Driver) fdb(ctx context.Context, r snmp.Reader, inv *drivers.Inventory) (int, error) {
	bad := 0
	ports := map[int64]int{}
	_, err := drivers.WalkColumn(ctx, r, dot1dBasePortIfIndex, d.limit(), func(idx []uint32, v snmp.Var) {
		x, ok := intVal(v)
		if len(idx) != 1 || !ok || x < 1 || x > math.MaxInt32 {
			bad++
			return
		}
		ports[int64(idx[0])] = int(x)
	})
	if err != nil {
		return bad, err
	}
	add := func(addr []uint32, vlan int, v snmp.Var) {
		b, ok := octets(addr)
		mac, okMAC := drivers.FormatMAC(b)
		port, okPort := intVal(v)
		if !ok || !okMAC || !okPort || port < 0 || port > math.MaxInt32 {
			bad++
			return
		}
		if port == 0 { /* not learned on a port, e.g. the bridge's own address */
			return
		}
		ifIndex, ok := ports[port]
		if len(ports) == 0 {
			ifIndex, ok = int(port), true
		}
		if !ok {
			bad++
			return
		}
		inv.MAC = append(inv.MAC, drivers.MACEntry{MAC: mac, VLAN: vlan, IfIndex: ifIndex})
	}
	/* index: timeMark, VlanIndex; a malformed row is skipped, the FDB id then falls back to itself */
	fdbVLAN := map[uint32]int{}
	_, err = drivers.WalkColumn(ctx, r, dot1qVlanFdbID, d.limit(), func(idx []uint32, v snmp.Var) {
		id, ok := snmp.AsUint64(v)
		if len(idx) != 2 || idx[1] < 1 || idx[1] > 4094 || !ok || id < 1 || id > math.MaxUint32 {
			return
		}
		if old, dup := fdbVLAN[uint32(id)]; dup && old != int(idx[1]) {
			fdbVLAN[uint32(id)] = 0 /* shared FDB: the VLAN of an entry is unknown */
			return
		}
		fdbVLAN[uint32(id)] = int(idx[1])
	})
	if err != nil {
		return bad, err
	}
	/* index: dot1qFdbId, MAC */
	n, err := drivers.WalkColumn(ctx, r, dot1qTpFdbPort, d.limit(), func(idx []uint32, v snmp.Var) {
		if len(idx) != 7 {
			bad++
			return
		}
		vlan, mapped := fdbVLAN[idx[0]]
		if !mapped && idx[0] >= 1 && idx[0] <= 4094 {
			vlan = int(idx[0])
		}
		add(idx[1:], vlan, v)
	})
	if err != nil || n > 0 {
		return bad, err
	}
	/* index: MAC */
	_, err = drivers.WalkColumn(ctx, r, dot1dTpFdbPort, d.limit(), func(idx []uint32, v snmp.Var) {
		if len(idx) != 6 {
			bad++
			return
		}
		add(idx, 0, v)
	})
	return bad, err
}

/* vlans walks dot1qVlanStaticName. */
func (d Driver) vlans(ctx context.Context, r snmp.Reader, inv *drivers.Inventory) (int, error) {
	bad := 0
	_, err := drivers.WalkColumn(ctx, r, dot1qVlanStaticName, d.limit(), func(idx []uint32, v snmp.Var) {
		if len(idx) != 1 || idx[0] < 1 || idx[0] > 4094 || v.Type != snmp.TypeOctetString {
			bad++
			return
		}
		inv.VLANs = append(inv.VLANs, drivers.VLAN{ID: int(idx[0]), Name: str(v)})
	})
	return bad, err
}

/* LLDP chassis/port ID subtypes that carry a MAC or a network address. */
const (
	chassisMAC = 4
	chassisNet = 5
	portMAC    = 3
	portNet    = 4

	lldpPortIfName = 5 /* lldpLocPortIdSubtype: interfaceName */
	lldpPortLocal  = 7 /* local */
)

type lldpRow struct {
	chassisSub, portSub int64
	chassis, port       []byte
	portDescr, sysName  string
	mgmt                netip.Addr
}

/*
lldp walks lldpRemTable and lldpRemManAddrTable. LocalIfIndex is the ifIndex
lldpLocPortTable ties the local port number to (see lldpLocalPorts); rows without
a chassis ID are malformed.
*/
func (d Driver) lldp(ctx context.Context, r snmp.Reader, inv *drivers.Inventory) (int, error) {
	rows := map[[3]uint32]*lldpRow{}
	var order [][3]uint32
	malformed := 0
	cols := []struct {
		col string
		set func(*lldpRow, snmp.Var)
	}{
		{"4", func(l *lldpRow, v snmp.Var) { l.chassisSub, _ = intVal(v) }},
		{"5", func(l *lldpRow, v snmp.Var) { l.chassis = rawBytes(v) }},
		{"6", func(l *lldpRow, v snmp.Var) { l.portSub, _ = intVal(v) }},
		{"7", func(l *lldpRow, v snmp.Var) { l.port = rawBytes(v) }},
		{"8", func(l *lldpRow, v snmp.Var) { l.portDescr = str(v) }},
		{"9", func(l *lldpRow, v snmp.Var) { l.sysName = str(v) }},
	}
	for _, c := range cols {
		bad := 0
		/* index: lldpRemTimeMark, lldpRemLocalPortNum, lldpRemIndex */
		_, err := drivers.WalkColumn(ctx, r, lldpRemEntry+"."+c.col, d.limit(), func(idx []uint32, v snmp.Var) {
			if len(idx) != 3 || !validIndex(idx[1]) {
				bad++
				return
			}
			k := [3]uint32(idx)
			row := rows[k]
			if row == nil {
				row = &lldpRow{}
				rows[k] = row
				order = append(order, k)
			}
			c.set(row, v)
		})
		malformed = max(malformed, bad)
		if err != nil {
			return malformed, err
		}
	}
	/* index: lldpRemTimeMark, lldpRemLocalPortNum, lldpRemIndex, address subtype, length-prefixed address; IPv4 is taken, IPv6 only when the row has no IPv4 */
	_, err := drivers.WalkColumn(ctx, r, lldpRemManAddrIfSubtype, d.limit(), func(idx []uint32, _ snmp.Var) {
		if len(idx) < 5 {
			return
		}
		row := rows[[3]uint32(idx[:3])]
		ip, rest, ok := inetAddr(idx[3], idx[4:])
		if row == nil || !ok || len(rest) != 0 || (row.mgmt.IsValid() && (row.mgmt.Is4() || !ip.Is4())) {
			return
		}
		row.mgmt = ip
	})
	if err != nil {
		return malformed, err
	}
	locIf, err := d.lldpLocalPorts(ctx, r)
	if err != nil {
		return malformed, err
	}
	for _, k := range order {
		row := rows[k]
		if len(row.chassis) == 0 {
			malformed++
			continue
		}
		ifIndex, resolved := locIf(k[1])
		inv.LLDP = append(inv.LLDP, drivers.LLDPNeighbor{
			LocalIfIndex: ifIndex, LocalPortResolved: resolved,
			ChassisID: lldpID(row.chassisSub, row.chassis, chassisMAC, chassisNet),
			PortID:    lldpID(row.portSub, row.port, portMAC, portNet),
			PortDescr: row.portDescr,
			SysName:   row.sysName,
			MgmtAddr:  row.mgmt,
		})
	}
	return malformed, nil
}

/*
lldpLocalPorts maps lldpRemLocalPortNum to an ifIndex. LLDP-MIB does not tie the
two together, so a port is resolved only when its lldpLocPortId (interfaceName(5)
or local(7) subtype) equals exactly one ifName/ifDescr; that ifIndex is returned
with resolved=true. Otherwise the port number is returned as is, unresolved
(agents commonly number ports like ifIndex, but nothing confirms it). Malformed
rows are ignored.
*/
func (d Driver) lldpLocalPorts(ctx context.Context, r snmp.Reader) (func(uint32) (int, bool), error) {
	type loc struct {
		sub int64
		id  string
	}
	locs := map[uint32]*loc{}
	for _, c := range []struct {
		col string
		set func(*loc, snmp.Var)
	}{
		{"2", func(l *loc, v snmp.Var) { l.sub, _ = intVal(v) }},
		{"3", func(l *loc, v snmp.Var) { l.id = lldpText(rawBytes(v)) }},
	} {
		/* index: lldpLocPortNum */
		_, err := drivers.WalkColumn(ctx, r, lldpLocPortEntry+"."+c.col, d.limit(), func(idx []uint32, v snmp.Var) {
			if len(idx) != 1 || !validIndex(idx[0]) {
				return
			}
			l := locs[idx[0]]
			if l == nil {
				l = &loc{}
				locs[idx[0]] = l
			}
			c.set(l, v)
		})
		if err != nil {
			return nil, err
		}
	}
	byName := map[string][]int{}
	if len(locs) > 0 {
		rows, keys, _, err := d.walkInterfaces(ctx, r, []ifColumn{colDescr, colName})
		if err != nil {
			return nil, err
		}
		for _, i := range keys {
			for _, n := range []string{rows[i].descr, rows[i].name} {
				if n != "" && !slices.Contains(byName[n], i) {
					byName[n] = append(byName[n], i)
				}
			}
		}
	}
	return func(port uint32) (int, bool) {
		if l := locs[port]; l != nil && (l.sub == lldpPortIfName || l.sub == lldpPortLocal) && l.id != "" {
			if c := byName[l.id]; len(c) == 1 {
				return c[0], true
			}
		}
		return int(port), false
	}, nil
}

/* lldpText renders an LLDP ID as text; empty when it is not printable. */
func lldpText(b []byte) string {
	if len(b) == 0 || !utf8.Valid(b) || strings.ContainsFunc(string(b), unicode.IsControl) {
		return ""
	}
	return drivers.CleanText(b)
}

func rawBytes(v snmp.Var) []byte {
	b, _ := v.Value.([]byte)
	if v.Type != snmp.TypeOctetString {
		return nil
	}
	return b
}

/*
lldpID renders an LLDP chassis or port ID: a MAC for the MAC subtype, an IP
for the network-address subtype (IANA family 1/2), printable text as text and
anything else as colon-separated hex.
*/
func lldpID(sub int64, b []byte, macSub, netSub int64) string {
	if sub == macSub {
		if m, ok := drivers.FormatMAC(b); ok {
			return m
		}
	}
	if sub == netSub && len(b) > 1 {
		if a, ok := netip.AddrFromSlice(b[1:]); ok && ((b[0] == 1 && a.Is4()) || (b[0] == 2 && a.Is6())) {
			return a.String()
		}
	}
	if utf8.Valid(b) && !strings.ContainsFunc(string(b), unicode.IsControl) {
		return drivers.CleanText(b)
	}
	b = b[:min(len(b), drivers.MaxTextLen/3)]
	parts := make([]string, len(b))
	for i := range b {
		parts[i] = hex.EncodeToString(b[i : i+1])
	}
	return strings.Join(parts, ":")
}

/* entPhysicalClass enum names (ENTITY-MIB, RFC 6933). */
var entClasses = []string{"", "other", "unknown", "chassis", "backplane", "container", "powerSupply",
	"fan", "sensor", "module", "port", "stack", "cpu", "energyObject", "battery", "storageDrive"}

/* entities walks entPhysicalTable. */
func (d Driver) entities(ctx context.Context, r snmp.Reader, inv *drivers.Inventory) (int, error) {
	rows := map[int]*drivers.Entity{}
	malformed := 0
	cols := []struct {
		col string
		set func(*drivers.Entity, snmp.Var)
	}{
		{"2", func(e *drivers.Entity, v snmp.Var) { e.Descr = str(v) }},
		{"5", func(e *drivers.Entity, v snmp.Var) {
			e.Class = "unknown"
			if x, ok := intVal(v); ok && x >= 1 && int(x) < len(entClasses) {
				e.Class = entClasses[x]
			}
		}},
		{"7", func(e *drivers.Entity, v snmp.Var) { e.Name = str(v) }},
		{"9", func(e *drivers.Entity, v snmp.Var) { e.FirmwareRev = str(v) }},
		{"10", func(e *drivers.Entity, v snmp.Var) { e.SoftwareRev = str(v) }},
		{"11", func(e *drivers.Entity, v snmp.Var) { e.Serial = str(v) }},
		{"13", func(e *drivers.Entity, v snmp.Var) { e.Model = str(v) }},
	}
	var err error
	for _, c := range cols {
		bad := 0
		_, err = drivers.WalkColumn(ctx, r, entPhysicalEntry+"."+c.col, d.limit(), func(idx []uint32, v snmp.Var) {
			if len(idx) != 1 || !validIndex(idx[0]) {
				bad++
				return
			}
			e := rows[int(idx[0])]
			if e == nil {
				e = &drivers.Entity{Index: int(idx[0])}
				rows[e.Index] = e
			}
			c.set(e, v)
		})
		malformed = max(malformed, bad)
		if err != nil {
			break
		}
	}
	for _, e := range rows {
		inv.Entities = append(inv.Entities, *e)
	}
	slices.SortFunc(inv.Entities, func(a, b drivers.Entity) int { return a.Index - b.Index })
	return malformed, err
}

/* IANAipRouteProtocol enum names. */
var routeProtos = []string{"", "other", "local", "netmgmt", "icmp", "egp", "ggp", "hello", "rip",
	"isIs", "esIs", "ciscoIgrp", "bbnSpfIgp", "ospf", "bgp", "idpr", "ciscoEigrp", "dvmrp"}

/* routes walks inetCidrRouteTable, or ipCidrRouteTable when the former is empty. */
func (d Driver) routes(ctx context.Context, r snmp.Reader, inv *drivers.Inventory) (int, error) {
	n, bad, err := d.routeTable(ctx, r, inv, inetCidrRouteEntry+".7", inetCidrRouteEntry+".9", parseInetCidrIndex)
	if err != nil || n > 0 {
		return bad, err
	}
	_, bad, err = d.routeTable(ctx, r, inv, ipCidrRouteEntry+".5", ipCidrRouteEntry+".7", parseIPCidrIndex)
	return bad, err
}

/* routeTable walks the protocol column, then the ifIndex column, which defines the rows. */
func (d Driver) routeTable(ctx context.Context, r snmp.Reader, inv *drivers.Inventory, ifCol, protoCol string,
	parse func([]uint32) (netip.Prefix, netip.Addr, bool)) (int, int, error) {
	proto := map[string]string{}
	_, err := drivers.WalkColumn(ctx, r, protoCol, d.limit(), func(_ []uint32, v snmp.Var) {
		if x, ok := intVal(v); ok && x >= 1 && int(x) < len(routeProtos) {
			proto[strings.TrimPrefix(v.OID, protoCol+".")] = routeProtos[x]
		}
	})
	if err != nil {
		return 0, 0, err
	}
	bad := 0
	n, err := drivers.WalkColumn(ctx, r, ifCol, d.limit(), func(idx []uint32, v snmp.Var) {
		dest, nh, ok := parse(idx)
		ifIndex, okIf := intVal(v)
		if !ok || !okIf || ifIndex < 0 || ifIndex > math.MaxInt32 {
			bad++
			return
		}
		p := proto[strings.TrimPrefix(v.OID, ifCol+".")]
		if p == "" {
			p = "other"
		}
		inv.Routes = append(inv.Routes, drivers.Route{Dest: dest, NextHop: nh, IfIndex: int(ifIndex), Proto: p})
	})
	return n, bad, err
}

/*
parseInetCidrIndex decodes the inetCidrRouteTable index: destType,
length-prefixed dest, pfxLen, length-prefixed policy OID, nextHopType,
length-prefixed next hop (type 0 with length 0 means none).
*/
func parseInetCidrIndex(idx []uint32) (netip.Prefix, netip.Addr, bool) {
	if len(idx) < 1 {
		return netip.Prefix{}, netip.Addr{}, false
	}
	dest, rest, ok := inetAddr(idx[0], idx[1:])
	if !ok || len(rest) < 2 || int(rest[0]) > dest.BitLen() {
		return netip.Prefix{}, netip.Addr{}, false
	}
	pfx := int(rest[0])
	rest = rest[1:]
	if int(rest[0]) > len(rest)-1 {
		return netip.Prefix{}, netip.Addr{}, false
	}
	rest = rest[1+rest[0]:]
	var nh netip.Addr
	switch {
	case len(rest) == 2 && rest[0] == 0 && rest[1] == 0:
	case len(rest) >= 2:
		var tail []uint32
		if nh, tail, ok = inetAddr(rest[0], rest[1:]); !ok || len(tail) != 0 {
			return netip.Prefix{}, netip.Addr{}, false
		}
	default:
		return netip.Prefix{}, netip.Addr{}, false
	}
	return netip.PrefixFrom(dest, pfx).Masked(), nh, true
}

/* parseIPCidrIndex decodes the ipCidrRouteTable index: dest, mask, tos, next hop (IPv4). */
func parseIPCidrIndex(idx []uint32) (netip.Prefix, netip.Addr, bool) {
	b, ok := octets(idx)
	if !ok || len(b) != 13 {
		return netip.Prefix{}, netip.Addr{}, false
	}
	mask := uint32(b[4])<<24 | uint32(b[5])<<16 | uint32(b[6])<<8 | uint32(b[7])
	ones := bits.LeadingZeros32(^mask)
	if mask != ^uint32(0)<<(32-ones) {
		return netip.Prefix{}, netip.Addr{}, false
	}
	dest := netip.PrefixFrom(netip.AddrFrom4([4]byte(b[0:4])), ones).Masked()
	return dest, netip.AddrFrom4([4]byte(b[9:13])), true
}
