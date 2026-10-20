package generic

import (
	"context"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/snmp"
)

const (
	ifEntry  = "1.3.6.1.2.1.2.2.1"    /* IF-MIB ifEntry */
	ifXEntry = "1.3.6.1.2.1.31.1.1.1" /* IF-MIB ifXEntry */

	hrProcessorLoad = "1.3.6.1.2.1.25.3.3.1.2" /* HOST-RESOURCES-MIB */
	hrStorageEntry  = "1.3.6.1.2.1.25.2.3.1"
	hrStorageRAM    = "1.3.6.1.2.1.25.2.1.2"

	entPhySensorEntry = "1.3.6.1.2.1.99.1.1.1" /* ENTITY-SENSOR-MIB */
	sensorCelsius     = 8
	sensorOK          = 1

	maxRAMRows = 16
	maxSensors = 64
)

/* ifRow collects the columns of one interface. */
type ifRow struct {
	descr, name, alias, mac string
	speed, high             uint64
	operUp                  bool
	c                       [6]uint64 /* in/out octets, in/out errors, in/out discards (32-bit) */
	hcIn, hcOut             uint64
	hasHCIn, hasHCOut       bool
}

func (r *ifRow) displayName() string {
	if r.name != "" {
		return r.name
	}
	return r.descr
}

/* speedBps prefers ifSpeed unless it is saturated (or unknown) and ifHighSpeed is set. */
func (r *ifRow) speedBps() uint64 {
	if (r.speed == math.MaxUint32 || r.speed == 0) && r.high > 0 {
		return r.high * 1_000_000
	}
	return r.speed
}

/* ifColumn is one walked IF-MIB column; ifXTable columns only fill rows seen in ifTable. */
type ifColumn struct {
	oid string
	x   bool
	set func(*ifRow, snmp.Var)
}

func counter(i int) func(*ifRow, snmp.Var) {
	return func(r *ifRow, v snmp.Var) {
		if n, ok := snmp.AsUint64(v); ok {
			r.c[i] = n
		}
	}
}

func gauge(dst func(*ifRow) *uint64) func(*ifRow, snmp.Var) {
	return func(r *ifRow, v snmp.Var) {
		if n, ok := snmp.AsUint64(v); ok {
			*dst(r) = n
		}
	}
}

var (
	colDescr = ifColumn{ifEntry + ".2", false, func(r *ifRow, v snmp.Var) { r.descr = str(v) }}
	colSpeed = ifColumn{ifEntry + ".5", false, gauge(func(r *ifRow) *uint64 { return &r.speed })}
	colMAC   = ifColumn{ifEntry + ".6", false, func(r *ifRow, v snmp.Var) {
		if b, ok := v.Value.([]byte); ok && v.Type == snmp.TypeOctetString {
			r.mac, _ = drivers.FormatMAC(b)
		}
	}}
	colOper = ifColumn{ifEntry + ".8", false, func(r *ifRow, v snmp.Var) {
		x, ok := intVal(v)
		r.operUp = ok && x == 1
	}}
	colName  = ifColumn{ifXEntry + ".1", true, func(r *ifRow, v snmp.Var) { r.name = str(v) }}
	colHCIn  = ifColumn{ifXEntry + ".6", true, func(r *ifRow, v snmp.Var) { r.hcIn, r.hasHCIn = counter64(v) }}
	colHCOut = ifColumn{ifXEntry + ".10", true, func(r *ifRow, v snmp.Var) { r.hcOut, r.hasHCOut = counter64(v) }}
	colHigh  = ifColumn{ifXEntry + ".15", true, gauge(func(r *ifRow) *uint64 { return &r.high })}
	colAlias = ifColumn{ifXEntry + ".18", true, func(r *ifRow, v snmp.Var) { r.alias = str(v) }}

	counterColumns = []ifColumn{
		colDescr, colSpeed, colOper,
		{ifEntry + ".10", false, counter(0)}, /* ifInOctets */
		{ifEntry + ".13", false, counter(4)}, /* ifInDiscards */
		{ifEntry + ".14", false, counter(2)}, /* ifInErrors */
		{ifEntry + ".16", false, counter(1)}, /* ifOutOctets */
		{ifEntry + ".19", false, counter(5)}, /* ifOutDiscards */
		{ifEntry + ".20", false, counter(3)}, /* ifOutErrors */
		colName, colHCIn, colHCOut, colHigh, colAlias,
	}
	inventoryColumns = []ifColumn{colDescr, colSpeed, colMAC, colOper, colName, colHigh, colAlias}
)

func counter64(v snmp.Var) (uint64, bool) {
	n, ok := v.Value.(uint64)
	return n, ok && v.Type == snmp.TypeCounter64
}

/*
walkInterfaces walks cols and returns the rows and their ifIndexes in
ascending order. Rows walked before an error are returned with the error.
*/
func (d Driver) walkInterfaces(ctx context.Context, r snmp.Reader, cols []ifColumn) (map[int]*ifRow, []int, int, error) {
	rows := map[int]*ifRow{}
	malformed := 0
	var err error
	for _, c := range cols {
		bad := 0
		_, err = drivers.WalkColumn(ctx, r, c.oid, d.limit(), func(idx []uint32, v snmp.Var) {
			if len(idx) != 1 || !validIndex(idx[0]) {
				bad++
				return
			}
			row := rows[int(idx[0])]
			if row == nil {
				if c.x {
					return
				}
				row = &ifRow{}
				rows[int(idx[0])] = row
			}
			c.set(row, v)
		})
		malformed = max(malformed, bad)
		if err != nil {
			break
		}
	}
	keys := make([]int, 0, len(rows))
	for k := range rows {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return rows, keys, malformed, err
}

/*
Collect reads sysUpTime, interface counters (64-bit ifHC* octets when the
device has both for an interface, else 32-bit with HC=false) and system
resources from HOST-RESOURCES-MIB and ENTITY-SENSOR-MIB when present.
*/
func (d Driver) Collect(ctx context.Context, r snmp.Reader) (drivers.Sample, error) {
	var s drivers.Sample
	vs, err := r.Get(ctx, oidSysUpTime)
	if err != nil {
		return s, err
	}
	if len(vs) == 1 && vs[0].Type == snmp.TypeTimeTicks {
		if t, ok := snmp.AsUint64(vs[0]); ok {
			s.SysUpTime = time.Duration(t) * 10 * time.Millisecond //nolint:gosec // TimeTicks is 32-bit
		}
	}
	rows, keys, _, err := d.walkInterfaces(ctx, r, counterColumns)
	if err != nil {
		return s, err
	}
	for _, i := range keys {
		row := rows[i]
		c := drivers.IfCounters{
			Index: i, Name: row.displayName(), Alias: row.alias, OperUp: row.operUp, SpeedBps: row.speedBps(),
			InOctets: row.c[0], OutOctets: row.c[1], InErrors: row.c[2], OutErrors: row.c[3],
			InDiscards: row.c[4], OutDiscards: row.c[5],
		}
		if row.hasHCIn && row.hasHCOut {
			c.InOctets, c.OutOctets, c.HC = row.hcIn, row.hcOut, true
		}
		s.Interfaces = append(s.Interfaces, c)
	}
	s.System = drivers.SysMetrics{CPUPct: d.cpu(ctx, r), MemUsedPct: d.mem(ctx, r), TempC: d.temp(ctx, r)}
	return s, ctx.Err()
}

/* cpu averages hrProcessorLoad over all processors; nil when absent or unreadable. */
func (d Driver) cpu(ctx context.Context, r snmp.Reader) *float64 {
	var sum float64
	n := 0
	_, err := drivers.WalkColumn(ctx, r, hrProcessorLoad, d.limit(), func(_ []uint32, v snmp.Var) {
		if x, ok := intVal(v); ok && x >= 0 && x <= 100 {
			sum += float64(x)
			n++
		}
	})
	if err != nil || n == 0 {
		return nil
	}
	return ptr(sum / float64(n))
}

/* mem is the used share of hrStorageRam entries; nil when absent or unreadable. */
func (d Driver) mem(ctx context.Context, r snmp.Reader) *float64 {
	var idx []string
	_, err := drivers.WalkColumn(ctx, r, hrStorageEntry+".2", d.limit(), func(i []uint32, v snmp.Var) {
		if o, ok := snmp.AsOID(v); ok && o == hrStorageRAM && len(i) == 1 && len(idx) < maxRAMRows {
			idx = append(idx, strconv.FormatUint(uint64(i[0]), 10))
		}
	})
	if err != nil || len(idx) == 0 {
		return nil
	}
	vals, ok := getByIndex(ctx, r, hrStorageEntry, []string{"4", "5", "6"}, idx)
	if !ok {
		return nil
	}
	num := func(k string) uint64 { n, _ := snmp.AsUint64(vals[k]); return n }
	var size, used float64
	for _, i := range idx {
		units, s, u := num("4."+i), num("5."+i), num("6."+i)
		if units == 0 || s == 0 || u > s {
			continue
		}
		size += float64(s) * float64(units)
		used += float64(u) * float64(units)
	}
	if size == 0 {
		return nil
	}
	return ptr(used / size * 100)
}

/* temp is the highest valid Celsius reading of ENTITY-SENSOR-MIB; nil when absent. */
func (d Driver) temp(ctx context.Context, r snmp.Reader) *float64 {
	var idx []string
	_, err := drivers.WalkColumn(ctx, r, entPhySensorEntry+".1", d.limit(), func(i []uint32, v snmp.Var) {
		if x, ok := intVal(v); ok && x == sensorCelsius && len(i) == 1 && len(idx) < maxSensors {
			idx = append(idx, strconv.FormatUint(uint64(i[0]), 10))
		}
	})
	if err != nil || len(idx) == 0 {
		return nil
	}
	vals, ok := getByIndex(ctx, r, entPhySensorEntry, []string{"2", "3", "4", "5"}, idx)
	if !ok {
		return nil
	}
	ints := map[string]int64{}
	for k, v := range vals {
		if x, ok := intVal(v); ok {
			ints[k] = x
		}
	}
	var best *float64
	for _, i := range idx {
		scale, ok1 := ints["2."+i]
		prec, ok2 := ints["3."+i]
		val, ok3 := ints["4."+i]
		if !ok1 || !ok2 || !ok3 || ints["5."+i] != sensorOK || scale < 1 || scale > 17 || prec < -8 || prec > 9 {
			continue
		}
		/* scale: yocto(1)..units(9)..yotta(17), steps of 10^3; precision: decimal places */
		t := float64(val) * math.Pow10(int((scale-9)*3))
		if prec > 0 {
			t /= math.Pow10(int(prec))
		} else {
			t *= math.Pow10(int(-prec))
		}
		if t < -60 || t > 200 {
			continue
		}
		if best == nil || t > *best {
			best = ptr(t)
		}
	}
	return best
}

/* getByIndex GETs entry.col.index for every pair and returns the variables keyed "col.index". */
func getByIndex(ctx context.Context, r snmp.Reader, entry string, cols, idx []string) (map[string]snmp.Var, bool) {
	vs, err := r.Get(ctx, columnOIDs(entry, cols, idx)...)
	if err != nil {
		return nil, false
	}
	out := map[string]snmp.Var{}
	for _, v := range vs {
		if k, ok := strings.CutPrefix(v.OID, entry+"."); ok {
			out[k] = v
		}
	}
	return out, true
}

func columnOIDs(entry string, cols, idx []string) []string {
	oids := make([]string, 0, len(cols)*len(idx))
	for _, i := range idx {
		for _, c := range cols {
			oids = append(oids, entry+"."+c+"."+i)
		}
	}
	return oids
}

func ptr[T any](v T) *T { return &v }
