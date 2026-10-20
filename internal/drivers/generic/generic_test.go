package generic

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/snmp"
	"github.com/beekamai/network-scheme/test/sim/snmpsim/simtest"
)

/* reader starts the simulator with both generic fixtures and opens a v2c session for community. */
func reader(t *testing.T, community string) snmp.Reader {
	t.Helper()
	t.Parallel()
	addr := simtest.Start(t, simtest.Fixture("generic-switch.snmprec"), simtest.Fixture("generic-router.snmprec"))
	r, c, err := snmp.Dial(context.Background(), addr, simtest.V2Cred(community), snmp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return r
}

func u(v uint64) *uint64 { return &v }

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return c
}

func TestGenericCollectHCCounters(t *testing.T) {
	r := reader(t, "generic-switch")
	s, err := New().Collect(ctx(t), r)
	if err != nil {
		t.Fatal(err)
	}
	if s.SysUpTime != 123456789*10*time.Millisecond {
		t.Fatalf("SysUpTime = %v", s.SysUpTime)
	}
	want := []drivers.IfCounters{
		{Index: 1, Name: "Gi1/0/1", Alias: "uplink", OperUp: true, SpeedBps: 1e9,
			InOctets: 18446744073709551000, OutOctets: 5000000000000, HC: true,
			InErrors: u(0), OutErrors: u(0), InDiscards: u(0), OutDiscards: u(0)},
		{Index: 2, Name: "Gi1/0/2", Alias: "server", SpeedBps: 1e9,
			InOctets: 987654321012, OutOctets: 87654321098, HC: true,
			InErrors: u(2), OutErrors: u(0), InDiscards: u(5), OutDiscards: u(1)},
		{Index: 3, Name: "Gi1/0/3", SpeedBps: 1e9, HC: true,
			InErrors: u(0), OutErrors: u(0), InDiscards: u(0), OutDiscards: u(0)},
	}
	if !reflect.DeepEqual(s.Interfaces, want) {
		t.Fatalf("interfaces\n got %+v\nwant %+v", s.Interfaces, want)
	}
	wantSys := drivers.SysMetrics{CPUPct: ptr(20.0), MemUsedPct: ptr(25.0), TempC: ptr(42.5)}
	if !reflect.DeepEqual(s.System, wantSys) {
		t.Fatalf("system %s, want %s", fmtSys(s.System), fmtSys(wantSys))
	}
}

func fmtSys(m drivers.SysMetrics) string {
	f := func(p *float64) string {
		if p == nil {
			return "nil"
		}
		return fmt.Sprint(*p)
	}
	return fmt.Sprintf("cpu=%s mem=%s temp=%s psu=%v", f(m.CPUPct), f(m.MemUsedPct), f(m.TempC), m.PSUOk)
}

func TestGenericFallback32bit(t *testing.T) {
	r := reader(t, "generic-router")
	s, err := New().Collect(ctx(t), r)
	if err != nil {
		t.Fatal(err)
	}
	want := []drivers.IfCounters{
		{Index: 1, Name: "eth0", OperUp: true, SpeedBps: 1e8, InOctets: 4294967000, OutOctets: 3000000,
			InErrors: u(2), OutErrors: u(4), InDiscards: u(1), OutDiscards: u(3)},
		{Index: 2, Name: "eth1", SpeedBps: 1e8, InOctets: 10, OutOctets: 20,
			InErrors: u(0), OutErrors: u(0), InDiscards: u(0), OutDiscards: u(0)},
	}
	if !reflect.DeepEqual(s.Interfaces, want) {
		t.Fatalf("interfaces\n got %+v\nwant %+v", s.Interfaces, want)
	}
	if s.System != (drivers.SysMetrics{}) {
		t.Fatalf("unsupported metrics must be nil: %s", fmtSys(s.System))
	}
}

func TestGenericIdentify(t *testing.T) {
	r := reader(t, "generic-switch")
	id, err := New().Identify(ctx(t), r)
	if err != nil {
		t.Fatal(err)
	}
	want := drivers.Identity{
		SysObjectID: "1.3.6.1.4.1.32473.1.100", SysDescr: "Synthetic Generic Switch 24-port, software 1.0.0",
		SysName: "sim-sw1", Model: "SIM-SW-24", Firmware: "1.0.0", Serial: "SIM0001",
	}
	if id != want {
		t.Fatalf("got %+v\nwant %+v", id, want)
	}
}

var allTables = []drivers.Table{
	drivers.TableInterfaces, drivers.TableARP, drivers.TableMAC, drivers.TableVLANs,
	drivers.TableLLDP, drivers.TableEntities, drivers.TableRoutes,
}

func assertComplete(t *testing.T, inv drivers.Inventory, except ...drivers.Table) {
	t.Helper()
	for _, tb := range allTables {
		want := true
		for _, e := range except {
			if e == tb {
				want = false
			}
		}
		if inv.Complete[tb] != want {
			t.Errorf("Complete[%s] = %v, want %v (err %v)", tb, inv.Complete[tb], want, inv.Errors[tb])
		}
	}
}

func eq(t *testing.T, name string, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s\n got %+v\nwant %+v", name, got, want)
	}
}

func TestGenericInventoryTables(t *testing.T) {
	r := reader(t, "generic-switch")
	inv, err := New().Inventory(ctx(t), r, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertComplete(t, inv)
	a := netip.MustParseAddr
	eq(t, "interfaces", inv.Interfaces, []drivers.Interface{
		{Index: 1, Name: "Gi1/0/1", Alias: "uplink", SpeedBps: 1e9, OperUp: true, MAC: "00:11:22:33:44:01"},
		{Index: 2, Name: "Gi1/0/2", Alias: "server", SpeedBps: 1e9, MAC: "00:11:22:33:44:02"},
		{Index: 3, Name: "Gi1/0/3", SpeedBps: 1e9, MAC: "00:11:22:33:44:03"},
	})
	eq(t, "arp", inv.ARP, []drivers.ARPEntry{
		{IP: a("10.0.0.1"), MAC: "00:aa:bb:cc:dd:01", IfIndex: 1},
		{IP: a("10.0.0.2"), MAC: "00:aa:bb:cc:dd:02", IfIndex: 1},
		{IP: a("fe80::1"), MAC: "00:aa:bb:cc:dd:03", IfIndex: 2},
	})
	eq(t, "mac", inv.MAC, []drivers.MACEntry{
		{MAC: "00:aa:bb:cc:dd:01", VLAN: 1, IfIndex: 1},
		{MAC: "00:aa:bb:cc:dd:02", VLAN: 10, IfIndex: 2},
		{MAC: "00:aa:bb:cc:dd:03", VLAN: 10, IfIndex: 3},
		{MAC: "00:aa:bb:cc:dd:04", VLAN: 20, IfIndex: 2},
	})
	eq(t, "vlans", inv.VLANs, []drivers.VLAN{{ID: 1, Name: "default"}, {ID: 10, Name: "users"}, {ID: 20, Name: "servers"}})
	eq(t, "lldp", inv.LLDP, []drivers.LLDPNeighbor{
		{LocalIfIndex: 1, ChassisID: "00:aa:bb:cc:dd:01", PortID: "gi0/1", PortDescr: "to sim-sw1", SysName: "sim-core1", MgmtAddr: a("10.0.0.1")},
		{LocalIfIndex: 2, ChassisID: "core-2", PortID: "00:aa:bb:cc:dd:02", SysName: "sim[31m-sw2"},
	})
	eq(t, "entities", inv.Entities, []drivers.Entity{
		{Index: 1, Class: "chassis", Name: "chassis", Descr: "Synthetic switch chassis", Model: "SIM-SW-24", Serial: "SIM0001", FirmwareRev: "boot 1.2", SoftwareRev: "1.0.0"},
		{Index: 2, Class: "powerSupply", Name: "psu1", Descr: "PSU 1", Model: "PSU-150", Serial: "PSU0001"},
		{Index: 3, Class: "sensor", Name: "temp1", Descr: "Board temperature sensor"},
	})
	p := netip.MustParsePrefix
	eq(t, "routes", inv.Routes, []drivers.Route{
		{Dest: p("0.0.0.0/0"), NextHop: a("10.0.0.1"), IfIndex: 1, Proto: "netmgmt"},
		{Dest: p("10.0.0.0/24"), NextHop: a("0.0.0.0"), IfIndex: 1, Proto: "local"},
		{Dest: p("2001:db8::/32"), NextHop: a("fe80::1"), IfIndex: 2, Proto: "ospf"},
	})
	eq(t, "malformed", inv.Malformed, map[drivers.Table]int{
		drivers.TableARP: 2, drivers.TableMAC: 1, drivers.TableLLDP: 1, drivers.TableRoutes: 1,
	})
}

func TestGenericInventoryFallbacks(t *testing.T) {
	r := reader(t, "generic-router")
	inv, err := New().Inventory(ctx(t), r, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertComplete(t, inv)
	a := netip.MustParseAddr
	eq(t, "interfaces", inv.Interfaces, []drivers.Interface{
		{Index: 1, Name: "eth0", SpeedBps: 1e8, OperUp: true, MAC: "00:aa:bb:cc:ee:10"},
		{Index: 2, Name: "eth1", SpeedBps: 1e8, MAC: "00:aa:bb:cc:ee:11"},
	})
	eq(t, "arp", inv.ARP, []drivers.ARPEntry{
		{IP: a("192.0.2.10"), MAC: "00:aa:bb:cc:ee:01", IfIndex: 1},
		{IP: a("198.51.100.7"), MAC: "00:aa:bb:cc:ee:02", IfIndex: 2},
	})
	eq(t, "mac", inv.MAC, []drivers.MACEntry{
		{MAC: "00:aa:bb:cc:ee:01", IfIndex: 1},
		{MAC: "00:aa:bb:cc:ee:02", IfIndex: 2},
	})
	eq(t, "routes", inv.Routes, []drivers.Route{
		{Dest: netip.MustParsePrefix("0.0.0.0/0"), NextHop: a("192.0.2.1"), IfIndex: 1, Proto: "netmgmt"},
		{Dest: netip.MustParsePrefix("192.0.2.0/24"), NextHop: a("0.0.0.0"), IfIndex: 1, Proto: "local"},
	})
	if len(inv.VLANs)+len(inv.LLDP)+len(inv.Entities) != 0 {
		t.Errorf("unexpected rows: %+v %+v %+v", inv.VLANs, inv.LLDP, inv.Entities)
	}
	eq(t, "malformed", inv.Malformed, map[drivers.Table]int{drivers.TableRoutes: 1})
}

/*
faultReader wraps a simulator session: walks under failRoot return
snmp.ErrTimeout after `after` variables; every walked root is recorded.
*/
type faultReader struct {
	snmp.Reader
	failRoot string
	after    int
	mu       sync.Mutex
	roots    []string
}

func (f *faultReader) Walk(ctx context.Context, root string, fn func(snmp.Var) error) error {
	f.mu.Lock()
	f.roots = append(f.roots, root)
	f.mu.Unlock()
	if f.failRoot == "" || !strings.HasPrefix(root+".", f.failRoot+".") {
		return f.Reader.Walk(ctx, root, fn)
	}
	n := 0
	return f.Reader.Walk(ctx, root, func(v snmp.Var) error {
		if n == f.after {
			return snmp.ErrTimeout
		}
		n++
		return fn(v)
	})
}

func (f *faultReader) walked(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.roots {
		if strings.HasPrefix(r+".", prefix+".") {
			return true
		}
	}
	return false
}

const (
	qBridgeFdb = "1.3.6.1.2.1.17.7.1.2.2"
	bridgeFdb  = "1.3.6.1.2.1.17.4.3"
)

func TestPartialWalkNotComplete(t *testing.T) {
	r := reader(t, "generic-switch")
	/* fail in the middle of the FDB, and on its very first variable (no rows, so no fallback either) */
	for _, after := range []int{2, 0} {
		f := &faultReader{Reader: r, failRoot: qBridgeFdb, after: after}
		inv, err := New().Inventory(ctx(t), f, nil)
		if err != nil {
			t.Fatal(err)
		}
		assertComplete(t, inv, drivers.TableMAC)
		if !errors.Is(inv.Errors[drivers.TableMAC], snmp.ErrTimeout) {
			t.Fatalf("after %d: Errors[MAC] = %v", after, inv.Errors[drivers.TableMAC])
		}
		if len(inv.MAC) > after {
			t.Fatalf("after %d: rows beyond the failure point: %+v", after, inv.MAC)
		}
		if f.walked(bridgeFdb) {
			t.Fatalf("after %d: a failed Q-BRIDGE walk must not fall back to BRIDGE-MIB", after)
		}
		if len(inv.ARP) != 3 || len(inv.Routes) != 3 {
			t.Fatalf("after %d: other tables lost rows: arp=%d routes=%d", after, len(inv.ARP), len(inv.Routes))
		}
	}
}

func TestRowCapNotComplete(t *testing.T) {
	r := reader(t, "generic-switch")
	d := New()
	d.maxRows = 5 /* the switch FDB column has 6 rows; no other column has more than 5 */
	inv, err := d.Inventory(ctx(t), r, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertComplete(t, inv, drivers.TableMAC)
	if !errors.Is(inv.Errors[drivers.TableMAC], drivers.ErrTooManyRows) {
		t.Fatalf("Errors[MAC] = %v", inv.Errors[drivers.TableMAC])
	}
}

func TestSkipHeavy(t *testing.T) {
	f := &faultReader{Reader: reader(t, "generic-switch")}
	c := drivers.WithBudget(ctx(t), drivers.Budget{SkipHeavy: true})
	inv, err := New().Inventory(c, f, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertComplete(t, inv, drivers.TableMAC)
	if len(inv.MAC) != 0 || f.walked(qBridgeFdb) || f.walked(bridgeFdb) {
		t.Fatalf("FDB walked under SkipHeavy: rows=%d", len(inv.MAC))
	}
}

func TestInventoryStopsOnCallerCancel(t *testing.T) {
	r := reader(t, "generic-switch")
	c, cancel := context.WithCancel(context.Background())
	cancel()
	inv, err := New().Inventory(c, r, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	for _, tb := range allTables {
		if inv.Complete[tb] {
			t.Fatalf("%s complete after cancel", tb)
		}
	}
}

func TestRegistryFallsBackToGeneric(t *testing.T) {
	d := drivers.Default().Select("1.3.6.1.4.1.32473.99", "Unknown device")
	if d == nil || d.Name() != "generic-snmp" {
		t.Fatalf("selected %v", d)
	}
	if !reflect.DeepEqual(d.Dialect(), New().Dialect()) || d.Dialect().ExecPrompt != nil || len(d.Dialect().Allowlist) != 0 {
		t.Fatal("generic driver must not carry an SSH dialect")
	}
}

/* staticReader serves Get and Walk from a fixed variable list, without a simulator. */
type staticReader struct{ vars []snmp.Var }

func (s staticReader) Get(_ context.Context, oids ...string) ([]snmp.Var, error) {
	var out []snmp.Var
	for _, o := range oids {
		for _, v := range s.vars {
			if v.OID == o {
				out = append(out, v)
			}
		}
	}
	return out, nil
}

func (s staticReader) Walk(ctx context.Context, root string, fn func(snmp.Var) error) error {
	for _, v := range s.vars {
		if strings.HasPrefix(v.OID, root+".") {
			if err := fn(v); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

func (s staticReader) BulkGet(context.Context, []string) ([]snmp.Var, error) { return nil, nil }

func ctr(oid string, n uint64) snmp.Var {
	return snmp.Var{OID: oid, Type: snmp.TypeCounter32, Value: n}
}
func c64(oid string, n uint64) snmp.Var {
	return snmp.Var{OID: oid, Type: snmp.TypeCounter64, Value: n}
}

var upTime = snmp.Var{OID: oidSysUpTime, Type: snmp.TypeTimeTicks, Value: uint64(100)}

func TestCollectDropsRowsMissingOctets(t *testing.T) {
	t.Parallel()
	/* if1 complete; if2 vanished before ifOutOctets was walked; if3 only in ifDescr */
	r := staticReader{vars: []snmp.Var{
		upTime,
		{OID: ifEntry + ".2.1", Type: snmp.TypeOctetString, Value: []byte("a")},
		{OID: ifEntry + ".2.2", Type: snmp.TypeOctetString, Value: []byte("b")},
		{OID: ifEntry + ".2.3", Type: snmp.TypeOctetString, Value: []byte("c")},
		ctr(ifEntry+".10.1", 100), ctr(ifEntry+".10.2", 200),
		ctr(ifEntry+".14.1", 7),
		ctr(ifEntry+".16.1", 300),
	}}
	s, err := New().Collect(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	want := []drivers.IfCounters{{Index: 1, Name: "a", InOctets: 100, OutOctets: 300, InErrors: u(7)}}
	eq(t, "interfaces", s.Interfaces, want)
	if s.Incomplete != 2 {
		t.Fatalf("Incomplete = %d, want 2", s.Incomplete)
	}
}

func TestCollectNeverMixesCounterFamilies(t *testing.T) {
	t.Parallel()
	/* HC-capable device: if1 has HC in+out; if2 only 32-bit (e.g. a slow serial port); if3 HC in but no HC out */
	r := staticReader{vars: []snmp.Var{
		upTime,
		ctr(ifEntry+".10.1", 1), ctr(ifEntry+".10.2", 2), ctr(ifEntry+".10.3", 3),
		ctr(ifEntry+".16.1", 1), ctr(ifEntry+".16.2", 2), ctr(ifEntry+".16.3", 3),
		c64(ifXEntry+".6.1", 1e12), c64(ifXEntry+".6.3", 3e12),
		c64(ifXEntry+".10.1", 2e12),
	}}
	s, err := New().Collect(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "interfaces", s.Interfaces, []drivers.IfCounters{
		{Index: 1, InOctets: 1e12, OutOctets: 2e12, HC: true},
		{Index: 2, InOctets: 2, OutOctets: 2},
	})
	if s.Incomplete != 1 {
		t.Fatalf("Incomplete = %d, want 1 (if3 with a single HC octet)", s.Incomplete)
	}
}
