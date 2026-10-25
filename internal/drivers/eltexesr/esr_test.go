package eltexesr_test

import (
	"context"
	"maps"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/drivers/eltexesr"
	"github.com/beekamai/network-scheme/internal/drivers/eltexmes"
	"github.com/beekamai/network-scheme/internal/drivers/generic"
	"github.com/beekamai/network-scheme/internal/snmp"
	"github.com/beekamai/network-scheme/test/sim/snmpsim/simtest"
)

func TestESRMatch(t *testing.T) {
	reg := drivers.NewRegistry(eltexesr.New(), eltexmes.New(), generic.New())
	if n := reg.Select(simtest.FixtureSys(t, "eltex-esr.snmprec")).Name(); n != eltexesr.Name {
		t.Fatalf("eltex-esr fixture selected %s", n)
	}
	for _, f := range []string{"eltex-mes.snmprec", "generic-switch.snmprec", "generic-router.snmprec"} {
		if eltexesr.New().Match(simtest.FixtureSys(t, f)) {
			t.Errorf("ESR matches %s", f)
		}
	}
	const descr = "Eltex ESR-100 Service Router 1.24.0 build 53"
	for oid, want := range map[string]bool{
		"1.3.6.1.4.1.35265.1.66":  true,
		"1.3.6.1.4.1.352650.1.66": false,
		"1.3.6.1.4.1.35265.10.66": false,
		"1.3.6.1.4.1.32473.1.66":  false, /* sysDescr alone is not enough */
	} {
		if got := eltexesr.New().Match(oid, descr); got != want {
			t.Errorf("Match(%s) = %v, want %v", oid, got, want)
		}
	}
	if eltexesr.New().Match("1.3.6.1.4.1.35265.1.66", "24-port 10/100/1000 Ethernet Switch") {
		t.Error("ESR matches a non-ESR sysDescr")
	}
}

func reader(t *testing.T) snmp.Reader {
	t.Helper()
	t.Parallel()
	addr := simtest.Start(t, simtest.Fixture("eltex-esr.snmprec"))
	r, c, err := snmp.Dial(context.Background(), addr, simtest.V2Cred("eltex-esr"), snmp.Options{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return r
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return c
}

func TestESRCollectResources(t *testing.T) {
	s, err := eltexesr.New().Collect(ctx(t), reader(t))
	if err != nil {
		t.Fatal(err)
	}
	m := s.System
	if m.CPUPct == nil || *m.CPUPct != 25 {
		t.Errorf("CPUPct = %v, want 25 (mean of 4 cores)", m.CPUPct)
	}
	if m.MemUsedPct == nil || *m.MemUsedPct != 30 {
		t.Errorf("MemUsedPct = %v, want 30 (invalid pool ignored)", m.MemUsedPct)
	}
	if m.TempC == nil || *m.TempC != 42 {
		t.Errorf("TempC = %v, want 42 (sensor with status != ok ignored)", m.TempC)
	}
	if len(s.Interfaces) != 2 || s.Interfaces[1].OutOctets != 8000 {
		t.Errorf("interfaces from the embedded generic driver: %+v", s.Interfaces)
	}
}

func TestUnknownResourceIsNil(t *testing.T) {
	/* ESR documentation gives no power-supply OID: PSUOk must stay nil. */
	s, err := eltexesr.New().Collect(ctx(t), reader(t))
	if err != nil {
		t.Fatal(err)
	}
	if s.System.PSUOk != nil {
		t.Fatalf("PSUOk = %v, want nil", *s.System.PSUOk)
	}
}

func TestESRRoutes(t *testing.T) {
	inv, err := eltexesr.New().Inventory(ctx(t), reader(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !inv.Complete[drivers.TableRoutes] {
		t.Fatalf("routes incomplete: %v", inv.Errors[drivers.TableRoutes])
	}
	p, a := netip.MustParsePrefix, netip.MustParseAddr
	want := []drivers.Route{
		{Dest: p("0.0.0.0/0"), NextHop: a("192.0.2.1"), IfIndex: 1, Proto: "netmgmt"},
		{Dest: p("192.0.2.0/24"), NextHop: a("0.0.0.0"), IfIndex: 1, Proto: "local"},
		{Dest: p("198.51.100.0/25"), NextHop: a("203.0.113.2"), IfIndex: 2, Proto: "bgp"},
		{Dest: p("203.0.113.0/24"), NextHop: a("0.0.0.0"), IfIndex: 2, Proto: "local"},
	}
	if !reflect.DeepEqual(inv.Routes, want) {
		t.Fatalf("routes\n got %+v\nwant %+v", inv.Routes, want)
	}
}

func TestDialectAllowlistReadOnly(t *testing.T) {
	d := eltexesr.New().Dialect()
	if len(d.Allowlist) == 0 || len(d.PagerOff) == 0 || d.ExecPrompt == nil {
		t.Fatalf("incomplete dialect %+v", d)
	}
	for _, c := range d.Allowlist {
		if !strings.HasPrefix(c.Name, "show ") {
			t.Errorf("allowlist command %q is not a show command", c.Name)
		}
	}
	for _, p := range d.PagerOff {
		for _, bad := range []string{"write", "configure", "copy", "reload"} {
			if strings.Contains(strings.ToLower(p), bad) {
				t.Errorf("PagerOff %q contains %q", p, bad)
			}
		}
	}
	/* the runner anchors the prompt as ^(?:...)$ */
	re := regexp.MustCompile(`^(?:` + d.ExecPrompt.String() + `)$`)
	for line, want := range map[string]bool{
		"esr#": true, "esr-100#": true, "edge.r1#": true,
		"esr>": false, "esr(config)#": false, "esr(config-if-gi)#": false,
		"esr# show": false, "#": false,
	} {
		if re.MatchString(line) != want {
			t.Errorf("prompt %q: match = %v, want %v", line, !want, want)
		}
	}
}

func TestVerifiedFlag(t *testing.T) {
	if eltexesr.Verified || eltexesr.New().Verified() {
		t.Fatal("ESR driver must stay unverified until checked on hardware")
	}
}

func TestESRPortKinds(t *testing.T) {
	inv, err := eltexesr.New().Inventory(ctx(t), reader(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]drivers.PortKind{}
	for _, i := range inv.Interfaces {
		got[i.Name] = i.PortKind
	}
	if want := map[string]drivers.PortKind{"gi1/0/1": drivers.PortRJ45, "te1/0/1": drivers.PortSFP}; !maps.Equal(got, want) {
		t.Fatalf("port kinds %v, want %v", got, want)
	}
}
