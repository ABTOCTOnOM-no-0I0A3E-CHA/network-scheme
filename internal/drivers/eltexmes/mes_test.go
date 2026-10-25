package eltexmes_test

import (
	"context"
	"fmt"
	"maps"
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

func TestMESMatch(t *testing.T) {
	reg := drivers.NewRegistry(eltexesr.New(), eltexmes.New(), generic.New())
	if n := reg.Select(simtest.FixtureSys(t, "eltex-mes.snmprec")).Name(); n != eltexmes.Name {
		t.Fatalf("eltex-mes fixture selected %s", n)
	}
	for _, f := range []string{"generic-switch.snmprec", "generic-router.snmprec"} {
		if eltexmes.New().Match(simtest.FixtureSys(t, f)) {
			t.Errorf("MES matches %s", f)
		}
	}
	for oid, want := range map[string]bool{
		"1.3.6.1.4.1.35265.1.83":   true,
		"1.3.6.1.4.1.35265.1":      false, /* the arc itself is no product */
		"1.3.6.1.4.1.352650.1.83":  false, /* prefix must end on an arc boundary */
		"1.3.6.1.4.1.35265.10.83":  false, /* prefix must end on an arc boundary */
		"1.3.6.1.4.1.35265.2.1":    false, /* elSoftware, not hardware */
		"1.3.6.1.4.1.89.1.1.1.252": false,
	} {
		if got := eltexmes.New().Match(oid, "MES2324 Eltex"); got != want {
			t.Errorf("Match(%s) = %v, want %v", oid, got, want)
		}
	}
}

func reader(t *testing.T) snmp.Reader {
	t.Helper()
	t.Parallel()
	addr := simtest.Start(t, simtest.Fixture("eltex-mes.snmprec"))
	r, c, err := snmp.Dial(context.Background(), addr, simtest.V2Cred("eltex-mes"), snmp.Options{Timeout: 10 * time.Second})
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

func TestMESCollectResources(t *testing.T) {
	s, err := eltexmes.New().Collect(ctx(t), reader(t))
	if err != nil {
		t.Fatal(err)
	}
	m := s.System
	if m.CPUPct == nil || *m.CPUPct != 17 {
		t.Errorf("CPUPct = %v, want 17", m.CPUPct)
	}
	if m.TempC == nil || *m.TempC != 41 {
		t.Errorf("TempC = %v, want 41 (out-of-range 500 ignored)", m.TempC)
	}
	if m.PSUOk == nil || !*m.PSUOk {
		t.Errorf("PSUOk = %v, want true (main normal, redundant notPresent)", m.PSUOk)
	}
	if len(s.Interfaces) != 28 || !s.Interfaces[0].HC || s.Interfaces[0].InOctets != 1000 {
		t.Errorf("interfaces from the embedded generic driver: %+v", s.Interfaces)
	}
}

func TestUnknownResourceIsNil(t *testing.T) {
	/* The MES SNMP guide gives the RAM column per model only; without HOST-RESOURCES-MIB it stays nil. */
	s, err := eltexmes.New().Collect(ctx(t), reader(t))
	if err != nil {
		t.Fatal(err)
	}
	if s.System.MemUsedPct != nil {
		t.Fatalf("MemUsedPct = %v, want nil", *s.System.MemUsedPct)
	}
}

func TestDialectAllowlistReadOnly(t *testing.T) {
	d := eltexmes.New().Dialect()
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
		"console#": true, "sw-1.lab#": true, "core_sw#": true,
		"console>": false, "console(config)#": false, "console(config-if)#": false,
		"console# show": false, "#": false, "More: <space>,  Quit: q or CTRL+Z, One line: <return>": false,
	} {
		if re.MatchString(line) != want {
			t.Errorf("prompt %q: match = %v, want %v", line, !want, want)
		}
	}
}

func TestVerifiedFlag(t *testing.T) {
	if eltexmes.Verified || eltexmes.New().Verified() {
		t.Fatal("MES driver must stay unverified until checked on hardware")
	}
}

func TestMESPortKinds(t *testing.T) {
	inv, err := eltexmes.New().Inventory(ctx(t), reader(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]drivers.PortKind{}
	for _, i := range inv.Interfaces {
		got[i.Name] = i.PortKind
	}
	want := map[string]drivers.PortKind{}
	for n := 1; n <= 24; n++ {
		want[fmt.Sprintf("gi1/0/%d", n)] = drivers.PortRJ45
	}
	for n := 1; n <= 4; n++ {
		want[fmt.Sprintf("te1/0/%d", n)] = drivers.PortSFP
	}
	if !maps.Equal(got, want) {
		t.Fatalf("port kinds %v, want %v", got, want)
	}
}

func TestMESIdentify(t *testing.T) {
	id, err := eltexmes.New().Identify(ctx(t), reader(t))
	if err != nil {
		t.Fatal(err)
	}
	if id.Model != "MES2324" || id.Firmware != "6.6.2" || id.Serial != "ES5D000137" || id.Role != drivers.RoleL3Switch {
		t.Fatalf("identity %+v", id)
	}
}
