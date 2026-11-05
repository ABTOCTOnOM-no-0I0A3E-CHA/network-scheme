package session_test

import (
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/mes6"
	"github.com/beekamai/network-scheme/cmd/executor/internal/session"
)

/*
The management context of the MES 6.x fixture: the SVI carrying the
registry address names VLAN 99, and the uplink is the port where the next
hop's MAC was learned (the default gateway, or the executor itself when it
is in the SVI's subnet). Anything missing refuses.
*/
func TestMgmtTargets(t *testing.T) {
	raw, err := os.ReadFile("../../../../test/fixtures/devices/mes6/config/running.cfg")
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(raw) + gatewayLine
	d := mes6.New()
	want := func(kind, name string) []core.Target {
		ts, ok := d.Targets(kind, name)
		if !ok {
			t.Fatalf("targets %s %s", kind, name)
		}
		return ts
	}
	vlan, port := want("vlan", "99"), want("interface", "gi1/0/1")
	got, err := session.MgmtTargets(d, cfg, devAddr, netip.MustParseAddr("10.9.9.9"), arpOut, macOut)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range append(vlan, port...) {
		if !slices.Contains(got, w) {
			t.Errorf("missing %v in %v", w, got)
		}
	}
	/* the executor in the SVI's subnet: its own ARP entry */
	self := strings.ReplaceAll(arpOut, "192.0.2.1 ", "192.0.2.77 ")
	if _, err := session.MgmtTargets(d, cfg, devAddr, netip.MustParseAddr("192.0.2.77"), self, macOut); err != nil {
		t.Fatalf("same subnet: %v", err)
	}
	for name, c := range map[string][3]string{
		"no interface carries the address": {strings.ReplaceAll(cfg, "192.0.2.10", "192.0.2.11"), arpOut, macOut},
		"no gateway":                       {string(raw), arpOut, macOut},
		"no ARP entry":                     {cfg, "", macOut},
		"no port of the MAC":               {cfg, strings.ReplaceAll(arpOut, "gi1/0/1", "-"), ""},
	} {
		if _, err := session.MgmtTargets(d, c[0], devAddr, netip.MustParseAddr("10.9.9.9"), c[1], c[2]); err == nil {
			t.Errorf("%s: no refusal", name)
		}
	}
}

/* Device text never panics the management context, and a result always holds the management interface's targets. */
func FuzzMgmtTargets(f *testing.F) {
	raw, err := os.ReadFile("../../../../test/fixtures/devices/mes6/config/running.cfg")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(string(raw)+gatewayLine, arpOut, macOut)
	f.Add("interface vlan 99\n ip address 192.0.2.10/24\n", "192.0.2.77 aaaa.bbbb.cccc gi1/0/1-48", "aaaa.bbbb.cccc vlan 4095")
	d := mes6.New()
	f.Fuzz(func(t *testing.T, cfg, arp, macs string) {
		got, err := session.MgmtTargets(d, cfg, devAddr, netip.MustParseAddr("192.0.2.77"), arp, macs)
		if err == nil && len(got) == 0 {
			t.Fatal("an empty management context")
		}
	})
}
