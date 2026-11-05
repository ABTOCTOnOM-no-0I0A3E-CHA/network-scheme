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

/*
I3: the context widens to every port carrying the management VLAN (access,
an allowed list including it, a trunk without a list) and to every member
of a port-channel in it; an ARP entry through an SVI needs a physical port
even when the management interface is routed; a routed or loopback
management interface takes the ARP entry's port.
*/
func TestMgmtTargetsWidened(t *testing.T) {
	d := mes6.New()
	tg := func(kind, name string) core.Target {
		ts, ok := d.Targets(kind, name)
		if !ok || len(ts) != 1 {
			t.Fatalf("targets %s %s", kind, name)
		}
		return ts[0]
	}
	self := netip.MustParseAddr("10.9.9.9")
	svi := "interface vlan 99\n ip address 192.0.2.10 255.255.255.0\nexit\n" + gatewayLine
	ports := "interface gigabitethernet1/0/3\n switchport access vlan 99\nexit\n" +
		"interface gigabitethernet1/0/4\n switchport trunk allowed vlan add 10,90-100\nexit\n" +
		"interface gigabitethernet1/0/5\n switchport mode trunk\n switchport trunk allowed vlan add 10\nexit\n" +
		"interface gigabitethernet1/0/6\n switchport access vlan 10\nexit\n" +
		"interface gigabitethernet1/0/7\n channel-group 1 mode auto\nexit\n" +
		"interface gigabitethernet1/0/8\n channel-group 2 mode auto\nexit\n"
	lagMAC := strings.ReplaceAll(macOut, "gi1/0/1 ", "po1     ")
	got, err := session.MgmtTargets(d, svi+ports, devAddr, self, strings.ReplaceAll(arpOut, "gi1/0/1", "-"), lagMAC)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"gi1/0/3", "gi1/0/4", "po1", "gi1/0/7"} {
		if !slices.Contains(got, tg("interface", n)) {
			t.Errorf("missing %s in %v", n, got)
		}
	}
	for _, n := range []string{"gi1/0/5", "gi1/0/6", "gi1/0/8"} {
		if slices.Contains(got, tg("interface", n)) {
			t.Errorf("%s does not carry the management VLAN: %v", n, got)
		}
	}

	routed := "interface gigabitethernet1/0/24\n ip address 192.0.2.10 255.255.255.0\nexit\n" + gatewayLine
	arpRouted := " gi1/0/24  192.0.2.1  a8:f9:4b:00:00:01  dynamic\n"
	if got, err := session.MgmtTargets(d, routed, devAddr, self, arpRouted, ""); err != nil || !slices.Contains(got, tg("interface", "gi1/0/24")) {
		t.Errorf("routed: %v %v", got, err)
	}
	/* the ARP entry is through an SVI: a routed management interface does not exempt it from a physical port */
	if _, err := session.MgmtTargets(d, routed, devAddr, self, " vlan 99  192.0.2.1  a8:f9:4b:00:00:01  dynamic\n", ""); err == nil {
		t.Error("an ARP entry through an SVI without a port was accepted")
	}
	loop := "interface loopback 1\n ip address 192.0.2.10 255.255.255.255\nexit\n" + gatewayLine
	if got, err := session.MgmtTargets(d, loop, devAddr, self, arpRouted, ""); err != nil || !slices.Contains(got, tg("interface", "gi1/0/24")) {
		t.Errorf("loopback: %v %v", got, err)
	}
	if _, err := session.MgmtTargets(d, loop, devAddr, self, " 192.0.2.1  a8:f9:4b:00:00:01  dynamic\n", ""); err == nil {
		t.Error("a loopback management interface without a physical port was accepted")
	}
}
