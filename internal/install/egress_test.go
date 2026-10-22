package install_test

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/internal/install"
)

/*
fakeIPTables emulates the filter table's DOCKER-USER chain for the commands
ApplyEgress uses (-L, -N, -C, -I 1, -D). Rules are stored as joined argv.
*/
type fakeIPTables struct {
	chain []string
	exist bool
}

var errNoRule = errors.New("iptables: bad rule (does a matching rule exist in that chain?)")

func (f *fakeIPTables) run(c install.Cmd) error {
	a := c.Args
	if c.Name != "iptables" || len(a) < 3 || a[0] != "-w" {
		return errors.New("unexpected command " + cmdline(c))
	}
	op, chain, rest := a[1], a[2], a[3:]
	if op == "-n" { /* -n -L CHAIN */
		chain = a[3]
	}
	if chain != "DOCKER-USER" {
		return errors.New("unexpected chain in " + cmdline(c))
	}
	if op == "-N" {
		f.exist = true
		return nil
	}
	if !f.exist {
		return errors.New("iptables: no chain/target/match by that name")
	}
	switch op {
	case "-n":
		return nil
	case "-C", "-D":
		i := slices.Index(f.chain, strings.Join(rest, " "))
		if i < 0 {
			return errNoRule
		}
		if op == "-D" {
			f.chain = slices.Delete(f.chain, i, i+1)
		}
		return nil
	case "-I":
		if len(rest) == 0 || rest[0] != "1" {
			return errors.New("insert without position 1: " + cmdline(c))
		}
		f.chain = slices.Insert(f.chain, 0, strings.Join(rest[1:], " "))
		return nil
	}
	return errors.New("unexpected operation " + cmdline(c))
}

func testEgress() install.Egress {
	return install.Egress{
		DevicesSubnet: netip.MustParsePrefix("172.30.1.0/24"),
		MgmtSubnets:   []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.168.10.0/24")},
	}
}

/* wantChain is the chain ApplyEgress must produce on top of whatever was there. */
var wantChain = []string{
	"-s 172.30.1.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
	"-s 172.30.1.0/24 -d 10.0.0.0/8 -j RETURN",
	"-s 172.30.1.0/24 -d 192.168.10.0/24 -j RETURN",
	"-s 172.30.1.0/24 -j DROP",
}

func applyEgress(t *testing.T, ipt *fakeIPTables, e install.Egress) []string {
	t.Helper()
	sys := newFakeSys()
	sys.run = ipt.run
	if err := install.ApplyEgress(context.Background(), sys, e); err != nil {
		t.Fatalf("ApplyEgress: %v", err)
	}
	var lines []string
	for _, c := range sys.cmds {
		lines = append(lines, cmdline(c))
	}
	return lines
}

func TestEgressRulesArgv(t *testing.T) {
	/* Fresh host before Docker started: the chain is created, DROP goes in first, allows above it. */
	ipt := &fakeIPTables{}
	got := applyEgress(t, ipt, testEgress())
	want := []string{
		"iptables -w -n -L DOCKER-USER",
		"iptables -w -N DOCKER-USER",
		"iptables -w -C DOCKER-USER -s 172.30.1.0/24 -j DROP",
		"iptables -w -C DOCKER-USER -s 172.30.1.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
		"iptables -w -C DOCKER-USER -s 172.30.1.0/24 -d 10.0.0.0/8 -j RETURN",
		"iptables -w -C DOCKER-USER -s 172.30.1.0/24 -d 192.168.10.0/24 -j RETURN",
		"iptables -w -I DOCKER-USER 1 -s 172.30.1.0/24 -j DROP",
		"iptables -w -C DOCKER-USER -s 172.30.1.0/24 -d 192.168.10.0/24 -j RETURN",
		"iptables -w -I DOCKER-USER 1 -s 172.30.1.0/24 -d 192.168.10.0/24 -j RETURN",
		"iptables -w -C DOCKER-USER -s 172.30.1.0/24 -d 10.0.0.0/8 -j RETURN",
		"iptables -w -I DOCKER-USER 1 -s 172.30.1.0/24 -d 10.0.0.0/8 -j RETURN",
		"iptables -w -C DOCKER-USER -s 172.30.1.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
		"iptables -w -I DOCKER-USER 1 -s 172.30.1.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("argv:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if !slices.Equal(ipt.chain, wantChain) {
		t.Fatalf("chain:\n%s\nwant (DROP last):\n%s", strings.Join(ipt.chain, "\n"), strings.Join(wantChain, "\n"))
	}

	/* Idempotent: a second run only checks. */
	for _, line := range applyEgress(t, ipt, testEgress()) {
		if !strings.Contains(line, " -C ") && !strings.Contains(line, " -L ") {
			t.Errorf("second run changed the chain: %s", line)
		}
	}
	if !slices.Equal(ipt.chain, wantChain) {
		t.Fatalf("chain after second run:\n%s", strings.Join(ipt.chain, "\n"))
	}
}

func TestEgressKeepsForeignRulesBelow(t *testing.T) {
	/* Docker < 28 ends DOCKER-USER with RETURN; an admin may have own rules. */
	ipt := &fakeIPTables{exist: true, chain: []string{"-s 10.9.9.9/32 -j DROP", "-j RETURN"}}
	applyEgress(t, ipt, testEgress())
	if want := append(slices.Clone(wantChain), "-s 10.9.9.9/32 -j DROP", "-j RETURN"); !slices.Equal(ipt.chain, want) {
		t.Fatalf("chain:\n%s", strings.Join(ipt.chain, "\n"))
	}
}

func TestEgressRestoresOrderWhenDropMissing(t *testing.T) {
	/* Someone deleted the DROP: re-inserting it on top must not shadow the allows. */
	ipt := &fakeIPTables{exist: true, chain: slices.Clone(wantChain[:3])}
	applyEgress(t, ipt, testEgress())
	if !slices.Equal(ipt.chain, wantChain) {
		t.Fatalf("chain:\n%s\nwant:\n%s", strings.Join(ipt.chain, "\n"), strings.Join(wantChain, "\n"))
	}

	/* A missing allow rule goes back above the DROP. */
	ipt = &fakeIPTables{exist: true, chain: []string{wantChain[0], wantChain[2], wantChain[3]}}
	applyEgress(t, ipt, testEgress())
	if ipt.chain[len(ipt.chain)-1] != wantChain[3] || len(ipt.chain) != 4 || !slices.Contains(ipt.chain, wantChain[1]) {
		t.Fatalf("chain:\n%s", strings.Join(ipt.chain, "\n"))
	}
}

func TestEgressRejectsBadConfigBeforeRunning(t *testing.T) {
	cases := map[string]func(*install.Egress){
		"no mgmt subnet":    func(e *install.Egress) { e.MgmtSubnets = nil },
		"no devices subnet": func(e *install.Egress) { e.DevicesSubnet = netip.Prefix{} },
		"ipv6 mgmt":         func(e *install.Egress) { e.MgmtSubnets = []netip.Prefix{netip.MustParsePrefix("fd00::/64")} },
		"default route":     func(e *install.Egress) { e.MgmtSubnets = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")} },
		"loopback":          func(e *install.Egress) { e.MgmtSubnets = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")} },
		"host bits":         func(e *install.Egress) { e.MgmtSubnets = []netip.Prefix{netip.MustParsePrefix("10.0.0.1/8")} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := testEgress()
			mutate(&e)
			sys := newFakeSys()
			if err := install.ApplyEgress(context.Background(), sys, e); err == nil {
				t.Fatal("ApplyEgress accepted a bad config")
			}
			if len(sys.cmds) != 0 {
				t.Fatalf("commands ran: %v", sys.cmds)
			}
		})
	}
}

func TestEgressErrorsCarryIPTablesStderr(t *testing.T) {
	const reason = "iptables v1.8.10 (nf_tables): Could not fetch rule set generation id: Permission denied (you must be root)"
	sys := newFakeSys()
	sys.run = func(c install.Cmd) error {
		if c.Stderr == nil {
			t.Fatalf("no stderr for %s", cmdline(c))
		}
		_, _ = io.WriteString(c.Stderr, reason+"\n"+strings.Repeat("x", 2000))
		return errors.New("exit status 4")
	}
	err := install.ApplyEgress(context.Background(), sys, testEgress())
	if err == nil || !strings.Contains(err.Error(), reason) || !strings.Contains(err.Error(), "exit status 4") {
		t.Fatalf("ApplyEgress error = %v, want the iptables reason", err)
	}
	if len(err.Error()) > 1024 {
		t.Fatalf("error not bounded: %d bytes", len(err.Error()))
	}
	err = install.CheckDockerUsesEgress(context.Background(), sys)
	if !errors.Is(err, install.ErrEgressBypassed) || !strings.Contains(err.Error(), reason) {
		t.Fatalf("CheckDockerUsesEgress error = %v", err)
	}
}

func TestParseMgmtSubnets(t *testing.T) {
	got, err := install.ParseMgmtSubnets([]string{"10.0.0.0/8", "192.168.10.0/24"})
	if err != nil || !slices.Equal(got, testEgress().MgmtSubnets) {
		t.Fatalf("ParseMgmtSubnets = %v, %v", got, err)
	}
	for _, bad := range [][]string{nil, {"10.0.0.1/8"}, {"10.0.0.0"}, {"169.254.0.0/16"}, {"224.0.0.0/4"}, {"fd00::/8"}, {"10.0.0.0/8", "x"}} {
		if _, err := install.ParseMgmtSubnets(bad); err == nil {
			t.Errorf("ParseMgmtSubnets(%q) accepted", bad)
		}
	}
}

func TestLoadEgress(t *testing.T) {
	p := filepath.Join(t.TempDir(), "egress.yaml")
	writeFile(t, p, "devices_subnet: 172.30.1.0/24\nmgmt_subnets: [10.0.0.0/8, 192.168.10.0/24]\n")
	e, err := install.LoadEgress(p)
	if err != nil || e.DevicesSubnet != testEgress().DevicesSubnet || !slices.Equal(e.MgmtSubnets, testEgress().MgmtSubnets) {
		t.Fatalf("LoadEgress = %+v, %v", e, err)
	}
	for _, bad := range []string{
		"devices_subnet: 172.30.1.0/24\nmgmt_subnets: []\n",
		"devices_subnet: 172.30.1.0/24\nmgmt_subnets: [10.0.0.0/8]\nextra: 1\n",
		"devices_subnet: nope\nmgmt_subnets: [10.0.0.0/8]\n",
	} {
		if err := os.WriteFile(p, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := install.LoadEgress(p); err == nil {
			t.Errorf("LoadEgress accepted %q", bad)
		}
	}
}
