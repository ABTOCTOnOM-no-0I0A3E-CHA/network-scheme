package poller

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"testing"

	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/snmp"
	"github.com/beekamai/network-scheme/internal/ssh"
)

/*
Pentest F1 (SSRF, N3): a compromised api writes core.device and discovery
scans directly, so the poller itself refuses addresses no device has and the
stack's own networks, where a listener in the api's container would receive
the SNMP community or the SSH password; management addresses pass.
*/
func TestAddrGuard(t *testing.T) {
	g := newAddrGuard([]netip.Prefix{netip.MustParsePrefix("172.30.0.0/24"), netip.MustParsePrefix("172.30.2.0/24")})
	for _, s := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "0.0.0.0", "0.1.2.3", "::", "169.254.169.254", "fe80::1",
		"224.0.0.1", "ff02::1", "255.255.255.255", "240.0.0.1", "172.30.0.5", "::ffff:172.30.0.5", "172.30.2.2"} {
		if err := g(netip.MustParseAddr(s)); !errors.Is(err, errAddrDenied) {
			t.Errorf("%s: %v, want denied", s, err)
		}
	}
	if err := g(netip.Addr{}); !errors.Is(err, errAddrDenied) {
		t.Errorf("no address: %v", err)
	}
	for _, s := range []string{"10.0.0.1", "192.168.1.1", "172.30.1.10", "2001:db8::1"} {
		if err := g(netip.MustParseAddr(s)); err != nil {
			t.Errorf("%s: %v, want allowed", s, err)
		}
	}
}

/* Every SNMP dial (polls and discovery) and every SSH dial goes through the guard before a credential is used. */
func TestDeniedAddressGetsNoContact(t *testing.T) {
	dials := 0
	p := New(Config{Workers: 1, DenySubnets: []netip.Prefix{netip.MustParsePrefix("172.30.0.0/24")}}, Deps{
		DialSNMP: func(context.Context, netip.AddrPort, creds.Credential, snmp.Options) (snmp.Reader, io.Closer, error) {
			dials++
			return nil, nil, errors.New("dialled")
		},
	})
	c := creds.Credential{Kind: "snmp2c"}
	for _, s := range []string{"172.30.0.3:161", "127.0.0.1:161", "169.254.169.254:161"} {
		if _, _, err := p.dial(context.Background(), netip.MustParseAddrPort(s), c, snmp.Options{}); !errors.Is(err, errAddrDenied) {
			t.Errorf("snmp %s: %v", s, err)
		}
		/* refused before execpub.device_busy is read (the pool is nil here) and before any connection */
		if _, err := p.dialSSH(context.Background(), device{ID: 1, Addr: netip.MustParseAddrPort(s)}, c, ssh.Dialect{}); !errors.Is(err, errAddrDenied) {
			t.Errorf("ssh %s: %v", s, err)
		}
	}
	if dials != 0 {
		t.Fatalf("%d SNMP dials reached the dialer", dials)
	}
	if _, _, err := p.dial(context.Background(), netip.MustParseAddrPort("10.1.2.3:161"), c, snmp.Options{}); err == nil || errors.Is(err, errAddrDenied) || dials != 1 {
		t.Fatalf("a management address: %v (dials %d)", err, dials)
	}
}

func TestConfigDenySubnets(t *testing.T) {
	c, err := LoadConfig(writeConfig(t, minimalConfig+`deny_subnets: ["172.30.0.0/24", "172.30.2.0/24"]`+"\n"))
	if err != nil || len(c.DenySubnets) != 2 {
		t.Fatalf("%+v, %v", c.DenySubnets, err)
	}
	if _, err := LoadConfig(writeConfig(t, minimalConfig+`deny_subnets: ["172.30.0.5/24"]`+"\n")); err == nil {
		t.Error("a host address with prefix was accepted")
	}
}
