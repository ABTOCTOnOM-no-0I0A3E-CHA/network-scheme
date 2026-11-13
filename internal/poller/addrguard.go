package poller

import (
	"errors"
	"fmt"
	"net/netip"
)

/* errAddrDenied is every device or scan address the poller refuses to contact. */
var errAddrDenied = errors.New("poller: address not allowed")

var (
	thisNetwork = netip.MustParsePrefix("0.0.0.0/8")
	reserved4   = netip.MustParsePrefix("240.0.0.0/4") /* class E, 255.255.255.255 included */
)

/*
newAddrGuard is the poller's own SSRF check (security.md 13, A01): the api
validates device addresses, but it is not trusted (N3) and writes core.device
and discovery scans directly, so the poller refuses on its own, before any
credential leaves (SNMP community or v3 HMAC, SSH password): loopback,
link-local (169.254.169.254 included), multicast, unspecified, "this
network", broadcast and reserved addresses, and every address inside deny,
the stack's own networks (core, xnet, edge from poller.yaml): the egress
rules filter only what leaves through the devices network, so a device
address in core would reach the api's container directly.
*/
func newAddrGuard(deny []netip.Prefix) func(netip.Addr) error {
	deny = append([]netip.Prefix(nil), deny...)
	return func(a netip.Addr) error {
		a = a.Unmap()
		why := ""
		switch {
		case !a.IsValid():
			why = "no address"
		case a.Zone() != "":
			why = "zoned"
		case a.IsUnspecified() || (a.Is4() && thisNetwork.Contains(a)):
			why = "unspecified"
		case a.IsLoopback():
			why = "loopback"
		case a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast():
			why = "link-local"
		case a.IsMulticast() || a.IsInterfaceLocalMulticast():
			why = "multicast"
		case a.Is4() && reserved4.Contains(a):
			why = "reserved or broadcast"
		}
		for _, p := range deny {
			if why == "" && p.Contains(a) {
				why = "inside the stack network " + p.String()
			}
		}
		if why != "" {
			return fmt.Errorf("%w: %s: %s", errAddrDenied, a, why)
		}
		return nil
	}
}
