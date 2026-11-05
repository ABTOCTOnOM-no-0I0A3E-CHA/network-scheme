package transport_test

import (
	"context"
	"net"
	"net/netip"

	"github.com/beekamai/network-scheme/cmd/executor/internal/netguard"
	"github.com/beekamai/network-scheme/cmd/executor/internal/transport"
)

/* The registry tests run through the executor's real network guard too (management subnet 192.0.2.0/24). */
func init() {
	guards["netguard"] = guardKind{denied: netguard.ErrDenied, build: func(dial func(ctx context.Context, address string) (net.Conn, error)) (transport.Dialer, error) {
		return netguard.New([]netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, netguard.Stack{
			Core: netip.MustParsePrefix("172.30.0.0/24"), Xnet: netip.MustParsePrefix("172.30.1.0/24"),
			Devices: netip.MustParsePrefix("172.30.2.0/24"), Edge: netip.MustParsePrefix("172.30.3.0/24"),
		}, func(ctx context.Context, _, address string) (net.Conn, error) { return dial(ctx, address) })
	}}
}
