// Package clientip derives the client address of an HTTP request.
package clientip

import (
	"net/http"
	"net/netip"
	"strings"
)

/*
FromRequest returns the client address of r. X-Forwarded-For is honoured only
when the direct peer (RemoteAddr) lies in trusted, and then only its last
entry: the gateway overwrites the header with the peer it saw, so earlier
entries are client-controlled. The result is unmapped and zone-free; it is
invalid when RemoteAddr cannot be parsed.
*/
func FromRequest(r *http.Request, trusted []netip.Prefix) netip.Addr {
	peer := parse(r.RemoteAddr)
	if !peer.IsValid() || !inAny(peer, trusted) {
		return peer
	}
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return peer
	}
	last := values[len(values)-1]
	if i := strings.LastIndexByte(last, ','); i >= 0 {
		last = last[i+1:]
	}
	if a, err := netip.ParseAddr(strings.TrimSpace(last)); err == nil {
		return a.Unmap().WithZone("")
	}
	return peer
}

/* parse accepts "host:port" (the net/http form) or a bare address. */
func parse(remote string) netip.Addr {
	if ap, err := netip.ParseAddrPort(remote); err == nil {
		return ap.Addr().Unmap().WithZone("")
	}
	if a, err := netip.ParseAddr(remote); err == nil {
		return a.Unmap().WithZone("")
	}
	return netip.Addr{}
}

func inAny(a netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
