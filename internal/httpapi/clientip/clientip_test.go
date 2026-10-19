package clientip_test

import (
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/beekamai/network-scheme/internal/httpapi/clientip"
)

func TestFromRequest(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("fd00::/8")}
	cases := []struct {
		name   string
		remote string
		xff    []string
		want   string
	}{
		{"untrusted peer ignores XFF", "192.0.2.7:4000", []string{"1.2.3.4"}, "192.0.2.7"},
		{"no XFF", "10.1.1.1:4000", nil, "10.1.1.1"},
		{"trusted peer takes last entry", "10.1.1.1:4000", []string{"6.6.6.6, 203.0.113.9"}, "203.0.113.9"},
		{"last header line wins", "10.1.1.1:4000", []string{"6.6.6.6", "7.7.7.7,203.0.113.10 "}, "203.0.113.10"},
		{"garbage XFF falls back to peer", "10.1.1.1:4000", []string{"1.1.1.1, not-an-ip"}, "10.1.1.1"},
		{"empty last entry falls back to peer", "10.1.1.1:4000", []string{"1.1.1.1,"}, "10.1.1.1"},
		{"IPv4-mapped peer is unmapped", "[::ffff:192.0.2.8]:4000", []string{"1.2.3.4"}, "192.0.2.8"},
		{"IPv6 trusted peer", "[fd00::1]:4000", []string{"2001:db8::5"}, "2001:db8::5"},
		{"zone is dropped", "[fe80::1%eth0]:4000", nil, "fe80::1"},
		{"bare address without port", "192.0.2.9", nil, "192.0.2.9"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = c.remote
			for _, v := range c.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if got := clientip.FromRequest(r, trusted); got != netip.MustParseAddr(c.want) {
				t.Fatalf("FromRequest = %v, want %s", got, c.want)
			}
		})
	}
}

func TestFromRequestInvalidPeer(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "pipe"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := clientip.FromRequest(r, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}); got.IsValid() {
		t.Fatalf("FromRequest = %v, want invalid", got)
	}
}
