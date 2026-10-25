package inventory_test

import (
	"testing"

	"github.com/beekamai/network-scheme/internal/inventory"
)

func TestMACRange(t *testing.T) {
	for _, c := range []struct {
		q, lo, hi string
		ok        bool
	}{
		{"00:1A:2b:3c:4d:5e", "001a2b3c4d5e", "001a2b3c4d5e", true},
		{"00-1a-2b-3c-4d-5e", "001a2b3c4d5e", "001a2b3c4d5e", true},
		{"001a.2b3c.4d5e", "001a2b3c4d5e", "001a2b3c4d5e", true},
		{"001A2B3C4D5E", "001a2b3c4d5e", "001a2b3c4d5e", true},
		{"00:1a:2b", "001a2b000000", "001a2bffffff", true},
		{"001a2", "001a20000000", "001a2fffffff", true},
		{"cafe", "cafe00000000", "cafeffffffff", true},
		{"00:1", "", "", false},                 /* fewer than four hex digits */
		{"00:1a:2b:3c:4d:5e:6f", "", "", false}, /* longer than a MAC */
		{"10.10", "", "", false},                /* an IPv4 prefix, not a MAC */
		{"192.168.1.1", "", "", false},
		{"00:1g:2b", "", "", false},
		{"00 1a 2b", "", "", false},
		{"%_\\", "", "", false},
	} {
		lo, hi, ok := inventory.MACRange(c.q)
		if lo != c.lo || hi != c.hi || ok != c.ok {
			t.Errorf("MACRange(%q) = %q, %q, %v; want %q, %q, %v", c.q, lo, hi, ok, c.lo, c.hi, c.ok)
		}
	}
}

func TestIPPrefix(t *testing.T) {
	for _, c := range []struct {
		q, lo, hi string
		ok        bool
	}{
		{"10.0.0.1", "10.0.0.1", "10.0.0.2", true},
		{"10.0.", "10.0.", "10.0/", true},
		{"10.9", "10.9", "10.:", true},
		{"FE80::", "fe80::", "fe80:;", true},
		{"2001:DB8", "2001:db8", "2001:db9", true},
		{"cafe", "", "", false}, /* no digit: a name or a MAC, not an address */
		{"10.0.0.1/24", "", "", false},
		{"10%", "", "", false},
		{"ge-0/0/1", "", "", false},
	} {
		lo, hi, ok := inventory.IPPrefix(c.q)
		if lo != c.lo || hi != c.hi || ok != c.ok {
			t.Errorf("IPPrefix(%q) = %q, %q, %v; want %q, %q, %v", c.q, lo, hi, ok, c.lo, c.hi, c.ok)
		}
	}
}
