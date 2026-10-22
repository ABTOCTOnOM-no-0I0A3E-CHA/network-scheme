package trap_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"

	"github.com/beekamai/network-scheme/internal/events/trap"
)

/* ber builds a BER TLV. */
func ber(tag byte, content ...[]byte) []byte {
	var c []byte
	for _, x := range content {
		c = append(c, x...)
	}
	out := []byte{tag}
	switch {
	case len(c) < 128:
		out = append(out, byte(len(c)))
	case len(c) < 256:
		out = append(out, 0x81, byte(len(c)))
	default:
		out = append(out, 0x82, byte(len(c)>>8), byte(len(c)))
	}
	return append(out, c...)
}

func berOID(dotted string) []byte {
	var nums []int
	for _, p := range strings.Split(dotted, ".") {
		n := 0
		for _, ch := range p {
			n = n*10 + int(ch-'0')
		}
		nums = append(nums, n)
	}
	b := []byte{byte(nums[0]*40 + nums[1])}
	for _, n := range nums[2:] {
		tmp := []byte{byte(n & 0x7f)}
		for n >>= 7; n > 0; n >>= 7 {
			tmp = append(tmp, byte(n&0x7f)|0x80)
		}
		for i := len(tmp) - 1; i >= 0; i-- {
			b = append(b, tmp[i])
		}
	}
	return ber(0x06, b)
}

func berInt(n int) []byte { return ber(0x02, []byte{byte(n)}) }

func varbind(oid string, val []byte) []byte { return ber(0x30, berOID(oid), val) }

/* v2cTrap is a hand-built SNMPv2c trap PDU for the seed corpus and decoder tests. */
func v2cTrap(trapOID string, vbs ...[]byte) []byte {
	all := [][]byte{
		varbind("1.3.6.1.2.1.1.3.0", ber(0x43, []byte{0x04, 0xd2})),
		varbind("1.3.6.1.6.3.1.1.4.1.0", berOID(trapOID)),
	}
	all = append(all, vbs...)
	body := ber(0xa7, berInt(1), berInt(0), berInt(0), ber(0x30, all...))
	return ber(0x30, berInt(1), ber(0x04, []byte("public")), body)
}

/* v1Trap is a hand-built SNMPv1 trap PDU. */
func v1Trap(enterprise string, generic, specific int, vbs ...[]byte) []byte {
	body := ber(0xa4, berOID(enterprise), ber(0x40, []byte{10, 0, 0, 1}), berInt(generic), berInt(specific),
		ber(0x43, []byte{0x63}), ber(0x30, vbs...))
	return ber(0x30, berInt(0), ber(0x04, []byte("public")), body)
}

func decode(b []byte) (*gosnmp.SnmpPacket, error) {
	g := &gosnmp.GoSNMP{Version: gosnmp.Version2c, Logger: gosnmp.NewLogger(nil)}
	return g.SnmpDecodePacket(b)
}

func TestDecodedWire(t *testing.T) {
	p, err := decode(v2cTrap("1.3.6.1.6.3.1.1.5.4", varbind("1.3.6.1.2.1.2.2.1.1.5", berInt(5))))
	if err != nil {
		t.Fatal(err)
	}
	tr := norm(t, p)
	if m, ok := trap.Standard(tr); !ok || m.Name != "linkUp" || m.IfIndex != 5 || tr.Uptime != 1234 {
		t.Fatalf("%+v %+v", m, tr)
	}
	p, err = decode(v1Trap("1.3.6.1.4.1.35265", 2, 0, varbind("1.3.6.1.2.1.2.2.1.1.9", berInt(9))))
	if err != nil {
		t.Fatal(err)
	}
	tr = norm(t, p)
	if m, ok := trap.Standard(tr); !ok || m.Name != "linkDown" || m.IfIndex != 9 || tr.Version != 1 {
		t.Fatalf("%+v %+v", m, tr)
	}
}

func FuzzNormalize(f *testing.F) {
	f.Add(v2cTrap("1.3.6.1.6.3.1.1.5.3", varbind("1.3.6.1.2.1.2.2.1.1.5", berInt(5))))
	f.Add(v2cTrap("1.3.6.1.4.1.35265.1.2", varbind("1.3.6.1.2.1.1.5.0", ber(0x04, []byte("sw\x01\xff"))),
		varbind("1.3.6.1.2.1.1.2.0", berOID("1.3.6.1.4.1.35265.1.23")), varbind("1.3.6.1.2.1.4.20.1.1.1", ber(0x40, []byte{1, 2, 3, 4}))))
	f.Add(v1Trap("1.3.6.1.4.1.35265", 6, 3, varbind("1.3.6.1.2.1.1.5.0", ber(0x04, []byte("x")))))
	f.Add(v1Trap("1.3.6.1.4.1.35265", 2, 0))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := decode(b)
		if err != nil || p == nil {
			return
		}
		tr, err := trap.Normalize(p)
		if err != nil {
			return
		}
		if len(tr.Varbinds) > trap.MaxVarbinds {
			t.Fatalf("%d varbinds", len(tr.Varbinds))
		}
		if len(tr.OID) > trap.MaxTrapOIDLen {
			t.Fatalf("trap OID %d bytes", len(tr.OID))
		}
		oids := []string{tr.OID}
		for _, v := range tr.Varbinds {
			oids = append(oids, v.OID)
			if len(v.Value) > trap.MaxValueLen || !utf8.ValidString(v.Value) {
				t.Fatalf("bad value %q", v.Value)
			}
			for _, r := range v.Value {
				if badRune(r) {
					t.Fatalf("bad character U+%04X in %q", r, v.Value)
				}
			}
		}
		for _, o := range oids {
			if n := strings.Count(o, ".") + 1; o == "" || n > trap.MaxOIDSubIDs {
				t.Fatalf("bad OID %q", o)
			}
		}
		trap.Map(nil, tr, nil)
	})
}

/* badRune is the set of characters that must never appear in a rendered value: C0 except tab, DEL, C1, bidi controls, U+2028/U+2029. */
func badRune(r rune) bool {
	return (r < 0x20 && r != '	') || (r >= 0x7f && r <= 0x9f) ||
		(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || r == 0x2028 || r == 0x2029
}
