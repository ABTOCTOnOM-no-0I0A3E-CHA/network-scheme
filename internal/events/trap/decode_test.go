package trap_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"

	"github.com/beekamai/network-scheme/internal/events/trap"
)

/* Fixtures are built from the MIB definitions (RFC 3418, 2863, 4268, LLDP-MIB), not captured from devices. */

func pdu(name string, typ gosnmp.Asn1BER, v any) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: name, Type: typ, Value: v}
}

func v2(oid string, vs ...gosnmp.SnmpPDU) *gosnmp.SnmpPacket {
	head := []gosnmp.SnmpPDU{
		pdu(".1.3.6.1.2.1.1.3.0", gosnmp.TimeTicks, uint32(1234)),
		pdu(".1.3.6.1.6.3.1.1.4.1.0", gosnmp.ObjectIdentifier, "."+oid),
	}
	return &gosnmp.SnmpPacket{Version: gosnmp.Version2c, PDUType: gosnmp.SNMPv2Trap, Variables: append(head, vs...)}
}

func norm(t *testing.T, p *gosnmp.SnmpPacket) trap.Trap {
	t.Helper()
	tr, err := trap.Normalize(p)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func TestStandardTraps(t *testing.T) {
	ifx := pdu(".1.3.6.1.2.1.2.2.1.1.7", gosnmp.Integer, 7)
	tests := []struct {
		oid, name, sev string
		state          bool
		ifIndex        int
		vbs            []gosnmp.SnmpPDU
	}{
		{"1.3.6.1.6.3.1.1.5.1", "coldStart", "warning", true, 0, nil},
		{"1.3.6.1.6.3.1.1.5.2", "warmStart", "info", true, 0, nil},
		{"1.3.6.1.6.3.1.1.5.3", "linkDown", "average", true, 7, []gosnmp.SnmpPDU{ifx}},
		{"1.3.6.1.6.3.1.1.5.4", "linkUp", "info", true, 7, []gosnmp.SnmpPDU{ifx}},
		{"1.3.6.1.6.3.1.1.5.5", "authenticationFailure", "warning", false, 0, nil},
		{"1.0.8802.1.1.2.0.0.1", "lldpRemTablesChange", "info", false, 0, nil},
		{"1.3.6.1.2.1.47.2.0.1", "entConfigChange", "info", false, 0, nil},
		{"1.3.6.1.2.1.131.0.1", "entStateOperEnabled", "info", false, 0, nil},
		{"1.3.6.1.2.1.131.0.2", "entStateOperDisabled", "high", false, 0, nil},
	}
	for _, c := range tests {
		t.Run(c.name, func(t *testing.T) {
			m, ok := trap.Standard(norm(t, v2(c.oid, c.vbs...)))
			want := trap.Mapped{Name: c.name, Severity: c.sev, AffectsState: c.state, IfIndex: c.ifIndex}
			if !ok || m != want {
				t.Fatalf("got %+v %v, want %+v", m, ok, want)
			}
		})
	}
}

func TestV2Fields(t *testing.T) {
	tr := norm(t, v2("1.3.6.1.6.3.1.1.5.3", pdu(".1.3.6.1.2.1.2.2.1.1.7", gosnmp.Integer, 7)))
	if tr.Version != 2 || tr.Uptime != 1234 || tr.OID != "1.3.6.1.6.3.1.1.5.3" || len(tr.Varbinds) != 1 ||
		tr.Varbinds[0] != (trap.Varbind{OID: "1.3.6.1.2.1.2.2.1.1.7", Type: "Integer", Value: "7"}) {
		t.Fatalf("%+v", tr)
	}
	p := v2("1.3.6.1.6.3.1.1.5.3")
	p.Version, p.PDUType = gosnmp.Version3, gosnmp.InformRequest
	if tr := norm(t, p); tr.Version != 3 {
		t.Fatalf("version %d", tr.Version)
	}
}

func TestV1GenericLinkDown(t *testing.T) {
	p := &gosnmp.SnmpPacket{Version: gosnmp.Version1, PDUType: gosnmp.Trap, Variables: []gosnmp.SnmpPDU{
		pdu(".1.3.6.1.2.1.2.2.1.1.3", gosnmp.Integer, 3)}}
	p.Enterprise, p.GenericTrap, p.Timestamp = ".1.3.6.1.4.1.35265", 2, 99
	tr := norm(t, p)
	if tr.Version != 1 || tr.OID != "1.3.6.1.6.3.1.1.5.3" || tr.Uptime != 99 {
		t.Fatalf("%+v", tr)
	}
	last := tr.Varbinds[len(tr.Varbinds)-1]
	if last != (trap.Varbind{OID: "1.3.6.1.6.3.1.1.4.3.0", Type: "ObjectIdentifier", Value: "1.3.6.1.4.1.35265"}) {
		t.Fatalf("enterprise varbind %+v", last)
	}
	if m, ok := trap.Standard(tr); !ok || m.Name != "linkDown" || m.IfIndex != 3 || !m.AffectsState {
		t.Fatalf("%+v %v", m, ok)
	}
}

func TestV1EnterpriseSpecific(t *testing.T) {
	p := &gosnmp.SnmpPacket{Version: gosnmp.Version1, PDUType: gosnmp.Trap}
	p.Enterprise, p.GenericTrap, p.SpecificTrap = "1.3.6.1.4.1.35265.7", 6, 12
	if tr := norm(t, p); tr.OID != "1.3.6.1.4.1.35265.7.0.12" {
		t.Fatalf("OID %s", tr.OID)
	}
	p.GenericTrap = 7
	if _, err := trap.Normalize(p); err == nil {
		t.Fatal("generic 7 accepted")
	}
}

type fixedMapper struct{ m trap.Mapped }

func (f fixedMapper) MapTrap(trap.Trap) (trap.Mapped, bool) { return f.m, f.m.Name != "" }

func TestMapOrder(t *testing.T) {
	rules := map[string]trap.Rule{
		"1.3.6.1.6.3.1.1.5.3":  {Name: "myLinkDown", Severity: "disaster"},
		"1.3.6.1.4.1.9999.0.1": {Name: "custom", Severity: "high"},
		"1.3.6.1.4.1.9999.0.2": {Name: "badsev", Severity: "critical"},
	}
	std := norm(t, v2("1.3.6.1.6.3.1.1.5.3"))
	if m, ok := trap.Map(nil, std, rules); !ok || m.Name != "linkDown" {
		t.Fatalf("rule overrode standard: %+v", m)
	}
	drv := fixedMapper{trap.Mapped{Name: "drv", Severity: "info"}}
	if m, ok := trap.Map(drv, std, rules); !ok || m.Name != "drv" {
		t.Fatalf("driver not first: %+v", m)
	}
	if m, ok := trap.Map(nil, norm(t, v2("1.3.6.1.4.1.9999.0.1")), rules); !ok || m.Name != "custom" || m.Severity != "high" {
		t.Fatalf("rule: %+v %v", m, ok)
	}
	if m, ok := trap.Map(nil, norm(t, v2("1.3.6.1.4.1.9999.0.2")), rules); ok || m.Severity != "" {
		t.Fatalf("invalid-severity rule applied: %+v", m)
	}
	m, ok := trap.Map(nil, norm(t, v2("1.3.6.1.4.1.9999.0.3")), rules)
	if ok || m.Name != "1.3.6.1.4.1.9999.0.3" || m.Severity != "" {
		t.Fatalf("unidentified: %+v", m)
	}
}

func TestLimits(t *testing.T) {
	many := func(n int) []gosnmp.SnmpPDU {
		var vs []gosnmp.SnmpPDU
		for i := 0; i < n; i++ {
			vs = append(vs, pdu(".1.3.6.1.4.1.1."+strconv.Itoa(i), gosnmp.Integer, i))
		}
		return vs
	}
	if _, err := trap.Normalize(v2("1.3.6.1.4.1.1", many(126)...)); err != nil {
		t.Fatalf("128 varbinds: %v", err)
	}
	if _, err := trap.Normalize(v2("1.3.6.1.4.1.1", many(127)...)); err == nil {
		t.Fatal("129 varbinds accepted")
	}
	ok128 := "1" + strings.Repeat(".1", 127)
	long := "1" + strings.Repeat(".1", 128) /* 129 sub-identifiers */
	if _, err := trap.Normalize(v2(ok128)); err != nil {
		t.Fatalf("128 sub-identifiers: %v", err)
	}
	if _, err := trap.Normalize(v2(long)); err == nil {
		t.Fatal("long trap OID accepted")
	}
	if _, err := trap.Normalize(v2("1.3.6.1.4.1.1", pdu("."+long, gosnmp.Integer, 1))); err == nil {
		t.Fatal("long varbind OID accepted")
	}
	if _, err := trap.Normalize(v2("1.3.6.1.4.1.1", pdu(".1.3.6.1.4.1.1", gosnmp.ObjectIdentifier, "."+long))); err == nil {
		t.Fatal("long OID value accepted")
	}
	for _, bad := range []string{"", "1..3", "1.a", "1.3.-1", "1.3.99999999999", "1.03"} {
		if _, err := trap.Normalize(v2("1.3.6.1.4.1.1", pdu(".1.3.6.1.4.1.1", gosnmp.ObjectIdentifier, bad))); err == nil {
			t.Fatalf("bad OID %q accepted", bad)
		}
	}
}

func TestValues(t *testing.T) {
	val := func(typ gosnmp.Asn1BER, v any) string {
		tr := norm(t, v2("1.3.6.1.4.1.1", pdu(".1.3.6.1.4.1.1.1", typ, v)))
		return tr.Varbinds[0].Value
	}
	if got := val(gosnmp.OctetString, []byte(strings.Repeat("a", 5000))); len(got) != trap.MaxValueLen {
		t.Fatalf("text len %d", len(got))
	}
	multi := strings.Repeat("я", 2000) /* 4000 bytes of 2-byte runes */
	if got := val(gosnmp.OctetString, []byte(multi)); len(got) > trap.MaxValueLen || !strings.HasPrefix(multi, got) || len(got) < trap.MaxValueLen-1 {
		t.Fatalf("rune cut: len %d", len(got))
	}
	if got := val(gosnmp.OctetString, []byte{}); got != "" {
		t.Fatalf("empty: %q", got)
	}
	if got := val(gosnmp.OctetString, []byte("eth0\x00")); got != "eth0" {
		t.Fatalf("nul-terminated: %q", got)
	}
	if got := val(gosnmp.OctetString, []byte{0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e}); got != "001a2b3c4d5e" {
		t.Fatalf("mac: %q", got)
	}
	bidi := string(rune(0x202e))
	for _, bad := range []string{"a\x1bb", "a\x7fb", "a\nb", "\xff\xfe", "x" + bidi + "y"} {
		got := val(gosnmp.OctetString, []byte(bad))
		if got == bad || strings.ContainsAny(got, "\x1b\x7f\n") || strings.Contains(got, bidi) {
			t.Fatalf("unsafe text kept for %q: %q", bad, got)
		}
	}
	if got := val(gosnmp.OctetString, make([]byte, 5000)); len(got) > trap.MaxValueLen {
		t.Fatalf("hex len %d", len(got))
	}
	if got := val(gosnmp.IPAddress, "10.0.0.1\x1b"); got != "10.0.0.1" {
		t.Fatalf("ip: %q", got)
	}
	if got := val(gosnmp.Counter64, uint64(1<<63)); got != "9223372036854775808" {
		t.Fatalf("c64: %q", got)
	}
	if got := val(gosnmp.Integer, -5); got != "-5" {
		t.Fatalf("int: %q", got)
	}
	if got := val(gosnmp.Integer, struct{ x int }{1}); got != "" {
		t.Fatalf("unexpected Go type rendered: %q", got)
	}
}

func TestRejects(t *testing.T) {
	if _, err := trap.Normalize(nil); err == nil {
		t.Fatal("nil accepted")
	}
	p := v2("1.3.6.1.4.1.1")
	p.PDUType = gosnmp.GetResponse
	if _, err := trap.Normalize(p); err == nil {
		t.Fatal("non-trap PDU accepted")
	}
	p = v2("1.3.6.1.4.1.1")
	p.Variables[0].Name = ".1.3.6.1.2.1.1.5.0"
	if _, err := trap.Normalize(p); err == nil {
		t.Fatal("missing sysUpTime accepted")
	}
	p = v2("1.3.6.1.4.1.1")
	p.Variables = p.Variables[:1]
	if _, err := trap.Normalize(p); err == nil {
		t.Fatal("missing snmpTrapOID accepted")
	}
}
