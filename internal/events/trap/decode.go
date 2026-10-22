/*
Package trap decodes SNMP trap and inform packets into a bounded, text-only
form and maps them to named events. Everything in a packet is untrusted: OIDs
are validated, counts and lengths are limited and values are rendered as
strings (printable text or hex), never as markup. The package does no I/O.
*/
package trap

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"
)

/* Limits on untrusted trap content. */
const (
	MaxVarbinds  = 128
	MaxValueLen  = 2048
	MaxOIDSubIDs = 128
	/* MaxTrapOIDLen is the byte bound of the trap OID, matching the events.trap name CHECK (Map uses the OID as the name of unidentified traps). */
	MaxTrapOIDLen = 1024

	maxHexBytes   = MaxValueLen / 2
	maxSubID      = math.MaxUint32
	oidSysUpTime  = "1.3.6.1.2.1.1.3.0"
	oidTrapOID    = "1.3.6.1.6.3.1.1.4.1.0"
	oidTrapEnt    = "1.3.6.1.6.3.1.1.4.3.0"
	oidSnmpTraps  = "1.3.6.1.6.3.1.1.5"
	genericEnterp = 6
)

/* Varbind is one variable binding; Value is always text (see Normalize). */
type Varbind struct {
	OID, Type, Value string
	/* Truncated is true when Value was cut to the limit (text) or to half the limit in bytes (hex). */
	Truncated bool
}

/* Trap is a trap in SNMPv2 form: Version is the version of the received packet (1, 2 or 3). */
type Trap struct {
	Version  uint8
	OID      string
	Varbinds []Varbind
	Uptime   uint32
}

/*
Normalize converts a decoded trap, inform or v1 trap packet into a Trap.
SNMPv1 traps are converted as in RFC 3584: snmpTrapOID is the standard
snmpTraps arc for generic 0..5 and enterprise.0.specific otherwise, and an
snmpTrapEnterprise.0 varbind is appended. For v2c/v3 the leading sysUpTime.0
and snmpTrapOID.0 varbinds are removed into Uptime and OID. Packets over the
limits or with malformed OIDs are rejected as a whole. Duplicate sysUpTime.0,
snmpTrapOID.0 and snmpTrapEnterprise.0 varbinds after the fixed positions are
dropped, so a v1 trap carries exactly one snmpTrapEnterprise.0 (the packet's).

The v1 agent-addr and any snmpTrapAddress.0 varbind are claimed by the device
and are never used to identify the source: eventd uses the UDP peer address.
*/
func Normalize(p *gosnmp.SnmpPacket) (Trap, error) {
	if p == nil {
		return Trap{}, errors.New("trap: nil packet")
	}
	if len(p.Variables) > MaxVarbinds {
		return Trap{}, fmt.Errorf("trap: %d varbinds, limit %d", len(p.Variables), MaxVarbinds)
	}
	switch p.Version {
	case gosnmp.Version1:
		if p.PDUType != gosnmp.Trap {
			return Trap{}, errors.New("trap: not a v1 trap PDU")
		}
		return normalizeV1(p)
	case gosnmp.Version2c, gosnmp.Version3:
		if p.PDUType != gosnmp.SNMPv2Trap && p.PDUType != gosnmp.InformRequest {
			return Trap{}, errors.New("trap: not a v2 trap or inform PDU")
		}
		v := uint8(2)
		if p.Version == gosnmp.Version3 {
			v = 3
		}
		return normalizeV2(p, v)
	}
	return Trap{}, errors.New("trap: unsupported SNMP version")
}

func normalizeV1(p *gosnmp.SnmpPacket) (Trap, error) {
	if len(p.Variables)+1 > MaxVarbinds {
		return Trap{}, fmt.Errorf("trap: %d varbinds, limit %d", len(p.Variables)+1, MaxVarbinds)
	}
	ent, err := cleanOID(p.Enterprise)
	if err == nil && len(ent) > MaxTrapOIDLen {
		err = errors.New("OID too long")
	}
	if err != nil {
		return Trap{}, fmt.Errorf("trap: enterprise: %w", err)
	}
	if p.GenericTrap < 0 || p.GenericTrap > genericEnterp {
		return Trap{}, errors.New("trap: bad generic-trap")
	}
	var oid string
	if p.GenericTrap < genericEnterp {
		oid = oidSnmpTraps + "." + strconv.Itoa(p.GenericTrap+1)
	} else {
		if p.SpecificTrap < 0 || int64(p.SpecificTrap) > maxSubID {
			return Trap{}, errors.New("trap: bad specific-trap")
		}
		oid = ent + ".0." + strconv.Itoa(p.SpecificTrap)
		if strings.Count(oid, ".")+1 > MaxOIDSubIDs || len(oid) > MaxTrapOIDLen {
			return Trap{}, errors.New("trap: trap OID too long")
		}
	}
	if uint64(p.Timestamp) > math.MaxUint32 {
		return Trap{}, errors.New("trap: bad time-stamp")
	}
	t := Trap{Version: 1, OID: oid, Uptime: uint32(p.Timestamp)}
	if t.Varbinds, err = renderAll(p.Variables); err != nil {
		return Trap{}, err
	}
	t.Varbinds = append(t.Varbinds, Varbind{OID: oidTrapEnt, Type: "ObjectIdentifier", Value: ent})
	return t, nil
}

func normalizeV2(p *gosnmp.SnmpPacket, version uint8) (Trap, error) {
	vs := p.Variables
	if len(vs) < 2 {
		return Trap{}, errors.New("trap: missing sysUpTime or snmpTrapOID")
	}
	if n, err := cleanOID(vs[0].Name); err != nil || n != oidSysUpTime {
		return Trap{}, errors.New("trap: first varbind is not sysUpTime.0")
	}
	up, ok := toUint(vs[0].Value)
	if !ok || vs[0].Type != gosnmp.TimeTicks || up > math.MaxUint32 {
		return Trap{}, errors.New("trap: bad sysUpTime value")
	}
	if n, err := cleanOID(vs[1].Name); err != nil || n != oidTrapOID {
		return Trap{}, errors.New("trap: second varbind is not snmpTrapOID.0")
	}
	s, _ := vs[1].Value.(string)
	oid, err := cleanOID(s)
	if vs[1].Type != gosnmp.ObjectIdentifier || err != nil || len(oid) > MaxTrapOIDLen {
		return Trap{}, errors.New("trap: bad snmpTrapOID value")
	}
	t := Trap{Version: version, OID: oid, Uptime: uint32(up)}
	if t.Varbinds, err = renderAll(vs[2:]); err != nil {
		return Trap{}, err
	}
	return t, nil
}

func renderAll(vs []gosnmp.SnmpPDU) ([]Varbind, error) {
	out := make([]Varbind, 0, len(vs)+1)
	for _, v := range vs {
		oid, err := cleanOID(v.Name)
		if err != nil {
			return nil, fmt.Errorf("trap: varbind name: %w", err)
		}
		switch oid {
		case oidSysUpTime, oidTrapOID, oidTrapEnt:
			continue
		}
		typ, val, cut, err := render(v)
		if err != nil {
			return nil, err
		}
		out = append(out, Varbind{OID: oid, Type: typ, Value: val, Truncated: cut})
	}
	return out, nil
}

/* cleanOID validates a dotted OID and returns it without a leading dot. */
func cleanOID(s string) (string, error) {
	s = strings.TrimPrefix(s, ".")
	if s == "" || len(s) > MaxOIDSubIDs*11 {
		return "", errors.New("malformed OID")
	}
	parts := strings.Split(s, ".")
	if len(parts) > MaxOIDSubIDs {
		return "", fmt.Errorf("OID has %d sub-identifiers, limit %d", len(parts), MaxOIDSubIDs)
	}
	for _, part := range parts {
		if part == "" || len(part) > 10 || (len(part) > 1 && part[0] == '0') {
			return "", errors.New("malformed OID")
		}
		for j := 0; j < len(part); j++ {
			if part[j] < '0' || part[j] > '9' {
				return "", errors.New("malformed OID")
			}
		}
		if v, _ := strconv.ParseUint(part, 10, 64); v > maxSubID {
			return "", errors.New("malformed OID")
		}
	}
	return s, nil
}

func toUint(v any) (uint64, bool) {
	switch x := v.(type) {
	case uint:
		return uint64(x), true
	case uint8:
		return uint64(x), true
	case uint16:
		return uint64(x), true
	case uint32:
		return uint64(x), true
	case uint64:
		return x, true
	}
	return 0, false
}

func toInt(v any) (int64, bool) {
	switch x := v.(type) {
	case int:
		return int64(x), true
	case int8:
		return int64(x), true
	case int16:
		return int64(x), true
	case int32:
		return int64(x), true
	case int64:
		return x, true
	}
	return 0, false
}

var uintTypes = map[gosnmp.Asn1BER]string{
	gosnmp.Counter32: "Counter32", gosnmp.Gauge32: "Gauge32", gosnmp.Uinteger32: "Unsigned32",
	gosnmp.TimeTicks: "TimeTicks", gosnmp.Counter64: "Counter64",
}

/* render returns the type name and bounded text of a value; cut reports a truncated value. */
func render(v gosnmp.SnmpPDU) (typ, val string, cut bool, err error) {
	switch v.Type {
	case gosnmp.Integer:
		typ = "Integer"
		if i, ok := toInt(v.Value); ok {
			val = strconv.FormatInt(i, 10)
		} else if u, ok := toUint(v.Value); ok {
			val = strconv.FormatUint(u, 10)
		}
	case gosnmp.Counter32, gosnmp.Gauge32, gosnmp.Uinteger32, gosnmp.TimeTicks, gosnmp.Counter64:
		typ = uintTypes[v.Type]
		if u, ok := toUint(v.Value); ok {
			val = strconv.FormatUint(u, 10)
		}
	case gosnmp.OctetString:
		typ = "OctetString"
		if b, ok := v.Value.([]byte); ok {
			val, cut = octets(b)
		}
	case gosnmp.Opaque, gosnmp.BitString, gosnmp.NsapAddress:
		typ = "Opaque"
		if b, ok := v.Value.([]byte); ok {
			val, cut = hexOf(b)
		}
	case gosnmp.ObjectIdentifier:
		typ = "ObjectIdentifier"
		s, _ := v.Value.(string)
		if val, err = cleanOID(s); err != nil {
			return "", "", false, fmt.Errorf("trap: OID value: %w", err)
		}
	case gosnmp.IPAddress:
		typ = "IpAddress"
		if s, ok := v.Value.(string); ok {
			val, cut = sanitize(s)
		}
	case gosnmp.OpaqueFloat:
		typ = "Float"
		if f, ok := v.Value.(float32); ok {
			val = strconv.FormatFloat(float64(f), 'g', -1, 32)
		}
	case gosnmp.OpaqueDouble:
		typ = "Double"
		if f, ok := v.Value.(float64); ok {
			val = strconv.FormatFloat(f, 'g', -1, 64)
		}
	case gosnmp.Boolean:
		typ = "Boolean"
		if b, ok := v.Value.(bool); ok {
			val = strconv.FormatBool(b)
		}
	case gosnmp.Null:
		typ = "Null"
	case gosnmp.NoSuchObject:
		typ = "NoSuchObject"
	case gosnmp.NoSuchInstance:
		typ = "NoSuchInstance"
	case gosnmp.EndOfMibView:
		typ = "EndOfMibView"
	default:
		typ = "Unknown"
	}
	return typ, val, cut, nil
}

func hexOf(b []byte) (string, bool) {
	cut := len(b) > maxHexBytes
	if cut {
		b = b[:maxHexBytes]
	}
	return hex.EncodeToString(b), cut
}

/*
badRune reports characters that must not reach stored text: C0 controls
except tab, DEL, C1 controls, bidi embeddings/overrides/isolates and the
line and paragraph separators. It is identical to badRune in the syslog
parser (internal/events/syslog); keep the two in sync.
*/
func badRune(r rune) bool {
	switch {
	case r < 0x20:
		return r != '\t'
	case r == 0x7f, r >= 0x80 && r <= 0x9f:
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0x2028, r == 0x2029:
		return true
	}
	return false
}

/* octets renders an OCTET STRING as text when it is clean UTF-8 without bad characters, else as hex. */
func octets(b []byte) (string, bool) {
	for len(b) > 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	c := b
	if len(c) > MaxValueLen {
		c = c[:MaxValueLen]
		/* drop a rune cut by the limit */
		for i := 0; i < utf8.UTFMax && len(c) > 0 && !utf8.Valid(c); i++ {
			c = c[:len(c)-1]
		}
	}
	if utf8.Valid(c) {
		clean := true
		for _, r := range string(c) {
			if r == utf8.RuneError || badRune(r) {
				clean = false
				break
			}
		}
		if clean {
			return string(c), len(b) > MaxValueLen
		}
	}
	return hexOf(b)
}

/* sanitize drops invalid UTF-8 and bad characters, then cuts to MaxValueLen on a rune boundary. */
func sanitize(s string) (string, bool) {
	s = strings.Map(func(r rune) rune {
		if badRune(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, "�"))
	if len(s) <= MaxValueLen {
		return s, false
	}
	cut := MaxValueLen
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut], true
}
