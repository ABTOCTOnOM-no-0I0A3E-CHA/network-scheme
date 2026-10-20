/*
Package snmp is the read-only SNMP transport. It wraps gosnmp and exposes only
GET, GETBULK and bulk-walk operations; there is deliberately no way to send a
SET through this package.
*/
package snmp

import (
	"context"
	"errors"
	"net/netip"
	"strings"
)

/* Errors returned by Reader implementations; match them with errors.Is. */
var (
	/* ErrTimeout: no (valid) response within Timeout x (Retries+1). */
	ErrTimeout = errors.New("snmp: request timed out")
	/* ErrAuth: the agent rejected or could not verify the credentials. */
	ErrAuth = errors.New("snmp: authentication failed")
	/* ErrNoSuchObject: none of the requested objects exist on the agent. */
	ErrNoSuchObject = errors.New("snmp: no such object")
)

/* Type is the SNMP data type of a Var. */
type Type uint8

/* SNMP data types. */
const (
	TypeOther Type = iota
	TypeInteger
	TypeOctetString
	TypeOID
	TypeIPAddress
	TypeCounter32
	TypeGauge32
	TypeTimeTicks
	TypeCounter64
	TypeOpaque
	TypeNull
	TypeNoSuchObject
	TypeNoSuchInstance
	TypeEndOfMibView
)

/*
Var is one variable binding. OID has no leading dot. Value is int64 (Integer),
uint64 (Counter32/Gauge32/TimeTicks/Counter64), []byte (OctetString, Opaque),
string (OID without leading dot, IPAddress) or nil. Data from devices is
untrusted: treat strings and bytes as text only.
*/
type Var struct {
	OID   string
	Type  Type
	Value any
}

/*
Reader reads from one SNMP agent. It has no write methods. Calls on one Reader
are serialised; use one Reader per device.
*/
type Reader interface {
	/*
		Get fetches the given OIDs (split into requests of at most
		Options.MaxOIDsPerRequest). Missing objects come back as Vars of type
		TypeNoSuchObject/TypeNoSuchInstance; ErrNoSuchObject is returned (with
		those Vars) only when every requested object is missing.
	*/
	Get(ctx context.Context, oids ...string) ([]Var, error)
	/* Walk visits every variable under root using GETBULK (max-repetitions 25). */
	Walk(ctx context.Context, root string, fn func(Var) error) error
	/* BulkGet sends GETBULK with every OID as a non-repeater: each result is the first variable after its OID in MIB order (GETNEXT semantics), chunked like Get. */
	BulkGet(ctx context.Context, oids []string) ([]Var, error)
}

/* AsUint64 returns the value of a counter, gauge, timeticks or non-negative integer. */
func AsUint64(v Var) (uint64, bool) {
	switch x := v.Value.(type) {
	case uint64:
		return x, true
	case int64:
		if x >= 0 {
			return uint64(x), true
		}
	}
	return 0, false
}

/* AsString returns an OctetString value as a string. */
func AsString(v Var) (string, bool) {
	if v.Type != TypeOctetString {
		return "", false
	}
	b, ok := v.Value.([]byte)
	return string(b), ok
}

/* AsOID returns an OID value without a leading dot. */
func AsOID(v Var) (string, bool) {
	if v.Type != TypeOID {
		return "", false
	}
	s, ok := v.Value.(string)
	return s, ok
}

/* AsIP returns an IpAddress value. */
func AsIP(v Var) (netip.Addr, bool) {
	if v.Type != TypeIPAddress {
		return netip.Addr{}, false
	}
	s, ok := v.Value.(string)
	if !ok {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(s)
	return a, err == nil
}

func trimDot(oid string) string { return strings.TrimPrefix(oid, ".") }
