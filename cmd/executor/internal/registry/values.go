package registry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"time"
)

func itoa(i int) string { return strconv.Itoa(i) }

var (
	plainNumber  = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?$`)
	negativeZero = regexp.MustCompile(`^-0(\.0+)?$`)
)

/*
value is one column value in its three forms: canon (the MACed bytes, nil
for NULL), typed (what decisions read: int64, bool, string, []byte,
time.Time in UTC, netip.Addr, json.RawMessage) and param (what is sent to
the database).
*/
type value struct {
	canon *string
	typed any
	param any
}

/*
norm maps a Go value of column c to its canonical form. Declared values
(writers) and scanned values (binary protocol) go through the same
function, so what is MACed is exactly what is decided on.
*/
func norm(c column, v any) (value, error) {
	if v == nil {
		if !c.null {
			return value{}, fmt.Errorf("%s: NULL", c.name)
		}
		return value{}, nil
	}
	s := func(x string) *string { return &x }
	switch c.kind {
	case kInt8, kInt4:
		var n int64
		switch x := v.(type) {
		case int:
			n = int64(x)
		case int32:
			n = int64(x)
		case int64:
			n = x
		default:
			return value{}, fmt.Errorf("%s: %T is not an integer", c.name, v)
		}
		if c.kind == kInt4 && (n < math.MinInt32 || n > math.MaxInt32) {
			return value{}, fmt.Errorf("%s: %d out of range", c.name, n)
		}
		return value{s(strconv.FormatInt(n, 10)), n, n}, nil
	case kBool:
		if x, ok := v.(bool); ok {
			return value{s(strconv.FormatBool(x)), x, x}, nil
		}
	case kText:
		if x, ok := v.(string); ok {
			return value{s(x), x, x}, nil
		}
	case kBytes:
		if x, ok := v.([]byte); ok {
			x = slices.Clone(x)
			return value{s(string(x)), x, x}, nil
		}
	case kTime:
		if x, ok := v.(time.Time); ok {
			us := x.UnixMicro()
			t := time.UnixMicro(us).UTC()
			return value{s(strconv.FormatInt(us, 10)), t, t}, nil
		}
	case kInet:
		var a netip.Addr
		switch x := v.(type) {
		case netip.Addr:
			a = x
		case netip.Prefix:
			if x.Bits() != x.Addr().BitLen() {
				return value{}, fmt.Errorf("%s: %s is not a host address", c.name, x)
			}
			a = x.Addr()
		default:
			return value{}, fmt.Errorf("%s: %T is not an address", c.name, v)
		}
		if !a.IsValid() || a.Is4In6() || a.Zone() != "" {
			return value{}, fmt.Errorf("%s: address %s not canonical", c.name, a)
		}
		p := netip.PrefixFrom(a, a.BitLen())
		return value{s(p.String()), a, p}, nil
	case kJSON:
		var raw []byte
		switch x := v.(type) {
		case json.RawMessage:
			raw = x
		case []byte:
			raw = x
		default:
			return value{}, fmt.Errorf("%s: %T is not JSON", c.name, v)
		}
		cj, err := canonJSON(raw)
		if err != nil {
			return value{}, fmt.Errorf("%s: %w", c.name, err)
		}
		return value{s(cj), json.RawMessage(cj), cj}, nil
	}
	return value{}, fmt.Errorf("%s: %T is not a %s", c.name, v, sqlType[c.kind])
}

/*
canonJSON is the canonical JSON text of a document, the same for what a
writer sends and what jsonb gives back (jsonb reorders keys and drops
whitespace and duplicate keys): object keys sorted, strings as
encoding/json writes them, numbers verbatim. jsonb keeps a number's decimal
scale ("1.0" stays "1.0") and never writes an exponent, so numbers must be
plain decimals and not a negative zero; then "1" and "1.0" stay distinct
and the MAC covers exactly the text decisions read (Row.Get returns it).
*/
func canonJSON(raw []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", err
	}
	if _, err := dec.Token(); err == nil {
		return "", errors.New("trailing data after JSON")
	}
	var b bytes.Buffer
	if err := writeCanon(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}

func writeCanon(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case json.Number:
		n := string(x)
		if !plainNumber.MatchString(n) || negativeZero.MatchString(n) {
			return fmt.Errorf("number %q: want a plain decimal", n)
		}
		b.WriteString(n)
	case string:
		q, err := json.Marshal(x)
		if err != nil {
			return err
		}
		b.Write(q)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanon(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanon(b, k); err != nil {
				return err
			}
			b.WriteByte(':')
			if err := writeCanon(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("unexpected JSON value %T", v)
	}
	return nil
}
