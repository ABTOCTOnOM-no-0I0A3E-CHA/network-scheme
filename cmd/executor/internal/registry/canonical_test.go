package registry

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"
	"testing"
)

/* decode is the strict inverse of Canonical; round-tripping every input proves the encoding injective. */
func decode(b []byte) (table string, pk, content []*string, version int64, err error) {
	bad := errors.New("bad encoding")
	if !bytes.HasPrefix(b, []byte(domain)) {
		return "", nil, nil, 0, bad
	}
	b = b[len(domain):]
	field := func() (*string, error) {
		if len(b) < 1 {
			return nil, bad
		}
		tag := b[0]
		b = b[1:]
		if tag == tagNull {
			return nil, nil
		}
		if tag != tagValue || len(b) < 4 {
			return nil, bad
		}
		n := binary.BigEndian.Uint32(b)
		b = b[4:]
		if uint32(len(b)) < n {
			return nil, bad
		}
		s := string(b[:n])
		b = b[n:]
		return &s, nil
	}
	list := func() ([]*string, error) {
		if len(b) < 4 {
			return nil, bad
		}
		n := binary.BigEndian.Uint32(b)
		b = b[4:]
		var out []*string
		for range n {
			f, err := field()
			if err != nil {
				return nil, err
			}
			out = append(out, f)
		}
		return out, nil
	}
	t, err := field()
	if err != nil || t == nil {
		return "", nil, nil, 0, bad
	}
	if pk, err = list(); err != nil {
		return "", nil, nil, 0, err
	}
	if content, err = list(); err != nil {
		return "", nil, nil, 0, err
	}
	if len(b) != 8 {
		return "", nil, nil, 0, bad
	}
	return *t, pk, content, int64(binary.BigEndian.Uint64(b)), nil // #nosec G115 -- test inverse
}

func eqFields(a, b []*string) bool {
	return slices.EqualFunc(a, b, func(x, y *string) bool { return (x == nil) == (y == nil) && (x == nil || *x == *y) })
}

func p(s string) *string { return &s }

func TestCanonicalSeparatesNeighbours(t *testing.T) {
	for _, c := range [][2][]byte{
		{Canonical("t", []*string{p("ab")}, []*string{p("c")}, 1), Canonical("t", []*string{p("a")}, []*string{p("bc")}, 1)},
		{Canonical("t", []*string{p("ab"), p("c")}, nil, 1), Canonical("t", []*string{p("a"), p("bc")}, nil, 1)},
		{Canonical("t", []*string{p("a")}, []*string{nil}, 1), Canonical("t", []*string{p("a")}, []*string{p("")}, 1)},
		{Canonical("t", []*string{p("a"), p("b")}, nil, 1), Canonical("t", []*string{p("a")}, []*string{p("b")}, 1)},
		{Canonical("ta", nil, nil, 1), Canonical("t", []*string{p("a")}, nil, 1)},
		{Canonical("t", nil, nil, 1), Canonical("t", nil, nil, 2)},
	} {
		if bytes.Equal(c[0], c[1]) {
			t.Fatalf("ambiguous: %x", c[0])
		}
	}
}

/*
FuzzCanonical: splits strings into pk and content fields (with NULLs) at
fuzzed points; every encoding decodes back to exactly its input.
*/
func FuzzCanonical(f *testing.F) {
	f.Add("write_grant", "abc", "def", uint8(1), uint8(2), uint8(0), int64(1))
	f.Add("t", "", "", uint8(0), uint8(0), uint8(0xff), int64(7))
	f.Fuzz(func(t *testing.T, table, a, b string, cutA, cutB, nulls uint8, version int64) {
		if version <= 0 {
			version = -version + 1
		}
		split := func(s string, cut uint8) []*string {
			i := int(cut) % (len(s) + 1)
			return []*string{p(s[:i]), p(s[i:])}
		}
		pk, content := split(a, cutA), split(b, cutB)
		for i, fs := range [][]*string{pk, content} {
			for j := range fs {
				if nulls&(1<<(i*2+j)) != 0 {
					fs[j] = nil
				}
			}
		}
		if nulls&0x10 != 0 {
			pk = pk[:1]
		}
		enc := Canonical(table, pk, content, version)
		gt, gpk, gc, gv, err := decode(enc)
		if err != nil || gt != table || !eqFields(gpk, pk) || !eqFields(gc, content) || gv != version {
			t.Fatalf("round trip of (%q, %v, %v, %d) failed: %v", table, pk, content, version, err)
		}
	})
}
