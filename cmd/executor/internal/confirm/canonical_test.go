package confirm

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

/* The encoding is pinned: H of a description never changes between versions of the executor. */
func TestCanonicalVector(t *testing.T) {
	d := Description{Action: "hostkey.accept", Fields: []Field{{"address", "192.0.2.7"}, {"device", "12"}}}
	c, err := d.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	want := "0000000e" + hex.EncodeToString([]byte("nms/confirm/v1")) +
		"0000000e" + hex.EncodeToString([]byte("hostkey.accept")) + "00000002" +
		"00000007" + hex.EncodeToString([]byte("address")) + "00000009" + hex.EncodeToString([]byte("192.0.2.7")) +
		"00000006" + hex.EncodeToString([]byte("device")) + "00000002" + hex.EncodeToString([]byte("12"))
	if hex.EncodeToString(c) != want {
		t.Fatalf("canonical %x\nwant      %s", c, want)
	}
}

func TestDescriptionValidate(t *testing.T) {
	for _, d := range []Description{
		{Action: ""}, {Action: "Bad"}, {Action: strings.Repeat("a", 57)}, {Action: ".x"},
		{Action: "a", Fields: []Field{{"b", "1"}, {"a", "2"}}}, /* unordered */
		{Action: "a", Fields: []Field{{"a", "1"}, {"a", "2"}}}, /* duplicate */
		{Action: "a", Fields: []Field{{"", "1"}}},              /* empty key */
		{Action: "a", Fields: []Field{{"A", "1"}}},             /* key form */
		{Action: "a", Fields: []Field{{"a", "\xff"}}},          /* not UTF-8 */
		{Action: "a", Fields: []Field{{"a", strings.Repeat("x", maxValue+1)}}},
	} {
		if _, err := d.Hash(); err == nil {
			t.Errorf("accepted %+v", d)
		}
	}
}

/* Two different descriptions never share an encoding: boundaries cannot be shifted between fields. */
func TestCanonicalBoundaries(t *testing.T) {
	pairs := [][2]Description{
		{{Action: "a", Fields: []Field{{"k", "ab"}}}, {Action: "a", Fields: []Field{{"k", "a"}, {"l", "b"}}}},
		{{Action: "ab", Fields: nil}, {Action: "a", Fields: []Field{{"b", ""}}}},
		{{Action: "a", Fields: []Field{{"ka", ""}}}, {Action: "a", Fields: []Field{{"k", "a"}}}},
		{{Action: "a", Fields: nil}, {Action: "a", Fields: []Field{}}},
	}
	for _, p := range pairs {
		h0, err0 := p[0].Hash()
		h1, err1 := p[1].Hash()
		if err0 != nil || err1 != nil {
			t.Fatal(err0, err1)
		}
		if (h0 == h1) != (len(p[0].Fields) == 0 && len(p[1].Fields) == 0 && p[0].Action == p[1].Action) {
			t.Errorf("%+v and %+v: same H %v", p[0], p[1], h0 == h1)
		}
	}
}

/*
FuzzCanonical: decode accepts only canonical encodings (decode then encode
gives the same bytes), and every valid description encodes to bytes that
decode back to it: the encoding is injective.
*/
func FuzzCanonical(f *testing.F) {
	seed, _ := Description{Action: "hostkey.accept", Fields: []Field{{"address", "192.0.2.7"}, {"device", "12"}}}.Canonical()
	f.Add(seed, "a", "k", "v", "l", "w")
	f.Add([]byte{}, "line.dangerous", "line", "reload", "", "")
	f.Fuzz(func(t *testing.T, raw []byte, action, k1, v1, k2, v2 string) {
		if d, err := decode(raw); err == nil {
			again, err := d.Canonical()
			if err != nil || !bytes.Equal(again, raw) {
				t.Fatalf("decode accepted a non-canonical encoding %x", raw)
			}
		}
		for _, d := range []Description{
			{Action: action},
			{Action: action, Fields: []Field{{k1, v1}}},
			{Action: action, Fields: []Field{{k1, v1}, {k2, v2}}},
		} {
			c, err := d.Canonical()
			if err != nil {
				continue
			}
			back, err := decode(c)
			if err != nil {
				t.Fatalf("%+v: its own encoding does not decode: %v", d, err)
			}
			if len(d.Fields) == 0 {
				d.Fields = nil
			}
			if !reflect.DeepEqual(back, d) {
				t.Fatalf("%+v decodes back as %+v", d, back)
			}
		}
	})
}

/* M5: what is shown is what H covers: control and format characters (newline, tab, C1, bidi overrides, zero width) are refused in values. */
func TestDescriptionRefusesInvisibleCharacters(t *testing.T) {
	for _, v := range []string{"a\x0ab", "a\x09b", "a\x00b", "a\x7fb", "a\xc2\x85b", "adm\xe2\x80\xaein", "a\xe2\x81\xa6b", "a\xe2\x80\x8bb", "\xef\xbb\xbfa"} {
		d := Description{Action: "a", Fields: []Field{{"v", v}}}
		if _, err := d.Hash(); err == nil {
			t.Errorf("accepted value %q", v)
		}
	}
	if _, err := (Description{Action: "a", Fields: []Field{{"v", "Ёлка 192.0.2.7 sw-1/0"}}}).Hash(); err != nil {
		t.Errorf("plain text refused: %v", err)
	}
}
