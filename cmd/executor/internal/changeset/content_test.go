package changeset

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/forms"
	"github.com/beekamai/network-scheme/internal/execpolicy"
)

func sample() Content {
	return Content{
		Title:   "VLAN 30 on the access ports",
		Devices: []int64{7, 3, 11},
		Steps: []Step{{Line: "configure"}, {Line: "interface {{port}}"}, {Line: "description {{desc}}"}, {Line: "end"},
			{Form: &forms.Params{Kind: "vlan-create", VLAN: 30}}},
		Vars: map[int64]map[string]string{
			7: {"port": "gi1/0/1", "desc": "a"}, 3: {"port": "gi1/0/2", "desc": "b"}, 11: {"port": "gi1/0/3", "desc": "c"},
		},
		BatchSize: 2, SettleS: 30,
	}
}

func TestCanonicalRoundTrip(t *testing.T) {
	for _, c := range []Content{sample(), {Title: "r", Devices: []int64{5}, BatchSize: 1, Restore: []RestoreItem{{5, 9}}}} {
		b := c.Canonical()
		d, err := decodeContent(b)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(d.Canonical(), b) || d.Title != c.Title || !reflect.DeepEqual(d.Devices, c.Devices) || d.Kind() != c.Kind() {
			t.Fatalf("round trip: %+v / %+v", d, c)
		}
	}
	/* map order never changes the encoding */
	a, b := sample(), sample()
	b.Vars = map[int64]map[string]string{11: b.Vars[11], 3: b.Vars[3], 7: b.Vars[7]}
	if !bytes.Equal(a.Canonical(), b.Canonical()) {
		t.Fatal("the encoding depends on map order")
	}
	/* the order of devices and steps is part of it */
	b.Devices = []int64{3, 7, 11}
	if bytes.Equal(a.Canonical(), b.Canonical()) {
		t.Fatal("another canary encodes alike")
	}
}

func TestDecodeRefusesNonCanonical(t *testing.T) {
	good := sample().Canonical()
	for name, b := range map[string][]byte{
		"empty":     nil,
		"trailing":  append(append([]byte{}, good...), 0),
		"truncated": good[:len(good)-1],
		"domain":    append([]byte{0, 0, 0, 1, 'x'}, good[len(contentDomain)+4:]...),
		"huge":      bytes.Repeat([]byte{0xff}, 64),
	} {
		if _, err := decodeContent(b); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}

/* FuzzContentCanonical: the encoding is injective (decode is its strict inverse) and decode never panics. */
func FuzzContentCanonical(f *testing.F) {
	f.Add(sample().Canonical())
	f.Add((Content{Title: "r", Devices: []int64{5}, Restore: []RestoreItem{{5, 9}}}).Canonical())
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := decodeContent(b)
		if err != nil {
			return
		}
		if !bytes.Equal(c.Canonical(), b) {
			t.Fatalf("decode accepted a non-canonical encoding")
		}
		d, err := decodeContent(c.Canonical())
		if err != nil || !bytes.Equal(d.Canonical(), b) {
			t.Fatalf("round trip: %v", err)
		}
	})
}

func TestCheckBounds(t *testing.T) {
	p := execpolicy.Default()
	if err := sample().Check(p); err != nil {
		t.Fatalf("sample refused: %v", err)
	}
	lines := func(n int) []Step {
		s := make([]Step, n)
		for i := range s {
			s[i] = Step{Line: "show version"}
		}
		return s
	}
	devs := func(n int) []int64 {
		d := make([]int64, n)
		for i := range d {
			d[i] = int64(i + 1)
		}
		return d
	}
	ok := map[string]func(*Content){
		"title 120":       func(c *Content) { c.Title = strings.Repeat("й", 120) },
		"max lines":       func(c *Content) { c.Steps, c.Vars = lines(p.ChangesetMaxLines), nil },
		"max devices":     func(c *Content) { c.Devices, c.Vars = devs(p.ChangesetMaxDevices), nil; c.Steps = lines(1) },
		"max batch":       func(c *Content) { c.BatchSize = p.ChangesetMaxBatch },
		"line 512":        func(c *Content) { c.Steps[0].Line = strings.Repeat("a", 512) },
		"value 128":       func(c *Content) { c.Vars[7]["desc"] = strings.Repeat("v", 128) },
		"settle 600":      func(c *Content) { c.SettleS = 600 },
		"unused variable": func(c *Content) { c.Vars[7]["spare"] = "x" },
	}
	for name, mod := range ok {
		c := sample()
		mod(&c)
		if err := c.Check(p); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
	refused := map[string]func(*Content){
		"no title":          func(c *Content) { c.Title = "" },
		"blank title":       func(c *Content) { c.Title = "   " },
		"title 121":         func(c *Content) { c.Title = strings.Repeat("a", 121) },
		"title bidi":        func(c *Content) { c.Title = "a" + string(rune(0x202e)) + "b" },
		"no devices":        func(c *Content) { c.Devices = nil },
		"too many devices":  func(c *Content) { c.Devices, c.Vars = devs(p.ChangesetMaxDevices+1), nil; c.Steps = lines(1) },
		"repeated device":   func(c *Content) { c.Devices = []int64{7, 7, 11} },
		"device 0":          func(c *Content) { c.Devices[1] = 0 },
		"too many lines":    func(c *Content) { c.Steps, c.Vars = lines(p.ChangesetMaxLines+1), nil },
		"no steps":          func(c *Content) { c.Steps = nil },
		"steps and restore": func(c *Content) { c.Restore = []RestoreItem{{7, 1}} },
		"line 513":          func(c *Content) { c.Steps[0].Line = strings.Repeat("a", 513) },
		"control char":      func(c *Content) { c.Steps[0].Line = "hostname a\rreload" },
		"newline":           func(c *Content) { c.Steps[0].Line = "hostname a\nreload" },
		"line and form":     func(c *Content) { c.Steps[0].Form = &forms.Params{Kind: "vlan-create", VLAN: 1} },
		"empty step":        func(c *Content) { c.Steps[0] = Step{} },
		"bad placeholder":   func(c *Content) { c.Steps[0].Line = "hostname {{Port}}" },
		"stray braces":      func(c *Content) { c.Steps[0].Line = "hostname }}" },
		"undefined var":     func(c *Content) { c.Steps[0].Line = "hostname {{name}}" },
		"var missing on 11": func(c *Content) { delete(c.Vars[11], "desc") },
		"var name":          func(c *Content) { c.Vars[7]["Bad"] = "x" },
		"var value 129":     func(c *Content) { c.Vars[7]["desc"] = strings.Repeat("v", 129) },
		"var value braces":  func(c *Content) { c.Vars[7]["desc"] = "{{port}}" },
		"var value utf8":    func(c *Content) { c.Vars[7]["desc"] = "й" },
		"var value newline": func(c *Content) { c.Vars[7]["desc"] = "a\nreload" },
		"vars of a stranger": func(c *Content) {
			c.Vars[99] = map[string]string{"port": "x"}
		},
		"too many vars": func(c *Content) {
			for i := range 33 {
				c.Vars[7][string(rune('a'+i%26))+strings.Repeat("x", i/26+1)] = "v"
			}
		},
		"batch 0":        func(c *Content) { c.BatchSize = 0 },
		"batch over":     func(c *Content) { c.BatchSize = p.ChangesetMaxBatch + 1 },
		"settle -1":      func(c *Content) { c.SettleS = -1 },
		"settle 601":     func(c *Content) { c.SettleS = 601 },
		"form vlan":      func(c *Content) { c.Steps[4].Form.VLAN = 4095 },
		"form var":       func(c *Content) { c.Steps[4].Form.Name = "{{desc}}" },
		"form non-ascii": func(c *Content) { c.Steps[4].Form.Description = "й" },
	}
	for name, mod := range refused {
		c := sample()
		c.Vars = map[int64]map[string]string{7: {"port": "gi1/0/1", "desc": "a"}, 3: {"port": "gi1/0/2", "desc": "b"}, 11: {"port": "gi1/0/3", "desc": "c"}}
		mod(&c)
		if err := c.Check(p); !errors.Is(err, ErrContent) {
			t.Errorf("%s: %v", name, err)
		}
	}
	restore := Content{Title: "r", Devices: []int64{5, 6}, BatchSize: 1, Restore: []RestoreItem{{5, 9}, {6, 10}}}
	if err := restore.Check(p); err != nil {
		t.Fatalf("restore refused: %v", err)
	}
	for name, mod := range map[string]func(*Content){
		"order":     func(c *Content) { c.Restore[0], c.Restore[1] = c.Restore[1], c.Restore[0] },
		"missing":   func(c *Content) { c.Restore = c.Restore[:1] },
		"version 0": func(c *Content) { c.Restore[1].Version = 0 },
		"vars":      func(c *Content) { c.Vars = map[int64]map[string]string{5: {"a": "b"}} },
	} {
		c := restore
		c.Restore = append([]RestoreItem{}, restore.Restore...)
		mod(&c)
		if err := c.Check(p); !errors.Is(err, ErrContent) {
			t.Errorf("restore %s: %v", name, err)
		}
	}
}
