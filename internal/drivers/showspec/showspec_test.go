package showspec_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/internal/drivers/showspec"
)

var (
	ifSpec   = showspec.Spec{Key: "i", Args: []showspec.ArgKind{showspec.InterfaceName}}
	vlanSpec = showspec.Spec{Key: "v", Args: []showspec.ArgKind{showspec.VLANID}}
	bare     = showspec.Spec{Key: "b"}
)

func TestParseArgsAccepts(t *testing.T) {
	cases := []struct {
		spec showspec.Spec
		raw  string
		want []string
		json string
	}{
		{ifSpec, `{"interface":"Gi1/0/1"}`, []string{"Gi1/0/1"}, `{"interface":"Gi1/0/1"}`},
		{ifSpec, `{"interface":"gigabitethernet 1/0/1"}`, []string{"gigabitethernet 1/0/1"}, `{"interface":"gigabitethernet 1/0/1"}`},
		{ifSpec, `{"interface":"Po1.200"}`, []string{"Po1.200"}, `{"interface":"Po1.200"}`},
		{vlanSpec, `{"vlan":1}`, []string{"1"}, `{"vlan":1}`},
		{vlanSpec, `{"vlan": 4094 }`, []string{"4094"}, `{"vlan":4094}`},
		{bare, `{}`, nil, `{}`},
		{bare, ``, nil, `{}`},
	}
	for _, c := range cases {
		got, canon, err := showspec.ParseArgs(c.spec, json.RawMessage(c.raw))
		if err != nil || !slices.Equal(got, c.want) || string(canon) != c.json {
			t.Errorf("ParseArgs(%s) = %q, %s, %v; want %q, %s", c.raw, got, canon, err, c.want, c.json)
		}
	}
}

func TestParseArgsRejects(t *testing.T) {
	long := strings.Repeat("a", 65)
	cases := []struct {
		spec showspec.Spec
		raw  string
	}{
		{ifSpec, `{"interface":"Gi1/0/1 | include x"}`},
		{ifSpec, `{"interface":"Gi1/0/1\n"}`},
		{ifSpec, `{"interface":"Gi1/0/1\r\nshow running-config"}`},
		{ifSpec, `{"interface":"Gi1/0/1;reload"}`},
		{ifSpec, `{"interface":"Gi1/0/1&&x"}`},
		{ifSpec, `{"interface":"$(id)"}`},
		{ifSpec, `{"interface":"Gi1/0/1\u0000"}`},
		{ifSpec, `{"interface":"G\u0456\u0031/0/1"}`}, /* Cyrillic i */
		{ifSpec, `{"interface":"Gi1\uff0f0\uff0f1"}`}, /* fullwidth slash */
		{ifSpec, `{"interface":"Gi1/0/1\u200b"}`},     /* zero width space */
		{ifSpec, `{"interface":" Gi1/0/1"}`},
		{ifSpec, `{"interface":"Gi1/0/1 "}`},
		{ifSpec, `{"interface":"Gi  1/0/1"}`},
		{ifSpec, `{"interface":""}`},
		{ifSpec, `{"interface":"` + long + `"}`},
		{ifSpec, `{"interface":1}`},
		{ifSpec, `{"interface":null}`},
		{ifSpec, `{"interface":["Gi1/0/1"]}`},
		{ifSpec, `{"interface":"Gi1/0/1","vlan":1}`},
		{ifSpec, `{"vlan":1}`},
		{ifSpec, `{}`},
		{ifSpec, `[]`},
		{ifSpec, `"Gi1/0/1"`},
		{ifSpec, `null`},
		{vlanSpec, `{"vlan":0}`},
		{vlanSpec, `{"vlan":4095}`},
		{vlanSpec, `{"vlan":-1}`},
		{vlanSpec, `{"vlan":1.5}`},
		{vlanSpec, `{"vlan":1.0}`},
		{vlanSpec, `{"vlan":1e1}`},
		{vlanSpec, `{"vlan":"10"}`},
		{vlanSpec, `{"vlan":true}`},
		{vlanSpec, `{"vlan":null}`},
		{vlanSpec, `{"vlan":99999999999999999999}`},
		{vlanSpec, `{"vlan":010}`},
		{bare, `{"interface":"Gi1/0/1"}`},
		{bare, `null`},
		{bare, `[]`},
		{bare, `{`},
	}
	for _, c := range cases {
		if got, _, err := showspec.ParseArgs(c.spec, json.RawMessage(c.raw)); err == nil {
			t.Errorf("ParseArgs(%s) accepted: %q", c.raw, got)
		}
	}
}

/* Every spec has distinct argument kinds (they name the members of the args object) and no key mentions a configuration. */
func TestForTable(t *testing.T) {
	for _, d := range []string{"eltex-mes", "eltex-esr"} {
		specs := showspec.For(d)
		if len(specs) == 0 {
			t.Fatalf("%s: no specs", d)
		}
		keys := map[string]bool{}
		for _, s := range specs {
			if keys[s.Key] || strings.Contains(s.Key, "config") {
				t.Errorf("%s: key %q repeated or a config key", d, s.Key)
			}
			keys[s.Key] = true
			seen := map[showspec.ArgKind]bool{}
			for _, k := range s.Args {
				if seen[k] {
					t.Errorf("%s/%s: kind %s twice", d, s.Key, k)
				}
				seen[k] = true
			}
		}
	}
	for _, d := range []string{"generic-snmp", "auto", "", "unknown"} {
		if showspec.For(d) != nil {
			t.Errorf("For(%q) is not empty", d)
		}
	}
}
