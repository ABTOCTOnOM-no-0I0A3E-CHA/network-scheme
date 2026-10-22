package triggers

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseValid(t *testing.T) {
	for _, tc := range []struct{ kind, raw string }{
		{"availability", `{"states":["down","partial"]}`},
		{"if_oper_down", `{}`},
		{"if_oper_down", ``},
		{"if_oper_down", `{"if_index":12}`},
		{"metric_threshold", `{"metric":"cpu","op":"gt","value":90}`},
		{"metric_threshold", `{"metric":"temp","op":"gt","value":-50}`},
		{"metric_threshold", `{"metric":"if_util_in","op":"gt","value":80,"if_index":3}`},
		{"metric_threshold", `{"metric":"if_errors","op":"gt","value":1e9}`},
		{"trap", `{"name":"linkDown"}`},
		{"syslog", `{"severity_min":4}`},
		{"syslog", `{"severity_min":3,"contains":"` + strings.Repeat("я", 128) + `"}`},
		{"poller_unavailable", `{}`},
	} {
		p, err := Parse(tc.kind, json.RawMessage(tc.raw))
		if err != nil {
			t.Errorf("%s %s: %v", tc.kind, tc.raw, err)
			continue
		}
		if string(p.Kind()) != tc.kind {
			t.Errorf("%s: Kind() = %s", tc.kind, p.Kind())
		}
	}
}

func TestParseInvalid(t *testing.T) {
	long := strings.Repeat("x", 129)
	for _, tc := range []struct{ name, kind, raw string }{
		{"unknown kind", "regex", `{}`},
		{"empty kind", "", `{}`},
		{"extra field", "trap", `{"name":"a","pattern":".*"}`},
		{"extra field system", "poller_unavailable", `{"x":1}`},
		{"trailing data", "trap", `{"name":"a"}{}`},
		{"not an object", "trap", `[]`},
		{"availability empty", "availability", `{"states":[]}`},
		{"availability unknown", "availability", `{"states":["up"]}`},
		{"availability duplicate", "availability", `{"states":["down","down"]}`},
		{"if_index zero", "if_oper_down", `{"if_index":0}`},
		{"if_index huge", "if_oper_down", `{"if_index":4294967296}`},
		{"cpu over", "metric_threshold", `{"metric":"cpu","op":"gt","value":100.1}`},
		{"cpu negative", "metric_threshold", `{"metric":"cpu","op":"gt","value":-1}`},
		{"temp low", "metric_threshold", `{"metric":"temp","op":"lt","value":-50.5}`},
		{"temp high", "metric_threshold", `{"metric":"temp","op":"gt","value":151}`},
		{"errors over", "metric_threshold", `{"metric":"if_errors","op":"gt","value":1e9001}`},
		{"errors over 1e9", "metric_threshold", `{"metric":"if_errors","op":"gt","value":2e9}`},
		{"bad metric", "metric_threshold", `{"metric":"disk","op":"gt","value":1}`},
		{"bad op", "metric_threshold", `{"metric":"cpu","op":"ge","value":1}`},
		{"if_index on device metric", "metric_threshold", `{"metric":"cpu","op":"gt","value":1,"if_index":1}`},
		{"trap empty", "trap", `{"name":""}`},
		{"trap long", "trap", `{"name":"` + strings.Repeat("a", 1025) + `"}`},
		{"trap control", "trap", `{"name":"a\u0000b"}`},
		{"syslog severity", "syslog", `{"severity_min":8}`},
		{"syslog negative", "syslog", `{"severity_min":-1}`},
		{"syslog long", "syslog", `{"severity_min":1,"contains":"` + long + `"}`},
		{"syslog empty contains", "syslog", `{"severity_min":1,"contains":""}`},
		{"syslog control", "syslog", `{"severity_min":1,"contains":"a\nb"}`},
	} {
		if _, err := Parse(tc.kind, json.RawMessage(tc.raw)); err == nil {
			t.Errorf("%s: %s %s accepted", tc.name, tc.kind, tc.raw)
		}
	}
}

func TestValidateDuration(t *testing.T) {
	for _, s := range []int{0, 60, 86400} {
		if err := ValidateDuration(s); err != nil {
			t.Errorf("%d: %v", s, err)
		}
	}
	for _, s := range []int{-1, 86401} {
		if err := ValidateDuration(s); err == nil {
			t.Errorf("%d accepted", s)
		}
	}
}
