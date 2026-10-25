package eltexmes

import (
	"strings"
	"testing"
)

func TestParseSysDescr(t *testing.T) {
	for in, want := range map[string]string{
		"MES2324P AC 28-port 1G/10G Managed Switch with 24 POE+ ports": "MES2324P",
		"MES2324 28-port 1G/10G Managed Switch":                        "MES2324",
		"MES-3124F 28-port 1G/10G Managed Switch":                      "MES-3124F",
		"MES5324":                             "MES5324",
		"24-port 10/100/1000 Ethernet Switch": "",
		"MES23 short":                         "",
		"MES2324<b> 28-port":                  "",
		"mes2324 28-port":                     "",
		" MES2324 28-port":                    "",
		"MES2324 " + strings.Repeat("x", 300): "",
		"MES2324TOOLONGSUFFIX 28-port":        "",
		"":                                    "",
	} {
		got, ok := parseSysDescr(in)
		if got != want || ok != (want != "") {
			t.Errorf("parseSysDescr(%.40q) = %q, %v; want %q", in, got, ok, want)
		}
	}
}
