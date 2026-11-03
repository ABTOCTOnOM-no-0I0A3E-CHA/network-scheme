package eltexesr

import (
	"strings"
	"testing"
)

func TestParseSysDescr(t *testing.T) {
	for _, c := range []struct {
		in, model, fw string
		ok            bool
	}{
		{"Eltex ESR-1000 Service Router 1.23.3 build 3 (date 27/03/2024 time 21:13:26)", "ESR-1000", "1.23.3", true},
		{"Eltex ESR-100 Service Router 1.24.0 build 53", "ESR-100", "1.24.0", true},
		{"Eltex ESR-12VF Service Router 1.11.6", "ESR-12VF", "1.11.6", true},
		{"Eltex ESR-1000 Service Router 1.23", "ESR-1000", "1.23", true},
		{"Eltex ESR-1000 Service Router", "", "", false},
		{"Eltex ESR-1000 Service Router x.y", "", "", false},
		{"Eltex ESR-1000 Service Router 1.23.3build", "", "", false},
		{"eltex esr-1000 service router 1.23.3", "", "", false},
		{"  Eltex ESR-1000 Service Router 1.23.3", "", "", false},
		{"Eltex ESR-<script> Service Router 1.2", "", "", false},
		{"Eltex ESR-1000 Service Router 1.23.3 " + strings.Repeat("x", 300), "", "", false},
		{"", "", "", false},
	} {
		m, fw, ok := parseSysDescr(c.in)
		if m != c.model || fw != c.fw || ok != c.ok {
			t.Errorf("parseSysDescr(%.40q) = %q, %q, %v; want %q, %q, %v", c.in, m, fw, ok, c.model, c.fw, c.ok)
		}
	}
}
