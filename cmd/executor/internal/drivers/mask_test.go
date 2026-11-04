package drivers_test

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
)

/* Known secrets, each also checked base64- and hex-encoded in the masked text [R §7]. */
const (
	sPass  = "Zq7-Pass-91xT"
	sComm  = "commZ81rw"
	sKey   = "radKey55q"
	sURL   = "urlPw-77k"
	sPSK   = "pskSecret4x"
	sEnc   = "CDE65039E5591FA3F1"
	sHash  = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
	sPEM   = "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu"
	sAbbr  = "abbrPw-3q"
	sTac   = "tacKey9z"
	sSnmpA = "authPw-8w"
	sSnmpP = "privPw-2v"
)

var maskInput = strings.Join([]string{
	"username admin password " + sPass + " privilege 15",
	"username bob password encrypted " + sHash,
	"  password encrypted $6$Q1w2E3r4$" + sPEM[:20],
	"enable password " + sPass + " level 15",
	"snmp-server community " + sComm + " ro",
	"encrypted snmp-server community " + sComm + " ro",
	"encrypted radius-server host 192.0.2.5 key " + sKey,
	"radius-server host 192.0.2.5 key " + sKey,
	"tacacs-server key " + sTac,
	"authentication key ascii-text encrypted " + sEnc,
	"authentication pre-shared-key hexadecimal " + hex.EncodeToString([]byte(sPSK)),
	"pre-shared-key ascii-text " + sPSK,
	"snmp-server user u1 g1 v3 auth sha " + sSnmpA + " priv " + sSnmpP,
	"backup server sftp://nms:" + sURL + "@192.0.2.9/cfg",
	"copy tftp://user:" + sURL + "@192.0.2.1/a.cfg running-config",
	"username x passw " + sAbbr,
	"crypto key import rsa",
	sPEM,
	sPEM[10:] + "Zx",
	".",
	"-----BEGIN RSA PRIVATE KEY-----",
	sPEM,
	"-----END RSA PRIVATE KEY-----",
	"hostname core-sw1",
	"interface gigabitethernet1/0/1",
	" description uplink",
}, "\n")

/* Golden: every secret kind masked (substring, base64, hex), the structure and the harmless lines kept. */
func TestMaskSecretsGolden(t *testing.T) {
	for name, f := range lines {
		out := f.d.MaskSecrets(maskInput)
		for _, s := range []string{sPass, sComm, sKey, sURL, sPSK, sEnc, sHash, sPEM, sPEM[10:], sAbbr, sTac, sSnmpA, sSnmpP, sPEM[:20]} {
			for _, enc := range []string{s, base64.StdEncoding.EncodeToString([]byte(s)), hex.EncodeToString([]byte(s))} {
				if strings.Contains(out, enc) {
					t.Errorf("%s: %q survives masking:\n%s", name, enc, out)
				}
			}
		}
		for _, keep := range []string{"hostname core-sw1", "interface gigabitethernet1/0/1", " description uplink",
			"snmp-server community *** ro", "@192.0.2.9/cfg", "-----END RSA PRIVATE KEY-----", "privilege 15"} {
			if !strings.Contains(out, keep) {
				t.Errorf("%s: %q lost:\n%s", name, keep, out)
			}
		}
		if again := f.d.MaskSecrets(out); again != out {
			t.Errorf("%s: masking is not idempotent", name)
		}
	}
}

/* RenderForm output passes Classify in order (safe on a non-management interface) and leaves the mode at the root. */
func TestRenderFormPassesClassify(t *testing.T) {
	forms := func(iface string) []drivers.Form {
		return []drivers.Form{
			{Kind: drivers.FormDescription, Interface: iface, Description: "to-core"},
			{Kind: drivers.FormDescription, Interface: iface},
			{Kind: drivers.FormState, Interface: iface, Up: true},
			{Kind: drivers.FormState, Interface: iface},
			{Kind: drivers.FormAccessVLAN, Interface: iface, VLAN: 20},
			{Kind: drivers.FormAccessVLAN, Interface: iface},
			{Kind: drivers.FormVLANCreate, VLAN: 20},
			{Kind: drivers.FormVLANName, VLAN: 20, Name: "users"},
			{Kind: drivers.FormVLANDelete, VLAN: 20},
		}
	}
	for name, f := range lines {
		g, ctx := f.d.Grammar(), f.ctx(t)
		for _, fm := range forms(f.other) {
			ls, err := f.d.RenderForm(fm)
			if err != nil {
				t.Fatalf("%s: %+v: %v", name, fm, err)
			}
			m := g.Root()
			for _, l := range ls {
				if v := g.Classify(l, m, ctx); v.Class != core.Safe || v.Line != l {
					t.Errorf("%s: %+v: %q = %v (%s) %q", name, fm, l, v.Class, v.Reason, v.Line)
				}
				m = g.Next(l, m)
			}
			if m.Name() != "exec" || m.Unsure() {
				t.Errorf("%s: %+v ends in %q", name, fm, m.Name())
			}
		}
		/* on the management interface the same form is dangerous, never safe */
		ls, _ := f.d.RenderForm(drivers.Form{Kind: drivers.FormState, Interface: f.mgmtIf})
		m, worst := g.Root(), core.Safe
		for _, l := range ls {
			worst = max(worst, g.Classify(l, m, ctx).Class)
			m = g.Next(l, m)
		}
		if worst != core.Dangerous {
			t.Errorf("%s: shutdown of the management interface by form = %v", name, worst)
		}
		for _, bad := range []drivers.Form{
			{Kind: drivers.FormDescription, Interface: f.other, Description: `a"b`},
			{Kind: drivers.FormDescription, Interface: f.other, Description: "a;reload"},
			{Kind: drivers.FormDescription, Interface: f.other, Description: "a\nreload"},
			{Kind: drivers.FormDescription, Interface: f.other, Description: "x?"},
			{Kind: drivers.FormDescription, Interface: f.other, Description: "a  b"},
			{Kind: drivers.FormDescription, Interface: f.other, Description: strings.Repeat("a", 300)},
			{Kind: drivers.FormDescription, Interface: "gi1/0/1;reload"},
			{Kind: drivers.FormDescription, Interface: "gi1/0/1-4"},
			{Kind: drivers.FormAccessVLAN, Interface: f.other, VLAN: 4095},
			{Kind: drivers.FormVLANCreate, VLAN: 0},
			{Kind: drivers.FormVLANName, VLAN: 20, Name: "a b"},
			{Kind: "other"},
		} {
			if ls, err := f.d.RenderForm(bad); err == nil {
				t.Errorf("%s: %+v rendered %q", name, bad, ls)
			}
		}
	}
}
