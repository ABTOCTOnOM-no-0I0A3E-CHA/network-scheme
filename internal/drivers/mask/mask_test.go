package mask_test

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/internal/drivers/mask"
)

const fixtures = "../../../test/fixtures/configs"

func load(t *testing.T, name string) (cfg string, secrets []string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtures, name+"-secrets.txt"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := os.ReadFile(filepath.Join(fixtures, name+"-secrets.secrets"))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(s), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			secrets = append(secrets, l)
		}
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n"), secrets
}

func TestGoldenNoSecretSurvives(t *testing.T) {
	for _, name := range []string{"mes", "esr"} {
		t.Run(name, func(t *testing.T) {
			cfg, secrets := load(t, name)
			if len(secrets) < 10 {
				t.Fatalf("fixture lists only %d secrets", len(secrets))
			}
			out := mask.Secrets(cfg)
			for _, s := range secrets {
				if !strings.Contains(cfg, s) {
					t.Errorf("fixture bug: %q is not in the config", s)
				}
				forms := []string{s, base64.StdEncoding.EncodeToString([]byte(s)), base64.RawURLEncoding.EncodeToString([]byte(s)),
					hex.EncodeToString([]byte(s)), strings.ToLower(hex.EncodeToString([]byte(s)))}
				for _, f := range forms {
					if strings.Contains(out, f) {
						t.Errorf("secret %q (form %q) survived masking", s, f)
					}
				}
			}
			if mask.Secrets(out) != out {
				t.Error("masking is not idempotent")
			}
		})
	}
}

/* Structure is kept: the non-secret commands are still there. */
func TestStructurePreserved(t *testing.T) {
	cfg, _ := load(t, "mes")
	out := mask.Secrets(cfg)
	for _, want := range []string{
		"username admin password *** privilege 15",
		"username oper password encrypted *** privilege 7",
		"enable password level 15 encrypted ***",
		"snmp-server community *** ro",
		"radius-server key ***",
		"ip ospf message-digest-key 1 md5 ***",
		"ntp authentication-key 1 md5 ***",
		"interface gigabitethernet1/0/1",
		"ip route 0.0.0.0 0.0.0.0 10.1.100.1",
		"crypto certificate 1 import\n***\n.",
		"-----BEGIN RSA PRIVATE KEY-----\n***\n-----END RSA PRIVATE KEY-----",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("masked config lacks %q", want)
		}
	}
	cfg, _ = load(t, "esr")
	out = mask.Secrets(cfg)
	for _, want := range []string{"snmp-server community *** ro", "  password encrypted ***", "interface gigabitethernet 1/0/1", "vlan 10"} {
		if !strings.Contains(out, want) {
			t.Errorf("masked ESR config lacks %q", want)
		}
	}
}

func TestMaskCases(t *testing.T) {
	for in, want := range map[string]string{
		"username a password 5 privilege 15":     "username a password *** privilege 15",
		"password 7 abcdef":                      "password *** ***",
		"snmp-server community \"my comm\" ro":   "snmp-server community *** ro",
		"snmp-server host 10.0.0.1 public":       "snmp-server host 10.0.0.1 ***",
		"description link md5 0123456789abcdef0": "description link md5 ***",
		"hostname sw1":                           "hostname sw1",
		"interface tengigabitethernet1/0/12":     "interface tengigabitethernet1/0/12",
		"authentication-key":                     "authentication-key",
		"-----BEGIN X-----\na\nb":                "-----BEGIN X-----\n***",
		"abcdEFGH0123456789abcdEFGH0123456789":   "***",
	} {
		if got := mask.Secrets(in); got != want {
			t.Errorf("Secrets(%q) = %q, want %q", in, got, want)
		}
	}
}

/* Bypasses found in review: the secret must not survive, and the line must stay stable. */
func TestReviewBypasses(t *testing.T) {
	nbsp := " "
	for _, c := range []struct{ in, secret string }{
		{"snmp-server community-group COMMSECRET grp", "COMMSECRET"},
		{`snmp-server community "esc\"aped quote" ro`, "aped"},
		{`snmp-server community "esc\"aped quote" ro`, "quote"},
		{`password "a\"b c"`, "b c"},
		{`password "a\"b c"`, `a\"b`},
		{"snmp-server user u g v3 auth sha AUTHKEY priv aes 128 PRIVKEY", "AUTHKEY"},
		{"snmp-server user u g v3 auth sha AUTHKEY priv aes 128 PRIVKEY", "PRIVKEY"},
		{"snmp-server host 10.0.0.1 vrf mgmt traps version 2c COMMSECRET", "COMMSECRET"},
		{"snmp-server host ipv6 2001:db8::1 traps COMMSECRET", "COMMSECRET"},
		{"snmp-server host 10.0.0.1 COMMSECRET udp-port 162", "COMMSECRET"},
		{"vrrp 1 authentication text KSECRET", "KSECRET"},
		{"vrrp 1 authentication KSECRET", "KSECRET"},
		{"wpa-psk ascii 0 KSECRET", "KSECRET"},
		{"password cipher KSECRET", "KSECRET"},
		{"bgp neighbor x password ascii KSECRET", "KSECRET"},
		{"local-user a password irreversible-cipher %^%#abcdefghijklmnopqrstuvwx%^%#", "abcdefghijklmnopqrstuvwx"},
		{"secret 12 KSECRET", "KSECRET"},
		{"password 12 KSECRET", "KSECRET"},
		{"password 99 KSECRET", "KSECRET"},
		{"key 12 KSECRET", "KSECRET"},
		{"password" + nbsp + "KSECRET", "KSECRET"},
		{"password-hash KSECRET", "KSECRET"},
		{"hash KSECRET", "KSECRET"},
		{"password two words", "words"},
		{"password two words", "two"},
		{"key-id 1 algorithm md5 KSECRET", "KSECRET"},
		{"password" + string(rune(0x200b)) + "KSECRET", "KSECRET"},
		{"community=KSECRET", "KSECRET"},
	} {
		out := mask.Secrets(c.in)
		if strings.Contains(out, c.secret) {
			t.Errorf("Secrets(%q) = %q leaks %q", c.in, out, c.secret)
		}
		if mask.Secrets(out) != out {
			t.Errorf("Secrets(%q) not idempotent", c.in)
		}
	}
	/* Structure that carries no secret stays readable. */
	for in, want := range map[string]string{
		"snmp-server community AAA ro":                          "snmp-server community *** ro",
		"radius-server host 1.1.1.1 key KSECRET auth-port 1812": "radius-server host 1.1.1.1 key *** auth-port 1812",
		"ip ospf authentication message-digest":                 "ip ospf authentication message-digest",
		"aaa authentication login default radius local":         "aaa authentication login default radius local",
	} {
		if got := mask.Secrets(in); got != want {
			t.Errorf("Secrets(%q) = %q, want %q", in, got, want)
		}
	}
}

func FuzzMaskSecrets(f *testing.F) {
	for _, n := range []string{"mes", "esr"} {
		b, _ := os.ReadFile(filepath.Join(fixtures, n+"-secrets.txt"))
		f.Add(string(b))
	}
	for _, s := range []string{"password", "password 5", "key key key", "-----BEGIN", "crypto key import\n", "snmp-server host", "\"unterminated password", "a\x00b\r\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out := mask.Secrets(in)
		if again := mask.Secrets(out); again != out {
			t.Fatalf("not idempotent:\n in %q\n 1st %q\n 2nd %q", in, out, again)
		}
	})
}
