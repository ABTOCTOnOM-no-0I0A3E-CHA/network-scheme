package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/internal/install"
)

func rendered(t *testing.T) string {
	t.Helper()
	out, err := install.Render(install.RenderInput{PublicHost: "nms.example.org", ImageTag: "1.0.0", APIImage: "nms/api", GatewayImage: "nms/gateway"})
	if err != nil {
		t.Fatal(err)
	}
	return string(out["config/executor.yaml"])
}

func load(t *testing.T, body string) (Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "executor.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

/* The file nmsctl install renders loads as is. */
func TestRenderedConfigLoads(t *testing.T) {
	c, err := load(t, rendered(t))
	if err != nil {
		t.Fatal(err)
	}
	if c.DB.User != "nms_executor" || c.DB.Host != "postgres" || c.DB.Port != 5432 || c.DB.PasswordFile != "/run/secrets/db_executor_password" ||
		c.DB.MaxConns != defaultMaxConns || c.ListenXnet.String() != "172.30.2.2:8444" ||
		c.CoreSubnet.String() != "172.30.0.0/24" || c.XnetSubnet.String() != "172.30.2.0/24" || c.EdgeSubnet.String() != "172.30.3.0/24" ||
		c.PanelOrigin != "https://nms.example.org" || c.ExecutorOrigin != "https://nms.example.org:8443" ||
		c.SealingKeyFile != "/run/secrets/executor_sealing_key" || c.WriteKeyFile != "/run/secrets/domain_write_key" ||
		c.BackupKeyFile != "/run/secrets/domain_backup_key" || c.TicketPubKeyFile != "/run/secrets/ticket_pub" ||
		c.ClientCAFile != "/run/secrets/ca_crt" || c.StateDir != "/var/lib/executor" ||
		c.PolicyFile != "/etc/nms/policies/executor.yaml" || c.EgressFile != "/etc/nms/egress.yaml" {
		t.Errorf("unexpected config: %+v", c)
	}
}

func TestLoadRejects(t *testing.T) {
	base := rendered(t)
	set := func(key, value string) string {
		var out []string
		for _, l := range strings.Split(base, "\n") {
			if strings.HasPrefix(l, key+":") {
				l = key + ": " + value
			}
			out = append(out, l)
		}
		return strings.Join(out, "\n")
	}
	for name, body := range map[string]string{
		"unknown field":         base + "write_password: x\n",
		"no write key":          set("write_key_file", `""`),
		"no policy file":        set("policy_file", `""`),
		"no state dir":          set("state_dir", `""`),
		"wildcard listener":     set("listen_xnet", `"0.0.0.0:8444"`),
		"loopback listener":     set("listen_xnet", `"127.0.0.1:8444"`),
		"ipv6 listener":         set("listen_xnet", `"[fd00::2]:8444"`),
		"no port":               set("listen_xnet", `"172.30.2.2:0"`),
		"no listener":           set("listen_xnet", `""`),
		"http executor origin":  set("executor_origin", `"http://nms.example.org:8443"`),
		"origin with path":      set("executor_origin", `"https://nms.example.org:8443/x"`),
		"same origins":          set("executor_origin", `"https://NMS.example.org:443"`),
		"no panel origin":       set("panel_origin", `""`),
		"db without user":       strings.Replace(base, `user: "nms_executor"`, `user: ""`, 1),
		"db unknown field":      strings.Replace(base, `  port: 5432`, "  port: 5432\n  password: x", 1),
		"listener not an addr":  set("listen_xnet", `"executor:8444"`),
		"panel origin is a URL": set("panel_origin", `"https://nms.example.org/?a=b"`),
		"relative key path":     set("write_key_file", `"run/secrets/domain_write_key"`),
		"dotdot key path":       set("sealing_key_file", `"/run/secrets/../x"`),
		"relative state dir":    set("state_dir", `"var/lib/executor"`),
		"relative db password":  strings.Replace(base, `password_file: "/run/secrets/db_executor_password"`, `password_file: "pw"`, 1),
		"origin port 0":         set("executor_origin", `"https://nms.example.org:0"`),
		"origin port too big":   set("executor_origin", `"https://nms.example.org:65536"`),
		"origin port padded":    set("executor_origin", `"https://nms.example.org:08443"`),
		"broadcast listener":    set("listen_xnet", `"255.255.255.255:8444"`),
		"xnet broadcast":        set("listen_xnet", `"172.30.2.255:8444"`),
		"xnet network address":  set("listen_xnet", `"172.30.2.0:8444"`),
		"listener outside xnet": set("listen_xnet", `"172.30.0.5:8444"`),
		"no core subnet":        set("core_subnet", `""`),
		"no xnet subnet":        set("xnet_subnet", `""`),
		"xnet host bits":        set("xnet_subnet", `"172.30.2.1/24"`),
		"xnet ipv6":             set("xnet_subnet", `"fd00::/64"`),
		"subnets overlap":       set("core_subnet", `"172.30.0.0/16"`),
		"no edge subnet":        set("edge_subnet", `""`),
		"edge overlaps xnet":    set("edge_subnet", `"172.30.2.0/25"`),
		"spki pin short":        base + "gateway_spki_sha256: \"abcd\"\n",
		"spki pin uppercase":    base + "gateway_spki_sha256: \"" + strings.Repeat("AB", 32) + "\"\n",
	} {
		if _, err := load(t, body); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	pin := strings.Repeat("ab", 32)
	if c, err := load(t, base+"gateway_spki_sha256: \""+pin+"\"\n"); err != nil || c.GatewaySPKI != pin {
		t.Errorf("a valid pin: %v %q", err, c.GatewaySPKI)
	}
}
