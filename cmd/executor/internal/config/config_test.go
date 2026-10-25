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
	} {
		if _, err := load(t, body); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
