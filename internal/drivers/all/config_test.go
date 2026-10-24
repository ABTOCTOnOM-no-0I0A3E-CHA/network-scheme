package all

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/secret"
	"github.com/beekamai/network-scheme/internal/ssh"
	"github.com/beekamai/network-scheme/internal/testdb"
	"github.com/beekamai/network-scheme/test/sim/sshemu"
)

func TestMain(m *testing.M) { testdb.Main(m) }

const (
	password = "read-only-secret-pw"
	runCfg   = "show running-config"
)

var cred = creds.Credential{Kind: creds.KindSSHRead, Username: "mon", Password: secret.New(password)}

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("../../../test/fixtures/configs", name+"-secrets.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

func byName(t *testing.T, name string) drivers.Driver {
	t.Helper()
	d := drivers.Default().ByName(name)
	if d == nil {
		t.Fatalf("no driver %s", name)
	}
	return d
}

func newDevice(t *testing.T, env *testdb.Env) int64 {
	t.Helper()
	p := env.Pool("postgres")
	var gid, id int64
	if err := p.QueryRow(context.Background(), `INSERT INTO core.device_group (name) VALUES ('g-' || gen_random_uuid()) RETURNING id`).Scan(&gid); err != nil {
		t.Fatal(err)
	}
	if err := p.QueryRow(context.Background(), `INSERT INTO core.device (name, address, group_id)
		VALUES ('d', '10.0.0.0'::inet + $1, $1) RETURNING id`, gid).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

/* dial connects a real ssh.Runner with the driver's own dialect to an emulator answering responses. */
func dial(t *testing.T, env *testdb.Env, d drivers.Driver, responses map[string]string) (*ssh.Runner, *sshemu.Log) {
	t.Helper()
	responses["terminal datadump"] = ""
	addr, log := sshemu.Start(t, sshemu.Config{HostKey: sshemu.NewHostKey(t), Prompt: "sw1#", Responses: responses, Username: "mon", Password: password})
	r, err := ssh.Dial(context.Background(), addr, newDevice(t, env), cred, ssh.NewHostKeys(env.Pool("nms_poller")), d.Dialect())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, log
}

func TestFetchConfigOnlyAllowlistedCommand(t *testing.T) {
	env := testdb.New(t)
	for _, name := range []string{"eltex-mes", "eltex-esr"} {
		t.Run(name, func(t *testing.T) {
			d := byName(t, name)
			cfg := fixture(t, strings.TrimPrefix(name, "eltex-"))
			r, log := dial(t, env, d, map[string]string{runCfg: strings.TrimSuffix(cfg, "\n")})
			got, err := d.FetchConfig(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			if d.NormalizeConfig(got) != d.NormalizeConfig(cfg) {
				t.Error("fetched config differs from the device output")
			}
			if want := []string{"terminal datadump", runCfg}; !slices.Equal(log.Commands(), want) {
				t.Fatalf("device saw %q, want %q", log.Commands(), want)
			}
			/* A command that is not in the allowlist never reaches the device. */
			if _, err := r.Run(context.Background(), ssh.ShowCommand{Name: "show startup-config"}); !errors.Is(err, ssh.ErrNotAllowed) {
				t.Errorf("startup-config: %v", err)
			}
			if len(log.Commands()) != 2 {
				t.Fatalf("device saw %q", log.Commands())
			}
		})
	}
}

func TestFetchConfigAborts(t *testing.T) {
	env := testdb.New(t)
	d := byName(t, "eltex-mes")
	cases := map[string]struct {
		out  string
		want error
	}{
		"prompt mid-output": {"hostname sw1\nsw1#\ninterface gi1/0/1\n exit", drivers.ErrConfigGarbage},
		"config prompt":     {"hostname sw1\nsw1(config)#\nexit", drivers.ErrConfigGarbage},
		"binary garbage":    {"hostname sw1\n\x00\x01\x02\xff\xfe\n exit", drivers.ErrConfigGarbage},
		"oversize":          {strings.Repeat("interface gi1/0/1 description x\n", 5<<15), drivers.ErrConfigTooLarge},
		"device error":      {"% Invalid input detected", drivers.ErrConfigRejected},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r, log := dial(t, env, d, map[string]string{runCfg: c.out})
			got, err := d.FetchConfig(context.Background(), r)
			if !errors.Is(err, c.want) || got != "" {
				t.Fatalf("got %d bytes, %v; want %v", len(got), err, c.want)
			}
			if !slices.Equal(log.Commands(), []string{"terminal datadump", runCfg}) {
				t.Fatalf("device saw %q", log.Commands())
			}
		})
	}
}

func TestGenericFetchNotSupported(t *testing.T) {
	d := byName(t, drivers.GenericName)
	if _, err := d.FetchConfig(context.Background(), nil); !errors.Is(err, drivers.ErrNotSupported) {
		t.Fatalf("got %v", err)
	}
	if d.ConfigNeedsWrite() || len(d.ShowCommands()) != 0 {
		t.Fatal("generic driver offers config or show commands")
	}
}

/* Two fetches differing only in volatile lines normalise to one hash. */
func TestNormalizedHashStable(t *testing.T) {
	for _, name := range []string{"mes", "esr"} {
		d := byName(t, "eltex-"+name)
		a := fixture(t, name)
		b := strings.NewReplacer("10:21:33", "23:59:59", "2026-10-20", "2026-11-01", "12 days 03:11:09", "13 days 03:11:09", "Mon Oct 20", "Tue Oct 21", "4821", "4900").Replace(a)
		if a == b {
			t.Fatalf("%s: replacement changed nothing", name)
		}
		ha, hb := sha256.Sum256([]byte(d.NormalizeConfig(a))), sha256.Sum256([]byte(d.NormalizeConfig(b)))
		if ha != hb {
			t.Errorf("%s: hash differs for volatile-only changes", name)
		}
		c := strings.Replace(a, "vlan 10", "vlan 11", 1)
		if sha256.Sum256([]byte(d.NormalizeConfig(c))) == ha {
			t.Errorf("%s: real change not detected", name)
		}
		norm := d.NormalizeConfig(a)
		if strings.Contains(norm, "Last configuration change") || strings.Contains(norm, "Uptime") || strings.Contains(norm, "Last change") {
			t.Errorf("%s: volatile lines remain", name)
		}
		if d.NormalizeConfig(norm) != norm || d.MaskSecrets(d.MaskSecrets(norm)) != d.MaskSecrets(norm) {
			t.Errorf("%s: not idempotent", name)
		}
	}
}

func TestConfigSections(t *testing.T) {
	for _, name := range []string{"mes", "esr"} {
		d := byName(t, "eltex-"+name)
		masked := d.MaskSecrets(d.NormalizeConfig(fixture(t, name)))
		got := map[string]int{}
		for _, s := range d.ConfigSections(masked) {
			got[s.Name] += len(s.Lines)
		}
		for _, k := range []string{drivers.SectionGeneral, drivers.SectionInterfaces, drivers.SectionVLAN, drivers.SectionRouting, drivers.SectionSNMP, drivers.SectionSyslog, drivers.SectionAAA} {
			if got[k] == 0 {
				t.Errorf("%s: section %s is empty (%v)", name, k, got)
			}
		}
	}
}

/* Every show command resolves to an allowlisted command; none dumps a configuration. */
func TestShowCommandsAllowlistedAndNoConfigDump(t *testing.T) {
	for _, name := range []string{"eltex-mes", "eltex-esr"} {
		d := byName(t, name)
		specs := d.ShowCommands()
		if len(specs) == 0 {
			t.Fatalf("%s: no show commands", name)
		}
		for _, s := range specs {
			args := make([]string, len(s.Args))
			for i, k := range s.Args {
				args[i] = map[string]string{"interface": "gi1/0/1", "vlan": "100"}[string(k)]
			}
			c, err := d.ShowCommand(s.Key, args)
			if err != nil {
				t.Fatalf("%s %s: %v", name, s.Key, err)
			}
			if strings.Contains(c.Name, "config") {
				t.Errorf("%s: show command %q exposes configuration", name, c.Name)
			}
			ok := false
			for _, a := range d.Dialect().Allowlist {
				ok = ok || a.Name == c.Name && len(a.Args) == len(c.Args)
			}
			if !ok {
				t.Errorf("%s: %q not in allowlist", name, c.Name)
			}
		}
		if _, err := d.ShowCommand("running_config", nil); !errors.Is(err, drivers.ErrUnknownShow) {
			t.Errorf("%s: running_config key resolved: %v", name, err)
		}
		if _, err := d.ShowCommand("interface_status", []string{"gi1; reload"}); !errors.Is(err, drivers.ErrUnknownShow) {
			t.Errorf("%s: injection accepted: %v", name, err)
		}
		if d.ConfigNeedsWrite() {
			t.Errorf("%s: ConfigNeedsWrite", name)
		}
		if v, ok := d.(interface{ Verified() bool }); !ok || v.Verified() {
			t.Errorf("%s must be unverified", name)
		}
	}
}
