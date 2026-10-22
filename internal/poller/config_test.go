package poller

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "poller.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const minimalConfig = `
db: {host: db, name: nms, user: nms_poller, password_file: /run/secrets/db_poller_password}
read_key_file: /run/secrets/read_key
read_pub_key_file: /run/secrets/read_pub_key
`

func TestConfigDefaults(t *testing.T) {
	c, err := LoadConfig(writeConfig(t, minimalConfig))
	if err != nil {
		t.Fatal(err)
	}
	want := Intervals{Availability: 30 * time.Second, Metrics: time.Minute, Inventory: 5 * time.Minute}
	if c.PollerID != "local" || c.Workers != 256 || c.SNMPTimeout != 2*time.Second || c.SNMPRetries == nil || *c.SNMPRetries != 1 ||
		c.DefaultIntervals != want || c.HeavyCPUThreshold != 80 || c.DB.Port != 5432 || c.DB.MaxConns != 64 {
		t.Fatalf("defaults = %+v", c)
	}
}

/* db.max_conns defaults to workers/4 + 8, at most 64, so the workers, River and the heartbeat share a pool sized to them. */
func TestConfigDBMaxConns(t *testing.T) {
	for _, tc := range []struct {
		extra string
		want  int
	}{
		{"workers: 16\n", 12},
		{"workers: 1\n", 8},
		{"workers: 10000\n", 64},
	} {
		c, err := LoadConfig(writeConfig(t, minimalConfig+tc.extra))
		if err != nil {
			t.Fatal(err)
		}
		if c.DB.MaxConns != tc.want {
			t.Errorf("%q: db.max_conns = %d, want %d", tc.extra, c.DB.MaxConns, tc.want)
		}
	}
	dbLine := "password_file: /run/secrets/db_poller_password}"
	c, err := LoadConfig(writeConfig(t, strings.ReplaceAll(minimalConfig, dbLine, dbLine[:len(dbLine)-1]+", max_conns: 20}")))
	if err != nil {
		t.Fatal(err)
	}
	if c.DB.MaxConns != 20 {
		t.Errorf("explicit db.max_conns = %d, want 20", c.DB.MaxConns)
	}
}

func TestConfigOverrides(t *testing.T) {
	c, err := LoadConfig(writeConfig(t, minimalConfig+`
poller_id: site-2
workers: 16
snmp_timeout: 500ms
snmp_retries: 0
default_intervals: {availability: 10s, metrics: 2m, inventory: 15m}
heavy_cpu_threshold: 90
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.PollerID != "site-2" || c.Workers != 16 || c.SNMPTimeout != 500*time.Millisecond || *c.SNMPRetries != 0 ||
		c.DefaultIntervals.Metrics != 2*time.Minute || c.DefaultIntervals.Availability != 10*time.Second ||
		c.DefaultIntervals.Inventory != 15*time.Minute || c.HeavyCPUThreshold != 90 {
		t.Fatalf("overrides = %+v", c)
	}
	/* snmp_retries 0 means no retries, which snmp.Options spells as a negative value. */
	if o := c.snmpOptions(); o.Retries >= 0 || o.Timeout != 500*time.Millisecond || o.ContextName != "" {
		t.Fatalf("snmp options = %+v", o)
	}
}

func TestConfigRejects(t *testing.T) {
	for name, extra := range map[string]string{
		"unknown field":     "comunity: public\n",
		"bad poller id":     "poller_id: 'Site 1'\n",
		"negative workers":  "workers: -1\n",
		"negative retry":    "snmp_retries: -1\n",
		"tiny timeout":      "snmp_timeout: 1ms\n",
		"negative interval": "default_intervals: {availability: -5s}\n",
		"cpu over 100":      "heavy_cpu_threshold: 101\n",
		"bad duration":      "snmp_timeout: soon\n",
		"interval typo":     "default_intervals: {availabilty: 30s}\n",
	} {
		if _, err := LoadConfig(writeConfig(t, minimalConfig+extra)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	/* The db block is replaced, not repeated: a duplicate key would fail for the wrong reason. */
	dbLine := "db: {host: db, name: nms, user: nms_poller, password_file: /run/secrets/db_poller_password}"
	for name, db := range map[string]string{
		"secret inline":   "db: {host: db, name: nms, user: u, password: x}",
		"missing db host": "db: {name: nms, user: u, password_file: /x}",
		"negative conns":  "db: {host: db, name: nms, user: u, password_file: /x, max_conns: -1}",
		"too many conns":  "db: {host: db, name: nms, user: u, password_file: /x, max_conns: 1001}",
	} {
		if _, err := LoadConfig(writeConfig(t, strings.ReplaceAll(minimalConfig, dbLine, db))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	noKeys := strings.ReplaceAll(minimalConfig, "read_key_file: /run/secrets/read_key\n", "")
	if _, err := LoadConfig(writeConfig(t, noKeys)); err == nil {
		t.Error("missing read_key_file accepted")
	}
}
