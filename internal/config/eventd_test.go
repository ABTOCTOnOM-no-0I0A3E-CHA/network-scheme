package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/config"
)

const eventdBase = `
db: {host: postgres, name: nms, user: nms_eventd, password_file: /run/secrets/db_eventd_password}
read_key_file: /run/secrets/domain_read_key
read_pub_key_file: /etc/nms/domain_read.pub
`

func TestLoadEventDDefaults(t *testing.T) {
	c, err := config.LoadEventD(write(t, "eventd.yaml", eventdBase))
	if err != nil {
		t.Fatal(err)
	}
	if c.SyslogUDP != "0.0.0.0:514" || c.SyslogTCP != "0.0.0.0:514" || c.SyslogTLS != "0.0.0.0:6514" || c.TrapUDP != "0.0.0.0:162" {
		t.Errorf("listeners = %q %q %q %q", c.SyslogUDP, c.SyslogTCP, c.SyslogTLS, c.TrapUDP)
	}
	if c.QueueSize != 10_000 || c.BatchSize != 1000 || c.BatchInterval != time.Second || c.RatePerSource != 200 || c.RateBurst != 400 ||
		c.MaxTCPConns != 256 || c.TCPIdle != 5*time.Minute || c.DB.Port != 5432 {
		t.Errorf("defaults = %+v", c)
	}
}

func TestLoadEventDRejects(t *testing.T) {
	for name, extra := range map[string]string{
		"unknown field":      "bogus: 1\n",
		"inline password":    "db_password: secret\n",
		"cert without key":   "tls_cert_file: /c.pem\n",
		"bad listener":       "trap_udp: nonsense\n",
		"huge queue":         "queue_size: 999999999\n",
		"retention too long": "retention_days: 100000\n",
		"idle too short":     "tcp_idle_timeout: 1ms\n",
	} {
		if _, err := config.LoadEventD(write(t, "eventd.yaml", eventdBase+extra)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := config.LoadEventD(write(t, "eventd.yaml", strings.Replace(eventdBase, "read_key_file: /run/secrets/domain_read_key\n", "", 1))); err == nil {
		t.Error("missing read_key_file accepted")
	}
	c, err := config.LoadEventD(write(t, "eventd.yaml", eventdBase+"syslog_tls: off\ntls_cert_file: /c.pem\ntls_key_file: /k.pem\n"))
	if err != nil || c.SyslogTLS != config.Off {
		t.Errorf("valid config: %v %+v", err, c)
	}
}
