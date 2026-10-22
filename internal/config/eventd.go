package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

/* Defaults and bounds of eventd.yaml. */
const (
	DefaultSyslogUDP  = "0.0.0.0:514"
	DefaultSyslogTCP  = "0.0.0.0:514"
	DefaultSyslogTLS  = "0.0.0.0:6514"
	DefaultTrapUDP    = "0.0.0.0:162"
	defaultQueueSize  = 10_000
	defaultBatchSize  = 1_000
	defaultBatchEvery = time.Second
	defaultRate       = 200
	defaultBurst      = 400
	defaultMaxConns   = 256
	defaultIdle       = 5 * time.Minute
	defaultEventdDB   = 8
	maxQueueSize      = 1_000_000
	maxBatchSize      = 10_000
)

/* Off disables a listener: the address of every listener is either host:port or "off". */
const Off = "off"

/*
EventD is eventd.yaml. Secrets are never inline: the database password and the
read-domain key pair are files named here. A listener address is host:port, or
"off" to disable it; an empty value selects the default (in LoadEventD only).
The TLS listener stays disabled while tls_cert_file / tls_key_file are unset.
*/
type EventD struct {
	/* Instance names this process in events.eventd_stats; empty selects the host name. */
	Instance       string `yaml:"instance"`
	DB             DB     `yaml:"db"`
	ReadKeyFile    string `yaml:"read_key_file"`
	ReadPubKeyFile string `yaml:"read_pub_key_file"`

	SyslogUDP   string `yaml:"syslog_udp"`
	SyslogTCP   string `yaml:"syslog_tcp"`
	SyslogTLS   string `yaml:"syslog_tls"`
	TrapUDP     string `yaml:"trap_udp"`
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`

	QueueSize     int           `yaml:"queue_size"`
	BatchSize     int           `yaml:"batch_size"`
	BatchInterval time.Duration `yaml:"batch_interval"`
	/* RatePerSource is events per second per source; RateBurst is the bucket size. */
	RatePerSource int           `yaml:"rate_per_source"`
	RateBurst     int           `yaml:"rate_burst"`
	MaxTCPConns   int           `yaml:"max_tcp_conns"`
	TCPIdle       time.Duration `yaml:"tcp_idle_timeout"`
}

/*
LoadEventD reads and validates eventd.yaml. Unknown fields are an error so that
a misspelled key (or a secret pasted inline) never goes unnoticed.
*/
func LoadEventD(path string) (EventD, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- path is an operator-supplied config location
	if err != nil {
		return EventD{}, fmt.Errorf("read config: %w", err)
	}
	var c EventD
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return EventD{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	c.ApplyDefaults()
	if err := c.Validate(); err != nil {
		return EventD{}, fmt.Errorf("config %s: %w", path, err)
	}
	return c, nil
}

// ApplyDefaults fills every unset field.
func (c *EventD) ApplyDefaults() {
	if c.DB.Port == 0 {
		c.DB.Port = defaultDBPort
	}
	if c.DB.MaxConns == 0 {
		c.DB.MaxConns = defaultEventdDB
	}
	for p, def := range map[*string]string{
		&c.SyslogUDP: DefaultSyslogUDP, &c.SyslogTCP: DefaultSyslogTCP, &c.SyslogTLS: DefaultSyslogTLS, &c.TrapUDP: DefaultTrapUDP,
	} {
		if *p == "" {
			*p = def
		}
	}
	for p, def := range map[*int]int{
		&c.QueueSize: defaultQueueSize, &c.BatchSize: defaultBatchSize, &c.RatePerSource: defaultRate,
		&c.RateBurst: defaultBurst, &c.MaxTCPConns: defaultMaxConns,
	} {
		if *p == 0 {
			*p = def
		}
	}
	if c.BatchInterval == 0 {
		c.BatchInterval = defaultBatchEvery
	}
	if c.TCPIdle == 0 {
		c.TCPIdle = defaultIdle
	}
}

// Validate checks the fields; ApplyDefaults must have run.
func (c EventD) Validate() error {
	switch {
	case c.ReadKeyFile == "" || c.ReadPubKeyFile == "":
		return errors.New("read_key_file and read_pub_key_file are required")
	case (c.TLSCertFile == "") != (c.TLSKeyFile == ""):
		return errors.New("tls_cert_file and tls_key_file go together")
	case c.QueueSize < 1 || c.QueueSize > maxQueueSize:
		return fmt.Errorf("queue_size must be 1..%d", maxQueueSize)
	case c.BatchSize < 1 || c.BatchSize > maxBatchSize:
		return fmt.Errorf("batch_size must be 1..%d", maxBatchSize)
	case c.BatchInterval < 10*time.Millisecond || c.BatchInterval > time.Minute:
		return errors.New("batch_interval must be 10ms..1m")
	case c.RatePerSource < 1 || c.RateBurst < 1:
		return errors.New("rate_per_source and rate_burst must be positive")
	case c.MaxTCPConns < 1 || c.MaxTCPConns > 65535:
		return errors.New("max_tcp_conns must be 1..65535")
	case c.TCPIdle < time.Second:
		return errors.New("tcp_idle_timeout must be at least 1s")
	case len(c.Instance) > 200:
		return errors.New("instance is too long")
	}
	for name, a := range map[string]string{"syslog_udp": c.SyslogUDP, "syslog_tcp": c.SyslogTCP, "syslog_tls": c.SyslogTLS, "trap_udp": c.TrapUDP} {
		if a != "" && a != Off && !strings.Contains(a, ":") {
			return fmt.Errorf("%s %q must be host:port or %q", name, a, Off)
		}
	}
	return c.DB.Validate()
}
