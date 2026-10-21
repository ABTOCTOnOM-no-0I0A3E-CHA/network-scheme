package poller

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/curve25519"
	"gopkg.in/yaml.v3"

	"github.com/beekamai/network-scheme/internal/config"
	"github.com/beekamai/network-scheme/internal/jobs"
	"github.com/beekamai/network-scheme/internal/snmp"
)

/* Defaults and bounds of poller.yaml. */
const (
	defaultPollerID     = "local"
	defaultWorkers      = 256
	defaultSNMPTimeout  = 2 * time.Second
	defaultSNMPRetries  = 1
	defaultHeavyCPU     = 80
	defaultDBPort       = 5432
	maxWorkers          = 10_000
	maxDefaultDBConns   = 64
	minSNMPTimeout      = 100 * time.Millisecond
	maxSNMPTimeout      = 30 * time.Second
	maxSNMPRetries      = 5
	minIntervalDuration = time.Second
	maxIntervalDuration = 24 * time.Hour
)

// Intervals are the polling intervals per class.
type Intervals struct {
	Availability time.Duration `yaml:"availability"`
	Metrics      time.Duration `yaml:"metrics"`
	Inventory    time.Duration `yaml:"inventory"`
}

/*
Config is poller.yaml. Secrets are never inline: the database password and
the read-domain key pair are files named here.
*/
type Config struct {
	PollerID       string        `yaml:"poller_id"`
	DB             config.DB     `yaml:"db"`
	ReadKeyFile    string        `yaml:"read_key_file"`
	ReadPubKeyFile string        `yaml:"read_pub_key_file"`
	Workers        int           `yaml:"workers"`
	SNMPTimeout    time.Duration `yaml:"snmp_timeout"`
	/* SNMPRetries is a pointer so that an explicit 0 (no retries) differs from "not set". */
	SNMPRetries       *int      `yaml:"snmp_retries"`
	DefaultIntervals  Intervals `yaml:"default_intervals"`
	HeavyCPUThreshold float64   `yaml:"heavy_cpu_threshold"`
}

/*
LoadConfig reads and validates poller.yaml. Unknown fields are an error so
that a misspelled key (or a secret pasted inline) never goes unnoticed.
*/
func LoadConfig(path string) (Config, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- path is an operator-supplied config location
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	return c, nil
}

func (c *Config) applyDefaults() {
	if c.PollerID == "" {
		c.PollerID = defaultPollerID
	}
	if c.DB.Port == 0 {
		c.DB.Port = defaultDBPort
	}
	if c.Workers == 0 {
		c.Workers = defaultWorkers
	}
	if c.DB.MaxConns == 0 && c.Workers > 0 {
		/* Every run writes to the database; River and the heartbeat share the pool. */
		c.DB.MaxConns = min(c.Workers/4+8, maxDefaultDBConns)
	}
	if c.SNMPTimeout == 0 {
		c.SNMPTimeout = defaultSNMPTimeout
	}
	if c.SNMPRetries == nil {
		r := defaultSNMPRetries
		c.SNMPRetries = &r
	}
	iv := &c.DefaultIntervals
	if iv.Availability == 0 {
		iv.Availability = 30 * time.Second
	}
	if iv.Metrics == 0 {
		iv.Metrics = time.Minute
	}
	if iv.Inventory == 0 {
		iv.Inventory = 5 * time.Minute
	}
	if c.HeavyCPUThreshold == 0 {
		c.HeavyCPUThreshold = defaultHeavyCPU
	}
}

func (c Config) validate() error {
	switch {
	case !jobs.ValidPollerID(c.PollerID):
		return fmt.Errorf("poller_id %q: lowercase letters, digits, '-' and '_' only", c.PollerID)
	case c.ReadKeyFile == "" || c.ReadPubKeyFile == "":
		return errors.New("read_key_file and read_pub_key_file are required")
	case c.Workers < 1 || c.Workers > maxWorkers:
		return fmt.Errorf("workers must be 1..%d", maxWorkers)
	case c.SNMPTimeout < minSNMPTimeout || c.SNMPTimeout > maxSNMPTimeout:
		return fmt.Errorf("snmp_timeout must be %v..%v", minSNMPTimeout, maxSNMPTimeout)
	case *c.SNMPRetries < 0 || *c.SNMPRetries > maxSNMPRetries:
		return fmt.Errorf("snmp_retries must be 0..%d", maxSNMPRetries)
	case c.HeavyCPUThreshold <= 0 || c.HeavyCPUThreshold > 100:
		return errors.New("heavy_cpu_threshold must be in (0, 100]")
	}
	for name, d := range map[string]time.Duration{
		"availability": c.DefaultIntervals.Availability, "metrics": c.DefaultIntervals.Metrics, "inventory": c.DefaultIntervals.Inventory,
	} {
		if d < minIntervalDuration || d > maxIntervalDuration {
			return fmt.Errorf("default_intervals.%s must be %v..%v", name, minIntervalDuration, maxIntervalDuration)
		}
	}
	return c.DB.Validate()
}

/* snmpOptions are the session options of every device; ContextName stays empty for real devices. */
func (c Config) snmpOptions() snmp.Options {
	retries := *c.SNMPRetries
	if retries == 0 {
		retries = -1 /* snmp.Options: 0 selects the default, negative means none */
	}
	return snmp.Options{Timeout: c.SNMPTimeout, Retries: retries}
}

/*
ReadKeys reads the read-domain key pair and checks that the public key
belongs to the private key, so a mixed-up file fails at start, not as
"undecryptable" on every credential.
*/
func (c Config) ReadKeys() (priv, pub *[32]byte, err error) {
	if priv, err = config.ReadKeyFile(c.ReadKeyFile); err != nil {
		return nil, nil, err
	}
	if pub, err = config.ReadKeyFile(c.ReadPubKeyFile); err != nil {
		return nil, nil, err
	}
	derived, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil || subtle.ConstantTimeCompare(derived, pub[:]) != 1 {
		return nil, nil, errors.New("read_pub_key_file does not belong to read_key_file")
	}
	return priv, pub, nil
}
