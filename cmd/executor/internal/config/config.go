/*
Package config loads executor.yaml: the database, the key files, the xnet
listener, both origins and the host-owned files the executor reads. Unknown
fields are an error, so a misspelled or misplaced key never goes unnoticed.
*/
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	nmsconfig "github.com/beekamai/network-scheme/internal/config"
)

/* Defaults of the database connection. */
const (
	defaultDBPort   = 5432
	defaultMaxConns = 8
)

// Config is the configuration of the executor (executor.yaml). Every file is a path; no value is a secret.
type Config struct {
	DB nmsconfig.DB `yaml:"db"`
	/* Docker secrets: the sealing key (TOTP secrets, row MACs, state file MAC), the write and backup domain keys. */
	SealingKeyFile string `yaml:"sealing_key_file"`
	WriteKeyFile   string `yaml:"write_key_file"`
	BackupKeyFile  string `yaml:"backup_key_file"`
	/* TicketPubKeyFile is the Ed25519 public key that verifies the api's session tickets. */
	TicketPubKeyFile string `yaml:"ticket_pub_key_file"`
	/* The xnet server certificate and the CA its only client (the gateway) must chain to. */
	TLSCertFile  string `yaml:"tls_cert_file"`
	TLSKeyFile   string `yaml:"tls_key_file"`
	ClientCAFile string `yaml:"client_ca_file"`
	/* GatewaySPKI, optional: hex SHA-256 of the gateway client certificate's public key (SubjectPublicKeyInfo); any other key is refused. */
	GatewaySPKI string `yaml:"gateway_spki_sha256"`
	/* ListenXnet is the executor's own address in xnet: a specific IPv4 address, never a wildcard. */
	ListenXnet netip.AddrPort `yaml:"listen_xnet"`
	/*
		CoreSubnet, XnetSubnet and EdgeSubnet are the stack's own networks (the devices subnet is in
		egress.yaml): no device address may fall into them. ListenXnet lies in XnetSubnet.
	*/
	CoreSubnet netip.Prefix `yaml:"core_subnet"`
	XnetSubnet netip.Prefix `yaml:"xnet_subnet"`
	EdgeSubnet netip.Prefix `yaml:"edge_subnet"`
	/* PanelOrigin may frame the executor UI; ExecutorOrigin is the only Origin the executor accepts. */
	PanelOrigin    string `yaml:"panel_origin"`
	ExecutorOrigin string `yaml:"executor_origin"`
	StateDir       string `yaml:"state_dir"`   /* the executor's own volume: state file */
	PolicyFile     string `yaml:"policy_file"` /* host-owned, read-only */
	EgressFile     string `yaml:"egress_file"` /* management subnets, read-only */
}

// Load reads and validates executor.yaml.
func Load(path string) (Config, error) {
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
	if c.DB.Port == 0 {
		c.DB.Port = defaultDBPort
	}
	if c.DB.MaxConns == 0 {
		c.DB.MaxConns = defaultMaxConns
	}
	if err := c.validate(); err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	return c, nil
}

func (c *Config) validate() error {
	if err := c.DB.Validate(); err != nil {
		return err
	}
	for _, f := range []struct{ name, v string }{
		{"db.password_file", c.DB.PasswordFile}, {"sealing_key_file", c.SealingKeyFile}, {"write_key_file", c.WriteKeyFile}, {"backup_key_file", c.BackupKeyFile},
		{"ticket_pub_key_file", c.TicketPubKeyFile}, {"tls_cert_file", c.TLSCertFile}, {"tls_key_file", c.TLSKeyFile},
		{"client_ca_file", c.ClientCAFile}, {"state_dir", c.StateDir}, {"policy_file", c.PolicyFile}, {"egress_file", c.EgressFile},
	} {
		if f.v == "" {
			return fmt.Errorf("%s is required", f.name)
		}
		/* Container paths; filepath also accepts a native absolute path (tests on Windows). */
		if (!path.IsAbs(f.v) && !filepath.IsAbs(f.v)) || slices.Contains(strings.Split(filepath.ToSlash(f.v), "/"), "..") {
			return fmt.Errorf("%s %q must be an absolute path without a .. element", f.name, f.v)
		}
	}
	for _, s := range []struct {
		name string
		p    netip.Prefix
	}{{"core_subnet", c.CoreSubnet}, {"xnet_subnet", c.XnetSubnet}, {"edge_subnet", c.EdgeSubnet}} {
		if !s.p.IsValid() || !s.p.Addr().Is4() || s.p != s.p.Masked() {
			return fmt.Errorf("%s is required as an IPv4 network address with prefix", s.name)
		}
	}
	if c.CoreSubnet.Overlaps(c.XnetSubnet) || c.EdgeSubnet.Overlaps(c.CoreSubnet) || c.EdgeSubnet.Overlaps(c.XnetSubnet) {
		return errors.New("core_subnet, xnet_subnet and edge_subnet overlap")
	}
	a := c.ListenXnet.Addr()
	switch {
	case !c.ListenXnet.IsValid() || c.ListenXnet.Port() == 0:
		return errors.New("listen_xnet is required as ipv4:port")
	case !a.Is4() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return fmt.Errorf("listen_xnet %s: must be the executor's own IPv4 address in xnet, not a wildcard", c.ListenXnet)
	case !c.XnetSubnet.Contains(a) || a == c.XnetSubnet.Addr() || a == lastAddr(c.XnetSubnet):
		return fmt.Errorf("listen_xnet %s: must be a host address in xnet_subnet %s", c.ListenXnet, c.XnetSubnet)
	}
	if c.GatewaySPKI != "" && !spkiRe.MatchString(c.GatewaySPKI) {
		return errors.New("gateway_spki_sha256 must be 64 lowercase hex digits")
	}
	var err error
	if c.PanelOrigin, err = httpsOrigin("panel_origin", c.PanelOrigin); err != nil {
		return err
	}
	if c.ExecutorOrigin, err = httpsOrigin("executor_origin", c.ExecutorOrigin); err != nil {
		return err
	}
	if c.PanelOrigin == c.ExecutorOrigin {
		return errors.New("executor_origin must differ from panel_origin: the executor is a separate origin")
	}
	return nil
}

var spkiRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

/* lastAddr is the broadcast address of an IPv4 prefix. */
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	for i := p.Bits(); i < 32; i++ {
		a[i/8] |= 0x80 >> (i % 8)
	}
	return netip.AddrFrom4(a)
}

/* httpsOrigin normalizes an https origin; a port must be canonical decimal in 1..65535. */
func httpsOrigin(name, raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	o, err := nmsconfig.NormalizeOrigin(raw)
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	if !strings.HasPrefix(o, "https://") {
		return "", fmt.Errorf("%s %q must be https", name, raw)
	}
	u, err := url.Parse(o)
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p {
			return "", fmt.Errorf("%s %q: port must be 1..65535", name, raw)
		}
	}
	return o, nil
}
