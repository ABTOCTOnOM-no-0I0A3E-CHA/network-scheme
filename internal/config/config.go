// Package config loads service configuration files and secret files.
package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/beekamai/network-scheme/internal/secret"
)

const defaultDBPort = 5432

// DB describes a PostgreSQL connection. The password lives in PasswordFile only.
type DB struct {
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	Name         string `yaml:"name"`
	User         string `yaml:"user"`
	PasswordFile string `yaml:"password_file"`
}

// API is the configuration of the api service (api.yaml).
type API struct {
	ListenAddr        string         `yaml:"listen_addr"`
	PublicOrigin      string         `yaml:"public_origin"`
	TrustedProxyCIDRs []netip.Prefix `yaml:"trusted_proxy_cidrs"`
	DB                DB             `yaml:"db"`
	DataKeyFile       string         `yaml:"data_key_file"`
	/* ReadKeyVersion is the key_version of the read domain in keys.json; sealed credentials under any other version are refused. */
	ReadKeyVersion int `yaml:"read_key_version"`
}

/*
LoadAPI reads and validates api.yaml. Unknown fields are an error so that a
misspelled (or misplaced secret) key never goes unnoticed.
*/
func LoadAPI(path string) (API, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- path is an operator-supplied config location
	if err != nil {
		return API{}, fmt.Errorf("read config: %w", err)
	}
	var c API
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return API{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	if c.PublicOrigin != "" {
		if c.PublicOrigin, err = NormalizeOrigin(c.PublicOrigin); err != nil {
			return API{}, fmt.Errorf("config %s: public_origin: %w", path, err)
		}
	}
	if c.DB.Port == 0 {
		c.DB.Port = defaultDBPort
	}
	if c.ReadKeyVersion < 0 {
		return API{}, fmt.Errorf("config %s: read_key_version must be positive", path)
	}
	if err := c.DB.validate(); err != nil {
		return API{}, fmt.Errorf("config %s: %w", path, err)
	}
	return c, nil
}

/*
NormalizeOrigin returns the canonical form of an http(s) origin as browsers
send it in the Origin header: lowercase scheme and host, default port
dropped. A path, query, fragment or userinfo is an error.
*/
func NormalizeOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid origin %q", raw)
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "https" && scheme != "http") || u.Hostname() == "" {
		return "", fmt.Errorf("origin %q must be http(s)://host[:port]", raw)
	}
	if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return "", fmt.Errorf("origin %q must not contain a path, query or credentials", raw)
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host, nil
}

// Validate checks that every connection field is set and the port is in range.
func (d DB) Validate() error { return d.validate() }

func (d DB) validate() error {
	switch {
	case d.Host == "":
		return errors.New("db.host is required")
	case d.Name == "":
		return errors.New("db.name is required")
	case d.User == "":
		return errors.New("db.user is required")
	case d.PasswordFile == "":
		return errors.New("db.password_file is required")
	case d.Port < 1 || d.Port > 65535:
		return fmt.Errorf("db.port %d out of range", d.Port)
	}
	return nil
}

/*
ReadSecretFile reads a docker-secret style file. One trailing newline
(LF or CRLF) is trimmed; an empty secret is an error.
*/
func ReadSecretFile(path string) (secret.Secret, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- path comes from trusted configuration
	if err != nil {
		return secret.Secret{}, fmt.Errorf("read secret file: %w", err)
	}
	v := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	if v == "" {
		return secret.Secret{}, fmt.Errorf("secret file %s is empty", path)
	}
	return secret.New(v), nil
}

/*
ReadKeyFile reads a 32-byte key secret (api_data_key, domain and sealing
keys): exactly 32 raw bytes, or the base64 (standard or URL alphabet, padded
or not) encoding of 32 bytes.
*/
func ReadKeyFile(path string) (*[32]byte, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- path comes from trusted configuration
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	key := new([32]byte)
	if len(raw) == len(key) {
		copy(key[:], raw)
		return key, nil
	}
	text := string(bytes.TrimSpace(raw))
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(text); err == nil && len(b) == len(key) {
			copy(key[:], b)
			return key, nil
		}
	}
	return nil, fmt.Errorf("key file %s: want 32 raw bytes or base64 of 32 bytes", path)
}
