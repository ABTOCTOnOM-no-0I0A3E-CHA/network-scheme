// Package config loads service configuration files and secret files.
package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
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
	if c.DB.Port == 0 {
		c.DB.Port = defaultDBPort
	}
	if err := c.DB.validate(); err != nil {
		return API{}, fmt.Errorf("config %s: %w", path, err)
	}
	return c, nil
}

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
