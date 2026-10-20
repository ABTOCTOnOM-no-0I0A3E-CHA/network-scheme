package store

import (
	"testing"

	"github.com/beekamai/network-scheme/internal/config"
	"github.com/beekamai/network-scheme/internal/secret"
)

func TestPoolConfigTreatsValuesVerbatim(t *testing.T) {
	hostile := "a' host=evil sslmode=disable"
	cfg, err := poolConfig(config.DB{Host: "db.internal", Port: 5432, Name: hostile, User: hostile},
		secret.New(hostile))
	if err != nil {
		t.Fatal(err)
	}
	cc := cfg.ConnConfig
	if cc.User != hostile || cc.Database != hostile || cc.Password != hostile {
		t.Errorf("values not verbatim: %q %q %q", cc.User, cc.Database, cc.Password)
	}
	if cc.Host != "db.internal" || cc.Port != 5432 {
		t.Errorf("host/port changed: %s:%d", cc.Host, cc.Port)
	}
	if cc.TLSConfig == nil {
		t.Error("sslmode was changed (TLS config missing)")
	}
	for _, fb := range cc.Fallbacks {
		if fb.Host != "db.internal" {
			t.Errorf("fallback host = %q", fb.Host)
		}
	}
}
