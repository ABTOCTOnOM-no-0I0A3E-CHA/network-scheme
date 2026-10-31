package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

/*
TestRegistryBoundary keeps the registry's guarantees from being bypassed by
later code in cmd/executor:
  - only package registry names the registry tables in SQL (everyone else
    reads through registry.View and writes through registry.Write, which
    verify and seal);
  - no package but registry, freeze (its alert) and main holds a database
    pool, so decision code cannot run its own queries;
  - attacktest (superuser tampering) is imported by tests only.
*/
func TestRegistryBoundary(t *testing.T) {
	registrySQL := regexp.MustCompile(`exec\.(registry_counter|write_device|write_grant|change_totp|exec_state|model_profile|write_credential)\b`)
	poolOK := map[string]bool{".": true, "internal/registry": true, "internal/freeze": true}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		src, err := os.ReadFile(path) // #nosec G304 -- walking the package's own sources
		if err != nil {
			return err
		}
		dir := filepath.ToSlash(filepath.Dir(path))
		text := string(src)
		if dir != "internal/registry" && dir != "internal/attacktest" && registrySQL.MatchString(text) {
			t.Errorf("%s: names a registry table; use registry.View / registry.Write", path)
		}
		if !poolOK[dir] && strings.Contains(text, "pgxpool") {
			t.Errorf("%s: holds a database pool; decisions go through the registry", path)
		}
		if dir != "internal/attacktest" && strings.Contains(text, "internal/attacktest") {
			t.Errorf("%s: imports attacktest outside tests", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
