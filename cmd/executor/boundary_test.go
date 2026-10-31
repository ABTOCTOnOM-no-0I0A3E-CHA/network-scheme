package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	/* A registry table in SQL, also quoted (exec."write_grant", as qname builds it), escaped in a Go string, or in capitals. */
	registrySQL = regexp.MustCompile(`(?i)\bexec\\?"?\s*\.\s*\\?"?(registry_counter|write_device|write_grant|change_totp|exec_state|model_profile|write_credential)\b`)
	/* Any way to a database connection of one's own: a pool, a direct connection, database/sql, store.Open. */
	dbAccess = regexp.MustCompile(`pgxpool|\bpgx\.Connect|\bpgconn\.Connect|"database/sql"|jackc/pgx/v5/stdlib|\bstore\.Open\b`)
)

/* violations lists what the source text of a non-test file in dir (relative to cmd/executor) does against the boundary. */
func violations(dir, text string) []string {
	var out []string
	if dir != "internal/registry" && dir != "internal/attacktest" && registrySQL.MatchString(text) {
		out = append(out, "names a registry table; use registry.View / registry.Write")
	}
	if dir != "." && dir != "internal/registry" && dir != "internal/freeze" && dbAccess.MatchString(text) {
		out = append(out, "opens or holds a database connection; decisions go through the registry")
	}
	if dir != "internal/attacktest" && strings.Contains(text, "internal/attacktest") {
		out = append(out, "imports attacktest outside tests")
	}
	return out
}

/*
TestRegistryBoundary keeps the registry's guarantees from being bypassed by
later code in cmd/executor:
  - only package registry names the registry tables in SQL (everyone else
    reads through registry.View and writes through registry.Write, which
    verify and seal);
  - no package but registry, freeze (its alert) and main holds or opens a
    database connection, so decision code cannot run its own queries;
  - attacktest (superuser tampering) is imported by tests only.
*/
func TestRegistryBoundary(t *testing.T) {
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		src, err := os.ReadFile(path) // #nosec G304 -- walking the package's own sources
		if err != nil {
			return err
		}
		for _, v := range violations(filepath.ToSlash(filepath.Dir(path)), string(src)) {
			t.Errorf("%s: %s", path, v)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

/* The boundary check catches each bypass it is meant to catch (negative fixtures) and lets the registry's API through. */
func TestRegistryBoundaryCatchesBypasses(t *testing.T) {
	for _, src := range []string{
		"q := `SELECT * FROM exec.write_grant`",
		"q := `SELECT * FROM exec.\"write_grant\"`",
		`q := "DELETE FROM exec.\"exec_state\""`,
		`q := "UPDATE \"exec\".\"write_device\" SET port = 23"`,
		`q := "select * from EXEC.Change_Totp"`,
		`q := "SELECT * FROM exec . registry_counter"`,
		`var p *pgxpool.Pool`,
		`c, _ := pgx.Connect(ctx, dsn)`,
		`c, _ := pgx.ConnectConfig(ctx, cfg)`,
		`c, _ := pgconn.Connect(ctx, dsn)`,
		`import "database/sql"`,
		`import _ "github.com/jackc/pgx/v5/stdlib"`,
		`p, _ := store.Open(ctx, cfg, pw)`,
		`import "github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"`,
	} {
		if len(violations("internal/authz", src)) == 0 {
			t.Errorf("not caught: %s", src)
		}
	}
	for _, src := range []string{
		`row, ok := s.Get("write_grant", 1, "write", "core")`,
		`err := g.View(ctx, func(s *registry.Snapshot) error { return nil })`,
		`kind := "executor_tamper"`,
		`if errors.As(err, &pe) {}`,
	} {
		if v := violations("internal/authz", src); len(v) != 0 {
			t.Errorf("false positive %v: %s", v, src)
		}
	}
}
