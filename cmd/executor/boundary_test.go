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
	/* Any table of schema exec (execpub is another schema). */
	execSQL = regexp.MustCompile(`(?i)\bexec\\?"?\s*\.`)
	/* The exec names a change session may write: its own append-only rows (each with its own MAC). */
	execTable     = regexp.MustCompile(`(?i)\bexec\\?"?\s*\.\s*\\?"?([a-z_]+)`)
	sessionTables = map[string]bool{"session": true, "session_device": true, "session_event": true, "session_event_id_seq": true}
	/* The exec names the recordings may use: their own append-only rows, and the session rows they belong to (read). */
	recordingTables = map[string]bool{"recording_chunk": true, "recording_manifest": true, "session": true, "session_device": true}
)

/* violations lists what the source text of a non-test file in dir (relative to cmd/executor) does against the boundary. */
func violations(dir, text string) []string {
	var out []string
	if dir != "internal/registry" && dir != "internal/attacktest" && registrySQL.MatchString(text) {
		out = append(out, "names a registry table; use registry.View / registry.Write")
	}
	if dir != "." && dir != "internal/registry" && dir != "internal/freeze" && dir != "internal/pub" && dir != "internal/backups" &&
		dir != "internal/session" && dir != "internal/recording" && dir != "internal/unmask" && dbAccess.MatchString(text) {
		out = append(out, "opens or holds a database connection; decisions go through the registry")
	}
	if dir == "internal/pub" && execSQL.MatchString(text) {
		out = append(out, "names schema exec; pub writes execpub only (the audit row goes through package audit)")
	}
	if dir == "internal/session" {
		for _, m := range execTable.FindAllStringSubmatch(text, -1) {
			if !sessionTables[strings.ToLower(m[1])] {
				out = append(out, "names exec."+m[1]+"; a session writes only its own append-only rows (exec.session*)")
			}
		}
	}
	if dir == "internal/recording" {
		for _, m := range execTable.FindAllStringSubmatch(text, -1) {
			if !recordingTables[strings.ToLower(m[1])] {
				out = append(out, "names exec."+m[1]+"; recordings use only their own rows (exec.recording_*) and read their session's")
			}
		}
	}
	if dir == "internal/backups" && execSQL.MatchString(text) {
		out = append(out, "names schema exec; backups reads its devices through the registry only")
	}
	if dir == "internal/unmask" && execSQL.MatchString(text) {
		out = append(out, "names schema exec; unmask reads configuration versions only, its devices through the registry")
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
  - no package but registry, freeze (its alert), pub (schema execpub only),
    backups (its configuration versions, backup_state and
    execpub.backup_taken; never schema exec), session (its own append-only
    rows exec.session, session_device and session_event only), recording
    (its own append-only rows exec.recording_chunk and recording_manifest,
    reading the session's), unmask (backups.config_version, read; never
    schema exec) and main holds or opens a database connection,
    so decision code cannot run its own queries;
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
	for _, src := range []string{"q := `SELECT * FROM exec.session`", `q := "INSERT INTO exec.\"audit_event\""`, "q := `UPDATE EXEC . audit_head`"} {
		if len(violations("internal/pub", src)) == 0 {
			t.Errorf("pub: not caught: %s", src)
		}
	}
	if v := violations("internal/pub", "var p *pgxpool.Pool; q := `DELETE FROM execpub.freeze_request`"); len(v) != 0 {
		t.Errorf("pub: false positive %v", v)
	}
	for _, src := range []string{"q := `SELECT * FROM exec.session_device`", `q := "SELECT 1 FROM \"exec\".\"write_device\""`, "q := `select * from EXEC . audit_head`"} {
		if len(violations("internal/backups", src)) == 0 {
			t.Errorf("backups: not caught: %s", src)
		}
	}
	for _, src := range []string{`q := "INSERT INTO exec.\"audit_event\""`, "q := `UPDATE EXEC . audit_head`", "q := `SELECT * FROM exec.recording_chunk`", "q := `SELECT * FROM exec.write_device`"} {
		if len(violations("internal/session", src)) == 0 {
			t.Errorf("session: not caught: %s", src)
		}
	}
	if v := violations("internal/session", "var p *pgxpool.Pool; q := `INSERT INTO exec.session_event (id) VALUES (nextval('exec.session_event_id_seq'))`; r := `SELECT 1 FROM exec.session_device`"); len(v) != 0 {
		t.Errorf("session: false positive %v", v)
	}
	for _, src := range []string{"q := `SELECT * FROM exec.write_grant`", "q := `INSERT INTO exec.audit_event`", "q := `SELECT * FROM exec.session_event`"} {
		if len(violations("internal/recording", src)) == 0 {
			t.Errorf("recording: not caught: %s", src)
		}
	}
	if v := violations("internal/recording", "var p *pgxpool.Pool; q := `INSERT INTO exec.recording_chunk`; r := `SELECT 1 FROM exec.session_device sd JOIN exec.session s`"); len(v) != 0 {
		t.Errorf("recording: false positive %v", v)
	}
	if v := violations("internal/backups", "var p *pgxpool.Pool; q := `INSERT INTO execpub.backup_taken (device_id) VALUES ($1)`"); len(v) != 0 {
		t.Errorf("backups: false positive %v", v)
	}
}
