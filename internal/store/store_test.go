package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/beekamai/network-scheme/internal/store"
	"github.com/beekamai/network-scheme/internal/testdb"
)

func TestMain(m *testing.M) { testdb.Main(m) }

func TestMigrationsOnCleanDB(t *testing.T) {
	env := testdb.New(t)
	want, err := store.LatestVersion()
	if err != nil {
		t.Fatal(err)
	}
	var got int64
	err = env.Pool("nms_migrator").QueryRow(context.Background(),
		`SELECT max(version_id) FROM core.goose_db_version`).Scan(&got)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("goose version = %d, want %d", got, want)
	}
}

func requireDenied(t *testing.T, role, sql string) {
	t.Helper()
	_, err := testdb.New(t).Pool(role).Exec(context.Background(), sql)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Errorf("%s: %q: want SQLSTATE 42501, got %v", role, sql, err)
	}
}

func TestAPIRoleCannotCreateObjects(t *testing.T) {
	for _, sql := range []string{
		`CREATE TABLE core.x (id int)`,
		`CREATE TABLE public.x (id int)`,
		`CREATE SCHEMA evil`,
	} {
		requireDenied(t, "nms_api", sql)
	}
}

func TestNoPublicSchemaAccess(t *testing.T) {
	for _, role := range []string{"nms_api", "nms_cli"} {
		requireDenied(t, role, `CREATE TABLE public.x (id int)`)
	}
}

func TestMigratorOwnsSchemas(t *testing.T) {
	env := testdb.New(t)
	var n int
	err := env.Pool("nms_migrator").QueryRow(context.Background(),
		`SELECT count(*) FROM pg_namespace n JOIN pg_roles r ON r.oid = n.nspowner
		 WHERE n.nspname IN ('core','audit') AND r.rolname = 'nms_migrator'`).Scan(&n)
	if err != nil || n != 2 {
		t.Fatalf("schemas owned by nms_migrator = %d, err %v", n, err)
	}
}
