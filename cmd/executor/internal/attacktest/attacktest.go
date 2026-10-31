/*
Package attacktest is the attacker of the executor's tests: direct edits of
schema exec as the database superuser (the api has no right on exec, so only
the database owner or a superuser can tamper with it, security.md 5.1a).
Test-only: nothing outside _test.go files may import it.
*/
package attacktest

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/beekamai/network-scheme/internal/testdb"
)

/* Tamper runs sql as the superuser and fails the test on error. */
func Tamper(t testing.TB, env *testdb.Env, sql string, args ...any) {
	t.Helper()
	if _, err := env.Pool("postgres").Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("tamper %q: %v", sql, err)
	}
}

var copies atomic.Int64

/*
Copy saves the current rows of exec.<table> (MACs included) and returns a
function that puts exactly them back, replacing whatever is there then: a
replay of an old, validly MACed state.
*/
func Copy(t testing.TB, env *testdb.Env, table string) (restore func()) {
	t.Helper()
	saved := fmt.Sprintf("attack.%s_%d", table, copies.Add(1))
	Tamper(t, env, `CREATE SCHEMA IF NOT EXISTS attack`)
	Tamper(t, env, fmt.Sprintf(`CREATE TABLE %s AS SELECT * FROM exec.%q`, saved, table))
	return func() {
		t.Helper()
		Tamper(t, env, fmt.Sprintf(`DELETE FROM exec.%q`, table))
		Tamper(t, env, fmt.Sprintf(`INSERT INTO exec.%q SELECT * FROM %s`, table, saved))
	}
}

/*
Stall stops the database backend pid with SIGSTOP (the superuser's COPY TO
PROGRAM runs as the server's OS user): it keeps its locks and never answers,
and no server-side timeout fires in a stopped process. The returned
function resumes it.
*/
func Stall(t testing.TB, env *testdb.Env, pid uint32) (resume func()) {
	t.Helper()
	Tamper(t, env, fmt.Sprintf(`COPY (SELECT 1) TO PROGRAM 'kill -STOP %d && cat >/dev/null'`, pid))
	return func() {
		t.Helper()
		Tamper(t, env, fmt.Sprintf(`COPY (SELECT 1) TO PROGRAM 'kill -CONT %d && cat >/dev/null'`, pid))
	}
}

/* Reset empties the registry (a fresh install) for the next test; the append-only tables stay untouched. */
func Reset(t testing.TB, env *testdb.Env) {
	t.Helper()
	Tamper(t, env, `DELETE FROM exec.write_device; DELETE FROM exec.write_grant; DELETE FROM exec.change_totp;
		DELETE FROM exec.model_profile; DELETE FROM exec.write_credential; DELETE FROM exec.exec_state;
		DELETE FROM exec.registry_counter; DELETE FROM execpub.alert`)
}
