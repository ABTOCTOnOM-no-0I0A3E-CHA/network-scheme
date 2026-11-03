/*
Package attacktest is the attacker of the executor's tests (security.md 18):
a compromised api (Attacker: the role nms_api and the ticket signing key) and
direct edits of schema exec as the database superuser (the api has no right
on exec, so only the database owner or a superuser can tamper with it,
security.md 5.1a). Its own tests index every attack scenario of Phase 4a
(TestTraceability). Test-only: nothing outside _test.go files may import it.
*/
package attacktest

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/testdb"
	"github.com/beekamai/network-scheme/internal/ticket"
)

/*
Attacker is a compromised api: a connection as its database role nms_api and
the key it signs session tickets with. It forges tickets for any user and
name and runs whatever its role may (Exec); tampering beyond that role is the
superuser's (Tamper, Copy, Stall).
*/
type Attacker struct {
	env *testdb.Env
	key ed25519.PrivateKey
}

/* NewAttacker is the api of env holding key, the ticket signing key the executor trusts. */
func NewAttacker(env *testdb.Env, key ed25519.PrivateKey) *Attacker {
	return &Attacker{env: env, key: key}
}

/* Exec runs sql as nms_api and returns the database's answer (a refusal is the point of most attacks). */
func (a *Attacker) Exec(ctx context.Context, sql string, args ...any) error {
	_, err := a.env.Pool("nms_api").Exec(ctx, sql, args...)
	return err
}

/* Ticket signs a ticket issued now for any user id and name, as the api's ticket endpoint would. */
func (a *Attacker) Ticket(t testing.TB, user int64, name string) string {
	t.Helper()
	tok, _, err := ticket.Issue(a.key, user, name, time.Now())
	if err != nil {
		t.Fatalf("forge a ticket for %d %q: %v", user, name, err)
	}
	return tok
}

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

/*
Reset empties the registry and the executor's audit chain (a fresh install),
the alerts and a pending freeze request for the next test; the other append-only tables stay untouched. The audit
rows go with the append-only trigger disabled for the statement, as only a
superuser could.
*/
func Reset(t testing.TB, env *testdb.Env) {
	t.Helper()
	Tamper(t, env, `DELETE FROM exec.write_device; DELETE FROM exec.write_grant; DELETE FROM exec.change_totp;
		DELETE FROM exec.model_profile; DELETE FROM exec.write_credential; DELETE FROM exec.exec_state;
		DELETE FROM exec.registry_counter; DELETE FROM execpub.alert; DELETE FROM execpub.freeze_request;
		ALTER TABLE exec.audit_event DISABLE TRIGGER audit_event_append_only;
		DELETE FROM exec.audit_event;
		ALTER TABLE exec.audit_event ENABLE TRIGGER audit_event_append_only;
		UPDATE exec.audit_head SET last_id = 0, hash = decode(repeat('00', 32), 'hex')`)
}
