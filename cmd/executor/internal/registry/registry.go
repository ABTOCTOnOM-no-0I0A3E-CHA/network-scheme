/*
Package registry is the executor's write registry in schema exec: the only
writer of its rows and their verifier. Every row carries
HMAC-SHA-256(mac subkey, Canonical(table, pk, content, version)); every
change takes the next value of the global counter as the version of the rows
it touches; the state file holds the counter's high-water mark and the hash
of all (table, pk, version, mac), so a changed, replayed, deleted or rolled
back row and a replaced state file are all detected (security.md 5.1a).

One Registry per process (the executor is the single writer): an in-process
mutex orders writes and verifications, the row lock on registry_counter
orders transactions (never an advisory lock: the api can take those).
*/
package registry

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/state"
)

/* ErrTampered means the registry or the state file does not match what the executor wrote. */
var ErrTampered = errors.New("registry: tampered")

func tampered(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrTampered, fmt.Sprintf(format, a...))
}

/* Registry verifies and changes the registry. */
type Registry struct {
	pool *pgxpool.Pool
	keys *seal.Keys
	path string
	mu   sync.Mutex
	/* hook, if set (tests), runs after the pending record is saved and after the COMMIT; an error stops the write there. */
	hook func(stage string) error
}

/* New returns the registry over pool, with the state file at path. */
func New(pool *pgxpool.Pool, keys *seal.Keys, path string) *Registry {
	return &Registry{pool: pool, keys: keys, path: path}
}

/* Report is the verified state of the registry. */
type Report struct {
	Seq    int64
	Frozen bool /* exec_state says so, exec_state is missing, or the state file is frozen */
	Reason string
}

/* Unsealed is the placeholder MAC for rows written inside Write; Write seals them before COMMIT. */
func Unsealed() []byte { return make([]byte, sha256.Size) }

type row struct {
	t       *table
	ctid    string
	pk      []*string
	content []*string
	version int64
	mac     []byte
}

/* snapshot is the whole registry read in one transaction. */
type snapshot struct {
	seq     int64 /* 0 when registry_counter has no row */
	rows    []row
	state   *row /* exec_state, nil when missing */
	counter *row
}

func scan(ctx context.Context, q pgx.Tx) (snapshot, error) {
	var s snapshot
	for i := range tables {
		t := &tables[i]
		rows, err := q.Query(ctx, t.selectSQL())
		if err != nil {
			return s, fmt.Errorf("registry: read %s: %w", t.name, err)
		}
		n := len(t.pk) + len(t.content)
		for rows.Next() {
			r := row{t: t}
			vals := make([]*string, n)
			dst := []any{&r.ctid}
			for j := range vals {
				dst = append(dst, &vals[j])
			}
			if err := rows.Scan(append(dst, &r.version, &r.mac)...); err != nil {
				rows.Close()
				return s, fmt.Errorf("registry: read %s: %w", t.name, err)
			}
			r.pk, r.content = vals[:len(t.pk)], vals[len(t.pk):]
			s.rows = append(s.rows, r)
		}
		if err := rows.Err(); err != nil {
			return s, fmt.Errorf("registry: read %s: %w", t.name, err)
		}
	}
	for i := range s.rows {
		switch s.rows[i].t.name {
		case counterTable:
			s.counter = &s.rows[i]
			s.seq = s.rows[i].version
		case "exec_state":
			s.state = &s.rows[i]
		}
	}
	return s, nil
}

func (r row) expected(key *[32]byte) []byte {
	return rowMAC(key, r.t.name, r.pk, r.content, r.version)
}

/* check verifies every row's MAC and version against the counter and returns the state hash. */
func (s snapshot) check(key *[32]byte) ([]byte, error) {
	entries := make([][]byte, 0, len(s.rows))
	for _, r := range s.rows {
		if !hmac.Equal(r.mac, r.expected(key)) {
			return nil, tampered("bad MAC in %s", r.t.name)
		}
		if r.version > s.seq {
			return nil, tampered("%s row version %d above counter %d", r.t.name, r.version, s.seq)
		}
		entries = append(entries, entry(r.t.name, r.pk, r.version, r.mac))
	}
	slices.SortFunc(entries, bytes.Compare)
	h := sha256.New()
	for _, e := range entries {
		h.Write(e)
	}
	return h.Sum(nil), nil
}

/*
match compares the verified database with the state file: the committed
record is accepted, and so is the pending one (crash after COMMIT, before
"committed" was written); it returns the record the database is at.
*/
func match(f state.File, seq int64, hash []byte) (state.Record, error) {
	if f.Committed.HWM == seq && bytes.Equal(f.Committed.StateHash, hash) {
		return f.Committed, nil
	}
	if p := f.Pending; p != nil && p.HWM == seq && bytes.Equal(p.StateHash, hash) {
		return *p, nil
	}
	return state.Record{}, tampered("registry at %d does not match the state file (committed %d)", seq, f.Committed.HWM)
}

func (r *Registry) load() (state.File, error) {
	f, err := state.Load(r.path, r.keys.State())
	switch {
	case errors.Is(err, os.ErrNotExist):
		return f, tampered("state file missing")
	case errors.Is(err, state.ErrInvalid):
		return f, tampered("state file invalid or of another install")
	}
	return f, err
}

/* advance records that the pending change did commit. */
func (r *Registry) advance(f state.File, at state.Record) (state.File, error) {
	if f.Pending == nil || !f.Pending.Equal(at) {
		return f, nil
	}
	f.Committed, f.Pending = at, nil
	return f, state.Save(r.path, r.keys.State(), f)
}

/*
Verify is the full check: every row's MAC and version, the counter, and the
state hash against the state file (security.md 5.1a). Call it at start,
periodically and before every decision. An ErrTampered error means freeze.
*/
func (r *Registry) Verify(ctx context.Context) (Report, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, err := r.load()
	if err != nil {
		return Report{}, err
	}
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return Report{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	s, err := scan(ctx, tx)
	if err != nil {
		return Report{}, err
	}
	hash, err := s.check(r.keys.MAC())
	if err != nil {
		return Report{}, err
	}
	at, err := match(f, s.seq, hash)
	if err != nil {
		return Report{}, err
	}
	if f, err = r.advance(f, at); err != nil {
		return Report{}, err
	}
	return report(s, f), nil
}

func report(s snapshot, f state.File) Report {
	rep := Report{Seq: s.seq}
	switch {
	case f.Frozen:
		rep.Frozen, rep.Reason = true, f.FreezeReason
	case s.state == nil:
		rep.Frozen, rep.Reason = true, "exec_state missing"
	case *s.state.content[0] == "true":
		rep.Frozen = true
		if s.state.content[1] != nil {
			rep.Reason = *s.state.content[1]
		}
	}
	return rep
}

/* Tx is the write transaction handed to Write's function: queries only, no commit. */
type Tx struct {
	tx  pgx.Tx
	seq int64
}

/* Seq is the version every row written in this transaction must take. */
func (t *Tx) Seq() int64 { return t.seq }

/* Exec runs a statement in the write transaction. */
func (t *Tx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return t.tx.Exec(ctx, sql, args...)
}

/* Query runs a query in the write transaction. */
func (t *Tx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return t.tx.Query(ctx, sql, args...)
}

/* QueryRow runs a single-row query in the write transaction. */
func (t *Tx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return t.tx.QueryRow(ctx, sql, args...)
}

/*
Write changes the registry: it locks the counter row, verifies the current
registry against the state file (an unverified registry is never extended),
takes seq+1, runs fn — which writes its rows with version = tx.Seq() and mac
= Unsealed() — seals those rows, verifies the result, records it as pending
in the state file, commits and records it as committed.
*/
func (r *Registry) Write(ctx context.Context, fn func(ctx context.Context, tx *Tx) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var err error
	for range 5 {
		if err = r.write(ctx, fn); !isSerialization(err) {
			return err
		}
	}
	return err
}

func isSerialization(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "40001"
}

func (r *Registry) write(ctx context.Context, fn func(ctx context.Context, tx *Tx) error) error {
	f, err := r.load()
	if err != nil {
		return err
	}
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var seq int64
	if err := tx.QueryRow(ctx, `SELECT seq FROM exec.registry_counter FOR UPDATE`).Scan(&seq); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return tampered("registry_counter missing")
		}
		return err
	}
	s, err := scan(ctx, tx)
	if err != nil {
		return err
	}
	hash, err := s.check(r.keys.MAC())
	if err != nil {
		return err
	}
	base, err := match(f, s.seq, hash)
	if err != nil {
		return err
	}
	next := seq + 1
	if _, err := tx.Exec(ctx, `UPDATE exec.registry_counter SET seq = $1, mac = $2`, next, Unsealed()); err != nil {
		return err
	}
	if err := fn(ctx, &Tx{tx: tx, seq: next}); err != nil {
		return err
	}
	return r.commit(ctx, tx, f, base, next)
}

/*
commit seals the rows at version seq, verifies the whole registry, writes
the pending record, commits, then writes the committed record.
*/
func (r *Registry) commit(ctx context.Context, tx pgx.Tx, f state.File, base state.Record, seq int64) error {
	s, err := scan(ctx, tx)
	if err != nil {
		return err
	}
	if s.seq != seq {
		return fmt.Errorf("registry: counter is %d inside the write of %d", s.seq, seq)
	}
	for i := range s.rows {
		rw := &s.rows[i]
		if rw.version != seq {
			continue
		}
		rw.mac = rw.expected(r.keys.MAC())
		if _, err := tx.Exec(ctx, `UPDATE exec."`+rw.t.name+`" SET mac = $1 WHERE ctid = $2::tid`, rw.mac, rw.ctid); err != nil {
			return err
		}
	}
	hash, err := s.check(r.keys.MAC())
	if err != nil {
		return fmt.Errorf("registry: write left an invalid registry: %v", err) /* a bug of the caller, not tampering */
	}
	if s.state == nil {
		return errors.New("registry: write left no exec_state")
	}
	next := state.Record{HWM: seq, StateHash: hash, AuditHead: base.AuditHead}
	f.Committed, f.Pending = base, &next
	if err := state.Save(r.path, r.keys.State(), f); err != nil {
		return err
	}
	if err := r.step("pending"); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if err := r.step("committed"); err != nil {
		return err
	}
	f.Committed, f.Pending = next, nil
	return state.Save(r.path, r.keys.State(), f)
}

func (r *Registry) step(stage string) error {
	if r.hook == nil {
		return nil
	}
	return r.hook(stage)
}

/*
Init runs once at start, before the first Verify. A fresh install (no state
file, or one whose last committed change is the empty registry, and a
database whose exec schema is untouched) is bootstrapped: registry_counter,
exec_state (not frozen) and the state file, through the same two-phase
write. A missing state file with a non-empty registry is ErrTampered.
*/
func (r *Registry) Init(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, err := state.Load(r.path, r.keys.State())
	missing := errors.Is(err, os.ErrNotExist)
	switch {
	case errors.Is(err, state.ErrInvalid):
		return tampered("state file invalid or of another install")
	case err != nil && !missing:
		return err
	}
	if !missing && f.Committed.HWM != 0 {
		return nil
	}
	var fresh bool
	if err := r.pool.QueryRow(ctx, `SELECT NOT EXISTS (SELECT FROM exec.registry_counter)
		AND NOT EXISTS (SELECT FROM exec.write_device) AND NOT EXISTS (SELECT FROM exec.write_grant)
		AND NOT EXISTS (SELECT FROM exec.change_totp) AND NOT EXISTS (SELECT FROM exec.exec_state)
		AND NOT EXISTS (SELECT FROM exec.model_profile) AND NOT EXISTS (SELECT FROM exec.write_credential)
		AND NOT EXISTS (SELECT FROM exec.session) AND NOT EXISTS (SELECT FROM exec.audit_event)
		AND (SELECT last_id = 0 FROM exec.audit_head)`).Scan(&fresh); err != nil {
		return err
	}
	if !fresh {
		if missing {
			return tampered("state file missing, registry not empty")
		}
		return nil /* Verify decides: the database may be at the pending record */
	}
	if missing {
		f = state.File{}
	}
	empty := sha256.Sum256(nil)
	base := state.Record{StateHash: empty[:], AuditHead: state.AuditHead{Hash: make([]byte, sha256.Size)}}
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO exec.registry_counter (singleton, seq, mac) VALUES (true, 1, $1)`, Unsealed()); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO exec.exec_state (singleton, "freeze", version, mac) VALUES (true, false, 1, $1)`, Unsealed()); err != nil {
		return err
	}
	return r.commit(ctx, tx, f, base, 1)
}

/*
MarkFrozen makes the freeze sticky in the state file (it outlives a database
put back as it was). Without a valid state file there is nothing to mark:
that condition alone freezes every start.
*/
func (r *Registry) MarkFrozen(reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, err := r.load()
	if err != nil {
		return err
	}
	if f.Frozen {
		return nil
	}
	f.Frozen, f.FreezeReason = true, reason
	return state.Save(r.path, r.keys.State(), f)
}
