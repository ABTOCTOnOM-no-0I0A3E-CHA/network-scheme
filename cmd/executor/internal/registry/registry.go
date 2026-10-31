/*
Package registry is the executor's write registry in schema exec: the only
writer of its rows and their verifier. Every row carries
HMAC-SHA-256(mac subkey, Canonical(table, pk, content, version)); every
change takes the next value of the global counter as the version of the rows
it touches; the state file holds the counter's high-water mark and the hash
of all (table, pk, version, mac), so a changed, replayed, deleted or rolled
back row and a replaced state file are all detected (security.md 5.1a).

Values are read over the binary protocol into Go values and MACed from
those, so no server-side function, cast or search_path takes part in what
is verified. Writes are declared (Tx.Put, Tx.Delete): the registry computes
each MAC from the declared values and, before COMMIT, insists the database
holds exactly the previous verified rows with the declared changes; it never
seals anything it reads back. Decisions read the registry only through View,
from the very snapshot that was verified.

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
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

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

/* Bounds of every registry transaction: a row or table lock held by someone else cannot stall the executor. */
const (
	LockTimeout      = 3 * time.Second
	StatementTimeout = 10 * time.Second
)

/* Sentinel is created in the state directory once the registry is bootstrapped and never removed. */
const Sentinel = "initialized"

/* PinSession sets the pool's sessions to resolve only pg_catalog (main passes it to store.Open). */
func PinSession(cfg *pgxpool.Config) {
	cfg.ConnConfig.RuntimeParams["search_path"] = "pg_catalog, pg_temp"
}

/* Registry verifies and changes the registry. */
type Registry struct {
	pool *pgxpool.Pool
	keys *seal.Keys
	path string
	mu   sync.Mutex
	/* Test seams: hook runs at named stages; commitTx commits. */
	hook     func(stage string, tx pgx.Tx)
	commitTx func(ctx context.Context, tx pgx.Tx) error
	/* settleFor bounds the wait for the fate of a transaction whose COMMIT failed ambiguously. */
	settleFor time.Duration
}

/* New returns the registry over pool, with the state file at path. */
func New(pool *pgxpool.Pool, keys *seal.Keys, path string) *Registry {
	return &Registry{pool: pool, keys: keys, path: path, settleFor: 2 * StatementTimeout,
		commitTx: func(ctx context.Context, tx pgx.Tx) error { return tx.Commit(ctx) }}
}

/* row is one verified registry row. */
type row struct {
	t       *table
	key     string /* table and encoded key: unique across the registry */
	pk      []*string
	content []*string
	typed   map[string]any
	version int64
	mac     []byte
}

func (r *row) canonical() []byte { return Canonical(r.t.name, r.pk, r.content, r.version) }

/* Snapshot is the registry as verified in one transaction. */
type Snapshot struct {
	seq    int64 /* 0 when registry_counter has no row */
	rows   []*row
	byKey  map[string]*row
	frozen bool
	reason string
}

/* Row is a read-only view of one verified row. */
type Row struct{ r *row }

/* Get returns the value of column col: int64, bool, string, []byte, time.Time, netip.Addr, json.RawMessage or nil (byte values are copies). */
func (r Row) Get(col string) any {
	switch v := r.r.typed[col].(type) {
	case []byte:
		return slices.Clone(v)
	case json.RawMessage:
		return slices.Clone(v)
	default:
		return v
	}
}

/* Version is the counter value of the change that last wrote the row. */
func (r Row) Version() int64 { return r.r.version }

/* Seq is the registry counter. */
func (s *Snapshot) Seq() int64 { return s.seq }

/* Frozen reports whether exec_state, a missing exec_state or the state file say frozen. */
func (s *Snapshot) Frozen() (bool, string) { return s.frozen, s.reason }

/* Rows lists the rows of table. */
func (s *Snapshot) Rows(table string) []Row {
	var out []Row
	for _, r := range s.rows {
		if r.t.name == table {
			out = append(out, Row{r})
		}
	}
	return out
}

/* Get returns the row of table with key pk (values as for Tx.Put). */
func (s *Snapshot) Get(table string, pk ...any) (Row, bool) {
	t := lookup(table)
	if t == nil {
		return Row{}, false
	}
	key, _, err := keyOf(t, pk)
	if err != nil {
		return Row{}, false
	}
	r, ok := s.byKey[key]
	return Row{r}, ok
}

/* keyOf encodes a key given as Go values; it also returns them as query parameters. */
func keyOf(t *table, pk []any) (string, []any, error) {
	if len(pk) != len(t.pk) {
		return "", nil, fmt.Errorf("registry: %s key has %d parts", t.name, len(t.pk))
	}
	enc := make([]*string, 0, len(pk))
	params := make([]any, 0, len(pk))
	for i, c := range t.pk {
		v, err := norm(c, pk[i])
		if err != nil {
			return "", nil, fmt.Errorf("registry: %s: %w", t.name, err)
		}
		enc, params = append(enc, v.canon), append(params, v.param)
	}
	return keyEnc(t, enc), params, nil
}

func keyEnc(t *table, pk []*string) string {
	name := t.name
	return string(appendList(appendField(nil, &name), pk))
}

/* pinSession bounds the transaction and resolves names in pg_catalog only (utility statements: nothing to resolve). */
func pinSession(ctx context.Context, tx pgx.Tx) error {
	for _, s := range []string{
		"SET LOCAL search_path = pg_catalog, pg_temp",
		fmt.Sprintf("SET LOCAL lock_timeout = %d", LockTimeout.Milliseconds()),
		fmt.Sprintf("SET LOCAL statement_timeout = %d", StatementTimeout.Milliseconds()),
	} {
		if _, err := tx.Exec(ctx, s); err != nil {
			return err
		}
	}
	return nil
}

/*
scan reads the whole registry into Go values. Values that cannot be
scanned or are out of their domain (NULL where none is allowed, infinite
time, a network instead of an address, two rows with one key) are tampering:
the executor never writes them.
*/
func scan(ctx context.Context, q pgx.Tx) (*Snapshot, error) {
	s := &Snapshot{byKey: map[string]*row{}}
	for i := range tables {
		t := &tables[i]
		rows, err := q.Query(ctx, t.selectSQL())
		if err != nil {
			return nil, fmt.Errorf("registry: read %s: %w", t.name, err)
		}
		cols := t.columns()
		for rows.Next() {
			dst := make([]any, 0, len(cols)+2)
			for _, c := range cols {
				dst = append(dst, dest(c.kind))
			}
			var version *int64
			var mac *[]byte
			if err := rows.Scan(append(dst, &version, &mac)...); err != nil {
				rows.Close()
				return nil, tampered("%s: %v", t.name, err)
			}
			r := &row{t: t, typed: map[string]any{}}
			for j, c := range cols {
				v, err := norm(c, deref(dst[j]))
				if err != nil {
					rows.Close()
					return nil, tampered("%s: %v", t.name, err)
				}
				r.typed[c.name] = v.typed
				if j < len(t.pk) {
					r.pk = append(r.pk, v.canon)
				} else {
					r.content = append(r.content, v.canon)
				}
			}
			if version == nil || mac == nil || len(*mac) != sha256.Size {
				rows.Close()
				return nil, tampered("%s: NULL version or bad mac", t.name)
			}
			r.version, r.mac = *version, *mac
			r.key = keyEnc(t, r.pk)
			if s.byKey[r.key] != nil {
				rows.Close()
				return nil, tampered("%s: two rows with one key", t.name)
			}
			s.byKey[r.key] = r
			s.rows = append(s.rows, r)
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("registry: read %s: %w", t.name, err)
		}
	}
	for _, name := range []string{counterTable, stateTable} {
		if n := len(s.Rows(name)); n > 1 {
			return nil, tampered("%s has %d rows", name, n)
		}
	}
	if c := s.Rows(counterTable); len(c) == 1 {
		s.seq = c[0].r.version
	}
	return s, nil
}

func dest(k kind) any {
	switch k {
	case kInt8:
		return new(*int64)
	case kInt4:
		return new(*int32)
	case kBool:
		return new(*bool)
	case kText:
		return new(*string)
	case kTime:
		return new(*time.Time)
	case kInet:
		return new(*netip.Prefix)
	default: /* kBytes, kJSON */
		return new(*[]byte)
	}
}

/* deref turns a **T scan destination into the T value, or nil for NULL. */
func deref(p any) any {
	v := reflect.ValueOf(p).Elem()
	if v.IsNil() {
		return nil
	}
	return v.Elem().Interface()
}

/* check verifies every row's MAC and version against the counter and returns the state hash. */
func (s *Snapshot) check(key *[32]byte) ([]byte, error) {
	entries := make([][]byte, 0, len(s.rows))
	for _, r := range s.rows {
		if !hmac.Equal(r.mac, macOf(key, r.canonical())) {
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

/* match compares the verified database with the committed record of the (settled) state file. */
func match(f state.File, seq int64, hash []byte) error {
	if f.Committed.HWM == seq && bytes.Equal(f.Committed.StateHash, hash) {
		return nil
	}
	return tampered("registry at %d does not match the state file (committed %d)", seq, f.Committed.HWM)
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

func (r *Registry) save(f state.File) error { return state.Save(r.path, r.keys.State(), f) }

/* errUnsettled: the fate of the pending transaction cannot be read now; nothing is decided until it can. */
var errUnsettled = errors.New("registry: the pending change is not settled yet")

/*
xactStatus is pg_xact_status of xid: "committed", "aborted", "in progress"
or "" (too old to be known). A transaction in the database's future means
the database was put back behind the state file: tampering.
*/
func (r *Registry) xactStatus(ctx context.Context, xid uint64) (string, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := pinSession(ctx, tx); err != nil {
		return "", err
	}
	var st *string
	err = tx.QueryRow(ctx, `SELECT pg_catalog.pg_xact_status($1::pg_catalog.text::pg_catalog.xid8)`,
		strconv.FormatUint(xid, 10)).Scan(&st)
	var pe *pgconn.PgError
	switch {
	case errors.As(err, &pe) && pe.Code == "22023":
		return "", tampered("pending transaction %d is in the database's future", xid)
	case err != nil:
		return "", err
	case st == nil:
		return "", nil
	}
	return *st, nil
}

/*
settle resolves a pending record by the fate of its own transaction, never
by comparing hashes: committed makes it the committed record, aborted (or
too old to know) drops it, so the rows of a change that did not commit can
never be accepted later, even replayed exactly. While the fate cannot be
read, settle fails and nothing is verified (fail closed).
*/
func (r *Registry) settle(ctx context.Context, f state.File) (state.File, error) {
	if f.Pending == nil {
		return f, nil
	}
	st, err := r.xactStatus(ctx, f.PendingXID)
	switch {
	case err != nil:
		return f, err
	case st == "committed":
		f.Committed = *f.Pending
	case st == "aborted" || st == "":
	default:
		return f, errUnsettled
	}
	f.Pending, f.PendingXID = nil, 0
	return f, r.save(f)
}

/* settleWait retries settle until it succeeds, is tampering or settleFor passes; r.mu stays held. */
func (r *Registry) settleWait(ctx context.Context, f state.File) (state.File, error) {
	deadline := time.Now().Add(r.settleFor)
	for {
		g, err := r.settle(ctx, f)
		if err == nil || errors.Is(err, ErrTampered) || time.Now().After(deadline) {
			return g, err
		}
		select {
		case <-ctx.Done():
			return g, errors.Join(err, ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

/* verified reads and verifies the whole registry; r.mu must be held. */
func (r *Registry) verified(ctx context.Context) (*Snapshot, error) {
	f, err := r.load()
	if err != nil {
		return nil, err
	}
	if f, err = r.settle(ctx, f); err != nil {
		return nil, err
	}
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := pinSession(ctx, tx); err != nil {
		return nil, err
	}
	if err := checkCatalog(ctx, tx); err != nil {
		return nil, err
	}
	s, err := scan(ctx, tx)
	if err != nil {
		return nil, err
	}
	hash, err := s.check(r.keys.MAC())
	if err != nil {
		return nil, err
	}
	if err := match(f, s.seq, hash); err != nil {
		return nil, err
	}
	s.frozen, s.reason = frozen(s, f)
	return s, nil
}

func frozen(s *Snapshot, f state.File) (bool, string) {
	st, ok := s.Get(stateTable, true)
	switch {
	case f.Frozen:
		return true, f.FreezeReason
	case !ok:
		return true, "exec_state missing"
	case st.Get("freeze") == true:
		reason, _ := st.Get("freeze_reason").(string)
		return true, reason
	}
	return false, ""
}

/*
View verifies the whole registry (every row's MAC and version, the counter,
the catalog, the state hash against the state file) and hands fn the very
snapshot it verified. It is the only way decisions read the registry: a
second query after a verification could see other rows. fn runs without
the registry's lock and must not call Write; a read-modify-write goes
through Write, whose function receives its own verified snapshot. An
ErrTampered error means freeze.
*/
func (r *Registry) View(ctx context.Context, fn func(*Snapshot) error) error {
	r.mu.Lock()
	s, err := r.verified(ctx)
	r.mu.Unlock()
	if err != nil {
		return err
	}
	return fn(s)
}

/* Report is the verified state of the registry. */
type Report struct {
	Seq    int64
	Frozen bool
	Reason string
}

/* Verify is View without a decision: call it at start and periodically. */
func (r *Registry) Verify(ctx context.Context) (Report, error) {
	var rep Report
	err := r.View(ctx, func(s *Snapshot) error {
		rep.Seq = s.seq
		rep.Frozen, rep.Reason = s.Frozen()
		return nil
	})
	return rep, err
}

/* op is one declared change. */
type op struct {
	t      *table
	key    string
	del    bool
	pk     []*string
	vals   []value /* all columns, for a put */
	params []any   /* key values, for a delete */
}

/* Tx collects the changes of one Write; nothing reaches the database before the function returns. */
type Tx struct {
	seq int64
	ops []op
}

/* Seq is the version every row of this change takes. */
func (t *Tx) Seq() int64 { return t.seq }

func newPut(table string, vals map[string]any) (op, error) {
	t := lookup(table)
	if t == nil {
		return op{}, fmt.Errorf("registry: unknown table %q", table)
	}
	cols := t.columns()
	if len(vals) != len(cols) {
		return op{}, fmt.Errorf("registry: %s: want every column of %d, got %d", table, len(cols), len(vals))
	}
	o := op{t: t}
	for i, c := range cols {
		v, ok := vals[c.name]
		if !ok {
			return op{}, fmt.Errorf("registry: %s: column %s missing", table, c.name)
		}
		n, err := norm(c, v)
		if err != nil {
			return op{}, fmt.Errorf("registry: %s: %w", table, err)
		}
		o.vals = append(o.vals, n)
		if i < len(t.pk) {
			o.pk = append(o.pk, n.canon)
		}
	}
	o.key = keyEnc(t, o.pk)
	return o, nil
}

/*
Put declares a full row of table (every key and content column, by name);
the registry sets version and mac. Values: integers (int, int32, int64),
bool, string, []byte, time.Time (kept to the microsecond), netip.Addr for
inet, json.RawMessage or []byte for jsonb, nil for NULL.
*/
func (t *Tx) Put(table string, vals map[string]any) error {
	if table == counterTable {
		return errors.New("registry: the counter is the registry's own")
	}
	o, err := newPut(table, vals)
	if err == nil {
		t.ops = append(t.ops, o)
	}
	return err
}

/* Delete declares the removal of the row of table with key pk. exec_state is never deleted. */
func (t *Tx) Delete(table string, pk ...any) error {
	tb := lookup(table)
	if tb == nil || table == counterTable || table == stateTable {
		return fmt.Errorf("registry: cannot delete from %q", table)
	}
	key, params, err := keyOf(tb, pk)
	if err != nil {
		return err
	}
	t.ops = append(t.ops, op{t: tb, key: key, del: true, params: params})
	return nil
}

/*
Write changes the registry. Under the registry's locks it verifies the
current registry against the state file (an unverified registry is never
extended), hands fn that verified snapshot to declare its changes with
tx.Put and tx.Delete, applies them at version seq+1 with MACs computed from
the declared values, checks that the database now holds exactly the
previous rows plus those changes (anything else — a trigger, a rule, a
default, a planted row — is tampering), then records the change as pending
in the state file (with its transaction id), commits and records it as
committed. Every registry table is locked in EXCLUSIVE mode for the whole
transaction. fn may run up to five times (serialization retries): it must
only declare changes, with no side effect of its own (no device I/O, no
other writes).
*/
func (r *Registry) Write(ctx context.Context, fn func(ctx context.Context, s *Snapshot, tx *Tx) error) error {
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

func (r *Registry) write(ctx context.Context, fn func(ctx context.Context, s *Snapshot, tx *Tx) error) error {
	f, err := r.load()
	if err != nil {
		return err
	}
	if f, err = r.settle(ctx, f); err != nil {
		return err
	}
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := pinSession(ctx, tx); err != nil {
		return err
	}
	if err := lockRegistry(ctx, tx); err != nil {
		return err
	}
	var seq int64
	if err := tx.QueryRow(ctx, `SELECT seq FROM exec.registry_counter FOR UPDATE`).Scan(&seq); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return tampered("registry_counter missing")
		}
		return err
	}
	if err := checkCatalog(ctx, tx); err != nil {
		return err
	}
	pre, err := scan(ctx, tx)
	if err != nil {
		return err
	}
	hash, err := pre.check(r.keys.MAC())
	if err != nil {
		return err
	}
	if err := match(f, pre.seq, hash); err != nil {
		return err
	}
	pre.frozen, pre.reason = frozen(pre, f)
	w := &Tx{seq: seq + 1}
	if err := fn(ctx, pre, w); err != nil {
		return err
	}
	r.step("verified", tx)
	counter, err := newPut(counterTable, map[string]any{"singleton": true})
	if err != nil {
		return err
	}
	return r.apply(ctx, tx, f, pre, append([]op{counter}, w.ops...), w.seq)
}

/*
apply writes ops at version seq, insists the database holds exactly pre
with ops applied, then commits in two phases through the state file.
*/
func (r *Registry) apply(ctx context.Context, tx pgx.Tx, f state.File, pre *Snapshot, ops []op, seq int64) error {
	type want struct {
		canonical, mac []byte
	}
	expect := map[string]want{}
	for k, rw := range pre.byKey {
		expect[k] = want{rw.canonical(), rw.mac}
	}
	for _, o := range ops {
		if o.del {
			if _, err := tx.Exec(ctx, o.t.deleteSQL(), o.params...); err != nil {
				return err
			}
			delete(expect, o.key)
			continue
		}
		content := make([]*string, 0, len(o.t.content))
		params := make([]any, 0, len(o.vals)+2)
		for i, v := range o.vals {
			if i >= len(o.t.pk) {
				content = append(content, v.canon)
			}
			params = append(params, v.param)
		}
		canonical := Canonical(o.t.name, o.pk, content, seq)
		mac := macOf(r.keys.MAC(), canonical)
		if _, err := tx.Exec(ctx, o.t.upsertSQL(), append(params, seq, mac)...); err != nil {
			return err
		}
		expect[o.key] = want{canonical, mac}
	}
	r.step("written", tx)
	if err := checkCatalog(ctx, tx); err != nil {
		return err
	}
	post, err := scan(ctx, tx)
	if err != nil {
		return err
	}
	if len(post.byKey) != len(expect) {
		return tampered("the write left %d rows, %d declared", len(post.byKey), len(expect))
	}
	for k, rw := range post.byKey {
		w, ok := expect[k]
		if !ok || !bytes.Equal(rw.canonical(), w.canonical) || !bytes.Equal(rw.mac, w.mac) {
			return tampered("the write left an undeclared %s row", rw.t.name)
		}
	}
	if post.seq != seq {
		return tampered("counter is %d inside the write of %d", post.seq, seq)
	}
	if _, ok := post.Get(stateTable, true); !ok {
		return errors.New("registry: a write must leave exec_state")
	}
	hash, err := post.check(r.keys.MAC())
	if err != nil {
		return err
	}
	var xid string
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.pg_current_xact_id()::pg_catalog.text`).Scan(&xid); err != nil {
		return err
	}
	xid8, err := strconv.ParseUint(xid, 10, 64)
	if err != nil || xid8 == 0 {
		return fmt.Errorf("registry: transaction id %q", xid)
	}
	base := f.Committed
	next := state.Record{HWM: seq, StateHash: hash, AuditHead: base.AuditHead}
	f.Pending, f.PendingXID = &next, xid8
	if err := r.save(f); err != nil {
		return err
	}
	r.step("pending", tx)
	if err := r.commitTx(ctx, tx); err != nil {
		return r.failedCommit(ctx, f, next, err)
	}
	r.step("committed", tx)
	f.Committed, f.Pending, f.PendingXID = next, nil, 0
	return r.save(f)
}

/*
failedCommit settles the pending record after a failed COMMIT, before the
lock is released. A COMMIT the server refused with an ERROR (or never
received) aborted: the record is dropped. Anything else (the connection
broke, or a FATAL that may come after the commit was written locally) is
settled by the fate of the transaction, retried for a while under the lock;
if it is still unknown, every verification keeps failing until it is known
(fail closed), and a change that did commit is then advanced, one that did
not is dropped: never accepted on a matching hash.
*/
func (r *Registry) failedCommit(ctx context.Context, f state.File, next state.Record, err error) error {
	var pe *pgconn.PgError
	if (errors.As(err, &pe) && pe.Severity == "ERROR") || pgconn.SafeToRetry(err) || errors.Is(err, pgx.ErrTxCommitRollback) {
		f.Pending, f.PendingXID = nil, 0
		return errors.Join(err, r.save(f))
	}
	g, serr := r.settleWait(ctx, f)
	if serr != nil {
		return errors.Join(err, serr)
	}
	if g.Committed.Equal(next) {
		return nil /* it did commit */
	}
	return err
}

func (r *Registry) step(stage string, tx pgx.Tx) {
	if r.hook != nil {
		r.hook(stage, tx)
	}
}

/*
Init runs once at start, before the first verification, and bootstraps a
fresh install: registry_counter and exec_state (not frozen), through the
same declared two-phase write, then the Sentinel. Fresh means a state
directory never used (no state file, no Sentinel, nothing else but
temporary files) and, checked under table locks inside the bootstrap
transaction, an untouched exec schema. A missing state file in a used
directory, or with a non-empty schema, is tampering; so is an invalid one.
*/
func (r *Registry) Init(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	dir := filepath.Dir(r.path)
	f, err := state.Load(r.path, r.keys.State())
	missing := errors.Is(err, os.ErrNotExist)
	switch {
	case errors.Is(err, state.ErrInvalid):
		return tampered("state file invalid or of another install")
	case err != nil && !missing:
		return err
	case !missing && f.Pending != nil:
		/* A crash inside a write or the bootstrap: settled by its transaction's fate, as after any failed COMMIT. */
		if f, err = r.settleWait(ctx, f); err != nil {
			return err
		}
	}
	switch {
	case !missing && f.Committed.HWM != 0:
		return r.markInitialized(dir)
	case missing:
		if err := unused(dir); err != nil {
			return err
		}
		f = state.File{}
	}
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := pinSession(ctx, tx); err != nil {
		return err
	}
	r.step("begin", tx)
	if err := lockRegistry(ctx, tx); err != nil {
		return err
	}
	if err := checkCatalog(ctx, tx); err != nil {
		return err
	}
	var fresh bool
	if err := tx.QueryRow(ctx, `SELECT NOT EXISTS (SELECT FROM exec.registry_counter)
		AND NOT EXISTS (SELECT FROM exec.write_device) AND NOT EXISTS (SELECT FROM exec.write_grant)
		AND NOT EXISTS (SELECT FROM exec.change_totp) AND NOT EXISTS (SELECT FROM exec.exec_state)
		AND NOT EXISTS (SELECT FROM exec.model_profile) AND NOT EXISTS (SELECT FROM exec.write_credential)
		AND NOT EXISTS (SELECT FROM exec.session) AND NOT EXISTS (SELECT FROM exec.audit_event)
		AND NOT EXISTS (SELECT FROM exec.audit_head WHERE last_id <> 0)`).Scan(&fresh); err != nil {
		return err
	}
	if !fresh {
		if missing {
			return tampered("state file missing, registry not empty")
		}
		return nil /* the verification decides (it fails: the state file says empty) */
	}
	empty := sha256.Sum256(nil)
	f.Committed = state.Record{StateHash: empty[:], AuditHead: state.AuditHead{Hash: make([]byte, sha256.Size)}}
	counter, err := newPut(counterTable, map[string]any{"singleton": true})
	if err != nil {
		return err
	}
	st, err := newPut(stateTable, map[string]any{"singleton": true, "freeze": false, "freeze_reason": nil,
		"global_fail_window": []byte("[]")})
	if err != nil {
		return err
	}
	if err := r.apply(ctx, tx, f, &Snapshot{byKey: map[string]*row{}}, []op{counter, st}, 1); err != nil {
		return err
	}
	return r.markInitialized(dir)
}

/*
lockRegistry takes every registry table (and audit_head) in EXCLUSIVE mode
before the transaction's first snapshot: from then until COMMIT nobody else
writes a row or changes the tables (DDL, triggers, constraints wait), so
what the catalog check and the scan see is what the write runs against.
Readers are not blocked.
*/
func lockRegistry(ctx context.Context, tx pgx.Tx) error {
	names := []string{"exec.audit_head"}
	for _, t := range tables {
		names = append(names, t.qname())
	}
	_, err := tx.Exec(ctx, "LOCK TABLE "+strings.Join(names, ", ")+" IN EXCLUSIVE MODE")
	return err
}

/* unused accepts a state directory that holds nothing but temporary files. */
func unused(dir string) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), ".state-") && !strings.HasPrefix(e.Name(), ".probe-") {
			return tampered("state file missing in a used state directory (%s)", e.Name())
		}
	}
	return nil
}

func (r *Registry) markInitialized(dir string) error {
	p := filepath.Join(dir, Sentinel)
	if _, err := os.Stat(p); err == nil {
		return nil
	}
	fh, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- inside the configured state directory
	if err != nil {
		return err
	}
	return errors.Join(fh.Sync(), fh.Close())
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
	return r.save(f)
}
