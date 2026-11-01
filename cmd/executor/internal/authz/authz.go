/*
Package authz decides whether a panel user may take one executor action
(security.md 5.2, D3, D10). Every action carries a session ticket of the api
and the user's change TOTP code; the decision, in this order:

  - the policy enables the executor and confirms with TOTP (fido2 is not
    available in Phase 4: refused), and nothing is frozen;
  - the ticket: signature, audience, lifetime, issued after this process
    started (minus 5 s, so no ticket survives a restart), its nonce never
    seen before (kept 2 minutes, longer than a ticket lives);
  - deny-only checks against the api's data (core.user): the user exists,
    is not disabled and still has the ticket's name;
  - in one registry write, on the verified snapshot: the user's change TOTP
    row and every grant the action needs exist and carry the ticket's name
    as their snapshot; the user is not locked; the secret opens under
    AAD user_id|change-totp|key_version; the code is valid for a step above
    the last one used. The outcome (step used, or failure and lockout, and
    the global failure window) and its audit row commit together.

Rights come only from the registry, never from the ticket or the api. The
registry write may fail, and an error other than tampering leaves its
outcome unknown (registry.Write): so the step used and every failure are
also kept in memory, merged with the registry by taking the stricter of
both, and a code is accepted only when its use committed. An attacker who
can make the recording writes fail (a database superuser) gains no attempt
and no replay in this process; across a restart only what committed counts.

Refusals tell the caller only ErrDisabled, ErrFrozen, ErrLocked,
ErrUnavailable or ErrDenied; why exactly (a class, never the code or a
secret) goes to the executor's audit chain, one row per decision.
*/
package authz

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/cmd/executor/internal/audit"
	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/cmd/executor/internal/policy"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/internal/auth"
	"github.com/beekamai/network-scheme/internal/execadmin"
	"github.com/beekamai/network-scheme/internal/execpolicy"
	"github.com/beekamai/network-scheme/internal/secret"
	"github.com/beekamai/network-scheme/internal/ticket"
)

/* What a refusal may tell the caller. Nothing else about why is said: the class is in the audit row. */
var (
	ErrDisabled    = errors.New("authz: the executor is disabled")
	ErrFrozen      = freeze.ErrFrozen
	ErrDenied      = errors.New("authz: denied")
	ErrLocked      = errors.New("authz: change TOTP locked")
	ErrUnavailable = errors.New("authz: cannot decide now, try again")
)

/* LockedError is ErrLocked with the end of the lock; Permanent: only nmsctl executor unlock lifts it. */
type LockedError struct {
	Until     time.Time
	Permanent bool
}

func (e *LockedError) Error() string {
	if e.Permanent {
		return "authz: change TOTP locked until nmsctl executor unlock"
	}
	return "authz: change TOTP locked until " + e.Until.UTC().Format(time.RFC3339)
}

/* Is makes a LockedError match ErrLocked. */
func (e *LockedError) Is(target error) bool { return target == ErrLocked }

/* Lockout rules (security.md 5.2). */
const (
	MaxFailures    = 5                /* failures in a row that lock the user */
	FirstLock      = 15 * time.Minute /* the first lock; every next one in a row lasts twice as long */
	MaxLocks       = 3                /* locks in a row after which only nmsctl executor unlock helps */
	GlobalWindow   = time.Hour
	GlobalUsers    = 3  /* failures of at least this many users ... */
	GlobalFailures = 20 /* ... and more than this many within GlobalWindow freeze the executor */
)

/* Bounds of the in-memory state and of a request. */
const (
	startSkew  = 5 * time.Second
	nonceTTL   = 2 * time.Minute
	maxNonces  = 1 << 16
	maxWindow  = 256 /* failure entries kept in the window; far more than ever needed to trip it */
	maxCode    = 16
	maxGroups  = 64
	decideTime = 2 * registry.OpTimeout /* bound of a decision's write and of its audit row, apart from the caller's context */
)

var actionRe = regexp.MustCompile(`^[a-z0-9_.-]{1,64}$`)

/* Need is the grant an action requires: write on every group of Groups (one at least), or the user's grant of Kind. */
type Need struct {
	Kind   string
	Groups []string
}

/* Valid reports whether n names a grant kind, with groups exactly for write. */
func (n Need) Valid() bool {
	if !slices.Contains(execadmin.Kinds, n.Kind) || len(n.Groups) > maxGroups {
		return false
	}
	return (n.Kind == execadmin.KindWrite) == (len(n.Groups) > 0)
}

/* Request is one action to authorize. */
type Request struct {
	Ticket string
	Code   string /* the change TOTP code */
	Need   Need
	Action string /* the audit action, e.g. session.open */
	Object string /* the audit object */
	/* User, if not 0, is the only user the ticket may be for (a confirmation challenge's user). */
	User   int64
	IP, UA string
	/* Details are added to the audit row; never a secret. */
	Details map[string]any
}

/* Decision is an accepted action: who took it, and the id of the ticket used. */
type Decision struct {
	UserID   int64
	Username string
	Ticket   string
}

/* Config builds an Authorizer. */
type Config struct {
	Guard     *freeze.Guard
	Reg       *registry.Registry
	Keys      *seal.Keys
	Policy    *policy.Holder
	Log       *slog.Logger
	TicketKey ed25519.PublicKey /* ticket.pub */
	Started   time.Time         /* the process start: earlier tickets are refused */
	Now       func() time.Time  /* nil: time.Now */
}

/* userState is a user's lockout state: from the registry row, or kept in memory. */
type userState struct {
	lastStep, failures, lockCount int64
	lockUntil                     time.Time
}

/* failure is one entry of the global failure window (exec_state.global_fail_window): user and time in Unix milliseconds. */
type failure struct {
	U int64 `json:"u"`
	T int64 `json:"t"`
}

/* Authorizer decides; one per process (its in-memory guards are the process's). */
type Authorizer struct {
	c Config
	/* sem orders decisions, so the in-memory guards are up to date when the next one reads them. */
	sem chan struct{}

	mu     sync.Mutex
	nonces map[[ticket.NonceSize]byte]time.Time
	users  map[int64]userState
	window []failure
	lastMs int64 /* the last failure time handed out: failure times are unique in this process */

	/* Test seams: abortWrite fails a decision's write after it declared its outcome; afterWrite replaces its result. */
	abortWrite func() error
	afterWrite func(error) error
}

/* New returns the Authorizer of cfg. */
func New(cfg Config) (*Authorizer, error) {
	if len(cfg.TicketKey) != ed25519.PublicKeySize {
		return nil, errors.New("authz: the ticket verification key must be an Ed25519 public key")
	}
	if cfg.Guard == nil || cfg.Reg == nil || cfg.Keys == nil || cfg.Policy == nil || cfg.Log == nil || cfg.Started.IsZero() {
		return nil, errors.New("authz: incomplete configuration")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Authorizer{c: cfg, sem: make(chan struct{}, 1), nonces: map[[ticket.NonceSize]byte]time.Time{},
		users: map[int64]userState{}}, nil
}

/*
ResetUser is called by the host's enroll and unlock (once committed): the
in-memory failures and locks of the user are dropped, the registry row is
what counts again. The last step used stays: a step is never reused.
*/
func (a *Authorizer) ResetUser(id int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if st, ok := a.users[id]; ok {
		a.users[id] = userState{lastStep: st.lastStep}
	}
}

/* ResetGlobal drops the in-memory global failure window (nmsctl executor unlock --global, registry reset). */
func (a *Authorizer) ResetGlobal() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.window = nil
}

/* decision is one Authorize call on its way. */
type decision struct {
	req    Request
	user   *int64
	ticket string
}

/* refusal is a refused decision: its audit class and what the caller is told. */
type refusal struct {
	class  string
	public error
}

func (r *refusal) Error() string { return "authz: refused (" + r.class + ")" }

/*
Authorize decides req and returns who took the action, or a refusal (see
the package comment). Every call writes one audit row (the accepted one in
the transaction that consumed the code).
*/
func (a *Authorizer) Authorize(ctx context.Context, req Request) (Decision, error) {
	d := &decision{req: req}
	now := a.c.Now()
	if !actionRe.MatchString(req.Action) {
		d.req.Action = "authz.request"
		return Decision{}, a.refuse(ctx, d, &refusal{"bad_action", ErrDenied})
	}
	if !req.Need.Valid() {
		return Decision{}, a.refuse(ctx, d, &refusal{"bad_need", ErrDenied})
	}
	st := a.c.Policy.Current()
	switch {
	case !st.Enabled():
		return Decision{}, a.refuse(ctx, d, &refusal{"disabled", ErrDisabled})
	case st.Policy.ConfirmMode != execpolicy.ConfirmTOTP:
		return Decision{}, a.refuse(ctx, d, &refusal{"confirm_mode", ErrDisabled})
	}
	if frozen, _ := a.c.Guard.Frozen(); frozen {
		return Decision{}, a.refuse(ctx, d, &refusal{"frozen", ErrFrozen})
	}
	c, class := a.checkTicket(req.Ticket, now)
	if class != "" {
		return Decision{}, a.refuse(ctx, d, &refusal{class, ErrDenied})
	}
	d.user, d.ticket = &c.UserID, c.ID()
	if req.User != 0 && req.User != c.UserID {
		return Decision{}, a.refuse(ctx, d, &refusal{"wrong_user", ErrDenied})
	}
	if r := a.panelUser(ctx, c); r != nil {
		return Decision{}, a.refuse(ctx, d, r)
	}
	select {
	case a.sem <- struct{}{}:
	case <-ctx.Done():
		return Decision{}, a.refuse(ctx, d, &refusal{"busy", ErrUnavailable})
	}
	defer func() { <-a.sem }()
	return a.decide(ctx, d, c)
}

/* checkTicket verifies the ticket and spends its nonce; a non-empty class refuses it. */
func (a *Authorizer) checkTicket(tok string, now time.Time) (ticket.Claims, string) {
	c, err := ticket.Verify(a.c.TicketKey, tok, now)
	if err != nil {
		var e *ticket.Error
		if errors.As(err, &e) {
			return c, "ticket_" + e.Reason
		}
		return c, "ticket_invalid"
	}
	if time.Unix(c.IssuedAt, 0).Before(a.c.Started.Add(-startSkew)) {
		return c, "ticket_before_start"
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for n, until := range a.nonces {
		if !now.Before(until) {
			delete(a.nonces, n)
		}
	}
	switch _, seen := a.nonces[c.Nonce]; {
	case seen:
		return c, "ticket_replayed"
	case len(a.nonces) >= maxNonces:
		return c, "ticket_cache_full" /* fail closed: a nonce that cannot be remembered is not accepted */
	}
	a.nonces[c.Nonce] = now.Add(nonceTTL)
	return c, ""
}

/* panelUser is the deny-only check against core.user (D10): it may refuse, never grant. */
func (a *Authorizer) panelUser(ctx context.Context, c ticket.Claims) *refusal {
	var name string
	var disabled, found bool
	err := a.c.Reg.Read(ctx, registry.OpTimeout, func(ctx context.Context, tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT username, disabled FROM core."user" WHERE id = $1`, c.UserID).Scan(&name, &disabled)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		found = err == nil
		return err
	})
	switch {
	case err != nil:
		a.c.Log.Error("authz: cannot read core.user", slog.Any("err", err))
		return &refusal{"panel_unavailable", ErrUnavailable}
	case !found:
		return &refusal{"unknown_user", ErrDenied}
	case disabled:
		return &refusal{"disabled_user", ErrDenied}
	case name != c.Username:
		return &refusal{"panel_name_mismatch", ErrDenied}
	}
	return nil
}

/* outcome is what one evaluation of the code decided. */
type outcome struct {
	refuse *refusal  /* refused before any code was checked: nothing to record */
	tamper string    /* the secret does not open: freeze */
	ok     bool      /* the code is accepted */
	class  string    /* audit class of an evaluated code */
	cur    userState /* the user's state before this attempt (registry and memory merged) */
	next   userState /* the user's state after this attempt */
	fail   *failure  /* the failure this attempt adds to the window */
	window []failure /* the window after this attempt (on failure) */
	locked *LockedError
}

var errAbort = errors.New("authz: nothing to record")

/*
decide runs the evaluation inside one registry write and records its
outcome, in the registry and in memory. The write runs apart from the
caller's context (bounded by decideTime): a client that goes away does not
cancel the recording of its own failure. The code is checked against the
time of the evaluation, not of the request (waiting for the registry does
not stretch the code's window).
*/
func (a *Authorizer) decide(ctx context.Context, d *decision, c ticket.Claims) (Decision, error) {
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), decideTime)
	defer cancel()
	var out outcome
	ran := false
	err := a.c.Guard.Write(wctx, func(_ context.Context, s *registry.Snapshot, tx *registry.Tx) error {
		ran = true
		out = a.evaluate(s, c, d.req, a.c.Now())
		if out.refuse != nil || out.tamper != "" {
			return errAbort
		}
		result := audit.OK
		if !out.ok {
			result = audit.Denied
		}
		ev := a.event(d, result, out.class)
		ev.IP = cleanIP(ev.IP)
		tx.Audit(audit.Append(ev))
		if err := a.declare(s, tx, c, out); err != nil {
			return err
		}
		if a.abortWrite != nil {
			return a.abortWrite()
		}
		return nil
	})
	if a.afterWrite != nil {
		err = a.afterWrite(err)
	}
	if ran && out.refuse == nil && out.tamper == "" {
		rem := out
		if err != nil && out.ok {
			/* A right code whose use may not have committed is refused: its step is spent, nothing else is forgiven. */
			rem.next = out.cur
			rem.next.lastStep = max(out.cur.lastStep, out.next.lastStep)
		}
		a.remember(c.UserID, rem)
	}
	switch {
	case ran && out.tamper != "":
		a.c.Guard.Trigger(ctx, freeze.KindTamper, out.tamper)
		return Decision{}, a.refuse(ctx, d, &refusal{"secret_unopenable", ErrFrozen})
	case ran && out.refuse != nil:
		return Decision{}, a.refuse(ctx, d, out.refuse)
	case errors.Is(err, freeze.ErrFrozen):
		a.trip(ctx, out)
		return Decision{}, a.refuse(ctx, d, &refusal{"frozen", ErrFrozen})
	case err != nil:
		/* The outcome is unknown: refused whatever it was, the in-memory guards hold it. */
		class := "unavailable"
		if ran {
			class = out.class + "_unrecorded"
		}
		a.c.Log.Error("authz: the decision was not recorded", slog.String("class", class), slog.Any("err", err))
		a.trip(ctx, out)
		return Decision{}, a.refuse(ctx, d, &refusal{class, ErrUnavailable})
	}
	a.trip(ctx, out)
	switch {
	case out.ok:
		return Decision{UserID: c.UserID, Username: c.Username, Ticket: d.ticket}, nil
	case out.locked != nil:
		return Decision{}, out.locked
	}
	return Decision{}, ErrDenied
}

/* registryState reads the lockout state of a change_totp row. */
func registryState(r registry.Row) userState {
	st := userState{}
	st.lastStep, _ = r.Get("last_step").(int64)
	st.failures, _ = r.Get("failures").(int64)
	st.lockCount, _ = r.Get("lock_count").(int64)
	st.lockUntil, _ = r.Get("lock_until").(time.Time)
	return st
}

/* stricter merges two states: the later lock cycle (or more failures in the same one), the higher step, the later lock end. */
func stricter(a, b userState) userState {
	out := a
	if b.lockCount > a.lockCount || (b.lockCount == a.lockCount && b.failures > a.failures) {
		out.failures, out.lockCount = b.failures, b.lockCount
	}
	out.lastStep = max(a.lastStep, b.lastStep)
	if b.lockUntil.After(out.lockUntil) {
		out.lockUntil = b.lockUntil
	}
	return out
}

/* lock reports the lock st is under at now, if any. */
func (st userState) lock(now time.Time) *LockedError {
	switch {
	case st.lockCount >= MaxLocks:
		return &LockedError{Permanent: true}
	case now.Before(st.lockUntil):
		return &LockedError{Until: st.lockUntil}
	}
	return nil
}

/* failed is st after one more failure at now: the MaxFailures-th locks, each lock in a row twice as long. */
func (st userState) failed(now time.Time) userState {
	st.failures++
	if st.failures >= MaxFailures {
		st.failures = 0
		st.lockCount++
		st.lockUntil = now.Add(FirstLock << (st.lockCount - 1)).Truncate(time.Microsecond)
	}
	return st
}

/*
evaluate decides on the verified snapshot and the in-memory guards. It only
reads (Write may run it more than once); the caller records the outcome.
*/
func (a *Authorizer) evaluate(s *registry.Snapshot, c ticket.Claims, req Request, now time.Time) outcome {
	row, ok := s.Get("change_totp", c.UserID)
	if !ok {
		return outcome{refuse: &refusal{"not_enrolled", ErrDenied}}
	}
	if snap, _ := row.Get("username_snapshot").(string); snap != c.Username {
		return outcome{refuse: &refusal{"snapshot_mismatch", ErrDenied}}
	}
	if r := granted(s, c, req.Need); r != nil {
		return outcome{refuse: r}
	}
	a.mu.Lock()
	mem, seen := a.users[c.UserID]
	memWindow := slices.Clone(a.window)
	a.mu.Unlock()
	cur := registryState(row)
	if seen {
		cur = stricter(cur, mem)
	}
	if l := cur.lock(now); l != nil {
		return outcome{refuse: &refusal{"locked", l}}
	}
	if kv, _ := row.Get("key_version").(int64); kv != seal.KeyVersion {
		return outcome{refuse: &refusal{"key_version", ErrUnavailable}}
	}
	/* Everything that can refuse comes before the code is looked at: an evaluated code is always recorded. */
	reg, err := parseWindow(s)
	if err != nil {
		return outcome{refuse: &refusal{"window_unreadable", ErrUnavailable}}
	}
	ct, _ := row.Get("ciphertext").([]byte)
	pt, err := a.c.Keys.OpenTOTP(c.UserID, seal.KeyVersion, ct)
	if err != nil {
		return outcome{tamper: fmt.Sprintf("the change TOTP secret of user #%d does not open under its AAD", c.UserID)}
	}
	sec := secret.New(string(pt))
	clear(pt)
	defer sec.Wipe()
	short := len(req.Code) <= maxCode
	if step, valid := auth.ValidateTOTP(req.Code, sec, cur.lastStep, now); short && valid {
		return outcome{ok: true, class: "accepted", cur: cur, next: userState{lastStep: step}}
	}
	class := "wrong_code"
	if _, valid := auth.ValidateTOTP(req.Code, sec, -1, now); short && valid {
		class = "replayed"
	}
	out := outcome{class: class, cur: cur, next: cur.failed(now), fail: &failure{U: c.UserID, T: a.stamp(now)}}
	out.window = mergeWindow(now, reg, memWindow, []failure{*out.fail})
	out.locked = out.next.lock(now)
	return out
}

/* granted checks every grant need asks for: present, and bound to the ticket's name (D10). */
func granted(s *registry.Snapshot, c ticket.Claims, need Need) *refusal {
	keys := [][]any{{c.UserID, need.Kind, nil}}
	if need.Kind == execadmin.KindWrite {
		keys = keys[:0]
		for _, g := range need.Groups {
			keys = append(keys, []any{c.UserID, need.Kind, g})
		}
	}
	for _, k := range keys {
		g, ok := s.Get("write_grant", k...)
		if !ok {
			return &refusal{"no_grant", ErrDenied}
		}
		if snap, _ := g.Get("username_snapshot").(string); snap != c.Username {
			return &refusal{"grant_snapshot_mismatch", ErrDenied}
		}
	}
	return nil
}

/* stamp returns now in Unix milliseconds, above every stamp handed out before (failure entries are unique). */
func (a *Authorizer) stamp(now time.Time) int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastMs = max(a.lastMs+1, now.UnixMilli())
	return a.lastMs
}

/* parseWindow reads exec_state.global_fail_window strictly: an array of {u, t}, nothing else. */
func parseWindow(s *registry.Snapshot) ([]failure, error) {
	st, ok := s.Get("exec_state", true)
	if !ok {
		return nil, errors.New("exec_state missing")
	}
	raw, _ := st.Get("global_fail_window").(json.RawMessage)
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var w []failure
	if err := dec.Decode(&w); err != nil || w == nil {
		return nil, fmt.Errorf("global_fail_window: %v", err)
	}
	return w, nil
}

/* mergeWindow is the union of the windows within GlobalWindow before now, oldest first, at most maxWindow entries. */
func mergeWindow(now time.Time, ws ...[]failure) []failure {
	from := now.Add(-GlobalWindow).UnixMilli()
	seen := map[failure]bool{}
	out := []failure{}
	for _, w := range ws {
		for _, f := range w {
			if f.T > from && !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	slices.SortFunc(out, func(x, y failure) int { return cmp.Or(cmp.Compare(x.T, y.T), cmp.Compare(x.U, y.U)) })
	if len(out) > maxWindow {
		out = out[len(out)-maxWindow:]
	}
	return out
}

/* tripped reports whether a window freezes the executor: failures of GlobalUsers users or more, over GlobalFailures in all. */
func tripped(w []failure) bool {
	users := map[int64]bool{}
	for _, f := range w {
		users[f.U] = true
	}
	return len(users) >= GlobalUsers && len(w) > GlobalFailures
}

/* declare writes an evaluated outcome: the user's row, and on failure the global window. */
func (a *Authorizer) declare(s *registry.Snapshot, tx *registry.Tx, c ticket.Claims, out outcome) error {
	row, _ := s.Get("change_totp", c.UserID)
	var lockUntil any
	if !out.next.lockUntil.IsZero() {
		lockUntil = out.next.lockUntil
	}
	if err := tx.Put("change_totp", map[string]any{"user_id": c.UserID, "username_snapshot": row.Get("username_snapshot"),
		"ciphertext": row.Get("ciphertext"), "key_version": row.Get("key_version"), "last_step": out.next.lastStep,
		"failures": out.next.failures, "lock_until": lockUntil, "lock_count": out.next.lockCount}); err != nil {
		return err
	}
	if out.ok {
		return nil
	}
	st, _ := s.Get("exec_state", true)
	w, err := json.Marshal(out.window)
	if err != nil {
		return err
	}
	return tx.Put("exec_state", map[string]any{"singleton": true, "freeze": st.Get("freeze"), "freeze_reason": st.Get("freeze_reason"),
		"global_fail_window": json.RawMessage(w)})
}

/* remember keeps an evaluated outcome in memory, whether or not its write committed. */
func (a *Authorizer) remember(user int64, out outcome) {
	a.mu.Lock()
	defer a.mu.Unlock()
	next := out.next
	if prev, ok := a.users[user]; ok {
		next.lastStep = max(next.lastStep, prev.lastStep)
	}
	a.users[user] = next
	if out.fail != nil {
		a.window = mergeWindow(time.UnixMilli(out.fail.T), a.window, out.window)
	}
}

/*
trip freezes the executor when out added a failure and the in-memory window
(a superset of the registry's) then says so. Only a new failure trips: a
freeze lifted by the host is not set again by an old window (nmsctl executor
unlock --global clears it).
*/
func (a *Authorizer) trip(ctx context.Context, out outcome) {
	if out.fail == nil {
		return
	}
	a.mu.Lock()
	w := mergeWindow(a.c.Now(), a.window)
	a.mu.Unlock()
	if !tripped(w) {
		return
	}
	users := map[int64]bool{}
	for _, f := range w {
		users[f.U] = true
	}
	a.c.Guard.Trigger(context.WithoutCancel(ctx), freeze.KindBruteforce,
		fmt.Sprintf("change TOTP: %d failures of %d users within an hour", len(w), len(users)))
}

/* event is the audit row of a decision; the class says why, never with the code. */
func (a *Authorizer) event(d *decision, result, class string) audit.Event {
	details := map[string]any{}
	for k, v := range d.req.Details {
		details[k] = v
	}
	details["class"], details["need"] = class, d.req.Need.Kind
	if len(d.req.Need.Groups) > 0 {
		details["groups"] = d.req.Need.Groups
	}
	if d.ticket != "" {
		details["ticket"] = d.ticket
	}
	return audit.Event{UserID: d.user, IP: d.req.IP, UA: d.req.UA, Action: d.req.Action, Object: d.req.Object, Result: result, Details: details}
}

func cleanIP(s string) string {
	if addr, err := netip.ParseAddr(s); err == nil && addr.Zone() == "" {
		return addr.String()
	}
	return ""
}

/* refuse records a refusal (alone in the chain) and returns what the caller is told. */
func (a *Authorizer) refuse(ctx context.Context, d *decision, r *refusal) error {
	a.Record(ctx, a.event(d, audit.Denied, r.class))
	return r.public
}

/*
Record appends ev to the executor's audit chain apart from the caller's
context (a client that goes away does not cancel the record); an IP that is
not a plain address is dropped (it comes from the request). Tampering with
the chain freezes, any other failure is logged.
*/
func (a *Authorizer) Record(ctx context.Context, ev audit.Event) {
	ev.IP = cleanIP(ev.IP)
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), decideTime)
	defer cancel()
	err := a.c.Reg.Append(rctx, audit.Append(ev))
	if errors.Is(err, registry.ErrTampered) {
		a.c.Guard.Trigger(ctx, freeze.KindTamper, err.Error())
	}
	if err != nil {
		a.c.Log.Error("executor audit: cannot record", slog.String("action", ev.Action), slog.Any("err", err))
	}
}
