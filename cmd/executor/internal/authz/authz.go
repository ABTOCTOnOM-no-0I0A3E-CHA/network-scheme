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
  - in one registry write, on the verified snapshot: the policy still
    enables the executor; the user's change TOTP row exists and carries the
    ticket's name as its snapshot; the user is not locked (before the
    grants, so a locked user's answer says nothing about its grants); every
    grant the action needs exists with the same name snapshot; the secret
    opens under AAD user_id|change-totp|key_version; the code is valid for
    a step above the last one used. The outcome (step used, or failure and
    lockout, and the global failure window, and the freeze it trips) and
    its audit row commit together.

Rights come only from the registry, never from the ticket or the api. The
registry write may fail, and an error other than tampering leaves its
outcome unknown (registry.Write): so the step used and every failure are
also kept in memory and in the guards file next to the state file (MACed,
see guards.go), merged with the registry by taking the stricter of both,
and a code is accepted only when its use committed. An attacker who can
make the recording writes fail (a database superuser) gains no attempt and
no replay, in this process or after a restart.

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
	"strings"
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
	startSkew   = 5 * time.Second
	nonceTTL    = 2 * time.Minute
	maxNonces   = 1 << 16
	maxWindow   = 256 /* failure entries kept in the window; far more than ever needed to trip it */
	maxCode     = 16
	maxGroups   = 64
	panelReads  = 4  /* concurrent core.user reads */
	totpPeriod  = 30 /* seconds of a TOTP step (auth.ValidateTOTP) */
	tripPrefix  = "change TOTP: "
	decideTime  = 2 * registry.OpTimeout /* bound of a decision's write and of its audit row, apart from the caller's context */
	tripMessage = tripPrefix + "%d failures of %d users within an hour"
)

var actionRe = regexp.MustCompile(`^[a-z0-9_.-]{1,64}$`)

/*
Need is the grant an action requires: write on every group of Groups (one
at least), or the user's grant of Kind. unmask is scoped to write groups too
(4d.1): the user's unmask grant and write on every group of Groups (one at
least, the device's group from the registry), so unmask never reaches a
device of a group the user holds no grant on.
*/
type Need struct {
	Kind   string
	Groups []string
}

/* grouped reports whether a Need of kind names groups (write and unmask must, the others must not). */
func grouped(kind string) bool { return kind == execadmin.KindWrite || kind == execadmin.KindUnmask }

/* Valid reports whether n names a grant kind, with groups exactly for write and unmask. */
func (n Need) Valid() bool {
	if !slices.Contains(execadmin.Kinds, n.Kind) || len(n.Groups) > maxGroups {
		return false
	}
	return grouped(n.Kind) == (len(n.Groups) > 0)
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
	/* GuardsFile keeps the in-memory guards across restarts (in the state directory, next to the state file). */
	GuardsFile string
}

/* nonceEntry keeps a spent nonce until both a monotonic TTL and the ticket's wall-clock end (plus skew) are past. */
type nonceEntry struct {
	mono time.Duration /* monotonic elapsed time after which it may go */
	wall int64         /* Unix seconds after which it may go */
}

/* userState is a user's lockout state: from the registry row, or kept in memory. */
type userState struct {
	lastStep, failures, lockCount int64
	lockUntil                     time.Time
	/* pending: the guards file's pessimistic record of an attempt whose outcome never replaced it (the process died); prevStep is the step before it. */
	pending  bool
	prevStep int64
}

/* failure is one entry of the global failure window (exec_state.global_fail_window): user and time in Unix milliseconds. */
type failure struct {
	U int64 `json:"u"`
	T int64 `json:"t"`
}

/* Authorizer decides; one per process (its in-memory guards are the process's). */
type Authorizer struct {
	c Config
	/* sem orders decisions and the host's resets, so the in-memory guards (and their file) are up to date when the next one reads them. */
	sem chan struct{}
	/* panel bounds the concurrent core.user reads. */
	panel chan struct{}
	/* mono is the monotonic time since New (a seam: the tests step it apart from the wall clock). */
	mono     func() time.Duration
	nonceCap int

	mu     sync.Mutex
	nonces map[[ticket.NonceSize]byte]nonceEntry
	users  map[int64]userState
	window []failure
	lastMs int64 /* the last failure time handed out: failure times are unique in this process */
	/* unsaved is set while the guards file cannot be written: no code is evaluated until a save succeeds. */
	unsaved bool

	/*
		Test seams: abortWrite fails a decision's write after it declared its
		outcome; afterWrite replaces its result; beforeDecide runs once the
		decision holds sem; noTrigger skips the freeze after a tripped window
		(a crash right after the COMMIT).
	*/
	abortWrite   func() error
	afterWrite   func(error) error
	beforeDecide func()
	noTrigger    bool
	panelHook    func()
}

/* New returns the Authorizer of cfg. */
func New(cfg Config) (*Authorizer, error) {
	if len(cfg.TicketKey) != ed25519.PublicKeySize {
		return nil, errors.New("authz: the ticket verification key must be an Ed25519 public key")
	}
	if cfg.Guard == nil || cfg.Reg == nil || cfg.Keys == nil || cfg.Policy == nil || cfg.Log == nil || cfg.Started.IsZero() || cfg.GuardsFile == "" {
		return nil, errors.New("authz: incomplete configuration")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	users, window, err := loadGuards(cfg.GuardsFile, cfg.Keys.State())
	if err != nil {
		return nil, err
	}
	start := time.Now()
	a := &Authorizer{c: cfg, sem: make(chan struct{}, 1), panel: make(chan struct{}, panelReads),
		mono: func() time.Duration { return time.Since(start) }, nonceCap: maxNonces,
		nonces: map[[ticket.NonceSize]byte]nonceEntry{}, users: users, window: window}
	a.republish()
	return a, nil
}

/*
republish sends the brute-force freeze's alert again when the registry
holds that freeze (committed with the failure that tripped it) but the
state file has no sticky mark: the process died between the COMMIT and
Trigger, so neither the alert nor the mark was made.
*/
func (a *Authorizer) republish() {
	frozen, reason := a.c.Guard.Frozen()
	if !frozen || !strings.HasPrefix(reason, tripPrefix) {
		return
	}
	if sticky, err := a.c.Reg.StickyFrozen(); err != nil || sticky {
		return
	}
	a.c.Guard.Trigger(context.Background(), freeze.KindBruteforce, reason)
}

/*
Exclusive runs fn with no decision in progress and none starting: the
host's enroll, unlock and reset make their registry change and reset the
in-memory guards (ResetUser, ResetGlobal, only inside fn) as one step, so
no decision evaluates the new registry against the old memory.
*/
func (a *Authorizer) Exclusive(fn func()) {
	a.sem <- struct{}{}
	defer func() { <-a.sem }()
	fn()
}

/*
ResetUser (inside Exclusive, after the host's enroll or unlock committed)
drops the in-memory failures and locks of the user: the registry row is
what counts again. The last step used stays: a step is never reused.
*/
func (a *Authorizer) ResetUser(id int64) {
	a.mu.Lock()
	if st, ok := a.users[id]; ok {
		a.users[id] = userState{lastStep: st.lastStep}
	}
	a.mu.Unlock()
	_ = a.saveGuards(context.Background(), nil)
}

/* ResetGlobal (inside Exclusive) drops the in-memory global failure window (nmsctl executor unlock --global, registry reset). */
func (a *Authorizer) ResetGlobal() {
	a.mu.Lock()
	a.window = nil
	a.mu.Unlock()
	_ = a.saveGuards(context.Background(), nil)
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
	c, err := a.admit(ctx, d, now)
	if err != nil {
		return Decision{}, err
	}
	select {
	case a.sem <- struct{}{}:
	case <-ctx.Done():
		return Decision{}, a.refuse(ctx, d, &refusal{"busy", ErrUnavailable})
	}
	defer func() { <-a.sem }()
	return a.decide(ctx, d, c)
}

/*
admit runs the checks before the registry: the policy enables the executor
with TOTP, nothing is frozen, the ticket (its nonce spent), the user it
must be for, the deny-only core.user check. A refusal is audited.
*/
func (a *Authorizer) admit(ctx context.Context, d *decision, now time.Time) (ticket.Claims, error) {
	st := a.c.Policy.Current()
	switch {
	case !st.Enabled():
		return ticket.Claims{}, a.refuse(ctx, d, &refusal{"disabled", ErrDisabled})
	case st.Policy.ConfirmMode != execpolicy.ConfirmTOTP:
		return ticket.Claims{}, a.refuse(ctx, d, &refusal{"confirm_mode", ErrDisabled})
	}
	if frozen, _ := a.c.Guard.Frozen(); frozen {
		return ticket.Claims{}, a.refuse(ctx, d, &refusal{"frozen", ErrFrozen})
	}
	c, class := a.checkTicket(d.req.Ticket, now)
	if class != "" {
		return ticket.Claims{}, a.refuse(ctx, d, &refusal{class, ErrDenied})
	}
	d.user, d.ticket = &c.UserID, c.ID()
	if d.req.User != 0 && d.req.User != c.UserID {
		return ticket.Claims{}, a.refuse(ctx, d, &refusal{"wrong_user", ErrDenied})
	}
	if r := a.panelUser(ctx, c); r != nil {
		return ticket.Claims{}, a.refuse(ctx, d, r)
	}
	return c, nil
}

/*
Identify checks who asks, for a step that takes no action yet (issuing a
confirmation challenge): the same checks as Authorize before the registry
(policy, freeze, ticket with its nonce spent, req.User, core.user), but no
TOTP code and no grant: the action itself is decided later by Authorize
(through confirm). req.Need is ignored. One audit row either way; when the
accepting row cannot be written the request is refused (ErrUnavailable).
*/
func (a *Authorizer) Identify(ctx context.Context, req Request) (Decision, error) {
	req.Need = Need{}
	d := &decision{req: req}
	if !actionRe.MatchString(req.Action) {
		d.req.Action = "authz.request"
		return Decision{}, a.refuse(ctx, d, &refusal{"bad_action", ErrDenied})
	}
	c, err := a.admit(ctx, d, a.c.Now())
	if err != nil {
		return Decision{}, err
	}
	if a.record(ctx, a.event(d, audit.OK, "identified")) != nil {
		return Decision{}, ErrUnavailable /* no row, no identity: fail closed */
	}
	return Decision{UserID: c.UserID, Username: c.Username, Ticket: d.ticket}, nil
}

/*
TicketUser returns the user of a ticket whose signature and lifetime
verify, without spending its nonce or writing anything: the :8443 rate
limit keys on it before anything is decided. It grants nothing.
*/
func (a *Authorizer) TicketUser(tok string) (int64, bool) {
	c, err := ticket.Verify(a.c.TicketKey, tok, a.c.Now())
	return c.UserID, err == nil
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
	/*
		A spent nonce stays until the ticket can no longer verify by the wall
		clock (exp plus skew) and the monotonic TTL has passed: a wall clock
		stepped back cannot make a ticket valid again after its nonce went.
	*/
	mono, wall := a.mono(), now.Unix()
	a.mu.Lock()
	defer a.mu.Unlock()
	for n, e := range a.nonces {
		if mono >= e.mono && wall > e.wall {
			delete(a.nonces, n)
		}
	}
	switch _, seen := a.nonces[c.Nonce]; {
	case seen:
		return c, "ticket_replayed"
	case len(a.nonces) >= a.nonceCap:
		return c, "ticket_cache_full" /* fail closed: a nonce that cannot be remembered is not accepted */
	}
	a.nonces[c.Nonce] = nonceEntry{mono: mono + nonceTTL, wall: max(c.Expires, wall) + int64(ticket.Skew/time.Second)}
	return c, ""
}

/*
panelUser is the deny-only check against core.user (D10): it may refuse,
never grant. At most panelReads run at once, and every message the
executor's connections receive is bounded (registry.BoundMessages), so a
huge value planted in core.user cannot exhaust the executor's memory.
*/
func (a *Authorizer) panelUser(ctx context.Context, c ticket.Claims) *refusal {
	select {
	case a.panel <- struct{}{}:
	case <-ctx.Done():
		return &refusal{"busy", ErrUnavailable}
	}
	defer func() { <-a.panel }()
	if a.panelHook != nil {
		a.panelHook()
	}
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
	if a.beforeDecide != nil {
		a.beforeDecide()
	}
	/* The guards file must be writable before any code is evaluated (a restart must not reset what memory knows). */
	if a.isUnsaved() && a.saveGuards(ctx, nil) != nil {
		return Decision{}, a.refuse(ctx, d, &refusal{"guards_unwritable", ErrUnavailable})
	}
	var out outcome
	ran := false
	err := a.c.Guard.Write(wctx, func(_ context.Context, s *registry.Snapshot, tx *registry.Tx) error {
		ran = true
		/* The policy again: a decision that waited for the registry must not pass after nmsctl executor disable. */
		if st := a.c.Policy.Current(); !st.Enabled() || st.Policy.ConfirmMode != execpolicy.ConfirmTOTP {
			out = outcome{refuse: &refusal{"disabled", ErrDisabled}}
			return errAbort
		}
		out = a.evaluate(ctx, s, c, d.req, a.c.Now())
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
		_ = a.saveGuards(ctx, nil)
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

/*
committedSince reports whether mem is the pessimistic record of an attempt
that committed as a success before the process died: the registry's step is
past the one the attempt started from, and the row holds no failure and no
lock (a success writes exactly that; a failure never moves the step). The
record is then dropped for the registry row, so a crash right after a right
code's COMMIT does not lock the user out. Its entry in the global window
stays (the stricter side).
*/
func committedSince(reg, mem userState) bool {
	return mem.pending && reg.lastStep > mem.prevStep && reg.failures == 0 && reg.lockCount == 0 && reg.lockUntil.IsZero()
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
func (a *Authorizer) evaluate(ctx context.Context, s *registry.Snapshot, c ticket.Claims, req Request, now time.Time) outcome {
	row, ok := s.Get("change_totp", c.UserID)
	if !ok {
		return outcome{refuse: &refusal{"not_enrolled", ErrDenied}}
	}
	if snap, _ := row.Get("username_snapshot").(string); snap != c.Username {
		return outcome{refuse: &refusal{"snapshot_mismatch", ErrDenied}}
	}
	a.mu.Lock()
	mem, seen := a.users[c.UserID]
	memWindow := slices.Clone(a.window)
	a.mu.Unlock()
	cur := registryState(row)
	if seen && !committedSince(cur, mem) {
		cur = stricter(cur, mem)
	}
	/* The lock before the grants: a locked user's answer is the same whatever grants it holds (no oracle on the registry). */
	if l := cur.lock(now); l != nil {
		return outcome{refuse: &refusal{"locked", l}}
	}
	if r := granted(s, c, req.Need); r != nil {
		return outcome{refuse: r}
	}
	if kv, _ := row.Get("key_version").(int64); kv != int64(a.c.Keys.Version()) {
		return outcome{refuse: &refusal{"key_version", ErrUnavailable}}
	}
	/* Everything that can refuse comes before the code is looked at: an evaluated code is always recorded. */
	reg, err := parseWindow(s)
	if err != nil {
		return outcome{refuse: &refusal{"window_unreadable", ErrUnavailable}}
	}
	ct, _ := row.Get("ciphertext").([]byte)
	pt, err := a.c.Keys.OpenTOTP(c.UserID, a.c.Keys.Version(), ct)
	if err != nil {
		return outcome{tamper: fmt.Sprintf("the change TOTP secret of user #%d does not open under its AAD", c.UserID)}
	}
	sec := secret.New(string(pt))
	clear(pt)
	defer sec.Wipe()
	/*
		Persist before evaluating: the guards file first records this attempt as
		failed and its step window as used, so whatever happens to the outcome
		(the registry write fails, the process dies) a restart never gives the
		attempt back. Write may run this function more than once: each run
		records the same kind of pessimistic state, the outcome then replaces it.
	*/
	fail := failure{U: c.UserID, T: a.stamp(now)}
	pess := cur.failed(now)
	pess.lastStep = max(cur.lastStep, now.Unix()/totpPeriod+1)
	pess.pending, pess.prevStep = true, cur.lastStep
	if a.saveGuards(ctx, &pessimism{user: c.UserID, st: pess, fail: fail}) != nil {
		return outcome{refuse: &refusal{"guards_unwritable", ErrUnavailable}}
	}
	short := len(req.Code) <= maxCode
	if step, valid := auth.ValidateTOTP(req.Code, sec, cur.lastStep, now); short && valid {
		return outcome{ok: true, class: "accepted", cur: cur, next: userState{lastStep: step}}
	}
	class := "wrong_code"
	if _, valid := auth.ValidateTOTP(req.Code, sec, -1, now); short && valid {
		class = "replayed"
	}
	out := outcome{class: class, cur: cur, next: cur.failed(now), fail: &fail}
	out.window = mergeWindow(now, reg, memWindow, []failure{*out.fail})
	out.locked = out.next.lock(now)
	return out
}

/* granted checks every grant need asks for: present, and bound to the ticket's name (D10). */
func granted(s *registry.Snapshot, c ticket.Claims, need Need) *refusal {
	keys := [][]any{{c.UserID, need.Kind, nil}}
	if need.Kind == execadmin.KindWrite {
		keys = keys[:0]
	}
	if grouped(need.Kind) {
		for _, g := range need.Groups {
			keys = append(keys, []any{c.UserID, execadmin.KindWrite, g})
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

/* tripReason is the freeze reason of a tripped window. */
func tripReason(w []failure) string {
	users := map[int64]bool{}
	for _, f := range w {
		users[f.U] = true
	}
	return fmt.Sprintf(tripMessage, len(w), len(users))
}

/*
declare writes an evaluated outcome: the user's row, and on failure the
global window, with the freeze it trips in the same transaction (a crash
right after the COMMIT still leaves the registry frozen; Trigger then adds
the alert and the sticky flag).
*/
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
	frz, reason := st.Get("freeze"), st.Get("freeze_reason")
	if tripped(out.window) {
		frz, reason = true, tripReason(out.window)
	}
	return tx.Put("exec_state", map[string]any{"singleton": true, "freeze": frz, "freeze_reason": reason,
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
	if !tripped(w) || a.noTrigger {
		return
	}
	a.c.Guard.Trigger(context.WithoutCancel(ctx), freeze.KindBruteforce, tripReason(w))
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
func (a *Authorizer) Record(ctx context.Context, ev audit.Event) { _ = a.record(ctx, ev) }

/* record is Record, reporting whether the row was written. */
func (a *Authorizer) record(ctx context.Context, ev audit.Event) error {
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
	return err
}
