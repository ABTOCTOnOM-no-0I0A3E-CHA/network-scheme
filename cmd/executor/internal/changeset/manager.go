package changeset

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/approval"
	"github.com/beekamai/network-scheme/cmd/executor/internal/audit"
	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/backups"
	"github.com/beekamai/network-scheme/cmd/executor/internal/devices"
	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/cmd/executor/internal/policy"
	"github.com/beekamai/network-scheme/cmd/executor/internal/pub"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/internal/execadmin"
)

/*
The changeset workspace (task 5.2). POST /x/changesets/open with the ticket
and the user's change TOTP code gives a bearer token (in the iframe's
memory only), bound to the user, ending idle_minutes after its last use and
session_minutes after it was given; every other route takes the token, and
every decision on it is taken again on the verified registry: the user's
write grants on every group of the changeset's devices (a revoked grant
counts at once, for the author too), the devices' write_device rows
(writes_enabled, a confirmed model, a pinned host key, a write credential).
Nothing the api holds counts: devices are ids of the write registry, their
addresses, groups and lines come from it.
*/

/* Gate is the decision path: *freeze.Guard. */
type Gate interface {
	View(ctx context.Context, fn func(*registry.Snapshot) error) error
	Frozen() (bool, string)
}

/* Authorizer is what the workspace needs of authz.Authorizer. */
type Authorizer interface {
	TicketUser(tok string) (int64, bool)
	Authorize(ctx context.Context, req authz.Request) (authz.Decision, error)
	Record(ctx context.Context, ev audit.Event)
}

/* Publisher is what changesets need of pub.Publisher. */
type Publisher interface {
	ChangesetSummary(ctx context.Context, s pub.ChangesetSummary) error
	Alert(ctx context.Context, kind, severity string, deviceID int64, text string) error
	Busy(ctx context.Context, dev registry.Row, session [16]byte) error
	Free(ctx context.Context, deviceID int64, session [16]byte) error
}

/* Config builds a Manager; every field but Log and Now is required. */
type Config struct {
	Gate   Gate
	Auth   Authorizer
	Policy func() policy.State
	Store  *Store
	Pub    Publisher
	/* Locks and Reader read the devices for a dry-run (the backup scheduler's: one connection per device). */
	Locks  *backups.Locks
	Reader Reader
	/* Approvals holds the authors' approvals waiting for a second person (shared with the sessions), in memory only. */
	Approvals *approval.Store
	/* BackupPriv and BackupPub open configuration versions for a restore (backup_key_file); nil: no restore. */
	BackupPriv, BackupPub *[32]byte
	/* Runner opens the service sessions of a run (*session.Manager): with it, Start is the run of run.go. */
	Runner Runner
	/* Start runs an approved changeset; nil (and no Runner): no changeset is approved (fail closed). */
	Start func(ctx context.Context, s Started) error
	Log   *slog.Logger
	Now   func() time.Time
}

/* Bounds of the workspaces (variables for the tests). */
var (
	maxTokensPerUser = 4
	maxTokens        = 4096
	listMost         = 200 /* changesets a list reads */
)

/* Manager holds the workspaces and the changesets' work in progress. */
type Manager struct {
	cfg     Config
	mu      sync.Mutex
	tokens  map[[32]byte]*workspace
	dry     map[[16]byte]*dryState /* the last dry-run of each changeset in this process */
	dryRuns map[int64][]time.Time  /* when each user started dry-runs, the last hour */
	runs    map[[16]byte]*run      /* the runs of this process */
}

/* workspace is one open workspace token. */
type workspace struct {
	user     int64
	username string
	given    time.Time
	expires  time.Time
	last     time.Time
	idle     time.Duration
}

/* New returns a manager. */
func New(cfg Config) *Manager {
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Store.Alert == nil {
		cfg.Store.Alert = cfg.Pub.Alert
	}
	m := &Manager{cfg: cfg, tokens: map[[32]byte]*workspace{}, dry: map[[16]byte]*dryState{}, dryRuns: map[int64][]time.Time{},
		runs: map[[16]byte]*run{}}
	if m.cfg.Start == nil && m.cfg.Runner != nil {
		m.cfg.Start = m.startRun
	}
	return m
}

/* Refusal is a changeset refused by a rule: a code the UI has a text for (web: 422) and what it is about. */
type Refusal struct {
	Code   string
	Device int64  /* the device it is about (0: none) */
	Step   int    /* the step (1-based) or line of the device's plan (0: none) */
	Reason string /* why, in the executor's words (never a value of the content) */
	status int
}

func (r *Refusal) Error() string {
	return fmt.Sprintf("changeset: refused (%s) device %d step %d: %s", r.Code, r.Device, r.Step, r.Reason)
}

/* RefusalCode is the code the UI has a text for. */
func (r *Refusal) RefusalCode() string { return r.Code }

/* HTTPStatus is 422, or 401 for a workspace token that is not (any longer) valid. */
func (r *Refusal) HTTPStatus() int {
	if r.status != 0 {
		return r.status
	}
	return http.StatusUnprocessableEntity
}

/* RefusalDetail is the device, step and reason, when there are any. */
func (r *Refusal) RefusalDetail() any {
	if r.Device == 0 && r.Step == 0 && r.Reason == "" {
		return nil
	}
	return map[string]any{"device_id": r.Device, "step": r.Step, "reason": r.Reason}
}

func refuse(code string) *Refusal { return &Refusal{Code: code} }

/* Refusal codes. */
const (
	CodeNoWorkspace = "no_workspace"
	CodeTooMany     = "too_many_workspaces"
	CodeBadParams   = "bad_params"
	CodeBadContent  = "bad_content"
	CodeNotFound    = "not_found"
	CodeNotAuthor   = "not_author"
	CodeConflict    = "conflict"
	CodeState       = "wrong_state"
	CodeKind        = "kind_changed"
	CodeBadLine     = "bad_line"
	CodeTampered    = "tampered"
)

/* noGroup is the group of a device the registry does not have: no grant can name it. */
const noGroup = "-unregistered"

/* Opened is the answer of open: the workspace's bearer token and its times. */
type Opened struct {
	Token       string    `json:"token"`
	Expires     time.Time `json:"expires"`
	IdleSeconds int       `json:"idle_seconds"`
}

/*
Open gives the user of req (ticket and change TOTP code) a workspace token.
The grant authz decides is write on every group the ticket's user holds a
write grant on (none: a group no grant names, so authz refuses and audits
it): opening the workspace needs a write grant, the changesets then need
theirs.
*/
func (m *Manager) Open(ctx context.Context, req authz.Request) (Opened, error) {
	pol := m.cfg.Policy()
	if !pol.Enabled() {
		return Opened{}, authz.ErrDisabled
	}
	if frozen, _ := m.cfg.Gate.Frozen(); frozen {
		return Opened{}, authz.ErrFrozen
	}
	var groups []string
	if uid, ok := m.cfg.Auth.TicketUser(req.Ticket); ok {
		if err := m.cfg.Gate.View(ctx, func(s *registry.Snapshot) error {
			for _, r := range s.Rows("write_grant") {
				u, _ := r.Get("user_id").(int64)
				k, _ := r.Get("kind").(string)
				g, _ := r.Get("write_group").(string)
				if u == uid && k == execadmin.KindWrite && g != "" {
					groups = append(groups, g)
				}
			}
			return nil
		}); err != nil {
			return Opened{}, viewErr(err)
		}
	}
	slices.Sort(groups)
	groups = slices.Compact(groups)
	if len(groups) == 0 {
		groups = []string{noGroup}
	}
	if len(groups) > 64 {
		groups = groups[:64]
	}
	req.Need = authz.Need{Kind: execadmin.KindWrite, Groups: groups}
	req.Action, req.Object = "changeset.open", "changesets"
	by, err := m.cfg.Auth.Authorize(ctx, req)
	if err != nil {
		return Opened{}, err
	}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return Opened{}, err
	}
	token := hex.EncodeToString(b[:])
	now := m.cfg.Now()
	ws := &workspace{user: by.UserID, username: by.Username, given: now, last: now,
		expires: now.Add(time.Duration(pol.Policy.SessionMinutes) * time.Minute), idle: time.Duration(pol.Policy.IdleMinutes) * time.Minute}
	m.mu.Lock()
	defer m.mu.Unlock()
	var mine []*workspace
	var oldest [32]byte
	for k, w := range m.tokens {
		switch {
		case !now.Before(w.expires) || now.Sub(w.last) >= w.idle:
			delete(m.tokens, k)
		case w.user == ws.user:
			if len(mine) == 0 || w.given.Before(m.tokens[oldest].given) {
				oldest = k
			}
			mine = append(mine, w)
		}
	}
	if len(mine) >= maxTokensPerUser {
		delete(m.tokens, oldest) /* the user's oldest workspace ends: a reloaded UI opens again */
	}
	if len(m.tokens) >= maxTokens {
		return Opened{}, refuse(CodeTooMany)
	}
	m.tokens[sha256.Sum256([]byte(token))] = ws
	return Opened{Token: token, Expires: ws.expires.UTC(), IdleSeconds: int(ws.idle / time.Second)}, nil
}

/* lookup returns the workspace of token and counts it as used. */
func (m *Manager) lookup(token string) (workspace, error) {
	h := sha256.Sum256([]byte(token))
	m.mu.Lock()
	defer m.mu.Unlock()
	w := m.tokens[h]
	now := m.cfg.Now()
	if w == nil || !now.Before(w.expires) || now.Sub(w.last) >= w.idle {
		delete(m.tokens, h)
		return workspace{}, &Refusal{Code: CodeNoWorkspace, status: http.StatusUnauthorized}
	}
	w.last = now
	return *w, nil
}

/* viewErr keeps a freeze and a refusal, and makes any other failure of the registry "try again". */
func viewErr(err error) error {
	var r *Refusal
	switch {
	case err == nil, errors.Is(err, freeze.ErrFrozen), errors.As(err, &r), errors.Is(err, authz.ErrDenied):
		return err
	}
	return fmt.Errorf("%w: %w", authz.ErrUnavailable, err)
}

/* granted checks the user's write grant on every group, bound to the user's name (as authz does). */
func granted(s *registry.Snapshot, ws workspace, groups []string) bool {
	for _, g := range groups {
		r, ok := s.Get("write_grant", ws.user, execadmin.KindWrite, g)
		if !ok {
			return false
		}
		if snap, _ := r.Get("username_snapshot").(string); snap != ws.username {
			return false
		}
	}
	return len(groups) > 0
}

/* groupsOf is the sorted write groups of ids on the snapshot (noGroup for a device the registry does not have). */
func groupsOf(s *registry.Snapshot, ids []int64) []string {
	var out []string
	for _, id := range ids {
		g := noGroup
		if d, ok := devices.Find(s, id); ok {
			g = d.Group
		}
		out = append(out, g)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

/* deviceRefusal says why device id may not be written now: the write_device row's flags, model, host key and credential. */
func deviceRefusal(s *registry.Snapshot, id int64) *Refusal {
	d, ok := devices.Find(s, id)
	code := ""
	switch {
	case !ok:
		code = "device_unknown"
	case !d.Writes:
		code = "writes_disabled"
	case d.ModelGate != devices.GateProfile:
		code = "model_unverified"
	case !d.Pinned():
		code = "no_host_key"
	}
	if code == "" {
		if _, ok := s.Get("write_credential", id); !ok {
			code = "no_credential"
		}
	}
	if code == "" {
		return nil
	}
	return &Refusal{Code: code, Device: id}
}

/* active re-checks the policy and the freeze before a decision. */
func (m *Manager) active() error {
	if !m.cfg.Policy().Enabled() {
		return authz.ErrDisabled
	}
	if frozen, _ := m.cfg.Gate.Frozen(); frozen {
		return authz.ErrFrozen
	}
	return nil
}

/*
load reads changeset id for the workspace's user: verified (a tampered one
is refused), and only when the user holds write on every group of its
devices now.
*/
func (m *Manager) load(ctx context.Context, ws workspace, id string) (Changeset, error) {
	cid, ok := ParseID(id)
	if !ok {
		return Changeset{}, refuse(CodeNotFound)
	}
	cs, err := m.cfg.Store.Load(ctx, cid)
	switch {
	case errors.Is(err, ErrNotFound):
		return Changeset{}, refuse(CodeNotFound)
	case errors.Is(err, ErrTampered):
		return Changeset{}, refuse(CodeTampered)
	case err != nil:
		return Changeset{}, fmt.Errorf("%w: %w", authz.ErrUnavailable, err)
	}
	if err := m.cfg.Gate.View(ctx, func(s *registry.Snapshot) error {
		if !granted(s, ws, groupsOf(s, cs.Content.Devices)) {
			return authz.ErrDenied
		}
		return nil
	}); err != nil {
		return Changeset{}, viewErr(err)
	}
	return cs, nil
}

/* Statuses of a changeset (execpub.changeset_summary.status). */
const (
	StatusDraft          = "draft"
	StatusDryRunOK       = "dry_run_ok"
	StatusDryRunFailed   = "dry_run_failed"
	StatusApproved       = "approved"
	StatusRunning        = "running"
	StatusDone           = "done"
	StatusRolledBack     = "rolled_back"
	StatusRollbackFailed = "rollback_failed"
	StatusInterrupted    = "interrupted"
	StatusDiscarded      = "discarded"
)

/* Event kinds. */
const (
	EventDryRun     = "dry_run"
	EventApproved   = "approved"    /* the author's approval waits for the second person */
	EventRunStarted = "run_started" /* both approvals given: the run begins (5.5) */
	EventDiscarded  = "discarded"
)

/* terminal are the statuses a run ends in (5.5 writes them as event kinds). */
var terminal = []string{StatusDone, StatusRolledBack, StatusRollbackFailed, StatusInterrupted}

/*
status is the state of cs from its events: discarded whatever the
revision; otherwise the last event of the newest revision that sets a
state (none: draft). failed is the device a run stopped on.
*/
func status(cs Changeset) (st string, failed int64) {
	st = StatusDraft
	for _, e := range cs.Events {
		if e.Kind == EventDiscarded {
			return StatusDiscarded, failed
		}
		if e.Rev != cs.Rev {
			continue
		}
		switch {
		case e.Kind == EventDryRun:
			var p struct {
				OK bool `json:"ok"`
			}
			st = StatusDryRunFailed
			if json.Unmarshal(e.Payload, &p) == nil && p.OK {
				st = StatusDryRunOK
			}
		case e.Kind == EventApproved:
			st = StatusApproved
		case e.Kind == EventRunStarted:
			st = StatusRunning
		case slices.Contains(terminal, e.Kind):
			st = e.Kind
			if e.Kind != StatusDone && e.Device > 0 {
				failed = e.Device
			}
		}
	}
	return st, failed
}

/* publish writes the panel's row of cs (a failure is logged: the panel's list is not a decision). */
func (m *Manager) publish(ctx context.Context, cs Changeset) {
	st, failed := status(cs)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), opTime)
	defer cancel()
	if err := m.cfg.Pub.ChangesetSummary(ctx, pub.ChangesetSummary{ID: cs.ID, Author: cs.Author, Kind: cs.Kind, Title: cs.Content.Title,
		Status: st, Devices: cs.Content.Devices, Created: cs.Created, Failed: failed}); err != nil {
		m.cfg.Log.Warn("changeset: summary not published", slog.String("changeset", IDString(cs.ID)), slog.String("err", err.Error()))
	}
}

/* record writes an audit row of the workspace's user about changeset id. */
func (m *Manager) record(ctx context.Context, ws workspace, action, id, result string, details map[string]any) {
	uid := ws.user
	m.cfg.Auth.Record(ctx, audit.Event{UserID: &uid, Action: action, Object: "changeset:" + id, Result: result, Details: details})
}

/* strict decodes params into v: no unknown fields, no trailing data; empty params are {}. */
func strict(params json.RawMessage, v any) error {
	if len(params) == 0 {
		params = json.RawMessage("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(params))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return refuse(CodeBadParams)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return refuse(CodeBadParams)
	}
	return nil
}
