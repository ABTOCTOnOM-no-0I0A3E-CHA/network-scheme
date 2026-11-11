/*
Package session opens and closes change sessions (security.md 5.3, Task
4c.2). A session is one user's write connection to at most
max_devices_per_session devices, held under a bearer token that the
executor UI keeps in memory. Opening checks, in this order, on the verified
registry and the host's policy only (the api's data never allows anything):
the policy enables the executor, nothing is frozen, the policy's windows,
device limit and two-person groups allow it (a two-person group or a window
that needs a second person opens only with a second person's approval,
approve.go; Phase 4 refused it), the user's change TOTP and
write grants on every device's group (authz), then per device
writes_enabled, a model profile of its line, a pinned host key and a write
credential.

Per device, in this order and under the device's lease (backups.Locks, so
the executor never has two connections to it): execpub.device_busy from the
verified write_device row (the poller opens no SSH to its id, address or host
key), the pre-session snapshot over a ReadOnly connection
(backups.Scheduler.BeforeSession: a 'pre_session' config_version) recorded
in exec.session_device under the executor's MAC, the Write connection
(transport: host key, model gate, ESR exclusivity), the policy's rules for
the line (core.NewRules: an error refuses and alerts), the management context
(mgmt.go) and the driver session (drivers.WriteDriver.Open: the MES 10.x
flash snapshot), whose own pre-session read must hash as the snapshot.
Anything that fails undoes what was opened.

A session lasts session_minutes (extend: a new TOTP) and ends after
idle_minutes without use; a device whose connection drops ends the session
as interrupted (alert session_interrupted, the snapshot stays for a
rollback). A restarted executor finds every session without an end event
and ends it as interrupted (Recover), and frees every device_busy row of the
previous process.
*/
package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/cmd/executor/internal/approval"
	"github.com/beekamai/network-scheme/cmd/executor/internal/audit"
	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/backups"
	"github.com/beekamai/network-scheme/cmd/executor/internal/devices"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/cmd/executor/internal/identify"
	"github.com/beekamai/network-scheme/cmd/executor/internal/policy"
	"github.com/beekamai/network-scheme/cmd/executor/internal/pub"
	"github.com/beekamai/network-scheme/cmd/executor/internal/recording"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/strategy"
	"github.com/beekamai/network-scheme/cmd/executor/internal/transport"
	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/execadmin"
	"github.com/beekamai/network-scheme/internal/execpolicy"
	"github.com/beekamai/network-scheme/internal/ssh"
)

/* Alert kinds (internal/triggers). */
const (
	KindInterrupted   = "session_interrupted"     /* high: a device's connection dropped, or the executor restarted */
	KindOutsideWindow = "session_outside_window"  /* warning */
	KindPolicyInvalid = "executor_policy_invalid" /* high: the policy's rules do not fit a line's grammar */
	KindTamper        = "executor_session_tamper" /* high: a session row fails its MAC (no freeze: the registry is not involved) */
)

/* Statuses of execpub.session_summary. */
const (
	StatusClosed      = "closed"
	StatusTimeout     = "timeout"
	StatusInterrupted = "interrupted"
)

/* Refusal is a session refused by a rule, with the code the UI has a text for (web: 422). */
type Refusal string

/* Error and RefusalCode make a Refusal an error with a code (web.Refusal). */
func (r Refusal) Error() string { return "session: refused (" + string(r) + ")" }

/* RefusalCode is the code the UI has a text for. */
func (r Refusal) RefusalCode() string { return string(r) }

/* Refusals. */
const (
	ErrBadDevices      Refusal = "bad_devices"
	ErrTooManyDevices  Refusal = "too_many_devices"
	ErrOutsideWindow   Refusal = "outside_window"
	ErrTwoPerson       Refusal = "two_person"
	ErrWritesDisabled  Refusal = "writes_disabled"
	ErrModelUnverified Refusal = "model_unverified"
	ErrNoHostKey       Refusal = "no_host_key"
	ErrHostKey         Refusal = "host_key_mismatch"
	ErrNoCredential    Refusal = "no_credential" // #nosec G101 -- a refusal code, not a secret
	ErrBusy            Refusal = "device_busy"
	ErrNotExclusive    Refusal = "not_exclusive"
	ErrLineMismatch    Refusal = "line_mismatch"
	ErrPolicyRules     Refusal = "policy_invalid"
	ErrMgmt            Refusal = "mgmt_unknown"
	ErrChanged         Refusal = "config_changed"
	ErrDevice          Refusal = "device_failed"
	ErrNoSession       Refusal = "no_session"
	ErrRecording       Refusal = "recording_failed" /* the device's recording could not start */
)

/* maxDevices bounds a request whatever the policy says. */
const maxDevices = 64

/* Timing (variables for the tests). */
var (
	tick        = 5 * time.Second  /* how often limits and connections are checked */
	deviceTime  = 5 * time.Minute  /* bound of opening one device */
	closeTime   = 2 * time.Minute  /* bound of closing one device */
	recordTime  = 10 * time.Second /* bound of one database statement */
	recoverPage = 100              /* session rows Recover reads at a time */
)

/* Gate is the decision path: *freeze.Guard. */
type Gate interface {
	View(ctx context.Context, fn func(*registry.Snapshot) error) error
	Frozen() (bool, string)
}

/* Authorizer is what a session needs of authz.Authorizer. */
type Authorizer interface {
	Authorize(ctx context.Context, req authz.Request) (authz.Decision, error)
	Record(ctx context.Context, ev audit.Event)
}

/* Publisher is what a session needs of pub.Publisher. */
type Publisher interface {
	Busy(ctx context.Context, dev registry.Row, session [16]byte) error
	Free(ctx context.Context, deviceID int64, session [16]byte) error
	SessionOpened(ctx context.Context, session [16]byte, userID, deviceID int64, openedAt time.Time) error
	SessionClosed(ctx context.Context, session [16]byte, deviceID int64, status string, post []byte) error
	Alert(ctx context.Context, kind, severity string, deviceID int64, text string) error
	Recover(ctx context.Context) error
}

/* Backups is the pre-session snapshot: *backups.Scheduler. */
type Backups interface {
	BeforeSession(ctx context.Context, le *backups.Lease, left func(context.Context, [32]byte) (bool, error)) (backups.Pre, error)
}

/* Config builds a Manager; every field but Log and Now is required. */
type Config struct {
	Gate    Gate
	Auth    Authorizer
	Policy  func() policy.State
	Pool    *pgxpool.Pool
	MAC     *[32]byte /* seal.Keys.MAC: the rows of exec.session* */
	Net     transport.Dialer
	Open    func(s *registry.Snapshot, deviceID int64) (creds.Credential, error) /* wcreds.Store.Open */
	Backups Backups
	Locks   *backups.Locks /* the scheduler's: one connection per device */
	Pub     Publisher
	/* BackupPriv and BackupPub open the pre-session envelopes for a rollback (backup_key_file). */
	BackupPriv, BackupPub *[32]byte
	/* Recordings records every device of a session (*recording.Store); without it no device opens. */
	Recordings Recordings
	/* Approvals holds the second persons' approvals (in memory); nil: a session that needs one is refused (two_person). */
	Approvals *approval.Store
	Log       *slog.Logger
	Now       func() time.Time
}

/* Manager holds the open sessions. */
type Manager struct {
	cfg      Config
	mu       sync.Mutex
	sessions map[[16]byte]*Session
	/* interrupted are ended sessions with a device whose driver session was not closed: the rollback of 4c.4 */
	interrupted map[[16]byte]*Session
	stopped     bool /* Run has ended: no session registers any more */
	/* lastOpen is when a session last began opening each device, in this process: the superseded check's second source beside exec */
	lastOpen map[int64]time.Time
}

/* openedAfter reports whether a session of this process began opening device after t. */
func (m *Manager) openedAfter(device int64, t time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastOpen[device].After(t)
}

/* New returns a manager. */
func New(cfg Config) *Manager {
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Manager{cfg: cfg, sessions: map[[16]byte]*Session{}, interrupted: map[[16]byte]*Session{}, lastOpen: map[int64]time.Time{}}
}

/*
Session is an open change session. Use holds mu while it works with the
devices (4c.3, 4c.4), so ending waits for a command in flight.
*/
type Session struct {
	ID       [16]byte
	User     int64
	Username string
	Opened   time.Time
	Devices  []*Device
	mu       sync.Mutex

	/* guarded by Manager.mu */
	token   [32]byte /* SHA-256 of the bearer token */
	expires time.Time
	idle    time.Duration
	last    time.Time
	ended   bool
	endedAt time.Time
}

/* Device is one device of a session. */
type Device struct {
	ID      int64
	Line    strategy.Line
	Driver  drivers.WriteDriver
	Session drivers.Session /* Session.Pre() is the only rollback target (4c.4) */
	Pre     [32]byte        /* exec.session_device.pre_sha256 */
	/*
		Shown, as the registry and the device itself named them at open (the
		panel only asked for the id): the verified write_device row's
		address:port and write group, and the model and firmware of show version.
	*/
	Address, Group, Model, Firmware string

	sh      *transport.Shell
	rec     *recording.Stream /* the device's recording, from its open to its end */
	lease   *backups.Lease
	busy    bool
	summary bool
	/* guarded by Session.mu */
	pending  time.Time /* ESR: the confirm timer's end of a commit not yet confirmed */
	reloadIn int       /* MES: the reload-in safety net armed at open, minutes (0: none) */
	closed   bool      /* the driver session was closed */
}

/* Lock serializes the use of a session's devices (Unlock ends it). */
func (s *Session) Lock() { s.mu.Lock() }

/* Unlock ends a use begun by Lock. */
func (s *Session) Unlock() { s.mu.Unlock() }

/* Opened is the answer of Open, Attach and Extend. */
type Opened struct {
	ID          string         `json:"session_id"`
	Token       string         `json:"token,omitempty"`
	Expires     time.Time      `json:"expires"`
	IdleSeconds int            `json:"idle_seconds"`
	Devices     []OpenedDevice `json:"devices"`
}

/*
OpenedDevice is a device of an open session: what the user checks against
the device they meant (the panel chose only the id). Address and group come
from the verified write_device row, model and firmware from the device's
own show version; nothing comes from core.device.
*/
type OpenedDevice struct {
	ID        int64  `json:"device_id"`
	Line      string `json:"line"`
	PreSHA256 string `json:"pre_sha256"`
	Address   string `json:"address"`
	Group     string `json:"write_group"`
	Model     string `json:"model"`
	Firmware  string `json:"firmware"`
}

/* IDString is a session id as a UUID. */
func IDString(id [16]byte) string {
	h := hex.EncodeToString(id[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

/* ParseID reads a session id written by IDString. */
func ParseID(s string) ([16]byte, bool) {
	var id [16]byte
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 || IDString([16]byte(b)) != s {
		return id, false
	}
	return [16]byte(b), true
}

func (m *Manager) refuse(ctx context.Context, req authz.Request, user int64, object string, err error, class string) error {
	ev := audit.Event{Action: "session.open", Object: object, Result: audit.Denied, IP: req.IP, UA: req.UA,
		Details: map[string]any{"class": class}}
	if user > 0 {
		ev.UserID = &user
	}
	m.cfg.Auth.Record(ctx, ev)
	return err
}

func object(ids []int64) string {
	s := make([]string, len(ids))
	for i, id := range ids {
		s[i] = strconv.FormatInt(id, 10)
	}
	return "devices:" + strings.Join(s, ",")
}

/*
Open opens a session on ids for the user of req (ticket and change TOTP
code). Before authz only the request's shape, the policy's enabled flag and
the freeze are checked: nothing about the devices or the user is told,
alerted or audited under the user's name before the TOTP code passed. A
device the registry does not have needs a grant no one has, so it is
refused by authz like a missing grant. See the package comment for the
order of the checks after authz.
*/
func (m *Manager) Open(ctx context.Context, req authz.Request, ids []int64) (Opened, error) {
	return m.OpenApproved(ctx, req, ids, "")
}

/*
OpenApproved is Open with the id of a second person's approval (approve.go):
a session that needs a second person (a group of two_person_groups, or
outside every window with outside_window: second_person) opens only with
it, spent here whatever the outcome; without it, two_person as in Phase 4.
*/
func (m *Manager) OpenApproved(ctx context.Context, req authz.Request, ids []int64, approvalID string) (Opened, error) {
	obj := object(ids)
	if len(ids) == 0 || len(ids) > maxDevices || slices.ContainsFunc(ids, func(id int64) bool { return id <= 0 }) ||
		len(slices.Compact(slices.Sorted(slices.Values(ids)))) != len(ids) {
		return Opened{}, ErrBadDevices
	}
	pol := m.cfg.Policy()
	if !pol.Enabled() {
		return Opened{}, authz.ErrDisabled
	}
	if frozen, _ := m.cfg.Gate.Frozen(); frozen {
		return Opened{}, authz.ErrFrozen
	}
	groups := map[int64]string{}
	if err := m.cfg.Gate.View(ctx, func(s *registry.Snapshot) error {
		for _, id := range ids {
			groups[id] = noGroup
			if r, ok := s.Get("write_device", id); ok {
				groups[id], _ = r.Get("write_group").(string)
			}
		}
		return nil
	}); err != nil {
		return Opened{}, viewErr(err)
	}
	var need []string
	for _, g := range groups {
		need = append(need, g)
	}
	slices.Sort(need)
	req.Need = authz.Need{Kind: execadmin.KindWrite, Groups: slices.Compact(need)}
	req.Action, req.Object = "session.open", obj
	by, err := m.cfg.Auth.Authorize(ctx, req)
	if err != nil {
		return Opened{}, err
	}
	p := pol.Policy
	if len(ids) > p.MaxDevicesPerSession {
		return Opened{}, m.refuse(ctx, req, by.UserID, obj, ErrTooManyDevices, "too_many_devices")
	}
	reason, err := m.secondReason(ctx, by.UserID, obj, p, req.Need.Groups)
	if err != nil {
		return Opened{}, m.refuse(ctx, req, by.UserID, obj, err, "outside_window")
	}
	var appr *approval.Approval
	if reason != "" {
		a, err := m.takeApproval(ctx, approvalID, by, ids, reason)
		if err != nil {
			return Opened{}, m.refuse(ctx, req, by.UserID, obj, err, refusalCode(err))
		}
		appr = &a
	}
	if err := m.preflight(ctx, ids, pol.Policy); err != nil {
		if r := Refusal(""); errors.As(err, &r) {
			return Opened{}, m.refuse(ctx, req, by.UserID, obj, err, string(r))
		}
		return Opened{}, err
	}
	o, err := m.open(ctx, req, by, ids, pol)
	if err == nil && appr != nil {
		sid, _ := ParseID(o.ID)
		m.event(ctx, sid, "approved", map[string]any{"by": appr.By, "request": appr.ID, "reason": reason, "challenge": appr.ByChal})
	}
	return o, err
}

/* noGroup is the group of a device the registry does not have: no grant can name it (write groups start with a letter or digit). */
const noGroup = "-unregistered"

/* InWindow is inWindow for changesets (Phase 5): the windows of the sessions. */
func InWindow(t time.Time, p execpolicy.Policy) bool { return inWindow(t, p) }

/* inWindow reports whether t is in a change window of p (no window: always); a zone that does not load is outside (fail closed). */
func inWindow(t time.Time, p execpolicy.Policy) bool {
	if len(p.Windows) == 0 {
		return true
	}
	loc, err := time.LoadLocation(p.Timezone)
	if err != nil {
		return false
	}
	t = t.In(loc)
	day, clock := strings.ToLower(t.Weekday().String()[:3]), t.Format("15:04")
	for _, w := range p.Windows {
		if slices.Contains(w.Days, day) && clock >= w.Start && clock < w.End {
			return true
		}
	}
	return false
}

/* preflight checks every device on a fresh verified snapshot: writes_enabled, model profile, host key, write credential, policy rules. */
func (m *Manager) preflight(ctx context.Context, ids []int64, p execpolicy.Policy) error {
	return viewErr(m.cfg.Gate.View(ctx, func(s *registry.Snapshot) error {
		for _, id := range ids {
			if err := deviceAllowed(s, id); err != nil {
				return err
			}
		}
		for _, id := range ids {
			d, _ := devices.Find(s, id)
			if _, err := m.rules(ctx, strategy.Line(d.Driver), p, id); err != nil {
				return err
			}
		}
		return nil
	}))
}

/* deviceAllowed: the write_device row's flags, a model profile of its line, its host key and its credential. */
func deviceAllowed(s *registry.Snapshot, id int64) error {
	d, ok := devices.Find(s, id)
	switch {
	case !ok:
		return authz.ErrDenied
	case !d.Writes:
		return ErrWritesDisabled
	case d.ModelGate != devices.GateProfile:
		return ErrModelUnverified
	case !d.Pinned():
		return ErrNoHostKey
	}
	if _, ok := s.Get("write_credential", id); !ok {
		return ErrNoCredential
	}
	return nil
}

/* rules builds the policy's rules for a line; an error refuses the session and raises executor_policy_invalid. */
func (m *Manager) rules(ctx context.Context, line strategy.Line, p execpolicy.Policy, device int64) (core.Rules, error) {
	drv, ok := drivers.For(line)
	if !ok {
		return core.Rules{}, ErrLineMismatch
	}
	r, err := core.NewRules(drv.Grammar(), string(line), p.ClassOverrides)
	if err != nil {
		m.alert(ctx, KindPolicyInvalid, "high", device, "the policy's class overrides do not fit the "+string(line)+" grammar: "+err.Error())
		return core.Rules{}, ErrPolicyRules
	}
	return r, nil
}

func (m *Manager) alert(ctx context.Context, kind, sev string, device int64, text string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTime)
	defer cancel()
	if err := m.cfg.Pub.Alert(ctx, kind, sev, device, text); err != nil {
		m.cfg.Log.Warn("session: alert not published", slog.String("kind", kind), slog.String("err", err.Error()))
	}
}

/* viewErr keeps a freeze and a refusal, and makes any other failure of the registry "try again". */
func viewErr(err error) error {
	var r Refusal
	switch {
	case err == nil, errors.Is(err, freeze.ErrFrozen), errors.As(err, &r), errors.Is(err, authz.ErrDenied):
		return err
	}
	return fmt.Errorf("%w: %w", authz.ErrUnavailable, err)
}

func (m *Manager) open(ctx context.Context, req authz.Request, by authz.Decision, ids []int64, pol policy.State) (Opened, error) {
	s := &Session{User: by.UserID, Username: by.Username, Opened: m.cfg.Now().UTC().Truncate(time.Microsecond)}
	if _, err := rand.Read(s.ID[:]); err != nil {
		return Opened{}, err
	}
	s.ID[6], s.ID[8] = s.ID[6]&0x0f|0x40, s.ID[8]&0x3f|0x80 /* UUID v4 */
	if err := m.insertSession(ctx, s, pol); err != nil {
		return Opened{}, fmt.Errorf("%w: %w", authz.ErrUnavailable, err)
	}
	for _, id := range ids {
		d, err := m.openDevice(ctx, s, id, pol.Policy)
		if d != nil {
			s.Devices = append(s.Devices, d)
		}
		if err != nil {
			m.cfg.Log.Info("session: device not opened", slog.String("session", IDString(s.ID)), slog.Int64("device_id", id),
				slog.String("err", err.Error()))
			m.finish(ctx, s, "aborted", nil)
			r := deviceRefusal(err)
			return Opened{}, m.refuse(ctx, req, by.UserID, object(ids), r, "device:"+strconv.FormatInt(id, 10)+":"+refusalClass(r))
		}
	}
	for _, d := range s.Devices {
		if err := m.cfg.Pub.SessionOpened(ctx, s.ID, s.User, d.ID, s.Opened); err != nil {
			m.finish(ctx, s, "aborted", nil)
			return Opened{}, fmt.Errorf("%w: %w", authz.ErrUnavailable, err)
		}
		d.summary = true
	}
	token, err := newToken()
	if err != nil {
		m.finish(ctx, s, "aborted", nil)
		return Opened{}, err
	}
	now := m.cfg.Now()
	m.mu.Lock()
	s.token, s.last, s.idle = sha256.Sum256([]byte(token)), now, time.Duration(pol.Policy.IdleMinutes)*time.Minute
	s.expires = now.Add(time.Duration(pol.Policy.SessionMinutes) * time.Minute)
	if m.stopped {
		m.mu.Unlock()
		m.finish(ctx, s, "aborted", nil) /* Run has ended: nothing would ever time this session out */
		return Opened{}, authz.ErrUnavailable
	}
	m.sessions[s.ID] = s
	m.mu.Unlock()
	return m.opened(s, token), nil
}

func refusalClass(err error) string {
	if r := Refusal(""); errors.As(err, &r) {
		return string(r)
	}
	return "frozen"
}

/* deviceRefusal maps why a device did not open to what the user is told. */
func deviceRefusal(err error) error {
	var r Refusal
	switch {
	case errors.As(err, &r):
		return r
	case errors.Is(err, freeze.ErrFrozen):
		return authz.ErrFrozen
	case errors.Is(err, transport.ErrHostKeyMismatch):
		return ErrHostKey
	case errors.Is(err, transport.ErrModelUnverified):
		return ErrModelUnverified
	case errors.Is(err, transport.ErrWritesDisabled):
		return ErrWritesDisabled
	case errors.Is(err, transport.ErrNotExclusive):
		return ErrNotExclusive
	case errors.Is(err, identify.ErrLineMismatch):
		return ErrLineMismatch
	case errors.Is(err, transport.ErrNotRegistered):
		return authz.ErrDenied
	case errors.Is(err, errMgmt):
		return ErrMgmt
	}
	return ErrDevice
}

func newToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func (m *Manager) opened(s *Session, token string) Opened {
	m.mu.Lock()
	o := Opened{ID: IDString(s.ID), Token: token, Expires: s.expires.UTC(), IdleSeconds: int(s.idle / time.Second)}
	m.mu.Unlock()
	for _, d := range s.Devices {
		o.Devices = append(o.Devices, OpenedDevice{ID: d.ID, Line: string(d.Line), PreSHA256: hex.EncodeToString(d.Pre[:]),
			Address: d.Address, Group: d.Group, Model: d.Model, Firmware: d.Firmware})
	}
	return o
}

/*
openDevice opens device id for s (see the package comment). The returned
Device, also on error, holds what was opened, for finish to undo.
*/
func (m *Manager) openDevice(ctx context.Context, s *Session, id int64, p execpolicy.Policy) (*Device, error) {
	ctx, cancel := context.WithTimeout(ctx, deviceTime)
	defer cancel()
	le, ok := m.cfg.Locks.TryLock(id)
	if !ok {
		return nil, ErrBusy
	}
	d := &Device{ID: id, lease: le}
	m.mu.Lock()
	m.lastOpen[id] = s.Opened
	m.mu.Unlock()
	var (
		row     registry.Row
		address netip.Addr
	)
	err := m.cfg.Gate.View(ctx, func(snap *registry.Snapshot) error {
		if err := deviceAllowed(snap, id); err != nil {
			return err
		}
		row, _ = snap.Get("write_device", id)
		address, _ = row.Get("address").(netip.Addr)
		port, _ := row.Get("port").(int64)
		if !address.IsValid() || port < 1 || port > 65535 {
			return authz.ErrDenied
		}
		d.Address = netip.AddrPortFrom(address, uint16(port)).String() // #nosec G115 -- checked above
		d.Group, _ = row.Get("write_group").(string)
		return nil
	})
	if err != nil {
		return d, err
	}
	switch err := m.cfg.Pub.Busy(ctx, row, s.ID); {
	case err == nil:
		d.busy = true
	case errors.Is(err, pub.ErrDeviceBusy):
		return d, ErrBusy
	default:
		return d, err
	}
	pre, err := m.cfg.Backups.BeforeSession(ctx, le, func(ctx context.Context, sum [32]byte) (bool, error) { return m.sessionLeft(ctx, id, sum) })
	if err != nil {
		return d, fmt.Errorf("pre-session snapshot: %w", err)
	}
	d.Pre = pre.SHA256
	if err := m.insertDevice(ctx, s.ID, id, pre); err != nil {
		return d, err
	}
	/*
		The recording right after its session_device row, before anything can
		fail (an abort then ends it with its manifest, never a recording without
		one). drivers.Mask is every line's MaskSecrets (drivers.Base).
	*/
	if m.cfg.Recordings == nil {
		return d, ErrRecording
	}
	if d.rec, err = m.cfg.Recordings.Open(ctx, s.ID, id, s.Username, drivers.Mask); err != nil {
		m.cfg.Log.Error("session: recording not started", slog.Int64("device_id", id), slog.String("err", err.Error()))
		return d, ErrRecording
	}
	if d.sh, err = m.dial(ctx, id, transport.Write); err != nil {
		return d, err
	}
	d.Line = d.sh.Line()
	d.Model, d.Firmware = d.sh.Identity().Model, d.sh.Identity().Firmware
	drv, ok := drivers.For(d.Line)
	if !ok {
		return d, ErrLineMismatch
	}
	d.Driver = drv
	rules, err := m.rules(ctx, d.Line, p, id)
	if err != nil {
		return d, err
	}
	mgmt, err := m.mgmt(ctx, d, pre.Text, address)
	if err != nil {
		return d, err
	}
	o := drivers.Options{SessionID: IDString(s.ID), Context: core.Context{Mgmt: mgmt, Rules: rules}, Alert: m.cfg.Pub.Alert,
		CommitTimeout: time.Duration(p.ESRCommitTimerS) * time.Second}
	if p.MESReloadInMin > 0 && d.Line != strategy.ESR {
		o.Strategies = drv.Strategies()
		o.Strategies.SafetyNet, o.Strategies.ReloadMinutes = "reload-in", p.MESReloadInMin
		d.reloadIn = p.MESReloadInMin
	}
	if d.Session, err = drv.Open(ctx, d.sh, o); err != nil {
		return d, err
	}
	if d.Session.Pre().SHA256 != pre.SHA256 {
		return d, ErrChanged /* the configuration changed between the snapshot and the session */
	}
	return d, nil
}

/* dial connects to device id with its write credential, after the registry allows it again. */
func (m *Manager) dial(ctx context.Context, id int64, access transport.Access) (*transport.Shell, error) {
	var c creds.Credential
	if err := m.cfg.Gate.View(ctx, func(snap *registry.Snapshot) error {
		if err := deviceAllowed(snap, id); err != nil {
			return err
		}
		var err error
		c, err = m.cfg.Open(snap, id)
		return err
	}); err != nil {
		return nil, err
	}
	defer c.Wipe()
	return transport.Dial(ctx, transport.Config{DeviceID: id, Access: access, Registry: m.cfg.Gate, Net: m.cfg.Net,
		Alert:      m.cfg.Pub.Alert,
		Credential: transport.Credential{Username: c.Username, Password: c.Password, PrivateKey: c.PrivateKey}})
}

/* mgmt reads the device's ARP and MAC tables (read allowlist) and builds the management context. */
func (m *Manager) mgmt(ctx context.Context, d *Device, config string, address netip.Addr) ([]core.Target, error) {
	arp, err := d.sh.Run(ctx, ssh.ShowCommand{Name: "show arp"})
	if err != nil {
		return nil, fmt.Errorf("%w: show arp: %w", errMgmt, err)
	}
	macs, err := d.sh.Run(ctx, ssh.ShowCommand{Name: "show mac address-table", LongOutput: true})
	if err != nil {
		return nil, fmt.Errorf("%w: show mac address-table: %w", errMgmt, err)
	}
	return mgmtTargets(d.Driver, config, address, d.sh.LocalAddr(), arp.Text(), macs.Text())
}

/*
Lookup returns the open session id whose bearer token is token and counts
it as used (the idle timer starts again).
*/
func (m *Manager) Lookup(id, token string) (*Session, error) {
	sid, ok := ParseID(id)
	if !ok {
		return nil, ErrNoSession
	}
	h := sha256.Sum256([]byte(token))
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[sid]
	now := m.cfg.Now()
	if s == nil || s.ended || subtle.ConstantTimeCompare(h[:], s.token[:]) != 1 || !now.Before(s.expires) || now.Sub(s.last) >= s.idle {
		return nil, ErrNoSession /* past its time: Run ends it */
	}
	s.last = now
	return s, nil
}

/*
Use runs fn on the open session id of token (Lookup) with the session
locked, only while it has not ended: the way 4c.3 and 4c.4 reach its
devices. fn re-Views the registry and the freeze before each decision.
*/
func (m *Manager) Use(id, token string, fn func(*Session) error) error {
	s, err := m.Lookup(id, token)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m.mu.Lock()
	ended := s.ended
	m.mu.Unlock()
	if ended {
		return ErrNoSession
	}
	return fn(s)
}

/* owned authorizes an action of the session's own user on it: ticket, new change TOTP, the write grants of its devices' groups. */
func (m *Manager) owned(ctx context.Context, id, action string, req authz.Request) (*Session, error) {
	sid, ok := ParseID(id)
	if !ok {
		return nil, ErrNoSession
	}
	m.mu.Lock()
	s := m.sessions[sid]
	m.mu.Unlock()
	if s == nil {
		return nil, ErrNoSession
	}
	var groups []string
	if err := m.cfg.Gate.View(ctx, func(snap *registry.Snapshot) error {
		for _, d := range s.Devices {
			r, ok := snap.Get("write_device", d.ID)
			if !ok {
				return authz.ErrDenied
			}
			g, _ := r.Get("write_group").(string)
			groups = append(groups, g)
		}
		return nil
	}); err != nil {
		return nil, viewErr(err)
	}
	slices.Sort(groups)
	req.Need = authz.Need{Kind: execadmin.KindWrite, Groups: slices.Compact(groups)}
	req.Action, req.Object, req.User = action, "session:"+id, s.User
	if _, err := m.cfg.Auth.Authorize(ctx, req); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if now := m.cfg.Now(); s.ended || !now.Before(s.expires) || now.Sub(s.last) >= s.idle {
		return nil, ErrNoSession
	}
	s.last = m.cfg.Now()
	return s, nil
}

/* Attach gives the session's user a new token for it (a reloaded executor UI): the old one stops working. */
func (m *Manager) Attach(ctx context.Context, id string, req authz.Request) (Opened, error) {
	s, err := m.owned(ctx, id, "session.attach", req)
	if err != nil {
		return Opened{}, err
	}
	token, err := newToken()
	if err != nil {
		return Opened{}, err
	}
	m.mu.Lock()
	s.token = sha256.Sum256([]byte(token))
	m.mu.Unlock()
	m.event(ctx, s.ID, "attached", map[string]any{})
	return m.opened(s, token), nil
}

/* Extend sets the session's end to session_minutes from now (a new change TOTP). */
func (m *Manager) Extend(ctx context.Context, id string, req authz.Request) (Opened, error) {
	s, err := m.owned(ctx, id, "session.extend", req)
	if err != nil {
		return Opened{}, err
	}
	pol := m.cfg.Policy()
	if !pol.Enabled() {
		return Opened{}, authz.ErrDisabled
	}
	m.mu.Lock()
	s.expires = m.cfg.Now().Add(time.Duration(pol.Policy.SessionMinutes) * time.Minute)
	m.mu.Unlock()
	m.event(ctx, s.ID, "extended", map[string]any{})
	return m.opened(s, ""), nil
}

/* Close ends the session whose token is token. */
func (m *Manager) Close(ctx context.Context, id, token string) error {
	s, err := m.Lookup(id, token)
	if err != nil {
		return err
	}
	m.finish(ctx, s, "closed", nil)
	return nil
}

/*
Run ends sessions past their end or idle time (timeout), sessions with a
device whose connection dropped (interrupted, that device), and every
session while the executor is frozen or disabled; when ctx ends, it ends
the sessions left (interrupted: the executor stops) and returns.
*/
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			m.mu.Lock()
			m.stopped = true
			m.mu.Unlock()
			for _, s := range m.live() {
				m.finish(ctx, s, "shutdown", nil)
			}
			return
		case <-t.C:
			m.check(ctx)
		}
	}
}

func (m *Manager) live() []*Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, s)
	}
	return out
}

func (m *Manager) check(ctx context.Context) {
	frozen, _ := m.cfg.Gate.Frozen()
	enabled := m.cfg.Policy().Enabled()
	now := m.cfg.Now()
	for _, s := range m.live() {
		lost := map[int64]bool{}
		for _, d := range s.Devices {
			select {
			case <-d.done():
				lost[d.ID] = true
			default:
			}
		}
		m.mu.Lock()
		over := !now.Before(s.expires) || now.Sub(s.last) >= s.idle
		m.mu.Unlock()
		switch {
		case len(lost) > 0:
			m.finish(ctx, s, "interrupted", lost)
		case frozen:
			m.finish(ctx, s, "frozen", nil)
		case !enabled:
			m.finish(ctx, s, "disabled", nil)
		case over:
			m.finish(ctx, s, "timeout", nil)
		}
	}
}

/*
finish ends s once: every device is closed (the driver session, the
connection), its summary ended, its device_busy row freed and its lease
released, then the end event. why: closed, timeout, interrupted (lost names
the devices whose connection dropped), shutdown (the executor stops: every
device interrupted), frozen and disabled (interrupted, MES safety net kept),
aborted (the open failed).
*/
func (m *Manager) finish(ctx context.Context, s *Session, why string, lost map[int64]bool) {
	m.mu.Lock()
	if s.ended {
		m.mu.Unlock()
		return
	}
	s.ended, s.endedAt = true, m.cfg.Now()
	delete(m.sessions, s.ID)
	m.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	defer m.keep(s)
	ctx = context.WithoutCancel(ctx)
	for _, d := range s.Devices {
		status := StatusClosed
		switch {
		case why == "timeout":
			status = StatusTimeout
		case why == "shutdown", why == "frozen", why == "disabled", lost[d.ID]:
			status = StatusInterrupted
		}
		/*
			Frozen or disabled: the executor must not act, so a MES session keeps
			its reload-in safety net armed (no driver Close); ESR restores the
			unconfirmed candidate. Either way the rollback is offered.
		*/
		keep := (why == "frozen" || why == "disabled") && d.Line != strategy.ESR
		label := "session ended: " + why
		if lost[d.ID] {
			label = "session interrupted: the connection to the device dropped"
		}
		m.closeDevice(ctx, s, d, status, !lost[d.ID] && !keep, label)
	}
	kind := "closed"
	if why != "closed" && why != "timeout" && why != "aborted" {
		kind = "interrupted"
	}
	m.event(ctx, s.ID, kind, map[string]any{"reason": why})
	user := s.User
	m.cfg.Auth.Record(ctx, audit.Event{UserID: &user, Action: "session.close", Object: "session:" + IDString(s.ID), Result: audit.OK,
		Details: map[string]any{"reason": why}})
}

/*
closeDevice closes one device; reachable: its connection is up and the
driver closes (the configuration after is read). Its recording ends with
label and its manifest.
*/
func (m *Manager) closeDevice(ctx context.Context, s *Session, d *Device, status string, reachable bool, label string) {
	ctx, cancel := context.WithTimeout(ctx, closeTime)
	defer cancel()
	var post []byte
	if d.Session != nil && reachable {
		d.closed = true
		if err := d.Session.Close(ctx); err != nil {
			m.cfg.Log.Warn("session: driver close failed", slog.Int64("device_id", d.ID), slog.String("err", err.Error()))
		} else if out, err := d.sh.Run(ctx, ssh.ShowCommand{Name: "show running-config", LongOutput: true}); err == nil {
			c := drivers.NewConfig(out.Text())
			post = c.SHA256[:]
		}
	}
	if d.sh != nil {
		_ = d.sh.Close()
	}
	if d.rec != nil {
		if err := d.rec.Close(ctx, label); err != nil {
			m.cfg.Log.Error("session: recording not completed", slog.Int64("device_id", d.ID), slog.String("err", err.Error()))
		}
	}
	if d.summary {
		if err := m.cfg.Pub.SessionClosed(ctx, s.ID, d.ID, status, post); err != nil {
			m.cfg.Log.Warn("session: summary not closed", slog.Int64("device_id", d.ID), slog.String("err", err.Error()))
		}
	}
	if d.busy {
		if err := m.cfg.Pub.Free(ctx, d.ID, s.ID); err != nil {
			m.cfg.Log.Error("session: device_busy not freed (Recover frees it at the next start)", slog.Int64("device_id", d.ID),
				slog.String("err", err.Error()))
		}
	}
	d.lease.Release()
	if status == StatusInterrupted {
		offer := "a rollback to the pre-session snapshot is offered"
		switch {
		case d.closed:
		case d.Line == strategy.ESR:
			/* the executor sends nothing (no confirm); the shared candidate keeps what was typed, and a Write connection refuses it */
			offer = "an uncommitted candidate configuration may remain on the device: discard it there (rollback) before anyone " +
				"commits; until then the executor cannot roll back"
			if !d.pending.IsZero() {
				offer = "the unconfirmed commit reverts by the device's timer at " + d.pending.UTC().Format(time.RFC3339) +
					" (no confirm is sent); " + offer
			}
		case d.reloadIn > 0:
			offer = fmt.Sprintf("the device's safety net may still reload it within %d minutes of the session's start (reload in, "+
				"the running configuration is lost unless saved); a rollback to the pre-session snapshot is offered", d.reloadIn)
		}
		m.alert(ctx, KindInterrupted, "high", d.ID, fmt.Sprintf("change session %s on device %d was interrupted; %s", IDString(s.ID), d.ID, offer))
	}
}

/* Bounds of the interrupted sessions kept for a rollback (variables for the tests). */
var (
	keepFor  = 24 * time.Hour
	keepMost = 256
)

/* keep holds an ended session with a device whose driver session is still open (connection lost, freeze) for its rollback. */
func (m *Manager) keep(s *Session) {
	if !slices.ContainsFunc(s.Devices, func(d *Device) bool { return d.Session != nil && !d.closed }) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.cfg.Now()
	var oldest *Session
	for id, k := range m.interrupted {
		if now.Sub(k.endedAt) >= keepFor {
			delete(m.interrupted, id)
		} else if oldest == nil || k.endedAt.Before(oldest.endedAt) {
			oldest = k
		}
	}
	if len(m.interrupted) >= keepMost && oldest != nil {
		delete(m.interrupted, oldest.ID)
	}
	m.interrupted[s.ID] = s
}

/* done is closed when the device's connection is gone. */
func (d *Device) done() <-chan struct{} {
	if d.sh == nil {
		return closed
	}
	return d.sh.Done()
}

var closed = func() chan struct{} { c := make(chan struct{}); close(c); return c }()
