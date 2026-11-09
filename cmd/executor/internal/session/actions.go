package session

/*
Actions of a change session (security.md 5.3, Task 4c.4). Every one runs
with the session locked (Use), so the terminal's input waits meanwhile, and
re-checks the policy, the freeze and the device's registry row first.

  - diff: the pre-session snapshot against the running configuration, read
    with the allowlist's show running-config, both masked by the driver,
    in a unified diff (internal/textdiff);
  - save: MES writes the startup configuration; ESR confirms the pending
    commit (irreversible) after exclusivity again. Either names the hash of
    the configuration its diff showed: anything else is refused;
  - commit (ESR): exclusivity again (show users), commit confirm-timeout
    of the policy, then the health check (the session answers and a new
    login passes); a failed check restores at once. Closing the session
    without a confirm restores (the driver's Close);
  - form (package forms): the equivalent commands, applied only as shown,
    each through the session's Classify and only when Safe;
  - rollback (session.rollback, confirm(H) over the session, its devices,
    their pre_sha256 as the executor recorded them at open, their state and
    write groups; nothing is read from a device or the database before the
    TOTP code): at Run every device's snapshot is read from
    exec.session_device only (the row's MAC over the envelope parts hashed
    in Go, the envelope opened under AAD(device, hex(pre_sha256)),
    sha256(normalize(pt)) == pre_sha256 == the session's own), all of them
    before anything is sent (one bad row refuses the whole rollback with a
    high alert), then the driver's Rollback and the hash once more. A
    poller backup is never a rollback target. An interrupted session's
    devices are rolled back over a new connection, unless another session
    opened on the device since; an ESR commit left unconfirmed is the
    device's timer's (nothing is sent, no confirm).

Typed is the way the terminal hands a typed control line to these flows.
*/

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/confirm"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
	"github.com/beekamai/network-scheme/cmd/executor/internal/forms"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/strategy"
	"github.com/beekamai/network-scheme/cmd/executor/internal/transport"
	"github.com/beekamai/network-scheme/internal/backup"
	"github.com/beekamai/network-scheme/internal/backup/open"
	rdrivers "github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/execadmin"
	"github.com/beekamai/network-scheme/internal/textdiff"
)

/* RollbackAction is the confirm(H) action of "roll back the whole session" (web.Action). */
const RollbackAction = "session.rollback"

/* Refusals of the actions. */
const (
	ErrNoDevice       Refusal = "no_device"          /* the device is not in the session */
	ErrNotApplicable  Refusal = "not_applicable"     /* commit on MES */
	ErrNothingToSave  Refusal = "nothing_to_confirm" /* ESR: no commit to confirm */
	ErrStale          Refusal = "diff_changed"       /* the configuration is not the one the user was shown */
	ErrHealth         Refusal = "health_failed"      /* after commit: the session or a new login failed; restored */
	ErrSnapshotBad    Refusal = "snapshot_tampered"  /* exec.session_device fails its MAC, AAD or hash */
	ErrForm           Refusal = "bad_form"
	ErrFormLine       Refusal = "form_not_safe" /* a form line is not Safe in the session: type it in the terminal */
	ErrDescription    Refusal = "changed"       /* the rollback is not the one confirmed */
	ErrCommitTimer    Refusal = "commit_timer"  /* ESR, interrupted: the device's timer reverts the commit */
	ErrNoRollback     Refusal = "rollback_unavailable"
	ErrRollbackFailed Refusal = "rollback_failed"
	ErrSuperseded     Refusal = "superseded"     /* another session opened on the device after this one ended */
	ErrCommitPending  Refusal = "commit_pending" /* ESR: a commit waits for its confirm (or restore) */
	ErrSaveMismatch   Refusal = "save_mismatch"  /* after the save the running configuration is not the one saved (alerted) */
)

/* Bounds (variables for the tests). */
var (
	maxEdits   = 20000       /* lines a diff may differ in */
	actionTime = time.Minute /* bound of one action on one device */
	/* confirmMargin: an ESR confirm is not sent this close to the end of its commit's timer */
	confirmMargin = 15 * time.Second
	/* snapshotMessage bounds the read of one pre-session envelope (pre_ct up to 4 MiB + 1 KiB): the only read above registry.MaxMessage. */
	snapshotMessage = 4<<20 + 64<<10
)

/* Device returns the session's device id, or nil. */
func (s *Session) Device(id int64) *Device {
	for _, d := range s.Devices {
		if d.ID == id {
			return d
		}
	}
	return nil
}

/* DeviceDiff is the diff of one device: pre-session snapshot against the running configuration, masked. */
type DeviceDiff struct {
	ID        int64      `json:"device_id"`
	Line      string     `json:"line"`
	PreSHA256 string     `json:"pre_sha256"`
	SHA256    string     `json:"sha256"` /* of the running configuration: what save names */
	Diff      string     `json:"diff"`
	TooLarge  bool       `json:"too_large,omitempty"`
	Pending   *time.Time `json:"commit_pending_until,omitempty"` /* ESR: a commit waits for confirm until then */
}

/* allowed re-checks the policy, the freeze and the device's registry row before a decision. */
func (m *Manager) allowed(ctx context.Context, id int64) error {
	if !m.cfg.Policy().Enabled() {
		return authz.ErrDisabled
	}
	if frozen, _ := m.cfg.Gate.Frozen(); frozen {
		return authz.ErrFrozen
	}
	return viewErr(m.cfg.Gate.View(ctx, func(s *registry.Snapshot) error { return deviceAllowed(s, id) }))
}

/* diff reads the running configuration of d (allowlist, from the privileged prompt) and diffs it with the pre-session snapshot. */
func (m *Manager) diff(ctx context.Context, d *Device) (DeviceDiff, drivers.Config, error) {
	cur, err := d.Session.Snapshot(ctx)
	if err != nil {
		return DeviceDiff{}, cur, err
	}
	pre := d.Session.Pre()
	out := DeviceDiff{ID: d.ID, Line: string(d.Line), PreSHA256: hex.EncodeToString(pre.SHA256[:]), SHA256: hex.EncodeToString(cur.SHA256[:])}
	if !d.pending.IsZero() {
		p := d.pending.UTC()
		out.Pending = &p
	}
	mask := func(t string) string { return printable(d.Driver.MaskSecrets(rdrivers.NormalizeText(t))) }
	out.Diff, err = textdiff.Unified(ctx, "pre-session", "running", mask(pre.Text), mask(cur.Text), 3, maxEdits)
	if errors.Is(err, textdiff.ErrTooLarge) {
		out.TooLarge, err = true, nil
	}
	return out, cur, err
}

/* printable drops what a device's text must not carry to the browser: controls but tab and newline, format characters, invalid UTF-8. */
func printable(t string) string {
	return strings.Map(func(r rune) rune {
		if r == utf8.RuneError || r != '\n' && r != '\t' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) {
			return -1
		}
		return r
	}, t)
}

/* Diff diffs every device of the session of token. */
func (m *Manager) Diff(ctx context.Context, id, token string) ([]DeviceDiff, error) {
	var out []DeviceDiff
	err := m.Use(id, token, func(s *Session) error {
		for _, d := range s.Devices {
			dd, err := m.readDiff(ctx, d)
			if err != nil {
				return err
			}
			out = append(out, dd)
		}
		return nil
	})
	return out, err
}

/* readDiff is the diff of one device, bounded, after the policy, freeze and registry allow it. */
func (m *Manager) readDiff(ctx context.Context, d *Device) (DeviceDiff, error) {
	ctx, cancel := context.WithTimeout(ctx, actionTime)
	defer cancel()
	if err := m.allowed(ctx, d.ID); err != nil {
		return DeviceDiff{}, err
	}
	dd, _, err := m.diff(ctx, d)
	return dd, err
}

/*
Save saves device of the session of token: MES the startup configuration,
ESR the confirm of its pending commit, after exclusivity again. sum is the
hash of the configuration the user's diff showed (DeviceDiff.SHA256).
*/
func (m *Manager) Save(ctx context.Context, id, token string, device int64, sum string) (DeviceDiff, error) {
	var out DeviceDiff
	err := m.Use(id, token, func(s *Session) error {
		var err error
		out, err = m.save(ctx, s, device, sum)
		return err
	})
	return out, err
}

func (m *Manager) save(ctx context.Context, s *Session, device int64, sum string) (DeviceDiff, error) {
	ctx, cancel := context.WithTimeout(ctx, actionTime)
	defer cancel()
	d := s.Device(device)
	if d == nil {
		return DeviceDiff{}, ErrNoDevice
	}
	if err := m.allowed(ctx, d.ID); err != nil {
		return DeviceDiff{}, err
	}
	if d.Line == strategy.ESR && d.pending.IsZero() {
		return DeviceDiff{}, ErrNothingToSave
	}
	_, cur, err := m.diff(ctx, d)
	if err != nil {
		return DeviceDiff{}, err
	}
	if hex.EncodeToString(cur.SHA256[:]) != sum {
		return DeviceDiff{}, ErrStale
	}
	sctx := ctx
	if d.Line == strategy.ESR {
		if err := d.sh.Exclusive(ctx, true); err != nil {
			return DeviceDiff{}, deviceRefusal(err)
		}
		/* last thing before the confirm, and the confirm bounded by it: never at or after the device's timer */
		left := d.pending.Sub(m.cfg.Now()) - confirmMargin
		if left <= 0 {
			return DeviceDiff{}, ErrCommitTimer
		}
		var cancel context.CancelFunc
		sctx, cancel = context.WithTimeout(ctx, left)
		defer cancel()
	}
	if err := d.Session.Save(sctx); err != nil {
		if errors.Is(err, drivers.ErrNothingToConfirm) {
			return DeviceDiff{}, ErrNothingToSave
		}
		return DeviceDiff{}, err
	}
	d.pending = time.Time{}
	m.event(ctx, s.ID, "saved", map[string]any{"device_id": d.ID, "sha256": sum})
	out, _, err := m.diff(ctx, d)
	if err == nil && out.SHA256 != sum {
		m.alert(ctx, drivers.KindRollbackMismatch, "high", d.ID, fmt.Sprintf("device %d, change session %s: after the save the running "+
			"configuration is not the one the user saved (%s)", d.ID, IDString(s.ID), sum))
		return out, ErrSaveMismatch
	}
	return out, err
}

/* Commit commits the candidate of an ESR device of the session of token (the typed commit's flow). */
func (m *Manager) Commit(ctx context.Context, id, token string, device int64) (DeviceDiff, error) {
	var out DeviceDiff
	err := m.Use(id, token, func(s *Session) error {
		d := s.Device(device)
		if d == nil {
			return ErrNoDevice
		}
		var err error
		out, err = m.commit(ctx, s, d)
		return err
	})
	return out, err
}

/* rooter is the privileged prompt of a driver session (drivers.Core, embedded by every line's session). */
type rooter interface {
	ToRoot(ctx context.Context) error
}

func (m *Manager) commit(ctx context.Context, s *Session, d *Device) (DeviceDiff, error) {
	ctx, cancel := context.WithTimeout(ctx, actionTime)
	defer cancel()
	if d.Line != strategy.ESR {
		return DeviceDiff{}, ErrNotApplicable
	}
	if err := m.allowed(ctx, d.ID); err != nil {
		return DeviceDiff{}, err
	}
	r, ok := d.Session.(rooter)
	if !ok {
		return DeviceDiff{}, ErrNotApplicable
	}
	if !d.pending.IsZero() {
		return DeviceDiff{}, ErrCommitPending /* one unconfirmed commit at a time: its timer is the one shown */
	}
	if err := r.ToRoot(ctx); err != nil {
		return DeviceDiff{}, err
	}
	if err := d.sh.Exclusive(ctx, false); err != nil {
		return DeviceDiff{}, deviceRefusal(err)
	}
	timeout := time.Duration(m.cfg.Policy().Policy.ESRCommitTimerS) * time.Second
	at := m.cfg.Now()
	if err := d.Session.Commit(ctx, timeout); err != nil {
		return DeviceDiff{}, err
	}
	d.pending = at.Add(timeout)
	m.event(ctx, s.ID, "committed", map[string]any{"device_id": d.ID, "timeout_s": int(timeout / time.Second)})
	out, _, err := m.diff(ctx, d)
	if err == nil {
		err = m.login(ctx, d.ID)
	}
	if err != nil {
		/*
			The health check failed: revert only this pending commit (restore),
			never the whole session (that is the rollback's, under confirm(H)):
			what an earlier confirm made permanent stays. Without a restore the
			device's timer reverts it.
		*/
		if rs, ok := d.Session.(restorer); ok && rs.Restore(ctx) == nil {
			d.pending = time.Time{}
		}
		m.event(ctx, s.ID, "health_failed", map[string]any{"device_id": d.ID})
		return DeviceDiff{}, ErrHealth
	}
	return out, nil
}

/* restorer reverts only a pending ESR commit (esr session.Restore). */
type restorer interface {
	Restore(ctx context.Context) error
}

/* login is the health check's new connection: it must log in (ReadOnly: no exclusivity, this session is still there). */
func (m *Manager) login(ctx context.Context, id int64) error {
	sh, err := m.dial(ctx, id, transport.ReadOnly)
	if err != nil {
		return err
	}
	return sh.Close()
}

/* Flow is what the terminal does with a typed control line: Kind "commit" ran the commit; "save" and "rollback" open those flows. */
type Flow struct {
	Kind string     `json:"flow"`
	Diff DeviceDiff `json:"diff"`
}

/*
Typed runs the flow of a control line v (Session.Classify: Class Control)
typed on device of s, which the caller holds (Use): a typed commit is the
commit (ESR: end + commit confirm-timeout of the policy, health check);
confirm, save, write and reload cancel open the save flow (its button, with
the diff); restore opens the rollback. Nothing typed reaches the device.
*/
func (m *Manager) Typed(ctx context.Context, s *Session, device int64, v core.Verdict) (Flow, error) {
	d := s.Device(device)
	if d == nil {
		return Flow{}, ErrNoDevice
	}
	if v.Class != core.Control {
		return Flow{}, ErrNotApplicable
	}
	switch v.Control {
	case core.Commit:
		dd, err := m.commit(ctx, s, d)
		return Flow{Kind: "commit", Diff: dd}, err
	case core.Restore:
		return Flow{Kind: "rollback"}, nil
	case core.Save, core.Confirm, core.ReloadCancel:
		dd, err := m.readDiff(ctx, d)
		return Flow{Kind: "save", Diff: dd}, err
	}
	return Flow{}, ErrNotApplicable
}

/* FormLines are the equivalent commands of a form on a device: what the user confirms. */
type FormLines struct {
	ID    int64    `json:"device_id"`
	Lines []string `json:"lines"`
}

/* formParams is the body of the form routes; form-apply carries the lines the user was shown. */
type formParams struct {
	Device int64        `json:"device_id"`
	Form   forms.Params `json:"form"`
	Lines  []string     `json:"lines,omitempty"`
}

/* FormApplied is a form's result: the lines the device got and the diff after. */
type FormApplied struct {
	Sent int        `json:"sent"`
	Diff DeviceDiff `json:"diff"`
}

func (m *Manager) form(s *Session, p formParams) (FormLines, error) {
	d := s.Device(p.Device)
	if d == nil {
		return FormLines{}, ErrNoDevice
	}
	lines, err := forms.Render(d.Driver, p.Form)
	if err != nil {
		return FormLines{}, ErrForm
	}
	return FormLines{ID: d.ID, Lines: lines}, nil
}

/* apply sends the lines of a form the user confirmed (forms.Apply), after the policy, freeze and registry allow it. */
func (m *Manager) apply(ctx context.Context, s *Session, p formParams) (FormApplied, error) {
	ctx, cancel := context.WithTimeout(ctx, actionTime)
	defer cancel()
	d := s.Device(p.Device)
	if d == nil {
		return FormApplied{}, ErrNoDevice
	}
	if err := m.allowed(ctx, d.ID); err != nil {
		return FormApplied{}, err
	}
	sent, err := forms.Apply(ctx, d.Driver, d.Session, p.Form, p.Lines)
	m.event(ctx, s.ID, "form", map[string]any{"device_id": d.ID, "kind": p.Form.Kind, "sent": sent})
	switch {
	case errors.Is(err, forms.ErrForm):
		return FormApplied{Sent: sent}, ErrForm
	case errors.Is(err, forms.ErrChanged):
		return FormApplied{Sent: sent}, ErrStale
	case errors.Is(err, forms.ErrNotSafe):
		return FormApplied{Sent: sent}, ErrFormLine
	case err != nil:
		return FormApplied{Sent: sent}, err
	}
	dd, _, err := m.diff(ctx, d)
	return FormApplied{Sent: sent, Diff: dd}, err
}

/*
Act serves the session routes with the bearer token (web.Sessions.Act): op
is diff ({}), save ({device_id, sha256}), commit ({device_id}), form
({device_id, form}: the lines to confirm) and form-apply ({device_id, form,
lines}). params are decoded strictly.
*/
func (m *Manager) Act(ctx context.Context, id, token, op string, params json.RawMessage) (any, error) {
	var p struct {
		Device int64  `json:"device_id"`
		SHA256 string `json:"sha256"`
	}
	switch op {
	case "diff":
		if err := strict(params, &struct{}{}); err != nil {
			return nil, err
		}
		return m.Diff(ctx, id, token)
	case "save":
		if err := strict(params, &p); err != nil {
			return nil, err
		}
		return m.Save(ctx, id, token, p.Device, p.SHA256)
	case "commit":
		if err := strict(params, &p); err != nil || p.SHA256 != "" {
			return nil, ErrForm
		}
		return m.Commit(ctx, id, token, p.Device)
	case "form", "form-apply":
		var f formParams
		if err := strict(params, &f); err != nil {
			return nil, err
		}
		var out any
		err := m.Use(id, token, func(s *Session) error {
			var err error
			if op == "form" {
				out, err = m.form(s, f)
			} else {
				out, err = m.apply(ctx, s, f)
			}
			return err
		})
		return out, err
	}
	return nil, ErrNotApplicable
}

func strict(b json.RawMessage, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return ErrForm
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ErrForm
	}
	return nil
}

/*
snapshot reads the pre-session snapshot of d from exec.session_device only,
over its own connection with the raised message bound (the only read above
registry.MaxMessage): the row's MAC over sha256(pre_ct) and sha256(pre_dek_ct)
computed here, the envelope opened under AAD(device, hex(pre_sha256)), and
sha256(normalize(pt)) == pre_sha256 == the session's own. Any failure is
tampering: a high alert and ErrSnapshotBad.
*/
func (m *Manager) snapshot(ctx context.Context, sid [16]byte, d *Device) (drivers.Config, error) {
	cc := m.cfg.Pool.Config().ConnConfig.Copy()
	cc.BuildFrontend = func(r io.Reader, w io.Writer) *pgproto3.Frontend {
		f := pgproto3.NewFrontend(r, w)
		f.SetMaxBodyLen(snapshotMessage)
		return f
	}
	qctx, cancel := context.WithTimeout(ctx, recordTime)
	defer cancel()
	conn, err := pgx.ConnectConfig(qctx, cc)
	if err != nil {
		return drivers.Config{}, fmt.Errorf("%w: %w", authz.ErrUnavailable, err)
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	var pre, ct, dek, mac []byte
	err = conn.QueryRow(qctx, `SELECT pre_sha256, pre_ct, pre_dek_ct, mac FROM exec.session_device WHERE session_id = $1 AND device_id = $2`,
		sid, d.ID).Scan(&pre, &ct, &dek, &mac)
	var big *pgproto3.ExceededMaxBodyLenErr
	switch {
	case errors.Is(err, pgx.ErrNoRows), errors.As(err, &big):
		return drivers.Config{}, m.tampered(ctx, sid, d.ID, "the pre-session snapshot row is missing or oversized")
	case err != nil:
		return drivers.Config{}, fmt.Errorf("%w: %w", authz.ErrUnavailable, err)
	}
	if len(pre) != sha256.Size || !hmac.Equal(mac, m.DeviceMAC(sid, d.ID, [32]byte(pre), ct, dek)) {
		return drivers.Config{}, m.tampered(ctx, sid, d.ID, "the pre-session snapshot row fails its MAC")
	}
	pt, err := open.Open(m.cfg.BackupPriv, m.cfg.BackupPub, ct, dek, backup.AAD(d.ID, hex.EncodeToString(pre)))
	if err != nil {
		return drivers.Config{}, m.tampered(ctx, sid, d.ID, "the pre-session envelope does not open under its AAD")
	}
	c := drivers.NewConfig(string(pt))
	clear(pt)
	if c.SHA256 != [32]byte(pre) || c.SHA256 != d.Pre {
		return drivers.Config{}, m.tampered(ctx, sid, d.ID, "the pre-session snapshot does not hash to its pre_sha256")
	}
	return c, nil
}

func (m *Manager) tampered(ctx context.Context, sid [16]byte, device int64, what string) error {
	m.alert(ctx, KindTamper, "high", device, fmt.Sprintf("change session %s, device %d: %s; the rollback is refused", IDString(sid), device, what))
	return ErrSnapshotBad
}

/* rollbackParams names the session of a rollback. */
type rollbackParams struct {
	Session string `json:"session_id"`
}

/* find returns the open or interrupted session id. */
func (m *Manager) find(id string) (*Session, bool) {
	sid, ok := ParseID(id)
	if !ok {
		return nil, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if s := m.sessions[sid]; s != nil {
		return s, true
	}
	s := m.interrupted[sid]
	return s, s != nil
}

/*
describe is the rollback's description, built only from the executor's own
memory and the verified registry, with nothing read from a device or the
session rows (it runs before the TOTP code): the session, its devices, each
one's pre_sha256 as recorded at open, its state (open, interrupted,
commit_pending: the ESR timer's, closed: no rollback) and the write groups
the grant is for. s is locked by the caller.
*/
func (m *Manager) describe(ctx context.Context, s *Session) (authz.Need, confirm.Description, error) {
	var groups []string
	addrs := map[int64]string{}
	if err := m.cfg.Gate.View(ctx, func(snap *registry.Snapshot) error {
		for _, d := range s.Devices {
			r, ok := snap.Get("write_device", d.ID)
			if !ok {
				return authz.ErrDenied
			}
			g, _ := r.Get("write_group").(string)
			groups = append(groups, g)
			a, _ := r.Get("address").(netip.Addr)
			p, _ := r.Get("port").(int64)
			if !a.IsValid() || p < 1 || p > 65535 {
				return authz.ErrDenied
			}
			addrs[d.ID] = netip.AddrPortFrom(a, uint16(p)).String() // #nosec G115 -- checked above
		}
		return nil
	}); err != nil {
		return authz.Need{}, confirm.Description{}, viewErr(err)
	}
	slices.Sort(groups)
	groups = slices.Compact(groups)
	m.mu.Lock()
	ended := s.ended
	m.mu.Unlock()
	ids := make([]string, len(s.Devices))
	fields := []confirm.Field{{Key: "groups", Value: strings.Join(groups, ",")}, {Key: "session", Value: IDString(s.ID)}}
	for i, d := range s.Devices {
		ids[i] = strconv.FormatInt(d.ID, 10)
		state := "open"
		switch {
		case d.Session == nil || d.closed:
			state = "closed"
		case !d.pending.IsZero() && ended:
			state = "commit_pending"
		case ended:
			state = "interrupted"
		}
		fields = append(fields, confirm.Field{Key: "address_" + ids[i], Value: addrs[d.ID]},
			confirm.Field{Key: "pre_sha256_" + ids[i], Value: hex.EncodeToString(d.Pre[:])},
			confirm.Field{Key: "state_" + ids[i], Value: state})
	}
	fields = append(fields, confirm.Field{Key: "devices", Value: strings.Join(ids, ",")})
	slices.SortFunc(fields, func(a, b confirm.Field) int { return strings.Compare(a.Key, b.Key) })
	return authz.Need{Kind: execadmin.KindWrite, Groups: groups}, confirm.Description{Action: RollbackAction, Fields: fields}, nil
}

/* DescribeRollback is the rollback's Describe (web.Action): only the session's own user. */
func (m *Manager) DescribeRollback(ctx context.Context, by authz.Decision, params json.RawMessage) (authz.Need, confirm.Description, error) {
	var p rollbackParams
	if err := strict(params, &p); err != nil {
		return authz.Need{}, confirm.Description{}, err
	}
	s, ok := m.find(p.Session)
	if !ok || s.User != by.UserID {
		return authz.Need{}, confirm.Description{}, ErrNoSession
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return m.describe(ctx, s)
}

/* RolledBack is the result of a rollback per device. */
type RolledBack struct {
	ID     int64  `json:"device_id"`
	SHA256 string `json:"sha256,omitempty"` /* the running configuration after: the pre-session one */
	Error  string `json:"error,omitempty"`
}

/*
RunRollback is the rollback's Run (web.Action) on the confirmed description:
the description is built again and must be the confirmed one (any change of
the session, its devices, a state or a write group since refuses: changed).
Then every device's snapshot is read from exec and verified (one that fails
refuses the whole rollback before anything is sent), and every device: the
policy, freeze and registry again, the driver's Rollback (it checks the
hash) and the hash once more; a mismatch raises the high
executor_rollback_mismatch alert.
*/
func (m *Manager) RunRollback(ctx context.Context, c confirm.Challenge, by authz.Decision) (any, error) {
	var id string
	for _, f := range c.Description.Fields {
		if f.Key == "session" {
			id = f.Value
		}
	}
	s, ok := m.find(id)
	if !ok || s.User != by.UserID || c.User != by.UserID {
		return nil, ErrNoSession
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, now, err := m.describe(ctx, s)
	if err != nil {
		return nil, err
	}
	if !slices.Equal(now.Fields, c.Description.Fields) || now.Action != c.Action || c.Action != RollbackAction {
		return nil, ErrDescription
	}
	to := map[int64]drivers.Config{}
	for _, d := range s.Devices {
		if d.Session == nil || d.closed {
			continue
		}
		if to[d.ID], err = m.snapshot(ctx, s.ID, d); err != nil {
			return nil, err
		}
	}
	var out []RolledBack
	failed := false
	for _, d := range s.Devices {
		r := m.rollbackDevice(ctx, s, d, to[d.ID])
		failed = failed || r.Error != ""
		out = append(out, r)
	}
	m.event(ctx, s.ID, "rolled_back", map[string]any{"ok": !failed})
	m.mu.Lock()
	if s.ended && !slices.ContainsFunc(s.Devices, func(d *Device) bool { return d.Session != nil && !d.closed }) {
		delete(m.interrupted, s.ID)
	}
	m.mu.Unlock()
	return map[string]any{"devices": out}, nil
}

/* rollbackDevice rolls d back to to, its verified pre-session snapshot. */
func (m *Manager) rollbackDevice(ctx context.Context, s *Session, d *Device, to drivers.Config) RolledBack {
	ctx, cancel := context.WithTimeout(ctx, deviceTime)
	defer cancel()
	res := RolledBack{ID: d.ID}
	fail := func(err error) RolledBack {
		var r Refusal
		switch {
		case errors.As(err, &r):
			res.Error = string(r)
		case errors.Is(err, drivers.ErrRollbackMismatch):
			res.Error = "rollback_mismatch"
		case errors.Is(err, drivers.ErrNoInverse):
			res.Error = "no_inverse"
		default:
			res.Error = string(ErrRollbackFailed)
		}
		return res
	}
	if d.Session == nil || d.closed {
		return fail(ErrNoRollback)
	}
	m.mu.Lock()
	ended := s.ended
	m.mu.Unlock()
	if ended && !d.pending.IsZero() {
		return fail(ErrCommitTimer) /* the device's own timer reverts it: the executor sends nothing */
	}
	if err := m.allowed(ctx, d.ID); err != nil {
		return fail(err)
	}
	if ended {
		done, err := m.reattach(ctx, s, d)
		if err != nil {
			return fail(err)
		}
		defer done()
	}
	if d.Line == strategy.ESR {
		/* the rollback may commit and confirm the snapshot: no other session on the device (its own candidate is dropped first) */
		if err := d.sh.Exclusive(ctx, false); err != nil {
			return fail(deviceRefusal(err))
		}
	}
	if err := d.Session.Rollback(ctx, to); err != nil {
		return fail(err)
	}
	d.pending = time.Time{}
	after, err := d.Session.Snapshot(ctx)
	if err != nil || after.SHA256 != to.SHA256 {
		m.alert(ctx, drivers.KindRollbackMismatch, "high", d.ID, fmt.Sprintf("device %d: after the rollback of change session %s the running "+
			"configuration is not the pre-session one", d.ID, IDString(s.ID)))
		return fail(drivers.ErrRollbackMismatch)
	}
	res.SHA256 = hex.EncodeToString(after.SHA256[:])
	return res
}

/* rebinder moves a driver session to a new connection (drivers.Core.Rebind). */
type rebinder interface {
	Rebind(ctx context.Context, sh drivers.Shell) error
}

/*
reattach connects again to a device of an ended session for its rollback:
its lease, device_busy and a Write connection of the same line (host key,
model, ESR exclusivity by the transport), the driver session moved onto it.
done closes the driver session (safety net, snapshot file), the connection,
device_busy and the lease.
*/
func (m *Manager) reattach(ctx context.Context, s *Session, d *Device) (done func(), err error) {
	rb, ok := d.Session.(rebinder)
	if !ok {
		return nil, ErrNoRollback
	}
	le, ok := m.cfg.Locks.TryLock(d.ID)
	if !ok {
		return nil, ErrBusy
	}
	undo := []func(){le.Release}
	release := func() {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
	}
	/* a session opened on the device since this one ended changed it from where the driver session left it: refuse (deny-only, any row counts) */
	var later bool
	qctx, qcancel := context.WithTimeout(ctx, recordTime)
	err = m.cfg.Pool.QueryRow(qctx, `SELECT EXISTS (SELECT 1 FROM exec.session_device sd JOIN exec.session s ON s.id = sd.session_id
		WHERE sd.device_id = $1 AND s.id <> $2 AND s.opened_at >= $3)`, d.ID, s.ID, s.Opened).Scan(&later)
	qcancel()
	switch {
	case err != nil:
		release()
		return nil, fmt.Errorf("%w: %w", authz.ErrUnavailable, err)
	case later, m.openedAfter(d.ID, s.Opened):
		release()
		return nil, ErrSuperseded
	}
	var row registry.Row
	if err := m.cfg.Gate.View(ctx, func(snap *registry.Snapshot) error {
		row, _ = snap.Get("write_device", d.ID)
		return nil
	}); err != nil {
		release()
		return nil, viewErr(err)
	}
	if err := m.cfg.Pub.Busy(ctx, row, s.ID); err != nil {
		release()
		return nil, deviceRefusal(err)
	}
	undo = append(undo, func() {
		if err := m.cfg.Pub.Free(context.WithoutCancel(ctx), d.ID, s.ID); err != nil {
			m.cfg.Log.Error("session: device_busy not freed after a rollback", slog.Int64("device_id", d.ID), slog.String("err", err.Error()))
		}
	})
	sh, err := m.dial(ctx, d.ID, transport.Write)
	if err != nil {
		release()
		return nil, deviceRefusal(err)
	}
	undo = append(undo, func() { _ = sh.Close() })
	if sh.Line() != d.Line {
		release()
		return nil, ErrLineMismatch
	}
	if err := rb.Rebind(ctx, sh); err != nil {
		release()
		return nil, err
	}
	d.sh = sh
	return func() {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), closeTime)
		defer cancel()
		d.closed = true
		if err := d.Session.Close(cctx); err != nil {
			m.cfg.Log.Warn("session: driver close after a rollback failed", slog.Int64("device_id", d.ID), slog.String("err", err.Error()))
		}
		release()
	}, nil
}
