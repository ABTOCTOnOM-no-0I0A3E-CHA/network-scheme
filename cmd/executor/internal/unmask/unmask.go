/*
Package unmask shows and exports full (unmasked) configuration versions
(plan 4d.1, security.md 11, 13): only the executor opens a version's
envelope, only for a user with the unmask grant and write on the device's
write group (the group from the executor's registry, never from the api),
confirmed with confirm(H) over (device, version) and a change TOTP code.

  - POST /x/configs (a read: ticket + TOTP, unmask on the device's group)
    lists a device's versions (metadata only);
  - config.view and config.export are described through /x/confirm/issue
    (H covers device, version, its hash, time, size and the registry's write
    group) and confirmed only on their own routes, POST
    /x/configs/{device}/{version} (JSON) and
    /x/download/configs/{device}/{version} (a text/plain attachment).

Before anything is shown the executor checks again that the device is in the
confirmed write group, reads the version row (its device and hash must be
the confirmed ones), opens the envelope under AAD(device, hash) and checks
sha256(normalize(text)) against the row: the envelope proves nothing (anyone
with the backup public key or the poller's INSERT can make one, security.md
13), so a mismatch is tampering, refused with a high alert, never shown. The
text is device data: it reaches the browser cleaned like the terminal's
output (no escape sequence, no control or format character but tab and line
end), as text. Views and exports per user and hour are bounded by
unmask_per_hour (past it: refused, a high alert once an hour); more than
mass_unmask_alert of all users in an hour raise the high mass_unmask alert.
Every outcome, refusals included, is an executor audit row (who, device,
version, hash, result).
*/
package unmask

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/cmd/executor/internal/audit"
	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/confirm"
	"github.com/beekamai/network-scheme/cmd/executor/internal/policy"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/internal/backup"
	"github.com/beekamai/network-scheme/internal/backup/open"
	rdrivers "github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/execadmin"
)

/* Actions: the list (a read), and the two confirmed ones with their routes. */
const (
	ActionList   = "config.list"
	ActionView   = "config.view"
	ActionExport = "config.export"
)

/* Alert kinds (internal/triggers). */
const (
	KindViews  = "executor_unmask_views"  /* high: a user asked for more unmasked configurations than unmask_per_hour */
	KindMass   = "mass_unmask"            /* high: more than mass_unmask_alert unmasked configurations of all users in an hour */
	KindTamper = "executor_config_tamper" /* high: a version row or its envelope does not hash to the confirmed version */
)

/* Refusal is a refusal with the code the UI has a text for (web: 422, or its HTTPStatus). */
type Refusal string

func (r Refusal) Error() string { return "unmask: refused (" + string(r) + ")" }

/* RefusalCode is the code the UI has a text for. */
func (r Refusal) RefusalCode() string { return string(r) }

/* Refusals. */
const (
	ErrParams        Refusal = "bad_params"
	ErrNotRegistered Refusal = "not_registered" /* the device is not in the executor's registry */
	ErrNotFound      Refusal = "not_found"      /* no such version of the device */
	ErrMismatch      Refusal = "mismatch"       /* the route names another device or version than the confirmed one */
	ErrChanged       Refusal = "changed"        /* the device left the confirmed write group: confirm again */
	ErrViewLimit     Refusal = "view_limit"
	ErrTampered      Refusal = "config_tampered"
)

/* ErrBusy refuses while maxShows run (503: try again). */
var ErrBusy = busy{}

type busy struct{}

func (busy) Error() string       { return "unmask: busy" }
func (busy) RefusalCode() string { return "unmask_busy" }
func (busy) HTTPStatus() int     { return 503 }

/* Bounds (variables for the tests). */
var (
	maxConfig   = 4 << 20            /* backups.config_version.size and full_ct are bounded to 4 MiB (+1 KiB) */
	rowMessage  = maxConfig + 64<<10 /* the version row's read: above registry.MaxMessage, on its own connection */
	listMost    = 100
	maxShows    = 2 /* configurations opened at once: each holds up to 4 MiB a few times */
	readTimeout = 10 * time.Second
)

/* Gate is the decision path: *freeze.Guard. */
type Gate interface {
	View(ctx context.Context, fn func(*registry.Snapshot) error) error
}

/* Config builds a Store; every field but Log and Now is required. */
type Config struct {
	Pool *pgxpool.Pool
	Gate Gate
	/* Priv and Pub open the envelopes (the backup domain's keys). */
	Priv, Pub *[32]byte
	/* Clean is what the live terminal does to device output (terminal.Clean). */
	Clean  func(string) string
	Policy func() policy.State
	Alert  func(ctx context.Context, kind, severity string, deviceID int64, text string) error
	Audit  func(ctx context.Context, ev audit.Event) /* authz.Authorizer.Record */
	Log    *slog.Logger
	Now    func() time.Time
}

/* Store serves the unmasked configurations. */
type Store struct {
	c     Config
	shows chan struct{}

	mu    sync.Mutex
	users map[int64]*hour /* per user: shows of the last hour, last alert */
	all   hour            /* every user's: the mass alert */
}

type hour struct {
	at      []time.Time
	alerted time.Time
}

/* New returns a Store. */
func New(c Config) (*Store, error) {
	if c.Pool == nil || c.Gate == nil || c.Priv == nil || c.Pub == nil || c.Clean == nil || c.Policy == nil || c.Alert == nil || c.Audit == nil {
		return nil, errors.New("unmask: incomplete configuration")
	}
	if c.Log == nil {
		c.Log = slog.New(slog.DiscardHandler)
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return &Store{c: c, shows: make(chan struct{}, maxShows), users: map[int64]*hour{}}, nil
}

func strict(b json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(v) != nil || dec.More() {
		return ErrParams
	}
	return nil
}

/* noGroup is the group of a device the registry does not have: no grant names it (groups start with a letter or digit). */
const noGroup = "-unregistered"

/* group is the device's write group in the verified registry, noGroup without a row. */
func (st *Store) group(ctx context.Context, device int64) (string, error) {
	g := noGroup
	err := st.c.Gate.View(ctx, func(s *registry.Snapshot) error {
		if r, ok := s.Get("write_device", device); ok {
			if v, _ := r.Get("write_group").(string); v != "" {
				g = v
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, authz.ErrFrozen) {
		err = fmt.Errorf("%w: %w", authz.ErrUnavailable, err)
	}
	return g, err
}

/* need is the grant of a device: unmask, scoped to its write group (authz: the unmask grant and write on the group). */
func need(group string) authz.Need {
	return authz.Need{Kind: execadmin.KindUnmask, Groups: []string{group}}
}

type deviceParams struct {
	Device int64 `json:"device_id"`
}

/* ListNeed is the list's grant, from the registry's group of the device named in params (an unknown device: a group no grant names). */
func (st *Store) ListNeed(ctx context.Context, params json.RawMessage) (authz.Need, error) {
	var p deviceParams
	if err := strict(params, &p); err != nil || p.Device <= 0 {
		return authz.Need{}, ErrParams
	}
	g, err := st.group(ctx, p.Device)
	return need(g), err
}

/* Version is the metadata of a configuration version (never its text). */
type Version struct {
	ID      int64     `json:"version_id"`
	Device  int64     `json:"device_id"`
	TakenAt time.Time `json:"taken_at"`
	Source  string    `json:"source"`
	SHA256  string    `json:"sha256"`
	Size    int       `json:"size"`
}

/* List is Run of POST /x/configs: the newest listMost versions of the device. */
func (st *Store) List(ctx context.Context, _ authz.Decision, params json.RawMessage) (any, error) {
	var p deviceParams
	if err := strict(params, &p); err != nil || p.Device <= 0 {
		return nil, ErrParams
	}
	qctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	rows, err := st.c.Pool.Query(qctx, `SELECT id, taken_at, source, sha256, size FROM backups.config_version
		WHERE device_id = $1 ORDER BY taken_at DESC, id DESC LIMIT $2`, p.Device, listMost)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", authz.ErrUnavailable, err)
	}
	defer rows.Close()
	out := []Version{}
	for rows.Next() {
		v := Version{Device: p.Device}
		var sum []byte
		if err := rows.Scan(&v.ID, &v.TakenAt, &v.Source, &sum, &v.Size); err != nil {
			return nil, fmt.Errorf("%w: %w", authz.ErrUnavailable, err)
		}
		v.SHA256, v.Source = hex.EncodeToString(sum), st.c.Clean(v.Source)
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", authz.ErrUnavailable, err)
	}
	return out, nil
}

type versionParams struct {
	Device  int64 `json:"device_id"`
	Version int64 `json:"version_id"`
}

/*
Describe is the description of config.view and config.export: what the
executor itself reads of the version (its device, hash, time, size) and the
device's write group in the registry, which the grant is scoped to. Only
metadata the panel shows too is read before the TOTP code.
*/
func (st *Store) Describe(action string) func(ctx context.Context, by authz.Decision, params json.RawMessage) (authz.Need, confirm.Description, error) {
	return func(ctx context.Context, _ authz.Decision, params json.RawMessage) (authz.Need, confirm.Description, error) {
		var p versionParams
		if err := strict(params, &p); err != nil || p.Device <= 0 || p.Version <= 0 {
			return authz.Need{}, confirm.Description{}, ErrParams
		}
		g, err := st.group(ctx, p.Device)
		switch {
		case err != nil:
			return authz.Need{}, confirm.Description{}, err
		case g == noGroup:
			return authz.Need{}, confirm.Description{}, ErrNotRegistered
		}
		qctx, cancel := context.WithTimeout(ctx, readTimeout)
		defer cancel()
		var (
			v   Version
			sum []byte
		)
		err = st.c.Pool.QueryRow(qctx, `SELECT taken_at, sha256, size FROM backups.config_version WHERE id = $1 AND device_id = $2`,
			p.Version, p.Device).Scan(&v.TakenAt, &sum, &v.Size)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return authz.Need{}, confirm.Description{}, ErrNotFound
		case err != nil:
			return authz.Need{}, confirm.Description{}, fmt.Errorf("%w: %w", authz.ErrUnavailable, err)
		}
		return need(g), confirm.Description{Action: action, Fields: []confirm.Field{
			{Key: "device_id", Value: strconv.FormatInt(p.Device, 10)},
			{Key: "sha256", Value: hex.EncodeToString(sum)},
			{Key: "size", Value: strconv.Itoa(v.Size)},
			{Key: "taken_at", Value: v.TakenAt.UTC().Format(time.RFC3339)},
			{Key: "version_id", Value: strconv.FormatInt(p.Version, 10)},
			{Key: "write_group", Value: g},
		}}, nil
	}
}

/* Shown is an unmasked configuration as the browser gets it: cleaned text. */
type Shown struct {
	Device  int64  `json:"device_id"`
	Version int64  `json:"version_id"`
	SHA256  string `json:"sha256"`
	TakenAt string `json:"taken_at"`
	Text    string `json:"text"`
}

func field(d confirm.Description, k string) string {
	for _, f := range d.Fields {
		if f.Key == k {
			return f.Value
		}
	}
	return ""
}

/* View is Run of POST /x/configs/{device}/{version}: the confirmed version, shown as JSON text. */
func (st *Store) View(ctx context.Context, c confirm.Challenge, by authz.Decision, objs []string) (any, error) {
	return st.show(ctx, c, by, objs, ActionView)
}

/* Export is File of POST /x/download/configs/{device}/{version}: the confirmed version as a text attachment. */
func (st *Store) Export(ctx context.Context, c confirm.Challenge, by authz.Decision, objs []string) (string, []byte, error) {
	s, err := st.show(ctx, c, by, objs, ActionExport)
	if err != nil {
		return "", nil, err
	}
	return fmt.Sprintf("config-%d-%d.txt", s.Device, s.Version), []byte(s.Text), nil
}

/*
show is the shared path of a view and an export (see the package comment):
every outcome is one audit row with the confirmed device, version and hash.
*/
func (st *Store) show(ctx context.Context, c confirm.Challenge, by authz.Decision, objs []string, action string) (Shown, error) {
	user := by.UserID
	d := c.Description
	dev, _ := strconv.ParseInt(field(d, "device_id"), 10, 64)
	ver, _ := strconv.ParseInt(field(d, "version_id"), 10, 64)
	sum, group := field(d, "sha256"), field(d, "write_group")
	ev := audit.Event{UserID: &user, Action: action, Object: "device:" + field(d, "device_id"), Result: audit.Denied,
		Details: map[string]any{"version_id": ver, "sha256": sum, "write_group": group, "challenge": c.ID}}
	refuse := func(err error, class string) (Shown, error) {
		ev.Details["class"] = class
		if class == "unavailable" {
			ev.Result = audit.Error
		}
		st.c.Audit(ctx, ev)
		return Shown{}, err
	}
	if c.Action != action || len(objs) != 2 || dev <= 0 || ver <= 0 || objs[0] != strconv.FormatInt(dev, 10) || objs[1] != strconv.FormatInt(ver, 10) {
		return refuse(ErrMismatch, "mismatch")
	}
	select {
	case st.shows <- struct{}{}:
		defer func() { <-st.shows }()
	default:
		return refuse(ErrBusy, "busy")
	}
	if !st.take(ctx, user, dev) {
		return refuse(ErrViewLimit, "view_limit")
	}
	g, err := st.group(ctx, dev)
	switch {
	case err != nil:
		return refuse(err, "unavailable")
	case g != group:
		return refuse(ErrChanged, "changed")
	}
	text, takenAt, err := st.open(ctx, dev, ver, sum)
	var rf Refusal
	switch {
	case errors.As(err, &rf):
		return refuse(err, string(rf))
	case err != nil:
		return refuse(err, "unavailable")
	}
	ev.Result, ev.Details["bytes"] = audit.OK, len(text)
	st.c.Audit(ctx, ev)
	return Shown{Device: dev, Version: ver, SHA256: sum, TakenAt: takenAt.UTC().Format(time.RFC3339), Text: text}, nil
}

/*
open reads the version row on its own connection (the only read here above
registry.MaxMessage), checks its device and hash against the confirmed ones,
opens the envelope under AAD(device, hash) and checks sha256(normalize(text))
against the row before anything leaves; the text is then cleaned.
*/
func (st *Store) open(ctx context.Context, device, version int64, want string) (string, time.Time, error) {
	cc := st.c.Pool.Config().ConnConfig.Copy()
	cc.BuildFrontend = func(r io.Reader, w io.Writer) *pgproto3.Frontend {
		f := pgproto3.NewFrontend(r, w)
		f.SetMaxBodyLen(rowMessage)
		return f
	}
	qctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	conn, err := pgx.ConnectConfig(qctx, cc)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("%w: %w", authz.ErrUnavailable, err)
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	var (
		sum, ct, dek []byte
		takenAt      time.Time
	)
	err = conn.QueryRow(qctx, `SELECT sha256, full_ct, full_dek_ct, taken_at FROM backups.config_version WHERE id = $1 AND device_id = $2`,
		version, device).Scan(&sum, &ct, &dek, &takenAt)
	var big *pgproto3.ExceededMaxBodyLenErr
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return "", takenAt, st.tampered(ctx, device, version, "the confirmed version row is gone")
	case errors.As(err, &big):
		return "", takenAt, st.tampered(ctx, device, version, "the version row is larger than any configuration")
	case err != nil:
		return "", takenAt, fmt.Errorf("%w: %w", authz.ErrUnavailable, err)
	}
	if hex.EncodeToString(sum) != want {
		return "", takenAt, st.tampered(ctx, device, version, "the version row's hash is not the confirmed one")
	}
	pt, err := open.Open(st.c.Priv, st.c.Pub, ct, dek, backup.AAD(device, want))
	if err != nil {
		return "", takenAt, st.tampered(ctx, device, version, "the envelope does not open under its AAD")
	}
	defer clear(pt)
	if got := sha256.Sum256([]byte(rdrivers.NormalizeText(string(pt)))); len(pt) > maxConfig || hex.EncodeToString(got[:]) != want {
		return "", takenAt, st.tampered(ctx, device, version, "the opened configuration does not hash to its version row")
	}
	return st.clean(string(pt)), takenAt, nil
}

/* clean cleans each line on its own (an unterminated escape sequence cannot swallow the lines after it). */
func (st *Store) clean(text string) string {
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		lines[i] = st.c.Clean(l)
	}
	return strings.Join(lines, "\n")
}

func (st *Store) tampered(ctx context.Context, device, version int64, what string) error {
	st.alert(ctx, KindTamper, "high", device, fmt.Sprintf("configuration version %d of device %d: %s; it is not shown", version, device, what))
	return ErrTampered
}

func (st *Store) alert(ctx context.Context, kind, sev string, device int64, text string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), readTimeout)
	defer cancel()
	if err := st.c.Alert(ctx, kind, sev, device, text); err != nil {
		st.c.Log.Warn("unmask: alert not published", slog.String("kind", kind), slog.String("err", err.Error()))
	}
}

/*
take counts one show of user: false past unmask_per_hour (a high alert at
the first refusal of the hour). Every counted show of every user counts
towards mass_unmask_alert: past it, the mass alert once an hour.
*/
func (st *Store) take(ctx context.Context, user, device int64) bool {
	p := st.c.Policy().Policy
	now := st.c.Now()
	st.mu.Lock()
	u := st.users[user]
	if u == nil {
		u = &hour{}
		st.users[user] = u
	}
	u.prune(now, time.Hour)
	if len(u.at) >= p.UnmaskPerHour {
		first := now.Sub(u.alerted) >= time.Hour
		if first {
			u.alerted = now
		}
		st.mu.Unlock()
		if first {
			st.alert(ctx, KindViews, "high", device, fmt.Sprintf("user %d asked for more than %d unmasked configurations in an hour; refused", user, p.UnmaskPerHour))
		}
		return false
	}
	u.at = append(u.at, now)
	st.all.prune(now, time.Hour)
	st.all.at = append(st.all.at, now)
	mass := len(st.all.at) > p.MassUnmaskAlert && now.Sub(st.all.alerted) >= time.Hour
	if mass {
		st.all.alerted = now
	}
	n := len(st.all.at)
	st.mu.Unlock()
	if mass {
		st.alert(ctx, KindMass, "high", 0, fmt.Sprintf("%d unmasked configurations shown or exported within an hour (mass_unmask_alert %d)", n, p.MassUnmaskAlert))
	}
	return true
}

func (h *hour) prune(now time.Time, window time.Duration) {
	k := 0
	for _, t := range h.at {
		if now.Sub(t) < window {
			h.at[k] = t
			k++
		}
	}
	h.at = h.at[:k]
}
