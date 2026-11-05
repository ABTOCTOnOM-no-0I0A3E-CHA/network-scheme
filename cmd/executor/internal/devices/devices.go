/*
Package devices is the executor's registry of write devices
(table write_device, security.md 5.1a): registration, the host key flow and
writes_enabled, through /x (write-admin, confirm(H) with the change TOTP)
and through nmsctl executor device (the host). Where and how the executor
connects to a device comes only from this registry: address, port,
protocol, the pinned host key, the line and the write group. The panel's
core.device is read for display and prefill only; what is stored is what
the user (or the host) confirmed, and what is dialed is what is stored.

There is no TOFU: a device is registered together with the host key the
executor itself read from the confirmed address (a probe without
authentication), and every later key, as every change of the routing
fields, is accepted only explicitly with the same flow. A device kept by a
registry reset has no pinned key: it is shown as "from reset, unconfirmed"
and is unusable (no dial, no writes) until its host key is accepted again,
which confirms all its routing fields anew.
*/
package devices

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/cmd/executor/internal/audit"
	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/cmd/executor/internal/netguard"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/state"
	"github.com/beekamai/network-scheme/internal/execadmin"
)

const table = "write_device"

/* Statuses of a device. */
const (
	StatusUnconfirmed = "from_reset_unconfirmed" /* no pinned host key: only a registry reset leaves a device so */
	StatusWritesOff   = "writes_off"
	StatusWritesOn    = "writes_on"
)

/* Device is a write_device row of a verified registry snapshot. */
type Device struct {
	ID        int64      `json:"device_id"`
	Address   netip.Addr `json:"address"`
	Port      int64      `json:"port"`
	Protocol  string     `json:"protocol"`
	Group     string     `json:"write_group"`
	Driver    string     `json:"write_driver"`
	Algo      string     `json:"hostkey_algo,omitempty"`
	FP        string     `json:"hostkey_fp,omitempty"`
	AllowSHA1 bool       `json:"allow_ssh_rsa_sha1"`
	Writes    bool       `json:"writes_enabled"`
	Backup    bool       `json:"backup_via_executor"`
	Version   int64      `json:"version"`
	Status    string     `json:"status"`
	/* ModelGate: "profile" when a model profile of the line is registered (writes may pass the model gate), else "read_only". */
	ModelGate string `json:"model_gate"`
}

/* Pinned reports whether the device has a pinned host key (it is confirmed). */
func (d Device) Pinned() bool { return d.FP != "" && d.Algo != "" }

func fromRow(r registry.Row) Device {
	d := Device{Version: r.Version()}
	d.ID, _ = r.Get("device_id").(int64)
	d.Address, _ = r.Get("address").(netip.Addr)
	d.Port, _ = r.Get("port").(int64)
	d.Protocol, _ = r.Get("protocol").(string)
	d.Group, _ = r.Get("write_group").(string)
	d.Driver, _ = r.Get("write_driver").(string)
	d.Algo, _ = r.Get("hostkey_algo").(string)
	d.FP, _ = r.Get("hostkey_fp").(string)
	d.AllowSHA1, _ = r.Get("allow_ssh_rsa_sha1").(bool)
	d.Writes, _ = r.Get("writes_enabled").(bool)
	d.Backup, _ = r.Get("backup_via_executor").(bool)
	switch {
	case !d.Pinned():
		d.Status = StatusUnconfirmed
	case d.Writes:
		d.Status = StatusWritesOn
	default:
		d.Status = StatusWritesOff
	}
	return d
}

/* Model gates of a device (Device.ModelGate). */
const (
	GateProfile  = "profile"
	GateReadOnly = "read_only"
)

/*
ModelVerified reports whether a verified snapshot has a model profile of the
firmware line driver: without one, the transport's model gate allows
ReadOnly only, so no change session can open on such a device.
*/
func ModelVerified(s *registry.Snapshot, driver string) bool {
	for _, r := range s.Rows("model_profile") {
		if d, _ := r.Get("write_driver").(string); d == driver {
			return true
		}
	}
	return false
}

func withGate(s *registry.Snapshot, d Device) Device {
	d.ModelGate = GateReadOnly
	if ModelVerified(s, d.Driver) {
		d.ModelGate = GateProfile
	}
	return d
}

/* Find returns device id of a verified snapshot. */
func Find(s *registry.Snapshot, id int64) (Device, bool) {
	r, ok := s.Get(table, id)
	if !ok {
		return Device{}, false
	}
	return withGate(s, fromRow(r)), true
}

/* All lists the devices of a verified snapshot by id. */
func All(s *registry.Snapshot) []Device {
	var out []Device
	for _, r := range s.Rows(table) {
		out = append(out, withGate(s, fromRow(r)))
	}
	slices.SortFunc(out, func(a, b Device) int { return int(min(max(a.ID-b.ID, -1), 1)) })
	return out
}

/* Target is what a registration or a host key acceptance confirms: every routing field and both flags. */
type Target struct {
	ID        int64
	Address   netip.Addr
	Port      int64
	Group     string
	Driver    string
	AllowSHA1 bool
	Backup    bool
}

var groupRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

/* Refusal is a request refused by a rule: nothing was written, and its text may be shown. */
type Refusal struct {
	msg   string
	cause error
}

func (r Refusal) Error() string { return r.msg }

/* Unwrap is the rule's own error (netguard.ErrDenied), if any. */
func (r Refusal) Unwrap() error { return r.cause }

func refuse(format string, a ...any) error { return Refusal{msg: fmt.Sprintf(format, a...)} }

/* wrapRefusal makes err (a network guard denial, an unreachable device) a refusal shown as such. */
func wrapRefusal(err error) error { return Refusal{msg: err.Error(), cause: err} }

/* IsRefusal reports whether err is a refusal by a rule (the network guard's included). */
func IsRefusal(err error) bool {
	return errors.As(err, new(Refusal)) || errors.Is(err, netguard.ErrDenied)
}

/*
outcomeUnknown is a change whose fate cannot be read back (the registry
write failed after it may have committed, and the registry cannot be read
now): /x answers 503 outcome_unknown (RefusalCode and HTTPStatus, the
convention of package web), and the user checks the device list.
*/
type outcomeUnknown struct{}

func (outcomeUnknown) Error() string       { return "devices: outcome unknown" }
func (outcomeUnknown) RefusalCode() string { return "outcome_unknown" }
func (outcomeUnknown) HTTPStatus() int     { return http.StatusServiceUnavailable }

/* ErrUnknown is a change whose outcome cannot be known now; it is not a refusal. */
var ErrUnknown error = outcomeUnknown{}

/* Service changes and reads the write device registry. */
type Service struct {
	Guard *freeze.Guard
	Reg   *registry.Registry
	Net   *netguard.Guard
	Log   *slog.Logger

	probes chan struct{}
}

/* maxProbes bounds the concurrent host key probes. */
const maxProbes = 4

/* New returns a service over the executor's guard, registry and network guard. */
func New(g *freeze.Guard, reg *registry.Registry, ng *netguard.Guard, log *slog.Logger) *Service {
	return &Service{Guard: g, Reg: reg, Net: ng, Log: log, probes: make(chan struct{}, maxProbes)}
}

/* checkTarget validates t; the address and port pass the network guard (SSRF). */
func (s *Service) checkTarget(t Target) error {
	switch {
	case t.ID <= 0:
		return refuse("bad device id %d", t.ID)
	case !groupRe.MatchString(t.Group):
		return refuse("bad write group %q (a-z0-9_.-, up to 64)", t.Group)
	case !slices.Contains(execadmin.Drivers, t.Driver):
		return refuse("bad write driver %q", t.Driver)
	}
	if err := netguard.CheckPort(t.Port); err != nil {
		return wrapRefusal(err)
	}
	if err := s.Net.Check(t.Address); err != nil {
		return wrapRefusal(err)
	}
	return nil
}

/* Panel is what the panel's core.device says about a device: display and prefill only, never a decision. */
type Panel struct {
	Name    string
	Address netip.Addr
}

/* Panel reads core.device id (a planted value is only ever shown, cleaned, or refused). */
func (s *Service) Panel(ctx context.Context, id int64) (Panel, bool, error) {
	var p Panel
	var addr netip.Prefix
	found := false
	err := s.Reg.Read(ctx, registry.OpTimeout, func(ctx context.Context, tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT name, address FROM core.device WHERE id = $1`, id).Scan(&p.Name, &addr)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		found = err == nil
		return err
	})
	if !found || err != nil {
		return Panel{}, false, err
	}
	p.Name = freeze.CleanText(p.Name)
	if addr.IsSingleIP() {
		p.Address = addr.Addr()
	}
	return p, true, nil
}

/* Writer is Guard.Write (/x) or Guard.HostWrite (nmsctl). */
type Writer func(ctx context.Context, fn func(ctx context.Context, s *registry.Snapshot, tx *registry.Tx) error) error

/* Change kinds. */
const (
	Register = "register"
	Accept   = "accept-hostkey"
	Writes   = "writes"
)

/*
Change is one confirmed change. Register needs Target and Key and creates
the device; Accept needs Target and Key and replaces the routing fields
and the pin of an existing device (writes stay on only if nothing
changed); Writes sets writes_enabled of Target.ID. Version, if not 0, is
the row version the confirmation was shown for: a device changed since is
refused.
*/
type Change struct {
	Kind    string
	Target  Target
	Key     Key
	Writes  bool
	Version int64
}

/* row is the full write_device row; no pin is NULL (a device from a reset). */
func row(t Target, k Key, writes bool) map[string]any {
	var algo, fp any
	if k.Algo != "" && k.FP != "" {
		algo, fp = k.Algo, k.FP
	}
	return map[string]any{"device_id": t.ID, "address": t.Address, "port": t.Port, "protocol": "ssh",
		"write_group": t.Group, "write_driver": t.Driver, "hostkey_algo": algo, "hostkey_fp": fp,
		"allow_ssh_rsa_sha1": t.AllowSHA1, "writes_enabled": writes, "backup_via_executor": t.Backup}
}

func (d Device) target() Target {
	return Target{ID: d.ID, Address: d.Address, Port: d.Port, Group: d.Group, Driver: d.Driver, AllowSHA1: d.AllowSHA1, Backup: d.Backup}
}

/* declare is the change on snapshot s: the full row to put, or a refusal. It has no side effect (Write may retry it). */
func declare(s *registry.Snapshot, c Change) (map[string]any, error) {
	cur, exists := Find(s, c.Target.ID)
	switch {
	case c.Kind == Register && exists:
		return nil, refuse("device %d is already registered: accept its host key to change it", c.Target.ID)
	case c.Kind == Register:
		return row(c.Target, c.Key, false), nil
	case !exists:
		return nil, refuse("device %d is not registered", c.Target.ID)
	case c.Version != 0 && cur.Version != c.Version:
		return nil, refuse("device %d changed since it was shown (version %d, now %d): start again", c.Target.ID, c.Version, cur.Version)
	case c.Kind == Accept:
		same := cur.Pinned() && cur.target() == c.Target && (Key{cur.Algo, cur.FP}) == c.Key
		return row(c.Target, c.Key, cur.Writes && same), nil
	case c.Kind == Writes && c.Writes && !cur.Pinned():
		return nil, refuse("device %d is from a registry reset and unconfirmed: accept its host key first", cur.ID)
	case c.Kind == Writes:
		return row(cur.target(), Key{cur.Algo, cur.FP}, c.Writes), nil
	}
	return nil, fmt.Errorf("devices: unknown change %q", c.Kind)
}

/*
applied reports whether s holds the row want written by this change: a
version above the row's version before it (pre, 0 for none). A change that
declared what was already there (writes off on a device that is off) is not
mistaken for one that committed.
*/
func applied(s *registry.Snapshot, want map[string]any, pre int64) bool {
	r, ok := s.Get(table, want["device_id"])
	if !ok || r.Version() <= pre {
		return false
	}
	for k, v := range want {
		if r.Get(k) != v {
			return false
		}
	}
	return true
}

/*
Apply makes change c through write, with ev (action, object, user) as its
audit row: in the change's own transaction when it commits, alone with
result denied or error otherwise. An error that is neither a refusal nor
a freeze leaves the outcome unknown (registry.Write), so the registry is
read again: a change that is there succeeded; one that is not is reported
as not applied; if the registry cannot be read, ErrUnknown.
*/
func (s *Service) Apply(ctx context.Context, write Writer, c Change, ev audit.Event) error {
	details := map[string]any{"change": c.Kind, "device": c.Target.ID}
	if c.Kind == Writes {
		details["writes_enabled"] = c.Writes
	} else {
		t := c.Target
		details["address"], details["port"], details["write_group"], details["write_driver"] = t.Address.String(), t.Port, t.Group, t.Driver
		details["allow_ssh_rsa_sha1"], details["backup_via_executor"] = t.AllowSHA1, t.Backup
		details["hostkey_algo"], details["hostkey_fp"] = c.Key.Algo, c.Key.FP
	}
	if c.Version != 0 {
		details["version"] = c.Version
	}
	for k, v := range ev.Details {
		details[k] = v
	}
	ev.Details = details
	var want map[string]any
	var pre int64
	err := write(ctx, func(_ context.Context, snap *registry.Snapshot, tx *registry.Tx) error {
		vals, err := declare(snap, c)
		if err != nil {
			return err
		}
		want, pre = vals, 0
		if cur, ok := Find(snap, c.Target.ID); ok {
			details["before"], pre = cur, cur.Version
		}
		ok := ev
		ok.Result = audit.OK
		tx.Audit(audit.Append(ok))
		return tx.Put(table, vals)
	})
	switch {
	case err == nil:
		return nil
	case IsRefusal(err) || errors.Is(err, freeze.ErrFrozen):
		s.record(ctx, ev, audit.Denied, err)
		return err
	case want == nil:
		s.record(ctx, ev, audit.Error, err)
		return err
	}
	there := false
	if verr := s.Reg.View(ctx, func(snap *registry.Snapshot) error { there = applied(snap, want, pre); return nil }); verr != nil {
		s.record(ctx, ev, audit.Error, fmt.Errorf("outcome unknown (%v): the registry cannot be read now: %v", err, verr))
		return fmt.Errorf("%w: %v", ErrUnknown, err)
	}
	if !there {
		s.record(ctx, ev, audit.Error, fmt.Errorf("not applied: %w", err))
		return fmt.Errorf("devices: not applied: %w", err)
	}
	/* Committed after all (its own row is in the change's transaction); this row says the error was not a failure. */
	ev.Details["confirmed_after"] = state.Reason(err.Error())
	s.record(ctx, ev, audit.OK, nil)
	return nil
}

/* record appends ev alone with result and the error; tampering with the chain freezes. */
func (s *Service) record(ctx context.Context, ev audit.Event, result string, cause error) {
	d := map[string]any{}
	for k, v := range ev.Details {
		d[k] = v
	}
	if cause != nil {
		d["error"] = state.Reason(cause.Error())
	}
	ev.Result, ev.Details = result, d
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*registry.OpTimeout)
	defer cancel()
	err := s.Reg.Append(rctx, audit.Append(ev))
	if errors.Is(err, registry.ErrTampered) {
		s.Guard.Trigger(ctx, freeze.KindTamper, err.Error())
	}
	if err != nil {
		s.Log.Error("executor audit: cannot record", slog.String("action", ev.Action), slog.Any("err", err))
	}
}
