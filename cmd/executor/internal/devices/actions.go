package devices

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/beekamai/network-scheme/cmd/executor/internal/audit"
	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/confirm"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/internal/execadmin"
)

/* Actions and reads of /x (write-admin; confirm(H) or ticket + change TOTP). */
const (
	ActionRegister = "device.register"
	ActionAccept   = "device.accept_hostkey"
	ActionWrites   = "device.writes"
	ActionList     = "device.list"
	ActionProbe    = "device.probe"
)

/*
Action and Read have the fields of web.Action and web.Read (main converts
them): package web's tests use admin, which uses this package.
*/
type Action struct {
	Describe func(ctx context.Context, by authz.Decision, params json.RawMessage) (authz.Need, confirm.Description, error)
	Run      func(ctx context.Context, c confirm.Challenge, by authz.Decision) (any, error)
}

/* Read is an authorized read (web.Read). */
type Read struct {
	Action string
	Need   authz.Need
	Run    func(ctx context.Context, by authz.Decision, params json.RawMessage) (any, error)
}

/* RefusalCode is the code /x answers a refusal with (web.Refusal). */
func (Refusal) RefusalCode() string { return "device_refused" }

var writeAdmin = authz.Need{Kind: execadmin.KindWriteAdmin}

/*
Actions are the device actions of /x/confirm. No Describe touches the
network: issuing a challenge needs only a ticket, so a forged one must not
make the executor connect anywhere. The host key comes from the client (it
read it through the probe, which needs the change TOTP) and is shown in H;
Run reads it again from the confirmed address and refuses any other key.
*/
func (s *Service) Actions() map[string]Action {
	return map[string]Action{
		ActionRegister: {Describe: s.describeKey(Register), Run: s.run(Register)},
		ActionAccept:   {Describe: s.describeKey(Accept), Run: s.run(Accept)},
		ActionWrites:   {Describe: s.describeWrites, Run: s.run(Writes)},
	}
}

/* List is POST /x/devices: the registry's devices for a write-admin (ticket + change TOTP). */
func (s *Service) List() Read {
	return Read{Action: ActionList, Need: writeAdmin, Run: func(ctx context.Context, _ authz.Decision, params json.RawMessage) (any, error) {
		if len(params) > 0 && strict(params, &struct{}{}) != nil {
			return nil, refuse("the device list takes no parameters")
		}
		var out []Device
		err := s.Guard.View(ctx, func(snap *registry.Snapshot) error { out = All(snap); return nil })
		if out == nil {
			out = []Device{}
		}
		return out, err
	}}
}

/*
ProbeRead is POST /x/devices/probe: the only network action before a
confirmation, and it needs the change TOTP of a write-admin (authz decides
and audits it). It reads the host key of the target that register (kind
"register") or accept-hostkey (kind "accept_hostkey") would confirm with
these params, without authentication, and returns what the confirmation
will show.
*/
func (s *Service) ProbeRead() Read {
	return Read{Action: ActionProbe, Need: writeAdmin, Run: func(ctx context.Context, _ authz.Decision, params json.RawMessage) (any, error) {
		var p probeParams
		if err := strict(params, &p); err != nil {
			return nil, refuse("bad probe parameters")
		}
		kind := map[string]string{"register": Register, "accept_hostkey": Accept}[p.Kind]
		if kind == "" {
			return nil, refuse("probe kind %q, want register or accept_hostkey", p.Kind)
		}
		r, err := s.resolve(ctx, kind, p.targetParams)
		if err != nil {
			return nil, err
		}
		k, err := s.Probe(ctx, r.t)
		if err != nil {
			return nil, err
		}
		return r.fields(k), nil
	}}
}

/* strict decodes params into v: one JSON object, no unknown field, nothing after it. */
func strict(params json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(params))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

/*
admin checks, before anything else, that the user holds write-admin bound
to the ticket's name; confirm (authz) decides it again with the change
TOTP. A refusal is audited.
*/
func (s *Service) admin(ctx context.Context, by authz.Decision, action string) error {
	err := s.Guard.View(ctx, func(snap *registry.Snapshot) error {
		if g, ok := snap.Get("write_grant", by.UserID, execadmin.KindWriteAdmin, nil); ok && g.Get("username_snapshot") == by.Username {
			return nil
		}
		return refuse("write-admin is required")
	})
	if IsRefusal(err) {
		user := by.UserID
		s.record(ctx, audit.Event{UserID: &user, Action: action, Object: "describe", Details: map[string]any{"ticket": by.Ticket}},
			audit.Denied, err)
	}
	return err
}

func (s *Service) current(ctx context.Context, id int64) (Device, error) {
	var d Device
	err := s.Guard.View(ctx, func(snap *registry.Snapshot) error {
		var ok bool
		if d, ok = Find(snap, id); !ok {
			return refuse("device %d is not registered", id)
		}
		return nil
	})
	return d, err
}

/* targetParams are what the client may give of a target; nil keeps the default (register) or the registry's value (accept). */
type targetParams struct {
	DeviceID  int64   `json:"device_id"`
	Address   *string `json:"address"`
	Port      *int64  `json:"port"`
	Group     *string `json:"write_group"`
	Driver    *string `json:"write_driver"`
	AllowSHA1 *bool   `json:"allow_ssh_rsa_sha1"`
	Backup    *bool   `json:"backup_via_executor"`
}

type probeParams struct {
	Kind string `json:"kind"`
	targetParams
}

type keyParams struct {
	targetParams
	Algo string `json:"hostkey_algo"`
	FP   string `json:"hostkey_fp"`
}

func parseAddr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, refuse("bad address %q", s)
	}
	return a, nil
}

/* Where a target's address came from (shown, and covered by H). */
const (
	SourceEntered  = "entered"  /* the user typed it */
	SourcePanel    = "panel"    /* prefilled from core.device: the panel's claim, shown for confirmation */
	SourceRegistry = "registry" /* accept-hostkey: the address the registry already has */
)

/* resolved is a target ready to show: the fields, where the address came from, and what else is shown. */
type resolved struct {
	kind    string
	t       Target
	source  string
	cur     Device /* accept: the registry's row */
	panel   Panel
	onPanel bool
}

/*
resolve builds the target of a registration (the client's fields; the
address entered or, failing that, the panel's core.device address as a
prefill) or of a host key acceptance (the registry's fields, never the
panel's, each replaceable by the client). The network guard checks it; no
connection is made.
*/
func (s *Service) resolve(ctx context.Context, kind string, p targetParams) (resolved, error) {
	r := resolved{kind: kind, source: SourceEntered}
	var err error
	if kind == Register {
		r.t = Target{ID: p.DeviceID, Port: 22}
		if r.panel, r.onPanel, err = s.Panel(ctx, p.DeviceID); err != nil {
			return r, err
		}
		if p.Address == nil {
			if !r.onPanel || !r.panel.Address.IsValid() {
				return r, refuse("device %d: no address given and none on the panel", p.DeviceID)
			}
			r.t.Address, r.source = r.panel.Address, SourcePanel
		}
	} else {
		if r.cur, err = s.current(ctx, p.DeviceID); err != nil {
			return r, err
		}
		r.t, r.source = r.cur.target(), SourceRegistry
	}
	if p.Address != nil {
		if r.t.Address, err = parseAddr(*p.Address); err != nil {
			return r, err
		}
		r.source = SourceEntered
	}
	setIf(&r.t.Port, p.Port)
	setIf(&r.t.Group, p.Group)
	setIf(&r.t.Driver, p.Driver)
	setIf(&r.t.AllowSHA1, p.AllowSHA1)
	setIf(&r.t.Backup, p.Backup)
	return r, s.checkTarget(r.t)
}

/* fields is what the confirmation shows (and H covers) for key k. */
func (r resolved) fields(k Key) map[string]string {
	f := targetFields(r.t, k)
	f["address_source"] = r.source
	if r.kind == Register && r.onPanel {
		f["panel_name"], f["panel_address"] = r.panel.Name, r.panel.Address.String()
	}
	if r.kind == Accept {
		f["pinned_fp"], f["status"], f["version"] = orNone(r.cur.FP), r.cur.Status, strconv.FormatInt(r.cur.Version, 10)
	}
	return f
}

/*
describeKey describes a registration or a host key acceptance with the key
the client read through the probe: the type must be one the registry may
pin and the fingerprint well-formed; Run checks the device presents it.
*/
func (s *Service) describeKey(kind string) func(ctx context.Context, by authz.Decision, params json.RawMessage) (authz.Need, confirm.Description, error) {
	action := map[string]string{Register: ActionRegister, Accept: ActionAccept}[kind]
	return func(ctx context.Context, by authz.Decision, params json.RawMessage) (authz.Need, confirm.Description, error) {
		if err := s.admin(ctx, by, action); err != nil {
			return authz.Need{}, confirm.Description{}, err
		}
		var p keyParams
		if err := strict(params, &p); err != nil {
			return authz.Need{}, confirm.Description{}, err
		}
		k := Key{Algo: p.Algo, FP: p.FP}
		if !slices.Contains(keyTypes, k.Algo) || !execadmin.FingerprintRe.MatchString(k.FP) {
			return authz.Need{}, confirm.Description{}, refuse("a host key read by the probe is required (type and SHA256 fingerprint)")
		}
		r, err := s.resolve(ctx, kind, p.targetParams)
		if err != nil {
			return authz.Need{}, confirm.Description{}, err
		}
		return writeAdmin, describe(action, r.fields(k)), nil
	}
}

func setIf[T any](dst *T, v *T) {
	if v != nil {
		*dst = *v
	}
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

type writesParams struct {
	DeviceID int64 `json:"device_id"`
	Enabled  bool  `json:"enabled"`
}

/* describeWrites shows the device as the registry has it and the new writes_enabled. */
func (s *Service) describeWrites(ctx context.Context, by authz.Decision, params json.RawMessage) (authz.Need, confirm.Description, error) {
	if err := s.admin(ctx, by, ActionWrites); err != nil {
		return authz.Need{}, confirm.Description{}, err
	}
	var p writesParams
	if err := strict(params, &p); err != nil {
		return authz.Need{}, confirm.Description{}, err
	}
	cur, err := s.current(ctx, p.DeviceID)
	if err != nil {
		return authz.Need{}, confirm.Description{}, err
	}
	if p.Enabled && !cur.Pinned() {
		return authz.Need{}, confirm.Description{}, refuse("device %d is from a registry reset and unconfirmed: accept its host key first", cur.ID)
	}
	f := targetFields(cur.target(), Key{cur.Algo, cur.FP})
	f["writes_enabled"], f["version"] = strconv.FormatBool(p.Enabled), strconv.FormatInt(cur.Version, 10)
	return writeAdmin, describe(ActionWrites, f), nil
}

/* targetFields are the confirmed routing fields, the flags and the host key, as shown. */
func targetFields(t Target, k Key) map[string]string {
	return map[string]string{"device": strconv.FormatInt(t.ID, 10), "address": t.Address.String(),
		"port": strconv.FormatInt(t.Port, 10), "protocol": "ssh", "write_group": t.Group, "write_driver": t.Driver,
		"allow_ssh_rsa_sha1": strconv.FormatBool(t.AllowSHA1), "backup_via_executor": strconv.FormatBool(t.Backup),
		"hostkey_algo": orNone(k.Algo), "hostkey_fp": orNone(k.FP)}
}

/* describe orders the fields by key, as the canonical description needs. */
func describe(action string, f map[string]string) confirm.Description {
	d := confirm.Description{Action: action}
	for k, v := range f {
		d.Fields = append(d.Fields, confirm.Field{Key: k, Value: v})
	}
	slices.SortFunc(d.Fields, func(a, b confirm.Field) int { return strings.Compare(a.Key, b.Key) })
	return d
}

/* confirmed parses a confirmed description back into its change (what H covered, nothing else). */
func confirmed(kind string, d confirm.Description) (Change, error) {
	f := map[string]string{}
	for _, x := range d.Fields {
		f[x.Key] = x.Value
	}
	bad := fmt.Errorf("devices: malformed confirmed %s", d.Action)
	var c Change
	var err error
	num := func(k string) int64 {
		n, e := strconv.ParseInt(f[k], 10, 64)
		err = errors.Join(err, e)
		return n
	}
	flag := func(k string) bool {
		b, e := strconv.ParseBool(f[k])
		err = errors.Join(err, e)
		return b
	}
	c.Kind = kind
	c.Target = Target{ID: num("device"), Port: num("port"), Group: f["write_group"], Driver: f["write_driver"],
		AllowSHA1: flag("allow_ssh_rsa_sha1"), Backup: flag("backup_via_executor")}
	a, e := netip.ParseAddr(f["address"])
	c.Target.Address, err = a, errors.Join(err, e)
	c.Key = Key{Algo: f["hostkey_algo"], FP: f["hostkey_fp"]}
	if kind != Register {
		c.Version = num("version")
	}
	if kind == Writes {
		c.Writes = flag("writes_enabled")
	}
	if err != nil || (kind != Writes && (c.Key.Algo == "none" || c.Key.FP == "none")) {
		return Change{}, bad
	}
	return c, nil
}

/* run executes a confirmed description through Guard.Write, audited as by's action. */
func (s *Service) run(kind string) func(ctx context.Context, ch confirm.Challenge, by authz.Decision) (any, error) {
	return func(ctx context.Context, ch confirm.Challenge, by authz.Decision) (any, error) {
		c, err := confirmed(kind, ch.Description)
		if err != nil {
			return nil, err
		}
		user := by.UserID
		ev := audit.Event{UserID: &user, Action: ch.Action, Object: "device:" + strconv.FormatInt(c.Target.ID, 10),
			Details: map[string]any{"ticket": by.Ticket, "username": by.Username, "challenge": ch.ID}}
		if kind != Writes {
			/* After the TOTP: the device must present the confirmed key at the confirmed address now (no TOFU). */
			k, err := s.Probe(ctx, c.Target)
			if err == nil && k != c.Key {
				err = refuse("device %d presents host key %s %s, not the confirmed %s %s: nothing changed", c.Target.ID, k.Algo, k.FP, c.Key.Algo, c.Key.FP)
			}
			if err != nil {
				ev.Details["change"], ev.Details["hostkey_fp"] = kind, c.Key.FP
				result := audit.Error
				if IsRefusal(err) {
					result = audit.Denied
				}
				s.record(ctx, ev, result, err)
				return nil, err
			}
		}
		if err := s.Apply(ctx, s.Guard.Write, c, ev); err != nil {
			return nil, err
		}
		return map[string]any{"device_id": c.Target.ID, "change": kind}, nil
	}
}
