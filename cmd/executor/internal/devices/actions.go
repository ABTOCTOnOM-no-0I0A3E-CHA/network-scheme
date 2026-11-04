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

/* Actions of /x (confirm(H), write-admin). */
const (
	ActionRegister = "device.register"
	ActionAccept   = "device.accept_hostkey"
	ActionWrites   = "device.writes"
	ActionList     = "device.list"
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
	Run    func(ctx context.Context, by authz.Decision) (any, error)
}

/* RefusalCode is the code /x answers a refusal with (web.Refusal). */
func (Refusal) RefusalCode() string { return "device_refused" }

var writeAdmin = authz.Need{Kind: execadmin.KindWriteAdmin}

/*
Actions are the device actions of /x/confirm: each Describe reads the
registry (and, for a key, the device) itself and builds every field the
user confirms; Run changes exactly the confirmed description.
*/
func (s *Service) Actions() map[string]Action {
	return map[string]Action{
		ActionRegister: {Describe: s.describeRegister, Run: s.run(Register)},
		ActionAccept:   {Describe: s.describeAccept, Run: s.run(Accept)},
		ActionWrites:   {Describe: s.describeWrites, Run: s.run(Writes)},
	}
}

/* List is POST /x/devices: the registry's devices for a write-admin (ticket + change TOTP). */
func (s *Service) List() Read {
	return Read{Action: ActionList, Need: writeAdmin, Run: func(ctx context.Context, _ authz.Decision) (any, error) {
		var out []Device
		err := s.Guard.View(ctx, func(snap *registry.Snapshot) error { out = All(snap); return nil })
		if out == nil {
			out = []Device{}
		}
		return out, err
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
admin checks, before anything is read from a device, that the user holds
write-admin bound to the ticket's name; confirm (authz) decides it again
with the change TOTP. A refusal is audited.
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

type registerParams struct {
	DeviceID  int64   `json:"device_id"`
	Address   *string `json:"address"`
	Port      *int64  `json:"port"`
	Group     string  `json:"write_group"`
	Driver    string  `json:"write_driver"`
	AllowSHA1 bool    `json:"allow_ssh_rsa_sha1"`
	Backup    bool    `json:"backup_via_executor"`
}

func parseAddr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, refuse("bad address %q", s)
	}
	return a, nil
}

/*
describeRegister: the address is the client's, or else the panel's
core.device address as a prefill; either way it is shown, checked by the
network guard, probed without authentication for its host key, and only
the confirmed value is stored. The panel's name and address are shown for
display only.
*/
func (s *Service) describeRegister(ctx context.Context, by authz.Decision, params json.RawMessage) (authz.Need, confirm.Description, error) {
	if err := s.admin(ctx, by, ActionRegister); err != nil {
		return authz.Need{}, confirm.Description{}, err
	}
	var p registerParams
	if err := strict(params, &p); err != nil {
		return authz.Need{}, confirm.Description{}, err
	}
	t := Target{ID: p.DeviceID, Port: 22, Group: p.Group, Driver: p.Driver, AllowSHA1: p.AllowSHA1, Backup: p.Backup}
	if p.Port != nil {
		t.Port = *p.Port
	}
	panel, onPanel, err := s.Panel(ctx, p.DeviceID)
	if err != nil {
		return authz.Need{}, confirm.Description{}, err
	}
	switch {
	case p.Address != nil:
		if t.Address, err = parseAddr(*p.Address); err != nil {
			return authz.Need{}, confirm.Description{}, err
		}
	case onPanel && panel.Address.IsValid():
		t.Address = panel.Address
	default:
		return authz.Need{}, confirm.Description{}, refuse("device %d: no address given and none on the panel", p.DeviceID)
	}
	k, err := s.Probe(ctx, t)
	if err != nil {
		return authz.Need{}, confirm.Description{}, err
	}
	f := targetFields(t, k)
	if onPanel {
		f["panel_name"], f["panel_address"] = panel.Name, panel.Address.String()
	}
	return writeAdmin, describe(ActionRegister, f), nil
}

type acceptParams struct {
	DeviceID  int64   `json:"device_id"`
	Address   *string `json:"address"`
	Port      *int64  `json:"port"`
	Group     *string `json:"write_group"`
	Driver    *string `json:"write_driver"`
	AllowSHA1 *bool   `json:"allow_ssh_rsa_sha1"`
	Backup    *bool   `json:"backup_via_executor"`
}

/*
describeAccept: the registry's routing fields (never the panel's), each
replaceable by the client, are shown with the host key the executor reads
from that address now and the key pinned so far; accepting it confirms
them all (a device from a reset is confirmed so).
*/
func (s *Service) describeAccept(ctx context.Context, by authz.Decision, params json.RawMessage) (authz.Need, confirm.Description, error) {
	if err := s.admin(ctx, by, ActionAccept); err != nil {
		return authz.Need{}, confirm.Description{}, err
	}
	var p acceptParams
	if err := strict(params, &p); err != nil {
		return authz.Need{}, confirm.Description{}, err
	}
	cur, err := s.current(ctx, p.DeviceID)
	if err != nil {
		return authz.Need{}, confirm.Description{}, err
	}
	t := cur.target()
	if p.Address != nil {
		if t.Address, err = parseAddr(*p.Address); err != nil {
			return authz.Need{}, confirm.Description{}, err
		}
	}
	setIf(&t.Port, p.Port)
	setIf(&t.Group, p.Group)
	setIf(&t.Driver, p.Driver)
	setIf(&t.AllowSHA1, p.AllowSHA1)
	setIf(&t.Backup, p.Backup)
	k, err := s.Probe(ctx, t)
	if err != nil {
		return authz.Need{}, confirm.Description{}, err
	}
	f := targetFields(t, k)
	f["pinned_fp"], f["status"], f["version"] = orNone(cur.FP), cur.Status, strconv.FormatInt(cur.Version, 10)
	return writeAdmin, describe(ActionAccept, f), nil
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
		if err := s.Apply(ctx, s.Guard.Write, c, ev); err != nil {
			return nil, err
		}
		return map[string]any{"device_id": c.Target.ID, "change": kind}, nil
	}
}
