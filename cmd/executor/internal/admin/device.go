package admin

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/beekamai/network-scheme/cmd/executor/internal/audit"
	"github.com/beekamai/network-scheme/cmd/executor/internal/devices"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/internal/execadmin"
)

/*
device runs nmsctl executor device add|accept-hostkey|writes on|off|list
(the host's way when /x is unavailable). add and accept-hostkey are two
steps unless the host gives the fingerprint it expects: the daemon reads
the device's host key without authentication and answers with what it
read and, for accept-hostkey, the registry row's version (a preview); the
confirmation carries that fingerprint, every previewed field and the
version, the daemon reads the key again and changes the registry only if it
is the same and the row did not change since (no TOFU). Changes go through
Guard.HostWrite, audited by package devices in the change's transaction.
*/
func (a *Admin) device(ctx context.Context, req execadmin.Request) execadmin.Response {
	obj := fmt.Sprintf("device:%d", req.DeviceID)
	details := map[string]any{"device": req.DeviceID}
	if a.Devices == nil {
		return a.refuse(ctx, req, obj, deny("device commands are not available"), details)
	}
	if req.Action == "list" {
		return a.deviceList(ctx, req)
	}
	if req.DeviceID <= 0 {
		return a.refuse(ctx, req, obj, deny("--device ID is required"), details)
	}
	if req.Action == "writes-on" || req.Action == "writes-off" {
		if req.Address != "" || req.Port != 0 || req.Group != "" || req.Driver != "" || req.AllowSHA1 != nil || req.Backup != nil || req.Fingerprint != "" {
			return a.refuse(ctx, req, obj, deny("device writes takes only --device"), details)
		}
		c := devices.Change{Kind: devices.Writes, Target: devices.Target{ID: req.DeviceID}, Writes: req.Action == "writes-on"}
		if err := a.Devices.Apply(ctx, a.hostWrite, c, a.event(req, obj, audit.OK, nil)); err != nil {
			return execadmin.Response{Error: err.Error()}
		}
		return execadmin.Response{OK: true, Text: fmt.Sprintf("device %d: writes %s", req.DeviceID, strings.TrimPrefix(req.Action, "writes-"))}
	}
	t, cur, err := a.deviceTarget(ctx, req)
	if err != nil {
		return a.refuse(ctx, req, obj, err, details)
	}
	if req.DeviceVersion != 0 && cur.Version != req.DeviceVersion {
		return a.refuse(ctx, req, obj, deny("device %d changed since the preview (version %d, now %d): run the command again",
			req.DeviceID, req.DeviceVersion, cur.Version), details)
	}
	k, err := a.Devices.Probe(ctx, t)
	if err != nil {
		return a.refuse(ctx, req, obj, err, details)
	}
	info := &execadmin.Device{ID: t.ID, Address: t.Address.String(), Port: t.Port, Group: t.Group, Driver: t.Driver,
		AllowSHA1: t.AllowSHA1, Backup: t.Backup, Algo: k.Algo, Fingerprint: k.FP, PinnedFP: cur.FP, Version: cur.Version}
	if p, ok, err := a.Devices.Panel(ctx, t.ID); err == nil && ok {
		info.PanelName, info.PanelAddress = p.Name, p.Address.String()
	}
	if req.Fingerprint == "" {
		details["step"], details["hostkey_algo"], details["hostkey_fp"], details["version"] = "preview", k.Algo, k.FP, cur.Version
		resp := a.done(ctx, req, obj, "", details)
		resp.Device = info
		return resp
	}
	if k.FP != req.Fingerprint {
		return a.refuse(ctx, req, obj, deny("device %d presents host key %s %s, not the confirmed %s: nothing changed", t.ID, k.Algo, k.FP, req.Fingerprint), details)
	}
	c := devices.Change{Kind: devices.Register, Target: t, Key: k}
	if req.Action == "accept-hostkey" {
		c.Kind, c.Version = devices.Accept, req.DeviceVersion
	}
	if err := a.Devices.Apply(ctx, a.hostWrite, c, a.event(req, obj, audit.OK, nil)); err != nil {
		return execadmin.Response{Error: err.Error()}
	}
	return execadmin.Response{OK: true, Text: fmt.Sprintf("device %d at %s:%d (%s, group %s): host key %s %s pinned; writes are off until enabled",
		t.ID, t.Address, t.Port, t.Driver, t.Group, k.Algo, k.FP), Device: info}
}

/*
deviceTarget is what add registers (every field from the host) or what
accept-hostkey confirms (the registry's fields, those the host gives
replaced: the flags either way). cur is the registry's row (accept-hostkey).
*/
func (a *Admin) deviceTarget(ctx context.Context, req execadmin.Request) (devices.Target, devices.Device, error) {
	var cur devices.Device
	t := devices.Target{ID: req.DeviceID, Port: 22, Group: req.Group, Driver: req.Driver}
	if req.Action == "accept-hostkey" {
		found := false
		if err := a.view(ctx, func(s *registry.Snapshot) error { cur, found = devices.Find(s, req.DeviceID); return nil }); err != nil {
			return t, cur, err
		}
		if !found {
			return t, cur, deny("device %d is not registered", req.DeviceID)
		}
		t = devices.Target{ID: cur.ID, Address: cur.Address, Port: cur.Port, Group: cur.Group, Driver: cur.Driver,
			AllowSHA1: cur.AllowSHA1, Backup: cur.Backup}
		if req.Group != "" {
			t.Group = req.Group
		}
		if req.Driver != "" {
			t.Driver = req.Driver
		}
	}
	if req.AllowSHA1 != nil {
		t.AllowSHA1 = *req.AllowSHA1
	}
	if req.Backup != nil {
		t.Backup = *req.Backup
	}
	if req.Port != 0 {
		t.Port = req.Port
	}
	if req.Address != "" {
		addr, err := netip.ParseAddr(req.Address)
		if err != nil {
			return t, cur, deny("bad address %q", req.Address)
		}
		t.Address = addr
	} else if req.Action == "add" {
		return t, cur, deny("--address is required (the panel's address is shown in the preview, never taken)")
	}
	return t, cur, nil
}

/* deviceList prints the registry's devices; an unconfirmed one (from a reset) says so. */
func (a *Admin) deviceList(ctx context.Context, req execadmin.Request) execadmin.Response {
	var all []devices.Device
	if err := a.view(ctx, func(s *registry.Snapshot) error { all = devices.All(s); return nil }); err != nil {
		return a.refuse(ctx, req, "device", err, nil)
	}
	var b strings.Builder
	for _, d := range all {
		status := d.Status
		if status == devices.StatusUnconfirmed {
			status = "from reset, unconfirmed: accept-hostkey confirms address, port, group and driver"
		}
		fmt.Fprintf(&b, "device %d  %s:%d  %s  group %s  driver %s  key %s %s  sha1 %v  backup %v  version %d  %s\n", d.ID, d.Address, d.Port,
			d.Protocol, d.Group, d.Driver, orNone(d.Algo), orNone(d.FP), d.AllowSHA1, d.Backup, d.Version, status)
	}
	if len(all) == 0 {
		b.WriteString("no write devices\n")
	}
	return a.done(ctx, req, "device", b.String(), map[string]any{"devices": len(all)})
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
