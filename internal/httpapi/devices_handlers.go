package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/audit"
	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/inventory"
	"github.com/beekamai/network-scheme/internal/rbac"
)

/*
Enqueuer puts background jobs on the queue inside the caller's transaction,
so a job exists exactly when the change that asked for it commits.
*/
type Enqueuer interface {
	EnqueuePollNow(ctx context.Context, tx pgx.Tx, deviceID int64) error
	EnqueueDiscovery(ctx context.Context, tx pgx.Tx, scanID int64) error
}

/* Limits of device input. */
const (
	maxCiphertext = 8<<10 + 48 /* sealed credential: 8 KiB plaintext + sealed-box overhead, bytes */
	minIntervalS  = 10
	maxIntervalS  = 86400
)

/* errKeyVersion: the credential was sealed to a read-domain key other than the current one. */
var errKeyVersion = errors.New("httpapi: credential sealed under a stale key version")

var deviceProfileKinds = map[string]bool{"snmp2c": true, "snmp3": true, "ssh_read": true, "telnet_read": true}

var broadcast4 = netip.AddrFrom4([4]byte{255, 255, 255, 255})

type deviceResponse struct {
	ID                int64      `json:"id"`
	Name              string     `json:"name"`
	Address           string     `json:"address"`
	GroupID           int64      `json:"group_id"`
	Driver            string     `json:"driver"`
	Model             string     `json:"model"`
	Firmware          string     `json:"firmware"`
	InsecureProtocols bool       `json:"insecure_protocols"`
	State             string     `json:"state"`
	StateSince        *time.Time `json:"state_since"`
}

type deviceDetailResponse struct {
	deviceResponse
	SNMPPort           int    `json:"snmp_port"`
	ParentID           *int64 `json:"parent_id"`
	IntervalAvailS     *int   `json:"interval_avail_s"`
	IntervalMetricsS   *int   `json:"interval_metrics_s"`
	IntervalInventoryS *int   `json:"interval_inventory_s"`
	LastError          string `json:"last_error"`
}

/* toDeviceResponse adds the availability state; a device the state view does not list yet is "unknown". */
func toDeviceResponse(d devices.Device, st inventory.DeviceState) deviceResponse {
	if st.State == "" {
		st = inventory.DeviceState{State: inventory.StateUnknown}
	}
	return deviceResponse{
		ID: d.ID, Name: d.Name, Address: d.Address.String(), GroupID: d.GroupID, Driver: d.Driver,
		Model: d.Model, Firmware: d.Firmware, InsecureProtocols: d.InsecureProtocols, State: st.State, StateSince: st.Since,
	}
}

/* parseDeviceAddr accepts a unicast host address without zone; loopback, multicast, broadcast and unspecified are refused. */
func parseDeviceAddr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	a = a.Unmap()
	if a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a == broadcast4 {
		return netip.Addr{}, false
	}
	return a, true
}

func validPort(p int) bool { return p >= 1 && p <= 65535 }

/* parseInterval reads an optional interval: absent (set false), null (clears) or minIntervalS…maxIntervalS. */
func parseInterval(raw json.RawMessage) (set bool, v *int, ok bool) {
	if raw == nil {
		return false, nil, true
	}
	if json.Unmarshal(raw, &v) != nil || (v != nil && (*v < minIntervalS || *v > maxIntervalS)) {
		return false, nil, false
	}
	return true, v, true
}

/* sealedCredential is a credential sealed in the browser to the read-domain key; the API never opens it. */
type sealedCredential struct {
	Ciphertext []byte `json:"ciphertext"` /* base64 in JSON */
	KeyVersion int    `json:"key_version"`
}

func (c sealedCredential) valid() bool {
	return len(c.Ciphertext) > 0 && len(c.Ciphertext) <= maxCiphertext && c.KeyVersion > 0
}

/* checkKeyVersion runs inside the change so that a stale-key attempt is audited as a failure. */
func (s *server) checkKeyVersion(v int) error {
	if v != s.cfg.ReadKeyVersion {
		return errKeyVersion
	}
	return nil
}

func (s *server) listDevices(w http.ResponseWriter, r *http.Request) {
	sc, err := s.scope(r, rbac.PermDevicesRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ds, err := s.devices.List(r.Context(), sc.filter())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ids := make([]int64, len(ds))
	for i, d := range ds {
		ids[i] = d.ID
	}
	states, err := s.inventory.States(r.Context(), ids)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]deviceResponse, 0, len(ds))
	for _, d := range ds {
		out = append(out, toDeviceResponse(d, states[d.ID]))
	}
	writeJSON(w, http.StatusOK, out)
}

/* createDevice adds a device to a group the caller manages; any other group answers 404. */
func (s *server) createDevice(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name     string `json:"name"`
		Address  string `json:"address"`
		SNMPPort *int   `json:"snmp_port"`
		GroupID  int64  `json:"group_id"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	addr, ok := parseDeviceAddr(in.Address)
	port := 161
	if in.SNMPPort != nil {
		port = *in.SNMPPort
	}
	if !ok || !validGroupName(in.Name) || !validPort(port) { /* device names follow the group name rules */
		writeError(w, errBadRequest)
		return
	}
	sc, err := s.scope(r, rbac.PermDevicesManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !sc.has(in.GroupID) {
		writeError(w, errNotFound)
		return
	}
	var id int64
	ev := audit.Event{Action: "devices.create", ObjectType: "device",
		Details: map[string]any{"name": in.Name, "address": addr.String(), "snmp_port": port, "group_id": in.GroupID}}
	if !s.change(w, r, ev, func(tx pgx.Tx, ev *audit.Event) error {
		var err error
		id, err = s.devices.Create(r.Context(), tx, devices.NewDevice{Name: in.Name, Address: addr, SNMPPort: port, GroupID: in.GroupID})
		if err != nil {
			return err
		}
		ev.ObjectID = strconv.FormatInt(id, 10)
		return nil
	}) {
		return
	}
	writeJSON(w, http.StatusCreated, idResponse{ID: id})
}

func (s *server) getDevice(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	d, err := s.authorizeDevice(r, rbac.PermDevicesRead, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	states, err := s.inventory.States(r.Context(), []int64{d.ID})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, deviceDetailResponse{
		deviceResponse: toDeviceResponse(d, states[d.ID]), SNMPPort: d.SNMPPort, ParentID: d.ParentID,
		IntervalAvailS: d.Intervals.AvailS, IntervalMetricsS: d.Intervals.MetricsS, IntervalInventoryS: d.Intervals.InventoryS,
		LastError: states[d.ID].LastError,
	})
}

/*
updateDevice changes the given fields; an absent field is unchanged and a
null interval falls back to the group's. Moving the device needs
devices.manage on the target group as well. parent_id (null clears) must name
a device the caller can see; cycles and chains over 16 are refused with 409.
*/
func (s *server) updateDevice(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	sc, err := s.scope(r, rbac.PermDevicesManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.deviceIn(r, sc, id); err != nil {
		s.fail(w, r, err)
		return
	}
	var in struct {
		Name               *string         `json:"name"`
		Address            *string         `json:"address"`
		SNMPPort           *int            `json:"snmp_port"`
		GroupID            *int64          `json:"group_id"`
		ParentID           json.RawMessage `json:"parent_id"`
		IntervalAvailS     json.RawMessage `json:"interval_avail_s"`
		IntervalMetricsS   json.RawMessage `json:"interval_metrics_s"`
		IntervalInventoryS json.RawMessage `json:"interval_inventory_s"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	var p devices.Patch
	details := map[string]any{}
	valid := true
	if in.Name != nil {
		valid = valid && validGroupName(*in.Name)
		p.Name, details["name"] = in.Name, *in.Name
	}
	if in.Address != nil {
		a, ok := parseDeviceAddr(*in.Address)
		valid = valid && ok
		p.Address, details["address"] = &a, a.String()
	}
	if in.SNMPPort != nil {
		valid = valid && validPort(*in.SNMPPort)
		p.SNMPPort, details["snmp_port"] = in.SNMPPort, *in.SNMPPort
	}
	if in.GroupID != nil {
		p.GroupID, details["group_id"] = in.GroupID, *in.GroupID
	}
	type intervalUpdate struct {
		set bool
		v   *int
	}
	var parent *int64
	setParent := in.ParentID != nil
	if setParent {
		if json.Unmarshal(in.ParentID, &parent) != nil || (parent != nil && *parent < 1) {
			valid = false
		}
		details["parent_id"] = parent
	}
	var iv [3]intervalUpdate
	for i, f := range []struct {
		key string
		raw json.RawMessage
	}{{"interval_avail_s", in.IntervalAvailS}, {"interval_metrics_s", in.IntervalMetricsS}, {"interval_inventory_s", in.IntervalInventoryS}} {
		set, v, ok := parseInterval(f.raw)
		valid = valid && ok
		if set {
			iv[i] = intervalUpdate{set: true, v: v}
			details[f.key] = v
		}
	}
	if !valid || len(details) == 0 {
		writeError(w, errBadRequest)
		return
	}
	if in.GroupID != nil && !sc.has(*in.GroupID) {
		writeError(w, errNotFound)
		return
	}
	if parent != nil {
		/* The parent need only be visible (devices.read), not manageable. */
		readSc, err := s.scope(r, rbac.PermDevicesRead)
		if err == nil {
			_, err = s.deviceIn(r, readSc, *parent)
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
	}
	ev := audit.Event{Action: "devices.update", ObjectType: "device", ObjectID: strconv.FormatInt(id, 10), Details: details}
	if !s.change(w, r, ev, func(tx pgx.Tx, _ *audit.Event) error {
		if iv[0].set || iv[1].set || iv[2].set {
			/* Patch.Intervals replaces all three: merge with the current values under a row lock. */
			cur, err := s.devices.Lock(r.Context(), tx, id)
			if err != nil {
				return err
			}
			merged := cur.Intervals
			for i, dst := range []**int{&merged.AvailS, &merged.MetricsS, &merged.InventoryS} {
				if iv[i].set {
					*dst = iv[i].v
				}
			}
			p.Intervals = &merged
		}
		if err := s.devices.Update(r.Context(), tx, id, p); err != nil {
			return err
		}
		if setParent {
			return s.devices.SetParent(r.Context(), tx, id, parent)
		}
		return nil
	}) {
		return
	}
	if setParent {
		s.configChanged() /* the engine reads parents with its configuration */
	}
	w.WriteHeader(http.StatusNoContent)
}

/* deleteDevice removes a device together with its credentials. */
func (s *server) deleteDevice(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	d, err := s.authorizeDevice(r, rbac.PermDevicesManage, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ev := audit.Event{Action: "devices.delete", ObjectType: "device", ObjectID: strconv.FormatInt(id, 10),
		Details: map[string]any{"name": d.Name, "address": d.Address.String()}}
	if !s.change(w, r, ev, func(tx pgx.Tx, _ *audit.Event) error {
		return s.devices.Delete(r.Context(), tx, id)
	}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type profileResponse struct {
	Kind      string    `json:"kind"`
	Status    string    `json:"status"`
	UpdatedAt time.Time `json:"updated_at"`
}

/* listProfiles tells which credentials are set; their content is never returned. */
func (s *server) listProfiles(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if _, err := s.authorizeDevice(r, rbac.PermDevicesRead, id); err != nil {
		s.fail(w, r, err)
		return
	}
	ps, err := s.devices.Profiles(r.Context(), devices.Owner{Kind: devices.OwnerDevice, ID: id})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]profileResponse, 0, len(ps))
	for _, p := range ps {
		out = append(out, profileResponse{Kind: p.Kind, Status: p.Status, UpdatedAt: p.UpdatedAt})
	}
	writeJSON(w, http.StatusOK, out)
}

/*
putProfile stores a sealed read credential as opaque bytes; the audit record
names the kind and key version only. snmp2c and telnet_read mark the device
as using an insecure protocol.
*/
func (s *server) putProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if _, err := s.authorizeDevice(r, rbac.PermDeviceCredentials, id); err != nil {
		s.fail(w, r, err)
		return
	}
	kind := chi.URLParam(r, "kind")
	if !deviceProfileKinds[kind] {
		writeError(w, errNotFound)
		return
	}
	var in sealedCredential
	if !decodeJSON(w, r, &in) {
		return
	}
	if !in.valid() {
		writeError(w, errBadRequest)
		return
	}
	owner := devices.Owner{Kind: devices.OwnerDevice, ID: id}
	ev := audit.Event{Action: "devices.profile_set", ObjectType: "device", ObjectID: strconv.FormatInt(id, 10),
		Details: map[string]any{"kind": kind, "key_version": in.KeyVersion}}
	if !s.change(w, r, ev, func(tx pgx.Tx, _ *audit.Event) error {
		if err := s.checkKeyVersion(in.KeyVersion); err != nil {
			return err
		}
		if err := s.devices.PutProfile(r.Context(), tx, owner, kind, in.Ciphertext, in.KeyVersion); err != nil {
			return err
		}
		return s.devices.RefreshInsecure(r.Context(), tx, id)
	}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) deleteProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if _, err := s.authorizeDevice(r, rbac.PermDeviceCredentials, id); err != nil {
		s.fail(w, r, err)
		return
	}
	kind := chi.URLParam(r, "kind")
	if !deviceProfileKinds[kind] {
		writeError(w, errNotFound)
		return
	}
	ev := audit.Event{Action: "devices.profile_delete", ObjectType: "device", ObjectID: strconv.FormatInt(id, 10),
		Details: map[string]any{"kind": kind}}
	if !s.change(w, r, ev, func(tx pgx.Tx, _ *audit.Event) error {
		if err := s.devices.DeleteProfile(r.Context(), tx, devices.Owner{Kind: devices.OwnerDevice, ID: id}, kind); err != nil {
			return err
		}
		return s.devices.RefreshInsecure(r.Context(), tx, id)
	}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

/* pollNow queues an immediate full poll; the job and its audit record commit together. */
func (s *server) pollNow(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if _, err := s.authorizeDevice(r, rbac.PermDevicesPoll, id); err != nil {
		s.fail(w, r, err)
		return
	}
	ev := audit.Event{Action: "devices.poll_now", ObjectType: "device", ObjectID: strconv.FormatInt(id, 10)}
	if !s.change(w, r, ev, func(tx pgx.Tx, _ *audit.Event) error {
		return s.jobs.EnqueuePollNow(r.Context(), tx, id)
	}) {
		return
	}
	w.WriteHeader(http.StatusAccepted)
}
