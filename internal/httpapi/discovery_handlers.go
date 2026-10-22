package httpapi

import (
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/audit"
	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/rbac"
)

/* Limits of discovery scans. */
const (
	minScanIntervalS = 300
	maxScanIntervalS = 30 * 86400
	defScanIntervalS = 86400
)

/* scanProfileKinds: a scan probes with SNMP only, using its single assigned profile. */
var scanProfileKinds = map[string]bool{"snmp2c": true, "snmp3": true}

var inboxStatuses = map[string]bool{"pending": true, "accepted": true, "ignored": true}

type scanResponse struct {
	ID        int64      `json:"id"`
	CIDR      string     `json:"cidr"`
	GroupID   int64      `json:"group_id"`
	Enabled   bool       `json:"enabled"`
	IntervalS int        `json:"interval_s"`
	LastRunAt *time.Time `json:"last_run_at"`
}

type discoveredResponse struct {
	ID          int64     `json:"id"`
	ScanID      int64     `json:"scan_id"`
	GroupID     int64     `json:"group_id"`
	Address     string    `json:"address"`
	SysObjectID string    `json:"sys_object_id"`
	SysDescr    string    `json:"sys_descr"`
	SysName     string    `json:"sys_name"`
	FoundAt     time.Time `json:"found_at"`
	Status      string    `json:"status"`
}

/* parseScanCIDR returns the masked prefix, or the client error for an invalid or too wide one. */
func parseScanCIDR(s string) (netip.Prefix, apiError, bool) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, errBadRequest, false
	}
	switch err := devices.CheckScanPrefix(p); {
	case errors.Is(err, devices.ErrScanTooWide):
		return netip.Prefix{}, errCIDRTooWide, false
	case err != nil:
		return netip.Prefix{}, errBadRequest, false
	}
	return p.Masked(), apiError{}, true
}

func validScanInterval(v int) bool { return v >= minScanIntervalS && v <= maxScanIntervalS }

/* scanIn returns the scan if its group is in sc, devices.ErrNotFound otherwise. */
func (s *server) scanIn(r *http.Request, sc groupScope, id int64) (devices.Scan, error) {
	scan, err := s.devices.GetScan(r.Context(), id)
	if err != nil {
		return devices.Scan{}, err
	}
	if !sc.has(scan.GroupID) {
		return devices.Scan{}, devices.ErrNotFound
	}
	return scan, nil
}

/* discoveredIn returns the item if the group of its scan is in sc, devices.ErrNotFound otherwise. */
func (s *server) discoveredIn(r *http.Request, sc groupScope, id int64) (devices.Discovered, error) {
	d, err := s.devices.GetDiscovered(r.Context(), id)
	if err != nil {
		return devices.Discovered{}, err
	}
	if !sc.has(d.GroupID) {
		return devices.Discovered{}, devices.ErrNotFound
	}
	return d, nil
}

func (s *server) listScans(w http.ResponseWriter, r *http.Request) {
	sc, err := s.scope(r, rbac.PermDevicesManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	scans, err := s.devices.ListScans(r.Context(), sc.filter())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]scanResponse, 0, len(scans))
	for _, x := range scans {
		out = append(out, scanResponse{ID: x.ID, CIDR: x.CIDR.String(), GroupID: x.GroupID, Enabled: x.Enabled,
			IntervalS: x.IntervalS, LastRunAt: x.LastRunAt})
	}
	writeJSON(w, http.StatusOK, out)
}

/* createScan schedules a subnet scan whose finds land in the inbox of its group. */
func (s *server) createScan(w http.ResponseWriter, r *http.Request) {
	var in struct {
		CIDR      string `json:"cidr"`
		GroupID   int64  `json:"group_id"`
		IntervalS *int   `json:"interval_s"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	cidr, e, ok := parseScanCIDR(in.CIDR)
	if !ok {
		writeError(w, e)
		return
	}
	interval := defScanIntervalS
	if in.IntervalS != nil {
		interval = *in.IntervalS
	}
	if !validScanInterval(interval) {
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
	ev := audit.Event{Action: "discovery.scan_create", ObjectType: "discovery_scan",
		Details: map[string]any{"cidr": cidr.String(), "group_id": in.GroupID, "interval_s": interval}}
	if !s.change(w, r, ev, func(tx pgx.Tx, ev *audit.Event) error {
		var err error
		id, err = s.devices.CreateScan(r.Context(), tx, devices.NewScan{CIDR: cidr, GroupID: in.GroupID, Enabled: true, IntervalS: interval})
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

/* updateScan changes the given fields; moving a scan needs devices.manage on the target group. */
func (s *server) updateScan(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	sc, err := s.scope(r, rbac.PermDevicesManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.scanIn(r, sc, id); err != nil {
		s.fail(w, r, err)
		return
	}
	var in struct {
		CIDR      *string `json:"cidr"`
		GroupID   *int64  `json:"group_id"`
		Enabled   *bool   `json:"enabled"`
		IntervalS *int    `json:"interval_s"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	var p devices.ScanPatch
	details := map[string]any{}
	if in.CIDR != nil {
		cidr, e, ok := parseScanCIDR(*in.CIDR)
		if !ok {
			writeError(w, e)
			return
		}
		p.CIDR, details["cidr"] = &cidr, cidr.String()
	}
	if in.IntervalS != nil {
		if !validScanInterval(*in.IntervalS) {
			writeError(w, errBadRequest)
			return
		}
		p.IntervalS, details["interval_s"] = in.IntervalS, *in.IntervalS
	}
	if in.Enabled != nil {
		p.Enabled, details["enabled"] = in.Enabled, *in.Enabled
	}
	if in.GroupID != nil {
		p.GroupID, details["group_id"] = in.GroupID, *in.GroupID
	}
	if len(details) == 0 {
		writeError(w, errBadRequest)
		return
	}
	if in.GroupID != nil && !sc.has(*in.GroupID) {
		writeError(w, errNotFound)
		return
	}
	ev := audit.Event{Action: "discovery.scan_update", ObjectType: "discovery_scan", ObjectID: strconv.FormatInt(id, 10), Details: details}
	if !s.change(w, r, ev, func(tx pgx.Tx, _ *audit.Event) error {
		return s.devices.UpdateScan(r.Context(), tx, id, p)
	}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

/*
putScanProfile sets the one credential a scan probes with (sealed, opaque
to the API); setting one kind removes the other. An enabled scan is queued
for a run with the new credential in the same transaction.
*/
func (s *server) putScanProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	sc, err := s.scope(r, rbac.PermDeviceCredentials)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	scan, err := s.scanIn(r, sc, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in struct {
		Kind string `json:"kind"`
		sealedCredential
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if !scanProfileKinds[in.Kind] || !in.valid() {
		writeError(w, errBadRequest)
		return
	}
	owner := devices.Owner{Kind: devices.OwnerScan, ID: id}
	ev := audit.Event{Action: "devices.profile_set", ObjectType: "discovery_scan", ObjectID: strconv.FormatInt(id, 10),
		Details: map[string]any{"kind": in.Kind, "key_version": in.KeyVersion}}
	if !s.change(w, r, ev, func(tx pgx.Tx, _ *audit.Event) error {
		if err := s.checkKeyVersion(in.KeyVersion); err != nil {
			return err
		}
		if err := s.devices.PutProfile(r.Context(), tx, owner, in.Kind, in.Ciphertext, in.KeyVersion); err != nil {
			return err
		}
		for kind := range scanProfileKinds {
			if kind == in.Kind {
				continue
			}
			if err := s.devices.DeleteProfile(r.Context(), tx, owner, kind); err != nil && !errors.Is(err, devices.ErrNotFound) {
				return err
			}
		}
		if !scan.Enabled {
			return nil
		}
		return s.jobs.EnqueueDiscovery(r.Context(), tx, id)
	}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

/* listInbox lists finds of scans in the caller's groups; ?status= pending (default), accepted or ignored. */
func (s *server) listInbox(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "pending"
	}
	if !inboxStatuses[status] {
		writeError(w, errBadRequest)
		return
	}
	sc, err := s.scope(r, rbac.PermDevicesManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := s.devices.Inbox(r.Context(), devices.InboxFilter{All: sc.all, GroupIDs: sc.ids, Status: status})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]discoveredResponse, 0, len(items))
	for _, d := range items {
		out = append(out, discoveredResponse{ID: d.ID, ScanID: d.ScanID, GroupID: d.GroupID, Address: d.Address.String(),
			SysObjectID: d.SysObjectID, SysDescr: d.SysDescr, SysName: d.SysName, FoundAt: d.FoundAt, Status: d.Status})
	}
	writeJSON(w, http.StatusOK, out)
}

/* acceptDiscovered turns a pending find into a device in a group the caller manages. */
func (s *server) acceptDiscovered(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	sc, err := s.scope(r, rbac.PermDevicesManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	item, err := s.discoveredIn(r, sc, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in struct {
		Name    string `json:"name"`
		GroupID int64  `json:"group_id"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if !validGroupName(in.Name) {
		writeError(w, errBadRequest)
		return
	}
	if !sc.has(in.GroupID) {
		writeError(w, errNotFound)
		return
	}
	var devID int64
	ev := audit.Event{Action: "discovery.accept", ObjectType: "discovered", ObjectID: strconv.FormatInt(id, 10),
		Details: map[string]any{"name": in.Name, "group_id": in.GroupID, "address": item.Address.String()}}
	if !s.change(w, r, ev, func(tx pgx.Tx, ev *audit.Event) error {
		var err error
		if devID, err = s.devices.Accept(r.Context(), tx, id, in.Name, in.GroupID); err != nil {
			return err
		}
		ev.Details["device_id"] = devID
		return nil
	}) {
		return
	}
	writeJSON(w, http.StatusCreated, idResponse{ID: devID})
}

func (s *server) ignoreDiscovered(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	sc, err := s.scope(r, rbac.PermDevicesManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	item, err := s.discoveredIn(r, sc, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ev := audit.Event{Action: "discovery.ignore", ObjectType: "discovered", ObjectID: strconv.FormatInt(id, 10),
		Details: map[string]any{"address": item.Address.String()}}
	if !s.change(w, r, ev, func(tx pgx.Tx, _ *audit.Event) error {
		return s.devices.Ignore(r.Context(), tx, id)
	}) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
