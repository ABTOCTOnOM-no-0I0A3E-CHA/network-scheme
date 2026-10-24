package httpapi

import (
	"cmp"
	"net/http"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/inventory"
	"github.com/beekamai/network-scheme/internal/rbac"
)

/*
Aggregates behind the dashboard widgets. Each one covers only the devices in
the caller's devices.read scope and returns a bounded number of rows.
*/
const (
	defaultTopLimit = 10
	maxTopLimit     = 50
	topSysWindow    = 15 * time.Minute /* a device's latest CPU/RAM sample must be newer than this */
	topIfWindow     = 10 * time.Minute /* interface load is averaged over this window */
)

var topDeviceMetrics = map[string]bool{"cpu": true, "mem": true, "uptime": true}

/* visibleDevices lists the devices the caller may read, by id. */
func (s *server) visibleDevices(r *http.Request) (map[int64]devices.Device, []int64, error) {
	sc, err := s.scope(r, rbac.PermDevicesRead)
	if err != nil {
		return nil, nil, err
	}
	if !sc.all && len(sc.ids) == 0 {
		return map[int64]devices.Device{}, nil, nil
	}
	ds, err := s.devices.List(r.Context(), sc.filter())
	if err != nil {
		return nil, nil, err
	}
	byID := make(map[int64]devices.Device, len(ds))
	ids := make([]int64, 0, len(ds))
	for _, d := range ds {
		byID[d.ID] = d
		ids = append(ids, d.ID)
	}
	return byID, ids, nil
}

type deviceStatesResponse struct {
	Total   int `json:"total"`
	Up      int `json:"up"`
	Partial int `json:"partial"`
	Down    int `json:"down"`
	Unknown int `json:"unknown"`
}

/* deviceStateCounts counts the visible devices by availability state. */
func (s *server) deviceStateCounts(w http.ResponseWriter, r *http.Request) {
	_, ids, err := s.visibleDevices(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	states, err := s.inventory.States(r.Context(), ids)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := deviceStatesResponse{Total: len(ids)}
	for _, id := range ids {
		switch states[id].State {
		case inventory.StateUp:
			out.Up++
		case inventory.StatePartial:
			out.Partial++
		case inventory.StateDown:
			out.Down++
		default:
			out.Unknown++
		}
	}
	writeJSON(w, http.StatusOK, out)
}

/* topDeviceItem: value is a percentage for cpu and mem, seconds for uptime; at is the sample time or the start of the uptime. */
type topDeviceItem struct {
	DeviceID   int64     `json:"device_id"`
	DeviceName string    `json:"device_name"`
	Value      float64   `json:"value"`
	At         time.Time `json:"at"`
}

type itemsResponse[T any] struct {
	Items []T `json:"items"`
}

/*
topDevices ranks the visible devices by their latest CPU or RAM load, or by
uptime: how long a device has been continuously available (state up).
*/
func (s *server) topDevices(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	metric, okM := single(q, "metric")
	limit, okL := queryInt(q, "limit", defaultTopLimit, 1, maxTopLimit)
	if !okM || !okL || !topDeviceMetrics[metric] {
		writeError(w, errBadRequest)
		return
	}
	byID, ids, err := s.visibleDevices(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := itemsResponse[topDeviceItem]{Items: []topDeviceItem{}}
	now := s.now()
	if metric == "uptime" {
		states, err := s.inventory.States(r.Context(), ids)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		for _, id := range ids {
			if st := states[id]; st.State == inventory.StateUp && st.Since != nil {
				out.Items = append(out.Items, topDeviceItem{DeviceID: id, DeviceName: byID[id].Name, Value: now.Sub(*st.Since).Seconds(), At: *st.Since})
			}
		}
		/* Longest up first: the earliest start. */
		slices.SortFunc(out.Items, func(a, b topDeviceItem) int {
			return cmp.Or(a.At.Compare(b.At), cmp.Compare(a.DeviceID, b.DeviceID))
		})
		out.Items = out.Items[:min(limit, len(out.Items))]
		writeJSON(w, http.StatusOK, out)
		return
	}
	top, err := s.metrics.TopSys(r.Context(), metric, ids, now.Add(-topSysWindow), limit)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, t := range top {
		out.Items = append(out.Items, topDeviceItem{DeviceID: t.DeviceID, DeviceName: byID[t.DeviceID].Name, Value: t.Value, At: t.TS})
	}
	writeJSON(w, http.StatusOK, out)
}

type topInterfaceItem struct {
	DeviceID   int64   `json:"device_id"`
	DeviceName string  `json:"device_name"`
	IfIndex    int     `json:"if_index"`
	PortName   string  `json:"port_name"`
	InBps      float64 `json:"in_bps"`
	OutBps     float64 `json:"out_bps"`
	SpeedBps   int64   `json:"speed_bps"`
	UtilPct    float64 `json:"util_pct"`
}

/* topInterfaces ranks the interfaces of visible devices by their average load over the last 10 minutes. */
func (s *server) topInterfaces(w http.ResponseWriter, r *http.Request) {
	limit, ok := queryInt(r.URL.Query(), "limit", defaultTopLimit, 1, maxTopLimit)
	if !ok {
		writeError(w, errBadRequest)
		return
	}
	byID, ids, err := s.visibleDevices(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	top, err := s.metrics.TopIfLoad(r.Context(), ids, s.now().Add(-topIfWindow), limit)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := itemsResponse[topInterfaceItem]{Items: make([]topInterfaceItem, 0, len(top))}
	if len(top) == 0 {
		writeJSON(w, http.StatusOK, out)
		return
	}
	devs, ifs := make([]int64, len(top)), make([]int32, len(top))
	for i, t := range top {
		devs[i], ifs[i] = t.DeviceID, int32(t.IfIndex) //nolint:gosec // if_index is an int column
	}
	/* Port names are the interface name, else its alias, else empty (device data). */
	rows, err := s.pool.Query(r.Context(), `SELECT i.device_id, i.if_index, coalesce(nullif(i.name, ''), nullif(i.alias, ''), '')
		FROM inventory.interface i JOIN unnest($1::bigint[], $2::int[]) AS k(d, x) ON i.device_id = k.d AND i.if_index = k.x`, devs, ifs)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	type key struct {
		dev int64
		idx int
	}
	names := map[key]string{}
	var (
		k    key
		name string
	)
	if _, err := pgx.ForEachRow(rows, []any{&k.dev, &k.idx, &name}, func() error {
		names[k] = name
		return nil
	}); err != nil {
		s.fail(w, r, err)
		return
	}
	for _, t := range top {
		out.Items = append(out.Items, topInterfaceItem{DeviceID: t.DeviceID, DeviceName: byID[t.DeviceID].Name, IfIndex: t.IfIndex,
			PortName: names[key{t.DeviceID, t.IfIndex}], InBps: t.InBps, OutBps: t.OutBps, SpeedBps: t.SpeedBps, UtilPct: t.UtilPct})
	}
	writeJSON(w, http.StatusOK, out)
}

type driftItem struct {
	VersionID  int64     `json:"version_id"`
	DeviceID   int64     `json:"device_id"`
	DeviceName string    `json:"device_name"`
	TakenAt    time.Time `json:"taken_at"`
}

/* configDrift lists the latest configuration versions marked as drift on visible devices, newest first. */
func (s *server) configDrift(w http.ResponseWriter, r *http.Request) {
	limit, ok := queryInt(r.URL.Query(), "limit", defaultTopLimit, 1, maxTopLimit)
	if !ok {
		writeError(w, errBadRequest)
		return
	}
	sc, err := s.scope(r, rbac.PermDevicesRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := itemsResponse[driftItem]{Items: []driftItem{}}
	if !sc.all && len(sc.ids) == 0 {
		writeJSON(w, http.StatusOK, out)
		return
	}
	rows, err := s.pool.Query(r.Context(), `SELECT v.id, v.device_id, d.name, v.taken_at
		FROM backups.config_version v JOIN core.device d ON d.id = v.device_id
		WHERE v.drift AND ($1::bool OR d.group_id = ANY($2))
		ORDER BY v.taken_at DESC, v.id DESC LIMIT $3`, sc.all, sc.ids, limit)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, pgx.RowToStructByPos[driftItem])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items != nil {
		out.Items = items
	}
	writeJSON(w, http.StatusOK, out)
}
