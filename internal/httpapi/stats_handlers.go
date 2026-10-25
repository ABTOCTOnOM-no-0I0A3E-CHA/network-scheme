package httpapi

import (
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/inventory"
	"github.com/beekamai/network-scheme/internal/metrics"
	"github.com/beekamai/network-scheme/internal/rbac"
	"github.com/beekamai/network-scheme/internal/store"
)

/*
Aggregates behind the dashboard widgets. Each one covers only the devices in
the caller's devices.read scope and returns a bounded number of rows.
*/
const (
	defaultTopLimit = 10
	maxTopLimit     = 50
	topSysWindow    = 15 * time.Minute /* a device's latest CPU/RAM sample must be newer than this */
	topIfWindow     = 10 * time.Minute /* an interface's latest sample must be newer than this */
	topIfTTL        = 30 * time.Second /* a ranking is reused this long for the same devices and limit */
	topIfCacheMax   = 256              /* rankings kept; beyond that the cache starts over */
)

/*
topIfCache keeps recent TopIfLoad rankings by the exact set of visible devices
(a hash of the sorted ids) and limit: dashboards of many users refresh the
widget often, and a ranking over thousands of devices is not cheap.
*/
type topIfCache struct {
	mu sync.Mutex
	m  map[topIfKey]topIfEntry
}

type topIfKey struct {
	ids   [sha256.Size]byte
	limit int
}

type topIfEntry struct {
	at  time.Time
	top []metrics.IfLoad
}

func newTopIfKey(ids []int64, limit int) topIfKey {
	sorted := slices.Sorted(slices.Values(ids))
	buf := make([]byte, 0, 8*len(sorted))
	for _, id := range sorted {
		buf = binary.LittleEndian.AppendUint64(buf, uint64(id)) //nolint:gosec // the bit pattern is hashed
	}
	return topIfKey{sha256.Sum256(buf), limit}
}

func (c *topIfCache) get(k topIfKey, now time.Time) ([]metrics.IfLoad, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	return e.top, ok && now.Sub(e.at) < topIfTTL && !now.Before(e.at)
}

func (c *topIfCache) put(k topIfKey, now time.Time, top []metrics.IfLoad) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil || len(c.m) >= topIfCacheMax {
		c.m = map[topIfKey]topIfEntry{}
	}
	c.m[k] = topIfEntry{now, top}
}

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

/* topInterfaces ranks the interfaces of visible devices by the load in their latest sample of the last 10 minutes (cached for topIfTTL). */
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
	ck, now := newTopIfKey(ids, limit), s.now()
	top, ok := s.topIf.get(ck, now)
	if !ok {
		if top, err = s.metrics.TopIfLoad(r.Context(), ids, now.Add(-topIfWindow), limit); err != nil {
			s.fail(w, r, err)
			return
		}
		s.topIf.put(ck, now, top)
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

/*
configDrift lists visible devices whose newest configuration version is
marked as drift, newest first: a drift superseded by a later version is no
longer listed. The partial drift index is walked in order; the query runs
under store.QueryTimeout.
*/
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
	var items []driftItem
	err = store.BoundedRead(r.Context(), s.pool, store.QueryTimeout, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `SELECT v.id, v.device_id, d.name, v.taken_at
			FROM backups.config_version v JOIN core.device d ON d.id = v.device_id
			WHERE v.drift AND ($1::bool OR d.group_id = ANY($2))
			  AND NOT EXISTS (SELECT 1 FROM backups.config_version n
			                  WHERE n.device_id = v.device_id AND (n.taken_at, n.id) > (v.taken_at, v.id))
			ORDER BY v.taken_at DESC, v.id DESC LIMIT $3`, sc.all, sc.ids, limit)
		if err != nil {
			return err
		}
		items, err = pgx.CollectRows(rows, pgx.RowToStructByPos[driftItem])
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items != nil {
		out.Items = items
	}
	writeJSON(w, http.StatusOK, out)
}
