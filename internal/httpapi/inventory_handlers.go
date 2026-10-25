package httpapi

import (
	"context"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/beekamai/network-scheme/internal/inventory"
	"github.com/beekamai/network-scheme/internal/rbac"
)

/* Limits of the inventory and metric reads. */
const (
	defaultInventoryPage = 200
	maxInventoryPage     = 1000
	maxMetricPoints      = 5000
	maxMetricRange       = 2 * 365 * 24 * time.Hour
	/* rawSpacing is the densest raw sampling (the minimum poll interval), used to bound raw reads. */
	rawSpacing = minIntervalS * time.Second
)

/* inventoryPage is one page of inventory rows; next_offset is null on the last page. */
type inventoryPage[T any] struct {
	Items      []T  `json:"items"`
	NextOffset *int `json:"next_offset"`
}

/* queryInt reads an optional single-valued integer query parameter within [lo, hi]. */
func queryInt(q url.Values, name string, def, lo, hi int) (int, bool) {
	vs, ok := q[name]
	if !ok {
		return def, true
	}
	if len(vs) != 1 {
		return 0, false
	}
	n, err := strconv.Atoi(vs[0])
	if err != nil || n < lo || n > hi {
		return 0, false
	}
	return n, true
}

/*
inventoryList serves one inventory table of a device page by page. The
device check runs first, so a foreign device answers 404 whatever the query.
*/
func inventoryList[T any](s *server, list func(*inventory.Store, context.Context, int64, inventory.Page) ([]T, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(w, r)
		if !ok {
			return
		}
		if _, err := s.authorizeDevice(r, rbac.PermDevicesRead, id); err != nil {
			s.fail(w, r, err)
			return
		}
		q := r.URL.Query()
		limit, okL := queryInt(q, "limit", defaultInventoryPage, 1, maxInventoryPage)
		offset, okO := queryInt(q, "offset", 0, 0, math.MaxInt32)
		if !okL || !okO {
			writeError(w, errBadRequest)
			return
		}
		/* One extra row tells whether another page follows. */
		rows, err := list(s.inventory, r.Context(), id, inventory.Page{Limit: limit + 1, Offset: offset})
		if err != nil {
			s.fail(w, r, err)
			return
		}
		out := inventoryPage[T]{Items: rows}
		if len(rows) > limit {
			out.Items = rows[:limit]
			next := offset + limit
			out.NextOffset = &next
		}
		if out.Items == nil {
			out.Items = []T{}
		}
		writeJSON(w, http.StatusOK, out)
	}
}

type ifPointResponse struct {
	TS        time.Time `json:"ts"`
	InBps     float64   `json:"in_bps"`
	InBpsMax  float64   `json:"in_bps_max"`
	OutBps    float64   `json:"out_bps"`
	OutBpsMax float64   `json:"out_bps_max"`
	InErrPS   *float64  `json:"in_err_ps"`
	OutErrPS  *float64  `json:"out_err_ps"`
	InDiscPS  *float64  `json:"in_disc_ps"`
	OutDiscPS *float64  `json:"out_disc_ps"`
	OperUp    bool      `json:"oper_up"`
	SpeedBps  int64     `json:"speed_bps"`
}

type ifPointsResponse struct {
	StepS  int64             `json:"step_s"` /* bucket width in seconds; 0: raw points */
	Points []ifPointResponse `json:"points"`
}

/* parseRFC3339 reads a required single-valued timestamp. */
func parseRFC3339(q url.Values, name string) (time.Time, bool) {
	vs := q[name]
	if len(vs) != 1 {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, vs[0])
	return t, err == nil
}

/*
metricRange reads from, to and step of a metric read and returns the bucket
width the store will use. The answer is bounded: a range of at most two years
and at most maxMetricPoints buckets after the store clamps the step to its
source resolution (raw points are counted at the densest poll interval).
*/
func (s *server) metricRange(w http.ResponseWriter, q url.Values) (from, to time.Time, step, bucket time.Duration, ok bool) {
	stepS, okS := queryInt(q, "step", 0, 1, int(maxMetricRange/time.Second))
	from, okF := parseRFC3339(q, "from")
	to, okT := parseRFC3339(q, "to")
	if !okS || !okF || !okT || !to.After(from) || to.Sub(from) > maxMetricRange {
		writeError(w, errBadRequest)
		return from, to, 0, 0, false
	}
	step = time.Duration(stepS) * time.Second
	bucket = s.metrics.IfStep(from, to, step)
	spacing := bucket
	if spacing == 0 {
		spacing = rawSpacing
	}
	if (to.Sub(from)+spacing-1)/spacing > maxMetricPoints {
		writeError(w, errTooManyPoints)
		return from, to, 0, 0, false
	}
	return from, to, step, bucket, true
}

/* ifMetrics returns the rate series of one interface, bounded by metricRange. */
func (s *server) ifMetrics(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if _, err := s.authorizeDevice(r, rbac.PermDevicesRead, id); err != nil {
		s.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	ifIndex, okI := queryInt(q, "if_index", 0, 1, math.MaxInt32)
	if _, given := q["if_index"]; !given || !okI {
		writeError(w, errBadRequest)
		return
	}
	from, to, step, bucket, ok := s.metricRange(w, q)
	if !ok {
		return
	}
	pts, err := s.metrics.QueryIf(r.Context(), id, ifIndex, from, to, step)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := ifPointsResponse{StepS: int64(bucket / time.Second), Points: make([]ifPointResponse, 0, len(pts))}
	for _, p := range pts {
		out.Points = append(out.Points, ifPointResponse{
			TS: p.TS, InBps: p.InBps, InBpsMax: p.InBpsMax, OutBps: p.OutBps, OutBpsMax: p.OutBpsMax,
			InErrPS: p.InErrPS, OutErrPS: p.OutErrPS, InDiscPS: p.InDiscPS, OutDiscPS: p.OutDiscPS,
			OperUp: p.OperUp, SpeedBps: p.SpeedBps,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

type sysPointResponse struct {
	TS         time.Time `json:"ts"`
	CPUPct     *float64  `json:"cpu_pct"`
	MemUsedPct *float64  `json:"mem_used_pct"`
	TempC      *float64  `json:"temp_c"`
}

/* sysMetrics returns the CPU, memory and temperature series of one device, bounded like ifMetrics. */
func (s *server) sysMetrics(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if _, err := s.authorizeDevice(r, rbac.PermDevicesRead, id); err != nil {
		s.fail(w, r, err)
		return
	}
	from, to, step, bucket, ok := s.metricRange(w, r.URL.Query())
	if !ok {
		return
	}
	pts, err := s.metrics.QuerySys(r.Context(), id, from, to, step)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := struct {
		StepS  int64              `json:"step_s"`
		Points []sysPointResponse `json:"points"`
	}{int64(bucket / time.Second), make([]sysPointResponse, 0, len(pts))}
	for _, p := range pts {
		out.Points = append(out.Points, sysPointResponse{TS: p.TS, CPUPct: p.CPUPct, MemUsedPct: p.MemUsedPct, TempC: p.TempC})
	}
	writeJSON(w, http.StatusOK, out)
}
