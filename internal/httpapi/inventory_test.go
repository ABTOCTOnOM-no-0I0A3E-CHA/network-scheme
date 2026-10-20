package httpapi_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/inventory"
	"github.com/beekamai/network-scheme/internal/metrics"
	"github.com/beekamai/network-scheme/internal/rbac"
)

/* applyInventory stores n rows per table for dev as the poller, with device-controlled markup in the strings. */
func (f *fixture) applyInventory(dev int64, n int) {
	f.t.Helper()
	inv := drivers.NewInventory()
	for _, t := range []drivers.Table{drivers.TableInterfaces, drivers.TableARP, drivers.TableMAC, drivers.TableVLANs,
		drivers.TableLLDP, drivers.TableEntities, drivers.TableRoutes} {
		inv.Complete[t] = true
	}
	for i := 1; i <= n; i++ {
		b := byte(i)
		mac := fmt.Sprintf("00:11:22:33:44:%02x", b)
		inv.Interfaces = append(inv.Interfaces, drivers.Interface{Index: i, Name: fmt.Sprintf("ge%d", i), Alias: `<img src=x onerror=alert(1)>`, SpeedBps: 1e9, OperUp: true})
		inv.ARP = append(inv.ARP, drivers.ARPEntry{IP: netip.AddrFrom4([4]byte{10, 0, 0, b}), MAC: mac, IfIndex: i})
		inv.MAC = append(inv.MAC, drivers.MACEntry{MAC: mac, VLAN: 10, IfIndex: i})
		inv.VLANs = append(inv.VLANs, drivers.VLAN{ID: i, Name: "<script>"})
		inv.LLDP = append(inv.LLDP, drivers.LLDPNeighbor{LocalIfIndex: i, ChassisID: mac, PortID: "p", SysName: "sw", MgmtAddr: netip.AddrFrom4([4]byte{10, 1, 0, b})})
		inv.Entities = append(inv.Entities, drivers.Entity{Index: i, Class: "chassis", Name: "c", Model: "m", Serial: "s"})
		inv.Routes = append(inv.Routes, drivers.Route{Dest: netip.PrefixFrom(netip.AddrFrom4([4]byte{10, b, 0, 0}), 16), IfIndex: i, Proto: "local"})
	}
	if err := inventory.NewStore(f.env.Pool("nms_poller")).Apply(context.Background(), dev, inv, f.clk.Now()); err != nil {
		f.t.Fatal(err)
	}
}

type inventoryPage struct {
	Items      []map[string]any `json:"items"`
	NextOffset *int             `json:"next_offset"`
}

func TestInventoryEndpoints(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	viewer := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &g})
	dev := f.newDevice(g)
	f.applyInventory(dev, 5)

	for _, c := range []struct{ path, field string }{
		{"interfaces", "if_index"}, {"arp", "ip"}, {"mac", "mac"}, {"vlans", "vlan_id"},
		{"lldp", "chassis_id"}, {"entities", "ent_index"}, {"routes", "dest"},
	} {
		resp := f.do(viewer.authed(req{method: "GET", path: fmt.Sprintf("/api/devices/%d/%s", dev, c.path)}))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d", c.path, resp.StatusCode)
		}
		p := decode[inventoryPage](t, resp)
		if len(p.Items) != 5 || p.NextOffset != nil {
			t.Errorf("%s: %d items, next %v", c.path, len(p.Items), p.NextOffset)
			continue
		}
		if _, ok := p.Items[0][c.field]; !ok {
			t.Errorf("%s: row lacks %s: %v", c.path, c.field, p.Items[0])
		}
		if s, _ := p.Items[0]["seen_at"].(string); s == "" {
			t.Errorf("%s: row lacks seen_at: %v", c.path, p.Items[0])
		}
	}

	/* Device strings come back verbatim as JSON strings, never as markup. */
	resp := f.do(viewer.authed(req{method: "GET", path: fmt.Sprintf("/api/devices/%d/interfaces?limit=2", dev)}))
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content type %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "<img") {
		t.Errorf("markup not escaped in JSON: %s", body)
	}
	resp = f.do(viewer.authed(req{method: "GET", path: fmt.Sprintf("/api/devices/%d/interfaces?limit=2", dev)}))
	p := decode[inventoryPage](t, resp)
	if len(p.Items) != 2 || p.NextOffset == nil || *p.NextOffset != 2 || p.Items[0]["alias"] != `<img src=x onerror=alert(1)>` {
		t.Errorf("first page = %+v", p)
	}
	resp = f.do(viewer.authed(req{method: "GET", path: fmt.Sprintf("/api/devices/%d/interfaces?limit=2&offset=4", dev)}))
	p = decode[inventoryPage](t, resp)
	if len(p.Items) != 1 || p.NextOffset != nil || p.Items[0]["if_index"] != float64(5) {
		t.Errorf("last page = %+v", p)
	}
	for _, q := range []string{"limit=0", "limit=1001", "limit=x", "offset=-1", "offset=x", "limit=2&limit=3"} {
		wantError(t, f.do(viewer.authed(req{method: "GET", path: fmt.Sprintf("/api/devices/%d/arp?%s", dev, q)})), http.StatusBadRequest, "bad_request")
	}
	resp = f.do(viewer.authed(req{method: "GET", path: fmt.Sprintf("/api/devices/%d/routes?limit=1000", dev)}))
	if resp.StatusCode != http.StatusOK {
		t.Errorf("limit=1000: status %d", resp.StatusCode)
	}
	/* A device without inventory has an empty list, not null. */
	empty := f.newDevice(g)
	resp = f.do(viewer.authed(req{method: "GET", path: fmt.Sprintf("/api/devices/%d/vlans", empty)}))
	if b, _ := io.ReadAll(resp.Body); !strings.Contains(string(b), `"items":[]`) {
		t.Errorf("empty device: %s", b)
	}
	/* A foreign device answers 404 even with a bad query. */
	other := f.newDevice(f.newGroup())
	wantError(t, f.do(viewer.authed(req{method: "GET", path: fmt.Sprintf("/api/devices/%d/arp?limit=0", other)})), http.StatusNotFound, "not_found")
}

type ifPoints struct {
	StepS  int64            `json:"step_s"`
	Points []map[string]any `json:"points"`
}

func TestIfMetricsEndpoint(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	viewer := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &g})
	dev := f.newDevice(g)
	now := time.Now().UTC().Truncate(5 * time.Minute)
	var pts []metrics.IfPoint
	for i := range 10 {
		pts = append(pts, metrics.IfPoint{DeviceID: dev, IfIndex: 3, TS: now.Add(time.Duration(i-10) * time.Minute), InBps: 100, OutBps: 200, OperUp: true, SpeedBps: 1e9})
	}
	if err := metrics.NewStore(f.env.Pool("nms_poller")).WriteIf(context.Background(), pts); err != nil {
		t.Fatal(err)
	}
	get := func(q url.Values) *http.Response {
		return f.do(viewer.authed(req{method: "GET", path: fmt.Sprintf("/api/devices/%d/metrics/if?%s", dev, q.Encode())}))
	}
	rfc := func(t time.Time) string { return t.Format(time.RFC3339) }
	q := url.Values{"if_index": {"3"}, "from": {rfc(now.Add(-time.Hour))}, "to": {rfc(now)}}
	resp := get(q)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("raw: status %d", resp.StatusCode)
	}
	got := decode[ifPoints](t, resp)
	if len(got.Points) != 10 || got.StepS != 0 || got.Points[0]["in_bps"] != float64(100) || got.Points[0]["in_err_ps"] != nil {
		t.Errorf("raw = %+v", got)
	}
	q.Set("step", "300")
	got = decode[ifPoints](t, get(q))
	if got.StepS != 300 || len(got.Points) != 2 {
		t.Errorf("5-minute buckets = %+v", got)
	}

	/* A day of raw points at the 10 s poll floor is 8640 points: too many; a 60 s step is 1440. */
	day := url.Values{"if_index": {"3"}, "from": {rfc(now.Add(-24 * time.Hour))}, "to": {rfc(now)}}
	wantError(t, get(day), http.StatusBadRequest, "too_many_points")
	day.Set("step", "60")
	if resp := get(day); resp.StatusCode != http.StatusOK {
		t.Errorf("day at 60 s: status %d", resp.StatusCode)
	}
	/* The cap counts the clamped step: 1 s on a 30-day range reads 5-minute aggregates (8640 points). */
	month := url.Values{"if_index": {"3"}, "from": {rfc(now.Add(-30 * 24 * time.Hour))}, "to": {rfc(now)}, "step": {"1"}}
	wantError(t, get(month), http.StatusBadRequest, "too_many_points")
	/* Two years of hourly aggregates (17520 points) need a step of at least 4 h. */
	years := url.Values{"if_index": {"3"}, "from": {rfc(now.Add(-730 * 24 * time.Hour))}, "to": {rfc(now)}, "step": {"14400"}}
	if resp := get(years); resp.StatusCode != http.StatusOK {
		t.Errorf("2 years at 4 h: status %d", resp.StatusCode)
	}

	bad := []url.Values{
		{"from": {rfc(now.Add(-time.Hour))}, "to": {rfc(now)}},                                                  /* no if_index */
		{"if_index": {"0"}, "from": {rfc(now.Add(-time.Hour))}, "to": {rfc(now)}},                               /* if_index < 1 */
		{"if_index": {"3"}, "to": {rfc(now)}},                                                                   /* no from */
		{"if_index": {"3"}, "from": {"yesterday"}, "to": {rfc(now)}},                                            /* not RFC3339 */
		{"if_index": {"3"}, "from": {rfc(now)}, "to": {rfc(now)}},                                               /* empty range */
		{"if_index": {"3"}, "from": {rfc(now)}, "to": {rfc(now.Add(-time.Hour))}},                               /* inverted */
		{"if_index": {"3"}, "from": {rfc(now.Add(-731 * 24 * time.Hour))}, "to": {rfc(now)}, "step": {"86400"}}, /* > 2 years */
		{"if_index": {"3"}, "from": {rfc(now.Add(-time.Hour))}, "to": {rfc(now)}, "step": {"0"}},                /* step < 1 */
		{"if_index": {"3"}, "from": {rfc(now.Add(-time.Hour))}, "to": {rfc(now)}, "step": {"1m"}},               /* step not seconds */
	}
	for _, q := range bad {
		wantError(t, get(q), http.StatusBadRequest, "bad_request")
	}
}

func TestDeviceStateFromStatusView(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	viewer := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &g})
	dev, silent := f.newDevice(g), f.newDevice(g)
	ctx := context.Background()
	st := inventory.NewStore(f.env.Pool("nms_poller"))
	since := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	if err := st.SetStatus(ctx, dev, "down", since, "timeout"); err != nil {
		t.Fatal(err)
	}
	/* Devices default to poller "local". */
	if err := st.Heartbeat(ctx, "local", time.Now()); err != nil {
		t.Fatal(err)
	}
	list := decode[[]deviceItem](t, f.do(viewer.authed(req{method: "GET", path: "/api/devices"})))
	byID := map[int64]deviceItem{}
	for _, d := range list {
		byID[d.ID] = d
	}
	if d := byID[dev]; d.State != "down" || d.StateSince == nil || !mustTime(t, *d.StateSince).Equal(since) {
		t.Errorf("list state = %+v", d)
	}
	if d := byID[silent]; d.State != "unknown" || d.StateSince != nil {
		t.Errorf("never polled = %+v", d)
	}
	detail := decode[deviceItem](t, f.do(viewer.authed(req{method: "GET", path: fmt.Sprintf("/api/devices/%d", dev)})))
	if detail.State != "down" || detail.StateSince == nil {
		t.Errorf("detail state = %+v", detail)
	}
	/* The poller goes silent: unknown. */
	if _, err := f.env.Pool("postgres").Exec(ctx, `UPDATE inventory.poller_heartbeat SET at = now() - interval '91 seconds' WHERE poller_id = 'local'`); err != nil {
		t.Fatal(err)
	}
	detail = decode[deviceItem](t, f.do(viewer.authed(req{method: "GET", path: fmt.Sprintf("/api/devices/%d", dev)})))
	if detail.State != "unknown" {
		t.Errorf("stale heartbeat detail = %+v", detail)
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
