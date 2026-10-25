package httpapi_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/rbac"
)

type searchJSON struct {
	Devices struct {
		Items []struct {
			ID      int64  `json:"id"`
			Name    string `json:"name"`
			Address string `json:"address"`
		} `json:"items"`
		More bool `json:"more"`
	} `json:"devices"`
	IPs struct {
		Items []struct {
			DeviceID int64  `json:"device_id"`
			IP       string `json:"ip"`
			MAC      string `json:"mac"`
			PortName string `json:"port_name"`
		} `json:"items"`
		More bool `json:"more"`
	} `json:"ips"`
	MACs struct {
		Items []struct {
			DeviceID int64   `json:"device_id"`
			MAC      string  `json:"mac"`
			Source   string  `json:"source"`
			VLAN     *int    `json:"vlan"`
			IP       *string `json:"ip"`
			PortName string  `json:"port_name"`
		} `json:"items"`
		More bool `json:"more"`
	} `json:"macs"`
	Ports struct {
		Items []struct {
			DeviceID int64  `json:"device_id"`
			IfIndex  int    `json:"if_index"`
			Name     string `json:"name"`
			Alias    string `json:"alias"`
		} `json:"items"`
		More bool `json:"more"`
	} `json:"ports"`
}

func (r searchJSON) counts() [4]int {
	return [4]int{len(r.Devices.Items), len(r.IPs.Items), len(r.MACs.Items), len(r.Ports.Items)}
}

/* searchAs runs GET /api/search?q= as s and expects 200. */
func (f *fixture) searchAs(s *subject, q string) searchJSON {
	f.t.Helper()
	resp := f.do(s.authed(req{method: "GET", path: "/api/search?q=" + url.QueryEscape(q)}))
	if resp.StatusCode != http.StatusOK {
		f.t.Fatalf("search %q: status %d", q, resp.StatusCode)
	}
	return decode[searchJSON](f.t, resp)
}

/* namedDevice creates a device called name in group g and returns its id and address. */
func (f *fixture) namedDevice(g int64, name string) (int64, string) {
	f.t.Helper()
	var id int64
	addr := nextAddr()
	f.inTx(func(ctx context.Context, tx pgx.Tx, st *devices.Store) (err error) {
		id, err = st.Create(ctx, tx, devices.NewDevice{Name: name, Address: addr, GroupID: g})
		return err
	})
	return id, addr.String()
}

func (f *fixture) newARP(dev int64, ip, mac string, ifIndex int) {
	f.exec(`INSERT INTO inventory.arp_entry (device_id, ip, mac, if_index, seen_at) VALUES ($1, $2, $3, $4, now())`, dev, ip, mac, ifIndex)
}

func (f *fixture) newFDB(dev int64, mac string, vlan, ifIndex int) {
	f.exec(`INSERT INTO inventory.mac_entry (device_id, mac, vlan, if_index, seen_at) VALUES ($1, $2, $3, $4, now())`, dev, mac, vlan, ifIndex)
}

/* TestSearchTypes: every result type is found, with MACs in any notation. */
func TestSearchTypes(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	viewer := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &g})
	tok := uniqueName("srch")
	dev, addr := f.namedDevice(g, "core-"+tok)
	f.newIface(dev, 7, "xe-0/0/7", "uplink to "+tok, 1e10)
	f.newARP(dev, "10.77.1.5", "02:aa:bb:cc:dd:ee", 7)
	f.newFDB(dev, "02:aa:bb:cc:dd:ee", 30, 7)

	if r := f.searchAs(viewer, strings.ToUpper(tok)); len(r.Devices.Items) != 1 || r.Devices.Items[0].ID != dev || r.Devices.Items[0].Address != addr {
		t.Errorf("device by name: %+v", r.Devices)
	}
	if r := f.searchAs(viewer, addr[:strings.LastIndex(addr, ".")+1]); len(r.Devices.Items) != 1 || r.Devices.Items[0].ID != dev {
		t.Errorf("device by address prefix: %+v", r.Devices)
	}
	if r := f.searchAs(viewer, "10.77.1"); len(r.IPs.Items) != 1 || r.IPs.Items[0].IP != "10.77.1.5" || r.IPs.Items[0].MAC != "02:aa:bb:cc:dd:ee" || r.IPs.Items[0].PortName != "xe-0/0/7" {
		t.Errorf("ARP by address prefix: %+v", r.IPs)
	} else if len(r.MACs.Items) != 0 {
		t.Errorf("a dotted decimal query matched MACs: %+v", r.MACs)
	}
	for _, q := range []string{"02:aa:bb:cc:dd:ee", "02-AA-BB-CC-DD-EE", "02aa.bbcc.ddee", "02AABBCCDDEE", "02:aa:bb", "02-AA-b", "02aab"} {
		r := f.searchAs(viewer, q)
		if len(r.MACs.Items) != 2 {
			t.Errorf("MAC %q: %+v", q, r.MACs)
			continue
		}
		fdb, arp := r.MACs.Items[1], r.MACs.Items[0] /* ordered by source: arp, fdb */
		if arp.Source != "arp" || arp.IP == nil || *arp.IP != "10.77.1.5" || arp.VLAN != nil || arp.PortName != "xe-0/0/7" ||
			fdb.Source != "fdb" || fdb.VLAN == nil || *fdb.VLAN != 30 || fdb.IP != nil || fdb.MAC != "02:aa:bb:cc:dd:ee" {
			t.Errorf("MAC %q: arp %+v fdb %+v", q, arp, fdb)
		}
	}
	if r := f.searchAs(viewer, "02:a"); len(r.MACs.Items) != 0 {
		t.Errorf("three hex digits matched MACs: %+v", r.MACs)
	}
	if r := f.searchAs(viewer, "02:aa:bb:cc:dd:ef"); len(r.MACs.Items) != 0 {
		t.Errorf("another MAC matched: %+v", r.MACs)
	}
	if r := f.searchAs(viewer, "xe"); len(r.Ports.Items) != 0 {
		t.Errorf("a two-character query searched ports: %+v", r.Ports)
	}
	for _, q := range []string{"XE-", "uplink to " + tok} {
		if r := f.searchAs(viewer, q); len(r.Ports.Items) != 1 || r.Ports.Items[0].DeviceID != dev || r.Ports.Items[0].IfIndex != 7 {
			t.Errorf("port %q: %+v", q, r.Ports)
		}
	}
}

/* TestSearchScope: a group-bound user finds nothing of a foreign group, whatever the type. */
func TestSearchScope(t *testing.T) {
	f := newFixture(t, nil)
	a, b := f.newGroup(), f.newGroup()
	tok := uniqueName("scope")
	devA, _ := f.namedDevice(a, "a-"+tok)
	devB, _ := f.namedDevice(b, "b-"+tok)
	for i, d := range []int64{devA, devB} {
		f.newIface(d, 1, "ge-"+tok, "", 1000)
		f.newARP(d, fmt.Sprintf("10.78.0.%d", i+1), fmt.Sprintf("02:bb:00:00:00:%02x", i+1), 1)
		f.newFDB(d, fmt.Sprintf("02:bb:00:00:00:%02x", i+1), 1, 1)
	}
	viewerA := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &a})
	for _, q := range []string{tok, "10.78.0", "02:bb:00"} {
		r := f.searchAs(viewerA, q)
		for _, d := range r.Devices.Items {
			if d.ID != devA {
				t.Errorf("%q as viewerA found device %d", q, d.ID)
			}
		}
		for _, ip := range r.IPs.Items {
			if ip.DeviceID != devA {
				t.Errorf("%q as viewerA found ARP of device %d", q, ip.DeviceID)
			}
		}
		for _, m := range r.MACs.Items {
			if m.DeviceID != devA {
				t.Errorf("%q as viewerA found MAC of device %d", q, m.DeviceID)
			}
		}
		for _, p := range r.Ports.Items {
			if p.DeviceID != devA {
				t.Errorf("%q as viewerA found port of device %d", q, p.DeviceID)
			}
		}
	}
	if c := f.searchAs(viewerA, tok).counts(); c != [4]int{1, 0, 0, 1} {
		t.Errorf("token as viewerA: counts %v", c)
	}
	if c := f.searchAs(viewerA, "02:bb:00").counts(); c != [4]int{0, 0, 2, 0} {
		t.Errorf("MAC as viewerA: counts %v", c)
	}
	/* The global viewer sees both groups; a user of a third group sees nothing. */
	if c := f.searchAs(f.login(false, rbac.Binding{Role: rbac.RoleViewer}), tok).counts(); c != [4]int{2, 0, 0, 2} {
		t.Errorf("token as global viewer: counts %v", c)
	}
	other := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: ptr(f.newGroup())})
	for _, q := range []string{tok, "10.78.0", "02:bb:00"} {
		if c := f.searchAs(other, q).counts(); c != [4]int{} {
			t.Errorf("%q in an empty scope: counts %v", q, c)
		}
	}
}

/* TestSearchQueryBounds: empty and short queries find nothing; long, repeated, control-character and non-UTF-8 ones are rejected. */
func TestSearchQueryBounds(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	viewer := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &g})
	f.namedDevice(g, "a")
	const empty = `{"devices":{"items":[],"more":false},"ips":{"items":[],"more":false},"macs":{"items":[],"more":false},"ports":{"items":[],"more":false}}` + "\n"
	for _, p := range []string{"/api/search", "/api/search?q=", "/api/search?q=a", "/api/search?q=+a+", "/api/search?q=%20%20%20"} {
		resp := f.do(viewer.authed(req{method: "GET", path: p}))
		if b := body(t, resp); resp.StatusCode != http.StatusOK || b != empty {
			t.Errorf("%s: %d %s", p, resp.StatusCode, b)
		}
	}
	if r := f.searchAs(viewer, strings.Repeat("я", 100)); r.counts() != [4]int{} {
		t.Errorf("100 characters: %v", r.counts())
	}
	for _, p := range []string{"/api/search?q=" + strings.Repeat("a", 101), "/api/search?q=ab&q=cd", "/api/search?q=%01ab", "/api/search?q=a%00b", "/api/search?q=%ff%fe"} {
		wantError(t, f.do(viewer.authed(req{method: "GET", path: p})), http.StatusBadRequest, "bad_request")
	}
}

/* TestSearchLikeEscaping: %, _ and \ in the query match themselves only. */
func TestSearchLikeEscaping(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	viewer := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &g})
	tok := uniqueName("esc")
	for _, c := range []struct{ match, other string }{
		{tok + "a_b", tok + "axb"},
		{tok + "50%off", tok + "50xoff"},
		{tok + `c\d`, tok + "cd"},
	} {
		want, _ := f.namedDevice(g, c.match)
		f.namedDevice(g, c.other)
		if r := f.searchAs(viewer, c.match); len(r.Devices.Items) != 1 || r.Devices.Items[0].ID != want {
			t.Errorf("%q: %+v", c.match, r.Devices.Items)
		}
	}
	if r := f.searchAs(viewer, "%%"); len(r.Devices.Items) != 0 {
		t.Errorf("%%%% matched %+v", r.Devices.Items)
	}
	if r := f.searchAs(viewer, "__"); len(r.Devices.Items) != 0 {
		t.Errorf("__ matched %+v", r.Devices.Items)
	}
}

/* TestSearchCap: each type returns at most 50 results and tells that there were more. */
func TestSearchCap(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	viewer := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &g})
	tok := uniqueName("cap")
	var dev int64
	for i := range 51 {
		dev, _ = f.namedDevice(g, fmt.Sprintf("%s-%02d", tok, i))
	}
	for i := 1; i <= 51; i++ {
		f.newIface(dev, i, fmt.Sprintf("port%d", i), "cap "+tok, 1000)
		f.newARP(dev, fmt.Sprintf("10.79.0.%d", i), fmt.Sprintf("02:cc:00:00:00:%02x", i), i)
		f.newFDB(dev, fmt.Sprintf("02:cc:00:00:01:%02x", i), 1, i)
	}
	r := f.searchAs(viewer, tok)
	if len(r.Devices.Items) != 50 || !r.Devices.More || r.Devices.Items[0].Name != tok+"-00" || len(r.Ports.Items) != 50 || !r.Ports.More {
		t.Errorf("devices %d more=%v, ports %d more=%v", len(r.Devices.Items), r.Devices.More, len(r.Ports.Items), r.Ports.More)
	}
	if r := f.searchAs(viewer, "10.79.0."); len(r.IPs.Items) != 50 || !r.IPs.More {
		t.Errorf("ips %d more=%v", len(r.IPs.Items), r.IPs.More)
	}
	r = f.searchAs(viewer, "02cc")
	if len(r.MACs.Items) != 50 || !r.MACs.More || r.MACs.Items[0].MAC != "02:cc:00:00:00:01" {
		t.Errorf("macs %d more=%v", len(r.MACs.Items), r.MACs.More)
	}
	/* Below the cap there is no "more". */
	if r := f.searchAs(viewer, tok+"-0"); len(r.Devices.Items) != 10 || r.Devices.More {
		t.Errorf("ten devices: %d more=%v", len(r.Devices.Items), r.Devices.More)
	}
}
