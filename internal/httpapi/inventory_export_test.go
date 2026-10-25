package httpapi_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/internal/rbac"
)

/* TestInventoryExport: the CSV export needs a step-up, is audited, filters like the table search, neutralizes formulas and caps the rows. */
func TestInventoryExport(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	dev := f.newDevice(g)
	f.newIface(dev, 1, "Gi1/0/1", "uplink", 1000)
	f.newIface(dev, 2, "=HYPERLINK(1)", " @alias", 1000)
	f.exec(`UPDATE inventory.interface SET oper_up = false WHERE device_id = $1 AND if_index = 2`, dev)
	u := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &g})
	base := fmt.Sprintf("/api/devices/%d/export", dev)

	/* Without a fresh step-up: refused, and the probe says so too. */
	wantError(t, f.do(u.authed(req{method: "GET", path: base + "/interfaces"})), http.StatusForbidden, "stepup_required")
	wantError(t, f.do(u.authed(req{method: "GET", path: "/api/auth/stepup-status"})), http.StatusForbidden, "stepup_required")
	f.stepUp(u)
	wantStatus(t, f.do(u.authed(req{method: "GET", path: "/api/auth/stepup-status"})), http.StatusNoContent)

	get := func(p string) (*http.Response, []string) {
		t.Helper()
		resp := f.do(u.authed(req{method: "GET", path: p}))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d %s", p, resp.StatusCode, body(t, resp))
		}
		b := body(t, resp)
		if !strings.HasPrefix(b, string(rune(0xFEFF))) || !strings.HasSuffix(b, "\r\n") {
			t.Fatalf("%s: no BOM or no final CRLF: %q", p, b)
		}
		return resp, strings.Split(strings.TrimSuffix(strings.TrimPrefix(b, string(rune(0xFEFF))), "\r\n"), "\r\n")
	}
	resp, lines := get(base + "/interfaces")
	if ct := resp.Header.Get("Content-Type"); ct != "text/csv; charset=utf-8" {
		t.Errorf("Content-Type %q", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.HasPrefix(cd, `attachment; filename="interfaces-`) || !strings.HasSuffix(cd, `.csv"`) {
		t.Errorf("Content-Disposition %q", cd)
	}
	if resp.Header.Get("X-Export-Capped") != "false" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("headers %v", resp.Header)
	}
	if len(lines) != 3 || !strings.HasPrefix(lines[0], `"if_index","name","alias","speed_bps","oper_up","seen_at"`) {
		t.Fatalf("csv %q", lines)
	}
	if !strings.HasPrefix(lines[2], `"2","'=HYPERLINK(1)","' @alias","1000","false",`) {
		t.Errorf("row 2 %q", lines[2])
	}
	wantAudit(t, f, "inventory.export")

	/* The table search and the named filters apply to the whole table. */
	if _, l := get(base + "/interfaces?q=GI1%2F0"); len(l) != 2 || !strings.Contains(l[1], "Gi1/0/1") {
		t.Errorf("q: %q", l)
	}
	if _, l := get(base + "/interfaces?filter=down"); len(l) != 2 || !strings.HasPrefix(l[1], `"2",`) {
		t.Errorf("filter: %q", l)
	}
	if _, l := get(base + "/arp"); len(l) != 1 || l[0] != `"ip","mac","if_index","seen_at"` {
		t.Errorf("empty table: %q", l)
	}
	wantError(t, f.do(u.authed(req{method: "GET", path: base + "/nope"})), http.StatusNotFound, "not_found")
	for _, q := range []string{"/arp?filter=up", "/interfaces?filter=sideways", "/interfaces?q=a&q=b", "/interfaces?q=" + strings.Repeat("x", 101)} {
		wantError(t, f.do(u.authed(req{method: "GET", path: base + q})), http.StatusBadRequest, "bad_request")
	}

	/* At most 20 000 rows are written. */
	f.exec(`INSERT INTO inventory.mac_entry (device_id, mac, vlan, if_index, seen_at)
		SELECT $1, ('02:00:00:' || to_hex(n >> 16 & 255) || ':' || to_hex(n >> 8 & 255) || ':' || to_hex(n & 255))::macaddr, 1, 1, now()
		FROM generate_series(1, 20001) AS n`, dev)
	resp, lines = get(base + "/mac")
	if resp.Header.Get("X-Export-Capped") != "true" || len(lines) != 20001 {
		t.Errorf("capped %q, %d lines", resp.Header.Get("X-Export-Capped"), len(lines))
	}
}
