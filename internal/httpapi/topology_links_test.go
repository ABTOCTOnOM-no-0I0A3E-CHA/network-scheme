package httpapi_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/internal/rbac"
)

/* Drawing a link with the exact ends of a detected one turns that link manual instead of answering 409. */
func TestManualLinkConvertsDetected(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	admin := f.login(false, rbac.Binding{Role: rbac.RoleAdmin})
	a, b, c := f.newDevice(g), f.newDevice(g), f.newDevice(g)
	auto := f.newLink(a, ifx(1), b, ifx(2), "lldp", 0.5)
	f.exec(`UPDATE core.link SET misses = 2 WHERE id = $1`, auto)
	wild := f.newLink(a, nil, c, nil, "mac", 0.5) /* NULL ports take part in the identity */
	post := func(body map[string]any) *http.Response {
		return f.do(admin.authed(req{method: "POST", path: "/api/links", body: body}))
	}

	resp := post(map[string]any{"a_device_id": b, "a_if_index": 2, "b_device_id": a, "b_if_index": 1})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("convert = %d", resp.StatusCode)
	}
	if got := decode[struct {
		ID int64 `json:"id"`
	}](t, resp).ID; got != auto {
		t.Errorf("id = %d, want the converted row %d", got, auto)
	}
	var src string
	var manual bool
	var conf float64
	var misses int
	if err := f.env.Pool("postgres").QueryRow(context.Background(),
		`SELECT source, manual, confidence::float8, misses FROM core.link WHERE id = $1`, auto).Scan(&src, &manual, &conf, &misses); err != nil {
		t.Fatal(err)
	}
	if src != "manual" || !manual || conf != 1 || misses != 0 {
		t.Errorf("link = %s %v %v misses %d", src, manual, conf, misses)
	}
	if n := f.queryID(`SELECT count(*) FROM core.link_change WHERE link_id = $1`, auto); n != 0 {
		t.Errorf("history rows = %d, want none (the link already appeared)", n)
	}
	if n := f.queryID(`SELECT count(*) FROM core.link WHERE a_device_id = $1 AND b_device_id = $2`, a, b); n != 1 {
		t.Errorf("links between the pair = %d", n)
	}
	var details string
	if err := f.env.Pool("postgres").QueryRow(context.Background(),
		`SELECT convert_from(payload, 'UTF8') FROM audit.event WHERE action = 'links.create' ORDER BY id DESC LIMIT 1`).Scan(&details); err != nil {
		t.Fatal(err)
	}
	if want := `"converted_from":"lldp"`; !strings.Contains(details, want) {
		t.Errorf("audit payload lacks %s: %s", want, details)
	}

	/* now it is manual: the same request is a duplicate */
	wantError(t, post(map[string]any{"a_device_id": a, "a_if_index": 1, "b_device_id": b, "b_if_index": 2}), http.StatusConflict, "link_exists")
	/* other ports are a new link */
	if resp := post(map[string]any{"a_device_id": a, "a_if_index": 3, "b_device_id": b, "b_if_index": 2}); resp.StatusCode != http.StatusCreated {
		t.Errorf("different ports = %d", resp.StatusCode)
	}
	/* unknown ports match unknown ports only */
	if resp := post(map[string]any{"a_device_id": a, "b_device_id": c}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("convert wildcard = %d", resp.StatusCode)
	}
	if n := f.queryID(`SELECT count(*) FROM core.link WHERE id = $1 AND manual`, wild); n != 1 {
		t.Error("the wildcard link was not converted")
	}
}

/* Deleting a device records the disappearance of its links before they cascade away. */
func TestDeviceDeleteRecordsLinkDisappearance(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	admin := f.login(true, rbac.Binding{Role: rbac.RoleAdmin})
	a, b, c, d := f.newDevice(g), f.newDevice(g), f.newDevice(g), f.newDevice(g)
	l1 := f.newLink(a, ifx(1), b, ifx(2), "lldp", 1)
	l2 := f.newLink(b, nil, c, nil, "manual", 1)
	l3 := f.newLink(c, nil, d, nil, "mac", 0.5) /* not b's */

	if resp := f.do(admin.authed(req{method: "DELETE", path: fmt.Sprintf("/api/devices/%d", b)})); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d", resp.StatusCode)
	}
	for id, src := range map[int64]string{l1: "lldp", l2: "manual"} {
		if n := f.queryID(`SELECT count(*) FROM core.link_change WHERE link_id = $1 AND change = 'disappeared' AND source = $2`, id, src); n != 1 {
			t.Errorf("link %d: disappeared records = %d", id, n)
		}
	}
	if n := f.queryID(`SELECT count(*) FROM core.link_change WHERE link_id = $1`, l3); n != 0 {
		t.Errorf("an unrelated link got %d records", n)
	}
	if n := f.queryID(`SELECT count(*) FROM core.link WHERE id = ANY($1)`, []int64{l1, l2}); n != 0 {
		t.Errorf("%d links survived the device", n)
	}
	var ai *int
	if err := f.env.Pool("postgres").QueryRow(context.Background(),
		`SELECT a_if_index FROM core.link_change WHERE link_id = $1`, l1).Scan(&ai); err != nil || ai == nil || *ai != 1 {
		t.Errorf("recorded port = %v, %v", ai, err)
	}
}
