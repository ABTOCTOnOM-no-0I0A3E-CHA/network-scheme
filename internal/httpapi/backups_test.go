package httpapi_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/drivers/mask"
	"github.com/beekamai/network-scheme/internal/rbac"
)

const configFixtures = "../../test/fixtures/configs"

/* newVersion stores a version the way the poller does (the ciphertext columns are filler); taken is the time of the version. */
func (f *fixture) newVersion(dev int64, masked, source string, drift bool, taken time.Time) int64 {
	f.t.Helper()
	var id int64
	err := f.env.Pool("postgres").QueryRow(context.Background(), `INSERT INTO backups.config_version
		(device_id, taken_at, source, sha256, size, masked, full_ct, full_dek_ct, drift)
		VALUES ($1, $2, $3, sha256($4::bytea), $5, $6, '\x434950484552544558542d4d41524b4552', '\x444b2d4d41524b4552', $7) RETURNING id`,
		dev, taken, source, masked, len(masked), masked, drift).Scan(&id)
	if err != nil {
		f.t.Fatal(err)
	}
	return id
}

func body(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

/* backupRequest builds valid requests for the backup routes with targets in m.target. */
func (m *matrixEnv) backupRequest(key string) (req, bool) {
	if !strings.Contains(key, "/backup") {
		return req{}, false
	}
	dev := m.newDevice(m.target)
	now := time.Now().UTC()
	v1 := m.newVersion(dev, "hostname a\n", "schedule", false, now.Add(-time.Hour))
	v2 := m.newVersion(dev, "hostname b\n", "event", true, now)
	base := fmt.Sprintf("/api/devices/%d", dev)
	switch key {
	case "GET /api/devices/{id}/backups":
		return req{method: "GET", path: base + "/backups"}, true
	case "POST /api/devices/{id}/backups":
		return req{method: "POST", path: base + "/backups"}, true
	case "GET /api/devices/{id}/backups/diff":
		return req{method: "GET", path: fmt.Sprintf("%s/backups/diff?a=%d&b=%d", base, v1, v2)}, true
	case "GET /api/devices/{id}/backups/{vid}":
		return req{method: "GET", path: fmt.Sprintf("%s/backups/%d", base, v2)}, true
	case "GET /api/devices/{id}/backups/{vid}/download":
		return req{method: "GET", path: fmt.Sprintf("%s/backups/%d/download", base, v2)}, true
	case "GET /api/devices/{id}/backup-state":
		return req{method: "GET", path: base + "/backup-state"}, true
	}
	return req{}, false
}

type versionJSON struct {
	ID      int64     `json:"id"`
	TakenAt time.Time `json:"taken_at"`
	Source  string    `json:"source"`
	Size    int       `json:"size"`
	SHA256  string    `json:"sha256"`
	Drift   bool      `json:"drift"`
	Text    string    `json:"text"`
}

type pageJSON struct {
	Items      []versionJSON `json:"items"`
	NextCursor *string       `json:"next_cursor"`
}

/* TestBackupScope: a user bound to group B reaches nothing of a group-A device, whatever the route. */
func TestBackupScope(t *testing.T) {
	f := newFixture(t, nil)
	a, b := f.newGroup(), f.newGroup()
	devA, devA2 := f.newDevice(a), f.newDevice(a)
	now := time.Now().UTC()
	v1 := f.newVersion(devA, "x\n", "schedule", false, now.Add(-time.Hour))
	v2 := f.newVersion(devA, "y\n", "event", true, now)
	other := f.newVersion(devA2, "z\n", "schedule", false, now)
	opB := f.login(false, rbac.Binding{Role: rbac.RoleOperator, GroupID: &b})
	opA := f.login(false, rbac.Binding{Role: rbac.RoleOperator, GroupID: &a})
	base := fmt.Sprintf("/api/devices/%d", devA)
	for _, c := range []struct{ method, path string }{
		{"GET", base + "/backups"},
		{"GET", fmt.Sprintf("%s/backups/%d", base, v1)},
		{"GET", fmt.Sprintf("%s/backups/%d/download", base, v1)},
		{"GET", fmt.Sprintf("%s/backups/diff?a=%d&b=%d", base, v1, v2)},
		{"GET", base + "/backup-state"},
		{"POST", base + "/backups"},
	} {
		wantError(t, f.do(opB.authed(req{method: c.method, path: c.path})), http.StatusNotFound, "not_found")
	}
	if len(f.jobs.backs) != 0 {
		t.Fatal("a foreign user queued a backup")
	}
	/* A version of another device is not reachable through this device, even in the same group. */
	wantError(t, f.do(opA.authed(req{method: "GET", path: fmt.Sprintf("%s/backups/%d", base, other)})), http.StatusNotFound, "not_found")
	wantError(t, f.do(opA.authed(req{method: "GET", path: fmt.Sprintf("%s/backups/%d/download", base, other)})), http.StatusNotFound, "not_found")
	wantError(t, f.do(opA.authed(req{method: "GET", path: fmt.Sprintf("%s/backups/diff?a=%d&b=%d", base, v1, other)})), http.StatusNotFound, "not_found")
	wantError(t, f.do(opA.authed(req{method: "GET", path: fmt.Sprintf("%s/backups/diff?a=%d&b=%d", base, other, v2)})), http.StatusNotFound, "not_found")
	wantError(t, f.do(opA.authed(req{method: "GET", path: base + "/backups/999999999"})), http.StatusNotFound, "not_found")
	wantError(t, f.do(opA.authed(req{method: "GET", path: base + "/backups/abc"})), http.StatusNotFound, "not_found")
	/* A viewer reads but cannot queue. */
	viewer := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &a})
	if resp := f.do(viewer.authed(req{method: "GET", path: base + "/backups"})); resp.StatusCode != http.StatusOK {
		t.Fatalf("viewer list %d", resp.StatusCode)
	}
	wantError(t, f.do(viewer.authed(req{method: "POST", path: base + "/backups"})), http.StatusForbidden, "forbidden")
}

/* TestBackupOfDeletedDeviceIsInvisible: versions outlive their device but nobody reaches them (R4). */
func TestBackupOfDeletedDeviceIsInvisible(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	dev := f.newDevice(g)
	v := f.newVersion(dev, "x\n", "schedule", false, time.Now().UTC())
	admin := f.login(true, rbac.Binding{Role: rbac.RoleAdmin})
	base := fmt.Sprintf("/api/devices/%d", dev)
	if resp := f.do(admin.authed(req{method: "GET", path: fmt.Sprintf("%s/backups/%d", base, v)})); resp.StatusCode != http.StatusOK {
		t.Fatalf("before delete %d", resp.StatusCode)
	}
	if resp := f.do(admin.authed(req{method: "DELETE", path: base})); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete %d", resp.StatusCode)
	}
	for _, p := range []string{"/backups", fmt.Sprintf("/backups/%d", v), fmt.Sprintf("/backups/%d/download", v), "/backup-state"} {
		wantError(t, f.do(admin.authed(req{method: "GET", path: base + p})), http.StatusNotFound, "not_found")
	}
}

func TestBackupListPaging(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	dev := f.newDevice(g)
	u := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &g})
	base := fmt.Sprintf("/api/devices/%d/backups", dev)
	/* An empty history is an empty page, not an error. */
	empty := decode[pageJSON](t, f.do(u.authed(req{method: "GET", path: base})))
	if empty.Items == nil || len(empty.Items) != 0 || empty.NextCursor != nil {
		t.Fatalf("empty = %+v", empty)
	}
	t0 := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	var want []int64 /* newest first: same instant breaks ties by id */
	for i := 0; i < 5; i++ {
		taken := t0.Add(time.Duration(i/2) * time.Minute) /* pairs share an instant */
		id := f.newVersion(dev, fmt.Sprintf("v%d\n", i), "schedule", i > 0, taken)
		want = append([]int64{id}, want...)
	}
	var got []int64
	cursor := ""
	pages := 0
	for {
		path := base + "?limit=2"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		p := decode[pageJSON](t, f.do(u.authed(req{method: "GET", path: path})))
		for _, it := range p.Items {
			got = append(got, it.ID)
			if len(it.SHA256) != 12 || it.Size == 0 || it.Text != "" {
				t.Fatalf("item = %+v", it)
			}
		}
		pages++
		if p.NextCursor == nil {
			break
		}
		cursor = *p.NextCursor
	}
	if pages != 3 || fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("pages %d, got %v, want %v", pages, got, want)
	}
	for _, q := range []string{"?limit=101", "?limit=0", "?limit=x", "?cursor=!!", "?cursor=e30", "?limit=1&limit=2"} {
		wantError(t, f.do(u.authed(req{method: "GET", path: base + q})), http.StatusBadRequest, "bad_request")
	}
}

func TestBackupGetDownloadAndState(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	dev := f.newDevice(g)
	u := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &g})
	base := fmt.Sprintf("/api/devices/%d", dev)
	/* A device never backed up. */
	st := decode[map[string]any](t, f.do(u.authed(req{method: "GET", path: base + "/backup-state"})))
	if st["last_ok_at"] != nil || st["last_error"] != nil || st["needs_write"] != false || st["latest_version"] != nil || st["last_sha256"] != nil {
		t.Fatalf("empty state = %v", st)
	}
	/* Mind the odd name: the file name must stay safe. */
	if _, err := f.env.Pool("postgres").Exec(context.Background(), `UPDATE core.device SET name = $2 WHERE id = $1`, dev, "sw \"01\"/../é;\r\nx"); err != nil {
		t.Fatal(err)
	}
	taken := time.Date(2026, 10, 20, 10, 21, 33, 0, time.UTC)
	text := "hostname sw-01\n! <b>not html</b>\ninterface vlan 1\n"
	v := f.newVersion(dev, text, "event", true, taken)
	if _, err := f.env.Pool("postgres").Exec(context.Background(),
		`INSERT INTO backups.backup_state (device_id, last_ok_at, last_error, needs_write, last_sha256) VALUES ($1, now(), 'configuration fetch failed', true, sha256('x'))`, dev); err != nil {
		t.Fatal(err)
	}
	got := decode[versionJSON](t, f.do(u.authed(req{method: "GET", path: fmt.Sprintf("%s/backups/%d", base, v)})))
	if got.ID != v || got.Text != text || got.Source != "event" || !got.Drift || got.Size != len(text) || !got.TakenAt.Equal(taken) {
		t.Fatalf("version = %+v", got)
	}
	resp := f.do(u.authed(req{method: "GET", path: fmt.Sprintf("%s/backups/%d/download", base, v)}))
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatalf("download %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	cd := resp.Header.Get("Content-Disposition")
	if !regexp.MustCompile(`^attachment; filename="[A-Za-z0-9_-]+-20261020T102133Z\.txt"$`).MatchString(cd) {
		t.Fatalf("Content-Disposition = %q", cd)
	}
	if b := body(t, resp); b != text {
		t.Fatalf("download body = %q", b)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("download lacks nosniff")
	}
	state := decode[struct {
		LastOKAt   *time.Time   `json:"last_ok_at"`
		LastError  *string      `json:"last_error"`
		NeedsWrite bool         `json:"needs_write"`
		LastSHA256 string       `json:"last_sha256"`
		Latest     *versionJSON `json:"latest_version"`
	}](t, f.do(u.authed(req{method: "GET", path: base + "/backup-state"})))
	if state.LastOKAt == nil || state.LastError == nil || *state.LastError != "configuration fetch failed" || !state.NeedsWrite ||
		len(state.LastSHA256) != 12 || state.Latest == nil || state.Latest.ID != v || !state.Latest.Drift {
		t.Fatalf("state = %+v", state)
	}
}

func TestBackupDiff(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	dev := f.newDevice(g)
	u := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &g})
	base := fmt.Sprintf("/api/devices/%d/backups/diff", dev)
	t0 := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	cfgA := "hostname sw\nvlan 10\nvlan 20\ninterface g1\n description up\nend\n"
	cfgB := "hostname sw\nvlan 10\nvlan 30\ninterface g1\n description up\nend\nntp server ***\n"
	a := f.newVersion(dev, cfgA, "schedule", false, t0)
	b := f.newVersion(dev, cfgB, "event", true, t0.Add(time.Hour))
	type diffJSON struct {
		A, B struct {
			ID int64 `json:"id"`
		}
		Diff string `json:"diff"`
	}
	got := decode[diffJSON](t, f.do(u.authed(req{method: "GET", path: fmt.Sprintf("%s?a=%d&b=%d", base, a, b)})))
	want := "--- version " + fmt.Sprint(a) + " 2026-10-20T10:00:00Z\n+++ version " + fmt.Sprint(b) + " 2026-10-20T11:00:00Z\n" +
		"@@ -1,6 +1,7 @@\n hostname sw\n vlan 10\n-vlan 20\n+vlan 30\n interface g1\n  description up\n end\n+ntp server ***\n"
	if got.Diff != want || got.A.ID != a || got.B.ID != b {
		t.Fatalf("diff = %+v\nwant:\n%s", got, want)
	}
	/* Equal texts: an empty diff. */
	if d := decode[diffJSON](t, f.do(u.authed(req{method: "GET", path: fmt.Sprintf("%s?a=%d&b=%d", base, a, a)}))); d.Diff != "" {
		t.Fatalf("self diff = %q", d.Diff)
	}
	for _, q := range []string{"", "?a=1", "?b=1", fmt.Sprintf("?a=%d&b=x", a), fmt.Sprintf("?a=0&b=%d", b), fmt.Sprintf("?a=%d&a=%d&b=%d", a, a, b)} {
		wantError(t, f.do(u.authed(req{method: "GET", path: base + q})), http.StatusBadRequest, "bad_request")
	}
}

func TestBackupDiffSizeCaps(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	dev := f.newDevice(g)
	u := f.login(false, rbac.Binding{Role: rbac.RoleViewer, GroupID: &g})
	base := fmt.Sprintf("/api/devices/%d/backups/diff", dev)
	t0 := time.Now().UTC().Add(-time.Hour)
	small := f.newVersion(dev, "a\n", "schedule", false, t0)
	/* A masked text over 2 MiB is refused before it is loaded. */
	huge := f.newVersion(dev, strings.Repeat("0123456789abcdef\n", (2<<20)/17+10), "schedule", false, t0.Add(time.Second))
	wantError(t, f.do(u.authed(req{method: "GET", path: fmt.Sprintf("%s?a=%d&b=%d", base, small, huge)})), http.StatusRequestEntityTooLarge, "too_large")
	wantError(t, f.do(u.authed(req{method: "GET", path: fmt.Sprintf("%s?a=%d&b=%d", base, huge, small)})), http.StatusRequestEntityTooLarge, "too_large")
	/* Under 2 MiB each, but too many differing lines. */
	var x, y strings.Builder
	for i := 0; i < 6000; i++ {
		fmt.Fprintf(&x, "left %d\n", i)
		fmt.Fprintf(&y, "right %d\n", i)
	}
	vx := f.newVersion(dev, x.String(), "schedule", false, t0.Add(2*time.Second))
	vy := f.newVersion(dev, y.String(), "schedule", false, t0.Add(3*time.Second))
	wantError(t, f.do(u.authed(req{method: "GET", path: fmt.Sprintf("%s?a=%d&b=%d", base, vx, vy)})), http.StatusRequestEntityTooLarge, "too_large")
	/* A large text with a small change is fine. */
	big := strings.Repeat("some configuration line\n", 60000)
	v1 := f.newVersion(dev, big, "schedule", false, t0.Add(4*time.Second))
	v2 := f.newVersion(dev, big+"one more\n", "schedule", false, t0.Add(5*time.Second))
	resp := f.do(u.authed(req{method: "GET", path: fmt.Sprintf("%s?a=%d&b=%d", base, v1, v2)}))
	if resp.StatusCode != http.StatusOK || !strings.Contains(body(t, resp), "+one more") {
		t.Fatalf("large diff status %d", resp.StatusCode)
	}
}

/* TestBackupResponsesCarryNoSecrets pushes the secret-laden fixtures through the driver masking and stores them like the poller; no route may return a known secret. */
func TestBackupResponsesCarryNoSecrets(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	dev := f.newDevice(g)
	admin := f.login(true, rbac.Binding{Role: rbac.RoleAdmin, GroupID: &g})
	var secrets []string
	var ids []int64
	t0 := time.Now().UTC().Add(-time.Hour)
	for i, name := range []string{"mes", "esr"} {
		raw, err := os.ReadFile(filepath.Join(configFixtures, name+"-secrets.txt"))
		if err != nil {
			t.Fatal(err)
		}
		list, err := os.ReadFile(filepath.Join(configFixtures, name+"-secrets.secrets"))
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range strings.Split(string(list), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				secrets = append(secrets, l)
				if !strings.Contains(string(raw), l) {
					t.Fatalf("fixture %s does not contain its secret %q", name, l)
				}
			}
		}
		text := strings.ToValidUTF8(mask.Secrets(strings.ReplaceAll(string(raw), "\r\n", "\n")), "?")
		ids = append(ids, f.newVersion(dev, text, "schedule", i > 0, t0.Add(time.Duration(i)*time.Minute)))
	}
	if len(secrets) < 20 {
		t.Fatalf("only %d known secrets", len(secrets))
	}
	base := fmt.Sprintf("/api/devices/%d", dev)
	paths := []string{
		base + "/backups", base + "/backup-state",
		fmt.Sprintf("%s/backups/%d", base, ids[0]), fmt.Sprintf("%s/backups/%d", base, ids[1]),
		fmt.Sprintf("%s/backups/%d/download", base, ids[0]), fmt.Sprintf("%s/backups/%d/download", base, ids[1]),
		fmt.Sprintf("%s/backups/diff?a=%d&b=%d", base, ids[0], ids[1]),
		base, base + "/profiles",
	}
	for _, p := range paths {
		resp := f.do(admin.authed(req{method: "GET", path: p}))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d", p, resp.StatusCode)
		}
		var hdr strings.Builder
		for k, v := range resp.Header {
			hdr.WriteString(k + ": " + strings.Join(v, ",") + "\n")
		}
		all := body(t, resp) + hdr.String()
		for _, s := range secrets {
			if strings.Contains(all, s) {
				t.Errorf("%s returns the secret %q", p, s)
			}
		}
		for _, marker := range []string{"CIPHERTEXT-MARKER", "DK-MARKER", "full_ct", "full_dek_ct"} {
			if strings.Contains(all, marker) {
				t.Errorf("%s returns %q", p, marker)
			}
		}
	}
	/* The text kept its structure. */
	got := decode[versionJSON](t, f.do(admin.authed(req{method: "GET", path: fmt.Sprintf("%s/backups/%d", base, ids[0])})))
	if !strings.Contains(got.Text, "sw-lab-01") {
		t.Error("masked text lost its structure")
	}
}

func TestBackupNowAuditRateLimitAndNote(t *testing.T) {
	f := newFixture(t, nil)
	g := f.newGroup()
	dev, dev2 := f.newDevice(g), f.newDevice(g)
	op := f.login(false, rbac.Binding{Role: rbac.RoleOperator, GroupID: &g})
	path := fmt.Sprintf("/api/devices/%d/backups", dev)
	resp := f.do(op.authed(req{method: "POST", path: path}))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("backup %d", resp.StatusCode)
	}
	if n := decode[map[string]any](t, resp); n["note"] != nil {
		t.Fatalf("note without a recent backup: %v", n)
	}
	if len(f.jobs.backs) != 1 || f.jobs.backs[0] != dev {
		t.Fatalf("backs = %v", f.jobs.backs)
	}
	wantAudit(t, f, "devices.backup_now")
	/* A backup newer than the poller's 5-minute gap: queued, but the answer says nothing will be fetched. */
	if _, err := f.env.Pool("postgres").Exec(context.Background(),
		`INSERT INTO backups.backup_state (device_id, last_ok_at) VALUES ($1, now() - interval '2 minutes')`, dev2); err != nil {
		t.Fatal(err)
	}
	resp = f.do(op.authed(req{method: "POST", path: fmt.Sprintf("/api/devices/%d/backups", dev2)}))
	if n := decode[map[string]any](t, resp); resp.StatusCode != http.StatusAccepted || n["note"] != "recent backup exists" {
		t.Fatalf("recent: %d %v", resp.StatusCode, n)
	}
	if _, err := f.env.Pool("postgres").Exec(context.Background(), `UPDATE backups.backup_state SET last_ok_at = now() - interval '6 minutes' WHERE device_id = $1`, dev2); err != nil {
		t.Fatal(err)
	}
	resp = f.do(op.authed(req{method: "POST", path: fmt.Sprintf("/api/devices/%d/backups", dev2)}))
	if n := decode[map[string]any](t, resp); resp.StatusCode != http.StatusAccepted || n["note"] != nil {
		t.Fatalf("old: %d %v", resp.StatusCode, n)
	}
	/* 10 a minute per user (3 used so far); another user is not affected. */
	for i := 3; i < 10; i++ {
		if r := f.do(op.authed(req{method: "POST", path: path})); r.StatusCode != http.StatusAccepted {
			t.Fatalf("request %d: %d", i+1, r.StatusCode)
		}
	}
	wantError(t, f.do(op.authed(req{method: "POST", path: path})), http.StatusTooManyRequests, "rate_limited")
	other := f.login(false, rbac.Binding{Role: rbac.RoleOperator, GroupID: &g})
	if r := f.do(other.authed(req{method: "POST", path: path})); r.StatusCode != http.StatusAccepted {
		t.Fatalf("other user: %d", r.StatusCode)
	}
	f.clk.Advance(61 * time.Second)
	if r := f.do(op.authed(req{method: "POST", path: path})); r.StatusCode != http.StatusAccepted {
		t.Fatalf("after a minute: %d", r.StatusCode)
	}
	/* A failed enqueue answers 500. */
	f.jobs.fail = true
	wantError(t, f.do(other.authed(req{method: "POST", path: path})), http.StatusInternalServerError, "internal")
}
