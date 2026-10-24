package httpapi_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/httpapi"
	"github.com/beekamai/network-scheme/internal/rbac"
)

/* stuckWriter is a client that stops reading: its first body Write blocks until release is closed. */
type stuckWriter struct {
	h       http.Header
	status  int
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *stuckWriter) Header() http.Header  { return w.h }
func (w *stuckWriter) WriteHeader(code int) { w.status = code }
func (w *stuckWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	<-w.release
	return len(p), nil
}

func randomBlob(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

/* A body of several chunks comes out byte for byte (the table does not validate the content). */
func TestBackgroundChunkedBody(t *testing.T) {
	f := newFixture(t, nil)
	viewer := f.login(false, rbac.Binding{Role: rbac.RoleViewer})
	for _, n := range []int{1, 1<<20 - 1, 1 << 20, 1<<20 + 1, 5<<20 + 12345} {
		blob := randomBlob(t, n)
		id := f.newBackground("image/png", blob, 1, 1)
		resp := f.do(viewer.authed(req{method: "GET", path: fmt.Sprintf("%s/%d", bgPath, id)}))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%d bytes: status %d", n, resp.StatusCode)
		}
		body := readBody(t, resp)
		want, got := sha256.Sum256(blob), sha256.Sum256(body)
		if want != got || len(body) != n || resp.Header.Get("Content-Length") != fmt.Sprint(n) {
			t.Errorf("%d bytes: served %d bytes, sha %s, want %s", n, len(body), hex.EncodeToString(got[:]), hex.EncodeToString(want[:]))
		}
	}
}

/*
Downloads take one of four slots while they stream; a fifth waits briefly and
gets 503 with Retry-After. A revalidation never takes a slot (it reads no bytes)
and a missing background is still 404.
*/
func TestBackgroundServeSlots(t *testing.T) {
	f := newFixture(t, nil)
	viewer := f.login(false, rbac.Binding{Role: rbac.RoleViewer})
	blob := randomBlob(t, 3<<20)
	id := f.newBackground("image/png", blob, 1, 1)
	sum := sha256.Sum256(blob)
	path := fmt.Sprintf("%s/%d", bgPath, id)

	release := make(chan struct{})
	var wg sync.WaitGroup
	var writers []*stuckWriter
	for i := 0; i < 4; i++ {
		sw := &stuckWriter{h: http.Header{}, started: make(chan struct{}), release: release}
		writers = append(writers, sw)
		hr := httptest.NewRequest("GET", path, nil)
		hr.RemoteAddr = f.ip + ":40000"
		hr.AddCookie(&http.Cookie{Name: cookieName, Value: viewer.cookie})
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.h.ServeHTTP(sw, hr)
		}()
	}
	released := false
	free := func() {
		if !released {
			released = true
			close(release)
			wg.Wait()
		}
	}
	defer free()
	for _, sw := range writers {
		select {
		case <-sw.started:
		case <-time.After(10 * time.Second):
			t.Fatal("a download did not start streaming")
		}
	}

	resp := f.do(viewer.authed(req{method: "GET", path: path}))
	if resp.Header.Get("Retry-After") == "" {
		t.Error("503 without Retry-After")
	}
	wantError(t, resp, http.StatusServiceUnavailable, "busy")
	if r := f.do(viewer.authed(req{method: "GET", path: path, inm: `"` + hex.EncodeToString(sum[:]) + `"`})); r.StatusCode != http.StatusNotModified {
		t.Errorf("revalidation with all slots taken = %d, want 304", r.StatusCode)
	}
	wantError(t, f.do(viewer.authed(req{method: "GET", path: bgPath + "/999999"})), http.StatusNotFound, "not_found")

	free()
	for _, sw := range writers {
		if sw.status != 0 && sw.status != http.StatusOK {
			t.Errorf("held download status %d", sw.status)
		}
	}
	if r := f.do(viewer.authed(req{method: "GET", path: path})); r.StatusCode != http.StatusOK {
		t.Errorf("after the slots free up = %d", r.StatusCode)
	}
}

func (f *fixture) viewWithBackground(bg *int64) int64 {
	return f.queryID(`INSERT INTO core.map_view (name, kind, background_id) VALUES ($1, 'logical', $2) RETURNING id`, uniqueName("view"), bg)
}

func (f *fixture) viewBackground(view int64) *int64 {
	f.t.Helper()
	var bg *int64
	if err := f.env.Pool("postgres").QueryRow(context.Background(), `SELECT background_id FROM core.map_view WHERE id = $1`, view).Scan(&bg); err != nil {
		f.t.Fatal(err)
	}
	return bg
}

func (f *fixture) backgroundExists(id int64) bool {
	return f.queryID(`SELECT count(*) FROM core.map_background WHERE id = $1`, id) == 1
}

func TestBackgroundDelete(t *testing.T) {
	f := newFixture(t, nil)
	admin := f.login(false, rbac.Binding{Role: rbac.RoleAdmin})
	bg := f.newBackground("image/png", pngBytes(), 1, 1)
	v1, v2 := f.viewWithBackground(&bg), f.viewWithBackground(&bg)

	path := fmt.Sprintf("%s/%d", bgPath, bg)
	if resp := f.do(admin.authed(req{method: "DELETE", path: path})); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d", resp.StatusCode)
	}
	if f.backgroundExists(bg) || f.viewBackground(v1) != nil || f.viewBackground(v2) != nil {
		t.Error("the background is still there or a view still points at it")
	}
	wantAudit(t, f, "map.background.delete")
	wantError(t, f.do(admin.authed(req{method: "DELETE", path: path})), http.StatusNotFound, "not_found")
	wantError(t, f.do(admin.authed(req{method: "DELETE", path: bgPath + "/abc"})), http.StatusNotFound, "not_found")
}

/* A background nobody uses any more goes with the last view that dropped or lost it. */
func TestBackgroundGarbageCollected(t *testing.T) {
	f := newFixture(t, nil)
	admin := f.login(false, rbac.Binding{Role: rbac.RoleAdmin})
	a := f.newBackground("image/png", pngBytes(), 1, 1)
	b := f.newBackground("image/png", pngBytes(), 1, 1)
	v1, v2, v3 := f.viewWithBackground(&a), f.viewWithBackground(&a), f.viewWithBackground(nil)
	patch := func(v int64, body any) {
		t.Helper()
		if resp := f.do(admin.authed(req{method: "PATCH", path: fmt.Sprintf("/api/map/views/%d", v), body: body})); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("patch view %d = %d", v, resp.StatusCode)
		}
	}

	patch(v1, map[string]any{"background_id": nil}) /* v2 still uses a */
	if !f.backgroundExists(a) {
		t.Fatal("a shared background was collected")
	}
	patch(v2, map[string]any{"name": uniqueName("r")}) /* the background field is untouched */
	if !f.backgroundExists(a) {
		t.Fatal("a rename collected the background")
	}
	patch(v2, map[string]any{"background_id": a}) /* the same one again */
	if !f.backgroundExists(a) {
		t.Fatal("re-setting the same background collected it")
	}
	patch(v2, map[string]any{"background_id": b}) /* the last user of a moves to b */
	if f.backgroundExists(a) || !f.backgroundExists(b) {
		t.Fatalf("a exists=%v b exists=%v", f.backgroundExists(a), f.backgroundExists(b))
	}
	patch(v3, map[string]any{"background_id": b})
	if resp := f.do(admin.authed(req{method: "DELETE", path: fmt.Sprintf("/api/map/views/%d", v2)})); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete view = %d", resp.StatusCode)
	}
	if !f.backgroundExists(b) {
		t.Fatal("deleting one of two users collected the background")
	}
	if resp := f.do(admin.authed(req{method: "DELETE", path: fmt.Sprintf("/api/map/views/%d", v3)})); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete view = %d", resp.StatusCode)
	}
	if f.backgroundExists(b) {
		t.Error("the last view is gone but its background stayed")
	}
	var details string
	if err := f.env.Pool("postgres").QueryRow(context.Background(),
		`SELECT convert_from(payload, 'UTF8') FROM audit.event WHERE action = 'map.view.delete' ORDER BY id DESC LIMIT 1`).Scan(&details); err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf(`"deleted_background_id":%d`, b); !strings.Contains(details, want) {
		t.Errorf("audit payload lacks %s: %s", want, details)
	}
}

/*
Deleting a background races a delete and an update of the views using it. The
paths take the background lock before any row lock, so none of them deadlocks
(40P01 would surface as a 500): every answer is 204 or 404.
*/
func TestBackgroundViewRaceNoDeadlock(t *testing.T) {
	f := newFixture(t, nil)
	admin := f.login(false, rbac.Binding{Role: rbac.RoleAdmin})
	for i := 0; i < 40; i++ {
		bg, other := f.newBackground("image/png", pngBytes(), 1, 1), f.newBackground("image/png", pngBytes(), 1, 1)
		v1, v2, v3 := f.viewWithBackground(&bg), f.viewWithBackground(&bg), f.viewWithBackground(&bg)
		reqs := []req{
			{method: "DELETE", path: fmt.Sprintf("%s/%d", bgPath, bg)},
			{method: "DELETE", path: fmt.Sprintf("/api/map/views/%d", v1)},
			{method: "PATCH", path: fmt.Sprintf("/api/map/views/%d", v2), body: map[string]any{"background_id": nil}},
			{method: "PATCH", path: fmt.Sprintf("/api/map/views/%d", v3), body: map[string]any{"background_id": other}},
		}
		codes := make([]int, len(reqs))
		start := make(chan struct{})
		var wg sync.WaitGroup
		for j, rq := range reqs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				codes[j] = f.do(admin.authed(rq)).StatusCode
			}()
		}
		close(start)
		wg.Wait()
		for j, c := range codes {
			if c != http.StatusNoContent && c != http.StatusNotFound {
				t.Fatalf("round %d: %s %s = %d; logs: %s", i, reqs[j].method, reqs[j].path, c, f.logs.String())
			}
		}
	}
	if strings.Contains(f.logs.String(), "40P01") {
		t.Fatalf("deadlock logged: %s", f.logs.String())
	}
}

/*
A download that fails before its first byte answers an error instead of
dropping the connection: 404 when the row went away after the metadata was
read, 500 for any other failure.
*/
func TestBackgroundFirstChunkFailure(t *testing.T) {
	f := newFixture(t, nil)
	viewer := f.login(false, rbac.Binding{Role: rbac.RoleViewer})
	t.Cleanup(func() {
		httpapi.SetBeforeBackgroundBody(nil)
		f.exec(`GRANT SELECT ON core.map_background TO nms_api`)
	})
	check := func(resp *http.Response, status int, code string) {
		t.Helper()
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("Content-Type = %q", ct)
		}
		if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
			t.Errorf("Cache-Control = %q", cc)
		}
		if resp.Header.Get("Etag") != "" || resp.Header.Get("Content-Disposition") != "" {
			t.Errorf("image headers left on the error: %v", resp.Header)
		}
		wantError(t, resp, status, code)
	}

	gone := f.newBackground("image/png", pngBytes(), 1, 1)
	httpapi.SetBeforeBackgroundBody(func() { f.exec(`DELETE FROM core.map_background WHERE id = $1`, gone) })
	check(f.do(viewer.authed(req{method: "GET", path: fmt.Sprintf("%s/%d", bgPath, gone)})), http.StatusNotFound, "not_found")

	broken := f.newBackground("image/png", pngBytes(), 1, 1)
	httpapi.SetBeforeBackgroundBody(func() { f.exec(`REVOKE SELECT ON core.map_background FROM nms_api`) })
	resp := f.do(viewer.authed(req{method: "GET", path: fmt.Sprintf("%s/%d", bgPath, broken)}))
	f.exec(`GRANT SELECT ON core.map_background TO nms_api`)
	check(resp, http.StatusInternalServerError, "internal")

	httpapi.SetBeforeBackgroundBody(nil)
	if r := f.do(viewer.authed(req{method: "GET", path: fmt.Sprintf("%s/%d", bgPath, broken)})); r.StatusCode != http.StatusOK {
		t.Errorf("after the failure = %d", r.StatusCode)
	}
}

/* The list carries metadata and use counts only, never the image bytes. */
func TestBackgroundList(t *testing.T) {
	f := newFixture(t, nil)
	admin := f.login(false, rbac.Binding{Role: rbac.RoleAdmin})
	f.exec(`DELETE FROM core.map_background`)
	resp := f.do(admin.authed(req{method: "GET", path: bgPath}))
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(readBody(t, resp))) != "[]" {
		t.Fatalf("empty list = %d", resp.StatusCode)
	}

	const marker = "svg-body-marker-5f3a"
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="10" height="20"><text>` + marker + `</text></svg>`)
	used := f.newBackground("image/svg+xml", svg, 10, 20)
	unused := f.newBackground("image/png", pngBytes(), 1, 1)
	f.viewWithBackground(&used)
	f.viewWithBackground(&used)

	resp = f.do(admin.authed(req{method: "GET", path: bgPath}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list = %d", resp.StatusCode)
	}
	raw := readBody(t, resp)
	if strings.Contains(string(raw), marker) || strings.Contains(string(raw), "PHN2Zy") {
		t.Fatalf("the list carries image content: %s", raw)
	}
	var items []struct {
		ID         int64     `json:"id"`
		Mime       string    `json:"mime"`
		Width      int       `json:"width"`
		Height     int       `json:"height"`
		Size       int       `json:"size"`
		SHA256     string    `json:"sha256"`
		UploadedAt time.Time `json:"uploaded_at"`
		Views      int       `json:"views"`
		Unused     bool      `json:"unused"`
	}
	if err := json.Unmarshal(raw, &items); err != nil || len(items) != 2 {
		t.Fatalf("list = %s, %v", raw, err)
	}
	sum := sha256.Sum256(svg)
	a, b := items[0], items[1]
	if a.ID != used || a.Mime != "image/svg+xml" || a.Width != 10 || a.Height != 20 || a.Size != len(svg) ||
		a.SHA256 != hex.EncodeToString(sum[:]) || a.UploadedAt.IsZero() || a.Views != 2 || a.Unused {
		t.Errorf("used background = %+v", a)
	}
	if b.ID != unused || b.Views != 0 || !b.Unused || b.Size != len(pngBytes()) {
		t.Errorf("unused background = %+v", b)
	}
}
