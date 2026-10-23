package httpapi_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/internal/rbac"
)

const bgPath = "/api/map/backgrounds"

func pngBytes() []byte {
	b, err := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")
	if err != nil {
		panic(err)
	}
	return b
}

func jpegBytes() []byte {
	var b bytes.Buffer
	if err := jpeg.Encode(&b, image.NewGray(image.Rect(0, 0, 7, 5)), nil); err != nil {
		panic(err)
	}
	return b.Bytes()
}

func webpBytes() []byte {
	return []byte("RIFF\x1a\x00\x00\x00WEBPVP8L\x0d\x00\x00\x00\x2f\x00\x00\x00\x10\x07\x10\x11\x11\x88\x88\xfe\x07\x00")
}

/* bombPNG declares 60000x60000 pixels in a valid header and carries no pixel data. */
func bombPNG() []byte {
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewGray(image.Rect(0, 0, 1, 1))); err != nil {
		panic(err)
	}
	b := buf.Bytes()
	binary.BigEndian.PutUint32(b[16:], 60000)
	binary.BigEndian.PutUint32(b[20:], 60000)
	binary.BigEndian.PutUint32(b[29:], crc32.ChecksumIEEE(b[12:29]))
	return b
}

type part struct {
	field, filename string
	data            []byte
}

func multipartBody(parts ...part) ([]byte, string) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	for _, p := range parts {
		h := textproto.MIMEHeader{}
		disp := fmt.Sprintf(`form-data; name=%q`, p.field)
		if p.filename != "" {
			disp += fmt.Sprintf(`; filename=%q`, p.filename)
		}
		h.Set("Content-Disposition", disp)
		h.Set("Content-Type", "application/octet-stream")
		pw, err := w.CreatePart(h)
		if err != nil {
			panic(err)
		}
		_, _ = pw.Write(p.data)
	}
	_ = w.Close()
	return b.Bytes(), w.FormDataContentType()
}

/* multipartFile is the body of a normal upload: one part "file". */
func multipartFile(filename string, data []byte) ([]byte, string) {
	return multipartBody(part{"file", filename, data})
}

func (f *fixture) newBackground(mime string, data []byte, w, h int) int64 {
	sum := sha256.Sum256(data)
	return f.queryID(`INSERT INTO core.map_background (mime, bytes, width, height, sha256, uploaded_by) VALUES ($1, $2, $3, $4, $5, 1) RETURNING id`,
		mime, data, w, h, sum[:])
}

type bgResp struct {
	ID     int64  `json:"id"`
	Mime   string `json:"mime"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}

func (f *fixture) upload(s *subject, filename string, data []byte) *http.Response {
	raw, ctype := multipartFile(filename, data)
	return f.do(s.authed(req{method: "POST", path: bgPath, raw: raw, ctype: ctype}))
}

func (f *fixture) backgroundRows() int64 {
	return f.queryID(`SELECT count(*) FROM core.map_background`)
}

func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBackgroundUploadAndServe(t *testing.T) {
	f := newFixture(t, nil)
	admin := f.login(false, rbac.Binding{Role: rbac.RoleAdmin})
	viewer := f.login(false, rbac.Binding{Role: rbac.RoleViewer})

	for _, tc := range []struct {
		name, mime, ext string
		data            []byte
		w, h            int
	}{
		{"map.png", "image/png", "png", pngBytes(), 1, 1},
		{"map.jpg", "image/jpeg", "jpg", jpegBytes(), 7, 5},
		{"map.webp", "image/webp", "webp", webpBytes(), 1, 1},
	} {
		t.Run(tc.mime, func(t *testing.T) {
			resp := f.upload(admin, tc.name, tc.data)
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("upload = %d: %s", resp.StatusCode, readBody(t, resp))
			}
			got := decode[bgResp](t, resp)
			sum := sha256.Sum256(tc.data)
			if got.Mime != tc.mime || got.Width != tc.w || got.Height != tc.h || got.Size != len(tc.data) || got.SHA256 != hex.EncodeToString(sum[:]) {
				t.Fatalf("response = %+v", got)
			}
			var uploader int64
			if err := f.env.Pool("postgres").QueryRow(context.Background(), `SELECT uploaded_by FROM core.map_background WHERE id = $1`, got.ID).Scan(&uploader); err != nil || uploader != admin.uid {
				t.Errorf("uploaded_by = %d, %v; want %d", uploader, err, admin.uid)
			}

			/* any devices.read holder fetches it, with the confining headers */
			g := f.do(viewer.authed(req{method: "GET", path: fmt.Sprintf("%s/%d", bgPath, got.ID)}))
			if g.StatusCode != http.StatusOK {
				t.Fatalf("get = %d", g.StatusCode)
			}
			for k, want := range map[string]string{
				"Content-Type":            tc.mime,
				"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; sandbox",
				"X-Content-Type-Options":  "nosniff",
				"Content-Disposition":     `inline; filename="map.` + tc.ext + `"`,
				"Cache-Control":           "private, max-age=3600",
				"Etag":                    `"` + got.SHA256 + `"`,
			} {
				if v := g.Header.Get(k); v != want {
					t.Errorf("%s = %q, want %q", k, v, want)
				}
			}
			if body := readBody(t, g); !bytes.Equal(body, tc.data) {
				t.Errorf("served %d bytes, want the %d uploaded", len(body), len(tc.data))
			}

			/* revalidation */
			for _, inm := range []string{`"` + got.SHA256 + `"`, `W/"` + got.SHA256 + `"`, `"other", "` + got.SHA256 + `"`, "*"} {
				r := f.do(viewer.authed(req{method: "GET", path: fmt.Sprintf("%s/%d", bgPath, got.ID), inm: inm}))
				if r.StatusCode != http.StatusNotModified || len(readBody(t, r)) != 0 || r.Header.Get("Etag") == "" {
					t.Errorf("If-None-Match %q = %d", inm, r.StatusCode)
				}
			}
			if r := f.do(viewer.authed(req{method: "GET", path: fmt.Sprintf("%s/%d", bgPath, got.ID), inm: `"nope"`})); r.StatusCode != http.StatusOK {
				t.Errorf("stale If-None-Match = %d", r.StatusCode)
			}
		})
	}
	wantAudit(t, f, "map.background.upload")
	var details string
	if err := f.env.Pool("postgres").QueryRow(context.Background(),
		`SELECT convert_from(payload, 'UTF8') FROM audit.event WHERE action = 'map.background.upload' ORDER BY id DESC LIMIT 1`).Scan(&details); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"sha256"`, `"size"`, `"mime":"image/webp"`, fmt.Sprintf(`"user_id":%d`, admin.uid)} {
		if !strings.Contains(details, want) {
			t.Errorf("audit payload lacks %s: %s", want, details)
		}
	}

	wantError(t, f.do(viewer.authed(req{method: "GET", path: bgPath + "/999999"})), http.StatusNotFound, "not_found")
	wantError(t, f.do(viewer.authed(req{method: "GET", path: bgPath + "/abc"})), http.StatusNotFound, "not_found")
}

/* The stored and served SVG is the sanitized rewrite; the original is not kept. */
func TestBackgroundSVGIsSanitized(t *testing.T) {
	f := newFixture(t, nil)
	admin := f.login(false, rbac.Binding{Role: rbac.RoleAdmin})
	evil := `<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" height="200" onload="alert(1)">` +
		`<script>alert(2)</script><foreignObject><div xmlns="http://www.w3.org/1999/xhtml">x</div></foreignObject>` +
		`<a xlink:href="javascript:alert(3)"><rect width="10" height="10" style="fill:url(http://evil.example/x)" fill="#123"/></a>` +
		`<image href="http://evil.example/t.png"/><rect id="keep" width="5" height="5" fill="#abc"/></svg>`
	resp := f.upload(admin, "plan.svg", []byte(evil))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload = %d: %s", resp.StatusCode, readBody(t, resp))
	}
	got := decode[bgResp](t, resp)
	if got.Mime != "image/svg+xml" || got.Width != 300 || got.Height != 200 {
		t.Fatalf("response = %+v", got)
	}
	g := f.do(admin.authed(req{method: "GET", path: fmt.Sprintf("%s/%d", bgPath, got.ID)}))
	if g.Header.Get("Content-Type") != "image/svg+xml" || g.Header.Get("Content-Disposition") != `inline; filename="map.svg"` ||
		g.Header.Get("Content-Security-Policy") != "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; sandbox" {
		t.Errorf("headers = %v", g.Header)
	}
	body := string(readBody(t, g))
	for _, bad := range []string{"script", "alert", "foreignObject", "evil", "onload", "javascript", "<a ", "<image", "<?xml"} {
		if strings.Contains(body, bad) {
			t.Errorf("served SVG has %q: %s", bad, body)
		}
	}
	if !strings.Contains(body, `fill="#abc"`) || got.Size != len(body) {
		t.Errorf("served SVG = %s (size %d)", body, got.Size)
	}
	sum := sha256.Sum256([]byte(body))
	if got.SHA256 != hex.EncodeToString(sum[:]) {
		t.Error("sha256 is not of the stored (sanitized) bytes")
	}
}

/* The type comes from the bytes, never from the file name or the part's declared type. */
func TestBackgroundTypeFromContent(t *testing.T) {
	f := newFixture(t, nil)
	admin := f.login(false, rbac.Binding{Role: rbac.RoleAdmin})

	got := decode[bgResp](t, f.upload(admin, "looks-like.svg", pngBytes()))
	if got.Mime != "image/png" {
		t.Errorf("PNG named .svg = %s", got.Mime)
	}
	got = decode[bgResp](t, f.upload(admin, "looks-like.png", []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="5" height="5"><script>1</script></svg>`)))
	if got.Mime != "image/svg+xml" {
		t.Errorf("SVG named .png = %s", got.Mime)
	}

	before := f.backgroundRows()
	for name, tc := range map[string]struct {
		data   []byte
		status int
		code   string
	}{
		"html":        {[]byte("<html><body><script>alert(1)</script></body></html>"), 415, "unsupported_media"},
		"text":        {[]byte("just text"), 415, "unsupported_media"},
		"empty":       {nil, 415, "unsupported_media"},
		"gif":         {[]byte("GIF89a\x01\x00\x01\x00\x00\x00\x00;"), 415, "unsupported_media"},
		"png-on-html": {append([]byte("\x89PNG\r\n\x1a\n"), "<script>alert(1)</script>"...), 400, "invalid_image"},
		"bomb":        {bombPNG(), 400, "invalid_image"},
		"doctype-xxe": {[]byte(`<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><text>&xxe;</text></svg>`), 400, "invalid_image"},
		"svg-no-size": {[]byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`), 400, "invalid_image"},
		"svg-huge":    {[]byte(`<svg xmlns="http://www.w3.org/2000/svg" width="20000" height="1"/>`), 400, "invalid_image"},
	} {
		t.Run(name, func(t *testing.T) {
			wantError(t, f.upload(admin, "x.png", tc.data), tc.status, tc.code)
		})
	}
	if n := f.backgroundRows(); n != before {
		t.Errorf("%d rows stored for rejected uploads", n-before)
	}
}

func TestBackgroundBodyLimits(t *testing.T) {
	f := newFixture(t, nil)
	admin := f.login(false, rbac.Binding{Role: rbac.RoleAdmin})
	padded := func(n int) []byte { /* a valid PNG followed by padding up to n bytes */
		return append(pngBytes(), make([]byte, n-len(pngBytes()))...)
	}

	/* exactly 20 MiB is stored (the multipart framing pushes the body past 20 MiB) */
	resp := f.upload(admin, "big.png", padded(20<<20))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("20 MiB upload = %d: %s", resp.StatusCode, readBody(t, resp))
	}
	if got := decode[bgResp](t, resp); got.Size != 20<<20 {
		t.Errorf("size = %d", got.Size)
	}
	before := f.backgroundRows()
	wantError(t, f.upload(admin, "big.png", padded(20<<20+1)), http.StatusRequestEntityTooLarge, "payload_too_large")
	/* a body far over the route limit is cut off while streaming */
	raw, ctype := multipartFile("huge.png", padded(22<<20))
	wantError(t, f.do(admin.authed(req{method: "POST", path: bgPath, raw: raw, ctype: ctype})), http.StatusRequestEntityTooLarge, "payload_too_large")
	if n := f.backgroundRows(); n != before {
		t.Errorf("%d rows stored for oversize uploads", n-before)
	}

	/* every other route keeps the 1 MiB limit */
	wantError(t, f.do(admin.authed(req{method: "POST", path: "/api/map/views", raw: bytes.Repeat([]byte(" "), 2<<20)})), http.StatusRequestEntityTooLarge, "payload_too_large")
	raw, ctype = multipartFile("a.png", padded(2<<20))
	wantError(t, f.do(admin.authed(req{method: "PUT", path: "/api/map/views/1/positions", raw: raw, ctype: ctype})), http.StatusRequestEntityTooLarge, "payload_too_large")
	wantError(t, f.do(admin.authed(req{method: "POST", path: bgPath + "/1", raw: raw, ctype: ctype})), http.StatusRequestEntityTooLarge, "payload_too_large")
}

func TestBackgroundMultipartShape(t *testing.T) {
	f := newFixture(t, nil)
	admin := f.login(false, rbac.Binding{Role: rbac.RoleAdmin})
	before := f.backgroundRows()
	post := func(raw []byte, ctype string) *http.Response {
		return f.do(admin.authed(req{method: "POST", path: bgPath, raw: raw, ctype: ctype}))
	}
	png := pngBytes()

	raw, ctype := multipartBody(part{"file", "a.png", png}, part{"file", "b.png", png})
	wantError(t, post(raw, ctype), http.StatusBadRequest, "bad_request")
	raw, ctype = multipartBody(part{"file", "a.png", png}, part{"note", "", []byte("x")})
	wantError(t, post(raw, ctype), http.StatusBadRequest, "bad_request")
	raw, ctype = multipartBody(part{"note", "", []byte("x")}, part{"file", "a.png", png})
	wantError(t, post(raw, ctype), http.StatusBadRequest, "bad_request")
	raw, ctype = multipartBody(part{"image", "a.png", png})
	wantError(t, post(raw, ctype), http.StatusBadRequest, "bad_request")
	raw, ctype = multipartBody(part{"file", "", png})
	wantError(t, post(raw, ctype), http.StatusBadRequest, "bad_request")
	raw, ctype = multipartBody()
	wantError(t, post(raw, ctype), http.StatusBadRequest, "bad_request")
	raw, ctype = multipartFile(strings.Repeat("n", 201)+".png", png)
	wantError(t, post(raw, ctype), http.StatusBadRequest, "bad_request")
	raw, ctype = multipartFile("badXXname.png", png)
	raw = bytes.Replace(raw, []byte("XX"), []byte{1}, 1) /* a raw control character in the name */
	wantError(t, post(raw, ctype), http.StatusBadRequest, "bad_request")
	wantError(t, post(png, "image/png"), http.StatusUnsupportedMediaType, "unsupported_media_type")
	wantError(t, post([]byte(`{"file":"x"}`), "application/json"), http.StatusUnsupportedMediaType, "unsupported_media_type")
	wantError(t, post(png, "multipart/form-data"), http.StatusUnsupportedMediaType, "unsupported_media_type")
	wantError(t, post([]byte("--b\r\ngarbage"), "multipart/form-data; boundary=b"), http.StatusBadRequest, "bad_request")

	raw, ctype = multipartFile(strings.Repeat("n", 196)+".png", png) /* 200 characters */
	if resp := post(raw, ctype); resp.StatusCode != http.StatusCreated {
		t.Errorf("200-character name = %d", resp.StatusCode)
	}
	if n := f.backgroundRows(); n != before+1 {
		t.Errorf("rows = %d, want %d", n, before+1)
	}
}

/* An upload is a state change: no CSRF token, no upload. */
func TestBackgroundUploadNeedsCSRF(t *testing.T) {
	f := newFixture(t, nil)
	admin := f.login(false, rbac.Binding{Role: rbac.RoleAdmin})
	raw, ctype := multipartFile("a.png", pngBytes())
	r := admin.authed(req{method: "POST", path: bgPath, raw: raw, ctype: ctype})
	r.csrf = ""
	wantError(t, f.do(r), http.StatusForbidden, "csrf")
}

func TestBackgroundCap(t *testing.T) {
	f := newFixture(t, nil)
	admin := f.login(false, rbac.Binding{Role: rbac.RoleAdmin})
	f.exec(`DELETE FROM core.map_background`)
	t.Cleanup(func() { f.exec(`DELETE FROM core.map_background`) })
	f.exec(`INSERT INTO core.map_background (mime, bytes, width, height, sha256, uploaded_by)
		SELECT 'image/png', '\x00', 1, 1, decode(repeat('00', 32), 'hex'), 1 FROM generate_series(1, 199)`)
	if resp := f.upload(admin, "a.png", pngBytes()); resp.StatusCode != http.StatusCreated {
		t.Fatalf("200th background = %d", resp.StatusCode)
	}
	wantError(t, f.upload(admin, "a.png", pngBytes()), http.StatusConflict, "too_many_backgrounds")
	if n := f.backgroundRows(); n != 200 {
		t.Errorf("rows = %d", n)
	}
}
