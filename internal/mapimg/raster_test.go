package mapimg_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/jpeg"
	"image/png"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/internal/mapimg"
)

/* bombPNG is a valid PNG header that declares 60000x60000 pixels and has no pixel data. */
func bombPNG(t *testing.T) []byte {
	t.Helper()
	return resizePNG(t, 60000, 60000)
}

func resizePNG(t *testing.T, w, h uint32) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewGray(image.Rect(0, 0, 1, 1))); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	/* signature (8) + length (4) + "IHDR" (4) + width + height + ... + crc */
	binary.BigEndian.PutUint32(b[16:], w)
	binary.BigEndian.PutUint32(b[20:], h)
	binary.BigEndian.PutUint32(b[29:], crc32.ChecksumIEEE(b[12:29]))
	return b
}

func TestProcessRasters(t *testing.T) {
	var jb bytes.Buffer
	if err := jpeg.Encode(&jb, image.NewGray(image.Rect(0, 0, 7, 5)), nil); err != nil {
		t.Fatal(err)
	}
	/* smallest lossless WebP: 1x1 */
	webp := []byte("RIFF\x1a\x00\x00\x00WEBPVP8L\x0d\x00\x00\x00\x2f\x00\x00\x00\x10\x07\x10\x11\x11\x88\x88\xfe\x07\x00")
	for name, tc := range map[string]struct {
		in   []byte
		mime string
		w, h int
	}{
		"png":  {png1x1(t), mapimg.MIMEPNG, 1, 1},
		"jpeg": {jb.Bytes(), mapimg.MIMEJPEG, 7, 5},
		"webp": {webp, mapimg.MIMEWebP, 1, 1},
		"max":  {resizePNG(t, 16384, 16384), mapimg.MIMEPNG, 16384, 16384},
	} {
		t.Run(name, func(t *testing.T) {
			r, err := mapimg.Process(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if r.Mime != tc.mime || r.Width != tc.w || r.Height != tc.h || !bytes.Equal(r.Data, tc.in) {
				t.Errorf("result = %s %dx%d", r.Mime, r.Width, r.Height)
			}
		})
	}
}

func TestProcessRejects(t *testing.T) {
	truncated := png1x1(t)[:20]
	for name, tc := range map[string]struct {
		in   []byte
		want error
	}{
		"empty":         {nil, mapimg.ErrUnsupported},
		"gif":           {[]byte("GIF89a\x01\x00\x01\x00"), mapimg.ErrUnsupported},
		"html":          {[]byte("\n \t<!DOCTYPE html><html></html>"), mapimg.ErrInvalid},
		"text":          {[]byte("hello"), mapimg.ErrUnsupported},
		"pdf":           {[]byte("%PDF-1.7"), mapimg.ErrUnsupported},
		"exe":           {[]byte("MZ\x90\x00"), mapimg.ErrUnsupported},
		"png-bomb":      {bombPNG(t), mapimg.ErrInvalid},
		"png-too-wide":  {resizePNG(t, 16385, 1), mapimg.ErrInvalid},
		"png-truncated": {truncated, mapimg.ErrInvalid},
		"png-zero":      {resizePNG(t, 0, 1), mapimg.ErrInvalid},
		"jpeg-garbage":  {[]byte{0xFF, 0xD8, 0xFF, 0xE0, 0, 0}, mapimg.ErrInvalid},
		"webp-garbage":  {[]byte("RIFF\x04\x00\x00\x00WEBP"), mapimg.ErrInvalid},
		"too-large":     {append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, mapimg.MaxBytes)...), mapimg.ErrTooLarge},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := mapimg.Process(tc.in)
			if tc.want == mapimg.ErrInvalid && errors.Is(err, mapimg.ErrNotSVG) {
				return /* SVG-looking text that is not SVG */
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

/* The type comes from the bytes: a PNG signature on a script, or an SVG with a PNG name, changes nothing. */
func TestDetectIgnoresEverythingButContent(t *testing.T) {
	if got := mapimg.Detect([]byte("\xEF\xBB\xBF \n<svg/>")); got != mapimg.MIMESVG {
		t.Errorf("svg after BOM = %q", got)
	}
	if got := mapimg.Detect(append([]byte("\x89PNG\r\n\x1a\n"), []byte(strings.Repeat("<svg>", 3))...)); got != mapimg.MIMEPNG {
		t.Errorf("png = %q", got)
	}
	if _, err := mapimg.Process(append([]byte("\x89PNG\r\n\x1a\n"), []byte("<svg onload=alert(1)>")...)); err == nil {
		t.Error("PNG signature on a script accepted")
	}
}
