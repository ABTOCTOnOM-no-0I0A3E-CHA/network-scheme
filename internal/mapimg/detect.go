// Package mapimg validates user-uploaded map backgrounds: it recognises the
// type by content, checks raster headers without decoding pixels and rewrites
// SVG through an allowlist so that nothing active survives.
package mapimg

import (
	"bytes"
	"errors"
)

/* Limits shared with the core.map_background CHECKs. */
const (
	MaxBytes = 20 << 20 /* stored size of one background */
	MaxDim   = 16384    /* width and height in pixels */
)

/* Stored media types (the CHECK of core.map_background.mime). */
const (
	MIMEPNG  = "image/png"
	MIMEJPEG = "image/jpeg"
	MIMEWebP = "image/webp"
	MIMESVG  = "image/svg+xml"
)

var (
	// ErrUnsupported means the content is none of PNG, JPEG, WebP or SVG.
	ErrUnsupported = errors.New("mapimg: unsupported image type")
	// ErrInvalid means the content has a known type but is malformed or not acceptable.
	ErrInvalid = errors.New("mapimg: invalid image")
	// ErrTooLarge means the content or its sanitized form exceeds MaxBytes.
	ErrTooLarge = errors.New("mapimg: image too large")
)

var bom = []byte{0xEF, 0xBB, 0xBF}

/*
Detect names the type of b by its signature alone (never by file name or
declared type). SVG is only a candidate here: an XML-looking text; Sanitize
decides whether the root element is really svg. It returns "" for anything
else.
*/
func Detect(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")):
		return MIMEPNG
	case bytes.HasPrefix(b, []byte{0xFF, 0xD8, 0xFF}):
		return MIMEJPEG
	case len(b) >= 12 && bytes.Equal(b[:4], []byte("RIFF")) && bytes.Equal(b[8:12], []byte("WEBP")):
		return MIMEWebP
	}
	t := bytes.TrimPrefix(b, bom)
	t = bytes.TrimLeft(t, " \t\r\n")
	if len(t) > 0 && t[0] == '<' {
		return MIMESVG
	}
	return ""
}

/* Ext is the file extension served for a stored media type. */
func Ext(mime string) string {
	switch mime {
	case MIMEPNG:
		return "png"
	case MIMEJPEG:
		return "jpg"
	case MIMEWebP:
		return "webp"
	case MIMESVG:
		return "svg"
	}
	return ""
}

/* Result is a validated background ready to store. */
type Result struct {
	Mime          string
	Data          []byte /* the original bytes for rasters, the re-serialized document for SVG */
	Width, Height int
}

/* Process detects the type of b and validates it (rasters) or sanitizes it (SVG). */
func Process(b []byte) (Result, error) {
	if len(b) == 0 {
		return Result{}, ErrUnsupported
	}
	if len(b) > MaxBytes {
		return Result{}, ErrTooLarge
	}
	switch mime := Detect(b); mime {
	case "":
		return Result{}, ErrUnsupported
	case MIMESVG:
		out, w, h, err := SanitizeSVG(b)
		if err != nil {
			return Result{}, err
		}
		return Result{Mime: mime, Data: out, Width: w, Height: h}, nil
	default:
		w, h, err := Raster(b, mime)
		if err != nil {
			return Result{}, err
		}
		return Result{Mime: mime, Data: b, Width: w, Height: h}, nil
	}
}
