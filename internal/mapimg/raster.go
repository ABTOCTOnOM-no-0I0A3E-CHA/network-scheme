package mapimg

import (
	"bytes"
	"fmt"
	"image"
	_ "image/jpeg" // registers the JPEG decoder for DecodeConfig
	_ "image/png"  // registers the PNG decoder for DecodeConfig

	_ "golang.org/x/image/webp" // registers the WebP decoder for DecodeConfig
)

var rasterFormats = map[string]string{"png": MIMEPNG, "jpeg": MIMEJPEG, "webp": MIMEWebP}

/*
Raster checks a PNG, JPEG or WebP by its header only: image.DecodeConfig never
decodes pixels, so a decompression bomb is rejected from its declared size. The
format found by the decoder must equal mime (the one sniffed from the bytes).
*/
func Raster(b []byte, mime string) (width, height int, err error) {
	cfg, format, err := image.DecodeConfig(bytes.NewReader(b))
	if err != nil {
		return 0, 0, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if rasterFormats[format] != mime {
		return 0, 0, fmt.Errorf("%w: content is %s, not %s", ErrInvalid, format, mime)
	}
	if cfg.Width < 1 || cfg.Height < 1 || cfg.Width > MaxDim || cfg.Height > MaxDim {
		return 0, 0, fmt.Errorf("%w: dimensions %dx%d out of range", ErrInvalid, cfg.Width, cfg.Height)
	}
	return cfg.Width, cfg.Height, nil
}
