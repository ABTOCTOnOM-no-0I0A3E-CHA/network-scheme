package mapimg_test

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/internal/mapimg"
)

const hdr = `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="100" height="50">`

var okElements = map[string]bool{"svg": true, "g": true, "path": true, "rect": true, "circle": true, "ellipse": true, "line": true,
	"polyline": true, "polygon": true, "text": true, "tspan": true, "defs": true, "linearGradient": true, "radialGradient": true,
	"stop": true, "clipPath": true, "mask": true, "pattern": true, "symbol": true, "use": true, "title": true, "desc": true, "image": true}

/*
assertSafe re-parses a sanitized document and fails when anything active is
left: a foreign element or namespace, an event handler, a href other than
#fragment or an embedded raster, a url() other than #fragment, script-ish words
in attributes. Character data is not checked: it is text.
*/
func assertSafe(out []byte) error {
	d := xml.NewDecoder(bytes.NewReader(out))
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("output does not parse: %w", err)
		}
		switch t := tok.(type) {
		case xml.Directive, xml.ProcInst:
			return fmt.Errorf("output has %T", t)
		case xml.StartElement:
			if t.Name.Space != "http://www.w3.org/2000/svg" || !okElements[t.Name.Local] {
				return fmt.Errorf("element %v", t.Name)
			}
			for _, a := range t.Attr {
				if a.Name.Space == "xmlns" || a.Name.Local == "xmlns" {
					continue
				}
				if a.Name.Space != "" {
					return fmt.Errorf("namespaced attribute %v", a.Name)
				}
				n, v := a.Name.Local, strings.ToLower(a.Value)
				if strings.HasPrefix(n, "on") {
					return fmt.Errorf("handler %s", n)
				}
				if n == "href" {
					if !strings.HasPrefix(v, "#") && !strings.HasPrefix(v, "data:image/png;base64,") &&
						!strings.HasPrefix(v, "data:image/jpeg;base64,") && !strings.HasPrefix(v, "data:image/webp;base64,") {
						return fmt.Errorf("href %q", a.Value)
					}
					continue
				}
				for _, bad := range []string{"javascript:", "script", "foreignobject", "@import", "expression", "http:", "https:", "data:"} {
					if strings.Contains(v, bad) {
						return fmt.Errorf("attribute %s=%q has %q", n, a.Value, bad)
					}
				}
				for rest := v; ; {
					i := strings.Index(rest, "url(")
					if i < 0 {
						break
					}
					rest = rest[i+4:]
					if !strings.HasPrefix(rest, "#") {
						return fmt.Errorf("attribute %s=%q has a non-fragment url()", n, a.Value)
					}
				}
			}
		}
	}
}

func sanitize(t *testing.T, in string) (string, int, int) {
	t.Helper()
	out, w, h, err := mapimg.SanitizeSVG([]byte(in))
	if err != nil {
		t.Fatalf("sanitize: %v\ninput: %s", err, in)
	}
	if err := assertSafe(out); err != nil {
		t.Fatalf("unsafe output: %v\n%s", err, out)
	}
	again, _, _, err := mapimg.SanitizeSVG(out)
	if err != nil || !bytes.Equal(again, out) {
		t.Fatalf("not idempotent (err %v)\n1: %s\n2: %s", err, out, again)
	}
	return string(out), w, h
}

func TestSVGPlain(t *testing.T) {
	out, w, h := sanitize(t, `<?xml version="1.0" encoding="UTF-8"?>`+"\n"+hdr+`<title>Plan</title><g id="a" fill="#fff" style="stroke:red;stroke-width:2"><rect x="1" y="2" width="3" height="4"/><text x="1" y="2">A &amp; B &lt;b&gt;</text></g></svg>`)
	if w != 100 || h != 50 {
		t.Errorf("size %dx%d", w, h)
	}
	for _, want := range []string{`<rect x="1" y="2" width="3" height="4"/>`, `style="stroke:red;stroke-width:2"`, `A &amp; B &lt;b&gt;`, `id="a"`} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %s: %s", want, out)
		}
	}
	if strings.Contains(out, "<?xml") {
		t.Errorf("declaration echoed: %s", out)
	}
}

func TestSVGBOMAndPrefixedNamespace(t *testing.T) {
	out, _, _ := sanitize(t, "\xEF\xBB\xBF  \n"+`<s:svg xmlns:s="http://www.w3.org/2000/svg" viewBox="0 0 10 20"><s:rect width="1" height="1"/></s:svg>`)
	if !strings.Contains(out, "<rect") || strings.Contains(out, "<s:") {
		t.Errorf("namespace not normalized: %s", out)
	}
}

/* Review Focus 3: every vector must leave nothing active behind. */
func TestSVGVectors(t *testing.T) {
	vectors := map[string]string{
		"script":            `<script>alert(1)</script><rect width="1" height="1"/>`,
		"script-ns-prefix":  `<x:script xmlns:x="http://www.w3.org/2000/svg">alert(1)</x:script>`,
		"script-other-ns":   `<script xmlns="http://www.w3.org/1999/xhtml">alert(1)</script>`,
		"onload":            `<rect width="1" height="1" onload="alert(1)" onclick="x()" onmouseover="y()"/>`,
		"foreignObject":     `<foreignObject width="10" height="10"><div xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script><img src="http://evil/x"/></div></foreignObject>`,
		"a-javascript":      `<a xlink:href="javascript:alert(1)"><rect width="1" height="1"/></a>`,
		"a-href":            `<a href="https://evil.example/"><text>x</text></a>`,
		"use-external":      `<use xlink:href="http://evil.example/x.svg#a"/>`,
		"use-data":          `<use href="data:image/svg+xml;base64,PHN2Zy8+"/>`,
		"use-js":            `<use href="javascript:alert(1)"/>`,
		"image-external":    `<image href="http://evil.example/track.png" width="1" height="1"/>`,
		"image-https-xlink": `<image xlink:href="https://evil.example/t.png"/>`,
		"image-svg-data":    `<image href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0naHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmcnIG9ubG9hZD0nYWxlcnQoMSknLz4="/>`,
		"image-html-data":   `<image href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="/>`,
		"image-fake-png":    `<image href="data:image/png;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==" width="1" height="1"/>`,
		"style-url":         `<rect width="1" height="1" style="fill:url(http://evil.example/x.svg#a)"/>`,
		"style-url-data":    `<rect width="1" height="1" style="fill:url('data:image/svg+xml;utf8,&lt;svg/&gt;')"/>`,
		"style-import":      `<rect width="1" height="1" style="@import url(http://evil/x.css); fill:red"/>`,
		"style-expression":  `<rect width="1" height="1" style="width:expression(alert(1)); fill:red"/>`,
		"style-behavior":    `<rect width="1" height="1" style="behavior:url(x.htc); -moz-binding:url(x.xml#a)"/>`,
		"style-js":          `<rect width="1" height="1" style="fill:javascript:alert(1)"/>`,
		"style-escape":      `<rect width="1" height="1" style="fill:u\72l(http://evil/)"/>`,
		"style-comment":     `<rect width="1" height="1" style="fill:ur/**/l(http://evil/)"/>`,
		"style-image-set":   `<rect width="1" height="1" style="fill:image-set('http://evil/x.png' 1x)"/>`,
		"style-element":     `<style>@import url(http://evil/x.css); rect{fill:url(http://evil/a)}</style><rect width="1" height="1"/>`,
		"attr-url":          `<rect width="1" height="1" fill="url(http://evil.example/a.svg#x)"/>`,
		"attr-url-upper":    `<rect width="1" height="1" fill="URL(HTTP://evil.example/)"/>`,
		"attr-url-space":    `<rect width="1" height="1" fill="url( 'https://evil/' )"/>`,
		"attr-js":           `<rect width="1" height="1" fill="javascript:alert(1)"/>`,
		"animate-href":      `<a><animate attributeName="href" values="javascript:alert(1)"/></a><set attributeName="onmouseover" to="alert(1)"/>`,
		"iframe-embed":      `<iframe src="http://evil"/><embed src="http://evil"/><object data="http://evil"/>`,
		"tref":              `<text><tref xlink:href="#a"/></text>`,
		"filter":            `<filter id="f"><feImage href="http://evil/x"/></filter><rect width="1" height="1" filter="url(#f)"/>`,
		"cursor":            `<rect width="1" height="1" cursor="url(http://evil/c.png), auto" style="cursor:url(http://evil/c.png)"/>`,
		"font-face":         `<font-face-uri href="http://evil/x.woff"/>`,
		"marker":            `<marker id="m"><image href="http://evil"/></marker><path d="M0 0L1 1" marker-end="url(http://evil/#m)"/>`,
		"xlink-on-g":        `<g xlink:href="http://evil/"><rect width="1" height="1"/></g>`,
		"unknown-ns-attr":   `<rect width="1" height="1" xmlns:q="urn:q" q:href="http://evil/" q:onload="x()"/>`,
		"xml-base":          `<g xml:base="http://evil/"><use href="#z"/></g>`,
		"gradient-href-ext": `<linearGradient id="g" xlink:href="http://evil/g.svg#x"/><rect width="1" height="1" fill="url(#g)"/>`,
	}
	for name, body := range vectors {
		t.Run(name, func(t *testing.T) {
			out, _, _ := sanitize(t, hdr+body+`</svg>`)
			for _, bad := range []string{"alert(1)", "evil", "<script", "onload", "onclick", "foreignObject", "<style", "<a ", "iframe"} {
				if strings.Contains(out, bad) {
					t.Errorf("output still has %q:\n%s", bad, out)
				}
			}
		})
	}
	t.Run("onload-root", func(t *testing.T) {
		out, _, _ := sanitize(t, `<svg xmlns="http://www.w3.org/2000/svg" width="5" height="5" onload="alert(1)" onclick="x()"></svg>`)
		if strings.Contains(out, "alert") || strings.Contains(out, "onload") {
			t.Errorf("root handler kept: %s", out)
		}
	})
}

func TestSVGTextIsEscaped(t *testing.T) {
	out, _, _ := sanitize(t, hdr+`<text><![CDATA[<script>alert(1)</script>]]></text></svg>`)
	if strings.Contains(out, "<script") || !strings.Contains(out, "&lt;script&gt;") {
		t.Errorf("text not escaped: %s", out)
	}
}

func TestSVGFragmentReferencesSurvive(t *testing.T) {
	out, _, _ := sanitize(t, hdr+`<defs><linearGradient id="g" xlink:href="#h"/><linearGradient id="h"><stop offset="0" stop-color="#000"/></linearGradient><symbol id="s"><rect width="1" height="1"/></symbol></defs>`+
		`<rect width="1" height="1" fill="url( '#g' )" style="stroke:url(#g)"/><use xlink:href="#s" x="3"/></svg>`)
	for _, want := range []string{`fill="url(#g)"`, `stroke:url(#g)`, `<use href="#s" x="3"/>`, `<linearGradient id="g" href="#h"/>`} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %s:\n%s", want, out)
		}
	}
}

func png1x1(t *testing.T) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSVGEmbeddedImage(t *testing.T) {
	png := base64.StdEncoding.EncodeToString(png1x1(t))
	out, _, _ := sanitize(t, hdr+`<image width="1" height="1" xlink:href="data:image/png;base64,`+png[:20]+"\n  "+png[20:]+`"/></svg>`)
	if !strings.Contains(out, `href="data:image/png;base64,`+png+`"`) {
		t.Errorf("canonical data URI missing: %s", out)
	}
	/* a PNG declared as JPEG, and an oversize bitmap, are dropped */
	for _, in := range []string{
		hdr + `<image href="data:image/jpeg;base64,` + png + `"/></svg>`,
		hdr + `<image href="data:image/png;base64,` + base64.StdEncoding.EncodeToString(bombPNG(t)) + `"/></svg>`,
	} {
		if out, _, _ := sanitize(t, in); strings.Contains(out, "<image") {
			t.Errorf("bad image kept: %s", out)
		}
	}
}

func TestSVGRejected(t *testing.T) {
	deep := hdr + strings.Repeat("<g>", 63) + strings.Repeat("</g>", 63) + `</svg>`
	tooDeep := hdr + strings.Repeat("<g>", 65) + strings.Repeat("</g>", 65) + `</svg>`
	skippedDeep := hdr + strings.Repeat("<foo>", 70) + strings.Repeat("</foo>", 70) + `</svg>`
	many := hdr + strings.Repeat("<g/>", 100_000) + `</svg>`
	manyAttrs := hdr + `<g ` + func() string {
		var b strings.Builder
		for i := 0; i < 250; i++ {
			fmt.Fprintf(&b, `a%d="1" `, i)
		}
		return b.String()
	}() + `/></svg>`
	for name, tc := range map[string]struct {
		in   string
		want error
	}{
		"doctype":        {`<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">` + hdr + `</svg>`, mapimg.ErrInvalid},
		"xxe":            {`<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` + hdr + `<text>&xxe;</text></svg>`, mapimg.ErrInvalid},
		"billion-laughs": {`<!DOCTYPE svg [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]>` + hdr + `<text>&c;</text></svg>`, mapimg.ErrInvalid},
		"undefined-ent":  {hdr + `<text>&nbsp;&foo;</text></svg>`, mapimg.ErrInvalid},
		"pi":             {hdr + `<?php echo 1 ?></svg>`, mapimg.ErrInvalid},
		"xml-stylesheet": {`<?xml version="1.0"?><?xml-stylesheet href="http://evil/x.css"?>` + hdr + `</svg>`, mapimg.ErrInvalid},
		"late-xml-decl":  {hdr + `<?xml version="1.0"?></svg>`, mapimg.ErrInvalid},
		"too-deep":       {tooDeep, mapimg.ErrInvalid},
		"skipped-deep":   {skippedDeep, mapimg.ErrInvalid},
		"too-many":       {many, mapimg.ErrInvalid},
		"second-root":    {hdr + `</svg><svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>`, mapimg.ErrInvalid},
		"text-after":     {hdr + `</svg>trailing`, mapimg.ErrInvalid},
		"unclosed":       {hdr + `<g>`, mapimg.ErrInvalid},
		"mismatch":       {hdr + `<g></h></svg>`, mapimg.ErrInvalid},
		"charset":        {`<?xml version="1.0" encoding="UTF-16"?>` + hdr + `</svg>`, mapimg.ErrInvalid},
		"no-size":        {`<svg xmlns="http://www.w3.org/2000/svg"></svg>`, mapimg.ErrInvalid},
		"percent-size":   {`<svg xmlns="http://www.w3.org/2000/svg" width="100%" height="100%"></svg>`, mapimg.ErrInvalid},
		"huge-size":      {`<svg xmlns="http://www.w3.org/2000/svg" width="16385" height="10"></svg>`, mapimg.ErrInvalid},
		"huge-viewbox":   {`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 99999"></svg>`, mapimg.ErrInvalid},
		"neg-viewbox":    {`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 -5 10"></svg>`, mapimg.ErrInvalid},
		"html-root":      {`<html><body><script>alert(1)</script></body></html>`, mapimg.ErrNotSVG},
		"svg-no-ns":      {`<svg width="1" height="1"/>`, mapimg.ErrNotSVG},
		"foreign-root":   {`<svg xmlns="http://www.w3.org/1999/xhtml" width="1" height="1"/>`, mapimg.ErrNotSVG},
		"plain-text":     {`hello`, mapimg.ErrInvalid},
		"broken-xml":     {`<svg`, mapimg.ErrInvalid},
		"too-many-attrs": {manyAttrs, mapimg.ErrInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, err := mapimg.SanitizeSVG([]byte(tc.in))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	sanitize(t, deep)
}

func TestSVGSize(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		w, h int
	}{
		"attrs":         {`<svg xmlns="http://www.w3.org/2000/svg" width="640px" height="480.5" viewBox="0 0 1 1"/>`, 640, 481},
		"viewbox":       {`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0,0,800 600"/>`, 800, 600},
		"percent+vb":    {`<svg xmlns="http://www.w3.org/2000/svg" width="100%" height="100%" viewBox="0 0 30 20"/>`, 30, 20},
		"one-attr+vb":   {`<svg xmlns="http://www.w3.org/2000/svg" width="10" viewBox="0 0 30 20"/>`, 30, 20},
		"max":           {`<svg xmlns="http://www.w3.org/2000/svg" width="16384" height="16384"/>`, 16384, 16384},
		"units+viewbox": {`<svg xmlns="http://www.w3.org/2000/svg" width="10cm" height="5cm" viewBox="0 0 50 25"/>`, 50, 25},
	} {
		t.Run(name, func(t *testing.T) {
			if _, w, h := sanitize(t, tc.in); w != tc.w || h != tc.h {
				t.Errorf("size = %dx%d, want %dx%d", w, h, tc.w, tc.h)
			}
		})
	}
}

func TestSVGUseLimits(t *testing.T) {
	/* a chain of uses is the building block of exponential expansion: every use of a target holding a use goes */
	var b strings.Builder
	b.WriteString(hdr + `<defs><g id="l0"><rect width="1" height="1"/></g>`)
	for i := 1; i <= 30; i++ {
		fmt.Fprintf(&b, `<g id="l%d"><use href="#l%d"/><use href="#l%d"/></g>`, i, i-1, i-1)
	}
	b.WriteString(`</defs><use href="#l30"/><use href="#missing"/><use href="#l0"/><use href="#l0"/></svg>`)
	out, _, _ := sanitize(t, b.String())
	if strings.Contains(out, `href="#l30"`) || strings.Contains(out, "missing") {
		t.Errorf("expanding use kept: %s", out)
	}
	if !strings.Contains(out, `<use href="#l0"/><use href="#l0"/></svg>`) {
		t.Errorf("plain uses dropped: %s", out)
	}
	if out, _, _ := sanitize(t, hdr+`<g id="a"><use href="#a"/></g></svg>`); strings.Contains(out, "<use") {
		t.Errorf("self-referencing use kept: %s", out)
	}
	if out, _, _ := sanitize(t, hdr+`<g id="a"/><g id="a"><rect width="1" height="1"/></g><use href="#a"/></svg>`); strings.Count(out, `id="a"`) != 1 {
		t.Errorf("duplicate id kept: %s", out)
	}
}

func TestSVGOversize(t *testing.T) {
	big := hdr + `<text>` + strings.Repeat("a", mapimg.MaxBytes) + `</text></svg>`
	if _, _, _, err := mapimg.SanitizeSVG([]byte(big)); !errors.Is(err, mapimg.ErrTooLarge) {
		t.Errorf("err = %v", err)
	}
	if _, _, _, err := mapimg.SanitizeSVG([]byte(hdr + `<text>` + strings.Repeat("a", 2<<20) + `</text></svg>`)); !errors.Is(err, mapimg.ErrInvalid) {
		t.Errorf("text limit: %v", err)
	}
}

/*
FuzzSanitizeSVG: no panic; a document that passes yields output that is safe
and unchanged by a second pass.
*/
func FuzzSanitizeSVG(f *testing.F) {
	for _, s := range []string{
		hdr + `<g id="a" style="fill:url(#b);stroke:red"><use href="#a"/><image href="data:image/png;base64,AAAA"/></g></svg>`,
		`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><text>a&amp;b<![CDATA[<x>]]></text><script>1</script></svg>`,
		hdr + `<rect onload="x()" fill="url(http://e/)" style="@import 'x'"/><foreignObject/><a href="javascript:1"/></svg>`,
		`<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY a "b">]><svg/>`,
		hdr + `<linearGradient id="g" xlink:href="#h"/><use xlink:href="#g" transform="rotate(5) translate(1,2)"/></svg>`,
		"\xEF\xBB\xBF<s:svg xmlns:s='http://www.w3.org/2000/svg' width='3' height='3'><s:path d='M0 0L1 1'/></s:svg>",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		out, w, h, err := mapimg.SanitizeSVG(in)
		if err != nil {
			return
		}
		if w < 1 || h < 1 || w > mapimg.MaxDim || h > mapimg.MaxDim {
			t.Fatalf("size %dx%d", w, h)
		}
		if err := assertSafe(out); err != nil {
			t.Fatalf("unsafe output: %v\ninput: %q\noutput: %s", err, in, out)
		}
		again, w2, h2, err := mapimg.SanitizeSVG(out)
		if err != nil || !bytes.Equal(again, out) || w2 != w || h2 != h {
			t.Fatalf("not idempotent (err %v)\ninput: %q\n1: %s\n2: %s", err, in, out, again)
		}
	})
}
