package mapimg

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

const (
	nsSVG   = "http://www.w3.org/2000/svg"
	nsXLink = "http://www.w3.org/1999/xlink"

	maxDepth    = 64        /* element nesting, dropped subtrees included */
	maxElements = 100_000   /* start tags in the input, dropped ones included */
	maxAttrs    = 200       /* attributes on one element, namespace declarations included */
	maxNodes    = 200_000   /* kept elements plus kept text nodes */
	maxKept     = 1_000_000 /* kept attributes in the whole document */
	maxAttrLen  = 4 << 20   /* one attribute value */
	maxText     = 1 << 20   /* all character data kept */
	maxUses     = 10_000    /* <use> elements kept */
	maxUseCost  = 2_000_000 /* total size of the subtrees <use> elements instantiate */
)

// ErrNotSVG means the document is XML without an svg root element (the caller reports
// "unsupported type"); every other rejection wraps ErrInvalid.
var ErrNotSVG = errors.New("mapimg: not an SVG document")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: svg: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

var svgElements = set("svg", "g", "path", "rect", "circle", "ellipse", "line", "polyline", "polygon", "text", "tspan",
	"defs", "linearGradient", "radialGradient", "stop", "clipPath", "mask", "pattern", "symbol", "use", "title", "desc", "image")

/* textHolders are the elements whose character data is kept. */
var textHolders = set("text", "tspan", "title", "desc")

/* Presentation properties: allowed as attributes and as declarations of style. */
var presentation = set("fill", "fill-opacity", "fill-rule", "stroke", "stroke-width", "stroke-opacity", "stroke-linecap",
	"stroke-linejoin", "stroke-miterlimit", "stroke-dasharray", "stroke-dashoffset", "opacity", "color", "display",
	"visibility", "overflow", "clip-path", "clip-rule", "mask", "font-family", "font-size", "font-style", "font-weight",
	"text-anchor", "text-decoration", "letter-spacing", "word-spacing", "dominant-baseline", "alignment-baseline",
	"baseline-shift", "stop-color", "stop-opacity", "shape-rendering", "text-rendering", "image-rendering",
	"vector-effect", "writing-mode", "transform")

var geometry = set("x", "y", "width", "height", "cx", "cy", "r", "rx", "ry", "x1", "y1", "x2", "y2", "fx", "fy", "fr",
	"points", "d", "dx", "dy", "rotate", "viewBox", "preserveAspectRatio", "transform", "offset", "pathLength",
	"textLength", "lengthAdjust", "gradientUnits", "gradientTransform", "spreadMethod", "patternUnits",
	"patternContentUnits", "patternTransform", "clipPathUnits", "maskUnits", "maskContentUnits", "class")

/* cssFuncs are the only functions a value may call. */
var cssFuncs = set("rgb", "rgba", "hsl", "hsla", "url", "matrix", "translate", "scale", "rotate", "skewx", "skewy")

/* badWords are rejected anywhere in a value, case-insensitively and with whitespace removed. */
var badWords = []string{"javascript:", "vbscript:", "data:", "http:", "https:", "file:", "ftp:", "expression", "behavior", "binding", "@import"}

var (
	idRe       = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.:-]{0,199}$`)
	fragmentRe = regexp.MustCompile(`^#[A-Za-z_][A-Za-z0-9_.:-]{0,199}$`)
	lengthRe   = regexp.MustCompile(`^\s*(\d{1,12}(?:\.\d{0,12})?|\.\d{1,12})\s*(?:px)?\s*$`)
)

func set(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

type kv struct{ k, v string }

type node struct {
	name     string /* "" for a text node */
	attrs    []kv
	children []*node
	text     []byte
	dead     bool
	href     string /* #fragment of a kept <use> */
}

/*
SanitizeSVG parses in with a strict streaming XML decoder and returns a freshly
serialized document that holds only allowlisted elements and attributes, with
its pixel size taken from the root element (width/height, else viewBox). The
input text is never echoed: whatever is not on the allowlists is dropped.
Rejected: DOCTYPE and entity declarations, processing instructions other than a
leading XML declaration, nesting over 64 levels, over 100 000 elements, a root
other than svg and sizes outside 1..16384.
*/
func SanitizeSVG(in []byte) (out []byte, width, height int, err error) {
	if len(in) > MaxBytes {
		return nil, 0, 0, ErrTooLarge
	}
	in = bytes.TrimPrefix(in, bom)
	d := xml.NewDecoder(bytes.NewReader(in))
	d.Strict = true

	var (
		root, cur *node
		parents   []*node
		depth     int
		skip      int /* >0: inside a dropped element (itself included) */
		elems     int
		textBytes int
		sawProc   bool
		rootDone  bool
		embedded  int
		nodes     int
		kept      int
	)
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, 0, 0, invalid("%v", err)
		}
		switch t := tok.(type) {
		case xml.Directive:
			return nil, 0, 0, invalid("DOCTYPE and declarations are not allowed")
		case xml.ProcInst:
			if sawProc || root != nil || t.Target != "xml" {
				return nil, 0, 0, invalid("processing instruction")
			}
			sawProc = true
		case xml.Comment:
		case xml.StartElement:
			if elems++; elems > maxElements {
				return nil, 0, 0, invalid("too many elements")
			}
			if depth++; depth > maxDepth {
				return nil, 0, 0, invalid("nesting too deep")
			}
			if skip > 0 {
				skip++
				continue
			}
			if rootDone {
				return nil, 0, 0, invalid("content after the root element")
			}
			if root == nil && (t.Name.Space != nsSVG || t.Name.Local != "svg") {
				return nil, 0, 0, ErrNotSVG
			}
			if len(t.Attr) > maxAttrs {
				return nil, 0, 0, invalid("too many attributes")
			}
			if t.Name.Space != nsSVG || !svgElements[t.Name.Local] {
				skip = 1
				continue
			}
			if nodes++; nodes > maxNodes {
				return nil, 0, 0, invalid("too many nodes")
			}
			attrs, ok, err := cleanAttrs(t.Name.Local, t.Attr, &embedded)
			if err != nil {
				return nil, 0, 0, err
			}
			if !ok {
				skip = 1
				continue
			}
			if kept += len(attrs); kept > maxKept {
				return nil, 0, 0, invalid("too many attributes in the document")
			}
			n := &node{name: t.Name.Local, attrs: attrs}
			if n.name == "use" {
				n.href = attrValue(attrs, "href")
			}
			if root == nil {
				root = n
			} else {
				cur.children = append(cur.children, n)
			}
			parents = append(parents, cur)
			cur = n
		case xml.EndElement:
			depth--
			if skip > 0 {
				skip--
				continue
			}
			cur = parents[len(parents)-1]
			parents = parents[:len(parents)-1]
			if cur == nil {
				rootDone = true
			}
		case xml.CharData:
			if skip > 0 {
				continue
			}
			if cur == nil {
				if len(bytes.TrimSpace(t)) > 0 {
					return nil, 0, 0, invalid("text outside the root element")
				}
				continue
			}
			if !textHolders[cur.name] || len(t) == 0 {
				continue
			}
			if textBytes += len(t); textBytes > maxText {
				return nil, 0, 0, invalid("too much text")
			}
			if last := len(cur.children) - 1; last >= 0 && cur.children[last].name == "" {
				cur.children[last].text = append(cur.children[last].text, t...) /* comments split text: merge */
				continue
			}
			if nodes++; nodes > maxNodes {
				return nil, 0, 0, invalid("too many nodes")
			}
			cur.children = append(cur.children, &node{text: append([]byte(nil), t...)})
		}
	}
	if root == nil {
		return nil, 0, 0, ErrNotSVG
	}

	width, height, err = fixRootSize(root)
	if err != nil {
		return nil, 0, 0, err
	}
	pruneUses(root)

	var b bytes.Buffer
	writeNode(&b, root, true)
	if b.Len() > MaxBytes {
		return nil, 0, 0, ErrTooLarge
	}
	return b.Bytes(), width, height, nil
}

func attrValue(attrs []kv, k string) string {
	for _, a := range attrs {
		if a.k == k {
			return a.v
		}
	}
	return ""
}

/*
cleanAttrs keeps the allowlisted attributes of element el with safe values.
ok is false when the element must be dropped because it lacks its mandatory
safe href (<use>, <image>).
*/
func cleanAttrs(el string, in []xml.Attr, embedded *int) (out []kv, ok bool, err error) {
	seen := map[string]bool{}
	for _, a := range in {
		var name string
		switch {
		case a.Name.Space == "" && a.Name.Local == "xmlns", a.Name.Space == "xmlns":
			continue
		case a.Name.Space == nsXLink && a.Name.Local == "href":
			name = "href"
		case a.Name.Space == "":
			name = a.Name.Local
		default:
			continue
		}
		if seen[name] {
			continue
		}
		var v string
		var good bool
		switch {
		case name == "href":
			v, good, err = cleanHref(el, a.Value, embedded)
			if err != nil {
				return nil, false, err
			}
		case name == "id":
			v, good = a.Value, idRe.MatchString(a.Value)
		case name == "style":
			v, good = cleanStyle(a.Value)
		case presentation[name] || geometry[name]:
			v, good = cleanValue(a.Value)
		}
		if good && v != "" {
			seen[name] = true
			out = append(out, kv{name, v})
		}
	}
	if (el == "use" || el == "image") && !seen["href"] {
		return nil, false, nil
	}
	return out, true, nil
}

/*
cleanHref accepts #fragment on <use>, gradients and <pattern>, and an embedded
PNG, JPEG or WebP data URI on <image>; the embedded bytes must pass the raster
check and are re-encoded canonically. Anything else is not kept.
*/
func cleanHref(el, v string, embedded *int) (string, bool, error) {
	switch el {
	case "use", "linearGradient", "radialGradient", "pattern":
		v = strings.TrimSpace(v)
		return v, fragmentRe.MatchString(v), nil
	case "image":
		s := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
				return -1
			}
			return r
		}, v)
		for _, mime := range []string{MIMEPNG, MIMEJPEG, MIMEWebP} {
			prefix := "data:" + mime + ";base64,"
			if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
				continue
			}
			raw, err := base64.StdEncoding.DecodeString(s[len(prefix):])
			if err != nil {
				raw, err = base64.RawStdEncoding.DecodeString(s[len(prefix):])
			}
			if err != nil || len(raw) == 0 || Detect(raw) != mime {
				return "", false, nil
			}
			if *embedded += len(raw); *embedded > MaxBytes {
				return "", false, ErrTooLarge
			}
			if _, _, err := Raster(raw, mime); err != nil {
				return "", false, nil
			}
			return prefix + base64.StdEncoding.EncodeToString(raw), true, nil
		}
	}
	return "", false, nil
}

/* cleanStyle keeps the declarations whose property is a presentation property and whose value is safe. */
func cleanStyle(s string) (string, bool) {
	var out []string
	for _, decl := range splitDecls(s) {
		k, v, found := strings.Cut(decl, ":")
		k = strings.ToLower(strings.TrimSpace(k))
		if !found || !presentation[k] {
			continue
		}
		if cv, ok := cleanValue(strings.TrimSpace(v)); ok && cv != "" {
			out = append(out, k+":"+cv)
		}
	}
	return strings.Join(out, ";"), len(out) > 0
}

/* splitDecls splits a style attribute at the semicolons outside quotes. */
func splitDecls(s string) []string {
	var out []string
	var quote byte
	start := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == ';':
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func safeRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r) || strings.ContainsRune(" \t\r\n.,+-#%()'\"/_:", r)
}

/*
cleanValue vets an attribute or declaration value: a conservative character
set (no ';', '\', '@', '&', '<', '!', '*'), no script-ish words, and every
function call must be on the cssFuncs list, with url() restricted to #fragment
(rewritten to its canonical form).
*/
func cleanValue(v string) (string, bool) {
	if len(v) > maxAttrLen {
		return "", false
	}
	for _, r := range v {
		if !safeRune(r) {
			return "", false
		}
	}
	squeezed := strings.ToLower(strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, v))
	for _, w := range badWords {
		if strings.Contains(squeezed, w) {
			return "", false
		}
	}
	if !strings.ContainsAny(v, "()") {
		return v, true
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == ')' {
			return "", false /* a closing parenthesis without its call */
		}
		b.WriteByte(c)
		if c != '(' {
			continue
		}
		s := b.String()
		j := len(s) - 1
		for j > 0 && (s[j-1] == '-' || s[j-1] == '_' || s[j-1] >= '0' && s[j-1] <= '9' || s[j-1] >= 'A' && s[j-1] <= 'Z' || s[j-1] >= 'a' && s[j-1] <= 'z') {
			j--
		}
		fn := strings.ToLower(s[j : len(s)-1])
		if !cssFuncs[fn] {
			return "", false
		}
		end := strings.IndexByte(v[i+1:], ')')
		if end < 0 {
			return "", false
		}
		args := v[i+1 : i+1+end]
		if strings.ContainsRune(args, '(') {
			return "", false /* no nesting */
		}
		if fn == "url" {
			args = strings.TrimSpace(args)
			if len(args) >= 2 && (args[0] == '\'' || args[0] == '"') && args[len(args)-1] == args[0] {
				args = strings.TrimSpace(args[1 : len(args)-1])
			}
			if !fragmentRe.MatchString(args) {
				return "", false
			}
		}
		b.WriteString(args)
		b.WriteByte(')')
		i += end + 1
	}
	return b.String(), true
}

func fmtNum(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

func parseLength(s string) (float64, bool) {
	m := lengthRe.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	f, err := strconv.ParseFloat(m[1], 64)
	return f, err == nil && f > 0
}

func parseViewBox(s string) (w, h float64, canon string, ok bool) {
	f := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	if len(f) != 4 {
		return 0, 0, "", false
	}
	var v [4]float64
	parts := make([]string, 4)
	for i := range f {
		x, err := strconv.ParseFloat(f[i], 64)
		if err != nil || math.IsNaN(x) || math.IsInf(x, 0) || math.Abs(x) > 1e9 {
			return 0, 0, "", false
		}
		v[i], parts[i] = x, fmtNum(x)
	}
	if v[2] <= 0 || v[3] <= 0 {
		return 0, 0, "", false
	}
	return v[2], v[3], strings.Join(parts, " "), true
}

/*
fixRootSize derives the pixel size of the document (width/height when both are
plain lengths, otherwise the viewBox) and rewrites the root's width, height and
viewBox in canonical form; unusable ones are removed.
*/
func fixRootSize(root *node) (int, int, error) {
	var w, h, vw, vh float64
	var vbCanon string
	wOK, hOK := false, false
	if s := attrValue(root.attrs, "width"); s != "" {
		w, wOK = parseLength(s)
	}
	if s := attrValue(root.attrs, "height"); s != "" {
		h, hOK = parseLength(s)
	}
	vbOK := false
	if s := attrValue(root.attrs, "viewBox"); s != "" {
		vw, vh, vbCanon, vbOK = parseViewBox(s)
	}
	var pw, ph float64
	switch {
	case wOK && hOK:
		pw, ph = w, h
	case vbOK:
		pw, ph = vw, vh
	default:
		return 0, 0, invalid("no usable width/height or viewBox")
	}
	pw, ph = math.Ceil(pw), math.Ceil(ph)
	if pw < 1 || ph < 1 || pw > MaxDim || ph > MaxDim {
		return 0, 0, invalid("dimensions out of range")
	}
	attrs := make([]kv, 0, len(root.attrs)+3)
	if wOK && hOK {
		attrs = append(attrs, kv{"width", fmtNum(w)}, kv{"height", fmtNum(h)})
	}
	if vbOK {
		attrs = append(attrs, kv{"viewBox", vbCanon})
	}
	for _, a := range root.attrs {
		if a.k != "width" && a.k != "height" && a.k != "viewBox" {
			attrs = append(attrs, a)
		}
	}
	root.attrs = attrs
	return int(pw), int(ph), nil
}

type subtree struct {
	size   int
	hasUse bool
}

/*
pruneUses drops duplicate ids and every <use> that points anywhere but at an
existing element without <use> inside it (no chains, so no exponential
expansion), then bounds the number of uses and the total size they instantiate.
*/
func pruneUses(root *node) {
	ids := map[string]*node{}
	var uses []*node
	info := map[*node]subtree{}
	var walk func(n *node) subtree
	walk = func(n *node) subtree {
		if n.name == "" {
			return subtree{}
		}
		s := subtree{size: 1, hasUse: n.name == "use"}
		if id := attrValue(n.attrs, "id"); id != "" {
			if ids[id] == nil {
				ids[id] = n
			} else {
				n.attrs = withoutAttr(n.attrs, "id")
			}
		}
		if n.name == "use" {
			uses = append(uses, n)
		}
		for _, c := range n.children {
			cs := walk(c)
			s.size += cs.size
			s.hasUse = s.hasUse || cs.hasUse
		}
		info[n] = s
		return s
	}
	walk(root)
	kept, cost := 0, 0
	for _, u := range uses {
		t := ids[strings.TrimPrefix(u.href, "#")]
		if t == nil || info[t].hasUse || kept+1 > maxUses || cost+info[t].size > maxUseCost {
			u.dead = true
			continue
		}
		kept++
		cost += info[t].size
	}
}

func withoutAttr(attrs []kv, k string) []kv {
	out := make([]kv, 0, len(attrs))
	for _, a := range attrs {
		if a.k != k {
			out = append(out, a)
		}
	}
	return out
}

var attrEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;", "\t", "&#x9;", "\n", "&#xA;", "\r", "&#xD;")

func writeNode(b *bytes.Buffer, n *node, root bool) {
	if n.dead {
		return
	}
	if n.name == "" {
		_ = xml.EscapeText(b, n.text)
		return
	}
	b.WriteByte('<')
	b.WriteString(n.name)
	if root {
		b.WriteString(` xmlns="` + nsSVG + `" xmlns:xlink="` + nsXLink + `"`)
	}
	for _, a := range n.attrs {
		b.WriteString(" " + a.k + `="`)
		_, _ = attrEscaper.WriteString(b, a.v)
		b.WriteByte('"')
	}
	live := false
	for _, c := range n.children {
		live = live || !c.dead
	}
	if !live {
		b.WriteString("/>")
		return
	}
	b.WriteByte('>')
	for _, c := range n.children {
		writeNode(b, c, false)
	}
	b.WriteString("</" + n.name + ">")
}
