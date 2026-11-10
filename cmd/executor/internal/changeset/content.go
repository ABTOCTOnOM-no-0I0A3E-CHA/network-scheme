/*
Package changeset is the executor's changesets (security.md 5.4, Phase 5):
one user's change of many devices at once, authored, stored, dry-run,
approved and run only in the executor. The api sees the metadata of
execpub.changeset_summary, never the lines or the configurations.

content.go is what a changeset changes (Content) and its canonical
encoding, which the stored revision holds and its SHA-256 covers; store.go
keeps the append-only rows of exec.changeset* under the executor's MAC.
*/
package changeset

import (
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers"
	"github.com/beekamai/network-scheme/cmd/executor/internal/forms"
	"github.com/beekamai/network-scheme/internal/execpolicy"
)

/* Kinds of changesets (exec.changeset.kind). */
const (
	KindLines   = "lines"
	KindRestore = "restore"
)

/* Bounds of a content (the policy bounds devices, lines and the batch below these). */
const (
	MaxContent   = 960 << 10 /* the canonical encoding: below registry.MaxMessage, as the CHECK of exec.changeset_revision */
	maxTitle     = 120       /* characters */
	maxLine      = 512       /* bytes of one line */
	maxVars      = 32        /* variables per device */
	maxVarValue  = 128
	maxSettleS   = 600
	maxFormField = 256
)

/*
Step is one step of a lines changeset: a line typed from the privileged
prompt (variables {{name}} are replaced per device), or a GUI form the
device's driver renders into lines. Exactly one is set.
*/
type Step struct {
	Line string        `json:"line,omitempty"`
	Form *forms.Params `json:"form,omitempty"`
}

/* RestoreItem is one device of a restore changeset and the configuration version it goes back to (task 5.6). */
type RestoreItem struct {
	Device  int64 `json:"device_id"`
	Version int64 `json:"version_id"`
}

/*
Content is what a changeset changes: Devices in the order of the run
(Devices[0] is the canary), then either Steps (with Vars per device) or
Restore (one version per device, in the order of Devices).
*/
type Content struct {
	Title     string                      `json:"title"`
	Devices   []int64                     `json:"device_ids"`
	Steps     []Step                      `json:"steps,omitempty"`
	Vars      map[int64]map[string]string `json:"vars,omitempty"`
	BatchSize int                         `json:"batch_size"`
	SettleS   int                         `json:"settle_s"`
	Restore   []RestoreItem               `json:"restore,omitempty"`
}

/* Kind is restore when the content restores versions, else lines. */
func (c Content) Kind() string {
	if len(c.Restore) > 0 {
		return KindRestore
	}
	return KindLines
}

var (
	varName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	/* a placeholder; any other "{{" or "}}" in a line is refused */
	placeholder = regexp.MustCompile(`\{\{([a-z][a-z0-9_]{0,31})\}\}`)
)

/* ErrContent is a content that Check refuses (the message says what, never a value). */
var ErrContent = errors.New("changeset: bad content")

func bad(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrContent, fmt.Sprintf(format, args...))
}

/* displayable is valid UTF-8 without control or format characters (Cf), as confirm shows it. */
func displayable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return false
		}
	}
	return true
}

/* printableASCII: every byte is 0x20..0x7e. */
func printableASCII(s string) bool {
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

/*
Check validates c against the policy's limits (security.md 5.4 D7) and the
fixed bounds: a title of 1..120 displayable characters; 1..
changeset_max_devices distinct positive devices; steps xor restore items;
at most changeset_max_lines steps, each a line of 1..512 bytes without
control characters or a form; variables only for the changeset's devices,
named ^[a-z][a-z0-9_]{0,31}$, at most 32 per device, values of at most 128
printable ASCII bytes without "{{" or "}}"; every placeholder of a line
defined for every device; a batch of 1..changeset_max_batch; settle_s
0..600; the encoding at most MaxContent.
*/
func (c Content) Check(p execpolicy.Policy) error {
	if n := utf8.RuneCountInString(c.Title); n == 0 || n > maxTitle || !displayable(c.Title) || strings.TrimSpace(c.Title) == "" {
		return bad("title: 1..%d displayable characters", maxTitle)
	}
	if len(c.Devices) == 0 || len(c.Devices) > p.ChangesetMaxDevices {
		return bad("devices: 1..%d", p.ChangesetMaxDevices)
	}
	seen := map[int64]bool{}
	for _, d := range c.Devices {
		if d <= 0 || seen[d] {
			return bad("devices: positive and distinct ids")
		}
		seen[d] = true
	}
	if (len(c.Steps) > 0) == (len(c.Restore) > 0) {
		return bad("either steps or restore items")
	}
	if c.BatchSize < 1 || c.BatchSize > p.ChangesetMaxBatch {
		return bad("batch_size: 1..%d", p.ChangesetMaxBatch)
	}
	if c.SettleS < 0 || c.SettleS > maxSettleS {
		return bad("settle_s: 0..%d", maxSettleS)
	}
	if c.Kind() == KindRestore {
		if len(c.Restore) != len(c.Devices) || len(c.Vars) > 0 {
			return bad("restore: one version per device, no variables")
		}
		for i, r := range c.Restore {
			if r.Device != c.Devices[i] || r.Version <= 0 {
				return bad("restore[%d]: the device of devices[%d] and a positive version", i, i)
			}
		}
	} else if err := c.checkSteps(p, seen); err != nil {
		return err
	}
	if len(c.Canonical()) > MaxContent {
		return bad("larger than %d bytes", MaxContent)
	}
	return nil
}

func (c Content) checkSteps(p execpolicy.Policy, devices map[int64]bool) error {
	if len(c.Steps) > p.ChangesetMaxLines {
		return bad("steps: at most %d", p.ChangesetMaxLines)
	}
	used := map[string]bool{}
	for i, s := range c.Steps {
		switch {
		case (s.Line == "") == (s.Form == nil):
			return bad("step %d: a line or a form", i+1)
		case s.Form != nil:
			f := s.Form
			if f.Kind == "" || len(f.Kind) > 64 || len(f.Interface) > 64 || len(f.Description) > maxFormField || len(f.Name) > 64 ||
				f.VLAN < 0 || f.VLAN > 4094 || !printableASCII(f.Kind+f.Interface+f.Description+f.Name) ||
				strings.Contains(f.Interface+f.Description+f.Name, "{{") {
				return bad("step %d: bad form", i+1)
			}
		default:
			if len(s.Line) > maxLine || !displayable(s.Line) {
				return bad("step %d: a line of 1..%d bytes without control characters", i+1, maxLine)
			}
			rest := placeholder.ReplaceAllStringFunc(s.Line, func(m string) string {
				used[m[2:len(m)-2]] = true
				return ""
			})
			if strings.Contains(rest, "{{") || strings.Contains(rest, "}}") {
				return bad("step %d: a variable is written {{name}}", i+1)
			}
		}
	}
	for dev, vars := range c.Vars {
		if !devices[dev] {
			return bad("variables of a device not in the changeset")
		}
		if len(vars) > maxVars {
			return bad("at most %d variables per device", maxVars)
		}
		for k, v := range vars {
			if !varName.MatchString(k) || len(v) > maxVarValue || !printableASCII(v) || strings.Contains(v, "{{") || strings.Contains(v, "}}") {
				return bad("variable %q of device %d: a name ^[a-z][a-z0-9_]{0,31}$ and at most %d printable ASCII bytes", k, dev, maxVarValue)
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(used)) {
		for _, dev := range c.Devices {
			if _, ok := c.Vars[dev][name]; !ok {
				return bad("variable %q is not set for device %d", name, dev)
			}
		}
	}
	return nil
}

/* Rendered is one line of a device's plan and the step (1-based) it comes from. */
type Rendered struct {
	Step int
	Line string
}

/*
Render is the lines of a lines changeset for one device, typed from the
privileged prompt: its variables replaced (Check has made sure every one is
set), its forms rendered by the device's driver.
*/
func (c Content) Render(dev int64, drv drivers.WriteDriver) ([]Rendered, error) {
	var out []Rendered
	vars := c.Vars[dev]
	for i, s := range c.Steps {
		if s.Form != nil {
			lines, err := forms.Render(drv, *s.Form)
			if err != nil {
				return nil, fmt.Errorf("step %d: %w", i+1, err)
			}
			for _, l := range lines {
				out = append(out, Rendered{Step: i + 1, Line: l})
			}
			continue
		}
		missing := false
		l := placeholder.ReplaceAllStringFunc(s.Line, func(m string) string {
			v, ok := vars[m[2:len(m)-2]]
			missing = missing || !ok
			return v
		})
		if missing {
			return nil, fmt.Errorf("step %d: %w: a variable is not set", i+1, ErrContent)
		}
		out = append(out, Rendered{Step: i + 1, Line: l})
	}
	return out, nil
}

/*
The canonical encoding (what exec.changeset_revision.content holds): the
domain label, then every field in a fixed order, strings and byte strings
preceded by their length (uint32 big-endian), integers as int64, counts as
uint32, maps in increasing key order. decode is its strict inverse, so one
content has exactly one encoding.
*/
const contentDomain = "nms/changeset-content/v1"

type enc struct{ b []byte }

func (e *enc) str(s string) {
	e.b = binary.BigEndian.AppendUint32(e.b, uint32(len(s))) // #nosec G115 -- bounded by Check / the decoder
	e.b = append(e.b, s...)
}
func (e *enc) n(v int) { e.b = binary.BigEndian.AppendUint32(e.b, uint32(v)) } // #nosec G115 -- counts and small values
func (e *enc) i64(v int64) {
	e.b = binary.BigEndian.AppendUint64(e.b, uint64(v)) // #nosec G115 -- encoding only
}

/* Canonical is the content's canonical encoding. */
func (c Content) Canonical() []byte {
	e := &enc{}
	e.str(contentDomain)
	e.str(c.Title)
	e.n(len(c.Devices))
	for _, d := range c.Devices {
		e.i64(d)
	}
	e.n(len(c.Steps))
	for _, s := range c.Steps {
		if s.Form == nil {
			e.str("L")
			e.str(s.Line)
			continue
		}
		f := s.Form
		e.str("F")
		e.str(f.Kind)
		e.str(f.Interface)
		e.str(f.Description)
		up := int64(0)
		if f.Up {
			up = 1
		}
		e.i64(up)
		e.i64(int64(f.VLAN))
		e.str(f.Name)
	}
	devs := slices.Sorted(maps.Keys(c.Vars))
	e.n(len(devs))
	for _, d := range devs {
		e.i64(d)
		names := slices.Sorted(maps.Keys(c.Vars[d]))
		e.n(len(names))
		for _, k := range names {
			e.str(k)
			e.str(c.Vars[d][k])
		}
	}
	e.i64(int64(c.BatchSize))
	e.i64(int64(c.SettleS))
	e.n(len(c.Restore))
	for _, r := range c.Restore {
		e.i64(r.Device)
		e.i64(r.Version)
	}
	return e.b
}

type dec struct {
	b   []byte
	bad bool
}

func (d *dec) u32() uint32 {
	if len(d.b) < 4 {
		d.bad = true
		return 0
	}
	v := binary.BigEndian.Uint32(d.b)
	d.b = d.b[4:]
	return v
}

func (d *dec) str() string {
	n := d.u32()
	if d.bad || uint64(n) > uint64(len(d.b)) {
		d.bad = true
		return ""
	}
	s := string(d.b[:n])
	d.b = d.b[n:]
	return s
}

func (d *dec) i64() int64 {
	if len(d.b) < 8 {
		d.bad = true
		return 0
	}
	v := int64(binary.BigEndian.Uint64(d.b)) // #nosec G115 -- decoding only
	d.b = d.b[8:]
	return v
}

/* count reads a count of at most limit items. */
func (d *dec) count(limit int) int {
	n := d.u32()
	if d.bad || n > uint32(limit) { // #nosec G115 -- limit is a small constant
		d.bad = true
		return 0
	}
	return int(n)
}

/* decodeContent is the strict inverse of Canonical: anything that Canonical would not write is refused. */
func decodeContent(b []byte) (Content, error) {
	fail := errors.New("changeset: not a canonical content")
	if len(b) > MaxContent {
		return Content{}, fail
	}
	d := &dec{b: b}
	var c Content
	if d.str() != contentDomain {
		return Content{}, fail
	}
	c.Title = d.str()
	for range d.count(execpolicy.MaxChangesetDevices) {
		c.Devices = append(c.Devices, d.i64())
	}
	for range d.count(execpolicy.MaxChangesetLines) {
		switch d.str() {
		case "L":
			c.Steps = append(c.Steps, Step{Line: d.str()})
		case "F":
			f := forms.Params{Kind: d.str(), Interface: d.str(), Description: d.str()}
			up, vlan := d.i64(), d.i64()
			if up != 0 && up != 1 || vlan < 0 || vlan > 4094 {
				d.bad = true
			}
			f.Up, f.VLAN, f.Name = up == 1, int(vlan), d.str()
			c.Steps = append(c.Steps, Step{Form: &f})
		default:
			d.bad = true
		}
		if d.bad {
			return Content{}, fail
		}
	}
	for range d.count(execpolicy.MaxChangesetDevices) {
		dev := d.i64()
		if c.Vars == nil {
			c.Vars = map[int64]map[string]string{}
		}
		vars := map[string]string{}
		for range d.count(maxVars) {
			k := d.str()
			vars[k] = d.str()
		}
		if d.bad {
			return Content{}, fail
		}
		c.Vars[dev] = vars
	}
	c.BatchSize, c.SettleS = int(d.i64()), int(d.i64())
	for range d.count(execpolicy.MaxChangesetDevices) {
		c.Restore = append(c.Restore, RestoreItem{Device: d.i64(), Version: d.i64()})
	}
	if d.bad || len(d.b) != 0 || string(c.Canonical()) != string(b) {
		return Content{}, fail /* the last check refuses unsorted or repeated keys and out-of-range numbers */
	}
	return c, nil
}
