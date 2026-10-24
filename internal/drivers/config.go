package drivers

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/beekamai/network-scheme/internal/drivers/showspec"
	"github.com/beekamai/network-scheme/internal/ssh"
)

/* MaxConfigSize is the largest accepted configuration, in bytes. */
const MaxConfigSize = 4 << 20

/* FetchTimeout bounds one configuration read. */
const FetchTimeout = 2 * time.Minute

var (
	/* ErrNotSupported means the driver cannot read a configuration over the read-only profile. */
	ErrNotSupported = errors.New("drivers: operation not supported")
	/* ErrConfigTooLarge means the configuration exceeds MaxConfigSize. */
	ErrConfigTooLarge = errors.New("drivers: configuration too large")
	/* ErrConfigGarbage means the output is binary or contains an embedded prompt. */
	ErrConfigGarbage = errors.New("drivers: configuration output is not text")
	/* ErrConfigRejected means the device answered with an error instead of a configuration. */
	ErrConfigRejected = errors.New("drivers: device rejected the configuration command")
	/* ErrUnknownShow means the key or arguments do not match a driver show command. */
	ErrUnknownShow = errors.New("drivers: unknown show command")
)

var configModePrompt = regexp.MustCompile(`^[\w.-]+\([\w\s.:/-]*\)# ?$`)

/*
FetchRunning runs cmd (which must be in the driver's allowlist; the runner
enforces the exact match) and returns the sanitised configuration text. It
fails on oversize output, binary garbage, a prompt in the middle of the
output and device error replies, never returning partial text.
*/
func FetchRunning(ctx context.Context, sh ShowRunner, d ssh.Dialect, cmd ssh.ShowCommand) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, FetchTimeout)
	defer cancel()
	out, err := sh.Run(ctx, cmd)
	if err != nil {
		if errors.Is(err, ssh.ErrOutputTooLarge) {
			return "", fmt.Errorf("%w: %w", ErrConfigTooLarge, err)
		}
		return "", err
	}
	if len(out) > MaxConfigSize {
		return "", ErrConfigTooLarge
	}
	if strings.IndexByte(out, 0) >= 0 {
		return "", fmt.Errorf("%w: NUL byte", ErrConfigGarbage)
	}
	text, dropped := sanitize(out)
	if dropped > max(16, len(out)/100) {
		return "", fmt.Errorf("%w: %d invalid bytes", ErrConfigGarbage, dropped)
	}
	first := ""
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimRight(l, " \t\r")
		if l == "" {
			continue
		}
		if configModePrompt.MatchString(l) || (d.ExecPrompt != nil && d.ExecPrompt.MatchString(l)) {
			return "", fmt.Errorf("%w: prompt inside output", ErrConfigGarbage)
		}
		if first == "" {
			first = strings.TrimSpace(l)
		}
	}
	if first == "" || strings.HasPrefix(first, "%") {
		return "", ErrConfigRejected
	}
	return text, nil
}

/* sanitize replaces invalid UTF-8 and removes C0 controls except tab, newline and carriage return (and DEL). */
func sanitize(s string) (string, int) {
	dropped := 0
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			b.WriteRune(utf8.RuneError)
			dropped++
		case r == '\t' || r == '\n' || r == '\r' || (r >= 0x20 && r != 0x7f):
			b.WriteRune(r)
		default:
			dropped++
		}
		i += size
	}
	return b.String(), dropped
}

/* volatileRe matches lines that change without a configuration change. */
var volatileRe = regexp.MustCompile(`(?i)^\s*(` +
	`[!#]\s*(last (configuration|config|change)|nvram config|running.config last|startup.config last|time ?stamp|generated|saved|configuration last)\b.*` +
	`|[!#]?\s*building configuration.*` +
	`|[!#]?\s*current configuration\s*:.*` +
	`|[!#]?\s*(system )?uptime\b.*` +
	`|[!#]\s*clock\b.*` +
	`|ntp clock-period\b.*` +
	`|[!#]?\s*(mon|tue|wed|thu|fri|sat|sun)[a-z]*,?\s+(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s+\d{1,2}\s+.*` +
	`|[!#]?\s*\d{4}-\d{2}-\d{2}[ t]\d{2}:\d{2}.*` +
	`|[!#]?\s*\d{2}:\d{2}:\d{2}.*)$`)

/*
NormalizeText converts CRLF to LF, drops volatile lines (timestamps, last-change
notes, uptime, "building configuration"), trims trailing whitespace and
surrounding blank lines, and ends the text with one newline. Idempotent.
*/
func NormalizeText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	var out []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimRight(l, " \t")
		if volatileRe.MatchString(l) {
			continue
		}
		out = append(out, l)
	}
	t := strings.Trim(strings.Join(out, "\n"), "\n")
	if t == "" {
		return ""
	}
	return t + "\n"
}

/* Section is a named part of a configuration; Name is a stable key the UI translates. */
type Section struct {
	Name  string
	Lines []string
}

/* Section keys, in display order. */
const (
	SectionGeneral    = "general"
	SectionInterfaces = "interfaces"
	SectionVLAN       = "vlan"
	SectionRouting    = "routing"
	SectionSNMP       = "snmp"
	SectionSyslog     = "syslog"
	SectionAAA        = "aaa"
	SectionOther      = "other"
)

var sectionOrder = []string{SectionGeneral, SectionInterfaces, SectionVLAN, SectionRouting, SectionSNMP, SectionSyslog, SectionAAA, SectionOther}

/* sectionPrefixes are checked in order against the lower-cased top-level line. */
var sectionPrefixes = []struct {
	section  string
	prefixes []string
}{
	{SectionInterfaces, []string{"interface", "port-channel"}},
	{SectionVLAN, []string{"vlan", "bridge"}},
	{SectionRouting, []string{"ip route", "ipv6 route", "router", "route-map", "ip prefix", "ipv6 prefix", "ip routing", "ip default-gateway", "ip vrf", "vrf", "route", "ip policy"}},
	{SectionSNMP, []string{"snmp"}},
	{SectionSyslog, []string{"logging", "syslog"}},
	{SectionAAA, []string{"aaa", "radius", "tacacs", "username", "enable", "privilege"}},
	{SectionGeneral, []string{"hostname", "clock", "ntp", "sntp", "ip domain", "ip name-server", "banner", "service", "system", "version", "config-file-header", "boot"}},
}

/* classify matches a prefix that is not followed by a letter, so "ip route" does not match "ip routing". */
func classify(line string) string {
	l := strings.ToLower(line)
	for _, s := range sectionPrefixes {
		for _, p := range s.prefixes {
			if !strings.HasPrefix(l, p) {
				continue
			}
			if len(l) == len(p) || l[len(p)] < 'a' || l[len(p)] > 'z' {
				return s.section
			}
		}
	}
	return SectionOther
}

/*
SplitSections groups configuration lines by their top-level command. An
unindented line starts a block that continues over indented lines and the
closing "exit"/"end"/comment lines; lines before the first command are general.
Every non-empty input line lands in exactly one section; empty sections are
omitted.
*/
func SplitSections(text string) []Section {
	by := map[string][]string{}
	cur := SectionGeneral
	for _, l := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		t := strings.TrimSpace(l)
		if t == "" {
			continue
		}
		top := l[0] != ' ' && l[0] != '\t'
		if top && t != "exit" && t != "end" && t[0] != '!' && t[0] != '#' {
			cur = classify(t)
		}
		by[cur] = append(by[cur], l)
	}
	var out []Section
	for _, name := range sectionOrder {
		if len(by[name]) > 0 {
			out = append(out, Section{Name: name, Lines: by[name]})
		}
	}
	return out
}

/* ShowDef binds a show spec to the exact command text of a dialect. */
type ShowDef struct {
	Spec showspec.Spec
	Name string
}

/* Allowlist returns the allowlist entries (with argument placeholders) for defs. */
func Allowlist(defs []ShowDef) []ssh.ShowCommand {
	out := make([]ssh.ShowCommand, 0, len(defs))
	for _, d := range defs {
		c := ssh.ShowCommand{Name: d.Name}
		for _, k := range d.Spec.Args {
			if k == showspec.VLANID {
				c.Args = append(c.Args, ssh.AnyVLANID)
			} else {
				c.Args = append(c.Args, ssh.AnyIfName)
			}
		}
		out = append(out, c)
	}
	return out
}

/* Specs returns the specs of defs. */
func Specs(defs []ShowDef) []showspec.Spec {
	out := make([]showspec.Spec, len(defs))
	for i, d := range defs {
		out[i] = d.Spec
	}
	return out
}

/* ResolveShow builds the typed command for key and string args; the arguments are validated by their kinds. */
func ResolveShow(defs []ShowDef, key string, args []string) (ssh.ShowCommand, error) {
	for _, d := range defs {
		if d.Spec.Key != key {
			continue
		}
		if len(args) != len(d.Spec.Args) {
			return ssh.ShowCommand{}, ErrUnknownShow
		}
		c := ssh.ShowCommand{Name: d.Name}
		for i, k := range d.Spec.Args {
			var (
				a   ssh.Arg
				err error
			)
			if k == showspec.VLANID {
				n, convErr := strconv.Atoi(args[i]) //nolint:gosec // len(args) == len(d.Spec.Args) checked above
				if convErr != nil {
					return ssh.ShowCommand{}, ErrUnknownShow
				}
				a, err = ssh.VLANID(n)
			} else {
				a, err = ssh.IfName(args[i]) //nolint:gosec // len(args) == len(d.Spec.Args) checked above
			}
			if err != nil {
				return ssh.ShowCommand{}, fmt.Errorf("%w: %w", ErrUnknownShow, err)
			}
			c.Args = append(c.Args, a)
		}
		return c, nil
	}
	return ssh.ShowCommand{}, ErrUnknownShow
}
