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

const months = `(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*`

var (
	/* alwaysVolatile are whole-line comments the device rewrites on every save, at column 0 anywhere. */
	alwaysVolatile = regexp.MustCompile(`(?i)^(! last configuration change at .*|! nvram config last updated.*|[!#] last change(d)?:? .*|ntp clock-period \d+)$`)
	/* headerVolatile are whole-line banners of the header block only (before the first command). */
	headerVolatile = regexp.MustCompile(`(?i)^(building configuration\.\.\.|current configuration ?: ?\d+ bytes|[!#] ?(system )?uptime( is|:) .*|(system )?uptime( is|:) .*|` +
		`[!#]? ?(mon|tue|wed|thu|fri|sat|sun)[a-z]*,? ` + months + ` \d{1,2} \d\d:\d\d:\d\d.*|[!#]? ?\d{4}-\d\d-\d\d[ t]\d\d:\d\d:\d\d.*)$`)
)

/*
NormalizeText converts CRLF to LF, drops volatile lines, trims trailing
whitespace and surrounding blank lines, and ends the text with one newline.
Volatile lines are whole column-0 lines only: "! Last configuration change",
"! NVRAM config last updated", "ntp clock-period N" anywhere, and in the
header block (before the first command) "Building configuration...", "Current
configuration : N bytes", uptime and date stamps. Indented lines and lines
after the header are never dropped. Idempotent.

The result is for computing the SHA-256 that decides whether a configuration
changed. The stored encrypted full copy and the masked copy are made from the
raw fetched text, never from the normalized one.
*/
func NormalizeText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	var out []string
	header := true
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimRight(l, " \t")
		switch {
		case alwaysVolatile.MatchString(l):
			continue
		case header && headerVolatile.MatchString(l):
			continue
		case header && l != "" && l[0] != '!' && l[0] != '#':
			header = false
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

/*
Allowlist returns the allowlist entries (with argument placeholders) for defs.
With longIf an interface argument is also accepted as "kind number"
("gigabitethernet 1/0/1", ESR style).
*/
func Allowlist(defs []ShowDef, longIf bool) []ssh.ShowCommand {
	out := make([]ssh.ShowCommand, 0, len(defs))
	for _, d := range defs {
		c := ssh.ShowCommand{Name: d.Name}
		hasIf := false
		for _, k := range d.Spec.Args {
			if k == showspec.VLANID {
				c.Args = append(c.Args, ssh.AnyVLANID)
			} else {
				c.Args, hasIf = append(c.Args, ssh.AnyIfName), true
			}
		}
		out = append(out, c)
		if hasIf && longIf {
			long := ssh.ShowCommand{Name: d.Name}
			for _, k := range d.Spec.Args {
				if k == showspec.VLANID {
					long.Args = append(long.Args, ssh.AnyVLANID)
				} else {
					long.Args = append(long.Args, ssh.AnyIfNameLong)
				}
			}
			out = append(out, long)
		}
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

/*
ResolveShow builds the typed command for a ShowCommands key and string args,
validated by their kinds. Only keys of defs resolve, and a definition whose
command text mentions "config" never does (defense in depth: the dialect
allowlist also holds the configuration read, which must never be reachable
from the on-demand path). Interface names must come from the device inventory;
Task 6 enforces that membership before calling this.
*/
func ResolveShow(defs []ShowDef, key string, args []string, longIf bool) (ssh.ShowCommand, error) {
	for _, d := range defs {
		if d.Spec.Key != key {
			continue
		}
		if len(args) != len(d.Spec.Args) || strings.Contains(strings.ToLower(d.Name), "config") {
			return ssh.ShowCommand{}, ErrUnknownShow
		}
		c := ssh.ShowCommand{Name: d.Name}
		for i, k := range d.Spec.Args {
			v := args[i] //nolint:gosec // len(args) == len(d.Spec.Args) checked above
			var (
				a   ssh.Arg
				err error
			)
			switch {
			case k == showspec.VLANID:
				n, convErr := strconv.Atoi(v)
				if convErr != nil {
					return ssh.ShowCommand{}, ErrUnknownShow
				}
				a, err = ssh.VLANID(n)
			case longIf && strings.Contains(v, " "):
				kind, num, _ := strings.Cut(v, " ")
				a, err = ssh.IfNameLong(kind, num)
			default:
				a, err = ssh.IfName(v)
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
