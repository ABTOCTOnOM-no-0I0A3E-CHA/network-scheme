package mes6

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
	"github.com/beekamai/network-scheme/cmd/executor/internal/transport"
)

/* entry is one line the device accepted: the context line it was typed under ("" at the root of config) and its mode. */
type entry struct {
	ctx, line, mode string
}

type session struct {
	*drivers.Core
	d       Driver
	journal []entry
	ctxLine string
	broken  bool /* the journal lost track of the context */
	armed   bool /* reload-in safety net */
}

/*
Open reads the pre-session snapshot and, with the reload-in safety net, arms
"reload in <minutes>" [R §2a]. Every accepted line goes to the journal that
Rollback inverts (Q7).
*/
func (d Driver) Open(ctx context.Context, sh *transport.Shell, o drivers.Options) (drivers.Session, error) {
	return d.open(ctx, sh, o)
}

/* OpenShell opens a session on any drivers.Shell (the in-memory emulator of other packages' tests); the executor opens through Open. */
func (d Driver) OpenShell(ctx context.Context, sh drivers.Shell, o drivers.Options) (drivers.Session, error) {
	s, err := d.open(ctx, sh, o)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (d Driver) open(ctx context.Context, sh drivers.Shell, o drivers.Options) (*session, error) {
	o, err := drivers.Prepare(d.L, d.S, o)
	if err != nil {
		return nil, err
	}
	c, err := drivers.NewCore(ctx, sh, d, d.G, o)
	if err != nil {
		return nil, err
	}
	s := &session{Core: c, d: d}
	c.Sent = s.record
	c.Failed = func(string) { s.broken = true }
	if o.Strategies.SafetyNet == "reload-in" {
		if _, err := s.System(ctx, "reload in "+strconv.Itoa(o.Strategies.ReloadMinutes)); err != nil {
			return nil, err
		}
		s.armed = true
	}
	return s, nil
}

func (s *session) record(line string, before core.Mode) { s.note(line, before, s.Mode()) }

/* note journals a line the device accepted in mode before, which left the session in after. */
func (s *session) note(line string, before, after core.Mode) {
	if before.Unsure() || after.Unsure() {
		s.broken = true
	}
	ctxLine := s.ctxLine
	switch {
	case isContext(line) && after.Name() != "config" && after.Name() != "exec":
		s.ctxLine, ctxLine = line, ""
	case after.Name() == "config" || after.Name() == "exec":
		s.ctxLine = ""
	}
	if before.Name() == "config" {
		ctxLine = ""
	}
	s.journal = append(s.journal, entry{ctx: ctxLine, line: line, mode: before.Name()})
}

func (s *session) Pre() drivers.Config { return s.Core.Pre }

/*
Reversible reports whether lines, typed from the privileged prompt of a
device whose configuration is pre (in context c) and all accepted, would
leave a journal Rollback can invert: ErrNoInverse otherwise. A changeset's
dry-run (Phase 5) refuses a MES 6.x device on it before anything is sent,
since a stopped run must roll back every device it reached.
*/
func (d Driver) Reversible(pre string, lines []string, c core.Context) error {
	s := &session{Core: &drivers.Core{G: d.G, D: d, Opt: drivers.Options{Context: c}}, d: d}
	m := d.G.Root()
	for _, l := range lines {
		before := m
		m = d.G.Next(l, m)
		s.note(l, before, m)
	}
	_, err := s.inverse(parseConfig(pre))
	return err
}

/* Save leaves the configuration and writes the startup configuration: write + Y, or copy [R §2a, §9.4]. */
func (s *session) Save(ctx context.Context) error {
	if err := s.ToRoot(ctx); err != nil {
		return err
	}
	cmd := "write"
	if s.Opt.Strategies.Save == "copy" {
		cmd = "copy running-config startup-config"
	}
	if _, err := s.System(ctx, cmd); err != nil {
		return err
	}
	return s.disarm(ctx)
}

func (s *session) disarm(ctx context.Context) error {
	if !s.armed {
		return nil
	}
	if err := s.ToRoot(ctx); err != nil {
		return err
	}
	if _, err := s.System(ctx, "reload cancel"); err != nil {
		return err
	}
	s.armed = false
	return nil
}

func (*session) Commit(context.Context, time.Duration) error { return drivers.ErrNotApplicable }

/* Close leaves the configuration and cancels the safety net; unsaved changes stay in running, as on any MES. */
func (s *session) Close(ctx context.Context) error {
	if err := s.ToRoot(ctx); err != nil {
		return err
	}
	return s.disarm(ctx)
}

/*
Rollback is the inverse journal (Q7; MES 6.x has no replace without a reload
[R §2a]): every line the session typed maps to a setting whose value is read
back from the pre-session snapshot, in its context. A line without a known
inverse refuses the whole rollback before anything is sent (ErrNoInverse:
restore the backup with boot config + reload). The plan must classify in
the session's context as safe or dangerous; afterwards the hash must match.
*/
func (s *session) Rollback(ctx context.Context, to drivers.Config) error {
	if err := s.CheckTarget(to); err != nil {
		return err
	}
	plan, err := s.inverse(parseConfig(to.Text))
	if err != nil {
		return err
	}
	if err := s.ToRoot(ctx); err != nil {
		return err
	}
	for _, l := range plan {
		if _, err := s.Sh.Send(ctx, l); err != nil {
			_ = s.ToRoot(ctx)
			return s.Fail(ctx, err)
		}
	}
	if err := s.Verify(ctx, to); err != nil {
		return err
	}
	s.journal, s.broken = nil, false
	return nil
}

/* section is a top-level context of a configuration: its line and its lines. */
type section struct {
	line  string
	lines []string
}

/* snapshot is a parsed MES 6.x configuration: top-level lines and contexts closed by "exit". */
type snapshot struct {
	root []string
	ctxs []section
}

func isContext(l string) bool {
	return strings.HasPrefix(l, "interface ") || l == "vlan database" || strings.HasPrefix(l, "line ") ||
		strings.HasPrefix(l, "crypto key pubkey-chain") || strings.HasPrefix(l, "user-key ")
}

func parseConfig(text string) snapshot {
	var s snapshot
	var cur *section
	for _, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		l := strings.Join(strings.Fields(raw), " ")
		switch {
		case cur != nil && l == "exit":
			s.ctxs, cur = append(s.ctxs, *cur), nil
		case cur != nil:
			cur.lines = append(cur.lines, l)
		case isContext(l):
			cur = &section{line: l}
		case l != "" && l != "!":
			s.root = append(s.root, l)
		}
	}
	return s
}

/* key is a context's identity: an interface by its canonical target, anything else by its line. */
func (d Driver) key(line string) string {
	f := strings.Fields(line)
	switch {
	case len(f) == 3 && f[0] == "interface" && f[1] == "vlan":
		if ts, ok := d.G.Targets("vlan", f[2]); ok {
			return "vlan:" + ts[0].Name
		}
	case len(f) == 3 && f[0] == "interface" && f[1] != "range":
		f = []string{f[0], f[1] + f[2]}
		fallthrough
	case len(f) == 2 && f[0] == "interface":
		if ts, ok := d.G.Targets("iface", f[1]); ok && len(ts) == 1 {
			return "if:" + ts[0].Name
		}
	}
	return "line:" + line
}

func (s snapshot) find(d Driver, key string) (section, bool) {
	for _, c := range s.ctxs {
		if d.key(c.line) == key {
			return c, true
		}
	}
	return section{}, false
}

/* settings: a line (without "no") starting with the words maps to the setting of its first n words. */
var settings = map[string][]struct {
	words string
	n     int
}{
	"config": {{"hostname", 1}, {"logging host", 3}, {"sntp server", 3}, {"snmp-server location", 2}, {"snmp-server contact", 2},
		{"snmp-server community", 3}},
	"config-if": {{"description", 1}, {"shutdown", 1}, {"switchport access vlan", 3}, {"name", 1}},
}

func setting(mode, line string) (string, bool) {
	f := strings.Fields(strings.TrimPrefix(line, "no "))
	for _, s := range settings[mode] {
		w := strings.Fields(s.words)
		if len(f) >= s.n && len(f) >= len(w) && slices.Equal(f[:len(w)], w) {
			return strings.Join(f[:s.n], " "), true
		}
	}
	return "", false
}

/* restore is what sets key back as lines has it: the snapshot's lines of the setting, or "no <key>". */
func restore(lines []string, key string) []string {
	var out []string
	for _, l := range lines {
		if l == key || strings.HasPrefix(l, key+" ") {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		out = []string{"no " + key}
	}
	return out
}

/* vlans of the vlan database section ("vlan 10,20-30" lines). */
func vlans(lines []string) map[int]bool {
	set := map[int]bool{}
	for _, l := range lines {
		if rest, ok := strings.CutPrefix(l, "vlan "); ok {
			vs, _ := drivers.ExpandVLANs(rest)
			for _, v := range vs {
				set[v] = true
			}
		}
	}
	return set
}

func vlanLines(cmd string, vs []int) []string {
	var out []string
	for len(vs) > 0 {
		n := min(len(vs), 64)
		ss := make([]string, n)
		for i, v := range vs[:n] {
			ss[i] = strconv.Itoa(v)
		}
		out, vs = append(out, cmd+strings.Join(ss, ",")), vs[n:]
	}
	return out
}

/* inverse builds the rollback plan from the journal and the pre-session configuration, and checks it with the grammar. */
func (s *session) inverse(pre snapshot) ([]string, error) {
	if s.broken {
		return nil, fmt.Errorf("%w: the session lost track of its mode", drivers.ErrNoInverse)
	}
	type group struct {
		key, line string
		lines     []string
	}
	var root []string
	var groups []*group
	seen := map[string]bool{}
	var touched []int
	vdb := false
	grp := func(ctxLine string) *group {
		k := s.d.key(ctxLine)
		for _, g := range groups {
			if g.key == k {
				return g
			}
		}
		g := &group{key: k, line: ctxLine}
		if c, ok := pre.find(s.d, k); ok {
			g.line = c.line
		}
		groups = append(groups, g)
		return g
	}
	for i := len(s.journal) - 1; i >= 0; i-- {
		e := s.journal[i]
		f := strings.Fields(e.line)
		switch {
		case f[0] == "show" || f[0] == "do" && len(f) > 1 && f[1] == "show" || f[0] == "exit" || f[0] == "end" || f[0] == "configure":
		case strings.HasPrefix(e.mode, "config") && isContext(e.line):
			if k := s.d.key(e.line); strings.HasPrefix(k, "vlan:") {
				if _, ok := pre.find(s.d, k); !ok && !seen["drop "+k] {
					seen["drop "+k] = true
					root = append(root, "no "+strings.Join(f, " "))
				}
			} else if strings.HasPrefix(k, "line:") && e.line != "vlan database" {
				return nil, fmt.Errorf("%w: %q", drivers.ErrNoInverse, e.line)
			}
		case e.mode == "config" && f[0] == "no" && len(f) == 4 && f[1] == "interface" && f[2] == "vlan":
			k := s.d.key(strings.TrimPrefix(e.line, "no "))
			if c, ok := pre.find(s.d, k); ok && !seen["make "+k] {
				seen["make "+k] = true
				g := grp(c.line)
				g.lines = append(g.lines, c.lines...)
			}
		case e.mode == "config":
			k, ok := setting("config", e.line)
			if !ok {
				return nil, fmt.Errorf("%w: %q", drivers.ErrNoInverse, e.line)
			}
			if !seen["root "+k] {
				seen["root "+k] = true
				root = append(root, restore(pre.root, k)...)
			}
		case e.mode == "config-if":
			k, ok := setting("config-if", e.line)
			if !ok || e.ctx == "" {
				return nil, fmt.Errorf("%w: %q", drivers.ErrNoInverse, e.line)
			}
			g := grp(e.ctx)
			if seen[g.key+" "+k] {
				continue
			}
			seen[g.key+" "+k] = true
			var lines []string
			if c, ok := pre.find(s.d, g.key); ok {
				lines = c.lines
			}
			g.lines = append(g.lines, restore(lines, k)...)
		case e.mode == "config-vlan" && (f[0] == "vlan" || f[0] == "no" && len(f) == 3 && f[1] == "vlan"):
			vs, ok := drivers.ExpandVLANs(f[len(f)-1])
			if !ok {
				return nil, fmt.Errorf("%w: %q", drivers.ErrNoInverse, e.line)
			}
			touched, vdb = append(touched, vs...), true
		default:
			return nil, fmt.Errorf("%w: %q", drivers.ErrNoInverse, e.line)
		}
	}
	if vdb {
		var have []string
		if c, ok := pre.find(s.d, "line:vlan database"); ok {
			have = c.lines
		}
		in := vlans(have)
		slices.Sort(touched)
		touched = slices.Compact(touched)
		var del []int
		for _, v := range touched {
			if !in[v] {
				del = append(del, v)
			}
		}
		/* the session's new VLANs go, then the snapshot's VLAN lines as printed (adding an existing VLAN changes nothing) */
		groups = append(groups, &group{key: "line:vlan database", line: "vlan database",
			lines: append(vlanLines("no vlan ", del), have...)})
	}
	plan := append([]string{"configure"}, root...)
	for _, g := range groups {
		if len(g.lines) > 0 && !seen["drop "+g.key] {
			plan = append(append(append(plan, g.line), g.lines...), "exit")
		}
	}
	plan = append(plan, "end")
	return plan, s.check(plan)
}

/* check walks the plan through the grammar from the root: every line safe or dangerous, the mode never unsure. */
func (s *session) check(plan []string) error {
	m := s.G.Root()
	for _, l := range plan {
		v := s.G.Classify(l, m, s.Opt.Context)
		if v.Class != core.Safe && v.Class != core.Dangerous || v.Line != l {
			return fmt.Errorf("%w: %q is %s (%s)", drivers.ErrNoInverse, l, v.Class, v.Reason)
		}
		if m = s.G.Next(l, m); m.Unsure() {
			return fmt.Errorf("%w: %q leaves the mode unsure", drivers.ErrNoInverse, l)
		}
	}
	return nil
}
