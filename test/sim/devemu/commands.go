package devemu

import (
	"slices"
	"strconv"
	"strings"
	"time"
)

/*
execOnly are the first words of commands that exist only outside the
configuration modes; typed in a configuration mode they are an unknown
command, not a configuration line (MES "write" there: [R §2b, assumptions]).
*/
var execOnly = map[string][]string{
	"esr":   {"commit", "confirm", "restore", "rollback", "save", "show", "copy", "delete", "reload", "terminal", "configure"},
	"mes6":  {"write", "copy", "show", "reload", "terminal", "delete", "boot", "configure"},
	"mes10": {"write", "copy", "show", "reload", "set", "replace", "clear", "configure"},
}

func (s *Session) err(key string) string {
	if t, ok := s.d.P.Errors[key]; ok {
		return t.Text
	}
	return s.d.P.Errors["incomplete"].Text
}

func (s *Session) msg(key string, kv ...string) string {
	return strings.NewReplacer(kv...).Replace(s.d.P.Messages[key].Text)
}

/* exec runs one command line and returns its output. */
func (s *Session) exec(line string) string {
	t := strings.Join(strings.Fields(line), " ")
	if t == "" {
		return ""
	}
	if m, ok := s.d.rejected(t); ok {
		return m
	}
	if s.config {
		return s.configLine(t)
	}
	return s.command(t)
}

/* command runs an EXEC or privileged EXEC command (also "do <command>" from a configuration mode). */
func (s *Session) command(t string) string {
	switch {
	case t == "exit" || t == "logout" || t == "quit":
		if s.config {
			return s.err("unknown")
		}
		s.close()
		return ""
	case strings.HasPrefix(t, "show "):
		return s.show(t)
	case !s.priv:
		if t == "enable" {
			s.priv = true
			return ""
		}
		if out, ok := s.terminal(t); ok {
			return out
		}
		return s.err("unknown")
	case t == "disable":
		s.priv, s.config, s.ctx = false, false, nil
		return ""
	case t == "configure terminal" || t == "configure" && s.d.P.Line != "mes10":
		s.config, s.ctx = true, nil
		return ""
	}
	if out, ok := s.terminal(t); ok {
		return out
	}
	switch s.d.P.Line {
	case "esr":
		return s.esr(t)
	case "mes6":
		return s.mes6(t)
	}
	return s.mes10(t)
}

/* terminal handles the per-session pager and confirmation switches [R §5]. */
func (s *Session) terminal(t string) (string, bool) {
	sw := map[string]map[string]func(){
		"esr": {
			"terminal datadump": func() { s.datadump = true }, "no terminal datadump": func() { s.datadump = false },
			"terminal mode machine": func() {}, "terminal mode human": func() {},
		},
		"mes6": {
			"terminal datadump": func() { s.datadump = true }, "terminal no datadump": func() { s.datadump = false },
			"terminal no prompt": func() { s.noPrompt = true }, "terminal prompt": func() { s.noPrompt = false },
		},
		"mes10": {
			"set cli pagination off": func() { s.datadump = true }, "set cli pagination on": func() { s.datadump = false },
			"set cli prompt off": func() { s.noPrompt = true }, "set cli prompt on": func() { s.noPrompt = false },
		},
	}[s.d.P.Line]
	f, ok := sw[t]
	if ok {
		f()
	}
	return "", ok
}

/* configLine handles a line typed in a configuration mode. */
func (s *Session) configLine(t string) string {
	switch {
	case t == "end":
		s.config, s.ctx = false, nil
		return ""
	case t == "exit":
		if len(s.ctx) == 0 {
			s.config = false
		} else {
			s.ctx = s.ctx[:len(s.ctx)-1]
		}
		return ""
	case strings.HasPrefix(t, "do "):
		return s.command(strings.TrimPrefix(t, "do "))
	case slices.Contains(execOnly[s.d.P.Line], strings.Fields(t)[0]):
		return s.err("unknown")
	}
	n := s.node()
	if rest, ok := strings.CutPrefix(t, "no "); ok {
		n.remove(rest)
		return ""
	}
	if mode := s.d.P.context(t); mode != "" {
		n.enter(t, mode)
		s.ctx = append(s.ctx, ctxStep{t, mode})
		return ""
	}
	n.set(t)
	return ""
}

/* node returns the current context of the configuration being edited (ESR: candidate; MES: running), creating it. */
func (s *Session) node() *node {
	n := s.d.running
	if s.d.P.Line == "esr" {
		n = s.d.cand
	}
	for _, c := range s.ctx {
		n = n.enter(c.text, c.mode)
	}
	return n
}

func (s *Session) show(t string) string {
	d := s.d
	if d.show != nil {
		if out, ok := d.show(t); ok {
			return out
		}
	}
	switch t {
	case "show running-config":
		return d.P.render(d.running)
	case "show candidate-config":
		if d.P.Line == "esr" {
			return d.P.render(d.cand)
		}
	case "show configuration changes":
		if d.P.Line == "esr" {
			return d.P.diff(d.running, d.cand)
		}
	case "show startup-config":
		if d.P.Line != "esr" {
			return d.P.render(d.saved)
		}
	case "show reload":
		if d.P.Line == "mes10" {
			if d.reload.IsZero() {
				return s.msg("reload_none")
			}
			return s.msg("reload_at", "{time}", d.reload.Format(time.DateTime))
		}
	}
	if out, ok := d.fx.Show[t]; ok {
		return out
	}
	return s.err("unknown")
}

/* load parses a stored file as a configuration. */
func (s *Session) load(name string) (*node, string) {
	switch name {
	case "system:running-config", "running-config":
		return s.d.running.clone(), ""
	case "startup-config":
		if s.d.P.Line != "esr" {
			return s.d.saved.clone(), ""
		}
	case "system:default-config", "system:factory-config":
		return &node{mode: "config"}, ""
	}
	text, ok := s.d.files[name]
	if !ok {
		return nil, s.err("invalid")
	}
	n, err := parseConfig(s.d.P, text)
	if err != nil {
		return nil, s.err("invalid")
	}
	return n, ""
}

/* merge adds every line of src to dst, as typing it in configuration mode does ("copy … running-config" on MES [R §2a]). */
func merge(dst, src *node, p *Profile) {
	for _, c := range src.children {
		switch {
		case c.mode != "":
			merge(dst.enter(c.text, c.mode), c, p)
		case c.text == "" || p.comment(c.text):
		default:
			if rest, ok := strings.CutPrefix(c.text, "no "); ok {
				dst.remove(rest)
			} else {
				dst.set(c.text)
			}
		}
	}
}

/* ESR: candidate configuration, commit with a confirm timer, confirm, restore, rollback [R §1]. */
func (s *Session) esr(t string) string {
	d := s.d
	f := strings.Fields(t)
	switch {
	case f[0] == "commit":
		return s.commit(f[1:])
	case t == "confirm":
		if d.pending.IsZero() {
			return s.msg("nothing_to_confirm")
		}
		d.pending, d.backup = time.Time{}, nil
		return s.msg("confirm")
	case t == "restore":
		if d.pending.IsZero() {
			return s.msg("no_backup")
		}
		d.running, d.saved, d.pending, d.backup = d.backup, d.backup.clone(), time.Time{}, nil
		return s.msg("restore")
	case t == "rollback":
		d.cand = d.running.clone()
		return s.msg("rollback")
	case len(f) == 3 && f[0] == "rollback" && f[1] == "to-backup":
		n, e := s.load("flash:backup/" + f[2])
		if n == nil {
			return e
		}
		d.cand = n
		return s.msg("rollback")
	case t == "save":
		return s.msg("save")
	case len(f) == 3 && f[0] == "copy":
		if f[2] == "system:candidate-config" {
			n, e := s.load(f[1])
			if n == nil {
				return e
			}
			d.cand = n
			return s.msg("copy_done")
		}
		if f[1] == "system:running-config" || f[1] == "system:candidate-config" {
			src := d.running
			if f[1] == "system:candidate-config" {
				src = d.cand
			}
			d.files[f[2]] = d.P.render(src)
			return s.msg("copy_done")
		}
		return s.err("invalid")
	case len(f) == 2 && f[0] == "delete": /* delete <file> [R §6]: no confirmation documented */
		if _, ok := d.files[f[1]]; !ok {
			return s.err("invalid")
		}
		delete(d.files, f[1])
		return ""
	case t == "reload system":
		return s.ask(d.P.Confirm["reload"].Text, false, func() string { d.reboot(); return "" }, nil)
	}
	return s.err("unknown")
}

/* commit [comment <TEXT>] [confirm-timeout <120..86400>] [R §1]. */
func (s *Session) commit(args []string) string {
	d := s.d
	timeout := d.defaultInt("confirm_timeout")
	for _, c := range d.cand.children { /* system config-confirm timeout <TIME> of the configuration being committed [R §1] */
		if v, ok := strings.CutPrefix(c.text, "system config-confirm timeout "); ok && c.mode == "" {
			if n, err := strconv.Atoi(v); err == nil {
				timeout = n
			}
		}
	}
	for i := 0; i < len(args); i += 2 {
		if i+1 >= len(args) {
			return s.err("incomplete")
		}
		switch args[i] {
		case "comment":
			if len(args[i+1]) > 31 {
				return s.err("invalid")
			}
		case "confirm-timeout":
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n < d.defaultInt("confirm_timeout_min") || n > d.defaultInt("confirm_timeout_max") {
				return s.err("invalid")
			}
			timeout = n
		default:
			return s.err("unknown")
		}
	}
	if d.pending.IsZero() {
		d.backup = d.running
	}
	d.running, d.saved = d.cand.clone(), d.cand.clone()
	d.pending = d.now.Add(time.Duration(timeout) * time.Second)
	return s.msg("commit", "{timeout}", strconv.Itoa(timeout))
}

/* MES 6.x: immediate apply, write + (Y/N), reload in, copy … running-config as a merge [R §2a]. */
func (s *Session) mes6(t string) string {
	d := s.d
	f := strings.Fields(t)
	save := func(n func() *node) func() string {
		return func() string {
			d.saved = n()
			d.syslog(d.P.Syslog["copy_start"].Text)
			d.syslog(d.P.Syslog["copy_done"].Text)
			return s.msg("copy_done")
		}
	}
	switch {
	case t == "write" || t == "write memory" || t == "copy running-config startup-config":
		return s.ask(d.P.Confirm["write"].Text, false, save(d.running.clone), nil)
	case len(f) == 3 && f[0] == "boot" && f[1] == "config", len(f) == 3 && f[0] == "copy" && f[2] == "startup-config":
		n, e := s.load(f[len(f)-2])
		if n == nil {
			return e
		}
		return s.ask(d.P.Confirm["write"].Text, false, save(func() *node { return n }), nil)
	case len(f) == 3 && f[0] == "copy":
		return s.copyMES(f[1], f[2])
	case t == "delete startup-config":
		return s.ask(strings.ReplaceAll(d.P.Confirm["delete"].Text, "{file}", "startup-config"), true,
			func() string { d.saved = &node{mode: "config"}; return "" }, nil)
	case len(f) == 2 && f[0] == "delete":
		if _, ok := d.files[f[1]]; !ok {
			return s.err("invalid")
		}
		return s.ask(strings.ReplaceAll(d.P.Confirm["delete"].Text, "{file}", f[1]), true,
			func() string { delete(d.files, f[1]); return "" }, nil)
	case t == "reload":
		return s.ask(d.P.Confirm["reload"].Text, false, func() string { d.reboot(); return "" }, nil)
	case t == "reload cancel":
		d.reload = time.Time{}
		return ""
	case len(f) == 3 && f[0] == "reload" && f[1] == "in": /* minutes 1..999 or hh:mm */
		var dt time.Duration
		if h, m, ok := strings.Cut(f[2], ":"); ok {
			hh, e1 := strconv.Atoi(h)
			mm, e2 := strconv.Atoi(m)
			if e1 != nil || e2 != nil || hh < 0 || mm < 0 || mm > 59 || hh*60+mm < 1 {
				return s.err("invalid")
			}
			dt = time.Duration(hh*60+mm) * time.Minute
		} else if n, err := strconv.Atoi(f[2]); err == nil && n >= 1 && n <= 999 {
			dt = time.Duration(n) * time.Minute
		} else {
			return s.err("invalid")
		}
		return s.ask(d.P.Confirm["reload"].Text, false, func() string { d.reload = d.now.Add(dt); return "" }, nil)
	}
	return s.err("unknown")
}

/* copyMES copies between files and configurations; into running-config it merges [R §2a]. */
func (s *Session) copyMES(src, dst string) string {
	d := s.d
	switch {
	case dst == "running-config":
		n, e := s.load(src)
		if n == nil {
			return e
		}
		merge(d.running, n, d.P)
	case src == "running-config" || src == "startup-config":
		n, _ := s.load(src)
		text := d.P.render(n)
		if d.P.Line == "mes10" && !strings.HasPrefix(text, "!") { /* a 10.x config file starts with "!" [R §2b] */
			text = "!\n" + text
		}
		d.files[dst] = text
	default:
		return s.err("invalid")
	}
	return s.msg("copy_done")
}

/* MES 10.x: configure terminal, write startup-config, replace running-config, reload in <hours> <minutes> [R §2b]. */
func (s *Session) mes10(t string) string {
	d := s.d
	f := strings.Fields(t)
	switch {
	case t == "configure":
		return s.err("incomplete")
	case t == "write startup-config" || t == "copy running-config startup-config":
		d.saved = d.running.clone()
		return s.msg("copy_done")
	case len(f) == 3 && f[0] == "copy" && f[2] == "startup-config":
		n, e := s.load(f[1])
		if n == nil {
			return e
		}
		d.saved = n
		return s.msg("copy_done")
	case len(f) == 3 && f[0] == "copy":
		return s.copyMES(f[1], f[2])
	case len(f) == 3 && f[0] == "replace" && f[1] == "running-config" && strings.HasPrefix(f[2], "flash:"):
		n, e := s.load(f[2])
		if n == nil {
			return e
		}
		d.running = n
		return s.msg("copy_done")
	case t == "clear running-config":
		d.running = &node{mode: "config"}
		return ""
	case t == "reload":
		return s.ask(d.P.Confirm["reload"].Text, false, func() string { d.reboot(); return "" }, nil)
	case t == "reload cancel":
		d.reload = time.Time{}
		return ""
	case len(f) == 4 && f[0] == "reload" && f[1] == "in": /* hours 0..168, minutes */
		h, e1 := strconv.Atoi(f[2])
		m, e2 := strconv.Atoi(f[3])
		if e1 != nil || e2 != nil || h < 0 || h > 168 || m < 0 || m > 59 || h+m == 0 {
			return s.err("invalid")
		}
		dt := time.Duration(h)*time.Hour + time.Duration(m)*time.Minute
		return s.ask(d.P.Confirm["reload"].Text, false, func() string { d.reload = d.now.Add(dt); return "" }, nil)
	}
	return s.err("unknown")
}
