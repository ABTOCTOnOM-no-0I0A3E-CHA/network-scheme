/*
Package devemu is a stateful emulator of Eltex device CLIs (ESR, MES 6.x,
MES 10.x) for executor tests. A device keeps its configuration as lines with
contexts, tracks modes and prompts, and implements the save/commit semantics of
its firmware line from .superpowers/research/eltex-cli.md [R]. Every string the
device prints comes from a replaceable fixture in test/fixtures/devices/<line>/
(profile.yaml, show/*.txt, config/running.cfg, transcripts/*.txt), so dumps
from real devices replace the documented guesses without code changes.
*/
package devemu

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

/* Text is one profile string and where it comes from. */
type Text struct {
	Text   string `yaml:"text"`
	Source string `yaml:"source"`
}

/* Context is a configuration line that opens a sub-mode. */
type Context struct {
	Match  string `yaml:"match"` /* regular expression on the whole line */
	Mode   string `yaml:"mode"`  /* the {ctx} of the prompt, e.g. "config-if" */
	Source string `yaml:"source"`
	re     *regexp.Regexp
}

/* Pager describes paged output. */
type Pager struct {
	Prompt Text `yaml:"prompt"`
	Lines  int  `yaml:"lines"` /* lines per page */
	Erase  Text `yaml:"erase"` /* printed after a key to clear the pager prompt */
}

/* SSH describes the transport the device offers. */
type SSH struct {
	HostKey           string   `yaml:"host_key"`            /* rsa | ed25519 | ecdsa */
	HostKeyAlgorithms []string `yaml:"host_key_algorithms"` /* restricts the algorithms offered for the host key; empty: all */
	KeyExchanges      []string `yaml:"kex"`                 /* empty: the x/crypto defaults */
	Ciphers           []string `yaml:"ciphers"`             /* empty: the x/crypto defaults */
	Auth              []string `yaml:"auth"`                /* password, keyboard-interactive, publickey */
	Source            string   `yaml:"source"`
}

/* Config describes how the running configuration is printed. */
type Config struct {
	Indent     Text   `yaml:"indent"`      /* one level of indentation */
	Exit       Text   `yaml:"exit"`        /* the line that closes a context */
	ExitIndent string `yaml:"exit_indent"` /* "child": the exit line is indented as the context's lines; "parent": as the context line */
	Comment    Text   `yaml:"comment"`     /* prefixes of top-level comment lines, space separated */
}

/* Profile is a parsed profile.yaml. */
type Profile struct {
	Line     string          `yaml:"line"`  /* semantics: esr | mes6 | mes10 */
	Model    string          `yaml:"model"` /* informational: the model and firmware the fixture describes */
	Source   string          `yaml:"source"`
	Hostname Text            `yaml:"hostname"` /* used while the configuration has no hostname line */
	Banner   Text            `yaml:"banner"`
	Prompts  map[string]Text `yaml:"prompts"` /* exec, privileged, config, context; {host}, {ctx} */
	Contexts []Context       `yaml:"contexts"`
	Config   Config          `yaml:"config"`
	Pager    Pager           `yaml:"pager"`
	Errors   map[string]Text `yaml:"errors"`
	Confirm  map[string]Text `yaml:"confirm"`  /* confirmation questions */
	Messages map[string]Text `yaml:"messages"` /* command results; {timeout}, {file} */
	Login    map[string]Text `yaml:"login"`    /* user, password, failed, expired, new_password */
	Syslog   map[string]Text `yaml:"syslog"`   /* pattern (regexp of an async line), stamp (Go time layout), and messages */
	SSH      SSH             `yaml:"ssh"`
	Defaults map[string]Text `yaml:"defaults"` /* numeric defaults, e.g. confirm_timeout */

	syslogRe *regexp.Regexp
}

/* Fixture is one device directory: profile, show outputs, configuration and transcripts. */
type Fixture struct {
	Dir         string
	Profile     *Profile
	Show        map[string]string /* command line -> output, from show/<command>.txt */
	Running     string            /* config/running.cfg */
	Transcripts []*Transcript
}

/* required keys of each map, per line; a profile without one fails to load. */
var required = map[string]map[string][]string{
	"*": {
		"prompts":  {"exec", "privileged", "config", "context"},
		"errors":   {"unknown", "incomplete"},
		"login":    {"user", "password", "failed", "expired", "new_password"},
		"syslog":   {"pattern", "stamp"},
		"defaults": {},
	},
	"esr": {
		"confirm":  {"reload"},
		"messages": {"commit", "commit_failed", "confirm", "nothing_to_confirm", "restore", "no_backup", "rollback", "save", "copy_done"},
		"defaults": {"confirm_timeout", "confirm_timeout_min", "confirm_timeout_max"},
	},
	"mes6": {
		"confirm":  {"write", "delete", "reload"},
		"messages": {"copy_done"},
		"syslog":   {"copy_start", "copy_done"},
	},
	"mes10": {
		"confirm":  {"reload"},
		"messages": {"copy_done"},
	},
}

/* sourceRe is the provenance every profile entry must carry. */
var sourceRe = regexp.MustCompile(`^(docs \[R §[0-9a-z.]+\]( .*)?|device \S.*|guess( .*)?)$`)

/* FixturesDir is test/fixtures/devices of this repository. */
func FixturesDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "fixtures", "devices")
}

/* LoadLine loads test/fixtures/devices/<name>. */
func LoadLine(name string) (*Fixture, error) { return Load(filepath.Join(FixturesDir(), name)) }

/* Lines lists the fixture directories under test/fixtures/devices. */
func Lines() ([]string, error) {
	es, err := os.ReadDir(FixturesDir())
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range es {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

/* Load reads and validates a fixture directory. */
func Load(dir string) (*Fixture, error) {
	p, err := LoadProfile(filepath.Join(dir, "profile.yaml"))
	if err != nil {
		return nil, err
	}
	fx := &Fixture{Dir: dir, Profile: p, Show: map[string]string{}}
	run, err := os.ReadFile(filepath.Join(dir, "config", "running.cfg")) // #nosec G304 -- test fixture
	if err != nil {
		return nil, err
	}
	fx.Running = normalizeNL(string(run))
	if _, err := parseConfig(p, fx.Running); err != nil {
		return nil, fmt.Errorf("%s: config/running.cfg: %w", dir, err)
	}
	shows, _ := filepath.Glob(filepath.Join(dir, "show", "*.txt"))
	for _, f := range shows {
		b, err := os.ReadFile(f) // #nosec G304 -- test fixture
		if err != nil {
			return nil, err
		}
		fx.Show[strings.TrimSuffix(filepath.Base(f), ".txt")] = strings.TrimRight(normalizeNL(string(b)), "\n")
	}
	trs, _ := filepath.Glob(filepath.Join(dir, "transcripts", "*.txt"))
	sort.Strings(trs)
	for _, f := range trs {
		b, err := os.ReadFile(f) // #nosec G304 -- test fixture
		if err != nil {
			return nil, err
		}
		t, err := ParseTranscript(p, filepath.Base(f), string(b))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		fx.Transcripts = append(fx.Transcripts, t)
	}
	return fx, nil
}

/* LoadProfile reads and validates one profile.yaml. */
func LoadProfile(path string) (*Profile, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- test fixture
	if err != nil {
		return nil, err
	}
	var p Profile
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &p, nil
}

func (p *Profile) validate() error {
	if _, ok := required[p.Line]; !ok || p.Line == "*" {
		return fmt.Errorf("line %q: want esr, mes6 or mes10", p.Line)
	}
	var errs []error
	src := func(where, s string) {
		if !sourceRe.MatchString(s) {
			errs = append(errs, fmt.Errorf("%s: source %q: want \"docs [R §…]\", \"device <model/firmware>\" or \"guess …\"", where, s))
		}
	}
	src("line", p.Source)
	src("hostname", p.Hostname.Source)
	src("banner", p.Banner.Source)
	src("ssh", p.SSH.Source)
	src("config.indent", p.Config.Indent.Source)
	src("config.exit", p.Config.Exit.Source)
	src("config.comment", p.Config.Comment.Source)
	src("pager.prompt", p.Pager.Prompt.Source)
	src("pager.erase", p.Pager.Erase.Source)
	maps := map[string]map[string]Text{"prompts": p.Prompts, "errors": p.Errors, "confirm": p.Confirm, "messages": p.Messages, "login": p.Login, "syslog": p.Syslog, "defaults": p.Defaults}
	for name, m := range maps {
		for k, v := range m {
			src(name+"."+k, v.Source)
		}
		for _, line := range []string{"*", p.Line} {
			for _, k := range required[line][name] {
				if _, ok := m[k]; !ok {
					errs = append(errs, fmt.Errorf("%s.%s is required for line %s", name, k, p.Line))
				}
			}
		}
	}
	for k, v := range p.Defaults {
		if _, err := strconv.Atoi(v.Text); err != nil {
			errs = append(errs, fmt.Errorf("defaults.%s: %w", k, err))
		}
	}
	for i := range p.Contexts {
		c := &p.Contexts[i]
		src("contexts["+c.Mode+"]", c.Source)
		re, err := regexp.Compile(c.Match)
		if err != nil || c.Mode == "" {
			errs = append(errs, fmt.Errorf("contexts[%d]: bad match %q or empty mode", i, c.Match))
			continue
		}
		c.re = re
	}
	if p.Hostname.Text == "" || p.Config.Exit.Text == "" || p.Pager.Prompt.Text == "" || p.Pager.Lines < 2 {
		errs = append(errs, errors.New("hostname, config.exit, pager.prompt and pager.lines >= 2 are required"))
	}
	if p.Config.ExitIndent != "child" && p.Config.ExitIndent != "parent" {
		errs = append(errs, fmt.Errorf("config.exit_indent %q: want child or parent", p.Config.ExitIndent))
	}
	switch p.SSH.HostKey {
	case "rsa", "ed25519", "ecdsa":
	default:
		errs = append(errs, fmt.Errorf("ssh.host_key %q: want rsa, ed25519 or ecdsa", p.SSH.HostKey))
	}
	if re, err := regexp.Compile(p.Syslog["pattern"].Text); err == nil {
		p.syslogRe = re
	} else {
		errs = append(errs, fmt.Errorf("syslog.pattern: %w", err))
	}
	return errors.Join(errs...)
}

/* context returns the sub-mode a configuration line opens, or "". */
func (p *Profile) context(line string) string {
	for _, c := range p.Contexts {
		if c.re.MatchString(line) {
			return c.Mode
		}
	}
	return ""
}

/* prompt renders a prompt template. */
func (p *Profile) prompt(key, host, ctx string) string {
	return strings.NewReplacer("{host}", host, "{ctx}", ctx).Replace(p.Prompts[key].Text)
}

/* promptRe matches any prompt of the profile at the start of a line (raw transcripts). */
func (p *Profile) promptRe() *regexp.Regexp {
	var alts []string
	for _, k := range []string{"context", "config", "privileged", "exec"} {
		q := regexp.QuoteMeta(p.Prompts[k].Text)
		q = strings.ReplaceAll(q, `\{host\}`, `[A-Za-z0-9_.-]+`)
		q = strings.ReplaceAll(q, `\{ctx\}`, `[a-z0-9-]+`)
		alts = append(alts, q)
	}
	return regexp.MustCompile(`^(?:` + strings.Join(alts, "|") + `)`)
}

func normalizeNL(s string) string { return strings.ReplaceAll(s, "\r\n", "\n") }
