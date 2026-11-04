/*
Package strategy holds every assumption the executor makes about a device's
CLI as a switchable strategy (.superpowers/research/eltex-cli.md [R] §9):
defaults per firmware line, each field tagged with the research section it
comes from (research:"§N.M"). A model profile verified on a stand
(registry table model_profile, nmsctl executor model-verify --strategy k=v) overrides
the switchable fields by key; an unknown key or variant fails closed.
*/
package strategy

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
)

/* Line is a firmware line, the unit of a write driver (registry table write_device.write_driver). */
type Line string

/* The firmware lines [R §0]. */
const (
	ESR   Line = "esr"
	MES6  Line = "mes6"
	MES10 Line = "mes10"
)

/* Lines lists every firmware line. */
func Lines() []Line { return []Line{ESR, MES6, MES10} }

/* Valid reports whether l is a known firmware line. */
func (l Line) Valid() bool { return slices.Contains(Lines(), l) }

/*
Answer is one entry of the confirmation table: a question the device asks
after a system command the executor itself sends (save, snapshot, reload
timer) is answered automatically only when both patterns match. A question
after any other line is never answered by the transport.
*/
type Answer struct {
	Command  *regexp.Regexp /* the whole command line */
	Question *regexp.Regexp /* the question line */
	Reply    string
}

/*
Set is the strategies of one connection. String fields with a key tag are
switchable: their variants are listed in the variants tag, default of the
research first; a model profile may override them by key. The remaining
fields are the line's patterns and constants (not overridable). Every field
names its research section.
*/
type Set struct {
	/* SSH authentication: password (a key credential: its key), the password through keyboard-interactive, or a key only. */
	Auth string `key:"auth" variants:"password,keyboard-interactive,publickey" research:"§9.9, §4"`
	/* In-band login: answer User Name:/Password: inside the channel once (auto) or refuse (off). */
	InbandLogin string `key:"inband_login" variants:"auto,off" research:"§9.9, §4"`
	/* Key exchanges: the x/crypto secure set, or without curve25519 (and the X25519 hybrid) for ESR. */
	KEX string `key:"kex" variants:"modern,no-curve25519" research:"§9.10, §4"`
	/* Terminal setup after the model gate: pager off (and machine mode on ESR), or nothing. */
	Terminal string `key:"terminal" variants:"datadump-machine,datadump,set-cli-pagination-off,none" research:"§9.6, §5"`
	/* A pager prompt that still shows up: press the line's key (answer) or fail. */
	Pager string `key:"pager" variants:"answer,fail" research:"§9.6, §5"`
	/* Confirmations: switch them off for the session and answer system commands by the table, or only the table. */
	Confirmations string `key:"confirmations" variants:"off,table" research:"§9.5, §5"`
	/* Error detection: the line's markers, or strict (any output to a configuration line is an error). */
	Errors string `key:"errors" variants:"markers,strict" research:"§9.7, §5"`
	/* Async syslog lines in the session: filtered out of command output (filter) or kept (keep). */
	Async string `key:"async" variants:"filter,keep" research:"§9.12, §5"`
	/* PTY: width 511 and joining lines the device wrapped at that width, or no joining. */
	PTY string `key:"pty" variants:"wide-join,wide" research:"§9.13, §5"`
	/* ESR shared candidate: refuse unless this is the only session and the candidate is empty (exclusive), or trust. MES: unused. */
	Concurrency string `key:"concurrency" variants:"exclusive,trust" research:"§9.11, §8"`

	/* Width is the PTY width requested. */
	Width int `research:"§9.13, §5"`
	/* Prompt matches a whole CLI prompt line: host, optional (mode), then # or >. */
	Prompt *regexp.Regexp `research:"§5"`
	/* Question matches a whole confirmation question line. */
	Question *regexp.Regexp `research:"§9.5, §5"`
	/* PagerPrompt matches the whole pager prompt line (trailing blanks removed). */
	PagerPrompt *regexp.Regexp `research:"§9.6, §5"`
	/* PagerKey is pressed at the pager prompt. */
	PagerKey string `research:"§5"`
	/* ErrorMarkers matches an output line that reports an error. */
	ErrorMarkers *regexp.Regexp `research:"§9.7, §5"`
	/* Syslog matches an async log line. */
	Syslog *regexp.Regexp `research:"§9.12, §5"`
	/* Expired matches a line of the forced password change: the executor stops and sends nothing. */
	Expired *regexp.Regexp `research:"§9.9, §4"`
	/* LoginUser and LoginPassword match the in-band login prompts. */
	LoginUser     *regexp.Regexp `research:"§4"`
	LoginPassword *regexp.Regexp `research:"§4"`
	/* TerminalCommands are the commands of each Terminal variant. */
	TerminalCommands map[string][]string `research:"§9.6, §5"`
	/* ConfirmOff is the session command that switches confirmations off (none documented for ESR). */
	ConfirmOff []string `research:"§9.5, §5"`
	/* Answers is the confirmation table, for system commands only. */
	Answers []Answer `research:"§9.5, §5"`
	/* UsersRow matches one session row of "show users" (ESR exclusive). */
	UsersRow *regexp.Regexp `research:"§9.11, §8"`
}

/* Patterns shared by the lines; every one is a guess where [R] says the text is not documented. */
var (
	/* "esr#", "console(config-if)#", "sw1>"; the hostname is at most 64 characters [R §5]. */
	promptRe = regexp.MustCompile(`^(?P<host>[A-Za-z0-9_.-]{1,64})(?:\((?P<ctx>[a-z0-9-]{1,32})\))?(?P<end>[#>]) ?$`)
	/* (y/N):  (Y/N)[N] ?  (y/n) [n]?  [confirm] [R §5]. */
	questionRe = regexp.MustCompile(`(?i)(?:\(y/n\) ?(?:\[[yn]\])? ?[:?]|\[confirm\]) ?$`)
	/* forced password change: CHANGE-EXPIRED-PASSWORD (ESR), passwords aging (MES) [R §4]; texts are guesses. */
	expiredRe  = regexp.MustCompile(`(?i)password (?:has )?expired|change-expired-password|must change (?:your|the) password|^(?:enter )?new password ?:? ?$`)
	loginUser  = regexp.MustCompile(`(?i)^(?:user ?name|login) ?: ?$`)
	loginPass  = regexp.MustCompile(`(?i)^password ?: ?$`)
	usersRowRe = regexp.MustCompile(`^\s*(\*)?\s*[0-9]+\s+\S+`)
)

const width = 511

func base() Set {
	return Set{
		Auth: "password", InbandLogin: "off", KEX: "modern", Pager: "answer", Confirmations: "off",
		Errors: "markers", Async: "filter", PTY: "wide-join", Concurrency: "trust",
		Width: width, Prompt: promptRe, Question: questionRe, Expired: expiredRe,
		LoginUser: loginUser, LoginPassword: loginPass, UsersRow: usersRowRe,
		TerminalCommands: map[string][]string{
			"datadump-machine":       {"terminal datadump", "terminal mode machine"},
			"datadump":               {"terminal datadump"},
			"set-cli-pagination-off": {"set cli pagination off"},
			"none":                   nil,
		},
	}
}

/*
Defaults returns the strategies of line l as the research documents them
(and the guesses it names). It panics on an unknown line: callers check
Line.Valid against the registry first.
*/
func Defaults(l Line) Set {
	s := base()
	switch l {
	case ESR:
		s.KEX, s.Terminal, s.Concurrency, s.PagerKey = "no-curve25519", "datadump-machine", "exclusive", "R"
		s.PagerPrompt = regexp.MustCompile(`^More\? Enter .* R . show the rest\.$`)
		s.ErrorMarkers = regexp.MustCompile(`^(?:%|Error\b|Can't |Nothing to confirm)`)
		s.Syslog = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d [+-]\d\d:\d\d %[A-Z0-9_]+-[A-Z]-`)
	case MES6:
		s.InbandLogin, s.Terminal, s.PagerKey = "auto", "datadump", " "
		s.PagerPrompt = regexp.MustCompile(`^More: <space>, +Quit: q or CTRL\+Z, One line: <return>$`)
		s.ErrorMarkers = regexp.MustCompile(`^%`)
		s.Syslog = regexp.MustCompile(`^\d{2}-\w{3}-\d{4} \d\d:\d\d:\d\d %[A-Z0-9_]+-[A-Z]-`)
		s.ConfirmOff = []string{"terminal no prompt"}
		s.Answers = []Answer{
			{regexp.MustCompile(`^(?:write|copy running-config startup-config)$`), regexp.MustCompile(`^Overwrite file \[startup-config\].*\(Y/N\)\[N\] \?$`), "Y"},
			{regexp.MustCompile(`^reload in [0-9]{1,3}(?::[0-9]{2})?$`), regexp.MustCompile(`\(y/n\) \[n\]\?$`), "y"},
		}
	case MES10:
		s.Terminal, s.PagerKey = "set-cli-pagination-off", " "
		s.PagerPrompt = regexp.MustCompile(`^--More--$`)
		s.ErrorMarkers = regexp.MustCompile(`^%`)
		s.Syslog = regexp.MustCompile(`^[A-Z][a-z]{2} +\d+ \d\d:\d\d:\d\d \d{4}:[A-Z0-9_-]+:`)
		s.ConfirmOff = []string{"set cli prompt off"}
		s.Answers = []Answer{
			{regexp.MustCompile(`^(?:write startup-config|copy running-config flash:nms-pre-[A-Za-z0-9-]{1,64}|replace running-config flash:nms-pre-[A-Za-z0-9-]{1,64})$`), regexp.MustCompile(`(?i)\(y/n\)`), "y"},
		}
	default:
		panic(fmt.Sprintf("strategy: unknown firmware line %q", l))
	}
	return s
}

/* ErrOverride refuses a profile's strategies: unknown key or variant. */
var ErrOverride = errors.New("strategy: bad override")

/* Keys returns the switchable keys and their variants (default of the research first). */
func Keys() map[string][]string {
	out := map[string][]string{}
	t := reflect.TypeFor[Set]()
	for i := range t.NumField() {
		f := t.Field(i)
		if k := f.Tag.Get("key"); k != "" {
			out[k] = strings.Split(f.Tag.Get("variants"), ",")
		}
	}
	return out
}

/*
Override returns s with the switchable fields named in o set to their
values. Every key must be a switchable key and every value one of its
variants, otherwise nothing is applied (ErrOverride).
*/
func (s Set) Override(o map[string]string) (Set, error) {
	keys := Keys()
	names := make([]string, 0, len(o))
	for k := range o {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		vs, ok := keys[k]
		if !ok {
			return s, fmt.Errorf("%w: unknown key %q", ErrOverride, k)
		}
		if !slices.Contains(vs, o[k]) {
			return s, fmt.Errorf("%w: %s=%q (want one of %s)", ErrOverride, k, o[k], strings.Join(vs, ", "))
		}
	}
	v := reflect.ValueOf(&s).Elem()
	for i := range v.NumField() {
		if k := v.Type().Field(i).Tag.Get("key"); k != "" {
			if val, ok := o[k]; ok {
				v.Field(i).SetString(val)
			}
		}
	}
	return s, nil
}

/* PreLogin reports the switchable values that act before the device is identified (auth, in-band login, KEX). */
func (s Set) PreLogin() [3]string { return [3]string{s.Auth, s.InbandLogin, s.KEX} }
