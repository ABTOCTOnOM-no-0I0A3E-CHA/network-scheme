/*
Package core is the line-independent half of the executor's write drivers
(security.md 5.3, architecture.md 5): a command tree per CLI mode, Normalize,
Classify and Complete. The drivers mes6, mes10 and esr supply a Spec (their
grammar and argument types); everything a session sends to a device is the
normalized line of a Verdict that is Safe or Dangerous.

Rules every grammar gets for free:
  - A line with a control or format character (C0, C1, DEL, NUL, bidi and
    other format characters, line separators, non-ASCII spaces, invalid UTF-8),
    a '?' (the device's help key, it would edit the line on the device), a tab
    inside quotes or an unterminated quote is refused whole. A tab outside
    quotes is a space.
  - A token is pure when it is printable ASCII without ';', '|' or '\' and
    without quotes, or one quoted string ("..." or '...') of such characters
    and spaces. A line with an impure token is refused, unless the token is a
    keyword of the grammar (the pipe "|") or an argument of a type with Text
    set (off by default). So "hostname a;reload", "hostname it's" or a
    Cyrillic hostname never reach a device.
  - `do` followed by another `do` (abbreviated or quoted) is refused.
  - Keywords match case-insensitively (ASCII only) by exact word or unique
    prefix and are sent spelled out; arguments are kept as typed. A prefix of
    two keywords, or of a keyword while an argument also fits, is ambiguous.
  - An unknown, ambiguous or incomplete line is dangerous in every mode (the
    device's own abbreviation rules may differ from the grammar), and so is
    any line in a mode the grammar does not know.
  - `do` in a mode whose ModeSpec has Do runs the rest in the root mode; a
    `do` of a command that enters or leaves a mode is dangerous and makes the
    session unsure of its mode.
  - Any line but navigation and `do` inside the management interface or VLAN
    (Context.Mgmt, from the registry address at session start) is dangerous,
    and so is a configuration line naming a management target, unless it
    only enters that target's mode.
  - Session-control commands (commit, confirm, restore, write and copy
    running-config startup-config, reload cancel) are Control: the session
    turns them into UI flows and never sends them. A dangerous or unparsed
    line that could be one of them as the device reads it (prefixes, quotes,
    extra words: "wr mem", "copy run start", "commit 600") is Denied with
    ReasonControl ("use the Save/Commit button").
  - Denied comes only from the policy (Rules). A policy override never makes
    a line less strict than the grammar: the class is the stricter of the two.
    Control stands above Denied: the Save and Commit flows are mandatory
    (security.md 5.3), so a policy cannot turn them into anything else.
*/
package core

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

/* Limits: line length (bytes), tokens per line, Complete results, targets one argument may name. */
const (
	MaxLine     = 2048
	MaxTokens   = 256
	MaxComplete = 64
	MaxTargets  = 4096
)

/* Errors of Normalize: the line is refused whole. */
var (
	ErrControlChar = errors.New("core: control or format character in the line")
	ErrHelpChar    = errors.New("core: '?' in the line")
	ErrTooLong     = errors.New("core: line too long")
	ErrQuote       = errors.New("core: unterminated quote or a tab inside quotes")
	ErrImpure      = errors.New("core: ';', '|', '\\', a quote or a non-ASCII character outside a text argument")
	ErrNestedDo    = errors.New("core: do after do")
)

/* Class is what the session does with a line. The zero value is not a class. */
type Class uint8

/* Classes; Safe < Dangerous < Denied < Control in strictness (Control: no policy changes it). */
const (
	_         Class = iota
	Safe            /* sent */
	Dangerous       /* sent after the device name and a fresh TOTP bound to the line */
	Denied          /* never sent */
	Control         /* session control: a UI flow, never sent as typed */
)

func (c Class) String() string {
	switch c {
	case Safe:
		return "safe"
	case Dangerous:
		return "dangerous"
	case Denied:
		return "denied"
	case Control:
		return "control"
	}
	return "invalid"
}

/* ControlKind names the UI flow of a Control line. */
type ControlKind uint8

/* Control kinds. */
const (
	NoControl    ControlKind = iota
	Commit                   /* ESR: end + commit confirm-timeout <policy> */
	Confirm                  /* ESR: the Save button (irreversible) */
	Restore                  /* ESR: drop an unconfirmed commit */
	Save                     /* MES: write / copy running-config startup-config */
	ReloadCancel             /* cancel the safety-net reload */
)

/* Reason says why a Verdict has its class (for the audit row and the UI). */
type Reason string

/* Reasons. */
const (
	ReasonGrammar    Reason = "grammar"    /* the grammar's class */
	ReasonEmpty      Reason = "empty"      /* nothing to send */
	ReasonRefused    Reason = "refused"    /* forbidden character, impure token, nested do, too long, bad quote */
	ReasonUnknown    Reason = "unknown"    /* a word the grammar does not know */
	ReasonAmbiguous  Reason = "ambiguous"  /* a prefix of several words */
	ReasonIncomplete Reason = "incomplete" /* the line stops before a command */
	ReasonMode       Reason = "mode"       /* a mode the grammar does not know */
	ReasonDoMode     Reason = "do-mode"    /* do of a command that enters or leaves a mode */
	ReasonUnsure     Reason = "unsure"     /* the session lost track of the context (Mode.Unsure) */
	ReasonMgmt       Reason = "mgmt"       /* the management interface or VLAN */
	ReasonControl    Reason = "control"    /* may be a session-control command: use the Save/Commit button */
	ReasonPolicy     Reason = "policy"     /* a policy override */
)

/* Verdict is the classification of one line. Line is what to send (empty when refused). */
type Verdict struct {
	Class   Class
	Control ControlKind
	Line    string
	Reason  Reason
	Err     error /* why a refused line is refused */
}

/* checkLine refuses a line with a forbidden character or over MaxLine bytes. */
func checkLine(s string) error {
	if len(s) > MaxLine {
		return ErrTooLong
	}
	if !utf8.ValidString(s) {
		return ErrControlChar
	}
	for _, r := range s {
		switch {
		case r == 0x09:
		case r == '?':
			return ErrHelpChar
		case r < 0x20 || r == 0x7f:
			return ErrControlChar
		case r < 0x7f:
		case r <= 0x9f, unicode.Is(unicode.Cf, r), unicode.In(r, unicode.Zs, unicode.Zl, unicode.Zp), !unicode.IsGraphic(r):
			return ErrControlChar
		}
	}
	return nil
}

func isSpace(c byte) bool { return c == ' ' || c == 0x09 }

/*
tokenize splits a checked line at spaces and tabs. A token that starts with a
quote runs to the matching quote (a backslash escapes inside double quotes)
and on to the next space; a tab inside it or a missing closing quote refuses
the line.
*/
func tokenize(s string) ([]string, error) {
	var toks []string
	for i := 0; ; {
		for i < len(s) && isSpace(s[i]) {
			i++
		}
		if i == len(s) {
			return toks, nil
		}
		j := i
		if q := s[i]; q == '"' || q == '\'' {
			for j++; j < len(s) && s[j] != q; j++ {
				if s[j] == 0x09 {
					return nil, ErrQuote
				}
				if q == '"' && s[j] == '\\' {
					j++
				}
			}
			if j >= len(s) {
				return nil, ErrQuote
			}
			j++
		}
		for j < len(s) && !isSpace(s[j]) {
			j++
		}
		if toks = append(toks, s[i:j]); len(toks) > MaxTokens {
			return nil, ErrTooLong
		}
		i = j
	}
}

/* pure reports whether a token may reach a device outside a Text argument (see the package doc). */
func pure(tok string) bool {
	inner, quoted := tok, false
	if q := tok[0]; q == '"' || q == '\'' {
		if len(tok) < 2 || tok[len(tok)-1] != q {
			return false
		}
		inner, quoted = tok[1:len(tok)-1], true
	}
	for i := 0; i < len(inner); i++ {
		switch c := inner[i]; {
		case c == ' ' && quoted:
		case c <= ' ' || c >= 0x7f, c == ';', c == '|', c == '\\', c == '"', c == '\'':
			return false
		}
	}
	return true
}

/* doLike reports whether a token may be `do` as a device reads it: a prefix, any case, quoted or not. */
func doLike(tok string) bool {
	t := unquote(asciiLower(tok))
	return t != "" && strings.HasPrefix("do", t)
}

/* unquote strips surrounding quotes, the way a device may read a quoted keyword. */
func unquote(s string) string { return strings.Trim(s, `"'`) }

/* asciiLower folds A-Z only: Unicode folding would turn, say, the Kelvin sign into a k. */
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
