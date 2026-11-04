package strategy

import (
	"errors"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

/*
sections are the parts of the research file .superpowers/research/eltex-cli.md
(not in the repository): "## N." headings 0..9, "### 2a."/"### 2b.", and the
numbered list of §9 (items 1..14). A tag naming anything else fails.
*/
func sectionExists(ref string) bool {
	m := regexp.MustCompile(`^§([0-9])(?:\.([0-9]{1,2})|([ab]))?$`).FindStringSubmatch(ref)
	switch {
	case m == nil:
		return false
	case m[3] != "":
		return m[1] == "2"
	case m[2] != "":
		n := 0
		for _, c := range m[2] {
			n = n*10 + int(c-'0')
		}
		return m[1] == "9" && n >= 1 && n <= 14
	}
	return true
}

/* Every field of Set names a research section, and every switchable field lists its variants. */
func TestEveryStrategyHasResearchRef(t *testing.T) {
	typ := reflect.TypeFor[Set]()
	if typ.NumField() == 0 {
		t.Fatal("no strategy fields")
	}
	for i := range typ.NumField() {
		f := typ.Field(i)
		tag, ok := f.Tag.Lookup("research")
		if !ok || tag == "" {
			t.Errorf("%s: no research tag", f.Name)
			continue
		}
		for _, ref := range strings.Split(tag, ", ") {
			if !sectionExists(ref) {
				t.Errorf("%s: research %q names no section of [R]", f.Name, ref)
			}
		}
		if k := f.Tag.Get("key"); k != "" {
			if f.Type.Kind() != reflect.String || len(strings.Split(f.Tag.Get("variants"), ",")) < 2 {
				t.Errorf("%s (%s): a switchable field is a string with at least two variants", f.Name, k)
			}
		}
	}
}

/* Each line's defaults are variants of their keys and set every pattern. */
func TestDefaultsAreComplete(t *testing.T) {
	keys := Keys()
	for _, l := range Lines() {
		s := Defaults(l)
		v := reflect.ValueOf(s)
		for i := range v.NumField() {
			f := v.Type().Field(i)
			if k := f.Tag.Get("key"); k != "" {
				if !slices.Contains(keys[k], v.Field(i).String()) {
					t.Errorf("%s: %s=%q is not a variant", l, k, v.Field(i).String())
				}
				continue
			}
			switch f.Name {
			case "ConfirmOff", "Answers":
				continue /* ESR documents neither */
			}
			if v.Field(i).IsZero() {
				t.Errorf("%s: %s is not set", l, f.Name)
			}
		}
		for _, variant := range keys["terminal"] {
			if _, ok := s.TerminalCommands[variant]; !ok {
				t.Errorf("%s: terminal variant %q has no commands entry", l, variant)
			}
		}
	}
	if got := Defaults(ESR).KEX; got != "no-curve25519" {
		t.Errorf("ESR kex %q: ESR offers no curve25519 [R §4]", got)
	}
	if got := Defaults(MES6).InbandLogin; got != "auto" {
		t.Errorf("MES 6.x inband_login %q: in-band login is expected on MES 6.x [R §4]", got)
	}
	defer func() {
		if recover() == nil {
			t.Error("Defaults of an unknown line did not panic")
		}
	}()
	Defaults("ios")
}

func TestOverride(t *testing.T) {
	s, err := Defaults(MES10).Override(map[string]string{"terminal": "none", "errors": "strict"})
	if err != nil || s.Terminal != "none" || s.Errors != "strict" || s.Auth != "password" {
		t.Fatalf("override: %+v %v", s, err)
	}
	for name, o := range map[string]map[string]string{
		"unknown key":     {"terminal": "none", "shell": "bash"},
		"unknown variant": {"auth": "none"},
		"pattern field":   {"Prompt": ".*"},
		"empty variant":   {"pty": ""},
	} {
		got, err := Defaults(ESR).Override(o)
		if !errors.Is(err, ErrOverride) {
			t.Errorf("%s: %v", name, err)
		}
		if got.Terminal != Defaults(ESR).Terminal {
			t.Errorf("%s: a refused override changed the set", name)
		}
	}
}

/* The answer table answers only the questions of system commands, never one of an arbitrary line. */
func TestAnswersOnlySystemCommands(t *testing.T) {
	s := Defaults(MES6)
	q := "Overwrite file [startup-config].... (Y/N)[N] ?"
	answered := func(cmd string) bool {
		for _, a := range s.Answers {
			if a.Command.MatchString(cmd) && a.Question.MatchString(q) {
				return true
			}
		}
		return false
	}
	if !answered("write") || !answered("copy running-config startup-config") {
		t.Error("save is not answered")
	}
	for _, cmd := range []string{"boot config", "delete startup-config", "write x", "copy tftp://h/a startup-config", " write"} {
		if answered(cmd) {
			t.Errorf("%q is answered", cmd)
		}
	}
	if !s.Question.MatchString(q) || !s.Question.MatchString("Do you really want to reload system ? (y/N):") ||
		!s.Question.MatchString("Delete flash:test? [confirm]") || !s.Question.MatchString("Do you want to continue (y/n) [n]?") {
		t.Error("a documented question is not recognised")
	}
}

func TestPrompt(t *testing.T) {
	p := Defaults(ESR).Prompt
	for _, ok := range []string{"esr#", "esr>", "esr(config)#", "console(config-if)#", "sw-1.lab(config-if-gi)# "} {
		if !p.MatchString(ok) {
			t.Errorf("%q is not a prompt", ok)
		}
	}
	for _, no := range []string{"#", "a b#", "esr(Config)#", "esr(config)#x", "% Unrecognized command#x", strings.Repeat("a", 65) + "#"} {
		if p.MatchString(no) {
			t.Errorf("%q is a prompt", no)
		}
	}
}
