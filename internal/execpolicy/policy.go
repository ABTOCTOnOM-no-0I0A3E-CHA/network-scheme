/*
Package execpolicy parses and validates the executor's policy file
(deploy/policies/executor.yaml, security.md 5.5): strict YAML, every value
checked against its range. It is shared by the executor (which reloads the
file by mtime and treats an invalid one as "disabled") and nmsctl (which
validates before it replaces the file). It decides nothing and holds no
code that talks to devices.
*/
package execpolicy

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"
	_ "time/tzdata" /* windows name an IANA zone; the distroless images carry no zoneinfo */
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

/* MaxSize bounds the policy file. */
const MaxSize = 64 << 10

/* Values of the enumerated fields. */
const (
	ConfirmTOTP  = "totp"
	ConfirmFIDO2 = "fido2" /* Phase 4: confirmed actions are refused (fail closed, security.md 5.2) */

	OutsideDeny         = "deny"
	OutsideSecondPerson = "second_person" /* Phase 4: refused (fail closed) */

	ClassSafe      = "safe"
	ClassDangerous = "dangerous"
	ClassDenied    = "denied"
)

/*
Policy is the executor's policy. Every field has a default (Default); a
file sets only what differs. Enabled is false by default: a fresh install
changes nothing until the host enables the executor.
*/
type Policy struct {
	Enabled               bool            `yaml:"enabled" json:"enabled"`
	ConfirmMode           string          `yaml:"confirm_mode" json:"confirm_mode"`
	SessionMinutes        int             `yaml:"session_minutes" json:"session_minutes"`
	IdleMinutes           int             `yaml:"idle_minutes" json:"idle_minutes"`
	MaxDevicesPerSession  int             `yaml:"max_devices_per_session" json:"max_devices_per_session"`
	MaxConfigLinesPerHour int             `yaml:"max_config_lines_per_hour" json:"max_config_lines_per_hour"`
	Timezone              string          `yaml:"timezone" json:"timezone"`
	Windows               []Window        `yaml:"windows" json:"windows"`
	OutsideWindow         string          `yaml:"outside_window" json:"outside_window"`
	TwoPersonGroups       []string        `yaml:"two_person_groups" json:"two_person_groups"`
	ClassOverrides        []ClassOverride `yaml:"class_overrides" json:"class_overrides"`
	TelnetWrite           bool            `yaml:"telnet_write" json:"telnet_write"`
	MESReloadInMin        int             `yaml:"mes_reload_in_min" json:"mes_reload_in_min"`
	ESRCommitTimerS       int             `yaml:"esr_commit_timer_s" json:"esr_commit_timer_s"`
	PasteConfirmLines     int             `yaml:"paste_confirm_lines" json:"paste_confirm_lines"`
	UnmaskPerHour         int             `yaml:"unmask_per_hour" json:"unmask_per_hour"`
	MassUnmaskAlert       int             `yaml:"mass_unmask_alert" json:"mass_unmask_alert"`
	RecordingMaxMiB       int             `yaml:"recording_max_mib" json:"recording_max_mib"`
	RecordingViewsPerHour int             `yaml:"recording_views_per_hour" json:"recording_views_per_hour"`
}

/*
Window is a change window in Policy.Timezone: on Days, from Start to End
(HH:MM, Start before End, End may be 24:00; a window across midnight is
written as two). No window at all means changes at any time.
*/
type Window struct {
	Days  []string `yaml:"days" json:"days"`
	Start string   `yaml:"start" json:"start"`
	End   string   `yaml:"end" json:"end"`
}

/*
ClassOverride sets the class of a command for a driver line ("any" for all):
Command is a normalized command prefix, as the driver's Normalize writes it
(single spaces, printable ASCII).
*/
type ClassOverride struct {
	Driver  string `yaml:"driver" json:"driver"`
	Command string `yaml:"command" json:"command"`
	Class   string `yaml:"class" json:"class"`
}

/* Default is the policy of a fresh install (security.md 5.5). */
func Default() Policy {
	return Policy{
		ConfirmMode:           ConfirmTOTP,
		SessionMinutes:        30,
		IdleMinutes:           10,
		MaxDevicesPerSession:  5,
		MaxConfigLinesPerHour: 500,
		Timezone:              "UTC",
		OutsideWindow:         OutsideDeny,
		ESRCommitTimerS:       300,
		PasteConfirmLines:     5,
		UnmaskPerHour:         10,
		MassUnmaskAlert:       20,
		RecordingMaxMiB:       16,
		RecordingViewsPerHour: 20,
	}
}

var (
	groupRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	clockRe   = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$|^24:00$`)
	commandRe = regexp.MustCompile(`^[!-~]+( [!-~]+)*$`)
	days      = []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
	drivers   = []string{"mes6", "mes10", "esr", "any"}
	boolKeys  = []string{"enabled", "telnet_write"}
)

/* Sum is the SHA-256 of a policy file's bytes (what the executor audits). */
func Sum(data []byte) [32]byte { return sha256.Sum256(data) }

/*
Parse reads a policy file strictly: at most MaxSize bytes of UTF-8, one
YAML document whose top level is a mapping, no anchors, aliases or custom
tags, no unknown or duplicate keys, booleans only as true/false; missing
keys take their defaults; then Validate.
*/
func Parse(data []byte) (Policy, error) {
	if len(data) > MaxSize {
		return Policy{}, fmt.Errorf("policy: larger than %d bytes", MaxSize)
	}
	if !utf8.Valid(data) {
		return Policy{}, errors.New("policy: not UTF-8")
	}
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return Policy{}, errors.New("policy: empty")
		}
		return Policy{}, fmt.Errorf("policy: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return Policy{}, errors.New("policy: more than one YAML document")
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return Policy{}, errors.New("policy: the top level must be a mapping")
	}
	if err := plain(&doc); err != nil {
		return Policy{}, err
	}
	top := doc.Content[0]
	for i := 0; i+1 < len(top.Content); i += 2 {
		if slices.Contains(boolKeys, top.Content[i].Value) && top.Content[i+1].Tag != "!!bool" {
			return Policy{}, fmt.Errorf("policy: %s must be true or false", top.Content[i].Value)
		}
	}
	p := Default()
	strict := yaml.NewDecoder(bytes.NewReader(data))
	strict.KnownFields(true)
	if err := strict.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("policy: %w", err)
	}
	p.normalize()
	if err := p.Validate(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

/*
plain refuses anchors, aliases, merge keys, nulls (an empty value would
silently keep the default), keys that are not plain strings and tags other
than the core schema's.
*/
func plain(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return errors.New("policy: anchors and aliases are not allowed")
	}
	switch n.Tag {
	case "", "!!map", "!!seq", "!!str", "!!int", "!!bool":
	case "!!null":
		return fmt.Errorf("policy: line %d: empty value", n.Line)
	default:
		return fmt.Errorf("policy: line %d: tag %s is not allowed", n.Line, n.Tag)
	}
	for i, c := range n.Content {
		if n.Kind == yaml.MappingNode && i%2 == 0 && (c.Kind != yaml.ScalarNode || c.Tag != "!!str") {
			return fmt.Errorf("policy: line %d: keys are plain words", c.Line)
		}
		if err := plain(c); err != nil {
			return err
		}
	}
	return nil
}

/* normalize makes empty lists nil, so a policy compares equal however its empty lists were written. */
func (p *Policy) normalize() {
	if len(p.Windows) == 0 {
		p.Windows = nil
	}
	if len(p.TwoPersonGroups) == 0 {
		p.TwoPersonGroups = nil
	}
	if len(p.ClassOverrides) == 0 {
		p.ClassOverrides = nil
	}
	for i := range p.Windows {
		if len(p.Windows[i].Days) == 0 {
			p.Windows[i].Days = nil
		}
	}
}

func inRange(name string, v, lo, hi int) error {
	if v < lo || v > hi {
		return fmt.Errorf("policy: %s = %d, want %d..%d", name, v, lo, hi)
	}
	return nil
}

/* Validate checks every value against its range (security.md 5.5). */
func (p Policy) Validate() error {
	if err := errors.Join(
		inRange("session_minutes", p.SessionMinutes, 5, 240),
		inRange("idle_minutes", p.IdleMinutes, 1, p.SessionMinutes),
		inRange("max_devices_per_session", p.MaxDevicesPerSession, 1, 50),
		inRange("max_config_lines_per_hour", p.MaxConfigLinesPerHour, 1, 100000),
		inRange("esr_commit_timer_s", p.ESRCommitTimerS, 120, 1200),
		inRange("paste_confirm_lines", p.PasteConfirmLines, 1, 100),
		inRange("unmask_per_hour", p.UnmaskPerHour, 1, 1000),
		inRange("mass_unmask_alert", p.MassUnmaskAlert, 1, 10000),
		inRange("recording_max_mib", p.RecordingMaxMiB, 1, 64),
		inRange("recording_views_per_hour", p.RecordingViewsPerHour, 1, 1000),
	); err != nil {
		return err
	}
	if p.MESReloadInMin != 0 {
		if err := inRange("mes_reload_in_min", p.MESReloadInMin, 5, 120); err != nil {
			return fmt.Errorf("%w (or 0: off)", err)
		}
	}
	if p.ConfirmMode != ConfirmTOTP && p.ConfirmMode != ConfirmFIDO2 {
		return fmt.Errorf("policy: confirm_mode %q, want totp or fido2", p.ConfirmMode)
	}
	if p.OutsideWindow != OutsideDeny && p.OutsideWindow != OutsideSecondPerson {
		return fmt.Errorf("policy: outside_window %q, want deny or second_person", p.OutsideWindow)
	}
	if p.Timezone == "" || len(p.Timezone) > 64 || p.Timezone == "Local" {
		return fmt.Errorf("policy: timezone %q, want an IANA zone name", p.Timezone)
	}
	if _, err := time.LoadLocation(p.Timezone); err != nil {
		return fmt.Errorf("policy: timezone %q: %w", p.Timezone, err)
	}
	if len(p.Windows) > 32 {
		return errors.New("policy: more than 32 windows")
	}
	for i, w := range p.Windows {
		if err := w.validate(); err != nil {
			return fmt.Errorf("policy: windows[%d]: %w", i, err)
		}
	}
	if len(p.TwoPersonGroups) > 256 {
		return errors.New("policy: more than 256 two_person_groups")
	}
	for i, g := range p.TwoPersonGroups {
		if !groupRe.MatchString(g) || slices.Contains(p.TwoPersonGroups[:i], g) {
			return fmt.Errorf("policy: two_person_groups: bad or repeated group %q", g)
		}
	}
	if len(p.ClassOverrides) > 256 {
		return errors.New("policy: more than 256 class_overrides")
	}
	for i, o := range p.ClassOverrides {
		switch {
		case !slices.Contains(drivers, o.Driver):
			return fmt.Errorf("policy: class_overrides[%d]: driver %q, want one of %s", i, o.Driver, strings.Join(drivers, ", "))
		case len(o.Command) > 256 || !commandRe.MatchString(o.Command):
			return fmt.Errorf("policy: class_overrides[%d]: command must be printable ASCII words separated by single spaces", i)
		case o.Class != ClassSafe && o.Class != ClassDangerous && o.Class != ClassDenied:
			return fmt.Errorf("policy: class_overrides[%d]: class %q, want safe, dangerous or denied", i, o.Class)
		}
		for _, prev := range p.ClassOverrides[:i] {
			if prev.Driver == o.Driver && prev.Command == o.Command {
				return fmt.Errorf("policy: class_overrides[%d]: repeated %s %q", i, o.Driver, o.Command)
			}
		}
	}
	return nil
}

func (w Window) validate() error {
	if len(w.Days) == 0 || len(w.Days) > 7 {
		return errors.New("days: one to seven of mon..sun")
	}
	for i, d := range w.Days {
		if !slices.Contains(days, d) || slices.Contains(w.Days[:i], d) {
			return fmt.Errorf("days: bad or repeated %q", d)
		}
	}
	if !clockRe.MatchString(w.Start) || !clockRe.MatchString(w.End) || w.Start == "24:00" {
		return errors.New("start and end are HH:MM (end may be 24:00)")
	}
	if w.Start >= w.End {
		return errors.New("start must be before end (split a window across midnight in two)")
	}
	return nil
}

/* Marshal renders p as a policy file (every key, defaults included). */
func Marshal(p Policy) ([]byte, error) {
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	return b.Bytes(), enc.Close()
}

/*
SetEnabled returns the policy file data with enabled set to on, keeping
everything else (comments included); data must be a valid policy before,
and the result is validated again.
*/
func SetEnabled(data []byte, on bool) ([]byte, error) {
	if _, err := Parse(data); err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	top := doc.Content[0]
	val := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: fmt.Sprint(on)}
	found := false
	for i := 0; i+1 < len(top.Content); i += 2 {
		if top.Content[i].Value == "enabled" {
			top.Content[i+1].Value, top.Content[i+1].Tag, top.Content[i+1].Style = val.Value, val.Tag, 0
			found = true
		}
	}
	if !found {
		top.Content = append([]*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: "enabled"}, val}, top.Content...)
	}
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	if _, err := Parse(b.Bytes()); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
