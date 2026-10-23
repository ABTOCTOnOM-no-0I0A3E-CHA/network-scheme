/*
Package triggers defines the closed set of trigger conditions and validates
their parameters. It is shared by the api (input validation) and the engine
(loading stored rows); parameters never carry expressions, patterns or SQL.
*/
package triggers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"unicode"
	"unicode/utf8"
)

// Kind is the type of a trigger condition.
type Kind string

/* User-defined kinds; the set is mirrored by a CHECK in core.trigger. */
const (
	KindAvailability    Kind = "availability"
	KindIfOperDown      Kind = "if_oper_down"
	KindMetricThreshold Kind = "metric_threshold"
	KindTrap            Kind = "trap"
	KindSyslog          Kind = "syslog"
)

/* System problem kinds raised by the engine itself; they take no user parameters. */
const (
	SystemPollerUnavailable Kind = "poller_unavailable"
	SystemDeviceUnreachable Kind = "device_unreachable"
)

/* Bounds shared with the schema and the UI. */
const (
	MaxDurationS    = 86400
	MaxContainsLen  = 128
	MaxTrapNameLen  = 1024
	MaxIfIndex      = math.MaxInt32
	maxIfErrorsRate = 1e9
)

// Params are the validated parameters of one trigger condition.
type Params interface {
	Kind() Kind
	Validate() error
}

// IsSystem reports whether k is an engine-raised system kind.
func (k Kind) IsSystem() bool { return k == SystemPollerUnavailable || k == SystemDeviceUnreachable }

// ParseUser is Parse for the api: system kinds cannot be configured by users.
func ParseUser(kind string, raw json.RawMessage) (Params, error) {
	if Kind(kind).IsSystem() {
		return nil, fmt.Errorf("trigger kind %q is reserved for the system", kind)
	}
	return Parse(kind, raw)
}

// Parse decodes raw as the parameters of kind and validates them. Unknown
// fields, trailing data and unknown kinds are rejected; a null or empty raw
// is treated as an empty object.
func Parse(kind string, raw json.RawMessage) (Params, error) {
	var p Params
	switch Kind(kind) {
	case KindAvailability:
		p = &Availability{}
	case KindIfOperDown:
		p = &IfOperDown{}
	case KindMetricThreshold:
		p = &MetricThreshold{}
	case KindTrap:
		p = &Trap{}
	case KindSyslog:
		p = &Syslog{}
	case SystemPollerUnavailable, SystemDeviceUnreachable:
		p = &System{kind: Kind(kind)}
	default:
		return nil, fmt.Errorf("unknown trigger kind %q", kind)
	}
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		raw = json.RawMessage("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(p); err != nil {
		return nil, fmt.Errorf("invalid %s params: %w", kind, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("invalid %s params: trailing data", kind)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

// ValidateDuration checks a condition duration in seconds.
func ValidateDuration(s int) error {
	if s < 0 || s > MaxDurationS {
		return fmt.Errorf("duration must be within 0..%d seconds", MaxDurationS)
	}
	return nil
}

// Availability fires while the device availability state is one of States.
type Availability struct {
	States []string `json:"states"`
}

// Kind returns KindAvailability.
func (*Availability) Kind() Kind { return KindAvailability }

// Validate checks that States is a non-empty set of down/partial.
func (a *Availability) Validate() error {
	if len(a.States) == 0 || len(a.States) > 2 {
		return errors.New("availability: states must list down and/or partial")
	}
	seen := map[string]bool{}
	for _, s := range a.States {
		if s != "down" && s != "partial" {
			return fmt.Errorf("availability: unknown state %q", s)
		}
		if seen[s] {
			return fmt.Errorf("availability: duplicate state %q", s)
		}
		seen[s] = true
	}
	return nil
}

// IfOperDown fires while an interface (or any interface when IfIndex is nil) is operationally down.
type IfOperDown struct {
	IfIndex *int `json:"if_index"`
}

// Kind returns KindIfOperDown.
func (*IfOperDown) Kind() Kind { return KindIfOperDown }

// Validate checks the optional interface index.
func (i *IfOperDown) Validate() error { return validateIfIndex(i.IfIndex) }

func validateIfIndex(idx *int) error {
	if idx != nil && (*idx < 1 || *idx > MaxIfIndex) {
		return fmt.Errorf("if_index must be within 1..%d", MaxIfIndex)
	}
	return nil
}

/* Metric names and comparison operators of MetricThreshold. */
const (
	MetricCPU        = "cpu"
	MetricMem        = "mem"
	MetricTemp       = "temp"
	MetricIfUtilIn   = "if_util_in"
	MetricIfUtilOut  = "if_util_out"
	MetricIfErrors   = "if_errors"
	OpGreater        = "gt"
	OpLess           = "lt"
	metricIfScopeMsg = "metric_threshold: if_index only applies to interface metrics"
)

// MetricThreshold fires while Metric compares to Value by Op.
type MetricThreshold struct {
	Metric  string   `json:"metric"`
	Op      string   `json:"op"`
	Value   *float64 `json:"value"`
	IfIndex *int     `json:"if_index"`
}

// Kind returns KindMetricThreshold.
func (*MetricThreshold) Kind() Kind { return KindMetricThreshold }

// Validate checks the metric, the operator and the value range of the metric.
func (m *MetricThreshold) Validate() error {
	var lo, hi float64
	ifMetric := false
	switch m.Metric {
	case MetricCPU, MetricMem:
		lo, hi = 0, 100
	case MetricTemp:
		lo, hi = -50, 150
	case MetricIfUtilIn, MetricIfUtilOut:
		lo, hi, ifMetric = 0, 100, true
	case MetricIfErrors:
		lo, hi, ifMetric = 0, maxIfErrorsRate, true
	default:
		return fmt.Errorf("metric_threshold: unknown metric %q", m.Metric)
	}
	if m.Op != OpGreater && m.Op != OpLess {
		return fmt.Errorf("metric_threshold: unknown operator %q", m.Op)
	}
	if m.Value == nil {
		return errors.New("metric_threshold: value is required")
	}
	if math.IsNaN(*m.Value) || *m.Value < lo || *m.Value > hi {
		return fmt.Errorf("metric_threshold: value for %s must be within %g..%g", m.Metric, lo, hi)
	}
	if m.IfIndex != nil && !ifMetric {
		return errors.New(metricIfScopeMsg)
	}
	return validateIfIndex(m.IfIndex)
}

// Trap fires when a trap with the (resolved) Name arrives.
type Trap struct {
	Name string `json:"name"`
}

// Kind returns KindTrap.
func (*Trap) Kind() Kind { return KindTrap }

// Validate checks the trap name length and content.
func (t *Trap) Validate() error {
	if t.Name == "" || len(t.Name) > MaxTrapNameLen {
		return fmt.Errorf("trap: name must be 1..%d bytes", MaxTrapNameLen)
	}
	if !utf8.ValidString(t.Name) || hasControl(t.Name) {
		return errors.New("trap: name has invalid characters")
	}
	return nil
}

// Syslog fires on a syslog message at SeverityMin (0 emergency .. 7 debug) or more severe, optionally containing Contains.
type Syslog struct {
	SeverityMin *int    `json:"severity_min"`
	Contains    *string `json:"contains"`
}

// Kind returns KindSyslog.
func (*Syslog) Kind() Kind { return KindSyslog }

// Validate checks the severity and the substring (<= 128 characters, no control characters).
func (s *Syslog) Validate() error {
	if s.SeverityMin == nil || *s.SeverityMin < 0 || *s.SeverityMin > 7 {
		return errors.New("syslog: severity_min is required and must be within 0..7")
	}
	if s.Contains == nil {
		return nil
	}
	c := *s.Contains
	if c == "" || utf8.RuneCountInString(c) > MaxContainsLen {
		return fmt.Errorf("syslog: contains must be 1..%d characters", MaxContainsLen)
	}
	if !utf8.ValidString(c) || hasControl(c) {
		return errors.New("syslog: contains has invalid characters")
	}
	return nil
}

func hasControl(s string) bool {
	return slices.ContainsFunc([]rune(s), func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) })
}

// System is the parameterless condition of an engine-raised system kind.
type System struct {
	kind Kind
}

// Kind returns the system kind.
func (s *System) Kind() Kind { return s.kind }

// Validate always succeeds: unknown fields are already rejected by Parse.
func (*System) Validate() error { return nil }
