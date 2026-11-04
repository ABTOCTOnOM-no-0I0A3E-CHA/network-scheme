/*
Package identify tells a device's firmware line, model and firmware from the
"show version" and "show system" outputs the executor read itself after
login, and applies the model gate (security.md 5.1a, 5.3): the line must be
the registered one (registry table write_device.write_driver), and writes are allowed
only when (model, firmware) matches exactly one model profile verified on a
stand (registry table model_profile), whose strategies then override the line's
defaults. Device output is untrusted: the parsers are strict and bounded.
*/
package identify

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/strategy"
)

/* Identity is what the device says it is. Model is "" when show system names none. */
type Identity struct {
	Line     strategy.Line
	Model    string
	Firmware string
}

var (
	/* ErrUnknown means the output names no firmware line, or names several, or the model names another line. */
	ErrUnknown = errors.New("identify: firmware line not recognised")
	/* ErrLineMismatch means the device's line is not the registered one; no session at all. */
	ErrLineMismatch = errors.New("identify: firmware line differs from the registered write driver")
)

/* maxOutput bounds what is parsed; a longer show version is not a version. */
const maxOutput = 64 << 10

var (
	/* ESR: "SW version:" then the version on the next line [fixture esr/show version]. */
	esrFirmware = regexp.MustCompile(`(?m)^SW version:[ \t]*\n[ \t]+([0-9]{1,3}(?:\.[0-9]{1,4}){1,3})\b`)
	/* MES 6.x: "  Version: 6.6.2" under "Active-image:" [fixture mes6/show version]. */
	mes6Firmware = regexp.MustCompile(`(?m)^[ \t]*Version:[ \t]*(6(?:\.[0-9]{1,4}){1,3})[ \t]*$`)
	/* MES 10.x: unit table "Switch ID  Hardware Version  Firmware Version", a row "0  1v1  10.4.5.2" [fixture mes10/show version]. */
	mes10Firmware = regexp.MustCompile(`(?m)^[ \t]*[0-9]{1,2}[ \t]+\S{1,32}[ \t]+(10(?:\.[0-9]{1,4}){1,3})[ \t]*$`)
	/* show system: "System type:" (ESR) or "System Description:" (MES) [fixtures esr, mes6 show system]. */
	systemLine = regexp.MustCompile(`(?m)^System (?:type|Type|Description|description):[ \t]+(.{1,200})$`)
	esrModel   = regexp.MustCompile(`\b(ESR-[0-9]{1,5}[A-Z0-9]{0,8})\b`)
	mesModel   = regexp.MustCompile(`\b(MES-?([0-9]{2})[0-9]{2}[A-Z0-9]{0,8})\b`)
	/* the MES series of each line, as the read side (internal/drivers/eltexmes) [R §0]. */
	mesSeries = map[string]strategy.Line{
		"23": strategy.MES6, "33": strategy.MES6, "35": strategy.MES6, "53": strategy.MES6, "54": strategy.MES6, "55": strategy.MES6,
		"14": strategy.MES10, "24": strategy.MES10, "34": strategy.MES10, "37": strategy.MES10,
	}
)

/*
Parse identifies the device from its outputs (CRLF already normalised).
Exactly one firmware line must be named; a model of the other family, or of
an MES series of the other line, makes the line unknown.
*/
func Parse(showVersion, showSystem string) (Identity, error) {
	if len(showVersion) > maxOutput || len(showSystem) > maxOutput {
		return Identity{}, fmt.Errorf("%w: output too long", ErrUnknown)
	}
	var found []Identity
	for line, re := range map[strategy.Line]*regexp.Regexp{strategy.ESR: esrFirmware, strategy.MES6: mes6Firmware, strategy.MES10: mes10Firmware} {
		ms := re.FindAllStringSubmatch(showVersion, -1)
		if len(ms) > 1 {
			return Identity{}, fmt.Errorf("%w: several %s versions", ErrUnknown, line)
		}
		if len(ms) == 1 {
			found = append(found, Identity{Line: line, Firmware: ms[0][1]})
		}
	}
	if len(found) != 1 {
		return Identity{}, fmt.Errorf("%w: %d firmware lines in show version", ErrUnknown, len(found))
	}
	id := found[0]
	sys := systemLine.FindAllStringSubmatch(showSystem, -1)
	if len(sys) > 1 {
		return Identity{}, fmt.Errorf("%w: several system lines", ErrUnknown)
	}
	if len(sys) == 1 {
		desc := sys[0][1]
		esr, mes := esrModel.FindString(desc), mesModel.FindStringSubmatch(desc)
		switch {
		case esr != "" && mes != nil:
			return Identity{}, fmt.Errorf("%w: model names both families", ErrUnknown)
		case esr != "":
			if id.Line != strategy.ESR {
				return Identity{}, fmt.Errorf("%w: ESR model with %s firmware", ErrUnknown, id.Line)
			}
			id.Model = esr
		case mes != nil:
			if l, ok := mesSeries[mes[2]]; id.Line == strategy.ESR || ok && l != id.Line {
				return Identity{}, fmt.Errorf("%w: model %s with %s firmware", ErrUnknown, mes[1], id.Line)
			}
			id.Model = mes[1]
		}
	}
	return id, nil
}

/* Profile is one registry table model_profile row. Err is set when the row cannot be used (it then never allows writes). */
type Profile struct {
	ID          int64
	WriteDriver strategy.Line
	ModelRe     string
	FirmwareRe  string
	Strategies  map[string]string
	Err         error
}

/* ProfilesOf reads the model profiles of a verified registry snapshot. */
func ProfilesOf(s *registry.Snapshot) []Profile {
	var out []Profile
	for _, r := range s.Rows("model_profile") {
		p := Profile{}
		p.ID, _ = r.Get("id").(int64)
		drv, _ := r.Get("write_driver").(string)
		p.WriteDriver = strategy.Line(drv)
		p.ModelRe, _ = r.Get("model_re").(string)
		p.FirmwareRe, _ = r.Get("firmware_re").(string)
		raw, _ := r.Get("strategies").(json.RawMessage)
		if err := json.Unmarshal(raw, &p.Strategies); err != nil {
			p.Err = fmt.Errorf("strategies: %w", err)
		}
		out = append(out, p)
	}
	return out
}

/*
Decision is the model gate's verdict. Set is always usable for reading: the
line's defaults, overridden by the matching profile when Write.
*/
type Decision struct {
	Write   bool
	Reason  string /* why writes are refused; "" when Write */
	Profile int64  /* the matching profile; 0: none */
	Set     strategy.Set
}

/* storedRe is how nmsctl executor model-verify stores a pattern: ^(?:RE)$ (matched as stored, never re-anchored). */
func storedRe(p string) (*regexp.Regexp, error) {
	if !strings.HasPrefix(p, "^(?:") || !strings.HasSuffix(p, ")$") {
		return nil, fmt.Errorf("pattern %q is not stored anchored", p)
	}
	/*
		The text form is not enough ("^(?:a)$|b" has it): wrap once more, so
		the whole string must match whatever the stored pattern holds.
	*/
	return regexp.Compile(`^(?:` + p + `)$`)
}

func (p Profile) matches(id Identity) (bool, error) {
	if p.WriteDriver != id.Line {
		return false, nil
	}
	m, err := storedRe(p.ModelRe)
	if err != nil {
		return false, err
	}
	f, err := storedRe(p.FirmwareRe)
	if err != nil {
		return false, err
	}
	return m.MatchString(id.Model) && f.MatchString(id.Firmware), nil
}

/*
Decide applies the model gate for a device registered with write driver
registered. A line other than the registered one is ErrLineMismatch (no
session, not even reading). Otherwise reading is always allowed with the
line's defaults, and writing only when exactly one usable profile matches
(model, firmware); an unusable profile that might match (bad pattern or
strategies, an unknown strategy key or variant) refuses writes too.
*/
func Decide(registered strategy.Line, profiles []Profile, id Identity) (Decision, error) {
	if !registered.Valid() {
		return Decision{}, fmt.Errorf("%w: registered %q", ErrLineMismatch, registered)
	}
	if id.Line != registered {
		return Decision{}, fmt.Errorf("%w: device %q, registered %q", ErrLineMismatch, id.Line, registered)
	}
	d := Decision{Set: strategy.Defaults(registered)}
	var hit []Profile
	for _, p := range profiles {
		ok, err := p.matches(id)
		if err == nil {
			err = p.Err
		}
		if err != nil {
			if p.WriteDriver == id.Line {
				d.Reason = fmt.Sprintf("model profile #%d is unusable: %v", p.ID, err)
				return d, nil
			}
			continue
		}
		if ok {
			hit = append(hit, p)
		}
	}
	switch len(hit) {
	case 0:
		d.Reason = fmt.Sprintf("model %q firmware %q is not verified (no model profile)", id.Model, id.Firmware)
		return d, nil
	case 1:
	default:
		d.Reason = fmt.Sprintf("model %q firmware %q matches %d model profiles", id.Model, id.Firmware, len(hit))
		return d, nil
	}
	set, err := d.Set.Override(hit[0].Strategies)
	if err != nil {
		d.Reason = fmt.Sprintf("model profile #%d: %v", hit[0].ID, err)
		return d, nil
	}
	return Decision{Write: true, Profile: hit[0].ID, Set: set}, nil
}
