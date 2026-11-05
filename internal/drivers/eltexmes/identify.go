package eltexmes

import (
	"context"
	"regexp"

	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/snmp"
)

/* maxSysDescr bounds the sysDescr that is parsed at all. */
const maxSysDescr = 256

/*
sysDescrRe takes the model from a sysDescr that starts with it, e.g.
"MES2324P AC 28-port 1G/10G Managed Switch with 24 POE+ ports" (as reported by
an MES2324P with sysObjectID 1.3.6.1.4.1.35265.1.92 in the LibreNMS community
thread "OS definition problems", https://community.librenms.org/t/os-definition-problems/13863).
The MES sysDescr carries no firmware version. The LLDP example of [UM]
("24-port 10/100/1000 Ethernet Switch") names no model and yields nothing.
Not verified on hardware.
*/
var sysDescrRe = regexp.MustCompile(`^(MES-?[0-9]{4}[A-Z0-9]{0,4})(?: |$)`)

/* parseSysDescr returns the model named at the start of an MES sysDescr. */
func parseSysDescr(s string) (model string, ok bool) {
	if len(s) > maxSysDescr {
		return "", false
	}
	m := sysDescrRe.FindStringSubmatch(s)
	if m == nil {
		return "", false
	}
	return m[1], true
}

/*
Identify runs the generic identification and fills the model from sysDescr
when entPhysicalTable gave none. The role is "l3switch" when sysServices
reports layer 3, else "switch".
*/
func (d Driver) Identify(ctx context.Context, r snmp.Reader) (drivers.Identity, error) {
	id, err := d.Driver.Identify(ctx, r)
	if err != nil {
		return id, err
	}
	if model, ok := parseSysDescr(id.SysDescr); ok && id.Model == "" {
		id.Model = model
	}
	if id.Role == drivers.RoleL3Switch || id.Role == drivers.RoleRouter {
		id.Role = drivers.RoleL3Switch
	} else {
		id.Role = drivers.RoleSwitch
	}
	return id, nil
}

/* Line is an MES firmware line: the read dialect and the configuration privilege differ between them. */
type Line string

/* Firmware lines. LineUnknown keeps the behaviour from before the lines were told apart (the 6.x dialect). */
const (
	LineUnknown Line = ""
	LineMES6    Line = "mes6"
	LineMES10   Line = "mes10"
)

var (
	/* firmwareRe takes the major version from a firmware such as "6.6.2" or "10.4.5.2" (entPhysicalSoftwareRev). */
	firmwareRe = regexp.MustCompile(`^([0-9]{1,3})\.[0-9]`)
	/* modelRe takes the series (first two digits) from a model such as "MES2324P" or "MES-3710". */
	modelRe = regexp.MustCompile(`^MES-?([0-9]{2})[0-9]{2}`)
)

/*
modelLines maps a model series to its firmware line. Source: the model lists
on the titles of [UM6] (MES23xx, MES33xx, MES35xx, MES53xx, MES54xx, MES5500:
firmware 6.x) and [UM10] (MES14xx, MES24xx, MES3400, MES37xx: firmware 10.x),
research [R §0]. Other series (e.g. MES31xx) name no line.
*/
var modelLines = map[string]Line{
	"23": LineMES6, "33": LineMES6, "35": LineMES6, "53": LineMES6, "54": LineMES6, "55": LineMES6,
	"14": LineMES10, "24": LineMES10, "34": LineMES10, "37": LineMES10,
}

/*
lineOf tells the firmware line from the identity the poller already read
(model from entPhysicalModelName or sysDescr, firmware from entPhysicalSoftwareRev;
the MES sysObjectIDs per model are not documented). Conservatively:
a reported firmware decides when its major version is 6 or 10 and the model
does not name the other line; a reported firmware of any other form gives
LineUnknown; without a firmware the model series decides. Not verified on hardware.
*/
func lineOf(id drivers.Identity) Line {
	byModel := LineUnknown
	if len(id.Model) <= maxSysDescr {
		if m := modelRe.FindStringSubmatch(id.Model); m != nil {
			byModel = modelLines[m[1]]
		}
	}
	if id.Firmware == "" {
		return byModel
	}
	byFirmware := LineUnknown
	if len(id.Firmware) <= maxSysDescr {
		if m := firmwareRe.FindStringSubmatch(id.Firmware); m != nil {
			switch m[1] {
			case "6":
				byFirmware = LineMES6
			case "10":
				byFirmware = LineMES10
			}
		}
	}
	if byModel != LineUnknown && byModel != byFirmware {
		return LineUnknown
	}
	return byFirmware
}

/* ForIdentity returns the driver for the firmware line id shows; implements drivers.LineDriver. */
func (d Driver) ForIdentity(id drivers.Identity) drivers.Driver {
	d.line = lineOf(id)
	return d
}
