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
