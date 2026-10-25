package eltexesr

import (
	"context"
	"regexp"

	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/snmp"
)

/* maxSysDescr bounds the sysDescr that is parsed at all; longer text is not an ESR sysDescr. */
const maxSysDescr = 256

/*
sysDescrRe takes the model and version from "Eltex ESR-<model> Service Router
<version> build …". Source: [MON] section "Системные параметры" (example
"Eltex ESR-100 Service Router 1.24.x build 53 …"). Not verified on hardware.
*/
var sysDescrRe = regexp.MustCompile(`^Eltex (ESR-[0-9]{1,5}[A-Z]{0,4}) Service Router ([0-9]{1,3}(?:\.[0-9]{1,5}){1,3})(?: |$)`)

/* parseSysDescr returns the model and firmware named in an ESR sysDescr. */
func parseSysDescr(s string) (model, firmware string, ok bool) {
	if len(s) > maxSysDescr {
		return "", "", false
	}
	m := sysDescrRe.FindStringSubmatch(s)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

/*
Identify runs the generic identification, fills model and firmware from
sysDescr when entPhysicalTable gave none, and reports the role "router".
*/
func (d Driver) Identify(ctx context.Context, r snmp.Reader) (drivers.Identity, error) {
	id, err := d.Driver.Identify(ctx, r)
	if err != nil {
		return id, err
	}
	if model, fw, ok := parseSysDescr(id.SysDescr); ok {
		if id.Model == "" {
			id.Model = model
		}
		if id.Firmware == "" {
			id.Firmware = fw
		}
	}
	id.Role = drivers.RoleRouter
	return id, nil
}
