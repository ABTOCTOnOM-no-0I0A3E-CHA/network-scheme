package drivers

/* Role is the kind of a device as the map and the device card show it. */
type Role string

/* Roles, as stored in core.device.role and role_auto (the CHECK of migration 00023 lists the same set). */
const (
	RoleSwitch   Role = "switch"
	RoleRouter   Role = "router"
	RoleL3Switch Role = "l3switch"
	RoleFirewall Role = "firewall"
	RoleServer   Role = "server"
	RoleAP       Role = "ap"
	RolePC       Role = "pc"
	RolePrinter  Role = "printer"
	RolePhone    Role = "phone"
	RoleCloud    Role = "cloud"
	RoleOther    Role = "other"
)

/* Roles lists every role in display order. */
var Roles = []Role{RoleSwitch, RoleRouter, RoleL3Switch, RoleFirewall, RoleServer, RoleAP, RolePC, RolePrinter, RolePhone, RoleCloud, RoleOther}

/* ValidRole reports whether s is one of Roles. */
func ValidRole(s string) bool {
	for _, r := range Roles {
		if string(r) == s {
			return true
		}
	}
	return false
}

/* sysServices layer bits (SNMPv2-MIB): 2^(layer-1). */
const (
	servicesL2 = 1 << 1 /* datalink/subnetwork, e.g. bridges */
	servicesL3 = 1 << 2 /* internet, e.g. IP routers */
)

/*
RoleFromServices maps sysServices (SNMPv2-MIB sysServices.0, 0..127) to a
role: layer 2 and 3 → l3switch, layer 2 only → switch, layer 3 only → router,
anything else (or a value outside the range) → other.
*/
func RoleFromServices(s int64) Role {
	if s < 0 || s > 127 {
		return RoleOther
	}
	switch l2, l3 := s&servicesL2 != 0, s&servicesL3 != 0; {
	case l2 && l3:
		return RoleL3Switch
	case l2:
		return RoleSwitch
	case l3:
		return RoleRouter
	}
	return RoleOther
}
