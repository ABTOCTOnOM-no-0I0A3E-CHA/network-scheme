package devices

import "slices"

/*
Roles is the closed set of device roles, as in the CHECK of migration 00023 and
the API enum DeviceRole; drivers.Roles must list the same (checked by a test).
*/
var Roles = []string{"switch", "router", "l3switch", "firewall", "server", "ap", "pc", "printer", "phone", "cloud", "other"}

/* ValidRole reports whether s is one of Roles. */
func ValidRole(s string) bool { return slices.Contains(Roles, s) }
