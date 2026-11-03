package drivers

import (
	"testing"

	"github.com/beekamai/network-scheme/internal/devices"
)

func TestRoleFromServices(t *testing.T) {
	for s, want := range map[int64]Role{
		2: RoleSwitch, 3: RoleSwitch, 6: RoleL3Switch, 78: RoleL3Switch, 4: RoleRouter, 76: RoleRouter,
		0: RoleOther, 72: RoleOther, 1: RoleOther, -1: RoleOther, 128: RoleOther, 1 << 40: RoleOther,
	} {
		if got := RoleFromServices(s); got != want {
			t.Errorf("RoleFromServices(%d) = %s, want %s", s, got, want)
		}
	}
	for _, r := range Roles {
		if !ValidRole(string(r)) {
			t.Errorf("ValidRole(%s) = false", r)
		}
	}
	for _, s := range []string{"", "Switch", "router ", "unknown"} {
		if ValidRole(s) {
			t.Errorf("ValidRole(%q) = true", s)
		}
	}
	/* the API validates with the devices package, which the api may link (it may not link drivers) */
	if len(devices.Roles) != len(Roles) {
		t.Fatalf("devices.Roles %v, drivers.Roles %v", devices.Roles, Roles)
	}
	for i, r := range Roles {
		if devices.Roles[i] != string(r) {
			t.Errorf("devices.Roles[%d] = %s, want %s", i, devices.Roles[i], r)
		}
	}
}
