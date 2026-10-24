// Package rbac implements roles, permissions and group-scoped role bindings.
package rbac

import "slices"

// Role is a named set of permissions.
type Role string

/* Roles known to the system; the set is mirrored by a CHECK in core.role_binding. */
const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
	RoleAuditor  Role = "auditor"
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool {
	switch r {
	case RoleViewer, RoleOperator, RoleAdmin, RoleAuditor:
		return true
	}
	return false
}

// Perm is a single permission.
type Perm string

/* Permissions; the device ones are group-scoped. */
const (
	PermSelf           Perm = "self"
	PermUsersManage    Perm = "users.manage"
	PermGroupsManage   Perm = "groups.manage"
	PermBindingsManage Perm = "bindings.manage"
	PermAuditRead      Perm = "audit.read"
	PermEventsManage   Perm = "events.manage"
	PermSystemRead     Perm = "system.read"

	PermDevicesRead       Perm = "devices.read"
	PermDevicesPoll       Perm = "devices.poll"
	PermDevicesBackup     Perm = "devices.backup"
	PermDevicesShow       Perm = "devices.show"
	PermDevicesManage     Perm = "devices.manage"
	PermDeviceCredentials Perm = "device.credentials" //nolint:gosec // a permission name, not a credential

	/* Problems and monitoring configuration; all group-scoped. */
	PermProblemsAck       Perm = "problems.ack"
	PermTriggersManage    Perm = "triggers.manage"
	PermMaintenanceManage Perm = "maintenance.manage"

	/* Map views, areas, backgrounds, manual links and pinned positions; global only (not group-scoped). */
	PermMapManage Perm = "map.manage"

	/* Shared dashboards and the default dashboard of each role; global only (not group-scoped). */
	PermDashboardsManage Perm = "dashboards.manage"
)

/* matrix is the role to permission mapping; PermSelf is handled in Can. */
var matrix = map[Role][]Perm{
	RoleViewer:   {PermDevicesRead},
	RoleOperator: {PermDevicesRead, PermDevicesPoll, PermDevicesBackup, PermDevicesShow, PermSystemRead, PermProblemsAck},
	RoleAdmin: {PermUsersManage, PermGroupsManage, PermBindingsManage, PermAuditRead, PermEventsManage, PermSystemRead,
		PermDevicesRead, PermDevicesPoll, PermDevicesBackup, PermDevicesShow, PermDevicesManage, PermDeviceCredentials,
		PermProblemsAck, PermTriggersManage, PermMaintenanceManage, PermMapManage, PermDashboardsManage},
	RoleAuditor: {PermAuditRead},
}

// Binding grants Role globally (GroupID nil) or on a group and its descendants.
type Binding struct {
	Role    Role
	GroupID *int64
}

// Subject is an authenticated user together with its role bindings.
type Subject struct {
	UserID   int64
	Bindings []Binding
}

/*
Can reports whether the subject holds p for an object in groupID (nil for an
object outside the group tree, which only global bindings cover). ancestors is
the object's parent chain as returned by Store.Ancestors. PermSelf is granted
to every subject: it only covers the user's own account.
*/
func (s Subject) Can(p Perm, groupID *int64, ancestors []int64) bool {
	if p == PermSelf {
		return true
	}
	for _, b := range s.Bindings {
		if !slices.Contains(matrix[b.Role], p) {
			continue
		}
		if b.GroupID == nil {
			return true
		}
		if groupID != nil && (*b.GroupID == *groupID || slices.Contains(ancestors, *b.GroupID)) {
			return true
		}
	}
	return false
}
