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

/* Phase 0 permissions; device permissions arrive in Phase 1. */
const (
	PermSelf           Perm = "self"
	PermUsersManage    Perm = "users.manage"
	PermGroupsManage   Perm = "groups.manage"
	PermBindingsManage Perm = "bindings.manage"
	PermAuditRead      Perm = "audit.read"
)

/* matrix is the Phase 0 role to permission mapping; PermSelf is handled in Can. */
var matrix = map[Role][]Perm{
	RoleViewer:   nil,
	RoleOperator: nil,
	RoleAdmin:    {PermUsersManage, PermGroupsManage, PermBindingsManage, PermAuditRead},
	RoleAuditor:  {PermAuditRead},
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
