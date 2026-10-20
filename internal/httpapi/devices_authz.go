package httpapi

import (
	"net/http"
	"slices"

	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/rbac"
)

/* groupScope is where the caller holds a permission: everywhere, or in ids (bound groups and their descendants). */
type groupScope struct {
	all bool
	ids []int64
}

func (g groupScope) has(groupID int64) bool { return g.all || slices.Contains(g.ids, groupID) }

/* filter selects the scope in SQL; an empty scope matches nothing, never everything. */
func (g groupScope) filter() devices.Filter { return devices.Filter{All: g.all, GroupIDs: g.ids} }

/*
scope resolves the groups where the caller holds p. The subject comes from
the route policy; a request that did not pass one sees nothing.
*/
func (s *server) scope(r *http.Request, p rbac.Perm) (groupScope, error) {
	subj, ok := r.Context().Value(keySubject).(rbac.Subject)
	if !ok {
		return groupScope{}, nil
	}
	all, ids, err := s.rbac.VisibleGroups(r.Context(), subj, p)
	if err != nil {
		return groupScope{}, err
	}
	return groupScope{all: all, ids: ids}, nil
}

/*
authorizeDevice is the object check of Scoped routes: it returns the device
only if the caller holds p on its group (or an ancestor). A missing and a
foreign device are indistinguishable, in the answer (devices.ErrNotFound,
which s.fail turns into 404 not_found, never 403) and in the queries made.
*/
func (s *server) authorizeDevice(r *http.Request, p rbac.Perm, deviceID int64) (devices.Device, error) {
	sc, err := s.scope(r, p)
	if err != nil {
		return devices.Device{}, err
	}
	return s.deviceIn(r, sc, deviceID)
}

/* deviceIn returns the device if its group is in sc, devices.ErrNotFound otherwise (also when it does not exist). */
func (s *server) deviceIn(r *http.Request, sc groupScope, deviceID int64) (devices.Device, error) {
	d, err := s.devices.Get(r.Context(), deviceID)
	if err != nil {
		return devices.Device{}, err
	}
	if !sc.has(d.GroupID) {
		return devices.Device{}, devices.ErrNotFound
	}
	return d, nil
}
