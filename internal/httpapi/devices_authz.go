package httpapi

import (
	"context"
	"net/http"

	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/rbac"
)

// DeviceLookup resolves a device for object-level checks; *devices.Store implements it.
type DeviceLookup interface {
	Get(ctx context.Context, id int64) (devices.Device, error)
}

/*
authorizeDevice is the object check of Scoped routes: it returns the device
only if the caller holds p on its group (or an ancestor). A missing and a
foreign device are indistinguishable: both give devices.ErrNotFound, which
s.fail answers with 404 not_found, never 403.
*/
func (s *server) authorizeDevice(r *http.Request, p rbac.Perm, deviceID int64) (devices.Device, error) {
	sc, ok := sessionFrom(r.Context())
	if !ok || !sc.valid {
		return devices.Device{}, devices.ErrNotFound
	}
	subj, err := s.rbac.LoadSubject(r.Context(), sc.sess.UserID)
	if err != nil {
		return devices.Device{}, err
	}
	d, err := s.devices.Get(r.Context(), deviceID)
	if err != nil {
		return devices.Device{}, err
	}
	anc, err := s.rbac.Ancestors(r.Context(), d.GroupID)
	if err != nil {
		return devices.Device{}, err
	}
	if !subj.Can(p, &d.GroupID, anc) {
		return devices.Device{}, devices.ErrNotFound
	}
	return d, nil
}
