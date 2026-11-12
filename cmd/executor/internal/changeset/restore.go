package changeset

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/beekamai/network-scheme/cmd/executor/internal/backups"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers"
	"github.com/beekamai/network-scheme/internal/textdiff"
)

/*
Restore changesets (task 5.6, FR-UI-DEV-6): kind restore puts each device
back to one of its own configuration versions (backups.config_version). The
executor opens the version itself (backups.OpenVersion: the envelope under
AAD(device, sha256), sha256(normalize(text)) == the row's; a version of
another device is unknown, a failed check raises executor_changeset_tamper),
plans the lines from the running configuration to it with the line's
Planner, and from then on the lines are a changeset's like any other: the
dry-run walks them (Safe only, D2: what cannot be restored that way is
listed and the device refused), plan_sha256 covers the version's id and
hash, the run sends them and then requires the running configuration to
hash as the version (else the device is rolled back).
*/

/* openVersion opens version of device for changeset id; the code says why not (version_unknown, version_tampered, unavailable). */
func (m *Manager) openVersion(ctx context.Context, id [16]byte, device, version int64, want string) (backups.Version, string) {
	if m.cfg.BackupPriv == nil || m.cfg.BackupPub == nil {
		return backups.Version{}, "restore_unavailable"
	}
	v, err := backups.OpenVersion(ctx, m.cfg.Store.Pool, m.cfg.BackupPriv, m.cfg.BackupPub, device, version, want)
	switch {
	case errors.Is(err, backups.ErrVersionUnknown):
		return v, "version_unknown"
	case errors.Is(err, backups.ErrVersionTampered):
		m.runAlert(ctx, KindTamper, device, fmt.Sprintf("changeset %s: configuration version %d of device %d fails its checks (%v); "+
			"it is not restored", IDString(id), version, device, err))
		return v, "version_tampered"
	case err != nil:
		return v, "unavailable"
	}
	return v, ""
}

/* restoreItem is the restore item of device in c. */
func restoreItem(c Content, device int64) (RestoreItem, bool) {
	i := slices.IndexFunc(c.Restore, func(r RestoreItem) bool { return r.Device == device })
	if i < 0 {
		return RestoreItem{}, false
	}
	return c.Restore[i], true
}

/* restorePlan is the lines that bring a device of drv from pre to the version's text. */
func restorePlan(drv drivers.WriteDriver, pre, version string) ([]Rendered, error) {
	p, ok := drv.(drivers.Planner)
	if !ok {
		return nil, fmt.Errorf("%w: the line cannot plan a restore", ErrContent)
	}
	lines, err := p.Plan(drivers.NewConfig(pre), drivers.NewConfig(version))
	if err != nil {
		return nil, err
	}
	out := make([]Rendered, len(lines))
	for i, l := range lines {
		out[i] = Rendered{Step: 1, Line: l}
	}
	return out, nil
}

/* restoreDiff is the masked diff between the running configuration and the version, shown only as text. */
func restoreDiff(ctx context.Context, drv drivers.WriteDriver, cur, version string, id int64) string {
	mask := func(t string) string { return strings.ToValidUTF8(drv.MaskSecrets(t), "?") }
	d, err := textdiff.Unified(ctx, "running", fmt.Sprintf("version %d", id), mask(cur), mask(version), 3, 20000)
	if err != nil {
		return "(the difference is too large to show)"
	}
	return d
}
