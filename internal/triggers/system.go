package triggers

import (
	"context"
	"fmt"
	"time"
)

/*
System problem kinds (problems.problem.system_kind). They are raised by the
engine from the state of the system itself and have no trigger row.
SystemPollerUnavailable is declared with the trigger kinds.
*/
const (
	SystemUnknownSource   = "unknown_source"
	SystemProfileMismatch = "access_profile_mismatch"
	SystemSSHMismatch     = "ssh_host_key_mismatch"
)

/*
An SSH host key mismatch is a problem while the poller keeps recording
rejected keys: ssh_hosts.mismatch rows (device_id, at; the api may read only
these two columns) newer than sshMismatchWindow. The poller retries with every
inventory poll (5 minutes by default), so a pin that was reset on the host with
nmsctl stops producing rows and the problem recovers within the window and two
evaluations.
*/
const (
	sshMismatchWindow = 30 * time.Minute
	pollerSilentAfter = 90 * time.Second /* as inventory.device_state_v */
)

/* Thresholds of the eventd flood check: more than this many unknown-source packets in the window. */
const (
	unknownSourceLimit  = 100
	unknownSourceWindow = 5 * time.Minute
	maxPollerObject     = 190 /* problem.object is bounded to 200 bytes */
)

// SystemName is the English title of a system problem kind.
func SystemName(kind string) string { return systemName(kind) }

func systemName(kind string) string {
	switch kind {
	case string(SystemPollerUnavailable):
		return "Poller is unavailable"
	case SystemUnknownSource:
		return "Events from unknown sources"
	case SystemProfileMismatch:
		return "Access profile does not match the device"
	case SystemSSHMismatch:
		return "SSH host key does not match the pinned one"
	}
	return "System problem"
}

type sysWant struct{ severity, value string }

type counterSample struct {
	at time.Time
	v  int64
}

/*
evalSystem raises and clears the system problems: a poller that owns devices
and whose heartbeat (inventory.poller_heartbeat, by the database clock) is
older than 90 s, rejected SSH host keys, a flood of packets from unknown
sources, and access profiles in status "mismatch".
*/
func (e *Engine) evalSystem(ctx context.Context, a *actions, now time.Time) error {
	want := map[pkey]sysWant{}

	rows, err := e.pool.Query(ctx, `
		SELECT h.poller_id FROM inventory.poller_heartbeat h
		WHERE h.at < now() - make_interval(secs => $1)
		  AND EXISTS (SELECT 1 FROM core.device d WHERE d.poller_id = h.poller_id)`, pollerSilentAfter.Seconds())
	if err != nil {
		return fmt.Errorf("triggers: poller check: %w", err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return fmt.Errorf("triggers: poller check: %w", err)
		}
		if len(id) <= maxPollerObject {
			want[pkey{sys: string(SystemPollerUnavailable), obj: "poller:" + id}] = sysWant{"high", "poller " + id + " has not written a heartbeat for over 90 s"}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("triggers: poller check: %w", err)
	}

	rows, err = e.pool.Query(ctx, `
		SELECT DISTINCT m.device_id FROM ssh_hosts.mismatch m JOIN core.device d ON d.id = m.device_id
		WHERE m.at > now() - make_interval(secs => $1)`, sshMismatchWindow.Seconds())
	if err != nil {
		return fmt.Errorf("triggers: ssh host key check: %w", err)
	}
	for rows.Next() {
		var dev int64
		if err := rows.Scan(&dev); err != nil {
			rows.Close()
			return fmt.Errorf("triggers: ssh host key check: %w", err)
		}
		want[pkey{sys: SystemSSHMismatch, dev: dev, obj: "ssh_host_key"}] = sysWant{"high", "the SSH host key offered by the device differs from the pinned one"}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("triggers: ssh host key check: %w", err)
	}

	rows, err = e.pool.Query(ctx, `
		SELECT p.owner_id, p.kind FROM core.access_profile p JOIN core.device d ON d.id = p.owner_id
		WHERE p.owner_kind = 'device' AND p.status = 'mismatch'`)
	if err != nil {
		return fmt.Errorf("triggers: access profile check: %w", err)
	}
	for rows.Next() {
		var dev int64
		var kind string
		if err := rows.Scan(&dev, &kind); err != nil {
			rows.Close()
			return fmt.Errorf("triggers: access profile check: %w", err)
		}
		want[pkey{sys: SystemProfileMismatch, dev: dev, obj: "profile:" + kind}] = sysWant{"high", "access profile " + kind + " has status mismatch"}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("triggers: access profile check: %w", err)
	}

	if grew, err := e.unknownSourceGrowth(ctx, now); err != nil {
		return err
	} else if grew > unknownSourceLimit {
		want[pkey{sys: SystemUnknownSource, obj: "eventd"}] = sysWant{"warning", fmt.Sprintf("%d packets from unknown sources in %s", grew, unknownSourceWindow)}
	}

	for k, w := range want {
		delete(e.sysFalse, k)
		a.open(e, openReq{key: k, severity: w.severity, value: w.value})
	}
	for k := range e.open {
		if k.sys == "" || k.trig != 0 {
			continue
		}
		if _, ok := want[k]; ok {
			continue
		}
		if e.sysFalse[k]++; e.sysFalse[k] >= recoverEvals {
			a.resolve(e, k, reasonRecovered, "", time.Time{})
		}
	}
	for k := range e.sysFalse {
		if e.open[k] == nil {
			delete(e.sysFalse, k)
		}
	}
	return nil
}

/*
unknownSourceGrowth sums the growth of eventd's unknown_source counters over
the window. A counter that went down (eventd restarted) counts from zero.
*/
func (e *Engine) unknownSourceGrowth(ctx context.Context, now time.Time) (int64, error) {
	rows, err := e.pool.Query(ctx, `SELECT instance, unknown_source FROM events.eventd_stats`)
	if err != nil {
		return 0, fmt.Errorf("triggers: eventd stats: %w", err)
	}
	cur := map[string]int64{}
	for rows.Next() {
		var inst string
		var v int64
		if err := rows.Scan(&inst, &v); err != nil {
			rows.Close()
			return 0, fmt.Errorf("triggers: eventd stats: %w", err)
		}
		cur[inst] = v
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("triggers: eventd stats: %w", err)
	}
	for inst := range e.unknown {
		if _, ok := cur[inst]; !ok {
			delete(e.unknown, inst)
		}
	}
	var total int64
	for inst, v := range cur {
		h := append(e.unknown[inst], counterSample{now, v})
		/* Keep one sample at or before the window start as the baseline. */
		for len(h) >= 2 && !h[1].at.After(now.Add(-unknownSourceWindow)) {
			h = h[1:]
		}
		e.unknown[inst] = h
		for i := 1; i < len(h); i++ {
			if h[i].v >= h[i-1].v {
				total += h[i].v - h[i-1].v
			} else {
				total += h[i].v
			}
		}
	}
	return total, nil
}
