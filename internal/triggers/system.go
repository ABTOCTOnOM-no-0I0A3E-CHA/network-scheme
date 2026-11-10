package triggers

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
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
	SystemConfigDrift     = "config_drift"
)

/*
Executor alert kinds (execpub.alert.kind, written by the executor only):
each is a system problem kind of its own with a fixed severity. A kind not
listed here (a newer executor) becomes SystemExecutorAlert with the severity
of the row and the kind in the object. executorUnfrozen is the marker the
executor writes when the host lifts a freeze; it is not a problem.
*/
const (
	SystemExecutorTamper        = "executor_tamper"
	SystemExecutorBruteforce    = "executor_bruteforce"
	SystemExecutorFreeze        = "executor_freeze"
	SystemExecutorPolicyInvalid = "executor_policy_invalid"
	SystemExecutorGuards        = "executor_guards_unwritable"
	SystemExecutorUnverifiable  = "executor_unverifiable"
	SystemHostKeyMismatchWrite  = "hostkey_mismatch_write"
	SystemMassUnmask            = "mass_unmask"
	SystemSessionInterrupted    = "session_interrupted"
	SystemSessionOutsideWindow  = "session_outside_window"
	SystemExecutorPassword      = "executor_password_expired"
	SystemExecutorLineMismatch  = "executor_line_mismatch"
	SystemExecutorRollback      = "executor_rollback_mismatch"
	SystemRecordingFailed       = "executor_recording_failed"
	SystemRecordingFull         = "executor_recording_full"
	SystemRecordingViews        = "executor_recording_views"
	SystemSessionTamper         = "executor_session_tamper"
	SystemRecordingTamper       = "executor_recording_tamper"
	SystemExecutorAlert         = "executor_alert"
	SystemExecutorUnreachable   = "executor_unreachable"
	executorUnfrozen            = "executor_unfrozen"
)

var executorSeverity = map[string]string{
	SystemExecutorTamper: "disaster", SystemExecutorBruteforce: "disaster", SystemExecutorFreeze: "warning",
	SystemExecutorPolicyInvalid: "high", SystemExecutorGuards: "high", SystemExecutorUnverifiable: "high",
	SystemHostKeyMismatchWrite: "high", SystemMassUnmask: "high", SystemSessionInterrupted: "high",
	SystemSessionOutsideWindow: "warning",
	SystemExecutorPassword:     "high", SystemExecutorLineMismatch: "high", SystemExecutorRollback: "high",
	SystemRecordingFailed: "high", SystemRecordingFull: "warning", SystemRecordingViews: "high",
	SystemSessionTamper: "high", SystemRecordingTamper: "high",
}

/*
An executor alert is an event: its problem (one per kind and device, from
the newest alert) is open while that alert is at most executorAlertFor old,
like config_drift; acknowledging does not resolve it. The freeze kinds
(executorFreezeKinds) resolve once the host lifted the freeze after them
(the executor_unfrozen marker is newer), and stay open, whatever their age,
while the executor may be frozen: its status says frozen, or the status is
stale (older than executorStaleAfter: a stale row never hides a problem).
Only while a fresh status says frozen does the newest freeze alert also stay
open behind a newer marker (a marker whose publication was retried can land
after the freeze that followed it); a stale status keeps open only freeze
alerts newer than the last marker, so a freeze lifted long ago does not
reopen whenever the executor stops publishing. A stale status of an enabled
executor is itself a problem (executor_unreachable, high).
*/
const (
	executorAlertFor   = 24 * time.Hour
	executorStaleAfter = 90 * time.Second /* the executor rewrites its status every 30 s; as GET /api/executor/status */
)

var executorFreezeKinds = []string{SystemExecutorTamper, SystemExecutorBruteforce, SystemExecutorFreeze}

/*
config_drift (warning) is open while the newest configuration version of a
device is drift (a change outside a change session of the panel; before
phase 4 every change) and is at most configDriftFor old. It resolves when that
time has passed or when a newer version that is not drift is stored, never
earlier on acknowledgement: an acknowledged problem stays open, but visibly
handled, until then. Only metadata columns of backups.config_version are read.
*/
const configDriftFor = 24 * time.Hour

/*
An SSH host key mismatch is a problem while the device has a pinned key
(ssh_hosts.host_key) and its newest rejected key (ssh_hosts.mismatch.at) is
later than the pin's last successful use (host_key.last_seen). Mismatch rows
are written only by inventory polls, which can be hours apart, so there is no
time window: only a later successful connection with the pinned key, or a reset
of the pin on the host (nmsctl removes the row), recovers it. A failing SNMP or
SSH poll changes neither column and so leaves the problem open. The api reads
only (device_id, at) and (device_id, last_seen), never fingerprints.
*/
/*
poller_unavailable uses the heartbeat by the database clock: the poller's own
timestamp is stored as LEAST(poller time, now()), so a fast poller clock cannot
hide a stop, and a slow one only makes it look silent sooner. A poller that
never wrote a heartbeat has no row, hence no problem (a misconfigured or never
started poller id is not detected here), and neither has one without devices.
*/
const pollerSilentAfter = 90 * time.Second /* as inventory.device_state_v */

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
	case SystemConfigDrift:
		return "Device configuration changed outside a change session"
	case SystemExecutorTamper:
		return "Executor registry or audit chain tampered with; executor frozen"
	case SystemExecutorBruteforce:
		return "Change TOTP failures of several users; executor frozen"
	case SystemExecutorFreeze:
		return "Executor frozen"
	case SystemExecutorPolicyInvalid:
		return "Executor policy invalid; executor disabled"
	case SystemExecutorGuards:
		return "Executor cannot save its change TOTP guards"
	case SystemExecutorUnverifiable:
		return "Executor registry cannot be verified"
	case SystemHostKeyMismatchWrite:
		return "SSH host key does not match the executor's pinned one"
	case SystemMassUnmask:
		return "Many unmasked configurations viewed"
	case SystemSessionInterrupted:
		return "Change session interrupted"
	case SystemSessionOutsideWindow:
		return "Change session refused outside its window"
	case SystemExecutorPassword:
		return "Write account password of a device has expired"
	case SystemExecutorLineMismatch:
		return "Device firmware line does not match its write driver"
	case SystemExecutorRollback:
		return "Configuration after rollback does not match the snapshot"
	case SystemRecordingFailed:
		return "Change session recording failed; the session sends nothing more"
	case SystemRecordingFull:
		return "Change session recording reached its size limit"
	case SystemRecordingViews:
		return "Too many change session recordings viewed"
	case SystemSessionTamper:
		return "Change session row fails its integrity check"
	case SystemRecordingTamper:
		return "Change session recording fails its integrity check"
	case SystemExecutorAlert:
		return "Executor alert"
	case SystemExecutorUnreachable:
		return "Executor does not publish its status"
	}
	return "System problem"
}

/*
executorAlerts adds to want the problems of the executor's alerts (see
executorAlertFor). The text is the executor's and may carry device data: it
is only the problem's value, sanitized like any device text. An alert about a
device the panel no longer has is kept as a problem without a device (object
"device:<id>"), never dropped.
*/
func (e *Engine) executorAlerts(ctx context.Context, want map[pkey]sysWant, now time.Time) error {
	var known, enabled, frozen, stale bool
	err := e.pool.QueryRow(ctx, `SELECT enabled, frozen, at < now() - make_interval(secs => $1) FROM execpub.status`,
		executorStaleAfter.Seconds()).Scan(&enabled, &frozen, &stale)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return fmt.Errorf("triggers: executor status: %w", err)
	default:
		known = true
	}
	frozenNow, mayBeFrozen := known && !stale && frozen, known && (frozen || stale)
	if known && stale && enabled {
		want[pkey{sys: SystemExecutorUnreachable, obj: "executor"}] = sysWant{"high",
			fmt.Sprintf("the executor has not published its status for over %s", executorStaleAfter)}
	}
	rows, err := e.pool.Query(ctx, `
		WITH unfrozen AS (SELECT coalesce(max(at), '-infinity') AS at FROM execpub.alert WHERE kind = $3),
		newest AS (SELECT coalesce(max(at), '-infinity') AS at FROM execpub.alert WHERE kind = ANY ($2)),
		last AS (
		    SELECT DISTINCT ON (a.kind, coalesce(a.device_id, 0)) a.kind, a.device_id, a.severity, a.text, a.at
		    FROM execpub.alert a, unfrozen u, newest w
		    WHERE a.kind <> $3 AND (a.at > $1 OR (a.kind = ANY ($2) AND (a.at > u.at OR a.at = w.at)))
		    ORDER BY a.kind, coalesce(a.device_id, 0), a.at DESC, a.id DESC)
		SELECT l.kind, coalesce(l.device_id, 0), d.id IS NOT NULL, l.severity, l.text, l.at > $1, l.at > u.at, l.at = w.at
		FROM last l CROSS JOIN unfrozen u CROSS JOIN newest w LEFT JOIN core.device d ON d.id = l.device_id`,
		now.Add(-executorAlertFor), executorFreezeKinds, executorUnfrozen)
	if err != nil {
		return fmt.Errorf("triggers: executor alerts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var kind, sev, text string
		var dev int64
		var known, recent, sinceUnfrozen, newestFreeze bool
		if err := rows.Scan(&kind, &dev, &known, &sev, &text, &recent, &sinceUnfrozen, &newestFreeze); err != nil {
			return fmt.Errorf("triggers: executor alerts: %w", err)
		}
		open := recent
		if slices.Contains(executorFreezeKinds, kind) {
			open = ((mayBeFrozen || recent) && sinceUnfrozen) || (frozenNow && newestFreeze)
		}
		if !open {
			continue
		}
		k := pkey{sys: kind, dev: dev, obj: "executor"}
		if s, ok := executorSeverity[kind]; ok {
			sev = s
		} else {
			k.sys, k.obj = SystemExecutorAlert, "kind:"+kind
		}
		if dev != 0 && !known {
			k.dev, k.obj = 0, fmt.Sprintf("%s:device:%d", k.obj, dev)
		}
		want[k] = sysWant{sev, text}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("triggers: executor alerts: %w", err)
	}
	return nil
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
sources, access profiles in status "mismatch", configuration drift and the
executor's alerts.
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
		SELECT k.device_id FROM ssh_hosts.host_key k JOIN core.device d ON d.id = k.device_id
		WHERE (SELECT max(m.at) FROM ssh_hosts.mismatch m WHERE m.device_id = k.device_id) > k.last_seen`)
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

	rows, err = e.pool.Query(ctx, `
		SELECT v.device_id, v.id FROM (
		    SELECT DISTINCT ON (device_id) device_id, id, drift
		    FROM backups.config_version WHERE taken_at > $1
		    ORDER BY device_id, taken_at DESC, id DESC) v
		JOIN core.device d ON d.id = v.device_id
		WHERE v.drift`, now.Add(-configDriftFor))
	if err != nil {
		return fmt.Errorf("triggers: config drift check: %w", err)
	}
	for rows.Next() {
		var dev, ver int64
		if err := rows.Scan(&dev, &ver); err != nil {
			rows.Close()
			return fmt.Errorf("triggers: config drift check: %w", err)
		}
		want[pkey{sys: SystemConfigDrift, dev: dev, obj: "config"}] = sysWant{"warning", fmt.Sprintf("configuration version %d differs from the previous one", ver)}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("triggers: config drift check: %w", err)
	}

	if err := e.executorAlerts(ctx, want, now); err != nil {
		return err
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
