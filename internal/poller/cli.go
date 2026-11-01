package poller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/ssh"
)

/*
errInSession: the executor holds the device in an open change session
(execpub.device_busy), or whether it does could not be read.
*/
var errInSession = errors.New("poller: device in a change session of the executor")

/* busyCheckTimeout bounds the read of execpub.device_busy (a variable for the tests). */
var busyCheckTimeout = 5 * time.Second

/*
dialSSH is the poller's only way to open a device's CLI (inventory, backup,
show): the read-only SSH session is opened only when execpub.device_busy has
no row for the device. It fails closed: when that cannot be read (database
error, lost grant, timeout) nothing is dialed either, since a session the
poller cannot see may be running and an extra login would show up in it
(ESR exclusive mode, `show users`) or race its configuration. This gates SSH
only: availability, metrics and the SNMP part of inventory never ask, so a
broken check costs the CLI tables, backups and show commands, never the
monitoring. The check and the dial are not atomic: a session opened right
after the check meets a poller session already running (the executor's
exclusive strategy is the defence there, 4b.5).
*/
func (p *Poller) dialSSH(ctx context.Context, d device, c creds.Credential, dl ssh.Dialect) (*ssh.Runner, error) {
	if err := p.checkNotInSession(ctx, d.ID); err != nil {
		return nil, err
	}
	return ssh.Dial(ctx, netip.AddrPortFrom(d.Addr.Addr(), p.sshPort), d.ID, c, p.hostKeys, dl)
}

/* checkNotInSession is nil only when execpub.device_busy was read and holds no row for the device. */
func (p *Poller) checkNotInSession(ctx context.Context, id int64) error {
	ctx, cancel := context.WithTimeout(ctx, busyCheckTimeout)
	defer cancel()
	var busy bool
	if err := p.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM execpub.device_busy WHERE device_id = $1)`, id).Scan(&busy); err != nil {
		p.log.Warn("change session check failed: no SSH to the device", slog.Int64("device_id", id), slog.String("err", err.Error()))
		return fmt.Errorf("%w: check: %w", errInSession, err)
	}
	if busy {
		return errInSession
	}
	return nil
}

/*
sessionResult reports whether sum (the normalized configuration just read)
is what a change session of the executor left on the device: the
post_sha256 of a session that closed since the previous observation of the
device (its last successful backup, else its newest version). Then the new
version is the session's, not drift. A configuration put back later outside a
session, even one equal to an older session's result, is drift. If the
check fails the version is drift (fail loud).
*/
func (p *Poller) sessionResult(ctx context.Context, id int64, sum [32]byte) bool {
	var ok bool
	err := p.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM execpub.session_summary s
		WHERE s.device_id = $1 AND s.post_sha256 = $2 AND s.status <> 'open' AND s.closed_at IS NOT NULL
		  AND s.closed_at >= coalesce((SELECT last_ok_at FROM backups.backup_state WHERE device_id = $1),
		                              (SELECT max(taken_at) FROM backups.config_version WHERE device_id = $1), '-infinity'))`,
		id, sum[:]).Scan(&ok)
	if err != nil {
		p.log.Warn("change session result check failed: version kept as drift", slog.Int64("device_id", id), slog.String("err", err.Error()))
		return false
	}
	return ok
}
