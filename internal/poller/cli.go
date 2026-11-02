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
no row for the device, by its id or by the address about to be dialed. The
address matters because core.device is the api's: it may add a second row
(another snmp_port) with the address of a device in a session. The address
is resolved once and that very value is checked and dialed; an IPv4-mapped
IPv6 address is unmapped first (the dialer would reach the IPv4 host). It
fails closed: when the table cannot be read (database error, lost grant,
timeout) nothing is dialed either, since a session the poller cannot see may
be running and an extra login would show up in it (ESR exclusive mode, `show
users`) or race its configuration. This gates SSH only: availability, metrics
and the SNMP part of inventory never ask, so a broken check costs the CLI
tables, backups and show commands, never the monitoring. The check and the
dial are not atomic: a session opened right after the check meets a poller
session already running (the executor's exclusive strategy is the defence
there, 4b.5).
*/
func (p *Poller) dialSSH(ctx context.Context, d device, c creds.Credential, dl ssh.Dialect) (*ssh.Runner, error) {
	addr := d.Addr.Addr().Unmap().WithZone("")
	if err := p.checkNotInSession(ctx, d.ID, addr); err != nil {
		return nil, err
	}
	return ssh.Dial(ctx, netip.AddrPortFrom(addr, p.sshPort), d.ID, c, p.hostKeys, dl)
}

/*
checkNotInSession is nil only when execpub.device_busy was read and holds no
row for the device id nor for addr (also in its IPv4-mapped form, should the
executor ever store that).
*/
func (p *Poller) checkNotInSession(ctx context.Context, id int64, addr netip.Addr) error {
	ctx, cancel := context.WithTimeout(ctx, busyCheckTimeout)
	defer cancel()
	mapped := addr
	if addr.Is4() {
		mapped = netip.AddrFrom16(addr.As16())
	}
	var busy bool
	if err := p.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM execpub.device_busy WHERE device_id = $1 OR address = $2 OR address = $3)`,
		id, addr, mapped).Scan(&busy); err != nil {
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
