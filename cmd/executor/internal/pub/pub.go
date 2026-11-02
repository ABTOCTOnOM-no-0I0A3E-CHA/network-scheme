/*
Package pub is the executor's side of schema execpub, the one-way channel to
the panel (architecture.md 4.1): it publishes the executor's status, alerts,
the devices in an open change session and the session summaries, and it
consumes the panel's only request, execpub.freeze_request ("freeze on").

Nothing here decides anything: execpub is written by the executor and read
by the api and the poller, and the executor never reads it back for a
decision, except that a pending freeze request freezes (freeze.Guard.Request).
There is no way for the api to ask for anything else, "freeze off" included.
*/
package pub

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/cmd/executor/internal/audit"
	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/state"
)

/* Channel is the wake-up channel of freeze requests (migration 00026: an empty payload on every api INSERT). */
const Channel = "execpub_freeze"

/* MaxAlertText mirrors the CHECK on execpub.alert.text (bytes). */
const MaxAlertText = freeze.MaxAlertText

/* Pace of Run (variables for the tests). */
var (
	/* pollEvery: the freeze request is read at least this often (security.md 5.1a: frozen within 5 s, LISTEN or not). */
	pollEvery = 2 * time.Second
	/* minProbe: wake-ups (anyone may NOTIFY) read the table at most this often. */
	minProbe = 250 * time.Millisecond
	/* frozenEvery: while frozen, a pending request is consumed at most this often (a flood grows the audit chain no faster). */
	frozenEvery = time.Minute
	/* retryMax: a failed consumption is retried after 2 s, doubling up to this. */
	retryMax = time.Minute
	/* heartbeat: the status row is rewritten at least this often, so its "at" tells the panel the executor is alive. */
	heartbeat = 30 * time.Second
	/* listenRetry: a lost LISTEN connection is opened again after this. */
	listenRetry = 5 * time.Second
	/* opTimeout bounds every statement of this package. */
	opTimeout = 5 * time.Second
)

var (
	kindRe     = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	severities = map[string]bool{"info": true, "warning": true, "average": true, "high": true, "disaster": true}
	statuses   = map[string]bool{"closed": true, "timeout": true, "interrupted": true, "rolled_back": true}
)

/* ErrDeviceBusy refuses Busy for a device that another session already holds. */
var ErrDeviceBusy = errors.New("pub: device already in a change session")

/* Publisher writes execpub. */
type Publisher struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

/* New returns a publisher over the executor's pool. */
func New(pool *pgxpool.Pool, log *slog.Logger) *Publisher { return &Publisher{pool: pool, log: log} }

func (p *Publisher) exec(ctx context.Context, sql string, args ...any) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	tag, err := p.pool.Exec(ctx, sql, args...)
	return tag.RowsAffected(), err
}

/* Status records whether the executor is enabled (policy) and frozen, stamped by the database clock. */
func (p *Publisher) Status(ctx context.Context, enabled, frozen bool) error {
	_, err := p.exec(ctx, `INSERT INTO execpub.status (singleton, enabled, frozen, at) VALUES (true, $1, $2, now())
		ON CONFLICT (singleton) DO UPDATE SET enabled = excluded.enabled, frozen = excluded.frozen, at = excluded.at`, enabled, frozen)
	return err
}

/* Alert publishes an alert of kind (a system problem kind of the panel) about deviceID (0: none). */
func (p *Publisher) Alert(ctx context.Context, kind, severity string, deviceID int64, text string) error {
	if !kindRe.MatchString(kind) || !severities[severity] || deviceID < 0 {
		return fmt.Errorf("pub: bad alert %q %q %d", kind, severity, deviceID)
	}
	var dev *int64
	if deviceID > 0 {
		dev = &deviceID
	}
	_, err := p.exec(ctx, `INSERT INTO execpub.alert (kind, severity, device_id, text) VALUES ($1, $2, $3, $4)`, kind, severity, dev, freeze.CleanText(text))
	return err
}

/*
Busy marks a device as held by session: the poller opens no SSH to the
device id nor to address, which must be the address the executor connects
to (the address of its registry row, write_device, never core.device:
the api may give another device row that address). A device another session
holds is refused.
*/
func (p *Publisher) Busy(ctx context.Context, deviceID int64, address netip.Addr, session [16]byte) error {
	if !address.IsValid() || address.Zone() != "" {
		return fmt.Errorf("pub: bad address %v", address)
	}
	n, err := p.exec(ctx, `INSERT INTO execpub.device_busy (device_id, session_id, address) VALUES ($1, $2, $3) ON CONFLICT (device_id) DO NOTHING`,
		deviceID, session, address.Unmap())
	if err == nil && n == 0 {
		return ErrDeviceBusy
	}
	return err
}

/* Free releases a device held by session (only by that session). */
func (p *Publisher) Free(ctx context.Context, deviceID int64, session [16]byte) error {
	_, err := p.exec(ctx, `DELETE FROM execpub.device_busy WHERE device_id = $1 AND session_id = $2`, deviceID, session)
	return err
}

/* SessionOpened records an open session on a device for the panel's history. */
func (p *Publisher) SessionOpened(ctx context.Context, session [16]byte, userID, deviceID int64, openedAt time.Time) error {
	_, err := p.exec(ctx, `INSERT INTO execpub.session_summary (session_id, user_id, device_id, opened_at, status)
		VALUES ($1, $2, $3, $4, 'open')`, session, userID, deviceID, openedAt)
	return err
}

/*
SessionClosed ends the open summary of a session on a device, at the
database clock (the poller compares it with its own backup times): status is
how it ended, post the SHA-256 of the normalized configuration after it (nil:
unknown). The poller does not raise drift for that configuration.
*/
func (p *Publisher) SessionClosed(ctx context.Context, session [16]byte, deviceID int64, status string, post []byte) error {
	if !statuses[status] || (post != nil && len(post) != 32) {
		return fmt.Errorf("pub: bad session end %q", status)
	}
	n, err := p.exec(ctx, `UPDATE execpub.session_summary SET status = $3, closed_at = greatest(now(), opened_at), post_sha256 = $4
		WHERE session_id = $1 AND device_id = $2 AND status = 'open'`, session, deviceID, status, post)
	if err == nil && n != 1 {
		return errors.New("pub: no open session summary to close")
	}
	return err
}

/* Freezer is the part of freeze.Guard that Run uses. */
type Freezer interface {
	Frozen() (bool, string)
	Request(ctx context.Context, reason string, consume registry.Appender) error
}

/* deleteRequests deletes every pending request (no WHERE) and reads one aggregate row: count, last claimed requester, last time. */
const deleteRequests = `WITH d AS (DELETE FROM execpub.freeze_request RETURNING requested_by, at)
	SELECT count(*), (SELECT requested_by FROM d ORDER BY at DESC LIMIT 1), max(at) FROM d`

/*
Pending reports the panel's pending freeze request, if any (count, the api's
claimed requester and time): the host's freeze off and registry reset show
it, since it would freeze the executor again right after them.
*/
func (p *Publisher) Pending(ctx context.Context) (n int64, by *int64, at *time.Time, err error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	err = p.pool.QueryRow(ctx, `SELECT count(*), (SELECT requested_by FROM execpub.freeze_request ORDER BY at DESC LIMIT 1),
		max(at) FROM execpub.freeze_request`).Scan(&n, &by, &at)
	return n, by, at, err
}

/*
DropRequests deletes the panel's pending freeze requests inside tx (the
host's freeze off or registry reset, --drop-panel-request), so they go in
the transaction that lifts the freeze and its audit row records them.
*/
func DropRequests(ctx context.Context, tx pgx.Tx) (n int64, by *int64, at *time.Time, err error) {
	err = tx.QueryRow(ctx, deleteRequests).Scan(&n, &by, &at)
	return n, by, at, err
}

/*
consumeRequest is the registry.Appender of a freeze request: inside the registry
transaction that records the freeze it deletes the request (no WHERE: every
row, whatever a superuser planted) and appends one audit row, reading one
aggregate row whatever the table holds. requested_by is the api's claim,
recorded as such. A request gone by then (the host dropped it) is
freeze.ErrNoRequest: the transaction is rolled back and nothing freezes.
*/
func consumeRequest(ctx context.Context, tx pgx.Tx, head state.AuditHead) (state.AuditHead, error) {
	var n int64
	var by *int64
	var at *time.Time
	if err := tx.QueryRow(ctx, deleteRequests).Scan(&n, &by, &at); err != nil {
		return head, fmt.Errorf("pub: consume freeze request: %w", err)
	}
	if n == 0 {
		return head, freeze.ErrNoRequest /* dropped by the host meanwhile: nothing to freeze */
	}
	return audit.Append(audit.Event{UA: "panel", Action: "executor.freeze.panel", Object: "executor", Result: audit.OK,
		Details: map[string]any{"requests": n, "claimed_user_id": by, "requested_at": at}})(ctx, tx, head)
}

/*
Consumer runs the freeze request loop and keeps execpub.status current. Wake,
wired to freeze.Guard.Published, makes it publish a status change at once.
*/
type Consumer struct {
	pub   *Publisher
	g     Freezer
	state func() (enabled, frozen bool)
	wake  chan struct{}
	/* probes counts the reads of freeze_request (the tests check the wake-up bound). */
	probes atomic.Int64
}

/* NewConsumer returns the loop of g; state reports what execpub.status publishes. */
func NewConsumer(p *Publisher, g Freezer, state func() (enabled, frozen bool)) *Consumer {
	return &Consumer{pub: p, g: g, state: state, wake: make(chan struct{}, 1)}
}

/* Wake asks the loop to run now; it never blocks (wake-ups coalesce). */
func (c *Consumer) Wake() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

/*
Run publishes the status and consumes freeze requests until ctx ends. It
reads freeze_request every pollEvery and on every LISTEN wake-up (at most
every minProbe; the payload is never read), so a request freezes within
pollEvery even without LISTEN. A pending request is consumed at once while
the executor is not frozen; while it is, at most every frozenEvery (a flood
by the api then grows nothing but that). A failed consumption is retried
with backoff and leaves the executor frozen (Request latches first).
*/
func (c *Consumer) Run(ctx context.Context) {
	listened := make(chan struct{})
	go func() {
		defer close(listened)
		c.listen(ctx)
	}()
	defer func() { <-listened }()
	t := time.NewTicker(pollEvery)
	defer t.Stop()
	var (
		published    bool
		last         [2]bool
		lastAt       time.Time
		lastProbe    time.Time
		next         time.Time
		backoff      time.Duration
		probeBlocked bool
	)
	for {
		if en, fr := c.state(); !published || last != [2]bool{en, fr} || time.Since(lastAt) >= heartbeat {
			if err := c.pub.Status(ctx, en, fr); err != nil {
				c.pub.log.Error("execpub.status: cannot publish", slog.Any("err", err))
				published = false
			} else {
				published, last, lastAt = true, [2]bool{en, fr}, time.Now()
			}
		}
		if probeBlocked = time.Since(lastProbe) < minProbe; !probeBlocked {
			lastProbe = time.Now()
			c.probes.Add(1)
			frozen, _ := c.g.Frozen()
			if !frozen || !time.Now().Before(next) {
				switch err := c.consume(ctx); {
				case err == nil:
					backoff, next = 0, time.Now().Add(frozenEvery)
				case errors.Is(err, errNoRequest), errors.Is(err, freeze.ErrNoRequest):
				default:
					c.pub.log.Error("freeze request: not consumed, retrying", slog.Any("err", err))
					backoff = min(max(2*backoff, 2*time.Second), retryMax)
					next = time.Now().Add(backoff)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-c.wake:
			if probeBlocked {
				time.Sleep(minProbe) /* a wake-up flood costs at most one read every minProbe */
			}
		}
	}
}

var errNoRequest = errors.New("pub: no freeze request")

/* consume freezes if a request is pending; errNoRequest if none is. */
func (c *Consumer) consume(ctx context.Context) error {
	var by int64
	qctx, cancel := context.WithTimeout(ctx, opTimeout)
	err := c.pub.pool.QueryRow(qctx, `SELECT requested_by FROM execpub.freeze_request LIMIT 1`).Scan(&by)
	cancel()
	if errors.Is(err, pgx.ErrNoRows) {
		return errNoRequest
	}
	if err != nil {
		return fmt.Errorf("read freeze request: %w", err)
	}
	return c.g.Request(ctx, fmt.Sprintf("panel: freeze requested (panel user %d, as claimed by the api)", by), consumeRequest)
}

/*
listen holds a connection of its own (taken out of the pool, so the
notifications it queues never reach other work) LISTENing on Channel and
turns every notification into a wake-up; a lost connection is opened again
after listenRetry. Polling covers the time without it.
*/
func (c *Consumer) listen(ctx context.Context) {
	for ctx.Err() == nil {
		err := c.listenOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		c.pub.log.Warn("execpub: LISTEN lost, polling meanwhile", slog.Any("err", err))
		select {
		case <-ctx.Done():
			return
		case <-time.After(listenRetry):
		}
	}
}

func (c *Consumer) listenOnce(ctx context.Context) error {
	actx, cancel := context.WithTimeout(ctx, opTimeout)
	pc, err := c.pub.pool.Acquire(actx)
	cancel()
	if err != nil {
		return err
	}
	conn := pc.Hijack()
	defer func() {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), opTimeout)
		defer cancel()
		_ = conn.Close(cctx)
	}()
	lctx, cancel := context.WithTimeout(ctx, opTimeout)
	_, err = conn.Exec(lctx, "LISTEN "+Channel)
	cancel()
	if err != nil {
		return err
	}
	c.Wake() /* requests made while not listening */
	for {
		if _, err := conn.WaitForNotification(ctx); err != nil {
			return err
		}
		c.Wake()
	}
}

/* Compile-time check: the guard is a Freezer. */
var _ Freezer = (*freeze.Guard)(nil)
