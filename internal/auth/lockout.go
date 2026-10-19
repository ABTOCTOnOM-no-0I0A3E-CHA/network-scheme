package auth

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/audit"
)

/* Lockout policy. */
const (
	accountLockAfter = 5                /* consecutive failures before the first lock */
	accountLockBase  = time.Minute      /* first lock; doubled by every further failure */
	accountLockMax   = 60 * time.Minute /* cap */
	ipFailureLimit   = 20               /* more failures than this within ipWindow lock the IP */
	ipWindow         = 10 * time.Minute
	ipLockFor        = 10 * time.Minute
)

/* querier is satisfied by pgx.Tx and *pgxpool.Pool. */
type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

/* accountLockFor returns the lock length after n consecutive failures (0 = none). */
func accountLockFor(n int) time.Duration {
	if n < accountLockAfter {
		return 0
	}
	if shift := n - accountLockAfter; shift < 6 { /* 2^6 min already exceeds the cap */
		return min(accountLockBase<<shift, accountLockMax)
	}
	return accountLockMax
}

/*
lockIP and lockUser serialise the evaluation of attempts from one IP and
against one account until tx ends, so that checking a lock and counting a
failure are atomic. Always take the IP lock first.
*/
func lockIP(ctx context.Context, tx pgx.Tx, ip netip.Addr) error {
	return advisoryLock(ctx, tx, "nms-login-ip:"+ip.String())
}

/* lockUser is a no-op for userID 0 (unknown user). */
func lockUser(ctx context.Context, tx pgx.Tx, userID int64) error {
	if userID == 0 {
		return nil
	}
	return advisoryLock(ctx, tx, "nms-login-user:"+strconv.FormatInt(userID, 10))
}

func advisoryLock(ctx context.Context, tx pgx.Tx, key string) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, key); err != nil {
		return fmt.Errorf("auth: lock attempts: %w", err)
	}
	return nil
}

/* checkLocks returns ErrRateLimited or ErrLocked as the outcome when one applies. */
func checkLocks(ctx context.Context, q querier, ip netip.Addr, userID int64, now time.Time) (outcome, err error) {
	if locked, err := ipLocked(ctx, q, ip, now); err != nil || locked {
		return lockedAs(locked, ErrRateLimited), err
	}
	if locked, err := accountLocked(ctx, q, userID, now); err != nil || locked {
		return lockedAs(locked, ErrLocked), err
	}
	return nil, nil
}

func lockedAs(locked bool, e error) error {
	if locked {
		return e
	}
	return nil
}

func ipLocked(ctx context.Context, q querier, ip netip.Addr, now time.Time) (bool, error) {
	var locked bool
	err := q.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM core.ip_lock WHERE ip = $1 AND locked_until > $2)`, ip, now).Scan(&locked)
	if err != nil {
		return false, fmt.Errorf("auth: check IP lock: %w", err)
	}
	return locked, nil
}

func accountLocked(ctx context.Context, q querier, userID int64, now time.Time) (bool, error) {
	if userID == 0 {
		return false, nil
	}
	var locked bool
	err := q.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM core.account_lock WHERE user_id = $1 AND locked_until > $2)`,
		userID, now).Scan(&locked)
	if err != nil {
		return false, fmt.Errorf("auth: check account lock: %w", err)
	}
	return locked, nil
}

/*
recordAccountFailure counts a failure against userID and returns an
auth.lockout event when it locks the account. Call under lockUser.
*/
func recordAccountFailure(ctx context.Context, tx pgx.Tx, userID int64, ip string, now time.Time) ([]audit.Event, error) {
	var n int
	err := tx.QueryRow(ctx,
		`INSERT INTO core.account_lock (user_id, failures) VALUES ($1, 1)
		 ON CONFLICT (user_id) DO UPDATE SET failures = core.account_lock.failures + 1
		 RETURNING failures`, userID).Scan(&n)
	if err != nil {
		return nil, fmt.Errorf("auth: count account failure: %w", err)
	}
	d := accountLockFor(n)
	if d == 0 {
		return nil, nil
	}
	if _, err := tx.Exec(ctx,
		`UPDATE core.account_lock SET locked_until = $2 WHERE user_id = $1`, userID, now.Add(d)); err != nil {
		return nil, fmt.Errorf("auth: lock account: %w", err)
	}
	return []audit.Event{{
		TS: now, UserID: &userID, IP: ip, Action: "auth.lockout",
		ObjectType: "user", ObjectID: strconv.FormatInt(userID, 10), Result: "locked",
		Details: map[string]any{"scope": "account", "failures": n, "seconds": int(d / time.Second)},
	}}, nil
}

/*
recordFailure counts a failed login from ip (and against userID unless 0)
and returns the auth.lockout events it caused. Call under lockIP/lockUser,
after checking that neither the IP nor the account is locked.
*/
func recordFailure(ctx context.Context, tx pgx.Tx, ip netip.Addr, userID int64, now time.Time) ([]audit.Event, error) {
	var uid *int64
	if userID != 0 {
		uid = &userID
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO core.login_failure (user_id, ip, at) VALUES ($1, $2, $3)`, uid, ip, now); err != nil {
		return nil, fmt.Errorf("auth: record failure: %w", err)
	}
	/* Rows outside the window and expired IP locks no longer matter. */
	if _, err := tx.Exec(ctx, `DELETE FROM core.login_failure WHERE at <= $1`, now.Add(-ipWindow)); err != nil {
		return nil, fmt.Errorf("auth: prune failures: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM core.ip_lock WHERE locked_until <= $1`, now); err != nil {
		return nil, fmt.Errorf("auth: prune IP locks: %w", err)
	}
	var events []audit.Event
	if uid != nil {
		ev, err := recordAccountFailure(ctx, tx, userID, ip.String(), now)
		if err != nil {
			return nil, err
		}
		events = ev
	}

	var n int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM core.login_failure WHERE ip = $1 AND at > $2`, ip, now.Add(-ipWindow)).Scan(&n); err != nil {
		return nil, fmt.Errorf("auth: count IP failures: %w", err)
	}
	if n <= ipFailureLimit {
		return events, nil
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO core.ip_lock (ip, locked_until) VALUES ($1, $2)
		 ON CONFLICT (ip) DO UPDATE SET locked_until = EXCLUDED.locked_until`, ip, now.Add(ipLockFor)); err != nil {
		return nil, fmt.Errorf("auth: lock IP: %w", err)
	}
	return append(events, audit.Event{
		TS: now, UserID: uid, IP: ip.String(), Action: "auth.lockout",
		ObjectType: "ip", ObjectID: ip.String(), Result: "locked",
		Details: map[string]any{"scope": "ip", "failures": n, "seconds": int(ipLockFor / time.Second)},
	}), nil
}

/* resetAccount clears the consecutive-failure counter after a successful login. */
func resetAccount(ctx context.Context, tx pgx.Tx, userID int64) error {
	if _, err := tx.Exec(ctx, `DELETE FROM core.account_lock WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("auth: reset lockout: %w", err)
	}
	return nil
}
