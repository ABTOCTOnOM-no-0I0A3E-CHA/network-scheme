package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/audit"
)

// ErrSessionExpired is returned for an unknown, expired or revoked session token.
var ErrSessionExpired = errors.New("auth: session expired")

/* Session lifetime. */
const (
	sessionIdle     = 30 * time.Minute
	sessionAbsolute = 12 * time.Hour
	stepUpValidFor  = 5 * time.Minute
)

// NewSession is a freshly opened session; Token goes to the __Host- cookie.
type NewSession struct {
	Token     string
	CSRF      string
	ExpiresAt time.Time /* absolute expiry; the idle timeout may end it earlier */
}

// Session is an authenticated request context.
type Session struct {
	UserID      int64
	Username    string
	CSRF        string
	StepUpValid bool /* a step-up TOTP was given within the last 5 minutes */
}

/* newToken returns 256 random bits as base64url and the SHA-256 that is stored. */
func newToken() (token string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, fmt.Errorf("auth: random token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, hashToken(token), nil
}

func hashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

func (s *Service) createSession(ctx context.Context, tx pgx.Tx, userID int64, ip netip.Addr, ua string, now time.Time) (NewSession, error) {
	if _, err := tx.Exec(ctx, `DELETE FROM core.session WHERE last_seen <= $1 OR created_at <= $2`,
		now.Add(-sessionIdle), now.Add(-sessionAbsolute)); err != nil {
		return NewSession{}, fmt.Errorf("auth: prune sessions: %w", err)
	}
	token, idHash, err := newToken()
	if err != nil {
		return NewSession{}, err
	}
	csrf, _, err := newToken()
	if err != nil {
		return NewSession{}, err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO core.session (id_hash, user_id, csrf_token, created_at, last_seen, ip, user_agent)
		 VALUES ($1, $2, $3, $4, $4, $5, $6)`, idHash, userID, csrf, now, ip, ua); err != nil {
		return NewSession{}, fmt.Errorf("auth: store session: %w", err)
	}
	return NewSession{Token: token, CSRF: csrf, ExpiresAt: now.Add(sessionAbsolute)}, nil
}

/*
Authenticate resolves token to its session and extends its idle timeout.
Expired sessions and sessions of disabled users are deleted.
*/
func (s *Service) Authenticate(ctx context.Context, token string) (Session, error) {
	now := s.now()
	h := hashToken(token)
	var (
		sess   Session
		stepUp *time.Time
	)
	err := s.pool.QueryRow(ctx,
		`UPDATE core.session s SET last_seen = GREATEST(s.last_seen, $2)
		 FROM core."user" u
		 WHERE s.id_hash = $1 AND u.id = s.user_id AND NOT u.disabled
		   AND s.last_seen > $3 AND s.created_at > $4
		 RETURNING s.user_id, u.username, s.csrf_token, s.stepup_at`,
		h, now, now.Add(-sessionIdle), now.Add(-sessionAbsolute)).
		Scan(&sess.UserID, &sess.Username, &sess.CSRF, &stepUp)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, err := s.pool.Exec(ctx, `DELETE FROM core.session WHERE id_hash = $1`, h); err != nil {
			return Session{}, fmt.Errorf("auth: delete session: %w", err)
		}
		return Session{}, ErrSessionExpired
	}
	if err != nil {
		return Session{}, fmt.Errorf("auth: load session: %w", err)
	}
	sess.StepUpValid = stepUp != nil && now.Sub(*stepUp) < stepUpValidFor
	return sess, nil
}

/*
StepUp re-checks the login TOTP (backup codes are not accepted) for a live
session, marks it stepped-up for 5 minutes and rotates its token: the old
token stops working. Failures count towards the account lockout.
*/
func (s *Service) StepUp(ctx context.Context, token, code string) (string, error) {
	now := s.now()
	oldHash := hashToken(token)
	var newTok string
	err := s.inTx(ctx, func(tx pgx.Tx) (error, error) {
		var (
			uid int64
			ip  netip.Addr
			ua  string
		)
		err := tx.QueryRow(ctx,
			`SELECT s.user_id, s.ip, s.user_agent FROM core.session s JOIN core."user" u ON u.id = s.user_id
			 WHERE s.id_hash = $1 AND NOT u.disabled AND s.last_seen > $2 AND s.created_at > $3`,
			oldHash, now.Add(-sessionIdle), now.Add(-sessionAbsolute)).Scan(&uid, &ip, &ua)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSessionExpired, nil
		}
		if err != nil {
			return nil, fmt.Errorf("auth: load session: %w", err)
		}
		if err := lockUser(ctx, tx, uid); err != nil {
			return nil, err
		}
		if locked, err := accountLocked(ctx, tx, uid, now); err != nil || locked {
			return lockedAs(locked, ErrLocked), err
		}
		u, err := loadUser(ctx, tx, uid)
		if err != nil {
			return nil, err
		}
		ok := false
		if u.secretEnc != nil && isTOTPCode(code) {
			if ok, err = s.useTOTP(ctx, tx, u, code, now); err != nil {
				return nil, err
			}
		}
		ev := audit.Event{
			TS: now, UserID: &uid, IP: ip.String(), UserAgent: ua, Action: "auth.stepup",
			ObjectType: "user", ObjectID: strconv.FormatInt(uid, 10), Result: "failure",
		}
		if !ok {
			lockouts, err := recordAccountFailure(ctx, tx, uid, ip.String(), now)
			if err != nil {
				return nil, err
			}
			return ErrInvalidCredentials, appendEvents(ctx, tx, append([]audit.Event{ev}, lockouts...)...)
		}

		if err := resetAccount(ctx, tx, uid); err != nil {
			return nil, err
		}
		tok, newHash, err := newToken()
		if err != nil {
			return nil, err
		}
		tag, err := tx.Exec(ctx,
			`UPDATE core.session SET id_hash = $2, stepup_at = $3, last_seen = $3 WHERE id_hash = $1`,
			oldHash, newHash, now)
		if err != nil {
			return nil, fmt.Errorf("auth: rotate session: %w", err)
		}
		if tag.RowsAffected() == 0 { /* rotated or ended concurrently: roll back */
			return nil, ErrSessionExpired
		}
		newTok, ev.Result = tok, "success"
		return nil, appendEvents(ctx, tx, ev)
	})
	if err != nil {
		return "", err
	}
	return newTok, nil
}

// Logout ends the session of token. Unknown tokens are ignored.
func (s *Service) Logout(ctx context.Context, token string) error {
	now := s.now()
	return s.inTx(ctx, func(tx pgx.Tx) (error, error) {
		var (
			uid int64
			ip  netip.Addr
			ua  string
		)
		err := tx.QueryRow(ctx,
			`DELETE FROM core.session WHERE id_hash = $1 RETURNING user_id, ip, user_agent`, hashToken(token)).
			Scan(&uid, &ip, &ua)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("auth: delete session: %w", err)
		}
		return nil, appendEvents(ctx, tx, audit.Event{
			TS: now, UserID: &uid, IP: ip.String(), UserAgent: ua, Action: "auth.logout",
			ObjectType: "user", ObjectID: strconv.FormatInt(uid, 10), Result: "success",
		})
	})
}
