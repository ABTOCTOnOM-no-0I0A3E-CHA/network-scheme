package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/internal/audit"
	nmscrypto "github.com/beekamai/network-scheme/internal/crypto"
	"github.com/beekamai/network-scheme/internal/secret"
)

/*
Login errors. ErrInvalidCredentials is the single answer for an unknown or
disabled user, a wrong password, a wrong or replayed code and an unknown or
used challenge.
*/
var (
	ErrInvalidCredentials = errors.New("auth: invalid credentials")
	ErrLocked             = errors.New("auth: account temporarily locked")
	ErrRateLimited        = errors.New("auth: too many failed attempts from this address")
	ErrChallengeExpired   = errors.New("auth: login challenge expired")
)

const (
	challengeTTL = 5 * time.Minute
	totpIssuer   = "network-scheme"
	maxUserAgent = 512 /* bytes kept of the untrusted User-Agent */
)

/* Login step kinds. */
const (
	kindTOTP   = "totp"
	kindEnroll = "enroll"
)

// LoginStep is the second step a password login must complete.
type LoginStep struct {
	Kind        string /* "totp" or "enroll" */
	ChallengeID string
	OTPAuthURI  string /* enroll only: the new secret to show as a QR code */
}

/*
Service is the login flow with mandatory TOTP, lockouts and server-side
sessions.
*/
type Service struct {
	pool     *pgxpool.Pool
	key      *[32]byte
	now      func() time.Time
	provider Provider
}

/*
NewService returns a Service over pool. dataKey (32 bytes, the api_data_key
docker secret) seals TOTP secrets; clock defaults to time.Now.
*/
func NewService(pool *pgxpool.Pool, dataKey *[32]byte, clock func() time.Time) *Service {
	if clock == nil {
		clock = time.Now
	}
	return &Service{pool: pool, key: dataKey, now: clock, provider: NewLocalProvider(pool)}
}

/*
BeginLogin checks username and password from ip. On success it returns a
5-minute challenge: "totp" for an enrolled user, "enroll" with a fresh
otpauth URI otherwise.
*/
func (s *Service) BeginLogin(ctx context.Context, username, password, ip string) (LoginStep, error) {
	now := s.now()
	addr, err := parseIP(ip)
	if err != nil {
		return LoginStep{}, err
	}
	/* Refuse locked attempts before spending an Argon2 computation on them. */
	uid, err := s.lookupUser(ctx, username)
	if err != nil {
		return LoginStep{}, err
	}
	if outcome, err := checkLocks(ctx, s.pool, addr, uid, now); err != nil {
		return LoginStep{}, err
	} else if outcome != nil {
		return LoginStep{}, outcome
	}

	vid, verr := s.provider.Verify(ctx, username, password)
	if verr != nil && !errors.Is(verr, ErrInvalidCredentials) {
		return LoginStep{}, verr
	}
	if verr == nil {
		uid = vid
	}

	var step LoginStep
	err = s.inTx(ctx, func(tx pgx.Tx) (error, error) {
		/* Concurrent attempts may have locked the IP or account meanwhile. */
		if err := lockIP(ctx, tx, addr); err != nil {
			return nil, err
		}
		if err := lockUser(ctx, tx, uid); err != nil {
			return nil, err
		}
		if outcome, err := checkLocks(ctx, tx, addr, uid, now); outcome != nil || err != nil {
			return outcome, err
		}
		if verr != nil {
			reason := "bad_password"
			if uid == 0 {
				reason = "unknown_user"
			}
			return s.fail(ctx, tx, addr, uid, "", reason, now)
		}
		var err error
		step, err = s.newChallenge(ctx, tx, uid, now)
		return nil, err
	})
	if err != nil {
		return LoginStep{}, err
	}
	return step, nil
}

/*
CompleteTOTP finishes a "totp" challenge with a TOTP code or a single-use
backup code and opens a session. The challenge is consumed by any attempt.
*/
func (s *Service) CompleteTOTP(ctx context.Context, challengeID, code, ip, ua string) (NewSession, error) {
	return s.complete(ctx, challengeID, code, ip, ua, kindTOTP, s.checkLoginCode)
}

/*
CompleteEnroll finishes an "enroll" challenge: code must come from the secret
shown in the otpauth URI. It stores the secret, opens a session and returns
the 10 backup codes (shown once; only their hashes are kept).
*/
func (s *Service) CompleteEnroll(ctx context.Context, challengeID, code, ip, ua string) (NewSession, []string, error) {
	var codes []string
	ns, err := s.complete(ctx, challengeID, code, ip, ua, kindEnroll,
		func(ctx context.Context, tx pgx.Tx, c challenge, u loginUser, code string, now time.Time) (bool, string, error) {
			if u.secretEnc != nil { /* enrolled meanwhile through another challenge */
				return false, "", nil
			}
			sec, err := s.open(c.pendingEnc, enrollAAD(u.id))
			if err != nil {
				return false, "", err
			}
			step, ok := ValidateTOTP(strings.TrimSpace(code), sec, u.lastStep, now)
			if !ok {
				return false, "", nil
			}
			enc, err := nmscrypto.Seal(s.key, []byte(sec.Reveal()), loginAAD(u.id))
			if err != nil {
				return false, "", err
			}
			plain, hashes := GenerateBackupCodes()
			if _, err := tx.Exec(ctx,
				`UPDATE core."user" SET totp_secret_enc = $2, totp_last_step = $3, backup_hashes = $4 WHERE id = $1`,
				u.id, enc, step, hashes); err != nil {
				return false, "", fmt.Errorf("auth: store TOTP secret: %w", err)
			}
			codes = plain
			return true, "totp", nil
		})
	if err != nil {
		return NewSession{}, nil, err
	}
	return ns, codes, nil
}

/* challenge is a consumed core.login_challenge row. */
type challenge struct {
	userID     int64
	kind       string
	pendingEnc []byte
	expires    time.Time
}

/* loginUser is the core."user" row a second factor is checked against. */
type loginUser struct {
	id        int64
	disabled  bool
	secretEnc []byte
	lastStep  int64
	backup    [][]byte
}

/*
secondFactor checks code inside tx and stores its effect (used step or backup
code). ok=false is a credential failure; method names the factor for audit.
*/
type secondFactor func(ctx context.Context, tx pgx.Tx, c challenge, u loginUser, code string, now time.Time) (ok bool, method string, err error)

func (s *Service) complete(ctx context.Context, challengeID, code, ip, ua, kind string, check secondFactor) (NewSession, error) {
	now := s.now()
	addr, err := parseIP(ip)
	if err != nil {
		return NewSession{}, err
	}
	ua = cleanUserAgent(ua)
	var ns NewSession
	err = s.inTx(ctx, func(tx pgx.Tx) (error, error) {
		if err := lockIP(ctx, tx, addr); err != nil {
			return nil, err
		}
		if outcome, err := checkLocks(ctx, tx, addr, 0, now); outcome != nil || err != nil {
			return outcome, err
		}
		c, found, err := consumeChallenge(ctx, tx, challengeID)
		if err != nil {
			return nil, err
		}
		if !found {
			return s.fail(ctx, tx, addr, 0, ua, "unknown_challenge", now)
		}
		if !now.Before(c.expires) {
			return ErrChallengeExpired, nil
		}
		if err := lockUser(ctx, tx, c.userID); err != nil {
			return nil, err
		}
		if outcome, err := checkLocks(ctx, tx, addr, c.userID, now); outcome != nil || err != nil {
			return outcome, err
		}
		u, err := loadUser(ctx, tx, c.userID)
		if err != nil {
			return nil, err
		}
		ok, method := false, ""
		if c.kind == kind && !u.disabled {
			if ok, method, err = check(ctx, tx, c, u, code, now); err != nil {
				return nil, err
			}
		}
		if !ok {
			return s.fail(ctx, tx, addr, c.userID, ua, "bad_code", now)
		}

		if err := resetAccount(ctx, tx, c.userID); err != nil {
			return nil, err
		}
		if ns, err = s.createSession(ctx, tx, c.userID, addr, ua, now); err != nil {
			return nil, err
		}
		ev := audit.Event{
			TS: now, UserID: &c.userID, IP: addr.String(), UserAgent: ua,
			ObjectType: "user", ObjectID: strconv.FormatInt(c.userID, 10), Result: "success",
		}
		var events []audit.Event
		if kind == kindEnroll {
			enroll := ev
			enroll.Action = "auth.enroll"
			events = append(events, enroll)
		}
		ev.Action, ev.Details = "auth.login.success", map[string]any{"method": method}
		return nil, appendEvents(ctx, tx, append(events, ev)...)
	})
	if err != nil {
		return NewSession{}, err
	}
	return ns, nil
}

/* checkLoginCode is the secondFactor of CompleteTOTP: a TOTP code or a backup code. */
func (s *Service) checkLoginCode(ctx context.Context, tx pgx.Tx, _ challenge, u loginUser, code string, now time.Time) (bool, string, error) {
	if u.secretEnc == nil { /* TOTP reset after the challenge was issued */
		return false, "", nil
	}
	code = strings.TrimSpace(code)
	if isTOTPCode(code) {
		ok, err := s.useTOTP(ctx, tx, u, code, now)
		return ok, "totp", err
	}
	ok, err := useBackupCode(ctx, tx, u, code)
	return ok, "backup_code", err
}

/* useTOTP validates a login TOTP code and records its step against replay. */
func (s *Service) useTOTP(ctx context.Context, tx pgx.Tx, u loginUser, code string, now time.Time) (bool, error) {
	sec, err := s.open(u.secretEnc, loginAAD(u.id))
	if err != nil {
		return false, err
	}
	step, ok := ValidateTOTP(code, sec, u.lastStep, now)
	if !ok {
		return false, nil
	}
	if _, err := tx.Exec(ctx, `UPDATE core."user" SET totp_last_step = $2 WHERE id = $1`, u.id, step); err != nil {
		return false, fmt.Errorf("auth: record TOTP step: %w", err)
	}
	return true, nil
}

/* useBackupCode consumes a matching backup code (case-insensitive). */
func useBackupCode(ctx context.Context, tx pgx.Tx, u loginUser, code string) (bool, error) {
	h := sha256.Sum256([]byte(strings.ToUpper(code)))
	for i, stored := range u.backup {
		if subtle.ConstantTimeCompare(h[:], stored) != 1 {
			continue
		}
		rest := slices.Delete(slices.Clone(u.backup), i, i+1)
		if _, err := tx.Exec(ctx, `UPDATE core."user" SET backup_hashes = $2 WHERE id = $1`, u.id, rest); err != nil {
			return false, fmt.Errorf("auth: consume backup code: %w", err)
		}
		return true, nil
	}
	return false, nil
}

func isTOTPCode(code string) bool {
	if len(code) != 6 {
		return false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

/*
fail records a credential failure and its audit events and yields
ErrInvalidCredentials as the outcome, so the caller commits the counters.
*/
func (s *Service) fail(ctx context.Context, tx pgx.Tx, ip netip.Addr, userID int64, ua, reason string, now time.Time) (error, error) {
	lockouts, err := recordFailure(ctx, tx, ip, userID, now)
	if err != nil {
		return nil, err
	}
	ev := audit.Event{
		TS: now, IP: ip.String(), UserAgent: ua, Action: "auth.login.failure",
		ObjectType: "user", Result: "failure", Details: map[string]any{"reason": reason},
	}
	if userID != 0 {
		ev.UserID, ev.ObjectID = &userID, strconv.FormatInt(userID, 10)
	}
	return ErrInvalidCredentials, appendEvents(ctx, tx, append([]audit.Event{ev}, lockouts...)...)
}

/* newChallenge issues the second login step for an authenticated password. */
func (s *Service) newChallenge(ctx context.Context, tx pgx.Tx, userID int64, now time.Time) (LoginStep, error) {
	if _, err := tx.Exec(ctx, `DELETE FROM core.login_challenge WHERE expires_at <= $1`, now); err != nil {
		return LoginStep{}, fmt.Errorf("auth: prune challenges: %w", err)
	}
	var (
		name     string
		enrolled bool
	)
	if err := tx.QueryRow(ctx,
		`SELECT username, totp_secret_enc IS NOT NULL FROM core."user" WHERE id = $1`, userID).Scan(&name, &enrolled); err != nil {
		return LoginStep{}, fmt.Errorf("auth: load user: %w", err)
	}
	id, idHash, err := newToken()
	if err != nil {
		return LoginStep{}, err
	}
	step := LoginStep{Kind: kindTOTP, ChallengeID: id}
	var pending []byte
	if !enrolled {
		sec, uri, err := NewTOTPSecret(totpIssuer, name)
		if err != nil {
			return LoginStep{}, fmt.Errorf("auth: new TOTP secret: %w", err)
		}
		if pending, err = nmscrypto.Seal(s.key, []byte(sec.Reveal()), enrollAAD(userID)); err != nil {
			return LoginStep{}, err
		}
		step.Kind, step.OTPAuthURI = kindEnroll, uri
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO core.login_challenge (id_hash, user_id, kind, pending_secret_enc, expires_at)
		 VALUES ($1, $2, $3, $4, $5)`, idHash, userID, step.Kind, pending, now.Add(challengeTTL)); err != nil {
		return LoginStep{}, fmt.Errorf("auth: store challenge: %w", err)
	}
	return step, nil
}

func consumeChallenge(ctx context.Context, tx pgx.Tx, id string) (challenge, bool, error) {
	var c challenge
	err := tx.QueryRow(ctx,
		`DELETE FROM core.login_challenge WHERE id_hash = $1
		 RETURNING user_id, kind, pending_secret_enc, expires_at`, hashToken(id)).
		Scan(&c.userID, &c.kind, &c.pendingEnc, &c.expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return challenge{}, false, nil
	}
	if err != nil {
		return challenge{}, false, fmt.Errorf("auth: consume challenge: %w", err)
	}
	return c, true, nil
}

/* loadUser reads and row-locks a user, serialising code checks per user. */
func loadUser(ctx context.Context, tx pgx.Tx, id int64) (loginUser, error) {
	u := loginUser{id: id}
	err := tx.QueryRow(ctx,
		`SELECT disabled, totp_secret_enc, totp_last_step, backup_hashes FROM core."user" WHERE id = $1 FOR UPDATE`, id).
		Scan(&u.disabled, &u.secretEnc, &u.lastStep, &u.backup)
	if err != nil {
		return loginUser{}, fmt.Errorf("auth: load user: %w", err)
	}
	return u, nil
}

/* lookupUser returns the id of username, or 0 when it is malformed or unknown. */
func (s *Service) lookupUser(ctx context.Context, username string) (int64, error) {
	name, err := NormalizeUsername(username)
	if err != nil {
		return 0, nil
	}
	var id int64
	err = s.pool.QueryRow(ctx, `SELECT id FROM core."user" WHERE username = $1`, name).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("auth: look up user: %w", err)
	}
	return id, nil
}

func loginAAD(userID int64) []byte  { return []byte("totp-login:" + strconv.FormatInt(userID, 10)) }
func enrollAAD(userID int64) []byte { return []byte("totp-enroll:" + strconv.FormatInt(userID, 10)) }

func (s *Service) open(box, aad []byte) (secret.Secret, error) {
	pt, err := nmscrypto.Open(s.key, box, aad)
	if err != nil {
		return secret.Secret{}, fmt.Errorf("auth: open TOTP secret: %w", err)
	}
	return secret.New(string(pt)), nil
}

/*
inTx runs fn in a READ COMMITTED transaction. A nil err commits and then
returns outcome: credential failures must persist their counters and audit.
*/
func (s *Service) inTx(ctx context.Context, fn func(pgx.Tx) (outcome, err error)) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("auth: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() /* no-op after Commit */
	outcome, err := fn(tx)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("auth: commit: %w", err)
	}
	return outcome
}

/* appendEvents writes events to the audit chain; call it last in the transaction. */
func appendEvents(ctx context.Context, tx pgx.Tx, events ...audit.Event) error {
	for _, e := range events {
		if _, err := audit.Append(ctx, tx, e); err != nil {
			return err
		}
	}
	return nil
}

func parseIP(ip string) (netip.Addr, error) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.Addr{}, errors.New("auth: invalid client address")
	}
	return a.Unmap().WithZone(""), nil
}

/* cleanUserAgent makes the untrusted header storable: valid UTF-8, no NUL, bounded. */
func cleanUserAgent(ua string) string {
	ua = strings.ReplaceAll(strings.ToValidUTF8(ua, ""), "\x00", "")
	if len(ua) <= maxUserAgent {
		return ua
	}
	cut := maxUserAgent
	for cut > 0 && !utf8.RuneStart(ua[cut]) {
		cut--
	}
	return ua[:cut]
}
