package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	nmscrypto "github.com/beekamai/network-scheme/internal/crypto"
	"github.com/beekamai/network-scheme/internal/secret"
)

/* User management errors. */
var (
	ErrUserExists   = errors.New("auth: user already exists")
	ErrUserNotFound = errors.New("auth: user not found")
)

// UserInfo is the non-secret view of a panel user.
type UserInfo struct {
	ID           int64
	Username     string
	Disabled     bool
	TOTPEnrolled bool
}

/*
UserStore manages panel users. Mutating methods run in the caller's
transaction so that the caller can audit the change atomically.
*/
type UserStore struct {
	pool *pgxpool.Pool
}

// NewUserStore returns a store over pool (used by List only).
func NewUserStore(pool *pgxpool.Pool) *UserStore { return &UserStore{pool: pool} }

/*
Create adds a user with a normalised name and an Argon2id hash of password.
The user has no TOTP yet and enrolls at the first login.
*/
func (*UserStore) Create(ctx context.Context, tx pgx.Tx, username, password string) (int64, error) {
	name, err := NormalizeUsername(username)
	if err != nil {
		return 0, err
	}
	if err := ValidateNewPassword(password); err != nil {
		return 0, err
	}
	phc, err := HashPassword(password, DefaultArgon2)
	if err != nil {
		return 0, err
	}
	var id int64
	err = tx.QueryRow(ctx,
		`INSERT INTO core."user" (username, password_phc) VALUES ($1, $2)
		 ON CONFLICT (username) DO NOTHING RETURNING id`, name, phc).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrUserExists
	}
	if err != nil {
		return 0, fmt.Errorf("auth: create user: %w", err)
	}
	return id, nil
}

// List returns all users ordered by name.
func (s *UserStore) List(ctx context.Context) ([]UserInfo, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, username, disabled, totp_secret_enc IS NOT NULL FROM core."user" ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("auth: list users: %w", err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (UserInfo, error) {
		var u UserInfo
		err := r.Scan(&u.ID, &u.Username, &u.Disabled, &u.TOTPEnrolled)
		return u, err
	})
}

// SetDisabled enables or disables a user; disabling ends all of its sessions.
func (*UserStore) SetDisabled(ctx context.Context, tx pgx.Tx, id int64, disabled bool) error {
	if err := updateUser(ctx, tx, id, `UPDATE core."user" SET disabled = $2 WHERE id = $1`, disabled); err != nil {
		return err
	}
	if disabled {
		return endSessions(ctx, tx, id)
	}
	return nil
}

/*
ResetTOTP removes the TOTP secret and backup codes and ends all sessions; the
user enrolls again at the next login.
*/
func (*UserStore) ResetTOTP(ctx context.Context, tx pgx.Tx, id int64) error {
	if err := updateUser(ctx, tx, id,
		`UPDATE core."user" SET totp_secret_enc = NULL, totp_last_step = 0, backup_hashes = '{}' WHERE id = $1`); err != nil {
		return err
	}
	return endSessions(ctx, tx, id)
}

/*
EnrollTOTP gives the user a fresh TOTP secret and 10 backup codes, stored
exactly as a completed web enrollment stores them (sealed with dataKey), and
ends its sessions. nmsctl uses it to show the break-glass admin's QR code in
the terminal. The secret and the codes are returned once and never stored in
clear.
*/
func (*UserStore) EnrollTOTP(ctx context.Context, tx pgx.Tx, id int64, dataKey *[32]byte) (sec secret.Secret, otpauthURI string, backupCodes []string, err error) {
	var name string
	err = tx.QueryRow(ctx, `SELECT username FROM core."user" WHERE id = $1`, id).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return secret.Secret{}, "", nil, ErrUserNotFound
	}
	if err != nil {
		return secret.Secret{}, "", nil, fmt.Errorf("auth: load user: %w", err)
	}
	sec, otpauthURI, err = NewTOTPSecret(totpIssuer, name)
	if err != nil {
		return secret.Secret{}, "", nil, fmt.Errorf("auth: new TOTP secret: %w", err)
	}
	enc, err := nmscrypto.Seal(dataKey, []byte(sec.Reveal()), loginAAD(id))
	if err != nil {
		return secret.Secret{}, "", nil, err
	}
	codes, hashes := GenerateBackupCodes()
	if err := updateUser(ctx, tx, id,
		`UPDATE core."user" SET totp_secret_enc = $2, totp_last_step = 0, backup_hashes = $3 WHERE id = $1`, enc, hashes); err != nil {
		return secret.Secret{}, "", nil, err
	}
	if err := endSessions(ctx, tx, id); err != nil {
		return secret.Secret{}, "", nil, err
	}
	return sec, otpauthURI, codes, nil
}

// SetPassword validates and stores a new password and ends all sessions of the user.
func (*UserStore) SetPassword(ctx context.Context, tx pgx.Tx, id int64, password string) error {
	if err := ValidateNewPassword(password); err != nil {
		return err
	}
	phc, err := HashPassword(password, DefaultArgon2)
	if err != nil {
		return err
	}
	if err := updateUser(ctx, tx, id, `UPDATE core."user" SET password_phc = $2 WHERE id = $1`, phc); err != nil {
		return err
	}
	return endSessions(ctx, tx, id)
}

func updateUser(ctx context.Context, tx pgx.Tx, id int64, sql string, args ...any) error {
	tag, err := tx.Exec(ctx, sql, append([]any{id}, args...)...)
	if err != nil {
		return fmt.Errorf("auth: update user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

/* endSessions deletes the sessions and pending login challenges of a user. */
func endSessions(ctx context.Context, tx pgx.Tx, id int64) error {
	for _, q := range []string{
		`DELETE FROM core.session WHERE user_id = $1`,
		`DELETE FROM core.login_challenge WHERE user_id = $1`,
	} {
		if _, err := tx.Exec(ctx, q, id); err != nil {
			return fmt.Errorf("auth: end sessions: %w", err)
		}
	}
	return nil
}
