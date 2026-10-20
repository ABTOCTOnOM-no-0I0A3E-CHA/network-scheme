package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

/*
Provider checks a username and password. Implementations return
ErrInvalidCredentials for an unknown or disabled user and for a wrong
password alike; any other error is an infrastructure failure.
*/
type Provider interface {
	Name() string
	Verify(ctx context.Context, username, password string) (userID int64, err error)
}

// LocalProvider verifies passwords against the Argon2id hashes in core."user".
type LocalProvider struct {
	pool *pgxpool.Pool
}

/* dummyPHC is verified for unknown names so they cost as much as real ones. */
var dummyPHC = sync.OnceValue(func() string {
	phc, err := HashPassword("nms-dummy-password-for-timing", DefaultArgon2)
	if err != nil {
		panic("auth: entropy source failed: " + err.Error())
	}
	return phc
})

// NewLocalProvider returns a provider over pool and precomputes its timing-equaliser hash.
func NewLocalProvider(pool *pgxpool.Pool) *LocalProvider {
	dummyPHC()
	return &LocalProvider{pool: pool}
}

// Name implements Provider.
func (*LocalProvider) Name() string { return "local" }

/*
Verify implements Provider. A hash with outdated parameters is upgraded on a
successful match (best effort: a failed upgrade is retried at the next login).
*/
func (p *LocalProvider) Verify(ctx context.Context, username, password string) (int64, error) {
	name, err := NormalizeUsername(username)
	if err != nil {
		_, _, _ = VerifyPassword(password, dummyPHC())
		return 0, ErrInvalidCredentials
	}
	var (
		id       int64
		phc      string
		disabled bool
	)
	err = p.pool.QueryRow(ctx,
		`SELECT id, password_phc, disabled FROM core."user" WHERE username = $1`, name).Scan(&id, &phc, &disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		_, _, _ = VerifyPassword(password, dummyPHC())
		return 0, ErrInvalidCredentials
	}
	if err != nil {
		return 0, fmt.Errorf("auth: load user: %w", err)
	}
	ok, rehash, err := VerifyPassword(password, phc)
	if err != nil {
		return 0, fmt.Errorf("auth: stored password hash of user %d: %w", id, err)
	}
	if !ok || disabled {
		return 0, ErrInvalidCredentials
	}
	if rehash {
		if fresh, err := HashPassword(password, DefaultArgon2); err == nil {
			_, _ = p.pool.Exec(ctx,
				`UPDATE core."user" SET password_phc = $1 WHERE id = $2 AND password_phc = $3`, fresh, id, phc)
		}
	}
	return id, nil
}
