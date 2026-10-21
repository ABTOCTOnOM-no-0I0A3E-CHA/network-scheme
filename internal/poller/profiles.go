package poller

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/devices"
)

/* Access profile statuses written by the poller. */
const (
	profileOK       = "ok"
	profileInvalid  = "invalid"
	profileWeak     = "weak"
	profileMismatch = "mismatch"
)

/* maxCiphertext is the database cap on a sealed credential; a longer one is never read. */
const maxCiphertext = 8240

/* snmpKinds are tried in this order; the first usable credential is used. */
var snmpKinds = []string{creds.KindSNMP3, creds.KindSNMP2c}

/* errNoProfile: the device has no usable credential of the wanted kinds. */
var errNoProfile = errors.New("poller: no usable credential")

/* opened is a verified (or rejected) credential, valid while the ciphertext is unchanged. */
type opened struct {
	sum  [32]byte
	cred creds.Credential
	err  error
}

/* profileStatus maps a verification failure to the status the API shows. */
func profileStatus(err error) string {
	switch {
	case err == nil:
		return profileOK
	case errors.Is(err, creds.ErrWeak):
		return profileWeak
	case errors.Is(err, creds.ErrOwnerMismatch), errors.Is(err, creds.ErrKindMismatch), errors.Is(err, creds.ErrStale):
		return profileMismatch
	default: /* undecryptable, malformed */
		return profileInvalid
	}
}

/*
credential returns the first usable credential of kinds for owner (a device
or a scan), or errNoProfile. A rejected profile gets its status and is
skipped: nothing is ever contacted with it. Other errors are database
failures.
*/
func (p *Poller) credential(ctx context.Context, owner devices.Owner, cache *devCache, kinds ...string) (creds.Credential, error) {
	type row struct {
		kind, status string
		ct           []byte
	}
	got := map[string]row{}
	/* An oversized ciphertext (nil here) is not read at all: the api is not trusted to bound it. */
	rows, err := p.pool.Query(ctx, `SELECT kind,
			CASE WHEN octet_length(ciphertext) <= $4 THEN ciphertext END, status FROM core.access_profile
		WHERE owner_kind = $1 AND owner_id = $2 AND kind = ANY($3)`, owner.Kind, owner.ID, kinds, maxCiphertext)
	if err != nil {
		return creds.Credential{}, fmt.Errorf("%w: read profiles: %w", errDB, err)
	}
	var r row
	if _, err := pgx.ForEachRow(rows, []any{&r.kind, &r.ct, &r.status}, func() error {
		got[r.kind] = r
		return nil
	}); err != nil {
		return creds.Credential{}, fmt.Errorf("%w: read profiles: %w", errDB, err)
	}
	for _, k := range kinds {
		r, ok := got[k]
		if !ok {
			continue
		}
		if r.ct == nil {
			if err := p.markOversized(ctx, owner, k, r.status); err != nil {
				return creds.Credential{}, fmt.Errorf("%w: %w", errDB, err)
			}
			continue
		}
		c, err := p.open(ctx, owner, k, r.ct, r.status, cache)
		if err == nil {
			return c, nil
		}
		if !isVerifyErr(err) {
			return creds.Credential{}, fmt.Errorf("%w: %w", errDB, err)
		}
	}
	return creds.Credential{}, errNoProfile
}

/* markOversized rejects a profile whose ciphertext exceeds the cap; it is never opened or dialed with. */
func (p *Poller) markOversized(ctx context.Context, owner devices.Owner, kind, status string) error {
	if status == profileInvalid {
		return nil
	}
	if _, err := p.pool.Exec(ctx, `UPDATE core.access_profile SET status = $4
		WHERE owner_kind = $1 AND owner_id = $2 AND kind = $3 AND octet_length(ciphertext) > $5`,
		owner.Kind, owner.ID, kind, profileInvalid, maxCiphertext); err != nil {
		return fmt.Errorf("poller: set profile status: %w", err)
	}
	p.log.Warn("credential rejected", slog.String("owner_kind", owner.Kind), slog.Int64("owner_id", owner.ID),
		slog.String("kind", kind), slog.String("status", profileInvalid))
	return nil
}

func isVerifyErr(err error) bool {
	for _, e := range []error{creds.ErrUndecryptable, creds.ErrOwnerMismatch, creds.ErrKindMismatch, creds.ErrStale, creds.ErrWeak, creds.ErrMalformed} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

/*
open verifies one sealed credential. Its created_at must not be older than
the newest one accepted for the profile (a rolled-back ciphertext is a
mismatch); a newer one advances that mark. The result is cached per
ciphertext, so an unchanged profile costs no database round trip after the
first poll.
*/
func (p *Poller) open(ctx context.Context, owner devices.Owner, kind string, ct []byte, status string, cache *devCache) (creds.Credential, error) {
	sum := sha256.Sum256(ct)
	old, cached := cache.creds[kind]
	if cached && old.sum == sum {
		return old.cred, old.err
	}
	if cached {
		old.cred.Wipe() /* the ciphertext changed: the old secret is dead */
		delete(cache.creds, kind)
	}
	last, err := p.inv.ProfileSeen(ctx, owner, kind)
	if err != nil {
		return creds.Credential{}, err
	}
	c, verr := creds.Open(p.priv, p.pub, ct, owner, kind, last, p.now())
	if verr == nil && c.CreatedAt.After(last) {
		if err := p.inv.MarkProfileSeen(ctx, owner, kind, c.CreatedAt); err != nil {
			c.Wipe()
			return creds.Credential{}, err
		}
	}
	if st := profileStatus(verr); st != status {
		/* Only for this ciphertext: a profile replaced meanwhile keeps its own (pending) status. */
		if _, err := p.pool.Exec(ctx, `UPDATE core.access_profile SET status = $4
			WHERE owner_kind = $1 AND owner_id = $2 AND kind = $3 AND ciphertext = $5`,
			owner.Kind, owner.ID, kind, st, ct); err != nil {
			c.Wipe()
			return creds.Credential{}, fmt.Errorf("poller: set profile status: %w", err)
		}
		if verr != nil {
			p.log.Warn("credential rejected", slog.String("owner_kind", owner.Kind), slog.Int64("owner_id", owner.ID),
				slog.String("kind", kind), slog.String("status", st))
		}
	}
	cache.creds[kind] = opened{sum: sum, cred: c, err: verr}
	return c, verr
}
