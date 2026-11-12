package backups

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/internal/backup"
	"github.com/beekamai/network-scheme/internal/backup/open"
	rdrivers "github.com/beekamai/network-scheme/internal/drivers"
)

/* Bounds of a version's read: the row on its own connection, above registry.MaxMessage (variables for the tests). */
var (
	MaxVersion  = 4 << 20             /* backups.config_version.size and full_ct are bounded to 4 MiB (+1 KiB) */
	versionRow  = MaxVersion + 64<<10 /* the row's message */
	versionTime = 10 * time.Second
)

/* Errors of OpenVersion. */
var (
	/* ErrVersionUnknown: no version of that id for that device (another device's version is unknown here). */
	ErrVersionUnknown = errors.New("backups: no such configuration version of the device")
	/* ErrVersionTampered: the row is oversized, its hash is not the wanted one, the envelope does not open or the text does not hash to it. */
	ErrVersionTampered = errors.New("backups: the configuration version fails its checks")
)

/* Version is a configuration version opened and checked. */
type Version struct {
	Text    string
	SHA256  [32]byte
	TakenAt time.Time
}

/*
OpenVersion reads version of device from backups.config_version on its own
connection (the only read here above registry.MaxMessage), opens its full
envelope under AAD(device, hex(sha256)) with the backup domain's keys and
checks sha256(normalize(text)) == the row's sha256; want, if set, must be
the row's hash (a confirmed one). Callers alert on ErrVersionTampered.
*/
func OpenVersion(ctx context.Context, pool *pgxpool.Pool, priv, pub *[32]byte, device, version int64, want string) (Version, error) {
	cc := pool.Config().ConnConfig.Copy()
	cc.BuildFrontend = func(r io.Reader, w io.Writer) *pgproto3.Frontend {
		f := pgproto3.NewFrontend(r, w)
		f.SetMaxBodyLen(versionRow)
		return f
	}
	qctx, cancel := context.WithTimeout(ctx, versionTime)
	defer cancel()
	conn, err := pgx.ConnectConfig(qctx, cc)
	if err != nil {
		return Version{}, err
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	var (
		sum, ct, dek []byte
		v            Version
	)
	err = conn.QueryRow(qctx, `SELECT sha256, full_ct, full_dek_ct, taken_at FROM backups.config_version WHERE id = $1 AND device_id = $2`,
		version, device).Scan(&sum, &ct, &dek, &v.TakenAt)
	var big *pgproto3.ExceededMaxBodyLenErr
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return Version{}, ErrVersionUnknown
	case errors.As(err, &big):
		return Version{}, fmt.Errorf("%w: the row is larger than any configuration", ErrVersionTampered)
	case err != nil:
		return Version{}, err
	}
	hexSum := hex.EncodeToString(sum)
	if len(sum) != sha256.Size || want != "" && hexSum != want {
		return Version{}, fmt.Errorf("%w: the row's hash is not the wanted one", ErrVersionTampered)
	}
	pt, err := open.Open(priv, pub, ct, dek, backup.AAD(device, hexSum))
	if err != nil {
		return Version{}, fmt.Errorf("%w: the envelope does not open under its AAD", ErrVersionTampered)
	}
	defer clear(pt)
	if got := sha256.Sum256([]byte(rdrivers.NormalizeText(string(pt)))); len(pt) > MaxVersion || hex.EncodeToString(got[:]) != hexSum {
		return Version{}, fmt.Errorf("%w: the opened configuration does not hash to its row", ErrVersionTampered)
	}
	v.Text, v.SHA256 = string(pt), [32]byte(sum)
	return v, nil
}
