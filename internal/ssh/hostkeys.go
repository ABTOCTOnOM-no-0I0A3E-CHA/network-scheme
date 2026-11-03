package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	gossh "golang.org/x/crypto/ssh"
)

// ErrHostKeyMismatch means the device presented a host key other than its pinned one.
var ErrHostKeyMismatch = errors.New("ssh: host key does not match the pinned key")

/*
ErrHostKeyInSession means the device presented the host key of a device the
executor holds in a change session (execpub.device_busy.hostkey_fp, or a key
the poller pinned for a busy device id), or that this could not be checked:
no credential is sent.
*/
var ErrHostKeyInSession = errors.New("ssh: host key of a device in a change session")

const dbTimeout = 10 * time.Second

/*
HostKeys pins each device's SSH host key on first use (TOFU) in
ssh_hosts.host_key, keyed by device id only, so an address change never
resets the pin. Only an operator on the host can reset a pin.
*/
type HostKeys struct {
	pool *pgxpool.Pool
}

// NewHostKeys returns a HostKeys backed by pool (connected as nms_poller).
func NewHostKeys(pool *pgxpool.Pool) *HostKeys {
	return &HostKeys{pool: pool}
}

/*
Callback returns a host key callback for deviceID reached at addr. A key
whose fingerprint belongs to a device the executor holds in a change session
is refused first (ErrHostKeyInSession, also when that cannot be read: fail
closed), whatever device row the dial is for: the api may give a second
device row any other address of the same switch. The busy table is read at
every callback, never cached. Then the first key seen is pinned; later keys
must match it, otherwise the attempt is recorded in ssh_hosts.mismatch and
ErrHostKeyMismatch is returned. The SSH handshake verifies the host key
before any credential is sent.
*/
func (h *HostKeys) Callback(deviceID int64, addr netip.Addr) gossh.HostKeyCallback {
	return h.callback(context.Background(), deviceID, addr)
}

func (h *HostKeys) callback(ctx context.Context, deviceID int64, addr netip.Addr) gossh.HostKeyCallback {
	return func(_ string, _ net.Addr, key gossh.PublicKey) error {
		ctx, cancel := context.WithTimeout(ctx, dbTimeout)
		defer cancel()
		fp := gossh.FingerprintSHA256(key)
		if err := h.notInSession(ctx, fp); err != nil {
			return err
		}
		return h.verify(ctx, deviceID, addr, key.Type(), fp)
	}
}

/*
notInSession is nil only when execpub.device_busy was read and fp is neither
the host key fingerprint the executor published for a busy device nor one
this poller pinned for a busy device id (ssh_hosts.host_key). The second
closes the alias of a switch with several host keys of different types: the
alias row negotiates the type of its own pin, so the switch may present a key
the executor never saw but the poller pinned for the busy device. Devices
sharing a host key (clones, factory keys) lose SSH while one is busy.
*/
func (h *HostKeys) notInSession(ctx context.Context, fp string) error {
	var busy bool
	if err := h.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM execpub.device_busy WHERE hostkey_fp = $1)
		OR EXISTS (SELECT 1 FROM ssh_hosts.host_key WHERE fingerprint_sha256 = $1
			AND device_id IN (SELECT device_id FROM execpub.device_busy))`, fp).Scan(&busy); err != nil {
		return fmt.Errorf("%w: check: %w", ErrHostKeyInSession, err)
	}
	if busy {
		return ErrHostKeyInSession
	}
	return nil
}

func (h *HostKeys) verify(ctx context.Context, deviceID int64, addr netip.Addr, algo, fp string) error {
	/* Race-safe first use: concurrent first connections all compare against the single winner. */
	if _, err := h.pool.Exec(ctx, `INSERT INTO ssh_hosts.host_key (device_id, algorithm, fingerprint_sha256)
		VALUES ($1, $2, $3) ON CONFLICT (device_id) DO NOTHING`, deviceID, algo, fp); err != nil {
		return fmt.Errorf("ssh: pin host key: %w", err)
	}
	var pAlgo, pFP string
	if err := h.pool.QueryRow(ctx, `SELECT algorithm, fingerprint_sha256 FROM ssh_hosts.host_key WHERE device_id = $1`,
		deviceID).Scan(&pAlgo, &pFP); err != nil {
		return fmt.Errorf("ssh: read pinned host key: %w", err)
	}
	if pAlgo == algo && pFP == fp {
		if _, err := h.pool.Exec(ctx, `UPDATE ssh_hosts.host_key SET last_seen = now() WHERE device_id = $1`, deviceID); err != nil {
			return fmt.Errorf("ssh: update host key: %w", err)
		}
		return nil
	}
	if _, err := h.pool.Exec(ctx, `INSERT INTO ssh_hosts.mismatch (device_id, seen_fingerprint, address) VALUES ($1, $2, $3)`,
		deviceID, fp, addr); err != nil {
		return errors.Join(ErrHostKeyMismatch, fmt.Errorf("ssh: record mismatch: %w", err))
	}
	return ErrHostKeyMismatch
}

/* pinnedAlgorithm returns the pinned key type for deviceID, or "" when none is pinned yet. */
func (h *HostKeys) pinnedAlgorithm(ctx context.Context, deviceID int64) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	var algo string
	err := h.pool.QueryRow(ctx, `SELECT algorithm FROM ssh_hosts.host_key WHERE device_id = $1`, deviceID).Scan(&algo)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("ssh: read pinned host key: %w", err)
	}
	return algo, nil
}

/*
hostKeyAlgorithms limits negotiation to the pinned key type (RSA only with
SHA-2 signatures); before a pin exists it offers a conservative modern set.
*/
func hostKeyAlgorithms(pinned string) []string {
	switch pinned {
	case "":
		return []string{gossh.KeyAlgoED25519, gossh.KeyAlgoECDSA256, gossh.KeyAlgoECDSA384, gossh.KeyAlgoECDSA521,
			gossh.KeyAlgoRSASHA512, gossh.KeyAlgoRSASHA256}
	case gossh.KeyAlgoRSA:
		return []string{gossh.KeyAlgoRSASHA512, gossh.KeyAlgoRSASHA256}
	default:
		return []string{pinned}
	}
}
