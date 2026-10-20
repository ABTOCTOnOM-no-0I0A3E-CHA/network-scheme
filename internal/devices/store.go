// Package devices persists monitored devices, their access profiles and discovery results.
package devices

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

/* Store errors. */
var (
	ErrNotFound      = errors.New("devices: not found")
	ErrAddressExists = errors.New("devices: address and port already used by another device")
	ErrGroupNotFound = errors.New("devices: group not found")
	ErrInvalid       = errors.New("devices: invalid value")
	ErrNotPending    = errors.New("devices: discovered item is not pending")
)

/* Owner kinds of an access profile. */
const (
	OwnerDevice = "device"
	OwnerScan   = "scan"
)

var profileKinds = map[string]bool{"snmp2c": true, "snmp3": true, "ssh_read": true, "telnet_read": true}

/*
Intervals are optional polling intervals in seconds; nil inherits from the
group (or the built-in default).
*/
type Intervals struct {
	AvailS     *int
	MetricsS   *int
	InventoryS *int
}

// Device is a monitored device.
type Device struct {
	ID                int64
	Name              string
	Address           netip.Addr
	SNMPPort          int
	GroupID           int64
	Driver            string
	Model             string
	Firmware          string
	SysObjectID       string
	InsecureProtocols bool
	PollerID          string
	Intervals         Intervals
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

/*
NewDevice describes a device to create. Zero SNMPPort, Driver and PollerID
select the defaults (161, "auto", "local").
*/
type NewDevice struct {
	Name              string
	Address           netip.Addr
	SNMPPort          int
	GroupID           int64
	Driver            string
	InsecureProtocols bool
	PollerID          string
	Intervals         Intervals
}

/*
Patch holds the fields to change; nil leaves a field as is. Intervals, when
set, replaces all three intervals (nil members clear them).
*/
type Patch struct {
	Name              *string
	Address           *netip.Addr
	SNMPPort          *int
	GroupID           *int64
	Driver            *string
	InsecureProtocols *bool
	PollerID          *string
	Intervals         *Intervals
}

/*
Filter selects devices by exact group id; the caller expands group
hierarchies. The zero Filter matches nothing.
*/
type Filter struct {
	GroupIDs []int64
	All      bool
}

// Owner identifies the holder of an access profile.
type Owner struct {
	Kind string /* "device" | "scan" */
	ID   int64
}

// ProfileInfo is the credential metadata the API may show; it never carries the ciphertext.
type ProfileInfo struct {
	Kind      string
	Status    string
	UpdatedAt time.Time
}

/*
Store persists devices, access profiles and discovery data. State-changing
methods run in the caller's transaction so the caller can audit the change
atomically; reads use the pool.
*/
type Store struct {
	pool *pgxpool.Pool
}

// NewStore returns a Store over pool.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

func pgErr(err error) *pgconn.PgError {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe
	}
	return nil
}

/* mapWrite translates constraint violations into typed errors. */
func mapWrite(op string, err error) error {
	if pe := pgErr(err); pe != nil {
		switch {
		case pe.Code == "23505" && pe.ConstraintName == "device_address_snmp_port_key":
			return ErrAddressExists
		case pe.Code == "23503" && pe.TableName == "device" || pe.Code == "23503" && pe.TableName == "discovery_scan":
			return ErrGroupNotFound
		case pe.Code == "23514" || pe.Code == "22023" || pe.Code == "22P02":
			return fmt.Errorf("%w: %s", ErrInvalid, pe.ConstraintName)
		}
	}
	return fmt.Errorf("devices: %s: %w", op, err)
}

const deviceCols = `id, name, address, snmp_port, group_id, driver, coalesce(model, ''), coalesce(firmware, ''),
	coalesce(sys_object_id, ''), insecure_protocols, poller_id,
	interval_avail_s, interval_metrics_s, interval_inventory_s, created_at, updated_at`

func scanDevice(r pgx.Row) (Device, error) {
	var d Device
	err := r.Scan(&d.ID, &d.Name, &d.Address, &d.SNMPPort, &d.GroupID, &d.Driver, &d.Model, &d.Firmware,
		&d.SysObjectID, &d.InsecureProtocols, &d.PollerID,
		&d.Intervals.AvailS, &d.Intervals.MetricsS, &d.Intervals.InventoryS, &d.CreatedAt, &d.UpdatedAt)
	return d, err
}

func orDefault[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}

// Create inserts a device and returns its id. A duplicate address and port yields ErrAddressExists.
func (s *Store) Create(ctx context.Context, tx pgx.Tx, d NewDevice) (int64, error) {
	if !d.Address.IsValid() {
		return 0, fmt.Errorf("%w: address", ErrInvalid)
	}
	var id int64
	err := tx.QueryRow(ctx, `
		INSERT INTO core.device (name, address, snmp_port, group_id, driver, insecure_protocols, poller_id,
			interval_avail_s, interval_metrics_s, interval_inventory_s)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`,
		d.Name, d.Address.Unmap(), orDefault(d.SNMPPort, 161), d.GroupID, orDefault(d.Driver, "auto"),
		d.InsecureProtocols, orDefault(d.PollerID, "local"),
		d.Intervals.AvailS, d.Intervals.MetricsS, d.Intervals.InventoryS).Scan(&id)
	if err != nil {
		return 0, mapWrite("create device", err)
	}
	return id, nil
}

// Get returns a device or ErrNotFound.
func (s *Store) Get(ctx context.Context, id int64) (Device, error) {
	d, err := scanDevice(s.pool.QueryRow(ctx, `SELECT `+deviceCols+` FROM core.device WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Device{}, ErrNotFound
	}
	if err != nil {
		return Device{}, fmt.Errorf("devices: get: %w", err)
	}
	return d, nil
}

// List returns the devices selected by f ordered by name and id.
func (s *Store) List(ctx context.Context, f Filter) ([]Device, error) {
	if !f.All && len(f.GroupIDs) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT `+deviceCols+` FROM core.device
		WHERE $1::bool OR group_id = ANY($2::bigint[]) ORDER BY name, id`, f.All, f.GroupIDs)
	if err != nil {
		return nil, fmt.Errorf("devices: list: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Device, error) { return scanDevice(r) })
	if err != nil {
		return nil, fmt.Errorf("devices: list: %w", err)
	}
	return out, nil
}

// Update applies p to device id: ErrNotFound if absent, ErrAddressExists on a clash.
func (s *Store) Update(ctx context.Context, tx pgx.Tx, id int64, p Patch) error {
	var iv Intervals
	if p.Intervals != nil {
		iv = *p.Intervals
	}
	tag, err := tx.Exec(ctx, `
		UPDATE core.device SET
			name = coalesce($2, name),
			address = coalesce($3::inet, address),
			snmp_port = coalesce($4, snmp_port),
			group_id = coalesce($5, group_id),
			driver = coalesce($6, driver),
			insecure_protocols = coalesce($7, insecure_protocols),
			poller_id = coalesce($8, poller_id),
			interval_avail_s = CASE WHEN $9::bool THEN $10::int ELSE interval_avail_s END,
			interval_metrics_s = CASE WHEN $9::bool THEN $11::int ELSE interval_metrics_s END,
			interval_inventory_s = CASE WHEN $9::bool THEN $12::int ELSE interval_inventory_s END,
			updated_at = now()
		WHERE id = $1`,
		id, p.Name, unmapPtr(p.Address), p.SNMPPort, p.GroupID, p.Driver, p.InsecureProtocols, p.PollerID,
		p.Intervals != nil, iv.AvailS, iv.MetricsS, iv.InventoryS)
	if err != nil {
		return mapWrite("update device", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func unmapPtr(a *netip.Addr) *netip.Addr {
	if a == nil {
		return nil
	}
	u := a.Unmap()
	return &u
}

// Delete removes a device and its access profiles; ErrNotFound if absent.
func (s *Store) Delete(ctx context.Context, tx pgx.Tx, id int64) error {
	tag, err := tx.Exec(ctx, `DELETE FROM core.device WHERE id = $1`, id)
	if err != nil {
		return mapWrite("delete device", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM core.access_profile WHERE owner_kind = 'device' AND owner_id = $1`, id); err != nil {
		return fmt.Errorf("devices: delete profiles: %w", err)
	}
	return nil
}

func checkOwner(o Owner) error {
	if o.Kind != OwnerDevice && o.Kind != OwnerScan {
		return fmt.Errorf("%w: owner kind", ErrInvalid)
	}
	return nil
}

/*
PutProfile stores (or replaces) the sealed credential of kind for owner and
resets its status to pending. The owner must exist; an unknown kind is ErrInvalid.
*/
func (s *Store) PutProfile(ctx context.Context, tx pgx.Tx, owner Owner, kind string, ciphertext []byte, keyVersion int) error {
	if err := checkOwner(owner); err != nil {
		return err
	}
	if !profileKinds[kind] || len(ciphertext) == 0 {
		return fmt.Errorf("%w: profile", ErrInvalid)
	}
	table := "core.device"
	if owner.Kind == OwnerScan {
		table = "core.discovery_scan"
	}
	/*
		An exclusive owner lock serializes puts for the same owner: with a shared
		one, two first-time puts would both insert and one would hit the key.
	*/
	var one int
	if err := tx.QueryRow(ctx, `SELECT 1 FROM `+table+` WHERE id = $1 FOR NO KEY UPDATE`, owner.ID).Scan(&one); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("devices: put profile: %w", err)
	}
	/*
		Replace in place or insert: no ON CONFLICT, because EXCLUDED would need
		SELECT on the ciphertext column, which the API role deliberately lacks.
	*/
	_, err := tx.Exec(ctx, `
		WITH upd AS (
			UPDATE core.access_profile SET ciphertext = $4, key_version = $5, status = 'pending', updated_at = now()
			WHERE owner_kind = $1 AND owner_id = $2 AND kind = $3 RETURNING 1
		)
		INSERT INTO core.access_profile (owner_kind, owner_id, kind, ciphertext, key_version)
		SELECT $1, $2, $3, $4, $5 WHERE NOT EXISTS (SELECT 1 FROM upd)`,
		owner.Kind, owner.ID, kind, ciphertext, keyVersion)
	if err != nil {
		return mapWrite("put profile", err)
	}
	return nil
}

// DeleteProfile removes a credential; ErrNotFound if it is not set.
func (s *Store) DeleteProfile(ctx context.Context, tx pgx.Tx, owner Owner, kind string) error {
	if err := checkOwner(owner); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx,
		`DELETE FROM core.access_profile WHERE owner_kind = $1 AND owner_id = $2 AND kind = $3`,
		owner.Kind, owner.ID, kind)
	if err != nil {
		return mapWrite("delete profile", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Profiles lists which credentials are set for owner (no secret material).
func (s *Store) Profiles(ctx context.Context, owner Owner) ([]ProfileInfo, error) {
	if err := checkOwner(owner); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT kind, status, updated_at FROM core.access_profile
		WHERE owner_kind = $1 AND owner_id = $2 ORDER BY kind`, owner.Kind, owner.ID)
	if err != nil {
		return nil, fmt.Errorf("devices: profiles: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (ProfileInfo, error) {
		var p ProfileInfo
		err := r.Scan(&p.Kind, &p.Status, &p.UpdatedAt)
		return p, err
	})
	if err != nil {
		return nil, fmt.Errorf("devices: profiles: %w", err)
	}
	return out, nil
}

// Lock returns device id locked FOR UPDATE in tx (read-modify-write); ErrNotFound if absent.
func (s *Store) Lock(ctx context.Context, tx pgx.Tx, id int64) (Device, error) {
	d, err := scanDevice(tx.QueryRow(ctx, `SELECT `+deviceCols+` FROM core.device WHERE id = $1 FOR NO KEY UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Device{}, ErrNotFound
	}
	if err != nil {
		return Device{}, fmt.Errorf("devices: lock: %w", err)
	}
	return d, nil
}

/*
RefreshInsecure sets insecure_protocols of device id from its profiles: true
while an snmp2c or telnet_read credential is set.
*/
func (s *Store) RefreshInsecure(ctx context.Context, tx pgx.Tx, id int64) error {
	tag, err := tx.Exec(ctx, `
		UPDATE core.device SET insecure_protocols = EXISTS (
			SELECT 1 FROM core.access_profile
			WHERE owner_kind = 'device' AND owner_id = $1 AND kind IN ('snmp2c', 'telnet_read')
		), updated_at = now()
		WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("devices: refresh insecure: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
