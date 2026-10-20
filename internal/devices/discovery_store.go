package devices

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
)

// NewScan describes a discovery scan to create.
type NewScan struct {
	CIDR      netip.Prefix
	GroupID   int64
	Enabled   bool
	IntervalS int /* zero selects the default of 24 hours */
}

// Scan is a configured discovery scan.
type Scan struct {
	ID        int64
	CIDR      netip.Prefix
	GroupID   int64
	Enabled   bool
	IntervalS int
	LastRunAt *time.Time
}

// Discovered is a device found by a scan and waiting in the inbox.
type Discovered struct {
	ID          int64
	ScanID      int64
	GroupID     int64 /* group of the scan that found it */
	Address     netip.Addr
	SysObjectID string
	SysDescr    string
	SysName     string
	FoundAt     time.Time
	Status      string /* pending | accepted | ignored */
}

/*
InboxFilter selects discovered items by the group of their scan (exact ids;
the caller expands hierarchies) and optionally by status. The zero value
matches nothing.
*/
type InboxFilter struct {
	GroupIDs []int64
	All      bool
	Status   string
}

// CreateScan inserts a scan and returns its id.
func (s *Store) CreateScan(ctx context.Context, tx pgx.Tx, n NewScan) (int64, error) {
	if !n.CIDR.IsValid() {
		return 0, fmt.Errorf("%w: cidr", ErrInvalid)
	}
	var id int64
	err := tx.QueryRow(ctx, `
		INSERT INTO core.discovery_scan (cidr, group_id, enabled, interval_s)
		VALUES ($1, $2, $3, $4) RETURNING id`,
		n.CIDR.Masked(), n.GroupID, n.Enabled, orDefault(n.IntervalS, 86400)).Scan(&id)
	if err != nil {
		return 0, mapWrite("create scan", err)
	}
	return id, nil
}

// ListScans returns the scans whose group f selects, ordered by id.
func (s *Store) ListScans(ctx context.Context, f Filter) ([]Scan, error) {
	if !f.All && len(f.GroupIDs) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT `+scanCols+` FROM core.discovery_scan
		WHERE $1::bool OR group_id = ANY($2::bigint[]) ORDER BY id`, f.All, f.GroupIDs)
	if err != nil {
		return nil, fmt.Errorf("devices: list scans: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Scan, error) { return scanScan(r) })
	if err != nil {
		return nil, fmt.Errorf("devices: list scans: %w", err)
	}
	return out, nil
}

/*
UpsertDiscovered records a find. A repeated address (even from another scan)
updates the existing row's scan, data and found_at; its status is kept.
*/
func (s *Store) UpsertDiscovered(ctx context.Context, tx pgx.Tx, scanID int64, address netip.Addr, sysObjectID, sysDescr, sysName string) error {
	if !address.IsValid() {
		return fmt.Errorf("%w: address", ErrInvalid)
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO core.discovered (scan_id, address, sys_object_id, sys_descr, sys_name)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (address) DO UPDATE
		SET scan_id = EXCLUDED.scan_id, sys_object_id = EXCLUDED.sys_object_id,
		    sys_descr = EXCLUDED.sys_descr, sys_name = EXCLUDED.sys_name, found_at = now()`,
		scanID, address.Unmap(), sysObjectID, sysDescr, sysName)
	if err != nil {
		return mapWrite("upsert discovered", err)
	}
	return nil
}

const discoveredCols = `d.id, d.scan_id, sc.group_id, d.address, coalesce(d.sys_object_id, ''),
	coalesce(d.sys_descr, ''), coalesce(d.sys_name, ''), d.found_at, d.status`

func scanDiscovered(r pgx.Row) (Discovered, error) {
	var d Discovered
	err := r.Scan(&d.ID, &d.ScanID, &d.GroupID, &d.Address, &d.SysObjectID, &d.SysDescr, &d.SysName, &d.FoundAt, &d.Status)
	return d, err
}

// Inbox lists discovered items matching f, newest first.
func (s *Store) Inbox(ctx context.Context, f InboxFilter) ([]Discovered, error) {
	if !f.All && len(f.GroupIDs) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT `+discoveredCols+` FROM core.discovered d JOIN core.discovery_scan sc ON sc.id = d.scan_id
		WHERE ($1::bool OR sc.group_id = ANY($2::bigint[])) AND ($3 = '' OR d.status = $3)
		ORDER BY d.found_at DESC, d.id DESC`, f.All, f.GroupIDs, f.Status)
	if err != nil {
		return nil, fmt.Errorf("devices: inbox: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Discovered, error) { return scanDiscovered(r) })
	if err != nil {
		return nil, fmt.Errorf("devices: inbox: %w", err)
	}
	return out, nil
}

/*
Accept turns a pending item into a device named name in groupID and marks it
accepted, all in tx. ErrNotFound for an unknown id, ErrNotPending if it was
already handled, ErrAddressExists if a device already uses the address.
*/
func (s *Store) Accept(ctx context.Context, tx pgx.Tx, id int64, name string, groupID int64) (int64, error) {
	var addr netip.Addr
	var sysOID, status string
	err := tx.QueryRow(ctx, `SELECT address, coalesce(sys_object_id, ''), status FROM core.discovered
		WHERE id = $1 FOR UPDATE`, id).Scan(&addr, &sysOID, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("devices: accept: %w", err)
	}
	if status != "pending" {
		return 0, ErrNotPending
	}
	devID, err := s.Create(ctx, tx, NewDevice{Name: name, Address: addr, GroupID: groupID})
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `UPDATE core.device SET sys_object_id = nullif($2, '') WHERE id = $1`, devID, sysOID); err != nil {
		return 0, fmt.Errorf("devices: accept: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE core.discovered SET status = 'accepted' WHERE id = $1`, id); err != nil {
		return 0, fmt.Errorf("devices: accept: %w", err)
	}
	return devID, nil
}

// Ignore marks a pending item ignored (ErrNotFound / ErrNotPending as for Accept).
func (s *Store) Ignore(ctx context.Context, tx pgx.Tx, id int64) error {
	var status string
	err := tx.QueryRow(ctx, `SELECT status FROM core.discovered WHERE id = $1 FOR UPDATE`, id).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("devices: ignore: %w", err)
	}
	if status != "pending" {
		return ErrNotPending
	}
	if _, err := tx.Exec(ctx, `UPDATE core.discovered SET status = 'ignored' WHERE id = $1`, id); err != nil {
		return fmt.Errorf("devices: ignore: %w", err)
	}
	return nil
}

// ScanPatch holds the scan fields to change; nil leaves a field as is.
type ScanPatch struct {
	CIDR      *netip.Prefix
	GroupID   *int64
	Enabled   *bool
	IntervalS *int
}

const scanCols = `id, cidr, group_id, enabled, interval_s, last_run_at`

func scanScan(r pgx.Row) (Scan, error) {
	var sc Scan
	err := r.Scan(&sc.ID, &sc.CIDR, &sc.GroupID, &sc.Enabled, &sc.IntervalS, &sc.LastRunAt)
	return sc, err
}

// GetScan returns a scan or ErrNotFound.
func (s *Store) GetScan(ctx context.Context, id int64) (Scan, error) {
	sc, err := scanScan(s.pool.QueryRow(ctx, `SELECT `+scanCols+` FROM core.discovery_scan WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Scan{}, ErrNotFound
	}
	if err != nil {
		return Scan{}, fmt.Errorf("devices: get scan: %w", err)
	}
	return sc, nil
}

// UpdateScan applies p to scan id: ErrNotFound if absent, ErrGroupNotFound for an unknown group.
func (s *Store) UpdateScan(ctx context.Context, tx pgx.Tx, id int64, p ScanPatch) error {
	var cidr *netip.Prefix
	if p.CIDR != nil {
		if !p.CIDR.IsValid() {
			return fmt.Errorf("%w: cidr", ErrInvalid)
		}
		m := p.CIDR.Masked()
		cidr = &m
	}
	tag, err := tx.Exec(ctx, `
		UPDATE core.discovery_scan SET
			cidr = coalesce($2::cidr, cidr),
			group_id = coalesce($3, group_id),
			enabled = coalesce($4, enabled),
			interval_s = coalesce($5, interval_s)
		WHERE id = $1`, id, cidr, p.GroupID, p.Enabled, p.IntervalS)
	if err != nil {
		return mapWrite("update scan", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GetDiscovered returns one discovered item (with its scan's group) or ErrNotFound.
func (s *Store) GetDiscovered(ctx context.Context, id int64) (Discovered, error) {
	d, err := scanDiscovered(s.pool.QueryRow(ctx, `
		SELECT `+discoveredCols+` FROM core.discovered d JOIN core.discovery_scan sc ON sc.id = d.scan_id
		WHERE d.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Discovered{}, ErrNotFound
	}
	if err != nil {
		return Discovered{}, fmt.Errorf("devices: get discovered: %w", err)
	}
	return d, nil
}
