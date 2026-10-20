/*
Package inventory stores what the poller learns about devices (inventory
tables, availability state), poller heartbeats and the newest accepted
credential timestamps, and reads them back for the API. The poller writes;
the API only reads, through Store's read methods on its own pool.
*/
package inventory

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/drivers"
)

/* Store errors. */
var (
	ErrNoDevice = errors.New("inventory: device does not exist")
	ErrInvalid  = errors.New("inventory: invalid value")
)

/* Availability states; StateUnknown is also what the API shows without a fresh status. */
const (
	StateUp      = "up"
	StatePartial = "partial"
	StateDown    = "down"
	StateUnknown = "unknown"
)

// Store reads and writes the inventory schema.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore returns a Store over pool (nms_poller writes, nms_api reads).
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

/* table is one inventory table: its upsert and its column arrays built from an Inventory. */
type table struct {
	name   drivers.Table
	upsert string
	args   func(drivers.Inventory) (n int, cols []any)
}

/*
Each upsert takes $1 device id, $2 seen_at and one array per column; rows
are deduplicated on the table key first (last wins), since one statement
may not update a row twice.
*/
var tables = []table{
	{drivers.TableInterfaces, `
		INSERT INTO inventory.interface AS t (device_id, if_index, name, alias, speed_bps, oper_up, seen_at)
		SELECT $1, i, n, a, s, o, $2 FROM unnest($3::int[], $4::text[], $5::text[], $6::bigint[], $7::bool[]) AS u(i, n, a, s, o)
		ON CONFLICT (device_id, if_index) DO UPDATE SET name = excluded.name, alias = excluded.alias,
			speed_bps = excluded.speed_bps, oper_up = excluded.oper_up, seen_at = excluded.seen_at`,
		func(inv drivers.Inventory) (int, []any) {
			rows := dedupe(inv.Interfaces, func(r drivers.Interface) int { return r.Index })
			idx, name, alias, speed, up := make([]int, len(rows)), make([]string, len(rows)), make([]string, len(rows)), make([]int64, len(rows)), make([]bool, len(rows))
			for k, r := range rows {
				idx[k], name[k], alias[k], speed[k], up[k] = r.Index, r.Name, r.Alias, clampInt64(r.SpeedBps), r.OperUp
			}
			return len(rows), []any{idx, name, alias, speed, up}
		}},
	{drivers.TableARP, `
		INSERT INTO inventory.arp_entry AS t (device_id, ip, mac, if_index, seen_at)
		SELECT $1, ip::inet, mac::macaddr, i, $2 FROM unnest($3::text[], $4::text[], $5::int[]) AS u(ip, mac, i)
		ON CONFLICT (device_id, if_index, ip) DO UPDATE SET mac = excluded.mac, seen_at = excluded.seen_at`,
		func(inv drivers.Inventory) (int, []any) {
			type key struct {
				ifIndex int
				ip      netip.Addr
			}
			rows := dedupe(inv.ARP, func(r drivers.ARPEntry) key { return key{r.IfIndex, r.IP} })
			ip, mac, idx := make([]string, len(rows)), make([]string, len(rows)), make([]int, len(rows))
			for k, r := range rows {
				ip[k], mac[k], idx[k] = r.IP.String(), r.MAC, r.IfIndex
			}
			return len(rows), []any{ip, mac, idx}
		}},
	{drivers.TableMAC, `
		INSERT INTO inventory.mac_entry AS t (device_id, mac, vlan, if_index, seen_at)
		SELECT $1, mac::macaddr, v, i, $2 FROM unnest($3::text[], $4::int[], $5::int[]) AS u(mac, v, i)
		ON CONFLICT (device_id, vlan, mac) DO UPDATE SET if_index = excluded.if_index, seen_at = excluded.seen_at`,
		func(inv drivers.Inventory) (int, []any) {
			type key struct {
				vlan int
				mac  string
			}
			rows := dedupe(inv.MAC, func(r drivers.MACEntry) key { return key{r.VLAN, r.MAC} })
			mac, vlan, idx := make([]string, len(rows)), make([]int, len(rows)), make([]int, len(rows))
			for k, r := range rows {
				mac[k], vlan[k], idx[k] = r.MAC, r.VLAN, r.IfIndex
			}
			return len(rows), []any{mac, vlan, idx}
		}},
	{drivers.TableVLANs, `
		INSERT INTO inventory.vlan AS t (device_id, vlan_id, name, seen_at)
		SELECT $1, v, n, $2 FROM unnest($3::int[], $4::text[]) AS u(v, n)
		ON CONFLICT (device_id, vlan_id) DO UPDATE SET name = excluded.name, seen_at = excluded.seen_at`,
		func(inv drivers.Inventory) (int, []any) {
			rows := dedupe(inv.VLANs, func(r drivers.VLAN) int { return r.ID })
			id, name := make([]int, len(rows)), make([]string, len(rows))
			for k, r := range rows {
				id[k], name[k] = r.ID, r.Name
			}
			return len(rows), []any{id, name}
		}},
	{drivers.TableLLDP, `
		INSERT INTO inventory.lldp_neighbor AS t (device_id, local_if_index, chassis_id, port_id, sys_name, mgmt_addr, seen_at)
		SELECT $1, i, c, p, n, NULLIF(m, '')::inet, $2 FROM unnest($3::int[], $4::text[], $5::text[], $6::text[], $7::text[]) AS u(i, c, p, n, m)
		ON CONFLICT (device_id, local_if_index, chassis_id, port_id) DO UPDATE SET sys_name = excluded.sys_name,
			mgmt_addr = excluded.mgmt_addr, seen_at = excluded.seen_at`,
		func(inv drivers.Inventory) (int, []any) {
			type key struct {
				ifIndex       int
				chassis, port string
			}
			rows := dedupe(inv.LLDP, func(r drivers.LLDPNeighbor) key { return key{r.LocalIfIndex, r.ChassisID, r.PortID} })
			idx, chassis, port, name, mgmt := make([]int, len(rows)), make([]string, len(rows)), make([]string, len(rows)), make([]string, len(rows)), make([]string, len(rows))
			for k, r := range rows {
				idx[k], chassis[k], port[k], name[k], mgmt[k] = r.LocalIfIndex, r.ChassisID, r.PortID, r.SysName, addrText(r.MgmtAddr)
			}
			return len(rows), []any{idx, chassis, port, name, mgmt}
		}},
	{drivers.TableEntities, `
		INSERT INTO inventory.entity AS t (device_id, ent_index, class, name, model, serial, seen_at)
		SELECT $1, i, c, n, m, s, $2 FROM unnest($3::int[], $4::text[], $5::text[], $6::text[], $7::text[]) AS u(i, c, n, m, s)
		ON CONFLICT (device_id, ent_index) DO UPDATE SET class = excluded.class, name = excluded.name,
			model = excluded.model, serial = excluded.serial, seen_at = excluded.seen_at`,
		func(inv drivers.Inventory) (int, []any) {
			rows := dedupe(inv.Entities, func(r drivers.Entity) int { return r.Index })
			idx, class, name, model, serial := make([]int, len(rows)), make([]string, len(rows)), make([]string, len(rows)), make([]string, len(rows)), make([]string, len(rows))
			for k, r := range rows {
				idx[k], class[k], name[k], model[k], serial[k] = r.Index, r.Class, r.Name, r.Model, r.Serial
			}
			return len(rows), []any{idx, class, name, model, serial}
		}},
	{drivers.TableRoutes, `
		INSERT INTO inventory.route AS t (device_id, dest, next_hop, if_index, proto, seen_at)
		SELECT $1, d::cidr, NULLIF(h, '')::inet, i, p, $2 FROM unnest($3::text[], $4::text[], $5::int[], $6::text[]) AS u(d, h, i, p)
		ON CONFLICT ON CONSTRAINT route_key DO UPDATE SET proto = excluded.proto, seen_at = excluded.seen_at`,
		func(inv drivers.Inventory) (int, []any) {
			type key struct {
				dest    netip.Prefix
				nextHop netip.Addr
				ifIndex int
			}
			rows := dedupe(inv.Routes, func(r drivers.Route) key { return key{r.Dest.Masked(), r.NextHop, r.IfIndex} })
			dest, hop, idx, proto := make([]string, len(rows)), make([]string, len(rows)), make([]int, len(rows)), make([]string, len(rows))
			for k, r := range rows {
				dest[k], hop[k], idx[k], proto[k] = r.Dest.Masked().String(), addrText(r.NextHop), r.IfIndex, r.Proto
			}
			return len(rows), []any{dest, hop, idx, proto}
		}},
}

/* sqlNames are the inventory table names of each drivers.Table, used in statements. */
var sqlNames = map[drivers.Table]string{
	drivers.TableInterfaces: "inventory.interface",
	drivers.TableARP:        "inventory.arp_entry",
	drivers.TableMAC:        "inventory.mac_entry",
	drivers.TableVLANs:      "inventory.vlan",
	drivers.TableLLDP:       "inventory.lldp_neighbor",
	drivers.TableEntities:   "inventory.entity",
	drivers.TableRoutes:     "inventory.route",
}

/* dedupe keeps the last row of each key, in first-seen key order. */
func dedupe[T any, K comparable](rows []T, key func(T) K) []T {
	pos := make(map[K]int, len(rows))
	out := make([]T, 0, len(rows))
	for _, r := range rows {
		k := key(r)
		if i, ok := pos[k]; ok {
			out[i] = r
			continue
		}
		pos[k] = len(out)
		out = append(out, r)
	}
	return out
}

func clampInt64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

/* addrText is "" for the zero Addr (stored as NULL). */
func addrText(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func mapErr(op string, err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23503" {
		return ErrNoDevice
	}
	return fmt.Errorf("inventory: %s: %w", op, err)
}

/*
Apply stores one inventory poll of a device in a single transaction: every
row is upserted with seen_at = at. Rows not seen in this poll are deleted
only for tables with inv.Complete[t]; an incomplete walk (timeout, skipped
heavy table) never removes what an earlier poll found.
*/
func (s *Store) Apply(ctx context.Context, deviceID int64, inv drivers.Inventory, at time.Time) error {
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		for _, t := range tables {
			n, cols := t.args(inv)
			if n > 0 {
				if _, err := tx.Exec(ctx, t.upsert, append([]any{deviceID, at}, cols...)...); err != nil {
					return mapErr("upsert "+string(t.name), err)
				}
			}
			if inv.Complete[t.name] {
				/* Table names come from the sqlNames constants only. */
				if _, err := tx.Exec(ctx, `DELETE FROM `+sqlNames[t.name]+` WHERE device_id = $1 AND seen_at <> $2`, deviceID, at); err != nil {
					return mapErr("prune "+string(t.name), err)
				}
			}
		}
		return nil
	})
	return err
}

/*
SetStatus records the availability state of a device as seen by the poller
it is assigned to. since changes only when the state changes; a status older
than the stored one is ignored. errText is device-influenced and is stored
cleaned and bounded. A deleted device is not an error.
*/
func (s *Store) SetStatus(ctx context.Context, deviceID int64, state string, at time.Time, errText string) error {
	switch state {
	case StateUp, StatePartial, StateDown, StateUnknown:
	default:
		return ErrInvalid
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO inventory.device_status AS t (device_id, state, since, last_poll_at, poller_id, last_error)
		SELECT id, $2, $3, $3, poller_id, $4 FROM core.device WHERE id = $1
		ON CONFLICT (device_id) DO UPDATE SET
			since = CASE WHEN t.state = excluded.state THEN t.since ELSE excluded.since END,
			state = excluded.state, last_poll_at = excluded.last_poll_at,
			poller_id = excluded.poller_id, last_error = excluded.last_error
		WHERE t.last_poll_at <= excluded.last_poll_at`,
		deviceID, state, at, drivers.CleanText([]byte(errText)))
	if err != nil {
		return mapErr("set status", err)
	}
	return nil
}

/*
Heartbeat records that pollerID is alive at at. The stored time never moves
backwards and never runs ahead of the database clock, so a poller with a
fast clock cannot keep its devices "fresh" after it stops.
*/
func (s *Store) Heartbeat(ctx context.Context, pollerID string, at time.Time) error {
	if pollerID == "" {
		return ErrInvalid
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO inventory.poller_heartbeat AS t (poller_id, at) VALUES ($1, LEAST($2::timestamptz, now()))
		ON CONFLICT (poller_id) DO UPDATE SET at = GREATEST(t.at, excluded.at)`, pollerID, at)
	if err != nil {
		return mapErr("heartbeat", err)
	}
	return nil
}

/* ProfileSeen returns the newest accepted created_at of owner's kind credential; zero if none. */
func (s *Store) ProfileSeen(ctx context.Context, owner devices.Owner, kind string) (time.Time, error) {
	var at time.Time
	err := s.pool.QueryRow(ctx, `SELECT created_at FROM inventory.profile_seen
		WHERE owner_kind = $1 AND owner_id = $2 AND kind = $3`, owner.Kind, owner.ID, kind).Scan(&at)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, mapErr("profile seen", err)
	}
	return at, nil
}

/* MarkProfileSeen records createdAt as accepted for owner's kind; the stored value only moves forward. */
func (s *Store) MarkProfileSeen(ctx context.Context, owner devices.Owner, kind string, createdAt time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO inventory.profile_seen AS t (owner_kind, owner_id, kind, created_at) VALUES ($1, $2, $3, $4)
		ON CONFLICT (owner_kind, owner_id, kind) DO UPDATE SET created_at = GREATEST(t.created_at, excluded.created_at)`,
		owner.Kind, owner.ID, kind, createdAt)
	if err != nil {
		return mapErr("mark profile seen", err)
	}
	return nil
}
