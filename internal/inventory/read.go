package inventory

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

/*
The read types are the rows the API returns; their JSON names are the API's.
Every string except addresses comes from the device: render it as text only.
*/

// Interface is a stored interface row.
type Interface struct {
	IfIndex  int       `json:"if_index"`
	Name     string    `json:"name"`
	Alias    string    `json:"alias"`
	SpeedBps int64     `json:"speed_bps"`
	OperUp   bool      `json:"oper_up"`
	SeenAt   time.Time `json:"seen_at"`
}

// ARPEntry is a stored IP-to-MAC row.
type ARPEntry struct {
	IP      string    `json:"ip"`
	MAC     string    `json:"mac"`
	IfIndex int       `json:"if_index"`
	SeenAt  time.Time `json:"seen_at"`
}

// MACEntry is a stored forwarding database row; VLAN 0 is unknown.
type MACEntry struct {
	MAC     string    `json:"mac"`
	VLAN    int       `json:"vlan"`
	IfIndex int       `json:"if_index"`
	SeenAt  time.Time `json:"seen_at"`
}

// VLAN is a stored VLAN row.
type VLAN struct {
	VLANID int       `json:"vlan_id"`
	Name   string    `json:"name"`
	SeenAt time.Time `json:"seen_at"`
}

// LLDPNeighbor is a stored LLDP neighbor; MgmtAddr is nil when none was advertised.
type LLDPNeighbor struct {
	LocalIfIndex int       `json:"local_if_index"`
	ChassisID    string    `json:"chassis_id"`
	PortID       string    `json:"port_id"`
	SysName      string    `json:"sys_name"`
	MgmtAddr     *string   `json:"mgmt_addr"`
	SeenAt       time.Time `json:"seen_at"`
}

// Entity is a stored physical component.
type Entity struct {
	EntIndex int       `json:"ent_index"`
	Class    string    `json:"class"`
	Name     string    `json:"name"`
	Model    string    `json:"model"`
	Serial   string    `json:"serial"`
	SeenAt   time.Time `json:"seen_at"`
}

// Route is a stored forwarding table row; NextHop is nil when unknown.
type Route struct {
	Dest    string    `json:"dest"`
	NextHop *string   `json:"next_hop"`
	IfIndex int       `json:"if_index"`
	Proto   string    `json:"proto"`
	SeenAt  time.Time `json:"seen_at"`
}

// Page selects Limit rows after skipping Offset, in the table's key order.
type Page struct {
	Limit, Offset int
}

/* page runs q ($1 device, $2 limit, $3 offset) and maps the columns to T's fields in order. */
func page[T any](ctx context.Context, s *Store, q string, deviceID int64, p Page) ([]T, error) {
	rows, err := s.pool.Query(ctx, q+` LIMIT $2 OFFSET $3`, deviceID, p.Limit, p.Offset)
	if err != nil {
		return nil, fmt.Errorf("inventory: list: %w", err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[T])
	if err != nil {
		return nil, fmt.Errorf("inventory: list: %w", err)
	}
	return out, nil
}

// Interfaces lists a device's interfaces by if_index.
func (s *Store) Interfaces(ctx context.Context, deviceID int64, p Page) ([]Interface, error) {
	return page[Interface](ctx, s, `SELECT if_index, name, alias, speed_bps, oper_up, seen_at
		FROM inventory.interface WHERE device_id = $1 ORDER BY if_index`, deviceID, p)
}

// ARP lists a device's ARP entries by address.
func (s *Store) ARP(ctx context.Context, deviceID int64, p Page) ([]ARPEntry, error) {
	return page[ARPEntry](ctx, s, `SELECT host(ip), mac::text, if_index, seen_at
		FROM inventory.arp_entry WHERE device_id = $1 ORDER BY ip, if_index`, deviceID, p)
}

// MAC lists a device's forwarding database by VLAN and MAC.
func (s *Store) MAC(ctx context.Context, deviceID int64, p Page) ([]MACEntry, error) {
	return page[MACEntry](ctx, s, `SELECT mac::text, vlan, if_index, seen_at
		FROM inventory.mac_entry WHERE device_id = $1 ORDER BY vlan, mac`, deviceID, p)
}

// VLANs lists a device's VLANs by id.
func (s *Store) VLANs(ctx context.Context, deviceID int64, p Page) ([]VLAN, error) {
	return page[VLAN](ctx, s, `SELECT vlan_id, name, seen_at
		FROM inventory.vlan WHERE device_id = $1 ORDER BY vlan_id`, deviceID, p)
}

// LLDP lists a device's LLDP neighbors by local port.
func (s *Store) LLDP(ctx context.Context, deviceID int64, p Page) ([]LLDPNeighbor, error) {
	return page[LLDPNeighbor](ctx, s, `SELECT local_if_index, chassis_id, port_id, sys_name, host(mgmt_addr), seen_at
		FROM inventory.lldp_neighbor WHERE device_id = $1 ORDER BY local_if_index, chassis_id, port_id`, deviceID, p)
}

// Entities lists a device's physical components by index.
func (s *Store) Entities(ctx context.Context, deviceID int64, p Page) ([]Entity, error) {
	return page[Entity](ctx, s, `SELECT ent_index, class, name, model, serial, seen_at
		FROM inventory.entity WHERE device_id = $1 ORDER BY ent_index`, deviceID, p)
}

// Routes lists a device's routes by destination.
func (s *Store) Routes(ctx context.Context, deviceID int64, p Page) ([]Route, error) {
	return page[Route](ctx, s, `SELECT dest::text, host(next_hop), if_index, proto, seen_at
		FROM inventory.route WHERE device_id = $1 ORDER BY dest, next_hop NULLS FIRST, if_index`, deviceID, p)
}

// DeviceState is the availability a device shows in the API; Since is nil when never polled.
type DeviceState struct {
	State     string
	Since     *time.Time
	LastError string /* fixed text of the poller, empty when none */
}

/* States returns the state of each device in ids from inventory.device_state_v; missing ids are absent. */
func (s *Store) States(ctx context.Context, ids []int64) (map[int64]DeviceState, error) {
	rows, err := s.pool.Query(ctx, `SELECT device_id, state, since, last_error FROM inventory.device_state_v WHERE device_id = ANY($1)`, ids)
	if err != nil {
		return nil, fmt.Errorf("inventory: states: %w", err)
	}
	out := make(map[int64]DeviceState, len(ids))
	var (
		id int64
		st DeviceState
	)
	_, err = pgx.ForEachRow(rows, []any{&id, &st.State, &st.Since, &st.LastError}, func() error {
		out[id] = st
		st.Since = nil
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("inventory: states: %w", err)
	}
	return out, nil
}
