-- +goose Up
-- Device inventory, availability state, poller heartbeats and the last
-- accepted credential timestamps. Only the poller writes; the API reads.
CREATE SCHEMA IF NOT EXISTS inventory;
REVOKE ALL ON SCHEMA inventory FROM PUBLIC;
GRANT USAGE ON SCHEMA inventory TO nms_api, nms_poller;

-- Rows are removed with their device; seen_at is the poll that last saw a row.
CREATE TABLE inventory.interface (
    device_id bigint      NOT NULL REFERENCES core.device (id) ON DELETE CASCADE,
    if_index  int         NOT NULL,
    name      text        NOT NULL,
    alias     text        NOT NULL,
    speed_bps bigint      NOT NULL,
    oper_up   bool        NOT NULL,
    seen_at   timestamptz NOT NULL,
    PRIMARY KEY (device_id, if_index)
);

CREATE TABLE inventory.arp_entry (
    device_id bigint      NOT NULL REFERENCES core.device (id) ON DELETE CASCADE,
    ip        inet        NOT NULL,
    mac       macaddr     NOT NULL,
    if_index  int         NOT NULL,
    seen_at   timestamptz NOT NULL,
    PRIMARY KEY (device_id, if_index, ip)
);

CREATE TABLE inventory.mac_entry (
    device_id bigint      NOT NULL REFERENCES core.device (id) ON DELETE CASCADE,
    mac       macaddr     NOT NULL,
    vlan      int         NOT NULL,
    if_index  int         NOT NULL,
    seen_at   timestamptz NOT NULL,
    PRIMARY KEY (device_id, vlan, mac)
);

CREATE TABLE inventory.vlan (
    device_id bigint      NOT NULL REFERENCES core.device (id) ON DELETE CASCADE,
    vlan_id   int         NOT NULL,
    name      text        NOT NULL,
    seen_at   timestamptz NOT NULL,
    PRIMARY KEY (device_id, vlan_id)
);

CREATE TABLE inventory.lldp_neighbor (
    device_id      bigint      NOT NULL REFERENCES core.device (id) ON DELETE CASCADE,
    local_if_index int         NOT NULL,
    chassis_id     text        NOT NULL,
    port_id        text        NOT NULL,
    sys_name       text        NOT NULL,
    mgmt_addr      inet        NULL,
    seen_at        timestamptz NOT NULL,
    PRIMARY KEY (device_id, local_if_index, chassis_id, port_id)
);

CREATE TABLE inventory.entity (
    device_id bigint      NOT NULL REFERENCES core.device (id) ON DELETE CASCADE,
    ent_index int         NOT NULL,
    class     text        NOT NULL,
    name      text        NOT NULL,
    model     text        NOT NULL,
    serial    text        NOT NULL,
    seen_at   timestamptz NOT NULL,
    PRIMARY KEY (device_id, ent_index)
);

-- next_hop is NULL when unknown; equal-cost routes differ by next hop or interface.
CREATE TABLE inventory.route (
    device_id bigint      NOT NULL REFERENCES core.device (id) ON DELETE CASCADE,
    dest      cidr        NOT NULL,
    next_hop  inet        NULL,
    if_index  int         NOT NULL,
    proto     text        NOT NULL,
    seen_at   timestamptz NOT NULL,
    CONSTRAINT route_key UNIQUE NULLS NOT DISTINCT (device_id, dest, next_hop, if_index)
);

CREATE TABLE inventory.device_status (
    device_id    bigint      PRIMARY KEY REFERENCES core.device (id) ON DELETE CASCADE,
    state        text        NOT NULL CHECK (state IN ('up', 'partial', 'down', 'unknown')),
    since        timestamptz NOT NULL,
    last_poll_at timestamptz NOT NULL,
    poller_id    text        NOT NULL,
    last_error   text        NOT NULL DEFAULT ''
);

CREATE TABLE inventory.poller_heartbeat (
    poller_id text        PRIMARY KEY,
    at        timestamptz NOT NULL
);

-- Newest accepted created_at of a sealed credential per owner and kind (replay
-- protection). No FK: the row must outlive a deleted and re-added profile.
CREATE TABLE inventory.profile_seen (
    owner_kind text        NOT NULL CHECK (owner_kind IN ('device', 'scan')),
    owner_id   bigint      NOT NULL,
    kind       text        NOT NULL CHECK (kind IN ('snmp2c', 'snmp3', 'ssh_read', 'telnet_read')),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (owner_kind, owner_id, kind)
);

-- Availability as the API shows it: unknown without a status from the
-- device's current poller or when that poller's heartbeat is older than 90 s.
CREATE VIEW inventory.device_state_v AS
SELECT d.id AS device_id,
       CASE WHEN s.device_id IS NOT NULL AND h.at >= now() - INTERVAL '90 seconds'
            THEN s.state ELSE 'unknown' END AS state,
       CASE WHEN s.device_id IS NULL THEN NULL
            WHEN h.at >= now() - INTERVAL '90 seconds' THEN s.since
            ELSE h.at + INTERVAL '90 seconds' END AS since
FROM core.device d
LEFT JOIN inventory.device_status s ON s.device_id = d.id AND s.poller_id = d.poller_id
LEFT JOIN inventory.poller_heartbeat h ON h.poller_id = d.poller_id;

REVOKE ALL ON ALL TABLES IN SCHEMA inventory FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON inventory.interface, inventory.arp_entry, inventory.mac_entry,
    inventory.vlan, inventory.lldp_neighbor, inventory.entity, inventory.route,
    inventory.device_status, inventory.poller_heartbeat TO nms_poller;
-- Credential timestamps only move forward: no DELETE.
GRANT SELECT, INSERT, UPDATE ON inventory.profile_seen TO nms_poller;
GRANT SELECT ON inventory.interface, inventory.arp_entry, inventory.mac_entry,
    inventory.vlan, inventory.lldp_neighbor, inventory.entity, inventory.route,
    inventory.device_state_v TO nms_api;

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
