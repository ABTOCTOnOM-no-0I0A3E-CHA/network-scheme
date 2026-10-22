-- +goose Up
-- Devices, access profiles, discovery scans and the read-only poller role.

ALTER TABLE core.device_group
    ADD COLUMN interval_avail_s     int NULL CHECK (interval_avail_s > 0),
    ADD COLUMN interval_metrics_s   int NULL CHECK (interval_metrics_s > 0),
    ADD COLUMN interval_inventory_s int NULL CHECK (interval_inventory_s > 0);

CREATE TABLE core.device (
    id                   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name                 text        NOT NULL CHECK (name <> '' AND char_length(name) <= 200),
    address              inet        NOT NULL
        CHECK (masklen(address) = CASE family(address) WHEN 4 THEN 32 ELSE 128 END),
    snmp_port            int         NOT NULL DEFAULT 161 CHECK (snmp_port BETWEEN 1 AND 65535),
    group_id             bigint      NOT NULL REFERENCES core.device_group (id),
    driver               text        NOT NULL DEFAULT 'auto',
    model                text        NULL,
    firmware             text        NULL,
    sys_object_id        text        NULL,
    insecure_protocols   bool        NOT NULL DEFAULT false,
    poller_id            text        NOT NULL DEFAULT 'local',
    interval_avail_s     int         NULL CHECK (interval_avail_s > 0),
    interval_metrics_s   int         NULL CHECK (interval_metrics_s > 0),
    interval_inventory_s int         NULL CHECK (interval_inventory_s > 0),
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT device_address_snmp_port_key UNIQUE (address, snmp_port)
);
CREATE INDEX device_group_id_idx ON core.device (group_id);

-- Credentials are sealed in the browser; the API stores and replaces the
-- ciphertext but cannot read it back (column-level SELECT below).
CREATE TABLE core.access_profile (
    owner_kind  text        NOT NULL CHECK (owner_kind IN ('device', 'scan')),
    owner_id    bigint      NOT NULL,
    kind        text        NOT NULL CHECK (kind IN ('snmp2c', 'snmp3', 'ssh_read', 'telnet_read')),
    ciphertext  bytea       NOT NULL,
    key_version int         NOT NULL,
    status      text        NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'ok', 'invalid', 'weak', 'mismatch')),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (owner_kind, owner_id, kind)
);

CREATE TABLE core.discovery_scan (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cidr        cidr        NOT NULL,
    group_id    bigint      NOT NULL REFERENCES core.device_group (id),
    enabled     bool        NOT NULL DEFAULT true,
    interval_s  int         NOT NULL DEFAULT 86400 CHECK (interval_s > 0),
    last_run_at timestamptz NULL
);
CREATE INDEX discovery_scan_group_id_idx ON core.discovery_scan (group_id);

CREATE TABLE core.discovered (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scan_id       bigint      NOT NULL REFERENCES core.discovery_scan (id),
    address       inet        NOT NULL
        CHECK (masklen(address) = CASE family(address) WHEN 4 THEN 32 ELSE 128 END),
    sys_object_id text        NULL,
    sys_descr     text        NULL,
    sys_name      text        NULL,
    found_at      timestamptz NOT NULL DEFAULT now(),
    status        text        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'ignored')),
    CONSTRAINT discovered_address_key UNIQUE (address)
);
CREATE INDEX discovered_scan_id_idx ON core.discovered (scan_id);

REVOKE ALL ON core.device, core.access_profile, core.discovery_scan, core.discovered FROM PUBLIC;

GRANT SELECT, INSERT, UPDATE, DELETE ON core.device, core.discovery_scan, core.discovered TO nms_api;
GRANT SELECT (owner_kind, owner_id, kind, key_version, status, updated_at),
      INSERT, UPDATE, DELETE ON core.access_profile TO nms_api;

-- The poller only reads; it writes back probe results and nothing else.
GRANT USAGE ON SCHEMA core TO nms_poller;
GRANT SELECT ON core.device, core.device_group, core.access_profile, core.discovery_scan TO nms_poller;
GRANT UPDATE (status) ON core.access_profile TO nms_poller;
GRANT UPDATE (model, firmware, sys_object_id, driver) ON core.device TO nms_poller;
GRANT SELECT, INSERT, UPDATE ON core.discovered TO nms_poller;
GRANT UPDATE (last_run_at) ON core.discovery_scan TO nms_poller;

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
