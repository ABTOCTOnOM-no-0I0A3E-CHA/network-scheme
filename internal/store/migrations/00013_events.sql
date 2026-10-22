-- +goose Up
-- Syslog and SNMP trap events (written by eventd, read by the api), storm
-- aggregates, eventd counters and the operator-managed trap rules.
-- Hypertables are append-only for every application role: eventd gets INSERT
-- only, retention and compression jobs run as the owner. Everything here comes
-- from untrusted devices, so the table bounds repeat the parser limits.
CREATE SCHEMA events AUTHORIZATION nms_migrator;
REVOKE ALL ON SCHEMA events FROM PUBLIC;
GRANT USAGE ON SCHEMA events TO nms_api, nms_eventd;
-- eventd resolves the source address to a device and the SNMP credentials to
-- check the packet against (read profiles only; the sealed rows stay opaque).
GRANT USAGE ON SCHEMA core TO nms_eventd;
GRANT USAGE ON SCHEMA jobs TO nms_eventd;

CREATE TABLE events.syslog (
    ts        timestamptz NOT NULL,
    device_id bigint      NOT NULL,
    facility  smallint    NOT NULL CHECK (facility BETWEEN 0 AND 23),
    severity  smallint    NOT NULL CHECK (severity BETWEEN 0 AND 7),
    host      text        NOT NULL CHECK (octet_length(host) <= 1024),
    app       text        NOT NULL CHECK (octet_length(app) <= 1024),
    msg       text        NOT NULL CHECK (octet_length(msg) <= 8192),
    raw_len   int         NOT NULL CHECK (raw_len >= 0),
    tsv       tsvector    GENERATED ALWAYS AS (to_tsvector('simple', msg)) STORED
);

CREATE TABLE events.trap (
    ts         timestamptz NOT NULL,
    device_id  bigint      NOT NULL,
    version    smallint    NOT NULL CHECK (version IN (1, 2, 3)),
    trap_oid   text        NOT NULL CHECK (octet_length(trap_oid) <= 2048),
    name       text        NOT NULL CHECK (octet_length(name) <= 1024),
    severity   text        NULL CHECK (severity IN ('info', 'warning', 'average', 'high', 'disaster')),
    -- 128 varbinds x 2 KiB values plus JSON overhead stays under 300000 bytes.
    varbinds   jsonb       NOT NULL CHECK (octet_length(varbinds::text) <= 300000),
    identified bool        NOT NULL,
    -- Full-text search covers the varbind string values only, not the JSON keys (oid, type, value).
    tsv        tsvector    GENERATED ALWAYS AS (
        jsonb_to_tsvector('simple', varbinds, '["string"]') ||
        to_tsvector('simple', coalesce(name, '') || ' ' || trap_oid)) STORED
);

-- Per source and minute: how many events above the rate limit were folded.
CREATE TABLE events.storm (
    ts        timestamptz NOT NULL,
    device_id bigint      NOT NULL,
    kind      text        NOT NULL CHECK (kind IN ('syslog', 'trap')),
    count     int         NOT NULL CHECK (count > 0)
);

SELECT create_hypertable('events.syslog', by_range('ts', INTERVAL '1 day'));
SELECT create_hypertable('events.trap', by_range('ts', INTERVAL '1 day'));
SELECT create_hypertable('events.storm', by_range('ts', INTERVAL '7 days'));

CREATE INDEX syslog_device_ts_idx ON events.syslog (device_id, ts DESC);
CREATE INDEX syslog_tsv_idx ON events.syslog USING gin (tsv);
CREATE INDEX trap_device_ts_idx ON events.trap (device_id, ts DESC);
CREATE INDEX trap_tsv_idx ON events.trap USING gin (tsv);
CREATE INDEX storm_device_ts_idx ON events.storm (device_id, ts DESC);

ALTER TABLE events.syslog SET (timescaledb.compress,
    timescaledb.compress_segmentby = 'device_id', timescaledb.compress_orderby = 'ts DESC');
ALTER TABLE events.trap SET (timescaledb.compress,
    timescaledb.compress_segmentby = 'device_id', timescaledb.compress_orderby = 'ts DESC');
SELECT add_compression_policy('events.syslog', INTERVAL '7 days');
SELECT add_compression_policy('events.trap', INTERVAL '7 days');

-- 90 days by default; the policy can be rescheduled by the owner.
SELECT add_retention_policy('events.syslog', INTERVAL '90 days');
SELECT add_retention_policy('events.trap', INTERVAL '90 days');
SELECT add_retention_policy('events.storm', INTERVAL '90 days');

CREATE TABLE events.eventd_stats (
    instance       text        PRIMARY KEY CHECK (octet_length(instance) <= 200),
    updated_at     timestamptz NOT NULL,
    received       bigint      NOT NULL DEFAULT 0,
    accepted       bigint      NOT NULL DEFAULT 0,
    unknown_source bigint      NOT NULL DEFAULT 0,
    auth_failed    bigint      NOT NULL DEFAULT 0,
    rate_limited   bigint      NOT NULL DEFAULT 0,
    dropped        bigint      NOT NULL DEFAULT 0,
    queue_depth    int         NOT NULL DEFAULT 0
);

-- Operator-defined trap OID -> name and severity; eventd reloads on NOTIFY.
CREATE TABLE events.trap_rule (
    id         bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    trap_oid   text        NOT NULL UNIQUE CHECK (octet_length(trap_oid) <= 2048),
    name       text        NOT NULL CHECK (octet_length(name) <= 1024),
    severity   text        NOT NULL CHECK (severity IN ('info', 'warning', 'average', 'high', 'disaster')),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Written by the trigger, not by api code: any change to the rules wakes
-- eventd. Empty payload; identical notifications of a transaction merge.
-- +goose StatementBegin
CREATE FUNCTION events.notify_trap_rules() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM pg_notify('trap_rules', '');
    RETURN NULL;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION events.notify_trap_rules() FROM PUBLIC;

CREATE TRIGGER trap_rules_changed AFTER INSERT OR UPDATE OR DELETE ON events.trap_rule
    FOR EACH STATEMENT EXECUTE FUNCTION events.notify_trap_rules();

REVOKE ALL ON ALL TABLES IN SCHEMA events FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA events FROM PUBLIC;
-- eventd only appends events; nothing but the owner's jobs removes them.
GRANT INSERT ON events.syslog, events.trap, events.storm TO nms_eventd;
-- SELECT: the counters are bumped with INSERT ... ON CONFLICT DO UPDATE SET x = t.x + ...
GRANT SELECT, INSERT, UPDATE ON events.eventd_stats TO nms_eventd;
GRANT SELECT ON events.trap_rule TO nms_eventd;
-- The core data eventd resolves sources with; no write access. Never the whole
-- access_profile table: ssh_read/telnet_read and scan-owned rows stay out of
-- reach of a network-facing parser. The view runs with the owner's rights.
CREATE VIEW core.event_auth_profile_v WITH (security_barrier = true) AS
SELECT owner_id AS device_id, kind, ciphertext, key_version, status, updated_at
FROM core.access_profile
WHERE owner_kind = 'device' AND kind IN ('snmp2c', 'snmp3');
REVOKE ALL ON core.event_auth_profile_v FROM PUBLIC;
GRANT SELECT ON core.device TO nms_eventd;
GRANT SELECT ON core.event_auth_profile_v TO nms_eventd;

GRANT SELECT ON events.syslog, events.trap, events.storm, events.eventd_stats TO nms_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON events.trap_rule TO nms_api;
GRANT USAGE ON SEQUENCE events.trap_rule_id_seq TO nms_api;

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
