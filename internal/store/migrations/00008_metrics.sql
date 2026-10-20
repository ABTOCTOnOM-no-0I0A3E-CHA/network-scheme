-- +goose NO TRANSACTION
-- +goose Up
-- Metric hypertables, compression, continuous aggregates and retention.
-- Continuous aggregates cannot be created inside a transaction, so this
-- migration runs statement by statement; every statement is idempotent so a
-- run interrupted halfway can simply be repeated.
-- Rates are computed by the poller from two adjacent samples; raw counters
-- are not stored.
CREATE SCHEMA IF NOT EXISTS metrics;
REVOKE ALL ON SCHEMA metrics FROM PUBLIC;
GRANT USAGE ON SCHEMA metrics TO nms_api, nms_poller;

CREATE TABLE IF NOT EXISTS metrics.availability (
    device_id bigint      NOT NULL,
    ts        timestamptz NOT NULL,
    icmp_ok   bool        NOT NULL,
    snmp_ok   bool        NOT NULL,
    rtt_ms    real        NULL,
    state     text        NOT NULL CHECK (state IN ('up', 'partial', 'down', 'unknown'))
);

CREATE TABLE IF NOT EXISTS metrics.if_metrics (
    device_id   bigint           NOT NULL,
    if_index    int              NOT NULL,
    ts          timestamptz      NOT NULL,
    in_bps      double precision NOT NULL,
    out_bps     double precision NOT NULL,
    in_err_ps   double precision NULL,
    out_err_ps  double precision NULL,
    in_disc_ps  double precision NULL,
    out_disc_ps double precision NULL,
    oper_up     bool             NOT NULL,
    speed_bps   bigint           NOT NULL
);

CREATE TABLE IF NOT EXISTS metrics.sys_metrics (
    device_id    bigint      NOT NULL,
    ts           timestamptz NOT NULL,
    cpu_pct      real        NULL,
    mem_used_pct real        NULL,
    temp_c       real        NULL,
    psu_ok       bool        NULL
);

SELECT create_hypertable('metrics.availability', by_range('ts', INTERVAL '1 day'), if_not_exists => true);
SELECT create_hypertable('metrics.if_metrics', by_range('ts', INTERVAL '1 day'), if_not_exists => true);
SELECT create_hypertable('metrics.sys_metrics', by_range('ts', INTERVAL '1 day'), if_not_exists => true);

CREATE INDEX IF NOT EXISTS availability_device_ts_idx ON metrics.availability (device_id, ts DESC);
CREATE INDEX IF NOT EXISTS if_metrics_device_if_ts_idx ON metrics.if_metrics (device_id, if_index, ts DESC);
CREATE INDEX IF NOT EXISTS sys_metrics_device_ts_idx ON metrics.sys_metrics (device_id, ts DESC);

ALTER TABLE metrics.availability SET (timescaledb.compress,
    timescaledb.compress_segmentby = 'device_id', timescaledb.compress_orderby = 'ts DESC');
ALTER TABLE metrics.if_metrics SET (timescaledb.compress,
    timescaledb.compress_segmentby = 'device_id', timescaledb.compress_orderby = 'if_index, ts DESC');
ALTER TABLE metrics.sys_metrics SET (timescaledb.compress,
    timescaledb.compress_segmentby = 'device_id', timescaledb.compress_orderby = 'ts DESC');

SELECT add_compression_policy('metrics.availability', INTERVAL '2 days', if_not_exists => true);
SELECT add_compression_policy('metrics.if_metrics', INTERVAL '2 days', if_not_exists => true);
SELECT add_compression_policy('metrics.sys_metrics', INTERVAL '2 days', if_not_exists => true);

SELECT add_retention_policy('metrics.availability', INTERVAL '14 days', if_not_exists => true);
SELECT add_retention_policy('metrics.if_metrics', INTERVAL '14 days', if_not_exists => true);
SELECT add_retention_policy('metrics.sys_metrics', INTERVAL '14 days', if_not_exists => true);

-- Aggregates are built from the raw tables. Refresh windows stay well inside
-- the 14-day raw retention: refreshing a range whose raw data was already
-- dropped would erase the aggregated history.
CREATE MATERIALIZED VIEW IF NOT EXISTS metrics.if_metrics_5m
    WITH (timescaledb.continuous, timescaledb.materialized_only = true) AS
SELECT device_id, if_index, time_bucket(INTERVAL '5 minutes', ts) AS ts,
       avg(in_bps) AS in_bps, max(in_bps) AS in_bps_max,
       avg(out_bps) AS out_bps, max(out_bps) AS out_bps_max,
       avg(in_err_ps) AS in_err_ps, avg(out_err_ps) AS out_err_ps,
       avg(in_disc_ps) AS in_disc_ps, avg(out_disc_ps) AS out_disc_ps,
       bool_and(oper_up) AS oper_up, max(speed_bps) AS speed_bps
FROM metrics.if_metrics
GROUP BY device_id, if_index, time_bucket(INTERVAL '5 minutes', ts)
WITH NO DATA;

CREATE MATERIALIZED VIEW IF NOT EXISTS metrics.if_metrics_1h
    WITH (timescaledb.continuous, timescaledb.materialized_only = true) AS
SELECT device_id, if_index, time_bucket(INTERVAL '1 hour', ts) AS ts,
       avg(in_bps) AS in_bps, max(in_bps) AS in_bps_max,
       avg(out_bps) AS out_bps, max(out_bps) AS out_bps_max,
       avg(in_err_ps) AS in_err_ps, avg(out_err_ps) AS out_err_ps,
       avg(in_disc_ps) AS in_disc_ps, avg(out_disc_ps) AS out_disc_ps,
       bool_and(oper_up) AS oper_up, max(speed_bps) AS speed_bps
FROM metrics.if_metrics
GROUP BY device_id, if_index, time_bucket(INTERVAL '1 hour', ts)
WITH NO DATA;

CREATE MATERIALIZED VIEW IF NOT EXISTS metrics.sys_metrics_5m
    WITH (timescaledb.continuous, timescaledb.materialized_only = true) AS
SELECT device_id, time_bucket(INTERVAL '5 minutes', ts) AS ts,
       avg(cpu_pct) AS cpu_pct, max(cpu_pct) AS cpu_pct_max,
       avg(mem_used_pct) AS mem_used_pct, max(mem_used_pct) AS mem_used_pct_max,
       avg(temp_c) AS temp_c, max(temp_c) AS temp_c_max,
       bool_and(psu_ok) AS psu_ok
FROM metrics.sys_metrics
GROUP BY device_id, time_bucket(INTERVAL '5 minutes', ts)
WITH NO DATA;

CREATE MATERIALIZED VIEW IF NOT EXISTS metrics.sys_metrics_1h
    WITH (timescaledb.continuous, timescaledb.materialized_only = true) AS
SELECT device_id, time_bucket(INTERVAL '1 hour', ts) AS ts,
       avg(cpu_pct) AS cpu_pct, max(cpu_pct) AS cpu_pct_max,
       avg(mem_used_pct) AS mem_used_pct, max(mem_used_pct) AS mem_used_pct_max,
       avg(temp_c) AS temp_c, max(temp_c) AS temp_c_max,
       bool_and(psu_ok) AS psu_ok
FROM metrics.sys_metrics
GROUP BY device_id, time_bucket(INTERVAL '1 hour', ts)
WITH NO DATA;

CREATE MATERIALIZED VIEW IF NOT EXISTS metrics.availability_1h
    WITH (timescaledb.continuous, timescaledb.materialized_only = true) AS
SELECT device_id, time_bucket(INTERVAL '1 hour', ts) AS ts,
       avg(icmp_ok::int) AS icmp_ok_ratio, avg(snmp_ok::int) AS snmp_ok_ratio,
       avg((state = 'up')::int) AS up_ratio,
       avg(rtt_ms) AS rtt_ms, max(rtt_ms) AS rtt_ms_max
FROM metrics.availability
GROUP BY device_id, time_bucket(INTERVAL '1 hour', ts)
WITH NO DATA;

SELECT add_continuous_aggregate_policy('metrics.if_metrics_5m',
    start_offset => INTERVAL '1 day', end_offset => INTERVAL '5 minutes',
    schedule_interval => INTERVAL '5 minutes', if_not_exists => true);
SELECT add_continuous_aggregate_policy('metrics.sys_metrics_5m',
    start_offset => INTERVAL '1 day', end_offset => INTERVAL '5 minutes',
    schedule_interval => INTERVAL '5 minutes', if_not_exists => true);
SELECT add_continuous_aggregate_policy('metrics.if_metrics_1h',
    start_offset => INTERVAL '3 days', end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour', if_not_exists => true);
SELECT add_continuous_aggregate_policy('metrics.sys_metrics_1h',
    start_offset => INTERVAL '3 days', end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour', if_not_exists => true);
SELECT add_continuous_aggregate_policy('metrics.availability_1h',
    start_offset => INTERVAL '3 days', end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour', if_not_exists => true);

SELECT add_retention_policy('metrics.if_metrics_5m', INTERVAL '90 days', if_not_exists => true);
SELECT add_retention_policy('metrics.sys_metrics_5m', INTERVAL '90 days', if_not_exists => true);
SELECT add_retention_policy('metrics.if_metrics_1h', INTERVAL '730 days', if_not_exists => true);
SELECT add_retention_policy('metrics.sys_metrics_1h', INTERVAL '730 days', if_not_exists => true);
SELECT add_retention_policy('metrics.availability_1h', INTERVAL '730 days', if_not_exists => true);

REVOKE ALL ON ALL TABLES IN SCHEMA metrics FROM PUBLIC;
-- The poller appends and reads back raw points; nobody updates or deletes
-- them (the retention jobs run as the owner).
GRANT SELECT, INSERT ON metrics.availability, metrics.if_metrics, metrics.sys_metrics TO nms_poller;
GRANT SELECT ON metrics.availability, metrics.if_metrics, metrics.sys_metrics,
    metrics.if_metrics_5m, metrics.if_metrics_1h, metrics.sys_metrics_5m,
    metrics.sys_metrics_1h, metrics.availability_1h TO nms_api;

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
