-- +goose Up
-- SNMPv3 authoritative engine IDs of the devices, learned by the poller from
-- its authenticated v3 polls and read by eventd, which pins the engine and
-- localizes the keys of a device at load time (no slow-path password hashing
-- for its first genuine trap after a restart). Also the grants the problem
-- engine (api) needs for the ssh host key and poller heartbeat system problems.
--
-- Trust: an engine ID only selects the fast path of eventd. A wrong one (a
-- compromised poller, or a replaced device) costs the slow path, never an
-- accepted message: the keys are derived from the device's own secrets. The
-- api has no rights on the table, so it cannot plant one. All pollers share
-- the nms_poller role, so SQL cannot tell them apart; the poller writes only
-- devices assigned to it (INSERT ... SELECT ... WHERE poller_id), and the
-- grant itself is the boundary against the api and eventd.
CREATE TABLE core.device_v3_engine (
    device_id bigint      PRIMARY KEY REFERENCES core.device (id) ON DELETE CASCADE,
    engine_id bytea       NOT NULL CHECK (octet_length(engine_id) BETWEEN 5 AND 32),
    seen_at   timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON core.device_v3_engine FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE (engine_id, seen_at) ON core.device_v3_engine TO nms_poller;
GRANT SELECT ON core.device_v3_engine TO nms_eventd;

-- A changed engine makes eventd (and the poller) reread, on the same channel
-- as device changes; an unchanged one notifies nobody.
CREATE TRIGGER device_v3_engine_inserted AFTER INSERT ON core.device_v3_engine
    FOR EACH ROW EXECUTE FUNCTION core.notify_device_changed();
CREATE TRIGGER device_v3_engine_changed AFTER UPDATE ON core.device_v3_engine
    FOR EACH ROW WHEN (OLD.engine_id IS DISTINCT FROM NEW.engine_id)
    EXECUTE FUNCTION core.notify_device_changed();

-- A template interval change must reach the poller too (the poller reads
-- core.monitoring_template for effective intervals).
CREATE TRIGGER monitoring_template_changed AFTER INSERT OR UPDATE OR DELETE ON core.monitoring_template
    FOR EACH STATEMENT EXECUTE FUNCTION core.notify_device_changed();

-- System problems of the engine: a host key mismatch per device and a silent
-- poller, from the real tables. Columns only: the fingerprints and addresses of
-- mismatch rows and nothing else stay out of the api's reach.
GRANT USAGE ON SCHEMA ssh_hosts TO nms_api;
GRANT SELECT (device_id, at) ON ssh_hosts.mismatch TO nms_api;
CREATE INDEX mismatch_at_idx ON ssh_hosts.mismatch (at);
GRANT SELECT (poller_id, at) ON inventory.poller_heartbeat TO nms_api;

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
