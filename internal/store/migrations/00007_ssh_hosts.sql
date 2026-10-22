-- +goose Up
-- SSH host keys pinned per device on first use, and rejected keys.
-- Only the poller reads and pins keys; resetting a pin is a host-only action (nms_cli).
CREATE SCHEMA IF NOT EXISTS ssh_hosts;
REVOKE ALL ON SCHEMA ssh_hosts FROM PUBLIC;

-- Keyed by device only: an address change never resets the pin. No FK to
-- core.device: a pin outlives its device and only nmsctl removes it.
CREATE TABLE ssh_hosts.host_key (
    device_id          bigint      PRIMARY KEY,
    algorithm          text        NOT NULL CHECK (algorithm <> ''),
    fingerprint_sha256 text        NOT NULL CHECK (fingerprint_sha256 LIKE 'SHA256:%'),
    first_seen         timestamptz NOT NULL DEFAULT now(),
    last_seen          timestamptz NOT NULL DEFAULT now()
);

-- Append-only record of keys that did not match the pin (kept after device deletion).
CREATE TABLE ssh_hosts.mismatch (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id        bigint      NOT NULL,
    seen_fingerprint text        NOT NULL,
    address          inet        NOT NULL,
    at               timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX mismatch_device_id_idx ON ssh_hosts.mismatch (device_id);

REVOKE ALL ON ssh_hosts.host_key, ssh_hosts.mismatch FROM PUBLIC;

GRANT USAGE ON SCHEMA ssh_hosts TO nms_poller, nms_cli;
GRANT SELECT, INSERT, UPDATE (last_seen) ON ssh_hosts.host_key TO nms_poller;
GRANT INSERT ON ssh_hosts.mismatch TO nms_poller;
-- DELETE ... WHERE device_id needs SELECT; fingerprints are not secret.
GRANT SELECT, DELETE ON ssh_hosts.host_key TO nms_cli;
GRANT SELECT ON ssh_hosts.mismatch TO nms_cli;

-- Device ids are never reused, so an id always names the same device for pins
-- and sealed credentials: explicit ids (OVERRIDING SYSTEM VALUE), id changes
-- and re-use of a deleted id are refused.
CREATE TABLE core.device_retired (
    id bigint PRIMARY KEY
);
REVOKE ALL ON core.device_retired FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION core.device_guard_id() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    generated bigint;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'device id cannot change' USING ERRCODE = '42501';
    END IF;
    BEGIN
        generated := currval(pg_get_serial_sequence('core.device', 'id'));
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        generated := NULL;
    END;
    IF NEW.id IS DISTINCT FROM generated
       OR EXISTS (SELECT 1 FROM core.device_retired WHERE id = NEW.id) THEN
        RAISE EXCEPTION 'device id must come from its identity sequence' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd

-- Sealed credentials never outlive their device, whatever the deletion path.
-- +goose StatementBegin
CREATE FUNCTION core.device_after_delete() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    DELETE FROM core.access_profile WHERE owner_kind = 'device' AND owner_id = OLD.id;
    INSERT INTO core.device_retired (id) VALUES (OLD.id) ON CONFLICT DO NOTHING;
    RETURN NULL;
END $$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION core.device_guard_id(), core.device_after_delete() FROM PUBLIC;

CREATE TRIGGER device_guard_id_insert BEFORE INSERT ON core.device
    FOR EACH ROW EXECUTE FUNCTION core.device_guard_id();
CREATE TRIGGER device_guard_id_update BEFORE UPDATE OF id ON core.device
    FOR EACH ROW WHEN (NEW.id IS DISTINCT FROM OLD.id) EXECUTE FUNCTION core.device_guard_id();
CREATE TRIGGER device_after_delete AFTER DELETE ON core.device
    FOR EACH ROW EXECUTE FUNCTION core.device_after_delete();

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
