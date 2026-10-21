-- +goose Up
-- Discovery scans: the poller that runs them, the same id protection as
-- devices, and bounded device-derived text in the inbox.

-- A scan is run by the poller with this id (as devices are polled).
ALTER TABLE core.discovery_scan ADD COLUMN poller_id text NOT NULL DEFAULT 'local';

UPDATE core.discovered SET sys_object_id = left(sys_object_id, 1024), sys_descr = left(sys_descr, 1024),
    sys_name = left(sys_name, 1024)
WHERE char_length(sys_object_id) > 1024 OR char_length(sys_descr) > 1024 OR char_length(sys_name) > 1024;
ALTER TABLE core.discovered ADD CONSTRAINT discovered_text_len CHECK (
    char_length(sys_object_id) <= 1024 AND char_length(sys_descr) <= 1024 AND char_length(sys_name) <= 1024);

-- Scan ids are never reused, so an id always names the same scan for its
-- sealed profile: explicit ids (OVERRIDING SYSTEM VALUE), id changes and
-- re-use of a deleted id are refused.
CREATE TABLE core.discovery_scan_retired (
    id bigint PRIMARY KEY
);
REVOKE ALL ON core.discovery_scan_retired FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION core.discovery_scan_guard_id() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    generated bigint;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'discovery scan id cannot change' USING ERRCODE = '42501';
    END IF;
    BEGIN
        generated := currval(pg_get_serial_sequence('core.discovery_scan', 'id'));
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        generated := NULL;
    END;
    IF NEW.id IS DISTINCT FROM generated
       OR EXISTS (SELECT 1 FROM core.discovery_scan_retired WHERE id = NEW.id) THEN
        RAISE EXCEPTION 'discovery scan id must come from its identity sequence' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd

-- A scan's sealed credential never outlives the scan, whatever the deletion path.
-- +goose StatementBegin
CREATE FUNCTION core.discovery_scan_after_delete() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    DELETE FROM core.access_profile WHERE owner_kind = 'scan' AND owner_id = OLD.id;
    INSERT INTO core.discovery_scan_retired (id) VALUES (OLD.id) ON CONFLICT DO NOTHING;
    RETURN NULL;
END $$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION core.discovery_scan_guard_id(), core.discovery_scan_after_delete() FROM PUBLIC;

CREATE TRIGGER discovery_scan_guard_id_insert BEFORE INSERT ON core.discovery_scan
    FOR EACH ROW EXECUTE FUNCTION core.discovery_scan_guard_id();
CREATE TRIGGER discovery_scan_guard_id_update BEFORE UPDATE OF id ON core.discovery_scan
    FOR EACH ROW WHEN (NEW.id IS DISTINCT FROM OLD.id) EXECUTE FUNCTION core.discovery_scan_guard_id();
CREATE TRIGGER discovery_scan_after_delete AFTER DELETE ON core.discovery_scan
    FOR EACH ROW EXECUTE FUNCTION core.discovery_scan_after_delete();

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
