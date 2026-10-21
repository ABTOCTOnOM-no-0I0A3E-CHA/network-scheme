-- +goose Up
-- Job queue schema (River tables are created in it by store.Migrate after
-- the goose migrations) and change notifications for the poller.

CREATE SCHEMA jobs AUTHORIZATION nms_migrator;
REVOKE ALL ON SCHEMA jobs FROM PUBLIC;
GRANT USAGE ON SCHEMA jobs TO nms_api, nms_poller;

-- The poller listens on device_changed and rereads its device list. The
-- payload is empty: PostgreSQL delivers identical notifications of one
-- transaction once, and updates that change nothing do not notify.
-- +goose StatementBegin
CREATE FUNCTION core.notify_device_changed() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM pg_notify('device_changed', '');
    RETURN NULL;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION core.notify_device_changed() FROM PUBLIC;

CREATE TRIGGER device_changed AFTER INSERT OR DELETE ON core.device
    FOR EACH ROW EXECUTE FUNCTION core.notify_device_changed();
CREATE TRIGGER device_updated AFTER UPDATE ON core.device
    FOR EACH ROW WHEN (OLD IS DISTINCT FROM NEW) EXECUTE FUNCTION core.notify_device_changed();
CREATE TRIGGER device_group_intervals_changed
    AFTER UPDATE OF interval_avail_s, interval_metrics_s, interval_inventory_s ON core.device_group
    FOR EACH ROW WHEN (OLD.interval_avail_s IS DISTINCT FROM NEW.interval_avail_s
        OR OLD.interval_metrics_s IS DISTINCT FROM NEW.interval_metrics_s
        OR OLD.interval_inventory_s IS DISTINCT FROM NEW.interval_inventory_s)
    EXECUTE FUNCTION core.notify_device_changed();

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
