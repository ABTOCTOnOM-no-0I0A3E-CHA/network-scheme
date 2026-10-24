-- +goose Up
-- Phase 3: configuration backups, on-demand `show` results, dashboards, the
-- per-object backup interval and the port kind of an interface.
--
-- The api never sees full configurations: it has no right on the columns
-- full_ct and full_dek_ct of backups.config_version (not even the ciphertext),
-- only the masked copy is readable by it.

-- Backup interval in seconds; NULL means the default (24 h). Existing
-- table-level grants of the api (DML) and the poller (SELECT) cover the columns.
ALTER TABLE core.monitoring_template
    ADD COLUMN interval_backup_s int NULL CHECK (interval_backup_s BETWEEN 3600 AND 2592000);
ALTER TABLE core.device_group
    ADD COLUMN interval_backup_s int NULL CHECK (interval_backup_s BETWEEN 3600 AND 2592000);
ALTER TABLE core.device
    ADD COLUMN interval_backup_s int NULL CHECK (interval_backup_s BETWEEN 3600 AND 2592000);

-- Physical port kind (set by the poller from the driver); poller and api
-- already have table-level rights on inventory.interface.
ALTER TABLE inventory.interface
    ADD COLUMN port_kind text NOT NULL DEFAULT 'other' CHECK (port_kind IN ('rj45', 'sfp', 'other'));

CREATE SCHEMA backups AUTHORIZATION nms_migrator;
REVOKE ALL ON SCHEMA backups FROM PUBLIC;
GRANT USAGE ON SCHEMA backups TO nms_api, nms_poller;

-- Config versions are history: no foreign keys (a device delete must not
-- cascade into an append-only table; device ids are never reused), append-only
-- for every role and, through the statement-level trigger, for the owner too.
-- id and taken_at are not insertable: the database sets them.
CREATE TABLE backups.config_version (
    id           bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id    bigint      NOT NULL,
    taken_at     timestamptz NOT NULL DEFAULT now(),
    source       text        NOT NULL CHECK (source IN ('schedule', 'event', 'manual', 'pre_session')),
    sha256       bytea       NOT NULL CHECK (octet_length(sha256) = 32),
    size         int         NOT NULL CHECK (size BETWEEN 0 AND 4 * 1024 * 1024),
    masked       text        NOT NULL CHECK (octet_length(masked) <= 4 * 1024 * 1024),
    full_ct      bytea       NOT NULL CHECK (octet_length(full_ct) <= 4 * 1024 * 1024 + 1024),
    full_dek_ct  bytea       NOT NULL CHECK (octet_length(full_dek_ct) BETWEEN 1 AND 1024),
    drift        bool        NOT NULL DEFAULT false,
    taken_by_job bigint      NULL
);
CREATE INDEX config_version_device_taken_idx ON backups.config_version (device_id, taken_at DESC);

CREATE TRIGGER config_version_guard_id_insert BEFORE INSERT ON backups.config_version
    FOR EACH ROW EXECUTE FUNCTION core.guard_identity_id();
CREATE TRIGGER config_version_guard_id_update BEFORE UPDATE OF id ON backups.config_version
    FOR EACH ROW WHEN (NEW.id IS DISTINCT FROM OLD.id) EXECUTE FUNCTION core.guard_identity_id();
CREATE TRIGGER config_version_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON backups.config_version
    FOR EACH STATEMENT EXECUTE FUNCTION core.reject_modification();

CREATE TABLE backups.backup_state (
    device_id   bigint      PRIMARY KEY REFERENCES core.device (id) ON DELETE CASCADE,
    last_ok_at  timestamptz NULL,
    last_error  text        NULL CHECK (octet_length(last_error) <= 1024),
    last_sha256 bytea       NULL CHECK (octet_length(last_sha256) = 32),
    needs_write bool        NOT NULL DEFAULT false
);

-- A request for `show` output: the api records it, the poller runs it and
-- writes the result columns, expired rows are deleted by the poller. The ids
-- are guarded on insert but not retired (rows are short-lived by design).
CREATE TABLE backups.show_result (
    id           bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id    bigint      NOT NULL REFERENCES core.device (id) ON DELETE CASCADE,
    user_id      bigint      NOT NULL REFERENCES core."user" (id),
    command_key  text        NOT NULL CHECK (command_key ~ '^[a-z0-9_.-]{1,64}$'),
    args         jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(args) = 'object' AND octet_length(args::text) <= 1024),
    requested_at timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz NULL,
    status       text        NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'failed')),
    output       text        NULL CHECK (octet_length(output) <= 1024 * 1024),
    truncated    bool        NOT NULL DEFAULT false,
    expires_at   timestamptz NOT NULL DEFAULT now() + interval '1 hour'
);
CREATE INDEX show_result_expires_idx ON backups.show_result (expires_at);
CREATE INDEX show_result_device_idx ON backups.show_result (device_id);

CREATE TRIGGER show_result_guard_id_insert BEFORE INSERT ON backups.show_result
    FOR EACH ROW EXECUTE FUNCTION core.guard_identity_id();
CREATE TRIGGER show_result_guard_id_update BEFORE UPDATE OF id ON backups.show_result
    FOR EACH ROW WHEN (NEW.id IS DISTINCT FROM OLD.id) EXECUTE FUNCTION core.guard_identity_id();

-- Dashboards: personal (owner_id set) or shared (owner_id NULL, managed by
-- admins); a shared one may be the default for a role (one per role).
CREATE TABLE core.dashboard (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    owner_id         bigint NULL REFERENCES core."user" (id),
    name             text   NOT NULL CHECK (name <> '' AND char_length(name) <= 200),
    shared           bool   NOT NULL DEFAULT false,
    default_for_role text   NULL CHECK (default_for_role IN ('viewer', 'operator', 'admin', 'auditor')),
    CONSTRAINT dashboard_shared_owner CHECK (shared = (owner_id IS NULL)),
    CONSTRAINT dashboard_default_shared CHECK (default_for_role IS NULL OR shared)
);
CREATE INDEX dashboard_owner_id_idx ON core.dashboard (owner_id);
CREATE UNIQUE INDEX dashboard_default_role_idx ON core.dashboard (default_for_role) WHERE default_for_role IS NOT NULL;

CREATE TABLE core.dashboard_widget (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    dashboard_id bigint NOT NULL REFERENCES core.dashboard (id) ON DELETE CASCADE,
    type         text   NOT NULL CHECK (type ~ '^[a-z0-9_.-]{1,64}$'),
    x            int    NOT NULL CHECK (x BETWEEN 0 AND 1000),
    y            int    NOT NULL CHECK (y BETWEEN 0 AND 1000),
    w            int    NOT NULL CHECK (w BETWEEN 1 AND 48),
    h            int    NOT NULL CHECK (h BETWEEN 1 AND 48),
    config       jsonb  NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(config) = 'object' AND octet_length(config::text) <= 16384)
);
CREATE INDEX dashboard_widget_dashboard_id_idx ON core.dashboard_widget (dashboard_id);

CREATE TRIGGER dashboard_guard_id_insert BEFORE INSERT ON core.dashboard
    FOR EACH ROW EXECUTE FUNCTION core.guard_identity_id();
CREATE TRIGGER dashboard_guard_id_update BEFORE UPDATE OF id ON core.dashboard
    FOR EACH ROW WHEN (NEW.id IS DISTINCT FROM OLD.id) EXECUTE FUNCTION core.guard_identity_id();
CREATE TRIGGER dashboard_after_delete AFTER DELETE ON core.dashboard
    FOR EACH ROW EXECUTE FUNCTION core.retire_identity_id();
CREATE TRIGGER dashboard_widget_guard_id_insert BEFORE INSERT ON core.dashboard_widget
    FOR EACH ROW EXECUTE FUNCTION core.guard_identity_id();
CREATE TRIGGER dashboard_widget_guard_id_update BEFORE UPDATE OF id ON core.dashboard_widget
    FOR EACH ROW WHEN (NEW.id IS DISTINCT FROM OLD.id) EXECUTE FUNCTION core.guard_identity_id();
CREATE TRIGGER dashboard_widget_after_delete AFTER DELETE ON core.dashboard_widget
    FOR EACH ROW EXECUTE FUNCTION core.retire_identity_id();

-- Caps: at most 50 dashboards per owner (shared ones count together) and 50
-- widgets per dashboard. Run with the caller's rights; the advisory lock
-- serializes concurrent inserts (READ COMMITTED, as in device_check_parent).
-- +goose StatementBegin
CREATE FUNCTION core.dashboard_check_cap() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('core.dashboard.cap:' || coalesce(NEW.owner_id::text, '')));
    IF (SELECT count(*) FROM core.dashboard WHERE owner_id IS NOT DISTINCT FROM NEW.owner_id) >= 50 THEN
        RAISE EXCEPTION 'too many dashboards' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION core.dashboard_widget_check_cap() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('core.dashboard_widget.cap:' || NEW.dashboard_id::text));
    IF (SELECT count(*) FROM core.dashboard_widget WHERE dashboard_id = NEW.dashboard_id) >= 50 THEN
        RAISE EXCEPTION 'too many widgets' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION core.dashboard_check_cap(), core.dashboard_widget_check_cap() FROM PUBLIC;

CREATE TRIGGER dashboard_check_cap BEFORE INSERT ON core.dashboard
    FOR EACH ROW EXECUTE FUNCTION core.dashboard_check_cap();
CREATE TRIGGER dashboard_widget_check_cap BEFORE INSERT ON core.dashboard_widget
    FOR EACH ROW EXECUTE FUNCTION core.dashboard_widget_check_cap();

REVOKE ALL ON ALL TABLES IN SCHEMA backups FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA backups FROM PUBLIC;
REVOKE ALL ON core.dashboard, core.dashboard_widget FROM PUBLIC;

-- config_version: the api reads everything except the ciphertext columns.
GRANT SELECT (id, device_id, taken_at, source, sha256, size, masked, drift, taken_by_job)
    ON backups.config_version TO nms_api;
GRANT SELECT ON backups.config_version TO nms_poller;
GRANT INSERT (device_id, source, sha256, size, masked, full_ct, full_dek_ct, drift, taken_by_job)
    ON backups.config_version TO nms_poller;
GRANT SELECT, INSERT, UPDATE ON backups.backup_state TO nms_poller;
GRANT SELECT ON backups.backup_state TO nms_api;
GRANT SELECT ON backups.show_result TO nms_api, nms_poller;
GRANT INSERT (device_id, user_id, command_key, args) ON backups.show_result TO nms_api;
GRANT UPDATE (finished_at, status, output, truncated) ON backups.show_result TO nms_poller;
GRANT DELETE ON backups.show_result TO nms_poller;
GRANT SELECT, INSERT, UPDATE, DELETE ON core.dashboard, core.dashboard_widget TO nms_api;
GRANT USAGE ON SEQUENCE backups.config_version_id_seq TO nms_poller;
GRANT USAGE ON SEQUENCE backups.show_result_id_seq TO nms_api;
GRANT USAGE ON SEQUENCE core.dashboard_id_seq, core.dashboard_widget_id_seq TO nms_api;

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
