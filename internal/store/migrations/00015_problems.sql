-- +goose Up
-- Phase 1c: monitoring templates and triggers, maintenance windows, the device
-- parent, and the problems schema the trigger engine writes to.

-- Device parent (set by hand). A parent's open availability problem suppresses
-- the children's problems. The link is a forest of depth <= 16: the check below
-- rejects cycles and over-deep chains. Deleting a parent orphans its children.
ALTER TABLE core.device
    ADD COLUMN parent_id bigint NULL REFERENCES core.device (id) ON DELETE SET NULL,
    ADD CONSTRAINT device_parent_not_self CHECK (parent_id IS NULL OR parent_id <> id);
CREATE INDEX device_parent_id_idx ON core.device (parent_id);

-- Runs with the caller's rights (the api has SELECT on core.device). The
-- advisory lock serializes parent changes so two concurrent transactions
-- cannot each pass the check and together close a cycle. This relies on READ
-- COMMITTED (the default): each statement then takes a fresh snapshot after the
-- lock is granted, so it sees the other transaction's committed parent change.
-- Under REPEATABLE READ or SERIALIZABLE the snapshot predates the lock.
-- +goose StatementBegin
CREATE FUNCTION core.device_check_parent() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    up      int;
    down    int;
    is_loop bool;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('core.device.parent'));
    WITH RECURSIVE anc(id, depth) AS (
        SELECT NEW.parent_id, 1
        UNION ALL
        SELECT d.parent_id, anc.depth + 1 FROM anc JOIN core.device d ON d.id = anc.id
        WHERE d.parent_id IS NOT NULL AND anc.depth < 17
    )
    SELECT coalesce(max(depth), 0), coalesce(bool_or(id = NEW.id), false) INTO up, is_loop FROM anc;
    IF is_loop THEN
        RAISE EXCEPTION 'device parent would create a cycle' USING ERRCODE = '23514';
    END IF;
    WITH RECURSIVE kids(id, depth) AS (
        SELECT id, 1 FROM core.device WHERE parent_id = NEW.id
        UNION ALL
        SELECT d.id, kids.depth + 1 FROM kids JOIN core.device d ON d.parent_id = kids.id WHERE kids.depth < 17
    )
    SELECT coalesce(max(depth), 0) INTO down FROM kids;
    IF up + 1 + down > 16 THEN
        RAISE EXCEPTION 'device parent chain is deeper than 16' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION core.device_check_parent() FROM PUBLIC;

CREATE TRIGGER device_check_parent BEFORE INSERT OR UPDATE OF parent_id ON core.device
    FOR EACH ROW WHEN (NEW.parent_id IS NOT NULL) EXECUTE FUNCTION core.device_check_parent();

-- Ids of templates and triggers come only from their identity sequences and are
-- never reused: explicit ids (OVERRIDING SYSTEM VALUE), id changes and re-use of
-- a deleted id are refused, as for devices.
CREATE TABLE core.identity_retired (
    tbl text   NOT NULL,
    id  bigint NOT NULL,
    PRIMARY KEY (tbl, id)
);
REVOKE ALL ON core.identity_retired FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION core.guard_identity_id() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    generated bigint;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION '% id cannot change', TG_TABLE_NAME USING ERRCODE = '42501';
    END IF;
    BEGIN
        generated := currval(pg_get_serial_sequence(TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME, 'id'));
    EXCEPTION WHEN object_not_in_prerequisite_state THEN
        generated := NULL;
    END;
    IF NEW.id IS DISTINCT FROM generated
       OR EXISTS (SELECT 1 FROM core.identity_retired WHERE tbl = TG_TABLE_NAME AND id = NEW.id) THEN
        RAISE EXCEPTION '% id must come from its identity sequence', TG_TABLE_NAME USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION core.retire_identity_id() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    INSERT INTO core.identity_retired (tbl, id) VALUES (TG_TABLE_NAME, OLD.id) ON CONFLICT DO NOTHING;
    RETURN NULL;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION core.guard_identity_id(), core.retire_identity_id() FROM PUBLIC;

-- A template applies to every device of a driver or of a group (and its
-- subgroups); intervals override the group/default ones for those devices.
CREATE TABLE core.monitoring_template (
    id                   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name                 text   NOT NULL CHECK (name <> '' AND char_length(name) <= 200),
    driver               text   NULL CHECK (driver <> '' AND char_length(driver) <= 200),
    group_id             bigint NULL REFERENCES core.device_group (id) ON DELETE CASCADE,
    interval_avail_s     int    NULL CHECK (interval_avail_s > 0),
    interval_metrics_s   int    NULL CHECK (interval_metrics_s > 0),
    interval_inventory_s int    NULL CHECK (interval_inventory_s > 0),
    CONSTRAINT monitoring_template_target CHECK (num_nonnulls(driver, group_id) = 1)
);
CREATE INDEX monitoring_template_group_id_idx ON core.monitoring_template (group_id);
-- Names are unique per binding (one driver or one group), not globally.
CREATE UNIQUE INDEX monitoring_template_name_binding_idx ON core.monitoring_template (name, coalesce(driver, ''), coalesce(group_id, 0));

-- Conditions are a closed set (see internal/triggers); params are validated by
-- the api and the engine, the table only bounds their shape and size.
CREATE TABLE core.trigger (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    template_id bigint  NOT NULL REFERENCES core.monitoring_template (id) ON DELETE CASCADE,
    kind        text    NOT NULL CHECK (kind IN ('availability', 'if_oper_down', 'metric_threshold', 'trap', 'syslog')),
    params      jsonb   NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(params) = 'object' AND octet_length(params::text) <= 4096),
    duration_s  int     NOT NULL DEFAULT 0 CHECK (duration_s BETWEEN 0 AND 86400),
    severity    text    NOT NULL CHECK (severity IN ('info', 'warning', 'average', 'high', 'disaster')),
    enabled     bool    NOT NULL DEFAULT true,
    name        text    NOT NULL CHECK (name <> '' AND char_length(name) <= 200)
);
CREATE INDEX trigger_template_id_idx ON core.trigger (template_id);

CREATE TRIGGER monitoring_template_guard_id_insert BEFORE INSERT ON core.monitoring_template
    FOR EACH ROW EXECUTE FUNCTION core.guard_identity_id();
CREATE TRIGGER monitoring_template_guard_id_update BEFORE UPDATE OF id ON core.monitoring_template
    FOR EACH ROW WHEN (NEW.id IS DISTINCT FROM OLD.id) EXECUTE FUNCTION core.guard_identity_id();
CREATE TRIGGER monitoring_template_after_delete AFTER DELETE ON core.monitoring_template
    FOR EACH ROW EXECUTE FUNCTION core.retire_identity_id();
CREATE TRIGGER trigger_guard_id_insert BEFORE INSERT ON core.trigger
    FOR EACH ROW EXECUTE FUNCTION core.guard_identity_id();
CREATE TRIGGER trigger_guard_id_update BEFORE UPDATE OF id ON core.trigger
    FOR EACH ROW WHEN (NEW.id IS DISTINCT FROM OLD.id) EXECUTE FUNCTION core.guard_identity_id();
CREATE TRIGGER trigger_after_delete AFTER DELETE ON core.trigger
    FOR EACH ROW EXECUTE FUNCTION core.retire_identity_id();

-- Per-device exceptions to a template trigger; NULL means "as in the trigger".
CREATE TABLE core.trigger_override (
    trigger_id bigint NOT NULL REFERENCES core.trigger (id) ON DELETE CASCADE,
    device_id  bigint NOT NULL REFERENCES core.device (id) ON DELETE CASCADE,
    enabled    bool   NULL,
    params     jsonb  NULL CHECK (jsonb_typeof(params) = 'object' AND octet_length(params::text) <= 4096),
    severity   text   NULL CHECK (severity IN ('info', 'warning', 'average', 'high', 'disaster')),
    PRIMARY KEY (trigger_id, device_id)
);
CREATE INDEX trigger_override_device_id_idx ON core.trigger_override (device_id);

-- Problems of the group's devices (including subgroups) are suppressed during the window.
CREATE TABLE core.maintenance_window (
    id        bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    group_id  bigint      NOT NULL REFERENCES core.device_group (id) ON DELETE CASCADE,
    starts_at timestamptz NOT NULL,
    ends_at   timestamptz NOT NULL,
    comment   text        NOT NULL DEFAULT '' CHECK (char_length(comment) <= 1000),
    CONSTRAINT maintenance_window_order CHECK (ends_at > starts_at),
    CONSTRAINT maintenance_window_span CHECK (ends_at - starts_at <= interval '7 days')
);
CREATE INDEX maintenance_window_group_id_idx ON core.maintenance_window (group_id);

REVOKE ALL ON core.monitoring_template, core.trigger, core.trigger_override, core.maintenance_window FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON core.monitoring_template, core.trigger, core.trigger_override,
    core.maintenance_window TO nms_api;
GRANT USAGE ON SEQUENCE core.monitoring_template_id_seq, core.trigger_id_seq, core.maintenance_window_id_seq TO nms_api;
GRANT SELECT ON core.monitoring_template TO nms_poller;

-- Default templates: availability and link-down triggers for the stock drivers.
WITH tpl AS (
    INSERT INTO core.monitoring_template (name, driver) VALUES
        ('Default: generic-snmp', 'generic-snmp'),
        ('Default: eltex-mes', 'eltex-mes'),
        ('Default: eltex-esr', 'eltex-esr')
    RETURNING id
)
INSERT INTO core.trigger (template_id, kind, params, duration_s, severity, name)
SELECT tpl.id, t.kind, t.params::jsonb, t.duration_s, t.severity, t.name
FROM tpl CROSS JOIN (VALUES
    ('availability', '{"states":["down"]}', 60, 'high', 'Device is unavailable'),
    ('availability', '{"states":["partial"]}', 120, 'average', 'Device is partially available'),
    ('if_oper_down', '{}', 0, 'average', 'Interface is down')
) AS t (kind, params, duration_s, severity, name);

-- Problems. Rows are history: they carry no foreign keys to triggers, devices
-- or users (their ids come from identity sequences and are never reused: guarded
-- for templates and triggers here, for devices by device_guard_id), so
-- deleting any of those cannot cascade into problems or acknowledgements; the
-- engine resolves the open problems of a deleted trigger or device.
CREATE SCHEMA problems AUTHORIZATION nms_migrator;
REVOKE ALL ON SCHEMA problems FROM PUBLIC;
GRANT USAGE ON SCHEMA problems TO nms_api;

-- A problem is either a trigger problem (trigger_id and device_id set) or a
-- system one (system_kind set). A system problem tied to a device has
-- device_id; one that is not (e.g. an unavailable poller) has device_id NULL
-- and an object such as 'poller:<id>'. Trigger problems use object '' or
-- 'if:<ifIndex>'. At most one non-resolved problem exists per key; NULLs
-- compare equal in the key, so the same index covers both kinds.
CREATE TABLE problems.problem (
    id              bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    trigger_id      bigint      NULL,
    system_kind     text        NULL CHECK (system_kind ~ '^[a-z_]{1,64}$'),
    device_id       bigint      NULL,
    object          text        NOT NULL DEFAULT '' CHECK (octet_length(object) <= 200),
    severity        text        NOT NULL CHECK (severity IN ('info', 'warning', 'average', 'high', 'disaster')),
    state           text        NOT NULL DEFAULT 'problem' CHECK (state IN ('problem', 'acknowledged', 'resolved')),
    suppressed      bool        NOT NULL DEFAULT false,
    opened_at       timestamptz NOT NULL DEFAULT now(),
    acknowledged_at timestamptz NULL,
    resolved_at     timestamptz NULL,
    resolve_reason  text        NULL CHECK (octet_length(resolve_reason) <= 200),
    last_value      text        NULL CHECK (octet_length(last_value) <= 1024),
    CONSTRAINT problem_source CHECK (num_nonnulls(trigger_id, system_kind) = 1),
    CONSTRAINT problem_trigger_device CHECK (trigger_id IS NULL OR device_id IS NOT NULL),
    CONSTRAINT problem_trigger_object CHECK (trigger_id IS NULL OR
        CASE WHEN object ~ '^if:[1-9][0-9]{0,9}$' THEN substr(object, 4)::bigint <= 2147483647 ELSE object = '' END),
    CONSTRAINT problem_resolved CHECK ((state = 'resolved') = (resolved_at IS NOT NULL)),
    CONSTRAINT problem_acknowledged CHECK (state <> 'acknowledged' OR acknowledged_at IS NOT NULL)
);
CREATE UNIQUE INDEX problem_open_key ON problems.problem (trigger_id, system_kind, device_id, object)
    NULLS NOT DISTINCT WHERE state <> 'resolved';
CREATE INDEX problem_device_state_idx ON problems.problem (device_id, state);
CREATE INDEX problem_state_opened_idx ON problems.problem (state, opened_at DESC);

-- Acknowledgement history: append-only for every application role and, through
-- the statement-level trigger below, for the owner too (as audit.event).
CREATE TABLE problems.ack (
    id         bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    problem_id bigint      NOT NULL REFERENCES problems.problem (id),
    user_id    bigint      NOT NULL,
    comment    text        NOT NULL CHECK (char_length(comment) BETWEEN 1 AND 1000),
    at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ack_problem_id_idx ON problems.ack (problem_id);

-- +goose StatementBegin
CREATE FUNCTION problems.reject_modification() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'problems: % on %.% is forbidden', TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege';
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION problems.reject_modification() FROM PUBLIC;

CREATE TRIGGER ack_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON problems.ack
    FOR EACH STATEMENT EXECUTE FUNCTION problems.reject_modification();

-- How far the engine has read each event stream.
CREATE TABLE problems.engine_state (
    name      text        PRIMARY KEY CHECK (name <> '' AND octet_length(name) <= 100),
    watermark timestamptz NOT NULL
);

REVOKE ALL ON ALL TABLES IN SCHEMA problems FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA problems FROM PUBLIC;
-- The engine resolves problems and never deletes them; `at` is always now().
GRANT SELECT, INSERT, UPDATE ON problems.problem TO nms_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON problems.engine_state TO nms_api;
GRANT SELECT ON problems.ack TO nms_api;
GRANT INSERT (problem_id, user_id, comment) ON problems.ack TO nms_api;
GRANT USAGE ON SEQUENCE problems.problem_id_seq, problems.ack_id_seq TO nms_api;

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
