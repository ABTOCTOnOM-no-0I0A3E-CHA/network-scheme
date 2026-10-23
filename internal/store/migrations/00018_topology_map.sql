-- +goose Up
-- Phase 2: topology links (built by the api from collected neighbour data, or
-- drawn by hand) and the map (views, areas, node positions, backgrounds).
-- Only the api touches these tables; poller, eventd and nmsctl have no rights.

-- Backgrounds are immutable blobs: replaced by a new row, never updated.
CREATE TABLE core.map_background (
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    mime        text        NOT NULL CHECK (mime IN ('image/png', 'image/jpeg', 'image/webp', 'image/svg+xml')),
    bytes       bytea       NOT NULL CHECK (octet_length(bytes) BETWEEN 1 AND 20 * 1024 * 1024),
    width       int         NOT NULL CHECK (width BETWEEN 1 AND 16384),
    height      int         NOT NULL CHECK (height BETWEEN 1 AND 16384),
    sha256      bytea       NOT NULL CHECK (octet_length(sha256) = 32),
    uploaded_by bigint      NOT NULL,
    uploaded_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE core.map_view (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name          text   NOT NULL CHECK (name <> '' AND char_length(name) <= 200),
    kind          text   NOT NULL CHECK (kind IN ('logical', 'plan')),
    background_id bigint NULL REFERENCES core.map_background (id) ON DELETE SET NULL
);
CREATE INDEX map_view_background_id_idx ON core.map_view (background_id);

-- Areas form a forest per view of depth <= 8 (organization > building > floor
-- > room with headroom). Geometry is bounded and finite: NaN sorts above every
-- number in PostgreSQL, so the range checks reject NaN and infinities too.
CREATE TABLE core.map_area (
    id        bigint           GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    view_id   bigint           NOT NULL REFERENCES core.map_view (id) ON DELETE CASCADE,
    parent_id bigint           NULL REFERENCES core.map_area (id) ON DELETE SET NULL,
    kind      text             NOT NULL CHECK (kind IN ('organization', 'building', 'floor', 'room')),
    name      text             NOT NULL CHECK (name <> '' AND char_length(name) <= 200),
    x         double precision NOT NULL CHECK (x BETWEEN -1e6 AND 1e6),
    y         double precision NOT NULL CHECK (y BETWEEN -1e6 AND 1e6),
    w         double precision NOT NULL CHECK (w > 0 AND w <= 1e6),
    h         double precision NOT NULL CHECK (h > 0 AND h <= 1e6),
    CONSTRAINT map_area_parent_not_self CHECK (parent_id IS NULL OR parent_id <> id)
);
CREATE INDEX map_area_view_id_idx ON core.map_area (view_id);
CREATE INDEX map_area_parent_id_idx ON core.map_area (parent_id);

-- Same scheme as core.device_check_parent (caller's rights, advisory lock,
-- READ COMMITTED), plus: the parent lives in the same view and an area never
-- changes view (children would end up in another view than their parent).
-- +goose StatementBegin
CREATE FUNCTION core.map_area_check_parent() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    up      int;
    down    int;
    is_loop bool;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('core.map_area.parent'));
    IF TG_OP = 'UPDATE' AND NEW.view_id <> OLD.view_id THEN
        RAISE EXCEPTION 'map area cannot change its view' USING ERRCODE = '23514';
    END IF;
    IF NEW.parent_id IS NULL THEN
        RETURN NEW;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM core.map_area WHERE id = NEW.parent_id AND view_id = NEW.view_id) THEN
        RAISE EXCEPTION 'map area parent must be in the same view' USING ERRCODE = '23514';
    END IF;
    WITH RECURSIVE anc(id, depth) AS (
        SELECT NEW.parent_id, 1
        UNION ALL
        SELECT a.parent_id, anc.depth + 1 FROM anc JOIN core.map_area a ON a.id = anc.id
        WHERE a.parent_id IS NOT NULL AND anc.depth < 9
    )
    SELECT coalesce(max(depth), 0), coalesce(bool_or(id = NEW.id), false) INTO up, is_loop FROM anc;
    IF is_loop THEN
        RAISE EXCEPTION 'map area parent would create a cycle' USING ERRCODE = '23514';
    END IF;
    WITH RECURSIVE kids(id, depth) AS (
        SELECT id, 1 FROM core.map_area WHERE parent_id = NEW.id
        UNION ALL
        SELECT a.id, kids.depth + 1 FROM kids JOIN core.map_area a ON a.parent_id = kids.id WHERE kids.depth < 9
    )
    SELECT coalesce(max(depth), 0) INTO down FROM kids;
    IF up + 1 + down > 8 THEN
        RAISE EXCEPTION 'map area chain is deeper than 8' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION core.map_area_check_parent() FROM PUBLIC;

CREATE TRIGGER map_area_check_parent BEFORE INSERT OR UPDATE OF parent_id, view_id ON core.map_area
    FOR EACH ROW EXECUTE FUNCTION core.map_area_check_parent();

CREATE TABLE core.map_node_position (
    view_id   bigint           NOT NULL REFERENCES core.map_view (id) ON DELETE CASCADE,
    device_id bigint           NOT NULL REFERENCES core.device (id) ON DELETE CASCADE,
    x         double precision NOT NULL CHECK (x BETWEEN -1e6 AND 1e6),
    y         double precision NOT NULL CHECK (y BETWEEN -1e6 AND 1e6),
    pinned    bool             NOT NULL DEFAULT false,
    PRIMARY KEY (view_id, device_id)
);
CREATE INDEX map_node_position_device_id_idx ON core.map_node_position (device_id);

-- A link between two devices, ends in canonical order (a < b) so one physical
-- link has one row. Several links between a pair are distinct by their ports;
-- a NULL port (unknown) takes part in the identity as -1. Manual links
-- (source 'manual') are never changed by the builder: the builder and the api
-- share one role, so that is enforced in code and tests, and by the CHECK that
-- `manual` and source 'manual' always agree.
CREATE TABLE core.link (
    id             bigint        GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    a_device_id    bigint        NOT NULL REFERENCES core.device (id) ON DELETE CASCADE,
    a_if_index     int           NULL CHECK (a_if_index > 0),
    b_device_id    bigint        NOT NULL REFERENCES core.device (id) ON DELETE CASCADE,
    b_if_index     int           NULL CHECK (b_if_index > 0),
    source         text          NOT NULL CHECK (source IN ('lldp', 'cdp', 'mac', 'manual')),
    confidence     numeric(3, 2) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    manual         bool          NOT NULL,
    first_seen     timestamptz   NOT NULL DEFAULT now(),
    last_confirmed timestamptz   NOT NULL DEFAULT now(),
    misses         int           NOT NULL DEFAULT 0 CHECK (misses >= 0),
    CONSTRAINT link_canonical_order CHECK (a_device_id < b_device_id),
    CONSTRAINT link_manual_source CHECK (manual = (source = 'manual'))
);
CREATE UNIQUE INDEX link_identity_idx ON core.link
    (a_device_id, coalesce(a_if_index, -1), b_device_id, coalesce(b_if_index, -1));
CREATE INDEX link_b_device_id_idx ON core.link (b_device_id);

-- Ids of links, views, areas and backgrounds come from their identity
-- sequences only and are never reused (guard from 00015); link_change keeps
-- link ids without a foreign key, so a reused id would rewrite history.
CREATE TRIGGER link_guard_id_insert BEFORE INSERT ON core.link
    FOR EACH ROW EXECUTE FUNCTION core.guard_identity_id();
CREATE TRIGGER link_guard_id_update BEFORE UPDATE OF id ON core.link
    FOR EACH ROW WHEN (NEW.id IS DISTINCT FROM OLD.id) EXECUTE FUNCTION core.guard_identity_id();
CREATE TRIGGER link_after_delete AFTER DELETE ON core.link
    FOR EACH ROW EXECUTE FUNCTION core.retire_identity_id();
CREATE TRIGGER map_view_guard_id_insert BEFORE INSERT ON core.map_view
    FOR EACH ROW EXECUTE FUNCTION core.guard_identity_id();
CREATE TRIGGER map_view_guard_id_update BEFORE UPDATE OF id ON core.map_view
    FOR EACH ROW WHEN (NEW.id IS DISTINCT FROM OLD.id) EXECUTE FUNCTION core.guard_identity_id();
CREATE TRIGGER map_view_after_delete AFTER DELETE ON core.map_view
    FOR EACH ROW EXECUTE FUNCTION core.retire_identity_id();
CREATE TRIGGER map_area_guard_id_insert BEFORE INSERT ON core.map_area
    FOR EACH ROW EXECUTE FUNCTION core.guard_identity_id();
CREATE TRIGGER map_area_guard_id_update BEFORE UPDATE OF id ON core.map_area
    FOR EACH ROW WHEN (NEW.id IS DISTINCT FROM OLD.id) EXECUTE FUNCTION core.guard_identity_id();
CREATE TRIGGER map_area_after_delete AFTER DELETE ON core.map_area
    FOR EACH ROW EXECUTE FUNCTION core.retire_identity_id();
CREATE TRIGGER map_background_guard_id_insert BEFORE INSERT ON core.map_background
    FOR EACH ROW EXECUTE FUNCTION core.guard_identity_id();
CREATE TRIGGER map_background_guard_id_update BEFORE UPDATE OF id ON core.map_background
    FOR EACH ROW WHEN (NEW.id IS DISTINCT FROM OLD.id) EXECUTE FUNCTION core.guard_identity_id();
CREATE TRIGGER map_background_after_delete AFTER DELETE ON core.map_background
    FOR EACH ROW EXECUTE FUNCTION core.retire_identity_id();

-- History of links appearing and disappearing: append-only for the api and,
-- through the statement-level trigger, for the owner too (as problems.ack).
-- No foreign keys: the link or its devices may be deleted later, the ends are
-- kept as plain ids and ports.
CREATE TABLE core.link_change (
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    link_id     bigint      NULL,
    a_device_id bigint      NOT NULL,
    a_if_index  int         NULL CHECK (a_if_index > 0),
    b_device_id bigint      NOT NULL,
    b_if_index  int         NULL CHECK (b_if_index > 0),
    change      text        NOT NULL CHECK (change IN ('appeared', 'disappeared')),
    source      text        NOT NULL CHECK (source IN ('lldp', 'cdp', 'mac', 'manual')),
    at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT link_change_canonical_order CHECK (a_device_id < b_device_id)
);
CREATE INDEX link_change_at_idx ON core.link_change (at DESC);
CREATE INDEX link_change_link_id_idx ON core.link_change (link_id);

-- +goose StatementBegin
CREATE FUNCTION core.reject_modification() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'core: % on %.% is forbidden', TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege';
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION core.reject_modification() FROM PUBLIC;

CREATE TRIGGER link_change_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON core.link_change
    FOR EACH STATEMENT EXECUTE FUNCTION core.reject_modification();

REVOKE ALL ON core.link, core.link_change, core.map_view, core.map_area, core.map_node_position,
    core.map_background FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON core.link, core.map_view, core.map_area, core.map_node_position TO nms_api;
GRANT SELECT, INSERT, DELETE ON core.map_background TO nms_api;
GRANT SELECT ON core.link_change TO nms_api;
GRANT INSERT (link_id, a_device_id, a_if_index, b_device_id, b_if_index, change, source) ON core.link_change TO nms_api;
GRANT USAGE ON SEQUENCE core.link_id_seq, core.link_change_id_seq, core.map_view_id_seq, core.map_area_id_seq,
    core.map_background_id_seq TO nms_api;

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
