-- +goose Up
-- Device group hierarchy and role bindings (RBAC).
CREATE TABLE core.device_group (
    id        bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    parent_id bigint NULL REFERENCES core.device_group (id),
    name      text   NOT NULL CHECK (name <> '' AND char_length(name) <= 200),
    CONSTRAINT device_group_parent_name_key UNIQUE NULLS NOT DISTINCT (parent_id, name),
    CHECK (parent_id IS NULL OR parent_id <> id)
);
CREATE INDEX device_group_parent_id_idx ON core.device_group (parent_id);

-- group_id NULL means a global binding.
CREATE TABLE core.role_binding (
    user_id  bigint NOT NULL REFERENCES core."user" (id) ON DELETE CASCADE,
    role     text   NOT NULL CHECK (role IN ('viewer', 'operator', 'admin', 'auditor')),
    group_id bigint NULL REFERENCES core.device_group (id) ON DELETE CASCADE,
    CONSTRAINT role_binding_key UNIQUE NULLS NOT DISTINCT (user_id, role, group_id)
);
CREATE INDEX role_binding_group_id_idx ON core.role_binding (group_id);

REVOKE ALL ON core.device_group, core.role_binding FROM PUBLIC;

GRANT SELECT, INSERT, UPDATE, DELETE ON core.device_group TO nms_api;
GRANT SELECT, INSERT, DELETE         ON core.role_binding TO nms_api;

-- nmsctl creates the break-glass admin binding.
GRANT SELECT                 ON core.device_group TO nms_cli;
GRANT SELECT, INSERT, DELETE ON core.role_binding TO nms_cli;

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
