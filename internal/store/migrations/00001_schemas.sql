-- +goose Up
-- The schemas are normally pre-created by deploy/postgres/initdb/10-roles.sh
-- (the goose version table lives in core); IF NOT EXISTS keeps this self-contained.
CREATE SCHEMA IF NOT EXISTS core;
CREATE SCHEMA IF NOT EXISTS audit;

REVOKE ALL ON SCHEMA core, audit FROM PUBLIC;
GRANT USAGE ON SCHEMA core, audit TO nms_api, nms_cli;

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
