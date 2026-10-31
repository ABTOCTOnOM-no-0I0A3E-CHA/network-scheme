-- +goose Up
-- nmsctl executor enroll/grant show the panel user's id, name and creation
-- date for the host to confirm (D10: the api may rename users, so the name
-- alone does not identify whom a grant binds). Display and refusal only.
GRANT SELECT (created_at) ON core."user" TO nms_executor;

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
