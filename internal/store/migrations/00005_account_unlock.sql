-- +goose Up
-- Account lockout decay and the host-side way out of a lock.
-- last_failure_at: a failure long after the previous one (and after the lock
-- ended) starts the consecutive-failure counter again.
ALTER TABLE core.account_lock ADD COLUMN last_failure_at timestamptz NULL;

-- nmsctl user unlock / user reset clear the counter and the lock.
GRANT DELETE, SELECT (user_id) ON core.account_lock TO nms_cli;

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
