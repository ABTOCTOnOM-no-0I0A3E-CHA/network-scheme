-- +goose Up
-- Ruling R1 (Phase 4b.1/4b.8): the poller keeps backing up a device whose
-- configuration read needs a write account until the executor has taken it
-- over. backup_taken is how the poller learns that: the executor's backup
-- scheduler stamps a row on every successful backup of a write_device with
-- backup_via_executor (and deletes the rows of devices it no longer backs up).
-- Only the executor writes it; the poller stops only while the stamp is
-- fresh, so a stopped executor hands the device back to the poller.
-- The api and the poller cannot write it (nor any other execpub table but
-- freeze_request); the executor never reads it back.
CREATE TABLE execpub.backup_taken (
    device_id bigint      PRIMARY KEY CHECK (device_id > 0),
    at        timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON execpub.backup_taken TO nms_executor;
GRANT SELECT ON execpub.backup_taken TO nms_api, nms_poller;

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
