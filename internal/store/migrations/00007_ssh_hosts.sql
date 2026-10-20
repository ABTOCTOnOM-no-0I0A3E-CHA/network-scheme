-- +goose Up
-- SSH host keys pinned per device on first use, and rejected keys.
-- Only the poller reads and pins keys; resetting a pin is a host-only action (nms_cli).
CREATE SCHEMA IF NOT EXISTS ssh_hosts;
REVOKE ALL ON SCHEMA ssh_hosts FROM PUBLIC;

-- Keyed by device only: an address change never resets the pin.
CREATE TABLE ssh_hosts.host_key (
    device_id          bigint      PRIMARY KEY REFERENCES core.device (id) ON DELETE CASCADE,
    algorithm          text        NOT NULL CHECK (algorithm <> ''),
    fingerprint_sha256 text        NOT NULL CHECK (fingerprint_sha256 LIKE 'SHA256:%'),
    first_seen         timestamptz NOT NULL DEFAULT now(),
    last_seen          timestamptz NOT NULL DEFAULT now()
);

-- Append-only record of keys that did not match the pin (kept after device deletion).
CREATE TABLE ssh_hosts.mismatch (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id        bigint      NOT NULL,
    seen_fingerprint text        NOT NULL,
    address          inet        NOT NULL,
    at               timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX mismatch_device_id_idx ON ssh_hosts.mismatch (device_id);

REVOKE ALL ON ssh_hosts.host_key, ssh_hosts.mismatch FROM PUBLIC;

GRANT USAGE ON SCHEMA ssh_hosts TO nms_poller, nms_cli;
GRANT SELECT, INSERT, UPDATE (last_seen) ON ssh_hosts.host_key TO nms_poller;
GRANT INSERT ON ssh_hosts.mismatch TO nms_poller;
-- DELETE ... WHERE device_id needs SELECT; fingerprints are not secret.
GRANT SELECT, DELETE ON ssh_hosts.host_key TO nms_cli;
GRANT SELECT ON ssh_hosts.mismatch TO nms_cli;

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
