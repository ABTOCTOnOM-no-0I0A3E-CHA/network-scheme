-- +goose Up
-- A device in a change session may be reachable at addresses other than the
-- one the executor dials (another VLAN interface, a NAT address), and the api
-- may give a second core.device row any of them. device_busy therefore also
-- carries the SHA-256 fingerprint of the device's SSH host key as the
-- executor pinned it (exec.write_device.hostkey_fp, under its MAC; same format
-- as there). The poller's host key callback refuses, before any credential is
-- sent, a presented key whose fingerprint is busy (internal/ssh).
--
-- Expand: a nullable column (a device whose host key the executor has not
-- accepted yet has none; the id and address checks still apply). The
-- table-level grants of 00024 cover it: the executor writes it, the api and
-- the poller read it.
ALTER TABLE execpub.device_busy ADD COLUMN hostkey_fp text NULL
    CHECK (hostkey_fp ~ '^SHA256:[A-Za-z0-9+/]{43}$');
CREATE INDEX device_busy_hostkey_fp_idx ON execpub.device_busy (hostkey_fp);

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
