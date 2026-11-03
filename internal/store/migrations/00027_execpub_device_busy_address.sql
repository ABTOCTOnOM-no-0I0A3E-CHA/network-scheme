-- +goose Up
-- The poller dials core.device.address, which the api controls: core.device
-- is unique only on (address, snmp_port), so a second row with the address of
-- a device in a change session (another snmp_port) would get a CLI session
-- the device_id check cannot see. device_busy therefore also carries the
-- address the executor itself connects to (exec.write_device.address, under
-- its MAC), and the poller refuses a dial when either the id or the address
-- it is about to dial is busy (internal/poller dialSSH).
--
-- Expand: a nullable column (rows of older executors have none, the id check
-- still applies to them); host addresses only, as write_device.address. The
-- table-level grants of 00024 cover it: the executor writes it, the api and
-- the poller read it.
ALTER TABLE execpub.device_busy ADD COLUMN address inet NULL
    CHECK (masklen(address) = CASE family(address) WHEN 4 THEN 32 ELSE 128 END);
CREATE INDEX device_busy_address_idx ON execpub.device_busy (address);

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
