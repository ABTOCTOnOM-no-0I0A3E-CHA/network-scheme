-- +goose NO TRANSACTION
-- +goose Up
-- A global search by a group-bound user reads the inventory tables by device
-- (device_id = ANY(visible ids)): per-device MAC ranges and address prefixes.
-- The ARP and FDB keys lead with device_id but not with the searched column.
-- Built CONCURRENTLY, as in 00021, so that writers are not blocked.
CREATE INDEX CONCURRENTLY IF NOT EXISTS arp_entry_device_mac_idx ON inventory.arp_entry (device_id, mac);
CREATE INDEX CONCURRENTLY IF NOT EXISTS arp_entry_device_host_idx ON inventory.arp_entry (device_id, (host(ip)) COLLATE "C");
CREATE INDEX CONCURRENTLY IF NOT EXISTS mac_entry_device_mac_idx ON inventory.mac_entry (device_id, mac);

-- The config-drift widget walks the drift versions newest first.
CREATE INDEX CONCURRENTLY IF NOT EXISTS config_version_drift_idx ON backups.config_version (taken_at DESC, id DESC) WHERE drift;

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
