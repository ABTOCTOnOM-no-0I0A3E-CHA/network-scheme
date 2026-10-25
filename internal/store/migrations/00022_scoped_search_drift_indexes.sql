-- +goose Up
-- A global search by a group-bound user reads the inventory tables by device
-- (device_id = ANY(visible ids)): per-device MAC ranges and address prefixes.
-- The ARP and FDB keys lead with device_id but not with the searched column.
CREATE INDEX arp_entry_device_mac_idx ON inventory.arp_entry (device_id, mac);
CREATE INDEX arp_entry_device_host_idx ON inventory.arp_entry (device_id, (host(ip)) COLLATE "C");
CREATE INDEX mac_entry_device_mac_idx ON inventory.mac_entry (device_id, mac);

-- The config-drift widget walks the drift versions newest first.
CREATE INDEX config_version_drift_idx ON backups.config_version (taken_at DESC, id DESC) WHERE drift;

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
