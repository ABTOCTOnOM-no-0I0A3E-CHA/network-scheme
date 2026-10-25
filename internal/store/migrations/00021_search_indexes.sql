-- +goose Up
-- Indexes of the global search (GET /api/search), so that a query stays cheap
-- with millions of ARP/FDB rows. Interface names and aliases are matched by
-- substring (trigram GIN indexes; pg_trgm is a trusted contrib extension of the
-- database image and lives in core, where the migrator may create objects).
-- ARP addresses are matched by text prefix: a C-collation range scan in index
-- order serves ORDER BY ... LIMIT without sorting. MAC addresses are matched by
-- prefix as a macaddr range.
CREATE EXTENSION IF NOT EXISTS pg_trgm SCHEMA core;

CREATE INDEX interface_name_trgm_idx ON inventory.interface USING gin (name core.gin_trgm_ops);
CREATE INDEX interface_alias_trgm_idx ON inventory.interface USING gin (alias core.gin_trgm_ops);
CREATE INDEX arp_entry_host_idx ON inventory.arp_entry ((host(ip)) COLLATE "C");
CREATE INDEX arp_entry_mac_idx ON inventory.arp_entry (mac);
CREATE INDEX mac_entry_mac_idx ON inventory.mac_entry (mac);

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
