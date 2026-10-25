-- +goose NO TRANSACTION
-- +goose Up
-- Indexes of the global search (GET /api/search), so that a query stays cheap
-- with millions of ARP/FDB rows. Interface names and aliases are matched by
-- substring (trigram GIN indexes; pg_trgm is a trusted contrib extension of the
-- database image and lives in core, where the migrator may create objects).
-- ARP addresses are matched by text prefix: a C-collation range scan in index
-- order serves ORDER BY ... LIMIT without sorting. MAC addresses are matched by
-- prefix as a macaddr range.
-- The indexes are built CONCURRENTLY (outside a transaction, statement by
-- statement) so that the poller keeps writing the tables during an upgrade;
-- IF NOT EXISTS lets an interrupted run be applied again (an index left
-- INVALID by a failed build must be dropped by hand first).
CREATE EXTENSION IF NOT EXISTS pg_trgm SCHEMA core;

CREATE INDEX CONCURRENTLY IF NOT EXISTS interface_name_trgm_idx ON inventory.interface USING gin (name core.gin_trgm_ops);
CREATE INDEX CONCURRENTLY IF NOT EXISTS interface_alias_trgm_idx ON inventory.interface USING gin (alias core.gin_trgm_ops);
CREATE INDEX CONCURRENTLY IF NOT EXISTS arp_entry_host_idx ON inventory.arp_entry ((host(ip)) COLLATE "C");
CREATE INDEX CONCURRENTLY IF NOT EXISTS arp_entry_mac_idx ON inventory.arp_entry (mac);
CREATE INDEX CONCURRENTLY IF NOT EXISTS mac_entry_mac_idx ON inventory.mac_entry (mac);

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
