-- +goose Up
-- LLDP local ports are resolved to an ifIndex through lldpLocPortTable;
-- local_port_resolved says whether local_if_index was confirmed by name (false:
-- the LLDP port number is stored unchecked). remote_port_descr is the
-- neighbour's own port description, untrusted text. Grants carry over.
ALTER TABLE inventory.lldp_neighbor
    ADD COLUMN remote_port_descr   text NULL CHECK (char_length(remote_port_descr) <= 1024),
    ADD COLUMN local_port_resolved bool NOT NULL DEFAULT false;

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
