-- +goose Up
-- The role of a device (map icon, device card): role is set by hand through the API (NULL = automatic), role_auto
-- is what the poller derives from the driver and sysServices. The effective role is coalesce(role, role_auto).
ALTER TABLE core.device
    ADD COLUMN role text NULL CHECK (role IN ('switch', 'router', 'l3switch', 'firewall', 'server', 'ap', 'pc',
        'printer', 'phone', 'cloud', 'other')),
    ADD COLUMN role_auto text NULL CHECK (role_auto IN ('switch', 'router', 'l3switch', 'firewall', 'server', 'ap', 'pc',
        'printer', 'phone', 'cloud', 'other'));

-- nms_api already holds UPDATE on the whole table (00006); the poller writes only the derived role.
GRANT UPDATE (role_auto) ON core.device TO nms_poller;

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
