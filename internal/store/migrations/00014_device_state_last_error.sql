-- +goose Up
-- The api shows why a device is not "up". last_error is fixed text written by
-- the poller (see internal/poller reasonText); like state it is hidden while
-- the device's poller is silent. The new column goes last so the view can be
-- replaced in place; grants carry over.
CREATE OR REPLACE VIEW inventory.device_state_v AS
SELECT d.id AS device_id,
       CASE WHEN s.device_id IS NOT NULL AND h.at >= now() - INTERVAL '90 seconds'
            THEN s.state ELSE 'unknown' END AS state,
       CASE WHEN s.device_id IS NULL THEN NULL
            WHEN h.at >= now() - INTERVAL '90 seconds' THEN s.since
            ELSE h.at + INTERVAL '90 seconds' END AS since,
       CASE WHEN s.device_id IS NOT NULL AND h.at >= now() - INTERVAL '90 seconds'
            THEN s.last_error ELSE '' END AS last_error
FROM core.device d
LEFT JOIN inventory.device_status s ON s.device_id = d.id AND s.poller_id = d.poller_id
LEFT JOIN inventory.poller_heartbeat h ON h.poller_id = d.poller_id;

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
