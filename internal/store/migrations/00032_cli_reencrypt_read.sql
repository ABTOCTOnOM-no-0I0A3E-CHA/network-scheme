-- +goose Up
-- Phase 6 (task 6.3): rotation of the read-domain key (nmsctl keys rotate read).
-- The tools container re-seals every read credential from the retired key to
-- the next one (the plaintext never leaves it) and records the new key
-- version; a credential that does not open under the retired key is marked
-- invalid (the operator enters it again). Nothing else of the profile.
GRANT SELECT (owner_kind, owner_id, kind, ciphertext, key_version),
    UPDATE (ciphertext, key_version, status) ON core.access_profile TO nms_cli;

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
