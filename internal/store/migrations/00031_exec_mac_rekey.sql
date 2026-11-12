-- +goose Up
-- Phase 6 (task 6.3): rotation of the executor's sealing key.
--
-- The append-only session, recording and changeset rows carry an HMAC under
-- the sealing key's mac subkey. A rotation rewrites that MAC under the next
-- key and nothing else: the statement guard now fires for an UPDATE naming
-- any other column (every column but mac is listed: a column added later
-- must be added here), and as before for DELETE and TRUNCATE, for every
-- role. The executor checks each MAC under the current key before it
-- rewrites it over the same input, so no row is vouched for that did not
-- verify. exec.audit_event (hash chain, no key) is not touched.

DROP TRIGGER session_append_only ON exec.session;
CREATE TRIGGER session_append_only
    BEFORE UPDATE OF id, user_id, opened_at, policy_snapshot OR DELETE OR TRUNCATE ON exec.session
    FOR EACH STATEMENT EXECUTE FUNCTION exec.reject_modification();
DROP TRIGGER session_device_append_only ON exec.session_device;
CREATE TRIGGER session_device_append_only
    BEFORE UPDATE OF session_id, device_id, pre_sha256, pre_ct, pre_dek_ct OR DELETE OR TRUNCATE ON exec.session_device
    FOR EACH STATEMENT EXECUTE FUNCTION exec.reject_modification();
DROP TRIGGER session_event_append_only ON exec.session_event;
CREATE TRIGGER session_event_append_only
    BEFORE UPDATE OF id, session_id, at, kind, payload OR DELETE OR TRUNCATE ON exec.session_event
    FOR EACH STATEMENT EXECUTE FUNCTION exec.reject_modification();
DROP TRIGGER recording_chunk_append_only ON exec.recording_chunk;
CREATE TRIGGER recording_chunk_append_only
    BEFORE UPDATE OF session_id, device_id, n, ct, dek_ct OR DELETE OR TRUNCATE ON exec.recording_chunk
    FOR EACH STATEMENT EXECUTE FUNCTION exec.reject_modification();
DROP TRIGGER recording_manifest_append_only ON exec.recording_manifest;
CREATE TRIGGER recording_manifest_append_only
    BEFORE UPDATE OF session_id, device_id, chunks, sha256 OR DELETE OR TRUNCATE ON exec.recording_manifest
    FOR EACH STATEMENT EXECUTE FUNCTION exec.reject_modification();
DROP TRIGGER changeset_append_only ON exec.changeset;
CREATE TRIGGER changeset_append_only
    BEFORE UPDATE OF id, author, author_username, kind, created_at OR DELETE OR TRUNCATE ON exec.changeset
    FOR EACH STATEMENT EXECUTE FUNCTION exec.reject_modification();
DROP TRIGGER changeset_revision_append_only ON exec.changeset_revision;
CREATE TRIGGER changeset_revision_append_only
    BEFORE UPDATE OF changeset_id, rev, created_at, content, content_sha256 OR DELETE OR TRUNCATE ON exec.changeset_revision
    FOR EACH STATEMENT EXECUTE FUNCTION exec.reject_modification();
DROP TRIGGER changeset_event_append_only ON exec.changeset_event;
CREATE TRIGGER changeset_event_append_only
    BEFORE UPDATE OF id, changeset_id, rev, at, kind, device_id, session_id, payload OR DELETE OR TRUNCATE ON exec.changeset_event
    FOR EACH STATEMENT EXECUTE FUNCTION exec.reject_modification();

GRANT UPDATE (mac) ON exec.session, exec.session_device, exec.session_event, exec.recording_chunk,
    exec.recording_manifest, exec.changeset, exec.changeset_revision, exec.changeset_event TO nms_executor;

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
