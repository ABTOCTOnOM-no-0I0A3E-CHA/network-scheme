-- +goose Up
-- Phase 6 (task 6.3): rotation of the backup-domain key (nmsctl keys rotate backup).
--
-- Every backup envelope is a random DEK sealed to the backup-domain key plus
-- the body encrypted under that DEK. A rotation re-seals only the DEK (the
-- body, and so full_ct, pre_ct and ct, stay byte for byte), so the old
-- private key can be destroyed without losing history. The rows are
-- append-only; this lets the executor, and only it, rewrite exactly the
-- sealed DEK columns and what covers them: the MAC of the exec rows (already
-- rewritable since 00031) and the manifest hash of a recording, which is
-- computed over every chunk's sha256(dek_ct). The statement guards now fire
-- for an UPDATE naming any other column (all are listed: a column added
-- later must be added here), and as before for DELETE and TRUNCATE, for
-- every role. The executor checks each MAC under the sealing key before it
-- rewrites a row and every update matches the old value. exec.audit_event
-- and the audit schema are not touched.

DROP TRIGGER config_version_append_only ON backups.config_version;
CREATE TRIGGER config_version_append_only
    BEFORE UPDATE OF id, device_id, taken_at, source, sha256, size, masked, full_ct, drift, taken_by_job
        OR DELETE OR TRUNCATE ON backups.config_version
    FOR EACH STATEMENT EXECUTE FUNCTION core.reject_modification();
DROP TRIGGER session_device_append_only ON exec.session_device;
CREATE TRIGGER session_device_append_only
    BEFORE UPDATE OF session_id, device_id, pre_sha256, pre_ct OR DELETE OR TRUNCATE ON exec.session_device
    FOR EACH STATEMENT EXECUTE FUNCTION exec.reject_modification();
DROP TRIGGER recording_chunk_append_only ON exec.recording_chunk;
CREATE TRIGGER recording_chunk_append_only
    BEFORE UPDATE OF session_id, device_id, n, ct OR DELETE OR TRUNCATE ON exec.recording_chunk
    FOR EACH STATEMENT EXECUTE FUNCTION exec.reject_modification();
DROP TRIGGER recording_manifest_append_only ON exec.recording_manifest;
CREATE TRIGGER recording_manifest_append_only
    BEFORE UPDATE OF session_id, device_id, chunks OR DELETE OR TRUNCATE ON exec.recording_manifest
    FOR EACH STATEMENT EXECUTE FUNCTION exec.reject_modification();

GRANT UPDATE (full_dek_ct) ON backups.config_version TO nms_executor;
GRANT UPDATE (pre_dek_ct) ON exec.session_device TO nms_executor;
GRANT UPDATE (dek_ct) ON exec.recording_chunk TO nms_executor;
GRANT UPDATE (sha256) ON exec.recording_manifest TO nms_executor;

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
