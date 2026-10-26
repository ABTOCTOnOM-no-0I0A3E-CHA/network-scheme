-- +goose Up
-- Phase 4: the executor's own schema `exec` and the one-way channel `execpub`.
--
-- exec is reachable by nms_executor only: no other application role gets any
-- right on it, not even USAGE. Registry rows carry a MAC (key known to the
-- executor only) over (table, key, content, version); the executor detects any
-- change made around it, so the table checks here only bound sizes and values.
-- Sessions, recordings and the executor's audit are append-only for every
-- role, the owner included (statement-level trigger); the single exception is
-- the one-row chain head exec.audit_head.
--
-- execpub is written by the executor and read by the panel: the api reads it
-- (except freeze_request) and may only insert `requested_by` into
-- freeze_request ("freeze on"; there is no way to ask for "off"); the poller
-- reads device_busy and session_summary.
--
-- No foreign keys into core: the api owns core, and a cascade or a restriction
-- would let it delete or pin executor rows. The executor never treats a
-- core.user id as a stable identity: what binds a user are the AAD of the
-- change TOTP secret and the username snapshot (deny-only, security.md 5.1a).

CREATE SCHEMA exec AUTHORIZATION nms_migrator;
CREATE SCHEMA execpub AUTHORIZATION nms_migrator;
REVOKE ALL ON SCHEMA exec, execpub FROM PUBLIC;

-- Registry: written only by the executor (one writer, under row MACs).

CREATE TABLE exec.registry_counter (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    seq       bigint  NOT NULL CHECK (seq >= 0),
    mac       bytea   NOT NULL CHECK (octet_length(mac) = 32)
);

CREATE TABLE exec.write_device (
    device_id           bigint  PRIMARY KEY CHECK (device_id > 0),
    address             inet    NOT NULL
        CHECK (masklen(address) = CASE family(address) WHEN 4 THEN 32 ELSE 128 END),
    port                int     NOT NULL DEFAULT 22 CHECK (port BETWEEN 1 AND 65535),
    protocol            text    NOT NULL DEFAULT 'ssh' CHECK (protocol = 'ssh'),
    write_group         text    NOT NULL CHECK (write_group ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'),
    write_driver        text    NOT NULL CHECK (write_driver IN ('mes6', 'mes10', 'esr')),
    hostkey_algo        text    NULL CHECK (hostkey_algo IN ('ssh-rsa', 'ecdsa-sha2-nistp256',
        'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'ssh-ed25519')),
    hostkey_fp          text    NULL CHECK (hostkey_fp ~ '^SHA256:[A-Za-z0-9+/]{43}$'),
    allow_ssh_rsa_sha1  boolean NOT NULL DEFAULT false,
    writes_enabled      boolean NOT NULL DEFAULT false,
    backup_via_executor boolean NOT NULL DEFAULT false,
    version             bigint  NOT NULL CHECK (version > 0),
    mac                 bytea   NOT NULL CHECK (octet_length(mac) = 32),
    -- A host key is accepted as a pair; writes need an accepted key (no TOFU).
    CONSTRAINT write_device_hostkey_pair CHECK ((hostkey_algo IS NULL) = (hostkey_fp IS NULL)),
    CONSTRAINT write_device_writes_need_hostkey CHECK (NOT writes_enabled OR hostkey_fp IS NOT NULL)
);

-- One row per (user, kind, group); only `write` names a group. A primary key
-- cannot hold the NULL group, so uniqueness treats NULLs as equal.
CREATE TABLE exec.write_grant (
    user_id           bigint NOT NULL CHECK (user_id > 0),
    kind              text   NOT NULL CHECK (kind IN ('write', 'write-admin', 'unmask', 'audit-read')),
    write_group       text   NULL CHECK (write_group ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'),
    username_snapshot text   NOT NULL CHECK (char_length(username_snapshot) BETWEEN 1 AND 64),
    version           bigint NOT NULL CHECK (version > 0),
    mac               bytea  NOT NULL CHECK (octet_length(mac) = 32),
    CONSTRAINT write_grant_group_iff_write CHECK ((kind = 'write') = (write_group IS NOT NULL)),
    CONSTRAINT write_grant_key UNIQUE NULLS NOT DISTINCT (user_id, kind, write_group)
);

CREATE TABLE exec.change_totp (
    user_id           bigint      PRIMARY KEY CHECK (user_id > 0),
    username_snapshot text        NOT NULL CHECK (char_length(username_snapshot) BETWEEN 1 AND 64),
    ciphertext        bytea       NOT NULL CHECK (octet_length(ciphertext) BETWEEN 1 AND 1024),
    key_version       int         NOT NULL CHECK (key_version > 0),
    last_step         bigint      NOT NULL DEFAULT 0 CHECK (last_step >= 0),
    failures          int         NOT NULL DEFAULT 0 CHECK (failures BETWEEN 0 AND 1000000),
    lock_until        timestamptz NULL,
    lock_count        int         NOT NULL DEFAULT 0 CHECK (lock_count BETWEEN 0 AND 1000000),
    version           bigint      NOT NULL CHECK (version > 0),
    mac               bytea       NOT NULL CHECK (octet_length(mac) = 32)
);

-- A missing row means "frozen" to the executor (fail closed). FREEZE is a
-- reserved word: the column is always quoted.
CREATE TABLE exec.exec_state (
    singleton          boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    "freeze"           boolean NOT NULL,
    freeze_reason      text    NULL CHECK (octet_length(freeze_reason) <= 1024),
    global_fail_window jsonb   NOT NULL DEFAULT '[]'
        CHECK (jsonb_typeof(global_fail_window) IN ('array', 'object') AND octet_length(global_fail_window::text) <= 65536),
    version            bigint  NOT NULL CHECK (version > 0),
    mac                bytea   NOT NULL CHECK (octet_length(mac) = 32)
);

-- The executor may reserve the id (nextval) before inserting, since the MAC covers it.
CREATE TABLE exec.model_profile (
    id           bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY CHECK (id > 0),
    write_driver text   NOT NULL CHECK (write_driver IN ('mes6', 'mes10', 'esr')),
    model_re     text   NOT NULL CHECK (octet_length(model_re) BETWEEN 1 AND 256),
    firmware_re  text   NOT NULL CHECK (octet_length(firmware_re) BETWEEN 1 AND 256),
    strategies   jsonb  NOT NULL DEFAULT '{}'
        CHECK (jsonb_typeof(strategies) = 'object' AND octet_length(strategies::text) <= 16384),
    note         text   NOT NULL CHECK (char_length(note) BETWEEN 1 AND 1000),
    version      bigint NOT NULL CHECK (version > 0),
    mac          bytea  NOT NULL CHECK (octet_length(mac) = 32)
);

-- Sealed box on the write-domain key; nonce is the inner payload's (16 bytes).
CREATE TABLE exec.write_credential (
    device_id  bigint      PRIMARY KEY CHECK (device_id > 0),
    kind       text        NOT NULL CHECK (kind = 'ssh_write'),
    ciphertext bytea       NOT NULL CHECK (octet_length(ciphertext) BETWEEN 1 AND 8240),
    created_at timestamptz NOT NULL,
    nonce      bytea       NOT NULL CHECK (octet_length(nonce) = 16),
    version    bigint      NOT NULL CHECK (version > 0),
    mac        bytea       NOT NULL CHECK (octet_length(mac) = 32)
);

-- Append-only: sessions, their pre-session snapshots, events, recordings and
-- the executor's hash-chained audit. Ids that a MAC covers are chosen by the
-- executor before the insert (the rows can never be updated afterwards).

CREATE TABLE exec.session (
    id              uuid        PRIMARY KEY,
    user_id         bigint      NOT NULL CHECK (user_id > 0),
    opened_at       timestamptz NOT NULL,
    policy_snapshot jsonb       NOT NULL
        CHECK (jsonb_typeof(policy_snapshot) = 'object' AND octet_length(policy_snapshot::text) <= 65536),
    mac             bytea       NOT NULL CHECK (octet_length(mac) = 32)
);
CREATE INDEX session_user_id_idx ON exec.session (user_id);

-- Envelope as in backups.config_version: DEK sealed on the backup-domain key.
CREATE TABLE exec.session_device (
    session_id uuid   NOT NULL REFERENCES exec.session (id),
    device_id  bigint NOT NULL CHECK (device_id > 0),
    pre_sha256 bytea  NOT NULL CHECK (octet_length(pre_sha256) = 32),
    pre_ct     bytea  NOT NULL CHECK (octet_length(pre_ct) BETWEEN 1 AND 4 * 1024 * 1024 + 1024),
    pre_dek_ct bytea  NOT NULL CHECK (octet_length(pre_dek_ct) BETWEEN 1 AND 1024),
    mac        bytea  NOT NULL CHECK (octet_length(mac) = 32),
    PRIMARY KEY (session_id, device_id)
);
CREATE INDEX session_device_device_id_idx ON exec.session_device (device_id);

CREATE TABLE exec.session_event (
    id         bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY CHECK (id > 0),
    session_id uuid        NOT NULL REFERENCES exec.session (id),
    at         timestamptz NOT NULL,
    kind       text        NOT NULL CHECK (kind ~ '^[a-z0-9_.-]{1,64}$'),
    payload    jsonb       NOT NULL
        CHECK (jsonb_typeof(payload) = 'object' AND octet_length(payload::text) <= 65536),
    mac        bytea       NOT NULL CHECK (octet_length(mac) = 32)
);
CREATE INDEX session_event_session_id_idx ON exec.session_event (session_id, id);

-- Chunks of at most 1 MiB of recording, each its own envelope.
CREATE TABLE exec.recording_chunk (
    session_id uuid   NOT NULL,
    device_id  bigint NOT NULL,
    n          int    NOT NULL CHECK (n BETWEEN 0 AND 1000000),
    ct         bytea  NOT NULL CHECK (octet_length(ct) BETWEEN 1 AND 1024 * 1024 + 1024),
    dek_ct     bytea  NOT NULL CHECK (octet_length(dek_ct) BETWEEN 1 AND 1024),
    mac        bytea  NOT NULL CHECK (octet_length(mac) = 32),
    PRIMARY KEY (session_id, device_id, n),
    FOREIGN KEY (session_id, device_id) REFERENCES exec.session_device (session_id, device_id)
);

CREATE TABLE exec.recording_manifest (
    session_id uuid   NOT NULL,
    device_id  bigint NOT NULL,
    chunks     int    NOT NULL CHECK (chunks BETWEEN 0 AND 1000001),
    sha256     bytea  NOT NULL CHECK (octet_length(sha256) = 32),
    mac        bytea  NOT NULL CHECK (octet_length(mac) = 32),
    PRIMARY KEY (session_id, device_id),
    FOREIGN KEY (session_id, device_id) REFERENCES exec.session_device (session_id, device_id)
);

-- As audit.event: hash = SHA-256(prev_hash || payload), payload holds the exact hashed bytes.
CREATE TABLE exec.audit_event (
    id        bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts        timestamptz NOT NULL,
    user_id   bigint      NULL CHECK (user_id > 0),
    ip        inet        NULL,
    ua        text        NULL CHECK (octet_length(ua) <= 512),
    action    text        NOT NULL CHECK (action ~ '^[a-z0-9_.-]{1,64}$'),
    object    text        NULL CHECK (octet_length(object) <= 256),
    result    text        NOT NULL CHECK (result IN ('ok', 'denied', 'error')),
    payload   bytea       NOT NULL CHECK (octet_length(payload) <= 65536),
    prev_hash bytea       NOT NULL CHECK (octet_length(prev_hash) = 32),
    hash      bytea       NOT NULL CHECK (octet_length(hash) = 32)
);
CREATE INDEX audit_event_ts_idx ON exec.audit_event (ts);

-- Single row: the tail of the executor's chain (also anchored in its state file).
CREATE TABLE exec.audit_head (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    last_id   bigint  NOT NULL CHECK (last_id >= 0),
    hash      bytea   NOT NULL CHECK (octet_length(hash) = 32)
);
INSERT INTO exec.audit_head (singleton, last_id, hash) VALUES (true, 0, decode(repeat('00', 32), 'hex'));

-- Statement-level guard: also fires for UPDATE/DELETE matching no rows and
-- for TRUNCATE, and for the owner and superusers, whom privileges do not stop.
-- +goose StatementBegin
CREATE FUNCTION exec.reject_modification() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'exec: % on %.% is forbidden', TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege';
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION exec.reject_modification() FROM PUBLIC;

CREATE TRIGGER session_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON exec.session
    FOR EACH STATEMENT EXECUTE FUNCTION exec.reject_modification();
CREATE TRIGGER session_device_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON exec.session_device
    FOR EACH STATEMENT EXECUTE FUNCTION exec.reject_modification();
CREATE TRIGGER session_event_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON exec.session_event
    FOR EACH STATEMENT EXECUTE FUNCTION exec.reject_modification();
CREATE TRIGGER recording_chunk_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON exec.recording_chunk
    FOR EACH STATEMENT EXECUTE FUNCTION exec.reject_modification();
CREATE TRIGGER recording_manifest_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON exec.recording_manifest
    FOR EACH STATEMENT EXECUTE FUNCTION exec.reject_modification();
CREATE TRIGGER audit_event_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON exec.audit_event
    FOR EACH STATEMENT EXECUTE FUNCTION exec.reject_modification();
CREATE TRIGGER audit_head_keep_row BEFORE DELETE OR TRUNCATE ON exec.audit_head
    FOR EACH STATEMENT EXECUTE FUNCTION exec.reject_modification();

-- audit_event ids come from the identity only, even with OVERRIDING SYSTEM VALUE.
CREATE TRIGGER audit_event_guard_id_insert BEFORE INSERT ON exec.audit_event
    FOR EACH ROW EXECUTE FUNCTION core.guard_identity_id();

-- execpub: executor -> panel, and the panel's single "freeze on" request.

-- At most one pending request: the api inserts with ON CONFLICT DO NOTHING (an
-- existing row already means "freeze pending"), the executor deletes it once
-- frozen. Flooding cannot grow the table.
CREATE TABLE execpub.freeze_request (
    singleton    boolean     PRIMARY KEY DEFAULT true CHECK (singleton),
    requested_by bigint      NOT NULL CHECK (requested_by > 0),
    at           timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE execpub.alert (
    id        bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at        timestamptz NOT NULL DEFAULT now(),
    kind      text        NOT NULL CHECK (kind ~ '^[a-z0-9_]{1,64}$'),
    severity  text        NOT NULL CHECK (severity IN ('info', 'warning', 'average', 'high', 'disaster')),
    device_id bigint      NULL CHECK (device_id > 0),
    text      text        NOT NULL CHECK (octet_length(text) <= 1024)
);
CREATE INDEX alert_at_idx ON execpub.alert (at);

CREATE TABLE execpub.device_busy (
    device_id  bigint      PRIMARY KEY CHECK (device_id > 0),
    session_id uuid        NOT NULL,
    since      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE execpub.session_summary (
    session_id  uuid        NOT NULL,
    user_id     bigint      NOT NULL CHECK (user_id > 0),
    device_id   bigint      NOT NULL CHECK (device_id > 0),
    opened_at   timestamptz NOT NULL,
    closed_at   timestamptz NULL,
    status      text        NOT NULL
        CHECK (status IN ('open', 'closed', 'timeout', 'interrupted', 'rolled_back')),
    post_sha256 bytea       NULL CHECK (octet_length(post_sha256) = 32),
    PRIMARY KEY (session_id, device_id),
    CONSTRAINT session_summary_closed_after_open CHECK (closed_at >= opened_at),
    CONSTRAINT session_summary_open_not_closed CHECK (status <> 'open' OR closed_at IS NULL)
);
CREATE INDEX session_summary_device_idx ON execpub.session_summary (device_id, opened_at DESC);

CREATE TABLE execpub.status (
    singleton boolean     PRIMARY KEY DEFAULT true CHECK (singleton),
    enabled   boolean     NOT NULL,
    frozen    boolean     NOT NULL,
    at        timestamptz NOT NULL DEFAULT now()
);

-- Executor backups: post-session versions and its own scheduler (expand: the
-- set of allowed sources only grows, existing rows stay valid).
ALTER TABLE backups.config_version
    DROP CONSTRAINT config_version_source_check,
    ADD CONSTRAINT config_version_source_check
        CHECK (source IN ('schedule', 'event', 'manual', 'pre_session', 'post_session', 'executor')) NOT VALID;
ALTER TABLE backups.config_version VALIDATE CONSTRAINT config_version_source_check;

-- Sources by writer: the session and executor-scheduler sources belong to the
-- executor alone, and the executor writes nothing else (it cannot pass for the
-- poller). Runs with the caller's rights, so current_user is the inserting role.
-- +goose StatementBegin
CREATE FUNCTION backups.config_version_check_source() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF (NEW.source IN ('pre_session', 'post_session', 'executor')) IS DISTINCT FROM (current_user = 'nms_executor') THEN
        RAISE EXCEPTION 'config_version source % is not allowed for %', NEW.source, current_user
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION backups.config_version_check_source() FROM PUBLIC;
CREATE TRIGGER config_version_check_source BEFORE INSERT ON backups.config_version
    FOR EACH ROW EXECUTE FUNCTION backups.config_version_check_source();

REVOKE ALL ON ALL TABLES IN SCHEMA exec, execpub FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA exec, execpub FROM PUBLIC;

-- nms_executor
GRANT USAGE ON SCHEMA exec, execpub, core, backups TO nms_executor;
GRANT SELECT, INSERT, UPDATE, DELETE ON exec.registry_counter, exec.write_device, exec.write_grant,
    exec.change_totp, exec.model_profile, exec.write_credential TO nms_executor;
-- exec_state is never deleted (its absence means frozen anyway).
GRANT SELECT, INSERT, UPDATE ON exec.exec_state TO nms_executor;
GRANT SELECT, INSERT ON exec.session, exec.session_device, exec.session_event, exec.recording_chunk,
    exec.recording_manifest, exec.audit_event TO nms_executor;
GRANT SELECT, UPDATE ON exec.audit_head TO nms_executor;
GRANT USAGE ON SEQUENCE exec.model_profile_id_seq, exec.session_event_id_seq, exec.audit_event_id_seq TO nms_executor;
GRANT SELECT, INSERT, UPDATE, DELETE ON execpub.alert, execpub.device_busy, execpub.session_summary,
    execpub.status TO nms_executor;
GRANT SELECT, DELETE ON execpub.freeze_request TO nms_executor;
GRANT USAGE ON SEQUENCE execpub.alert_id_seq TO nms_executor;
-- core is the api's: for display, prefill and refusal only (deny-only).
GRANT SELECT (id, name, address, model, firmware, driver, group_id) ON core.device TO nms_executor;
GRANT SELECT (id, username, disabled) ON core."user" TO nms_executor;
-- id and taken_at are set by the database, as for the poller.
GRANT SELECT ON backups.config_version TO nms_executor;
GRANT INSERT (device_id, source, sha256, size, masked, full_ct, full_dek_ct, drift, taken_by_job)
    ON backups.config_version TO nms_executor;
GRANT USAGE ON SEQUENCE backups.config_version_id_seq TO nms_executor;
GRANT SELECT, INSERT, UPDATE ON backups.backup_state TO nms_executor;

-- nms_api: reads the channel, asks for "freeze on" and nothing else.
GRANT USAGE ON SCHEMA execpub TO nms_api;
GRANT SELECT ON execpub.alert, execpub.device_busy, execpub.session_summary, execpub.status TO nms_api;
GRANT INSERT (requested_by) ON execpub.freeze_request TO nms_api;

-- nms_poller: skips busy devices and drift right after a session.
GRANT USAGE ON SCHEMA execpub TO nms_poller;
GRANT SELECT ON execpub.device_busy, execpub.session_summary TO nms_poller;

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
