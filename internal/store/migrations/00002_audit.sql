-- +goose Up
-- Append-only, hash-chained audit log.
-- hash = SHA-256(prev_hash || payload); payload holds the exact hashed bytes.
CREATE TABLE audit.event (
    id        bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts        timestamptz NOT NULL,
    action    text        NOT NULL,
    user_id   bigint      NULL,
    payload   bytea       NOT NULL,
    prev_hash bytea       NOT NULL CHECK (octet_length(prev_hash) = 32),
    hash      bytea       NOT NULL CHECK (octet_length(hash) = 32)
);
CREATE INDEX event_ts_idx ON audit.event (ts);
CREATE INDEX event_action_idx ON audit.event (action);
CREATE INDEX event_user_id_idx ON audit.event (user_id);

-- Single row: the tail of the chain. Appenders lock it FOR UPDATE.
CREATE TABLE audit.chain_head (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    last_id   bigint  NOT NULL,
    hash      bytea   NOT NULL CHECK (octet_length(hash) = 32)
);
INSERT INTO audit.chain_head (singleton, last_id, hash) VALUES (true, 0, decode(repeat('00', 32), 'hex'));

-- Statement-level guard: also fires for UPDATE/DELETE matching no rows and
-- for TRUNCATE, which row-level triggers never see. Privileges alone do not
-- stop the table owner (nms_migrator), the trigger does.
-- +goose StatementBegin
CREATE FUNCTION audit.reject_modification() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit: % on %.% is forbidden', TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege';
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION audit.reject_modification() FROM PUBLIC;

CREATE TRIGGER event_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON audit.event
    FOR EACH STATEMENT EXECUTE FUNCTION audit.reject_modification();
CREATE TRIGGER chain_head_keep_row
    BEFORE DELETE OR TRUNCATE ON audit.chain_head
    FOR EACH STATEMENT EXECUTE FUNCTION audit.reject_modification();

REVOKE ALL ON audit.event, audit.chain_head FROM PUBLIC;
GRANT INSERT, SELECT ON audit.event TO nms_api, nms_cli;
GRANT SELECT, UPDATE ON audit.chain_head TO nms_api, nms_cli;

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
