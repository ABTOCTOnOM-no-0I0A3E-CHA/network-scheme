-- +goose Up
-- execpub.freeze_request as it is used (task 4a.7); this replaces the table
-- comment in 00024, which left out how the api must insert.
--
-- The api inserts with a target-less ON CONFLICT DO NOTHING: ON CONFLICT
-- (singleton) needs SELECT on the column, which the api does not get. Zero
-- inserted rows mean a request is already pending, which is as good as one:
-- the api treats both as success. A target-less DO NOTHING swallows a
-- violation of ANY unique index or exclusion constraint of the table, so the
-- singleton primary key must stay its only one (TestFreezeRequestOnlyUniqueIndex):
-- another one would let a request be dropped silently while none is pending.
--
-- The executor consumes the row with DELETE ... RETURNING (no WHERE) in the
-- same transaction that records the freeze in exec.exec_state, so a request
-- is never consumed without the freeze being recorded. There is no column and
-- no statement that asks for "freeze off".
--
-- Every INSERT statement on the table (also one that inserted nothing)
-- notifies channel execpub_freeze with an empty payload: a wake-up only. The
-- executor reads the table itself, and polls it as well (anyone may NOTIFY).
COMMENT ON TABLE execpub.freeze_request IS
    'Panel request to freeze the executor (singleton). api: INSERT (requested_by) ... ON CONFLICT DO NOTHING without a target; executor: DELETE ... RETURNING in the transaction recording the freeze. The primary key must stay the only unique index.';

-- +goose StatementBegin
CREATE FUNCTION execpub.freeze_request_notify() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM pg_catalog.pg_notify('execpub_freeze', '');
    RETURN NULL;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION execpub.freeze_request_notify() FROM PUBLIC;
CREATE TRIGGER freeze_request_notify AFTER INSERT ON execpub.freeze_request
    FOR EACH STATEMENT EXECUTE FUNCTION execpub.freeze_request_notify();

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
