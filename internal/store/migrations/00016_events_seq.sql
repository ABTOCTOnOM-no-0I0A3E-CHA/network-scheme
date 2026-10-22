-- +goose Up
-- Insertion order of events for the trigger engine. eventd has ONE writer
-- goroutine that commits its batches one after another, so ingest_seq order is
-- commit order: when the engine has read every row up to a sequence number, no
-- row with a smaller number can still appear later (a rolled-back batch only
-- leaves a gap). Timestamps cannot give that guarantee (syslog time comes from
-- the device; trap time is the receipt time but commits lag behind it). The
-- column is a plain bigint with a nextval() default (an identity column cannot
-- be added to a compressed hypertable): eventd's column lists do not name it,
-- the default needs USAGE on the sequence, and eventd has no INSERT privilege
-- on the column itself, so it cannot choose a value.
CREATE SEQUENCE events.ingest_seq AS bigint;
REVOKE ALL ON SEQUENCE events.ingest_seq FROM PUBLIC;
GRANT USAGE ON SEQUENCE events.ingest_seq TO nms_eventd;
-- A column with a volatile default cannot be added to a hypertable with
-- compression enabled, so the column is added bare and the default set after.
-- Rows written before this migration keep NULL (the engine starts at the
-- current end of each stream anyway).
ALTER TABLE events.syslog ADD COLUMN ingest_seq bigint;
ALTER TABLE events.trap ADD COLUMN ingest_seq bigint;
ALTER TABLE events.syslog ALTER COLUMN ingest_seq SET DEFAULT nextval('events.ingest_seq');
ALTER TABLE events.trap ALTER COLUMN ingest_seq SET DEFAULT nextval('events.ingest_seq');
-- eventd inserts every column except ingest_seq (and the generated tsv).
REVOKE INSERT ON events.syslog, events.trap FROM nms_eventd;
GRANT INSERT (ts, device_id, facility, severity, host, app, msg, raw_len) ON events.syslog TO nms_eventd;
GRANT INSERT (ts, device_id, version, trap_oid, name, severity, varbinds, identified) ON events.trap TO nms_eventd;
CREATE INDEX syslog_ingest_seq_idx ON events.syslog (ingest_seq);
CREATE INDEX trap_ingest_seq_idx ON events.trap (ingest_seq);

-- The engine's position in an event stream is a sequence number; the time
-- watermark column stays (it records when the position was saved).
ALTER TABLE problems.engine_state ADD COLUMN seq bigint NULL;

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
