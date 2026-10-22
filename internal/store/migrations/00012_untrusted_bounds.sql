-- +goose Up
-- Bounds on what the api can write and the poller reads on every poll: a
-- sealed credential is a few hundred bytes (the cap leaves room for large
-- keys), a driver name is short.

DELETE FROM core.access_profile WHERE octet_length(ciphertext) > 8240;
ALTER TABLE core.access_profile ADD CONSTRAINT access_profile_ciphertext_len
    CHECK (octet_length(ciphertext) <= 8240);

UPDATE core.device SET driver = left(driver, 200) WHERE char_length(driver) > 200;
ALTER TABLE core.device ADD CONSTRAINT device_driver_len CHECK (char_length(driver) <= 200);

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
