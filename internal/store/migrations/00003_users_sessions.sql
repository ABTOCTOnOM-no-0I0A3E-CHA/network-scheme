-- +goose Up
-- Panel users, login challenges, server-side sessions and lockouts.
-- Users are disabled, never deleted: no role gets DELETE on core."user".
CREATE TABLE core."user" (
    id              bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username        text        NOT NULL UNIQUE,
    password_phc    text        NOT NULL,
    totp_secret_enc bytea       NULL,
    totp_last_step  bigint      NOT NULL DEFAULT 0,
    backup_hashes   bytea[]     NOT NULL DEFAULT '{}',
    disabled        boolean     NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- Second login step. Only SHA-256 of the challenge id is stored.
CREATE TABLE core.login_challenge (
    id_hash            bytea       PRIMARY KEY CHECK (octet_length(id_hash) = 32),
    user_id            bigint      NOT NULL REFERENCES core."user" (id) ON DELETE CASCADE,
    kind               text        NOT NULL CHECK (kind IN ('totp', 'enroll')),
    pending_secret_enc bytea       NULL,
    expires_at         timestamptz NOT NULL,
    CHECK ((kind = 'enroll') = (pending_secret_enc IS NOT NULL))
);
CREATE INDEX login_challenge_user_id_idx ON core.login_challenge (user_id);
CREATE INDEX login_challenge_expires_at_idx ON core.login_challenge (expires_at);

-- Only SHA-256 of the session token is stored.
CREATE TABLE core.session (
    id_hash    bytea       PRIMARY KEY CHECK (octet_length(id_hash) = 32),
    user_id    bigint      NOT NULL REFERENCES core."user" (id) ON DELETE CASCADE,
    csrf_token text        NOT NULL,
    created_at timestamptz NOT NULL,
    last_seen  timestamptz NOT NULL,
    stepup_at  timestamptz NULL,
    ip         inet        NOT NULL,
    user_agent text        NOT NULL
);
CREATE INDEX session_user_id_idx ON core.session (user_id);
CREATE INDEX session_last_seen_idx ON core.session (last_seen);
CREATE INDEX session_created_at_idx ON core.session (created_at);

-- Failed attempts within the IP window; user_id is NULL for unknown names.
CREATE TABLE core.login_failure (
    user_id bigint      NULL REFERENCES core."user" (id) ON DELETE CASCADE,
    ip      inet        NOT NULL,
    at      timestamptz NOT NULL
);
CREATE INDEX login_failure_ip_at_idx ON core.login_failure (ip, at);
CREATE INDEX login_failure_at_idx ON core.login_failure (at);

-- Consecutive failures per account; reset by a successful login.
CREATE TABLE core.account_lock (
    user_id      bigint      PRIMARY KEY REFERENCES core."user" (id) ON DELETE CASCADE,
    failures     integer     NOT NULL DEFAULT 0 CHECK (failures >= 0),
    locked_until timestamptz NULL
);

-- Active per-IP rate limits (fixed 10 minutes from the triggering failure).
CREATE TABLE core.ip_lock (
    ip           inet        PRIMARY KEY,
    locked_until timestamptz NOT NULL
);

REVOKE ALL ON core."user", core.login_challenge, core.session,
              core.login_failure, core.account_lock, core.ip_lock FROM PUBLIC;

GRANT SELECT, INSERT, UPDATE         ON core."user"          TO nms_api;
GRANT SELECT, INSERT, DELETE         ON core.login_challenge TO nms_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON core.session         TO nms_api;
GRANT SELECT, INSERT, DELETE         ON core.login_failure   TO nms_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON core.account_lock    TO nms_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON core.ip_lock         TO nms_api;

-- nmsctl: user management (break-glass admin, reset of password / TOTP).
-- Disabling or resetting a user must end its sessions and pending challenges.
GRANT SELECT, INSERT, UPDATE   ON core."user"                         TO nms_cli;
GRANT DELETE, SELECT (user_id) ON core.session, core.login_challenge TO nms_cli;

-- +goose Down
-- Forward-only (expand/contract): no down migration.
SELECT 1;
