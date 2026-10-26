CREATE TABLE agent_secrets (
    name TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('agent_api_key', 'site_login')),
    incarnation TEXT NOT NULL UNIQUE CHECK (length(incarnation) = 32),
    state TEXT NOT NULL CHECK (state IN ('active', 'corrupt')),
    host TEXT, path_prefix TEXT, location TEXT, origin TEXT,
    record_version INTEGER NOT NULL CHECK (record_version = 1),
    key_id TEXT NOT NULL, envelope BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    CHECK ((kind = 'agent_api_key' AND host IS NOT NULL AND location IS NOT NULL AND location != '' AND origin IS NULL)
        OR (kind = 'site_login' AND origin IS NOT NULL AND host IS NULL AND path_prefix IS NULL AND location IS NULL))
);
CREATE TABLE secret_phone_keys (
    fingerprint TEXT NOT NULL, pairing_id TEXT NOT NULL,
    deposit_pub BLOB NOT NULL CHECK (length(deposit_pub) = 32),
    approval_pub BLOB NOT NULL CHECK (length(approval_pub) = 65),
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (fingerprint, pairing_id)
);
CREATE TABLE secret_phone_observations (
    fingerprint TEXT PRIMARY KEY, pairing_id TEXT, observed_at_ms INTEGER NOT NULL
);
CREATE TABLE secret_pending_requests (
    request_id TEXT PRIMARY KEY,
    request_kind TEXT NOT NULL CHECK (request_kind IN ('approve', 'delete')),
    secret_name TEXT NOT NULL, incarnation TEXT NOT NULL, member_id TEXT NOT NULL,
    mapped_owner TEXT, mapped_kind TEXT, mapped_ref TEXT, mapped_epoch INTEGER,
    coverage TEXT, agent_id TEXT,
    statement_bytes BLOB NOT NULL, statement_sha256 TEXT NOT NULL,
    request_expires_at_ms INTEGER NOT NULL,
    consumed INTEGER NOT NULL DEFAULT 0 CHECK (consumed IN (0, 1))
);
CREATE INDEX secret_pending_incarnation ON secret_pending_requests(incarnation);
CREATE TABLE secret_grants (
    grant_id TEXT PRIMARY KEY, secret_name TEXT NOT NULL, incarnation TEXT NOT NULL,
    scope_owner TEXT NOT NULL, scope_kind TEXT NOT NULL, scope_ref TEXT NOT NULL,
    coverage TEXT NOT NULL CHECK (coverage IN ('scope', 'agent_and_workers')),
    duration TEXT NOT NULL CHECK (duration IN ('once', 'hour', 'session', 'permanent')),
    expires_at_ms INTEGER NOT NULL, granted_at_ms INTEGER NOT NULL,
    envelope_sha256 TEXT NOT NULL, agent_id TEXT, card_ref TEXT,
    first_released INTEGER NOT NULL DEFAULT 0 CHECK (first_released IN (0, 1)),
    last_use_ms INTEGER
);
CREATE INDEX secret_grants_incarnation ON secret_grants(incarnation);
CREATE TABLE secret_deposit_tombstones (
    deposit_id TEXT PRIMARY KEY, digest TEXT NOT NULL, member_id TEXT NOT NULL,
    incarnation TEXT NOT NULL
);
