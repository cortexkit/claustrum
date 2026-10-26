CREATE TABLE secret_flow_grants (
    grant_id TEXT PRIMARY KEY, secret_name TEXT NOT NULL, incarnation TEXT NOT NULL,
    flow_id TEXT NOT NULL,
    flow_version INTEGER NOT NULL CHECK (typeof(flow_version) = 'integer' AND flow_version BETWEEN 1 AND 9007199254740991),
    flow_code_hash TEXT NOT NULL, flow_install_id TEXT NOT NULL,
    -- JSON array of sorted HTTP methods for API keys, NULL for site logins.
    methods TEXT,
    granted_at_ms INTEGER NOT NULL,
    envelope_sha256 TEXT NOT NULL, card_ref TEXT,
    first_released INTEGER NOT NULL DEFAULT 0 CHECK (first_released IN (0, 1)),
    last_use_ms INTEGER
);
CREATE INDEX secret_flow_grants_incarnation ON secret_flow_grants(incarnation);
CREATE INDEX secret_flow_grants_install ON secret_flow_grants(flow_install_id, flow_version);

ALTER TABLE secret_pending_requests ADD COLUMN flow_id TEXT;
ALTER TABLE secret_pending_requests ADD COLUMN flow_version INTEGER
    CHECK (flow_version IS NULL OR (typeof(flow_version) = 'integer' AND flow_version BETWEEN 1 AND 9007199254740991));
ALTER TABLE secret_pending_requests ADD COLUMN flow_code_hash TEXT;
ALTER TABLE secret_pending_requests ADD COLUMN flow_install_id TEXT;
ALTER TABLE secret_pending_requests ADD COLUMN methods TEXT;
