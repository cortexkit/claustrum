CREATE TABLE broker_action_requests (
    request_id TEXT PRIMARY KEY NOT NULL,
    principal TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    scope_json TEXT NOT NULL CHECK (typeof(scope_json) = 'text' AND json_type(scope_json) = 'object'),
    statement_bytes BLOB NOT NULL CHECK (typeof(statement_bytes) = 'blob'),
    statement_sha256 TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    identity TEXT NOT NULL,
    legs_json TEXT NOT NULL CHECK (typeof(legs_json) = 'text' AND json_type(legs_json) = 'array'),
    created_at_ms INTEGER NOT NULL CHECK (typeof(created_at_ms) = 'integer' AND created_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK (typeof(expires_at_ms) = 'integer' AND expires_at_ms >= 0),
    approved_at_ms INTEGER,
    device_fingerprint TEXT,
    envelope_sha256 TEXT,
    issued_legs INTEGER NOT NULL DEFAULT 0 CHECK (
        typeof(issued_legs) = 'integer' AND issued_legs BETWEEN 0 AND json_array_length(legs_json)
    )
) WITHOUT ROWID;

CREATE INDEX broker_action_requests_expiry ON broker_action_requests(expires_at_ms);

-- A replacement would bypass the update guard and could reset an issued request.
CREATE TRIGGER broker_action_requests_no_replace BEFORE INSERT ON broker_action_requests
WHEN EXISTS (SELECT 1 FROM broker_action_requests WHERE request_id = NEW.request_id) BEGIN
    SELECT RAISE(ABORT, 'broker action request already exists');
END;

CREATE TRIGGER broker_action_requests_update BEFORE UPDATE ON broker_action_requests BEGIN
    SELECT RAISE(ABORT, 'broker action request is immutable')
    WHERE NEW.request_id IS NOT OLD.request_id
       OR NEW.principal IS NOT OLD.principal
       OR NEW.agent_id IS NOT OLD.agent_id
       OR NEW.scope_json IS NOT OLD.scope_json
       OR NEW.statement_bytes IS NOT OLD.statement_bytes
       OR NEW.statement_sha256 IS NOT OLD.statement_sha256
       OR NEW.policy_version IS NOT OLD.policy_version
       OR NEW.identity IS NOT OLD.identity
       OR NEW.legs_json IS NOT OLD.legs_json
       OR NEW.created_at_ms IS NOT OLD.created_at_ms
       OR NEW.expires_at_ms IS NOT OLD.expires_at_ms;

    SELECT RAISE(ABORT, 'broker action approval is write-once')
    WHERE (OLD.approved_at_ms IS NOT NULL AND NEW.approved_at_ms IS NOT OLD.approved_at_ms)
       OR (OLD.device_fingerprint IS NOT NULL AND NEW.device_fingerprint IS NOT OLD.device_fingerprint)
       OR (OLD.envelope_sha256 IS NOT NULL AND NEW.envelope_sha256 IS NOT OLD.envelope_sha256);

    SELECT RAISE(ABORT, 'broker action issuance must advance one leg')
    WHERE NEW.issued_legs IS NOT OLD.issued_legs AND NEW.issued_legs IS NOT (OLD.issued_legs + 1);
END;

-- Keep expired requests for diagnosis for 24 hours. If the transaction that
-- inserts a request rolls back, it also restores any pruned rows.
CREATE TRIGGER broker_action_requests_prune AFTER INSERT ON broker_action_requests BEGIN
    DELETE FROM broker_action_requests WHERE expires_at_ms < NEW.created_at_ms - 86400000;
END;
