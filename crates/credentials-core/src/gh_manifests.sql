CREATE TABLE gh_manifests (
    version INTEGER PRIMARY KEY,
    manifest_bytes BLOB NOT NULL,
    manifest_sha256 TEXT NOT NULL CHECK (length(manifest_sha256) = 64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'),
    key_id TEXT NOT NULL,
    signature BLOB NOT NULL CHECK (length(signature) = 64),
    signed_at_ms INTEGER NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('import', 'ceremony', 'one_tap')),
    approval_audit_seq INTEGER,
    CHECK (source = 'import' OR approval_audit_seq IS NOT NULL)
);

CREATE TRIGGER gh_manifests_no_update BEFORE UPDATE ON gh_manifests BEGIN
    SELECT RAISE(ABORT, 'gh_manifests is insert-only');
END;
CREATE TRIGGER gh_manifests_no_delete BEFORE DELETE ON gh_manifests BEGIN
    SELECT RAISE(ABORT, 'gh_manifests is insert-only');
END;
CREATE TRIGGER gh_manifests_increasing BEFORE INSERT ON gh_manifests
WHEN EXISTS (SELECT 1 FROM gh_manifests WHERE version >= NEW.version) BEGIN
    SELECT RAISE(ABORT, 'gh_manifests version must increase');
END;

CREATE TABLE gh_manifest_proposals (
    proposal_id TEXT PRIMARY KEY NOT NULL,
    agent_id TEXT NOT NULL,
    app_id INTEGER NOT NULL,
    app_slug TEXT NOT NULL,
    repo TEXT NOT NULL,
    installation_permissions BLOB NOT NULL,
    base_version INTEGER NOT NULL,
    manifest_bytes BLOB NOT NULL,
    manifest_sha256 TEXT NOT NULL CHECK (length(manifest_sha256) = 64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'),
    statement_bytes BLOB NOT NULL,
    statement_sha256 TEXT NOT NULL CHECK (length(statement_sha256) = 64 AND statement_sha256 NOT GLOB '*[^0-9a-f]*'),
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'approved', 'superseded', 'expired')),
    approved_envelope_sha256 TEXT,
    approved_fingerprint TEXT,
    CHECK ((state = 'approved' AND approved_envelope_sha256 IS NOT NULL AND approved_fingerprint IS NOT NULL)
        OR (state != 'approved' AND approved_envelope_sha256 IS NULL AND approved_fingerprint IS NULL))
);
CREATE UNIQUE INDEX gh_manifest_proposals_pending_repo
    ON gh_manifest_proposals(agent_id, lower(repo)) WHERE state = 'pending';

CREATE TABLE gh_manifest_activations (
    member_id TEXT PRIMARY KEY NOT NULL,
    version INTEGER,
    payload_sha256 TEXT,
    verdict TEXT CHECK (verdict IN ('valid', 'invalid')),
    reason TEXT,
    reported_at_ms INTEGER,
    retired_at_ms INTEGER,
    CHECK ((version IS NULL AND payload_sha256 IS NULL AND verdict IS NULL
            AND reason IS NULL AND reported_at_ms IS NULL AND retired_at_ms IS NOT NULL)
        OR (version IS NOT NULL AND payload_sha256 IS NOT NULL AND verdict IS NOT NULL
            AND reported_at_ms IS NOT NULL
            AND ((verdict = 'valid' AND reason IS NULL) OR (verdict = 'invalid' AND reason IS NOT NULL))))
);

CREATE TABLE gh_manifest_activation_audits (
    member_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    verdict TEXT NOT NULL CHECK (verdict IN ('valid', 'invalid')),
    PRIMARY KEY (member_id, version, verdict)
);
