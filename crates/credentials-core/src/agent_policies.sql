CREATE TABLE agent_policies (
    version INTEGER PRIMARY KEY NOT NULL CHECK (typeof(version) = 'integer' AND version > 0),
    policy_bytes BLOB NOT NULL CHECK (typeof(policy_bytes) = 'blob' AND length(policy_bytes) > 0),
    policy_sha256 TEXT NOT NULL CHECK (typeof(policy_sha256) = 'text'
        AND length(policy_sha256) = 64 AND length(CAST(policy_sha256 AS BLOB)) = 64
        AND policy_sha256 NOT GLOB '*[^0-9a-f]*'),
    key_id TEXT NOT NULL CHECK (typeof(key_id) = 'text'
        AND length(key_id) = 16 AND length(CAST(key_id AS BLOB)) = 16
        AND key_id NOT GLOB '*[^0-9a-f]*'),
    signature BLOB NOT NULL CHECK (typeof(signature) = 'blob' AND length(signature) = 64),
    signed_at_ms INTEGER NOT NULL CHECK (typeof(signed_at_ms) = 'integer' AND signed_at_ms > 0),
    source TEXT NOT NULL CHECK (typeof(source) = 'text' AND source IN ('ceremony', 'one_tap')),
    approval_seq INTEGER NOT NULL CHECK (typeof(approval_seq) = 'integer' AND approval_seq > 0),
    manifest_version INTEGER NOT NULL UNIQUE REFERENCES gh_manifests(version)
        CHECK (typeof(manifest_version) = 'integer')
) WITHOUT ROWID;

CREATE TRIGGER agent_policies_no_update BEFORE UPDATE ON agent_policies BEGIN
    SELECT RAISE(ABORT, 'agent_policies is insert-only');
END;
CREATE TRIGGER agent_policies_no_delete BEFORE DELETE ON agent_policies BEGIN
    SELECT RAISE(ABORT, 'agent_policies is insert-only');
END;
CREATE TRIGGER agent_policies_increasing BEFORE INSERT ON agent_policies
WHEN EXISTS (SELECT 1 FROM agent_policies WHERE version >= NEW.version) BEGIN
    SELECT RAISE(ABORT, 'agent_policies version must increase');
END;
-- These guards also apply with foreign keys or recursive triggers disabled.
CREATE TRIGGER agent_policies_manifest_exists BEFORE INSERT ON agent_policies
WHEN NOT EXISTS (SELECT 1 FROM gh_manifests WHERE version = NEW.manifest_version) BEGIN
    SELECT RAISE(ABORT, 'agent_policies manifest must exist');
END;
CREATE TRIGGER agent_policies_manifest_unpaired BEFORE INSERT ON agent_policies
WHEN EXISTS (SELECT 1 FROM agent_policies WHERE manifest_version = NEW.manifest_version) BEGIN
    SELECT RAISE(ABORT, 'agent_policies manifest is already paired');
END;

CREATE TABLE read_grants_v51 (
    principal_kind TEXT NOT NULL CHECK (principal_kind IN ('reserved','enrolled')),
    principal_id TEXT NOT NULL,
    selector_kind TEXT NOT NULL CHECK (selector_kind IN ('exact','category','audience')),
    selector TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('read','sign','open','list','deposit','account_token','seal','policy_token')),
    created_at_ms INTEGER NOT NULL,
    CHECK ((operation = 'account_token') = (selector_kind = 'audience')),
    CHECK (operation <> 'seal' OR selector_kind = 'exact'),
    CHECK (operation <> 'policy_token' OR selector_kind = 'exact'),
    PRIMARY KEY (principal_kind, principal_id, selector_kind, selector, operation)
);
INSERT INTO read_grants_v51 (principal_kind, principal_id, selector_kind, selector, operation, created_at_ms)
    SELECT principal_kind, principal_id, selector_kind, selector, operation, created_at_ms FROM read_grants;
DROP TABLE read_grants;
ALTER TABLE read_grants_v51 RENAME TO read_grants;

ALTER TABLE credentials ADD COLUMN github_app_id TEXT;
ALTER TABLE credentials ADD COLUMN github_app_slug TEXT CHECK (
    (github_app_id IS NULL AND github_app_slug IS NULL)
    OR (
        github_app_id IS NOT NULL AND github_app_slug IS NOT NULL
        AND credential_id GLOB 'github_app:*'
        AND typeof(github_app_id) = 'text' AND typeof(github_app_slug) = 'text'
        AND github_app_id GLOB '[1-9]*' AND github_app_id NOT GLOB '*[^0-9]*'
        AND length(CAST(github_app_id AS BLOB)) = length(github_app_id)
        AND CAST(github_app_slug AS BLOB) = substr(CAST(credential_id AS BLOB), length('github_app:') + 1)
    )
);
