CREATE TABLE hub_login_targets (
    member_id TEXT PRIMARY KEY NOT NULL,
    box_id TEXT NOT NULL,
    transfer_public_key BLOB NOT NULL CHECK (length(transfer_public_key) = 32),
    pairing_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (typeof(generation) = 'integer' AND generation > 0),
    kind TEXT NOT NULL CHECK (kind IN ('snapshot', 'ended')),
    sealed_bytes BLOB,
    stale INTEGER NOT NULL CHECK (stale IN (0, 1)),
    delivered INTEGER NOT NULL CHECK (delivered IN (0, 1)),
    CHECK (sealed_bytes IS NOT NULL OR (stale = 1 AND delivered = 0))
);

CREATE TABLE hub_login_homes (
    home_member TEXT PRIMARY KEY NOT NULL,
    generation INTEGER NOT NULL CHECK (typeof(generation) = 'integer' AND generation > 0),
    pairing_id TEXT,
    skipped_ids_json TEXT NOT NULL,
    reapply INTEGER NOT NULL CHECK (reapply IN (0, 1))
);

CREATE TABLE hub_own_report (
    singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
    version INTEGER NOT NULL,
    payload_sha256 TEXT NOT NULL,
    verdict TEXT NOT NULL CHECK (verdict IN ('valid', 'invalid')),
    reason TEXT,
    CHECK ((verdict = 'valid' AND reason IS NULL) OR (verdict = 'invalid' AND reason IS NOT NULL))
);

CREATE TABLE hub_report_task (
    singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
    seq INTEGER NOT NULL CHECK (typeof(seq) = 'integer' AND seq BETWEEN 1 AND 9007199254740991),
    signed_bytes BLOB NOT NULL,
    sent INTEGER NOT NULL CHECK (sent IN (0, 1))
);

CREATE TABLE hub_manifest_high_water (
    member_id TEXT NOT NULL,
    box_id TEXT NOT NULL,
    pairing_id TEXT NOT NULL,
    seq INTEGER NOT NULL CHECK (typeof(seq) = 'integer' AND seq BETWEEN 1 AND 9007199254740991),
    PRIMARY KEY (member_id, box_id)
);

-- Keep the roster, retirements, and audit history. No pre-upgrade report, even
-- the self report, was verified from the hub or committed to the own-report row.
CREATE TABLE gh_manifest_activations_v50 (
    member_id TEXT PRIMARY KEY NOT NULL,
    version INTEGER,
    payload_sha256 TEXT,
    verdict TEXT CHECK (verdict IN ('valid', 'invalid')),
    reason TEXT,
    reported_at_ms INTEGER,
    retired_at_ms INTEGER,
    report_box_id TEXT CHECK (report_box_id IS NULL OR version IS NOT NULL),
    CHECK ((version IS NULL AND payload_sha256 IS NULL AND verdict IS NULL
            AND reason IS NULL AND reported_at_ms IS NULL)
        OR (version IS NOT NULL AND payload_sha256 IS NOT NULL AND verdict IS NOT NULL
            AND reported_at_ms IS NOT NULL
            AND ((verdict = 'valid' AND reason IS NULL) OR (verdict = 'invalid' AND reason IS NOT NULL))))
);
INSERT INTO gh_manifest_activations_v50 (member_id, retired_at_ms)
    SELECT member_id, retired_at_ms FROM gh_manifest_activations;
DROP TABLE gh_manifest_activations;
ALTER TABLE gh_manifest_activations_v50 RENAME TO gh_manifest_activations;
