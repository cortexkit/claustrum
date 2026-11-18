//! Ordered vault migrations and schema upgrade handling.

use super::*;

pub(super) const MIGRATION_10_CONVERSION_TABLE: &[Migration10Conversion] = &[
    Migration10Conversion {
        principal_kind: "reserved",
        principal_id: "broca",
        old_selector: "apikey:opencode-",
        operation: GrantOperation::Read,
        replacement: Migration10Replacement::Exact {
            selector: "apikey:opencode-go",
        },
    },
    Migration10Conversion {
        principal_kind: "reserved",
        principal_id: "prefrontal-routing",
        old_selector: "apikey:artificial-analysis",
        operation: GrantOperation::Read,
        replacement: Migration10Replacement::Exact {
            selector: "apikey:artificial-analysis",
        },
    },
    Migration10Conversion {
        principal_kind: "reserved",
        principal_id: "prefrontal-core",
        old_selector: "signing:agent-assertion:",
        operation: GrantOperation::Read,
        replacement: Migration10Replacement::Exact {
            selector: "signing:agent-assertion:1",
        },
    },
    Migration10Conversion {
        principal_kind: "reserved",
        principal_id: "prefrontal-core",
        old_selector: "signing:agent-assertion:",
        operation: GrantOperation::Sign,
        replacement: Migration10Replacement::Exact {
            selector: "signing:agent-assertion:1",
        },
    },
    Migration10Conversion {
        principal_kind: "reserved",
        principal_id: "prefrontal-core",
        old_selector: "github_app:",
        operation: GrantOperation::Read,
        replacement: Migration10Replacement::Category {
            selector: "forge-identity",
            assignments: &[
                "github_app:aft-alfonso",
                "github_app:alf-alfonso",
                "github_app:astro-alfonso",
                "github_app:ava-alfonso",
                "github_app:broca-alfonso",
                "github_app:callo-alfonso",
                "github_app:cereb-alfonso",
                "github_app:ckcred-alfonso",
                "github_app:ckdesk-alfonso",
                "github_app:cke2e-alfonso",
                "github_app:ckios-alfonso",
                "github_app:cktui-alfonso",
                "github_app:engram-alfonso",
                "github_app:fusi-alfonso",
                "github_app:magic-alfonso",
                "github_app:oaiauth-alfonso",
                "github_app:plex-alfonso",
                "github_app:qta-alfonso",
                "github_app:subc-alfonso",
                "github_app:synapse-alfonso",
                "github_app:thalamus-alfonso",
                "github_app:werni-alfonso",
            ],
        },
    },
];

/// The vault schema. The fence table is created lazily by `with_conn_fenced` on
/// the first fenced write and is not declared here.
///
/// `refresh_intent` is the durable crash-safety log for OAuth refresh: a row is
/// fsynced BEFORE the provider's rotating refresh endpoint is called, and cleared
/// in the same transaction that commits the new tokens. A row that survives a
/// restart means a refresh was interrupted between the provider call and the
/// commit (its outcome is INDETERMINATE — the provider may have rotated), which
/// startup reconciliation resolves fail-safe. At most one intent per credential
/// (the id is the primary key), matching the engine's single-flight.
pub(super) const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        statements: "CREATE TABLE credentials (\
                         credential_id   TEXT PRIMARY KEY, \
                         record_version  INTEGER NOT NULL, \
                         key_id          TEXT NOT NULL, \
                         state           TEXT NOT NULL, \
                         envelope        BLOB NOT NULL, \
                         updated_at_ms   INTEGER NOT NULL\
                     ); \
                     CREATE TABLE refresh_intent (\
                         credential_id    TEXT PRIMARY KEY, \
                         record_version   INTEGER NOT NULL, \
                         old_refresh_hash TEXT NOT NULL, \
                         lease_epoch      INTEGER NOT NULL, \
                         started_at_ms    INTEGER NOT NULL\
                     );",
    },
    // Capability handles + the tamper-evident audit chain.
    //
    // `handles`: a credential is read by an unguessable 256-bit capability handle,
    // not its public alias. Only the handle's SHA-256 HASH is stored (the raw handle
    // is returned once at mint and written into the consumer's 0600 config), so a
    // database leak yields no usable handle — just which credential_ids exist and
    // how many handles each has (metadata, never a secret), which is why these are
    // plaintext columns while credential payloads stay value-encrypted. Handles are
    // per-credential revocable (revoke one, or all for a credential, and mint a fresh
    // one without re-login).
    //
    // `audit_log`: an append-only, HMAC-chained record of EVERY durable mutation
    // (admin writes, refresh commits, revocations), so every credential version is
    // accounted for and an unexplained version bump is a detectable chain gap. Each
    // entry's `entry_mac` is HMAC(audit_key, prev_mac || fields), keyed by a
    // master-key-derived audit key, so the log cannot be forged or repaired without
    // the master key. `alarm` flags a detected anomaly (overwrite-without-CAS,
    // fetch-rate anomaly, admin write) as a durable, queryable row rather than a live
    // notification.
    // `handles.created_at_ms` is WRITTEN AND NEVER READ, deliberately. The audit chain
    // already answers when a handle was minted -- a `mint_handle` entry carries the
    // same instant, written in the same transaction -- so this column is a
    // denormalized copy kept for forensic queries against the table alone, where
    // joining the chain for a timestamp would be the awkward path.
    //
    // Recorded here because a column with no reader is indistinguishable from an
    // abandoned one: a later cleanup would see an unread field and drop it, taking
    // the ability to date a handle from its own row along with it, and dropping a
    // column is not something a test would catch.
    Migration {
        version: 2,
        statements: "CREATE TABLE handles (\
                         handle_hash    TEXT PRIMARY KEY, \
                         credential_id  TEXT NOT NULL, \
                         created_at_ms  INTEGER NOT NULL, \
                         revoked        INTEGER NOT NULL DEFAULT 0\
                     ); \
                     CREATE INDEX idx_handles_credential ON handles(credential_id); \
                     CREATE TABLE audit_log (\
                         seq            INTEGER PRIMARY KEY AUTOINCREMENT, \
                         ts_ms          INTEGER NOT NULL, \
                         op             TEXT NOT NULL, \
                         credential_id  TEXT, \
                         payload_hash   TEXT, \
                         actor          TEXT NOT NULL, \
                         alarm          INTEGER NOT NULL DEFAULT 0, \
                         alarm_reason   TEXT, \
                         prev_mac       TEXT NOT NULL, \
                         entry_mac      TEXT NOT NULL\
                     ); \
                     CREATE TABLE vault_secrets (\
                         name      TEXT PRIMARY KEY, \
                         key_id    TEXT NOT NULL, \
                         envelope  BLOB NOT NULL\
                     );",
    },
    // `auth_events`: why a credential stopped working, which the audit chain cannot say.
    //
    // The chain records mutations, and that is the wrong shape for this question in two
    // specific ways, so without this table a credential marked `needs_reauth` leaves no
    // record of the cause:
    //
    //   - It records only what CHANGED. A consumer's report naming a superseded
    //     `record_version` is a deliberate no-op, so it writes nothing at all -- the
    //     case where a consumer is reporting against stale state is exactly the one
    //     that leaves no trace. Likewise a refresh that fails transiently clears its
    //     intent and returns; nothing durable says the provider was ever called.
    //   - It has no field for the DETAIL. `provider_status` arrives on every report and
    //     is discarded, though 401 (token rejected) and 403 (request forbidden) point
    //     at different causes and different fixes.
    //
    // A field could not simply be added to `audit_log`: the entry MAC covers a fixed
    // field list, so a new column in the transcript changes the MAC of every historical
    // entry and breaks verification of the whole chain. Reusing `alarm_reason` fails
    // differently -- `alarm` is derived as `alarm_reason.is_some()`, so recording a
    // routine 401 there would raise an operator alarm for normal provider behaviour.
    //
    // Hence a separate table, deliberately NOT chained. These rows are diagnostics, not
    // evidence: they are not MAC-protected, they may be pruned, and nothing should
    // depend on them being complete. The chain remains the authority for what happened;
    // this only explains it.
    //
    // `detail` carries a TYPED VARIANT NAME and never provider body text. Adapters put
    // raw response bodies into their error values, and an OAuth error body can echo
    // submitted parameters -- so persisting one risks writing token material into a
    // plaintext column, which is the one thing this table must never do.
    Migration {
        version: 3,
        statements: "CREATE TABLE auth_events (\
                         seq             INTEGER PRIMARY KEY AUTOINCREMENT, \
                         ts_ms           INTEGER NOT NULL, \
                         credential_id   TEXT NOT NULL, \
                         kind            TEXT NOT NULL, \
                         provider_status INTEGER, \
                         detail          TEXT, \
                         record_version  INTEGER, \
                         applied         INTEGER NOT NULL DEFAULT 0\
                     ); \
                     CREATE INDEX idx_auth_events_credential ON auth_events(credential_id);",
    },
    // Principal-scoped read refusals must name the caller for the operator while the
    // wire remains uniformly `not_found`. These nullable columns preserve the older
    // non-principal auth-event rows and their existing diagnostics.
    Migration {
        version: 4,
        statements: "CREATE TABLE read_grants (\
                         principal_kind    TEXT NOT NULL, \
                         principal_id      TEXT NOT NULL, \
                         credential_prefix TEXT NOT NULL, \
                         created_at_ms     INTEGER NOT NULL, \
                         PRIMARY KEY (principal_kind, principal_id, credential_prefix)\
                     ); \
                     ALTER TABLE auth_events ADD COLUMN principal_kind TEXT; \
                     ALTER TABLE auth_events ADD COLUMN principal_id TEXT;",
    },
    // A consumer can prove that the access token it received was refused, but cannot
    // prove that the durable refresh grant is dead. Keep that local assertion outside
    // the sealed provider facts so it can force the next read to refresh without
    // rewriting the envelope or moving its version fence.
    Migration {
        version: 5,
        statements: "ALTER TABLE credentials ADD COLUMN stale_pending INTEGER NOT NULL DEFAULT 0;",
    },
    // Grants are operation-scoped. Rebuild the table so one principal/prefix can hold
    // independent read and sign authorities, then visibly classify every legacy row as
    // read rather than silently relying on a default that could widen an old grant.
    Migration {
        version: 6,
        statements: "CREATE TABLE read_grants_v6 (\
                         principal_kind    TEXT NOT NULL, \
                         principal_id      TEXT NOT NULL, \
                         credential_prefix TEXT NOT NULL, \
                         operation         TEXT NOT NULL CHECK(operation IN ('read', 'sign')), \
                         created_at_ms     INTEGER NOT NULL, \
                         PRIMARY KEY (principal_kind, principal_id, credential_prefix, operation)\
                     ); \
                     INSERT INTO read_grants_v6 \
                         (principal_kind, principal_id, credential_prefix, operation, created_at_ms) \
                     SELECT principal_kind, principal_id, credential_prefix, 'read', created_at_ms \
                     FROM read_grants; \
                     DROP TABLE read_grants; \
                     ALTER TABLE read_grants_v6 RENAME TO read_grants;",
    },
    // GitHub installation-token permissions are non-secret diagnostic metadata. Keep
    // only the latest observation on the credential row so repeated mints cannot grow
    // a table, while leaving historical audit-log MAC transcripts untouched.
    Migration {
        version: 7,
        statements: "ALTER TABLE credentials ADD COLUMN last_github_app_permissions TEXT;",
    },
    Migration {
        version: 8,
        statements: "ALTER TABLE auth_events ADD COLUMN reporter_source TEXT;",
    },
    // Selector kind is part of grant identity. Preserve every legacy column name so the
    // previous reader can still render this table from a read-only open.
    Migration {
        version: 9,
        statements: "CREATE TABLE read_grants_v9 (\
                         principal_kind    TEXT NOT NULL, \
                         principal_id      TEXT NOT NULL, \
                         selector_kind     TEXT NOT NULL CHECK(selector_kind IN ('prefix', 'category')), \
                         credential_prefix TEXT NOT NULL, \
                         operation         TEXT NOT NULL CHECK(operation IN ('read', 'sign')), \
                         created_at_ms     INTEGER NOT NULL, \
                         PRIMARY KEY (principal_kind, principal_id, selector_kind, credential_prefix, operation)\
                     ); \
                     INSERT INTO read_grants_v9 \
                         (principal_kind, principal_id, selector_kind, credential_prefix, operation, created_at_ms) \
                     SELECT principal_kind, principal_id, 'prefix', credential_prefix, operation, created_at_ms \
                     FROM read_grants; \
                     DROP TABLE read_grants; \
                     ALTER TABLE read_grants_v9 RENAME TO read_grants; \
                     CREATE TABLE credential_categories (\
                         credential_id TEXT NOT NULL, \
                         category TEXT NOT NULL, \
                         PRIMARY KEY (credential_id, category), \
                         FOREIGN KEY (credential_id) REFERENCES credentials(credential_id) ON DELETE CASCADE\
                     ); \
                     CREATE INDEX idx_credential_categories_id ON credential_categories(credential_id);",
    },
    // Enrolled consumers, their pending ceremonies, and the store-wide grant
    // generation -- plus the selector vocabulary the grant table now keys on.
    //
    // `read_grants` is rebuilt (create, copy, DROP, rename) rather than altered
    // because the two CHECK constraints and the renamed `selector` column all land
    // inside its compound primary key, which SQLite cannot alter in place. The
    // selector column carries bare selector text for both kinds; the kind column
    // says how to read it, so the historical `credential_prefix` name no longer
    // describes what is stored.
    //
    // `principal_kind` becomes a closed allowlist: a grant belongs either to a
    // launch-nonce module (`reserved`) or to an enrolled consumer (`enrolled`), and
    // a third value in that column would be a principal no authorization path can
    // evaluate.
    //
    // PARTIAL UNIQUENESS IS A SEPARATE STATEMENT, NOT A COLUMN CONSTRAINT: SQLite
    // accepts no `WHERE` clause on an in-table `UNIQUE`, and uniqueness here is a
    // property of LIVE rows only. A revoked enrollment row stays readable forever
    // (the audit join to its grants must survive), so a name may repeat across
    // incarnations while at most one incarnation is live; the same holds for a
    // proposed name across terminal ceremony rows.
    //
    // `credentials.created_at_ms` is backfilled from each row's own chain birth
    // entry -- the earliest audit row that deposited it -- and deliberately NOT from
    // `updated_at_ms`, which is a WRITE time: an actively refreshing credential
    // rewrites it several times a day, so a consumer keyed on it would see every
    // refreshing credential as newly created. A credential the chain cannot date is
    // refused by the guard in `EncryptedStore::migrate` rather than given a default,
    // so no uniform value is ever written here.
    //
    // The generation seed is the LAST statement of this migration on purpose. It is
    // a single store-wide counter that every later grant and category mutation
    // increments, and this migration's own writes are not such a mutation: seeding
    // after them means a migrated store and a store created fresh at this version
    // both observe exactly 1, and the first mutation afterwards is the first bump.
    Migration {
        version: 10,
        statements: "CREATE TABLE read_grants_v10 (\
                         principal_kind    TEXT NOT NULL CHECK (principal_kind IN ('reserved','enrolled')), \
                         principal_id      TEXT NOT NULL, \
                         selector_kind     TEXT NOT NULL CHECK (selector_kind IN ('exact','category')), \
                         selector          TEXT NOT NULL, \
                         operation         TEXT NOT NULL CHECK(operation IN ('read', 'sign')), \
                         created_at_ms     INTEGER NOT NULL, \
                         PRIMARY KEY (principal_kind, principal_id, selector_kind, selector, operation)\
                     ); \
                     INSERT INTO read_grants_v10 \
                         (principal_kind, principal_id, selector_kind, selector, operation, created_at_ms) \
                     SELECT principal_kind, principal_id, selector_kind, selector, operation, created_at_ms \
                     FROM migration_10_grant_plan; \
                     DROP TABLE read_grants; \
                     ALTER TABLE read_grants_v10 RENAME TO read_grants; \
                     INSERT OR IGNORE INTO credential_categories (credential_id, category) \
                     SELECT credential_id, category FROM migration_10_category_plan; \
                     CREATE TABLE enrolled_consumers (\
                         enrollment_id    TEXT PRIMARY KEY, \
                         name             TEXT NOT NULL, \
                         token_hash       TEXT, \
                         token_generation INTEGER NOT NULL DEFAULT 0, \
                         approved_at_ms   INTEGER NOT NULL, \
                         approved_by      TEXT NOT NULL, \
                         revoked_at_ms    INTEGER\
                     ); \
                     CREATE UNIQUE INDEX enrolled_consumers_live_name \
                         ON enrolled_consumers(name) WHERE revoked_at_ms IS NULL; \
                     CREATE TABLE pending_enrollments (\
                         request_id          TEXT PRIMARY KEY, \
                         proposed_name       TEXT NOT NULL, \
                         final_name          TEXT, \
                         enrollment_id       TEXT, \
                         request_secret_hash TEXT NOT NULL, \
                         state               TEXT NOT NULL \
                             CHECK (state IN ('pending','approved','denied','consumed','expired')), \
                         approved_by         TEXT, \
                         approved_at_ms      INTEGER, \
                         created_at_ms       INTEGER NOT NULL, \
                         expires_at_ms       INTEGER NOT NULL\
                     ); \
                     CREATE UNIQUE INDEX pending_enrollments_live_name \
                         ON pending_enrollments(proposed_name) WHERE state IN ('pending','approved'); \
                     ALTER TABLE credentials ADD COLUMN created_at_ms INTEGER; \
                     UPDATE credentials SET created_at_ms = (\
                         SELECT MIN(ts_ms) FROM audit_log \
                          WHERE audit_log.credential_id = credentials.credential_id \
                            AND audit_log.op IN ('put', 'import', 'login', 'create', 'store')\
                     ); \
                     /* Rust appends category.migrate before creating grants_generation. */ \
                     CREATE TABLE grants_generation (\
                         id    INTEGER PRIMARY KEY CHECK (id = 1), \
                         value INTEGER NOT NULL\
                     ); \
                     INSERT INTO grants_generation (id, value) VALUES (1, 1);",
    },
    // Only the operation CHECK changes. Copy stored rows without reconstructing
    // grants or bumping the generation: no grant authority changes here.
    Migration {
        version: 11,
        statements: "CREATE TABLE read_grants_v11 (\
                         principal_kind    TEXT NOT NULL CHECK (principal_kind IN ('reserved','enrolled')), \
                         principal_id      TEXT NOT NULL, \
                         selector_kind     TEXT NOT NULL CHECK (selector_kind IN ('exact','category')), \
                         selector          TEXT NOT NULL, \
                         operation         TEXT NOT NULL CHECK(operation IN ('read', 'sign', 'open')), \
                         created_at_ms     INTEGER NOT NULL, \
                         PRIMARY KEY (principal_kind, principal_id, selector_kind, selector, operation)\
                     ); \
                     INSERT INTO read_grants_v11 \
                         (principal_kind, principal_id, selector_kind, selector, operation, created_at_ms) \
                     SELECT principal_kind, principal_id, selector_kind, selector, operation, created_at_ms \
                     FROM read_grants; \
                     DROP TABLE read_grants; \
                     ALTER TABLE read_grants_v11 RENAME TO read_grants;",
    },
    // Who proposed a pending enrollment, stored on the request row itself so an
    // operator approving it can see where it came from. The same principal is also
    // written to `auth_events` at propose time, but that row carries no request id and
    // the table is a bounded ring, so it cannot be joined back to a request reliably.
    //
    // Nullable, and existing rows are deliberately left NULL: nothing on disk holds
    // their proposer reliably, and a guessed value would read as an observed one.
    Migration {
        version: 12,
        statements: "ALTER TABLE pending_enrollments ADD COLUMN proposer_kind TEXT; \
                     ALTER TABLE pending_enrollments ADD COLUMN proposer_id TEXT;",
    },
    // Admit the metadata-only `list` operation. SQLite cannot alter a CHECK constraint in
    // place, so the table is rebuilt with `list` added to the allowed operations, the
    // same way migration 11 added `open`. Stored rows are copied unchanged and the grant
    // generation is not bumped: no existing grant gains or loses authority.
    Migration {
        version: 13,
        statements: "CREATE TABLE read_grants_v13 (\
                         principal_kind    TEXT NOT NULL CHECK (principal_kind IN ('reserved','enrolled')), \
                         principal_id      TEXT NOT NULL, \
                         selector_kind     TEXT NOT NULL CHECK (selector_kind IN ('exact','category')), \
                         selector          TEXT NOT NULL, \
                         operation         TEXT NOT NULL CHECK(operation IN ('read', 'sign', 'open', 'list')), \
                         created_at_ms     INTEGER NOT NULL, \
                         PRIMARY KEY (principal_kind, principal_id, selector_kind, selector, operation)\
                     ); \
                     INSERT INTO read_grants_v13 \
                         (principal_kind, principal_id, selector_kind, selector, operation, created_at_ms) \
                     SELECT principal_kind, principal_id, selector_kind, selector, operation, created_at_ms \
                     FROM read_grants; \
                     DROP TABLE read_grants; \
                     ALTER TABLE read_grants_v13 RENAME TO read_grants;",
    },
    // Existing creators remain unknown. Copy grants unchanged while adding deposit
    // to the operation constraint, so no existing grant gains authority.
    Migration {
        version: 14,
        statements: "ALTER TABLE credentials ADD COLUMN created_by TEXT; \
                     CREATE TABLE read_grants_v14 (\
                         principal_kind    TEXT NOT NULL CHECK (principal_kind IN ('reserved','enrolled')), \
                         principal_id      TEXT NOT NULL, \
                         selector_kind     TEXT NOT NULL CHECK (selector_kind IN ('exact','category')), \
                         selector          TEXT NOT NULL, \
                         operation         TEXT NOT NULL CHECK(operation IN ('read', 'sign', 'open', 'list', 'deposit')), \
                         created_at_ms     INTEGER NOT NULL, \
                         PRIMARY KEY (principal_kind, principal_id, selector_kind, selector, operation)\
                     ); \
                     INSERT INTO read_grants_v14 SELECT * FROM read_grants; \
                     DROP TABLE read_grants; \
                     ALTER TABLE read_grants_v14 RENAME TO read_grants;",
    },
    // Provider ids are non-secret operator metadata, kept beside the credential row
    // so writing them never touches the sealed record. Every existing credential
    // starts with none: the vault never derives one.
    Migration {
        version: PROVIDER_ID_SCHEMA_VERSION,
        statements: "CREATE TABLE credential_provider_ids (\
                         credential_id TEXT NOT NULL, \
                         provider_id TEXT NOT NULL, \
                         PRIMARY KEY (credential_id, provider_id), \
                         FOREIGN KEY (credential_id) REFERENCES credentials(credential_id) ON DELETE CASCADE\
                     );",
    },
    // No tier is inferred for existing credentials: only an operator can assert it.
    Migration {
        version: 16,
        statements: "CREATE TABLE credential_plan_tiers (\
                         credential_id TEXT NOT NULL PRIMARY KEY, \
                         plan_tier TEXT NOT NULL, \
                         FOREIGN KEY (credential_id) REFERENCES credentials(credential_id) ON DELETE CASCADE\
                     );",
    },
    // Audience grants authorize an exchange, never access to a credential row.
    // Copy all older grants verbatim so migration changes no existing authority.
    Migration {
        version: 17,
        statements: "CREATE TABLE read_grants_v17 (\
                         principal_kind TEXT NOT NULL CHECK (principal_kind IN ('reserved','enrolled')), \
                         principal_id TEXT NOT NULL, \
                         selector_kind TEXT NOT NULL CHECK (selector_kind IN ('exact','category','audience')), \
                         selector TEXT NOT NULL, \
                         operation TEXT NOT NULL CHECK (operation IN ('read','sign','open','list','deposit','account_token')), \
                         created_at_ms INTEGER NOT NULL, \
                         CHECK ((operation = 'account_token') = (selector_kind = 'audience')), \
                         PRIMARY KEY (principal_kind, principal_id, selector_kind, selector, operation)\
                     ); \
                     INSERT INTO read_grants_v17 SELECT * FROM read_grants; \
                     DROP TABLE read_grants; \
                     ALTER TABLE read_grants_v17 RENAME TO read_grants;",
    },
    // Admit the `seal` operation, exact selectors only. SQLite cannot alter a CHECK in
    // place, so the table is rebuilt the way migrations 13, 14 and 17 rebuilt it. Every
    // row is copied unchanged and the grant generation is not bumped: no existing grant
    // gains or loses authority. The seal/exact pairing is a CHECK as well as a code rule
    // so a row written by any path that skips `validate_operation` is still refused.
    Migration {
        version: 18,
        statements: "CREATE TABLE read_grants_v18 (\
                         principal_kind TEXT NOT NULL CHECK (principal_kind IN ('reserved','enrolled')), \
                         principal_id TEXT NOT NULL, \
                         selector_kind TEXT NOT NULL CHECK (selector_kind IN ('exact','category','audience')), \
                         selector TEXT NOT NULL, \
                         operation TEXT NOT NULL CHECK (operation IN ('read','sign','open','list','deposit','account_token','seal')), \
                         created_at_ms INTEGER NOT NULL, \
                         CHECK ((operation = 'account_token') = (selector_kind = 'audience')), \
                         CHECK (operation <> 'seal' OR selector_kind = 'exact'), \
                         PRIMARY KEY (principal_kind, principal_id, selector_kind, selector, operation)\
                     ); \
                     INSERT INTO read_grants_v18 SELECT * FROM read_grants; \
                     DROP TABLE read_grants; \
                     ALTER TABLE read_grants_v18 RENAME TO read_grants;",
    },
    // Vault release 2 (home-vault federation) starts here. Every table it needs lands
    // in migrations 19 to 26 together, so a later federation change adds code, never
    // schema, and a release-1 binary refuses the whole set at once.
    //
    // `remote_records`: a rotating login whose home is another member's vault. This
    // vault only borrows short-lived access tokens for it, so the row holds the home's
    // non-secret description and this vault's own view of the last fetch. THERE IS NO PAYLOAD
    // OR OAUTH COLUMN, by design: a refresh token must never be stored here, and the
    // access token lives only in memory. `kind` is a one-value CHECK so a future reader
    // cannot mistake the table for a general record store.
    //
    // `incarnation` (32 lowercase hex) is new on every `remote add`, so a delayed reply
    // fetched for an earlier add of the same id can be recognised and discarded.
    // `detected_plan` is the home's `DetectedPlan` as JSON. `last_home_state` and
    // `last_home_error` change only on an authoritative home answer;
    // `last_fetch_outcome` changes on every fetch, transport failures included.
    Migration {
        version: FEDERATION_SCHEMA_VERSION,
        statements: "CREATE TABLE remote_records (\
                         credential_id      TEXT PRIMARY KEY, \
                         home_member        TEXT NOT NULL, \
                         incarnation        TEXT NOT NULL CHECK (length(incarnation) = 32), \
                         kind               TEXT NOT NULL CHECK (kind = 'oauth'), \
                         refresh_adapter    TEXT, \
                         detected_plan      TEXT, \
                         account_id         TEXT, \
                         email              TEXT, \
                         org_name           TEXT, \
                         last_home_version  INTEGER NOT NULL, \
                         last_home_state    TEXT NOT NULL \
                             CHECK (last_home_state IN ('active','needs_reauth','corrupt')), \
                         last_home_error    TEXT, \
                         last_fetch_outcome TEXT, \
                         last_fetch_at_ms   INTEGER, \
                         reported_version   INTEGER, \
                         created_at_ms      INTEGER NOT NULL, \
                         updated_at_ms      INTEGER NOT NULL\
                     );",
    },
    // The metadata this vault, not the home, owns for a remote record. The tables that
    // hold the same facts for local records cannot be reused: each has a cascading
    // foreign key to `credentials`, which a remote id never appears in.
    Migration {
        version: REMOTE_METADATA_SCHEMA_VERSION,
        statements: "CREATE TABLE remote_record_categories (\
                         credential_id TEXT NOT NULL, \
                         category TEXT NOT NULL, \
                         PRIMARY KEY (credential_id, category), \
                         FOREIGN KEY (credential_id) REFERENCES remote_records(credential_id) ON DELETE CASCADE\
                     ); \
                     CREATE TABLE remote_record_provider_ids (\
                         credential_id TEXT NOT NULL, \
                         provider_id TEXT NOT NULL, \
                         PRIMARY KEY (credential_id, provider_id), \
                         FOREIGN KEY (credential_id) REFERENCES remote_records(credential_id) ON DELETE CASCADE\
                     ); \
                     CREATE TABLE remote_record_plan_tiers (\
                         credential_id TEXT NOT NULL PRIMARY KEY, \
                         plan_tier TEXT NOT NULL, \
                         FOREIGN KEY (credential_id) REFERENCES remote_records(credential_id) ON DELETE CASCADE\
                     );",
    },
    // ONE ID, ONE RECORD. An id is either a local record or a remote one, never both:
    // a scoped read would otherwise have two answers. The check sits in the database
    // rather than in each creator so every path that inserts a row is covered at once,
    // including ones written after these triggers. The RAISE messages are matched by
    // `StoreOpError::from` to name the conflict, so they are part of the contract.
    Migration {
        version: 21,
        statements: "CREATE TRIGGER credentials_id_not_remote_insert \
                         BEFORE INSERT ON credentials \
                         WHEN EXISTS (SELECT 1 FROM remote_records WHERE credential_id = NEW.credential_id) \
                     BEGIN SELECT RAISE(ABORT, 'credential_id_is_remote'); END; \
                     CREATE TRIGGER credentials_id_not_remote_update \
                         BEFORE UPDATE OF credential_id ON credentials \
                         WHEN EXISTS (SELECT 1 FROM remote_records WHERE credential_id = NEW.credential_id) \
                     BEGIN SELECT RAISE(ABORT, 'credential_id_is_remote'); END; \
                     CREATE TRIGGER remote_records_id_not_local_insert \
                         BEFORE INSERT ON remote_records \
                         WHEN EXISTS (SELECT 1 FROM credentials WHERE credential_id = NEW.credential_id) \
                     BEGIN SELECT RAISE(ABORT, 'credential_id_is_local'); END; \
                     CREATE TRIGGER remote_records_id_not_local_update \
                         BEFORE UPDATE OF credential_id ON remote_records \
                         WHEN EXISTS (SELECT 1 FROM credentials WHERE credential_id = NEW.credential_id) \
                     BEGIN SELECT RAISE(ABORT, 'credential_id_is_local'); END;",
    },
    // What another member's vault may do here. Kept apart from `read_grants` so no
    // existing operation can ever be granted to a member, and no member operation to a
    // module. `pairing_id` is the member's pairing at grant time: a grant counts only
    // while it equals the member's current one, so a re-pair voids every older grant.
    // `transfer_deliver` takes no selector, stored as kind `none` with an empty selector.
    Migration {
        version: MEMBER_GRANTS_SCHEMA_VERSION,
        statements: "CREATE TABLE member_grants (\
                         member_id     TEXT NOT NULL, \
                         operation     TEXT NOT NULL CHECK (operation IN ('remote_read','transfer_deliver')), \
                         selector_kind TEXT NOT NULL CHECK (selector_kind IN ('exact','category','none')), \
                         selector      TEXT NOT NULL, \
                         pairing_id    TEXT NOT NULL, \
                         created_at_ms INTEGER NOT NULL, \
                         CHECK ((operation = 'transfer_deliver') = (selector_kind = 'none')), \
                         CHECK ((selector_kind = 'none') = (selector = '')), \
                         PRIMARY KEY (member_id, operation, selector_kind, selector)\
                     );",
    },
    // One row per (member, credential, home record version, digest of the stored
    // encrypted bytes) the home has issued a token for, so a `remote_issue` audit row is
    // written once per material rather than once per fetch, also across restarts.
    Migration {
        version: 23,
        statements: "CREATE TABLE remote_issue_seen (\
                         member_id       TEXT NOT NULL, \
                         credential_id   TEXT NOT NULL, \
                         record_version  INTEGER NOT NULL, \
                         material_digest TEXT NOT NULL, \
                         seen_at_ms      INTEGER NOT NULL, \
                         PRIMARY KEY (member_id, credential_id, record_version, material_digest)\
                     ); \
                     CREATE INDEX idx_remote_issue_seen_credential ON remote_issue_seen(credential_id);",
    },
    // Sealed static-key transfers received from other members. A row is created only
    // after its envelope opened and its body validated, and it keeps the SEALED bytes
    // only: nothing here is plaintext. `transfer_id` is the one bound in the
    // authenticated envelope; `body_hash` is SHA-256(enc || ciphertext), the dedup key
    // checked before any open. Terminal rows (accepted, rejected, expired) keep their
    // id and hash forever with the envelope cleared, so a resend answers its stored
    // state and an accepted transfer can never be imported twice.
    Migration {
        version: 24,
        statements: "CREATE TABLE pending_transfers (\
                         sender_member  TEXT NOT NULL, \
                         transfer_id    TEXT NOT NULL CHECK (length(transfer_id) = 32), \
                         body_hash      TEXT NOT NULL CHECK (length(body_hash) = 64), \
                         state          TEXT NOT NULL \
                             CHECK (state IN ('pending','accepted','rejected','expired')), \
                         credential_id  TEXT NOT NULL, \
                         kind           TEXT NOT NULL, \
                         categories     TEXT NOT NULL DEFAULT '', \
                         size_bytes     INTEGER NOT NULL, \
                         enc            BLOB, \
                         ciphertext     BLOB, \
                         aad            BLOB, \
                         reject_reason  TEXT, \
                         received_at_ms INTEGER NOT NULL, \
                         expires_at_ms  INTEGER NOT NULL, \
                         decided_at_ms  INTEGER, \
                         CHECK ((state = 'pending') = (enc IS NOT NULL AND ciphertext IS NOT NULL AND aad IS NOT NULL)), \
                         PRIMARY KEY (sender_member, transfer_id), \
                         UNIQUE (sender_member, body_hash)\
                     ); \
                     CREATE INDEX idx_pending_transfers_state ON pending_transfers(state);",
    },
    // Transfers this vault sent and has not seen a terminal reply for. Each keeps the
    // one sealed envelope made at `send`, so every retry, including `send --resume`
    // after a restart, delivers identical bytes. `abandoned` marks rows sealed under a
    // transfer key this vault has since replaced; they can only fail at the receiver.
    Migration {
        version: 25,
        statements: "CREATE TABLE outgoing_transfers (\
                         transfer_id      TEXT PRIMARY KEY CHECK (length(transfer_id) = 32), \
                         receiver_member  TEXT NOT NULL, \
                         credential_id    TEXT NOT NULL, \
                         body_hash        TEXT NOT NULL CHECK (length(body_hash) = 64), \
                         enc              BLOB NOT NULL, \
                         ciphertext       BLOB NOT NULL, \
                         aad              BLOB NOT NULL, \
                         state            TEXT NOT NULL CHECK (state IN ('pending','abandoned')), \
                         last_reply_code  TEXT, \
                         created_at_ms    INTEGER NOT NULL, \
                         expires_at_ms    INTEGER NOT NULL, \
                         last_attempt_at_ms INTEGER\
                     );",
    },
    // Store-wide settings read on every federation decision, so a change takes effect
    // without a restart and a whole-store restore brings them back with the data they
    // govern. Written only by audited admin ops (`EncryptedStore::set_federation_*`).
    Migration {
        version: SETTINGS_SCHEMA_VERSION,
        statements: "CREATE TABLE settings (\
                         name          TEXT PRIMARY KEY, \
                         value         TEXT NOT NULL, \
                         updated_at_ms INTEGER NOT NULL\
                     );",
    },
    Migration {
        version: AGENT_SECRET_SCHEMA_VERSION,
        statements: include_str!("agent_secrets.sql"),
    },
    Migration {
        version: FLOW_SECRET_SCHEMA_VERSION,
        statements: include_str!("flow_secrets.sql"),
    },
    // Admit the `secret_use` member operation: a paired computer may forward agent-secret
    // calls to this vault, which holds the account's secrets. Like `transfer_deliver` it
    // takes no selector, so kind `none` is now valid for exactly those two operations.
    // SQLite cannot alter a CHECK in place, so the table is rebuilt the way migrations 13,
    // 14, 17 and 18 rebuilt `read_grants`, and the migration that created `member_grants`
    // stays as it was. Every row is copied unchanged, pairing id and creation time
    // included, so no existing grant gains or loses authority.
    Migration {
        version: SECRET_USE_MEMBER_GRANT_SCHEMA_VERSION,
        statements: "CREATE TABLE member_grants_v29 (\
                         member_id     TEXT NOT NULL, \
                         operation     TEXT NOT NULL CHECK (operation IN ('remote_read','transfer_deliver','secret_use')), \
                         selector_kind TEXT NOT NULL CHECK (selector_kind IN ('exact','category','none')), \
                         selector      TEXT NOT NULL, \
                         pairing_id    TEXT NOT NULL, \
                         created_at_ms INTEGER NOT NULL, \
                         CHECK ((operation IN ('transfer_deliver','secret_use')) = (selector_kind = 'none')), \
                         CHECK ((selector_kind = 'none') = (selector = '')), \
                         PRIMARY KEY (member_id, operation, selector_kind, selector)\
                     ); \
                     INSERT INTO member_grants_v29 \
                         (member_id, operation, selector_kind, selector, pairing_id, created_at_ms) \
                         SELECT member_id, operation, selector_kind, selector, pairing_id, created_at_ms \
                         FROM member_grants; \
                     DROP TABLE member_grants; \
                     ALTER TABLE member_grants_v29 RENAME TO member_grants;",
    },
    // A grant or pending request now also belongs to the computer whose agent or flow
    // asked for it: `''` for a request made on this vault itself, or the paired member id
    // (`fed-computer:<fp>`) of a computer that forwarded the call here. Grant selection,
    // pending reuse and flow-grant revocation compare it, so one computer's grant never
    // answers another computer's request for the same scope stamp or flow identity.
    // Every existing row was made locally, which the `''` default records. Adding a
    // column with a constant default rewrites no row.
    Migration {
        version: SECRET_ASKING_MEMBER_SCHEMA_VERSION,
        statements: "ALTER TABLE secret_grants ADD COLUMN asking_member_id TEXT NOT NULL DEFAULT ''; \
                     ALTER TABLE secret_flow_grants ADD COLUMN asking_member_id TEXT NOT NULL DEFAULT ''; \
                     ALTER TABLE secret_pending_requests ADD COLUMN asking_member_id TEXT NOT NULL DEFAULT '';",
    },
    // One row per secret release sealed for a paired computer, keyed by that computer's
    // member id and the nonce from the request's additional authenticated data (AAD). A
    // retry of the same request (same nonce, same AAD bytes) gets the stored `enc` and `ciphertext` back unchanged, so a
    // reply lost in transit neither consumes a `once` grant twice nor writes a second
    // release audit. The row records the secret's incarnation and the grant used: a retry
    // is refused once the incarnation changes or the grant is no longer live (a `once`
    // grant the release consumed is exempt), and
    // `expires_at_ms` bounds how long a nonce can be replayed at all. Rows are deleted
    // after expiry, but every lookup compares `expires_at_ms` itself.
    Migration {
        version: SECRET_RELEASE_RECEIPT_SCHEMA_VERSION,
        statements: "CREATE TABLE secret_release_receipts (\
                         requester     TEXT NOT NULL, \
                         nonce         TEXT NOT NULL, \
                         aad_sha256    TEXT NOT NULL, \
                         incarnation   TEXT NOT NULL, \
                         grant_kind    TEXT NOT NULL CHECK (grant_kind IN ('agent','once','flow')), \
                         grant_id      TEXT NOT NULL, \
                         enc           BLOB NOT NULL, \
                         ciphertext    BLOB NOT NULL, \
                         expires_at_ms INTEGER NOT NULL, \
                         PRIMARY KEY (requester, nonce)\
                     ); \
                     CREATE INDEX secret_release_receipts_expiry ON secret_release_receipts(expires_at_ms);",
    },
    // A profile observation waits for the next token commit without changing the
    // sealed record or its audit chain. Version changes and removal discard it in
    // the same transaction, including replacements made outside the refresh engine.
    Migration {
        version: 32,
        statements: "CREATE TABLE held_detected_plans (\
                         credential_id TEXT PRIMARY KEY, \
                         record_version INTEGER NOT NULL, \
                         token_hash TEXT NOT NULL, \
                         identity TEXT NOT NULL, \
                         tier TEXT, \
                         raw TEXT, \
                         observed_at_ms INTEGER NOT NULL\
                     ); \
                     CREATE TRIGGER held_detected_plans_version AFTER UPDATE OF record_version ON credentials \
                     WHEN OLD.record_version != NEW.record_version BEGIN \
                         DELETE FROM held_detected_plans WHERE credential_id = OLD.credential_id; \
                     END; \
                     CREATE TRIGGER held_detected_plans_remove AFTER DELETE ON credentials BEGIN \
                         DELETE FROM held_detected_plans WHERE credential_id = OLD.credential_id; \
                     END; \
                     CREATE TRIGGER held_detected_plans_insert AFTER INSERT ON credentials BEGIN \
                         DELETE FROM held_detected_plans WHERE credential_id = NEW.credential_id; \
                      END;",
    },
    // Versions restart after removal, and creation timestamps can share a millisecond.
    // A separate identity binds pending reads and writes to one row's lifetime.
    Migration {
        version: 33,
        statements: "ALTER TABLE credentials ADD COLUMN incarnation TEXT NOT NULL DEFAULT ''; \
                     UPDATE credentials SET incarnation = lower(hex(randomblob(16))); \
                     CREATE TRIGGER credentials_incarnation_insert AFTER INSERT ON credentials \
                     WHEN NEW.incarnation = '' BEGIN \
                         UPDATE credentials SET incarnation = lower(hex(randomblob(16))) \
                         WHERE credential_id = NEW.credential_id; \
                     END;",
    },
    Migration {
        version: ENROLLMENT_DISPLAY_NAME_SCHEMA_VERSION,
        statements: "ALTER TABLE pending_enrollments ADD COLUMN display_name TEXT; \
                     ALTER TABLE enrolled_consumers ADD COLUMN display_name TEXT;",
    },
    // SQLite cannot alter a CHECK in place. Rebuild only the secret table, keeping
    // legacy columns and sealed bodies unchanged; NULL scope_json marks legacy rows.
    Migration {
        version: SECRET_SCOPE_SCHEMA_VERSION,
        statements: "CREATE TABLE agent_secrets_v35 (\
                         name TEXT PRIMARY KEY, \
                         kind TEXT NOT NULL CHECK (kind IN ('agent_api_key', 'site_login')), \
                         incarnation TEXT NOT NULL UNIQUE CHECK (length(incarnation) = 32), \
                         state TEXT NOT NULL CHECK (state IN ('active', 'corrupt')), \
                         host TEXT, path_prefix TEXT, location TEXT, origin TEXT, \
                         record_version INTEGER NOT NULL CHECK (record_version = 1), \
                         key_id TEXT NOT NULL, envelope BLOB NOT NULL, \
                         created_at_ms INTEGER NOT NULL, \
                         scope_json TEXT, \
                         CHECK ((kind = 'agent_api_key' AND location IS NOT NULL AND location != '' AND origin IS NULL \
                             AND ((host IS NOT NULL AND scope_json IS NULL) \
                                 OR (host IS NULL AND path_prefix IS NULL AND scope_json IS NOT NULL))) \
                             OR (kind = 'site_login' AND host IS NULL AND path_prefix IS NULL AND location IS NULL \
                                 AND ((origin IS NOT NULL AND scope_json IS NULL) \
                                     OR (origin IS NULL AND scope_json IS NOT NULL))))\
                     ); \
                     INSERT INTO agent_secrets_v35 \
                         (name, kind, incarnation, state, host, path_prefix, location, origin, record_version, key_id, envelope, created_at_ms) \
                         SELECT name, kind, incarnation, state, host, path_prefix, location, origin, record_version, key_id, envelope, created_at_ms \
                         FROM agent_secrets; \
                     DROP TABLE agent_secrets; \
                     ALTER TABLE agent_secrets_v35 RENAME TO agent_secrets;",
    },
    // No backfill: neither the last record write nor the last tier observation
    // proves when an existing value first took effect.
    Migration {
        version: PLAN_TIER_OBSERVED_SCHEMA_VERSION,
        statements: "ALTER TABLE credential_plan_tiers ADD COLUMN observed_at_ms INTEGER; \
                     ALTER TABLE remote_record_plan_tiers ADD COLUMN observed_at_ms INTEGER; \
                     ALTER TABLE remote_records ADD COLUMN detected_plan_tier_observed_at_ms INTEGER;",
    },
    Migration {
        version: REGISTERED_PROVIDERS_SCHEMA_VERSION,
        statements: "CREATE TABLE registered_providers (\
                         service TEXT PRIMARY KEY, \
                         categories_json TEXT NOT NULL, \
                         provider_ids_json TEXT NOT NULL, \
                         created_at_ms INTEGER NOT NULL\
                     );",
    },
    Migration {
        version: MEMBER_GRANT_SOURCE_SCHEMA_VERSION,
        statements: "ALTER TABLE member_grants ADD COLUMN source TEXT NOT NULL \
                     DEFAULT 'operator' CHECK (source IN ('operator', 'sharing_switch'));",
    },
    Migration {
        version: REMOTE_RECORD_SOURCE_SCHEMA_VERSION,
        statements: "ALTER TABLE remote_records ADD COLUMN source TEXT NOT NULL \
                     DEFAULT 'operator' CHECK (source IN ('operator', 'home_watch')); \
                     ALTER TABLE remote_records ADD COLUMN home_pairing_id TEXT \
                     CHECK ((source = 'home_watch') = (home_pairing_id IS NOT NULL));",
    },
    Migration {
        version: ENROLLMENT_REQUESTED_GRANTS_SCHEMA_VERSION,
        statements: "ALTER TABLE pending_enrollments ADD COLUMN requested_grants_json TEXT;",
    },
    Migration {
        version: GH_MANIFEST_SCHEMA_VERSION,
        statements: include_str!("gh_manifests.sql"),
    },
    Migration {
        version: REGISTERED_PROVIDER_DESCRIPTOR_SCHEMA_VERSION,
        statements: "ALTER TABLE registered_providers ADD COLUMN hosts_json TEXT NOT NULL DEFAULT '[]'; \
                     ALTER TABLE registered_providers ADD COLUMN auth_header TEXT DEFAULT NULL; \
                     ALTER TABLE registered_providers ADD COLUMN auth_scheme TEXT DEFAULT NULL; \
                     ALTER TABLE registered_providers ADD COLUMN fusiform_provider_id TEXT DEFAULT NULL;",
    },
    Migration {
        version: GATEWAY_SETTINGS_SCHEMA_VERSION,
        statements: "CREATE TABLE credential_gateway_settings (\
                         credential_id TEXT NOT NULL PRIMARY KEY REFERENCES credentials(credential_id) ON DELETE CASCADE, \
                         incarnation TEXT NOT NULL, \
                         base_url TEXT NOT NULL, \
                         auth_header TEXT NOT NULL, \
                         auth_scheme TEXT NOT NULL, \
                         headers_json TEXT NOT NULL\
                     );",
    },
    Migration {
        version: PLAN_TIER_SINCE_SCHEMA_VERSION,
        statements: "ALTER TABLE credential_plan_tiers ADD COLUMN since_ms INTEGER; \
                     ALTER TABLE remote_record_plan_tiers ADD COLUMN since_ms INTEGER;",
    },
    Migration {
        version: DECLARED_GRANTS_SCHEMA_VERSION,
        statements: "CREATE TABLE declared_grant_sets (\
            module_id TEXT PRIMARY KEY, \
            declaration_digest TEXT, \
            approved_declarations_digest TEXT, \
            origin TEXT, \
            grants_json TEXT NOT NULL, \
            skipped_count INTEGER NOT NULL, \
            first_seen_ms INTEGER NOT NULL\
        );",
    },
    Migration {
        version: LOCAL_PROGRAM_SECRET_SCHEMA_VERSION,
        statements: "CREATE TABLE agent_secrets_v46 (\
            name TEXT PRIMARY KEY, \
            kind TEXT NOT NULL CHECK (kind IN ('agent_api_key', 'site_login', 'local_program')), \
            incarnation TEXT NOT NULL UNIQUE CHECK (length(incarnation) = 32), \
            state TEXT NOT NULL CHECK (state IN ('active', 'corrupt')), \
            host TEXT, path_prefix TEXT, location TEXT, origin TEXT, \
            record_version INTEGER NOT NULL CHECK (record_version = 1), \
            key_id TEXT NOT NULL, envelope BLOB NOT NULL, created_at_ms INTEGER NOT NULL, scope_json TEXT, \
            CHECK ((kind = 'agent_api_key' AND location IS NOT NULL AND location != '' AND origin IS NULL \
                AND ((host IS NOT NULL AND scope_json IS NULL) OR (host IS NULL AND path_prefix IS NULL AND scope_json IS NOT NULL))) \
                OR (kind = 'site_login' AND host IS NULL AND path_prefix IS NULL AND location IS NULL \
                    AND ((origin IS NOT NULL AND scope_json IS NULL) OR (origin IS NULL AND scope_json IS NOT NULL))) \
                OR (kind = 'local_program' AND host IS NULL AND path_prefix IS NULL AND location IS NULL AND origin IS NULL AND scope_json IS NOT NULL))\
        ); \
        INSERT INTO agent_secrets_v46 SELECT * FROM agent_secrets; \
        DROP TABLE agent_secrets; \
        ALTER TABLE agent_secrets_v46 RENAME TO agent_secrets; \
        ALTER TABLE secret_grants ADD COLUMN local_use TEXT; \
        ALTER TABLE secret_pending_requests ADD COLUMN local_use TEXT;",
    },
    Migration {
        version: FLEET_SCHEMA_VERSION,
        statements: "CREATE TABLE fleet_epochs (\
            epoch INTEGER PRIMARY KEY, key BLOB NOT NULL, minter TEXT NOT NULL, \
            members_json TEXT NOT NULL, mint_id TEXT, \
            state TEXT NOT NULL CHECK (state IN ('pending','current','retired')), \
            created_at_ms INTEGER NOT NULL\
        ); \
        CREATE UNIQUE INDEX fleet_one_current ON fleet_epochs(state) WHERE state = 'current'; \
        CREATE UNIQUE INDEX fleet_one_pending ON fleet_epochs(state) WHERE state = 'pending'; \
        CREATE TABLE fleet_removals (\
            member_id TEXT NOT NULL, removal_id TEXT NOT NULL, observed_at_ms INTEGER NOT NULL, \
            PRIMARY KEY (member_id, removal_id)\
        ); \
        CREATE TABLE fleet_discards (mint_id TEXT PRIMARY KEY, epoch INTEGER NOT NULL);",
    },
    Migration {
        version: MODULE_SECRET_SCHEMA_VERSION,
        statements: "CREATE TABLE module_secrets (\
            module_id TEXT NOT NULL, name TEXT NOT NULL, \
            version INTEGER NOT NULL CHECK (version >= 1), \
            protected INTEGER NOT NULL CHECK (protected IN (0, 1)), \
            state TEXT NOT NULL CHECK (state IN ('active', 'corrupt')), \
            key_id TEXT NOT NULL, envelope BLOB NOT NULL, \
            created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL, \
            PRIMARY KEY (module_id, name)\
        );",
    },
    Migration {
        version: CONDITION_SCHEMA_VERSION,
        statements: "CREATE TABLE credential_conditions (\
            credential_id TEXT NOT NULL PRIMARY KEY REFERENCES credentials(credential_id) ON DELETE CASCADE, \
            incarnation TEXT NOT NULL, \
            reason TEXT NOT NULL, \
            since_ms INTEGER NOT NULL CHECK (typeof(since_ms) = 'integer' AND since_ms BETWEEN 0 AND 9007199254740991), \
            reporter TEXT NOT NULL, \
            action_url TEXT\
        ); \
        CREATE TABLE remote_record_conditions (\
            credential_id TEXT NOT NULL PRIMARY KEY REFERENCES remote_records(credential_id) ON DELETE CASCADE, \
            incarnation TEXT NOT NULL, \
            reason TEXT NOT NULL, \
            since_ms INTEGER NOT NULL CHECK (typeof(since_ms) = 'integer' AND since_ms BETWEEN 0 AND 9007199254740991), \
            action_url TEXT\
        );",
    },
];

/// The newest store migration THIS BINARY knows how to apply.
///
/// Published so the module manifest can declare `store_schema_version` as a derived
/// fact. The number is not an implementation detail: it is a COMPATIBILITY MARKER,
/// monotone by construction, and the supervisor contract already treats it as a
/// fleet-visible value that modules are asked to state.
///
/// DERIVED FROM THE LIST, NEVER HAND-TYPED. A literal here would fall behind the list
/// the first time a migration is added without updating it, and nothing would fail.
/// Deriving makes the drift impossible rather than merely discouraged.
///
/// WHAT DECLARING IT BUYS, precisely, because it is easy to overstate: a binary older
/// than the store it opens already REFUSES to open it. [`EncryptedStore::migrate`]
/// compares the store's recorded version with this number and fails, naming both
/// versions, before serving anything. Declaring the number adds a second, earlier view
/// of the same mismatch: a supervisor comparing declared against actual sees it
/// without starting the binary. Because of that refusal, rolling a binary back past a
/// migration also means restoring the store snapshot taken before that migration ran.
pub const fn newest_migration_version() -> u32 {
    let mut newest = 0;
    let mut i = 0;
    while i < MIGRATIONS.len() {
        if MIGRATIONS[i].version > newest {
            newest = MIGRATIONS[i].version;
        }
        i += 1;
    }
    newest
}

/// Apply the migration chain only through `version`, so a test can build a store
/// sitting at an older schema.
///
/// The placement window this reproduces is a store one migration behind the binary,
/// and the faithful way to build one is to run the REAL chain up to the previous
/// version. A hand-written schema would drift from the migrations it stands in for,
/// and the drift would stay invisible until the day it mattered.
#[cfg(any(test, feature = "test-support"))]
pub fn migrate_through_for_test(store: &SqliteStore, version: u32) -> Result<(), StoreError> {
    if version >= SELECTOR_SCHEMA_VERSION {
        return EncryptedStore::migrate_inner(store, None, version);
    }
    let chain: Vec<Migration> = MIGRATIONS
        .iter()
        .copied()
        .filter(|migration| migration.version <= version)
        .collect();
    store.migrate(SCHEMA_NAMESPACE, &chain)?;
    Ok(())
}

fn migration_10_conversion(row: &Schema9GrantRow) -> Option<&'static Migration10Conversion> {
    MIGRATION_10_CONVERSION_TABLE.iter().find(|entry| {
        row.selector_kind == "prefix"
            && row.principal_kind == entry.principal_kind
            && row.principal_id == entry.principal_id
            && row.selector == entry.old_selector
            && row.operation == entry.operation.as_str()
    })
}

fn schema_9_covered_set(state: &Migration10State, row: &Schema9GrantRow) -> BTreeSet<String> {
    match row.selector_kind.as_str() {
        "prefix" => state
            .credential_ids
            .iter()
            .filter(|credential_id| credential_id.starts_with(&row.selector))
            .cloned()
            .collect(),
        "category" => {
            let category = row
                .selector
                .strip_prefix("category:")
                .unwrap_or(&row.selector);
            state
                .credential_ids
                .iter()
                .filter(|credential_id| {
                    state
                        .categories
                        .get(*credential_id)
                        .is_some_and(|categories| categories.contains(category))
                })
                .cloned()
                .collect()
        }
        _ => BTreeSet::new(),
    }
}

fn migration_10_plan(state: Migration10State) -> Result<Migration10Plan, StoreError> {
    let mut assignments = BTreeSet::new();
    for row in &state.grants {
        if let Some(Migration10Conversion {
            replacement:
                Migration10Replacement::Category {
                    selector,
                    assignments: ids,
                },
            ..
        }) = migration_10_conversion(row)
        {
            for credential_id in *ids {
                if state.credential_ids.contains(*credential_id) {
                    assignments.insert(((*credential_id).to_string(), (*selector).to_string()));
                }
            }
        }
    }

    let mut categories_after = state.categories.clone();
    for (credential_id, category) in &assignments {
        categories_after
            .entry(credential_id.clone())
            .or_default()
            .insert(category.clone());
    }

    let mut grants = Vec::with_capacity(state.grants.len());
    for row in &state.grants {
        let before = schema_9_covered_set(&state, row);
        let (selector_kind, selector) = match row.selector_kind.as_str() {
            "prefix" => match migration_10_conversion(row).map(|entry| entry.replacement) {
                Some(Migration10Replacement::Exact { selector }) => {
                    (SelectorKind::Exact.as_str(), selector.to_string())
                }
                Some(Migration10Replacement::Category { selector, .. }) => {
                    (SelectorKind::Category.as_str(), selector.to_string())
                }
                None if before.len() == 1 => (
                    SelectorKind::Exact.as_str(),
                    before.iter().next().expect("one prefix match").clone(),
                ),
                None => {
                    return Err(StoreError::Backend(format!(
                        "migration 10 refused prefix row {}: match set {:?}; expected exactly one credential",
                        row.label(),
                        before.iter().collect::<Vec<_>>()
                    )))
                }
            },
            "category" => (
                SelectorKind::Category.as_str(),
                row.selector
                    .strip_prefix("category:")
                    .unwrap_or(&row.selector)
                    .to_string(),
            ),
            other => {
                return Err(StoreError::Backend(format!(
                    "migration 10 refused row {}: unsupported schema-9 selector kind {other:?}",
                    row.label()
                )))
            }
        };

        let after: BTreeSet<String> = match selector_kind {
            "exact" => state
                .credential_ids
                .iter()
                .filter(|credential_id| credential_id.as_str() == selector)
                .cloned()
                .collect(),
            "category" => state
                .credential_ids
                .iter()
                .filter(|credential_id| {
                    categories_after
                        .get(*credential_id)
                        .is_some_and(|categories| categories.contains(&selector))
                })
                .cloned()
                .collect(),
            _ => unreachable!("the migration plan emits only schema-10 selector kinds"),
        };
        if before != after {
            let removed: Vec<&String> = before.difference(&after).collect();
            let added: Vec<&String> = after.difference(&before).collect();
            return Err(StoreError::Backend(format!(
                "migration 10 refused reach change for row {}: before covered set {:?}; after covered set {:?}; difference removed {:?}, added {:?}",
                row.label(),
                before.iter().collect::<Vec<_>>(),
                after.iter().collect::<Vec<_>>(),
                removed,
                added
            )));
        }

        grants.push(Migration10GrantPlanRow {
            principal_kind: row.principal_kind.clone(),
            principal_id: row.principal_id.clone(),
            selector_kind: selector_kind.to_string(),
            selector,
            operation: row.operation.clone(),
            created_at_ms: row.created_at_ms,
        });
    }

    Ok(Migration10Plan {
        grants,
        assignments: assignments.into_iter().collect(),
    })
}

fn load_migration_10_state(store: &SqliteStore) -> Result<Migration10State, StoreError> {
    store.with_conn(|conn| {
        let credential_ids = conn
            .prepare("SELECT credential_id FROM credentials ORDER BY credential_id")?
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<BTreeSet<_>>>()?;

        let mut categories = BTreeMap::<String, BTreeSet<String>>::new();
        let mut categories_stmt = conn.prepare(
            "SELECT credential_id, category FROM credential_categories ORDER BY credential_id, category",
        )?;
        for row in categories_stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })? {
            let (credential_id, category) = row?;
            categories.entry(credential_id).or_default().insert(category);
        }
        drop(categories_stmt);

        let mut grants_stmt = conn.prepare(
            "SELECT principal_kind, principal_id, selector_kind, credential_prefix, operation, created_at_ms \
             FROM read_grants ORDER BY principal_kind, principal_id, selector_kind, credential_prefix, operation",
        )?;
        let grants = grants_stmt
            .query_map([], |row| {
                Ok(Schema9GrantRow {
                    principal_kind: row.get(0)?,
                    principal_id: row.get(1)?,
                    selector_kind: row.get(2)?,
                    selector: row.get(3)?,
                    operation: row.get(4)?,
                    created_at_ms: row.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        Ok(Migration10State {
            credential_ids,
            categories,
            grants,
        })
    })
}

fn load_migration_10_audit_key(
    store: &SqliteStore,
    key: Option<&MasterKey>,
) -> Result<Zeroizing<[u8; 32]>, StoreError> {
    let Some(key) = key else {
        return Err(StoreError::Backend(
            "migration 10 refused: audit chain key unavailable; no category assignment was written"
                .to_string(),
        ));
    };
    let envelope_bytes: Option<Vec<u8>> = store.with_conn(|conn| {
        conn.query_row(
            "SELECT envelope FROM vault_secrets WHERE name = ?1",
            rusqlite::params![AUDIT_KEY_SECRET_NAME],
            |row| row.get(0),
        )
        .optional()
    })?;
    let Some(envelope_bytes) = envelope_bytes else {
        return Err(StoreError::Backend(
            "migration 10 refused: audit chain key unavailable; no category assignment was written"
                .to_string(),
        ));
    };
    let plaintext = envelope::open(
        key,
        &envelope_bytes,
        &RecordBinding {
            credential_id: AUDIT_KEY_SECRET_NAME,
            record_version: AUDIT_KEY_RECORD_VERSION,
        },
    )
    .map_err(|_| {
        StoreError::Backend(
            "migration 10 refused: audit chain key unavailable; no category assignment was written"
                .to_string(),
        )
    })?;
    let bytes: [u8; 32] = plaintext.as_slice().try_into().map_err(|_| {
        StoreError::Backend(
            "migration 10 refused: audit chain key is corrupt; no category assignment was written"
                .to_string(),
        )
    })?;
    Ok(Zeroizing::new(bytes))
}

pub(super) fn migration_category_targets(assignments: &[(String, String)]) -> Vec<String> {
    let mut grouped = std::collections::BTreeMap::<&str, Vec<&str>>::new();
    for (id, category) in assignments {
        grouped.entry(category).or_default().push(id);
    }
    grouped
        .into_iter()
        .map(|(category, ids)| format!("category:{category}|{}", ids.join(",")))
        .collect()
}

fn apply_migration_10(
    store: &SqliteStore,
    plan: &Migration10Plan,
    audit_key: Option<&[u8; 32]>,
) -> Result<(), StoreError> {
    store.with_conn(|conn| {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(
            "CREATE TEMP TABLE migration_10_grant_plan (\
                 principal_kind TEXT NOT NULL, principal_id TEXT NOT NULL, \
                 selector_kind TEXT NOT NULL, selector TEXT NOT NULL, \
                 operation TEXT NOT NULL, created_at_ms INTEGER NOT NULL\
             ); \
             CREATE TEMP TABLE migration_10_category_plan (\
                 credential_id TEXT NOT NULL, category TEXT NOT NULL\
             );",
        )?;
        for grant in &plan.grants {
            tx.execute(
                "INSERT INTO migration_10_grant_plan \
                 (principal_kind, principal_id, selector_kind, selector, operation, created_at_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    grant.principal_kind,
                    grant.principal_id,
                    grant.selector_kind,
                    grant.selector,
                    grant.operation,
                    grant.created_at_ms
                ],
            )?;
        }
        for (credential_id, category) in &plan.assignments {
            tx.execute(
                "INSERT INTO migration_10_category_plan (credential_id, category) VALUES (?1, ?2)",
                rusqlite::params![credential_id, category],
            )?;
        }

        let statements = MIGRATIONS
            .iter()
            .find(|migration| migration.version == SELECTOR_SCHEMA_VERSION)
            .expect("migration 10 is present")
            .statements;
        // The audit append belongs after the assignments but before the generation seed,
        // so split the declarative batch at the explicit Rust insertion boundary.
        let (before_generation, generation) = statements
            .split_once("/* Rust appends category.migrate before creating grants_generation. */")
            .expect("migration 10 carries its audit insertion marker");
        tx.execute_batch(before_generation)?;

        if !plan.assignments.is_empty() {
            let audit_key = audit_key.expect("an assignment plan requires a loaded audit key");
            for target in migration_category_targets(&plan.assignments) {
                append_audit_tx(
                    &tx,
                    audit_key,
                    &AuditRecord {
                        op: AuditOp::CategoryMigrate,
                        credential_id: Some(target),
                        payload_hash: None,
                        actor: "migration:10".to_string(),
                        alarm: None,
                    },
                )?;
            }
        }

        tx.execute_batch(generation)?;
        tx.execute(
            "INSERT INTO cortexkit_schema_version (namespace, version, applied_at_unix) \
             VALUES (?1, ?2, ?3)",
            rusqlite::params![SCHEMA_NAMESPACE, SELECTOR_SCHEMA_VERSION, now_ms() / 1_000],
        )?;
        tx.execute_batch(
            "DROP TABLE migration_10_grant_plan; DROP TABLE migration_10_category_plan;",
        )?;
        tx.commit()?;
        Ok(())
    })
}

/// Refuse a store whose recorded schema is newer than the binary's own chain.
///
/// `binary_newest` is the newest migration the running binary knows: production
/// passes [`newest_migration_version`]. It is a parameter so a test can run the exact
/// check a release-1 binary runs (its newest was [`VAULT_RELEASE_1_SCHEMA_VERSION`])
/// against a store this binary migrated.
pub(super) fn refuse_store_ahead_of_binary(
    recorded: u32,
    binary_newest: u32,
) -> Result<(), StoreError> {
    if recorded <= binary_newest {
        return Ok(());
    }
    let who = std::env::current_exe()
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "this binary".to_string());
    Err(StoreError::Backend(format!(
        "{who}: store schema {recorded} is newer than this binary's {binary_newest} -- refusing to serve. This binary predates migrations already applied to this vault; one of them rebuilt a table, so writes would fail later rather than now. Roll {who} forward to a binary at or above {recorded}, or restore the store from the backup that matches it. If ck-auth and ck-claustrum were built separately they can carry different chains -- rebuild both from one revision."
    )))
}

/// Read the vault's recorded schema version from a connection that may be read-only.
///
/// `MAX(version)` over this namespace's rows, or 0 when the namespace has no rows. A
/// file with no version table at all is not a vault; it reports 0 so the caller takes
/// the pre-9 path and the missing `credentials` table is what it reports, exactly as
/// before this check existed.
///
/// *** THE TOLERANCE THIS ENABLES IS FOR THE PLACEMENT WINDOW, NOT A GENERAL
/// OLD-STORE READER. *** A CLI-only change is placed first and the daemon, which
/// migrates, is restarted later, so between the two every offline read meets a store
/// exactly ONE migration behind. That is the case the readers below handle. A store
/// two or more migrations behind (schema 7 or lower) is out of scope and may fail as
/// it did before: the pre-9 shape is read, and nothing promises that the columns the
/// migrations between that store and 9 added are present.
pub(super) fn read_schema_version(conn: &rusqlite::Connection) -> rusqlite::Result<u32> {
    let version: Option<i64> = conn
        .query_row(
            "SELECT MAX(version) FROM cortexkit_schema_version WHERE namespace = ?1",
            rusqlite::params![SCHEMA_NAMESPACE],
            |row| row.get(0),
        )
        .or_else(|error| match error {
            rusqlite::Error::SqliteFailure(_, Some(ref message))
                if message.contains("no such table") =>
            {
                Ok(None)
            }
            other => Err(other),
        })?;
    Ok(version.unwrap_or(0).max(0) as u32)
}

impl EncryptedStore {
    /// Apply the vault schema migrations to a freshly opened store and set the
    /// vault's durability level. Idempotent. Call once, right after opening, before
    /// any credential write.
    ///
    /// Sets `PRAGMA synchronous=FULL` on the store's connection: the vault's SQLite
    /// IS its own source of truth, so it must fsync every commit.
    ///
    /// The consequence rather than the adjective, because a severity word travels
    /// unchecked while an observable does not: a provider that ROTATES its refresh token
    /// hands back a new one and kills the old in the same exchange. If the commit
    /// recording the new token is lost to power failure, the vault holds a token the
    /// provider has already retired and there is no second copy anywhere -- the
    /// credential is dead until an operator re-authenticates it interactively. This is stronger than WAL's default
    /// `synchronous=NORMAL` (which can lose the last transaction on power loss) and
    /// is set vault-locally rather than in `cortexkit-store`, because the other
    /// consumers hold rebuildable projections that are correct at NORMAL and should
    /// not pay FULL's fsync-per-commit. `SqliteStore` is one connection behind a
    /// mutex, so setting it once here covers every later `with_conn`/
    /// `with_conn_fenced` call.
    /// Read the database's recorded master-key fingerprint WITHOUT the master key:
    /// the plaintext `key_id` of the sealed audit-key row (which always exists from
    /// vault-init). This is the crash-safe-resolve anchor — the resolver compares it
    /// to each key-store slot's fingerprint to pick the slot the database is actually
    /// sealed under (see [`resolver::resolve_for_db`]). `None` on a brand-new vault
    /// whose audit-key row does not exist yet (then `Current` is the only candidate).
    pub fn read_db_key_id(store: &SqliteStore) -> Result<Option<KeyId>, StoreError> {
        let hex: Option<String> = store
            .with_conn(|c| {
                c.query_row(
                    "SELECT key_id FROM vault_secrets WHERE name = ?1",
                    rusqlite::params![AUDIT_KEY_SECRET_NAME],
                    |r| r.get::<_, String>(0),
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    rusqlite::Error::SqliteFailure(_, Some(ref message))
                        if message.contains("no such table: vault_secrets") =>
                    {
                        Ok(None)
                    }
                    other => Err(other),
                })
            })
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        // Distinguish "no row" (a brand-new vault, resolve against `Current`) from "row
        // present but its fingerprint is unparseable" (a corrupt anchor). The old code
        // collapsed both to `None`, which would silently downgrade a corrupt anchor into
        // the bootstrap path and could open a mismatched key. A present-but-invalid
        // fingerprint fails closed as a corrupt store instead.
        match hex {
            None => Ok(None),
            Some(h) => KeyId::from_hex(&h).map(Some).ok_or_else(|| {
                StoreError::Backend(format!(
                    "vault_secrets audit-key row has an invalid key_id fingerprint '{h}' \
                     (corrupt anchor)"
                ))
            }),
        }
    }

    /// Apply the schema chain and refuse a store newer than this binary.
    ///
    /// Migration 10 is planned in Rust before its transaction starts because selector
    /// conversion must be total and reach preserving. Call [`Self::migrate_with_key`]
    /// when the schema-9 store contains the category backfill: its audit entry cannot be
    /// written without first decrypting the existing chain key.
    pub fn migrate(store: &SqliteStore) -> Result<(), StoreError> {
        Self::migrate_inner(store, None, newest_migration_version())
    }

    /// Apply the schema chain with the master key available for migration 10's single
    /// `category.migrate` chain entry.
    pub fn migrate_with_key(store: &SqliteStore, key: &MasterKey) -> Result<(), StoreError> {
        Self::migrate_inner(store, Some(key), newest_migration_version())
    }

    fn migrate_inner(
        store: &SqliteStore,
        key: Option<&MasterKey>,
        target: u32,
    ) -> Result<(), StoreError> {
        let recorded = store.with_conn(read_schema_version)?;
        refuse_store_ahead_of_binary(recorded, newest_migration_version())?;

        // Migration 9 reserves lowercase `category:` byte-for-byte. SQLite LIKE is
        // case-insensitive for ASCII by default, so the predicate stays in Rust.
        if recorded < CATEGORY_SCHEMA_VERSION {
            let offending_ids = store.with_conn(|conn| {
                if !table_exists(conn, "credentials")? {
                    return Ok(Vec::new());
                }
                let mut stmt =
                    conn.prepare("SELECT credential_id FROM credentials ORDER BY credential_id")?;
                let ids = stmt
                    .query_map([], |row| row.get::<_, String>(0))?
                    .filter_map(|id| match id {
                        Ok(id) if id.starts_with("category:") => Some(Ok(id)),
                        Ok(_) => None,
                        Err(error) => Some(Err(error)),
                    })
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(ids)
            })?;
            if !offending_ids.is_empty() {
                return Err(StoreError::Backend(format!(
                    "migration 9 refused reserved credential ids: {}",
                    offending_ids.join(", ")
                )));
            }
        }

        // The shared runner applies the declarative chain through schema 9. Migration
        // 10 is run below in one custom transaction so its computed grant plan, category
        // assignments, audit append, DDL, and version row either all commit or none do.
        if recorded < CATEGORY_SCHEMA_VERSION {
            let before_selector: Vec<Migration> = MIGRATIONS
                .iter()
                .copied()
                .filter(|migration| migration.version < SELECTOR_SCHEMA_VERSION)
                .collect();
            store.migrate(SCHEMA_NAMESPACE, &before_selector)?;
        }

        let recorded = store.with_conn(read_schema_version)?;
        if recorded < SELECTOR_SCHEMA_VERSION {
            // Every existing credential is dated from its own chain birth row. The
            // declarative runner cannot refuse with the offending ids, so establish
            // totality before the migration transaction starts.
            let undatable_ids = store.with_conn(|conn| {
                if !table_exists(conn, "credentials")? {
                    return Ok(Vec::new());
                }
                let birth_ops = CHAIN_BIRTH_OPS
                    .iter()
                    .map(|op| format!("'{op}'"))
                    .collect::<Vec<_>>()
                    .join(", ");
                let mut stmt = conn.prepare(&format!(
                    "SELECT credential_id FROM credentials WHERE credential_id NOT IN (\
                         SELECT credential_id FROM audit_log \
                          WHERE credential_id IS NOT NULL AND op IN ({birth_ops})\
                     ) ORDER BY credential_id"
                ))?;
                let ids = stmt
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(ids)
            })?;
            if !undatable_ids.is_empty() {
                return Err(StoreError::Backend(format!(
                    "migration 10 refused: {} credential(s) have no birth row in the audit chain, so their creation time cannot be derived: {}. A birth row is the earliest audit entry naming the credential with op in [{}]. The store is untouched and still at schema {recorded}; restore the chain that dates these credentials, or remove them, and migrate again.",
                    undatable_ids.len(),
                    undatable_ids.join(", "),
                    CHAIN_BIRTH_OPS.join(", "),
                )));
            }

            let plan = migration_10_plan(load_migration_10_state(store)?)?;
            let audit_key = if plan.assignments.is_empty() {
                None
            } else {
                Some(load_migration_10_audit_key(store, key)?)
            };
            apply_migration_10(store, &plan, audit_key.as_deref())?;
        }

        // Every migration after 10 is declarative again, so the shared runner applies
        // them through `target`; it skips any the store has already recorded.
        let after_selector = MIGRATIONS
            .iter()
            .copied()
            .filter(|m| m.version > SELECTOR_SCHEMA_VERSION && m.version <= target)
            .collect::<Vec<_>>();
        if !after_selector.is_empty() {
            store.migrate(SCHEMA_NAMESPACE, &after_selector)?;
        }

        store
            .with_conn(|conn| conn.pragma_update(None, "synchronous", "FULL"))
            .map_err(|error| StoreError::Backend(error.to_string()))
    }
}
