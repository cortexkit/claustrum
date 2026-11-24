//! Tests for the encrypted store.

use crate::test_support::TestTempDir;
/// AFTER EXPIRY THE SAME SECRET STARTS A FRESH REQUEST, WITH A NEW ID.
///
/// A fresh request falls out of the mechanism rather than being chosen: the sweep
/// moves the row to `expired`, the resume lookup matches only `state = 'pending'`, and
/// the name check counts only `pending`/`approved` -- so an expired row blocks nothing
/// and hides nothing.
///
/// It is also the behaviour a consumer wants. Expiry means the operator never
/// approved; a terminal outcome would tell a consumer to stop asking for something
/// nobody refused, and the remedy would be an operator deleting a row. A fresh
/// proposal costs one queue slot and reaches the operator again.
///
/// THE ID MUST CHANGE. Reusing the expired id would make a stale poll from before the
/// expiry -- the consumer may still be looping on it -- silently attach to the new
/// request, so a crash-and-retry would look like an approval of something the
/// operator saw once and let lapse.
#[test]
fn after_expiry_the_same_secret_starts_a_fresh_request() {
    let (_root, store) = tmp_store(0x7a);
    let secret = "d".repeat(64);
    let t0 = 1_000_000_i64;

    let first = store
        .propose_enrollment_at("expiry-probe", &secret, t0)
        .expect("first propose");

    let after = t0 + ENROLLMENT_PENDING_TTL_MS + 1;
    let second = store
        .propose_enrollment_at("expiry-probe", &secret, after)
        .expect("an expired pending row must not block a fresh proposal");

    assert_ne!(
        second.request_id, first.request_id,
        "a fresh request must get a FRESH id: reusing it would let a stale poll from \
             before the expiry attach to the new request"
    );
}

/// A CRASHED PROPOSER RESUMES; A SQUATTER DOES NOT.
///
/// `request_id` is minted server-side and returned, so a consumer CANNOT persist it
/// before proposing. A crash in the window between the row committing and the
/// consumer writing the id down left it holding a secret it could not poll with, and
/// the name held until TTL -- and the obvious retry then hit `pending_exists`,
/// wedging the consumer out of its own enrollment with its own earlier attempt.
///
/// Both arms are load-bearing and they pull in opposite directions. Without the
/// RESUME arm, a plain refusal passes and the crash gap stays. Without the SQUATTER
/// arm, resuming on the name alone passes -- and that is strictly worse than the
/// original defect, because it hands any local process the pending enrollment of a
/// name it merely guessed.
///
/// The secret is the right discriminator because the consumer mints it in-process and
/// sends only its hash: possession of the matching hash is evidence of being the same
/// caller, where the name is public by construction.
#[test]
fn a_crashed_proposer_resumes_with_its_secret_and_a_stranger_does_not() {
    let (_root, store) = tmp_store(0x79);
    let mine = "a".repeat(64);
    let theirs = "b".repeat(64);

    let first = store
        .propose_enrollment("resume-probe", &mine)
        .expect("first propose");

    // THE RESUME. Same name, same secret: the id must be the SAME one, not a second
    // id for one pending row -- re-minting would leave the first unreachable and
    // still holding the name, turning the fix into a second leak.
    let again = store
        .propose_enrollment("resume-probe", &mine)
        .expect("a crashed proposer must be able to resume");
    assert_eq!(
        again.request_id, first.request_id,
        "resuming must return the ORIGINAL request id"
    );

    // THE SQUATTER. Same name, different secret: refused.
    let err = store
        .propose_enrollment("resume-probe", &theirs)
        .expect_err("a different secret is a different caller and must be refused");
    assert!(
        matches!(
            err,
            EnrollmentError::Refused(EnrollmentRefusal::PendingExists)
        ),
        "a stranger guessing the name must still be refused, got {err:?}"
    );
}

/// A SCOPED FIRST USE IS RECORDED ONCE, NOT PER CALL.
///
/// The idempotence is the whole design, and the reason is EVICTION rather than
/// growth: `auth_events` trims to the newest 64 rows per credential, so a per-call
/// success row would push out the refusal rows that answer why something stopped
/// working. The least interesting row would evict the most interesting.
///
/// Both arms are load-bearing and fail differently. Without the FIRST arm, a method
/// that writes nothing at all passes -- and writing nothing is the status quo this
/// exists to change. Without the REPEAT arm, a plain INSERT passes, which is the
/// defect: 467 calls a day against one credential would clear the table's forensic
/// window in hours.
#[test]
fn a_scoped_first_use_is_recorded_once_however_many_times_it_is_exercised() {
    let (_root, store) = tmp_store(0x77);
    let id = "apikey:first-use-probe";
    let record = VaultRecord::new_static(CredentialKind::ApiKey, "test", b"k".to_vec(), None);
    store
        .create_audited(id, &record, AuditCtx::admin(AuditOp::Put))
        .expect("seed");

    let count = |op: &str| -> i64 {
        store
            .recent_auth_events(256)
            .expect("events")
            .iter()
            .filter(|e| {
                e.credential_id == id
                    && e.kind == AuthEventKind::ScopedFirstUse.as_str()
                    && e.detail.as_deref() == Some(op)
            })
            .count() as i64
    };

    assert_eq!(count("read"), 0, "nothing exercised it yet");
    for _ in 0..25 {
        store
            .record_scoped_first_use(id, "reserved", Some("probe"), GrantOperation::Read)
            .expect("record");
    }
    assert_eq!(
        count("read"),
        1,
        "twenty-five exercises must leave ONE row: a per-call row would evict the \
             refusal rows this table exists to keep"
    );

    // A DIFFERENT OPERATION IS A DIFFERENT FACT. `read` and `sign` are separate
    // authorities, so "this principal has ever read it" does not answer "has it ever
    // signed with it", and collapsing them would hide the stronger one.
    store
        .record_scoped_first_use(id, "reserved", Some("probe"), GrantOperation::Sign)
        .expect("record sign");
    assert_eq!(count("sign"), 1);
    assert_eq!(
        count("read"),
        1,
        "the sign row must not disturb the read row"
    );

    // A DIFFERENT PRINCIPAL IS ALSO A DIFFERENT FACT, and this is the arm that
    // catches a dedup keyed on the credential alone -- which would make the second
    // consumer's first use invisible forever.
    store
        .record_scoped_first_use(id, "enrolled", Some("other"), GrantOperation::Read)
        .expect("record other");
    assert_eq!(
        count("read"),
        2,
        "a second principal's first use is its own fact, not a duplicate of the first"
    );
}

#[test]
fn repeated_scoped_first_use_makes_no_attempt_to_acquire_the_writer() {
    thread_local! {
        static WRITER_CONTENTION: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    let (root, store) = tmp_store(0x77);
    let id = "apikey:first-use-probe";
    store
        .record_scoped_first_use(id, "direct", None, GrantOperation::Read)
        .unwrap();
    let mut writer = rusqlite::Connection::open(root.join("store.db")).unwrap();
    let reservation = writer
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    store
        .with_raw_conn(|conn| {
            conn.busy_handler(Some(|_| {
                WRITER_CONTENTION.with(|count| count.set(count.get() + 1));
                false
            }))
        })
        .unwrap();

    // A first use for a different operation is a write and must hit the reservation.
    assert!(store
        .record_scoped_first_use(id, "direct", None, GrantOperation::Sign)
        .is_err());
    assert_eq!(WRITER_CONTENTION.with(|count| count.replace(0)), 1);
    for _ in 0..4 {
        store
            .record_scoped_first_use(id, "direct", None, GrantOperation::Read)
            .expect("a repeated use does not need the writer");
    }
    assert_eq!(WRITER_CONTENTION.with(std::cell::Cell::get), 0);
    assert_eq!(store.recent_auth_events(5).unwrap().len(), 1);
    reservation.rollback().unwrap();
}

/// The scrub shape leaves a WRITABLE store, which was the one claim in the restore
/// contract I had only read at source rather than exercised.
///
/// The contract says a restored copy must have `cortexkit_fence` rows deleted, because
/// the epoch belongs to the captured machine's lease lifetime and an inherited one that
/// outruns the destination's counter refuses every write while the health detail blames
/// a newer writer that does not exist.
///
/// So the scrub had better not break writing on its own. cortexkit-store reads
/// `COALESCE((SELECT epoch FROM cortexkit_fence WHERE id = 0), 0)`, so an EMPTY table
/// yields 0 and any holder epoch claims it -- but that is a sibling crate's line, and a
/// property this repo depends on deserves a test here rather than a citation.
///
/// Note what the assertion is: the write COMMITS and the record READS BACK. Asserting
/// only that the call returned Ok would pass against a fence that silently swallowed
/// the write, which is the failure this table exists to prevent.
///
/// WHAT THIS TEST DOES NOT COVER: a real daemon opening a scrubbed store at the
/// canonical data dir. The master key is scoped to that path, so a scratch placement
/// refuses by name before any of this runs: the master key and the store are separate
/// files, and the key is tied to the store's path, so neither works alone. This
/// exercises the store layer only, and the placement remains an operator action.
#[test]
fn a_fence_scrubbed_store_still_commits_writes() {
    let (_root, store) = tmp_store(0x5c);
    let id = "apikey:scrub-probe";
    let before = VaultRecord::new_static(CredentialKind::ApiKey, "test", b"before".to_vec(), None);
    store
        .create_audited(id, &before, AuditCtx::admin(AuditOp::Put))
        .expect("seed the store before the scrub");

    // The scrub. EITHER FORM IS SAFE, and finding that out is why this test exists.
    //
    // I sent the backup owner a "correction" saying DELETE FROM and DROP TABLE differ
    // -- that a dropped table makes the fence SELECT fail to prepare and kills every
    // write. Measured with the sqlite3 CLI against the file, which is true of the FILE
    // and false of the STORE: `with_conn_fenced` opens every fenced write with
    // `CREATE TABLE IF NOT EXISTS cortexkit_fence` INSIDE the transaction, so the table
    // is repaired before the epoch is read and the two forms converge.
    //
    // Mutation result, recorded because the test reads as if it depended on the
    // distinction: swapping DELETE FROM for DROP TABLE leaves this test GREEN. That is
    // not a gap -- the property under test is "the scrub leaves a writable store", and
    // it holds for both. Instrumented at the time: table gone right after the drop,
    // write committed and read back, epoch > 0 afterwards.
    let removed = store
        .with_raw_conn(|c| c.execute("DELETE FROM cortexkit_fence", []))
        .expect("scrub the fence rows");
    assert!(
        removed > 0,
        "the fixture must HAVE a fence row before the scrub, or this test proves \
             nothing about deleting one"
    );

    // A write after the scrub must commit AND be readable back.
    let after = VaultRecord::new_static(CredentialKind::ApiKey, "test", b"after".to_vec(), None);
    store
        .create_audited(
            "apikey:scrub-probe-2",
            &after,
            AuditCtx::admin(AuditOp::Put),
        )
        .expect("a fence-scrubbed store must still accept writes");
    let got = store
        .get("apikey:scrub-probe-2")
        .expect("the post-scrub write must read back");
    assert_eq!(
        got.payload.expose(),
        b"after",
        "the write committed rather than being swallowed by the fence path"
    );

    // And the epoch is re-claimed rather than left absent, so the next writer inherits
    // a real fence rather than starting from nothing again.
    let epoch: i64 = store
        .with_raw_conn(|c| {
            c.query_row(
                "SELECT COALESCE((SELECT epoch FROM cortexkit_fence WHERE id = 0), 0)",
                [],
                |r| r.get(0),
            )
        })
        .expect("read the fence back");
    assert!(
        epoch > 0,
        "the first write after a scrub must re-claim the fence, not leave it empty"
    );
}

/// A scratch database path under the same temp-dir idiom the rest of this module
/// uses: pid plus a counter, so parallel test threads cannot collide and a recycled
/// pid on windows cannot inherit a previous run's directory.
fn scratch_db(label: &str) -> (TestTempDir, std::path::PathBuf) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let root = TestTempDir::new(format!(
        "ck-restore-{}-{}-{}",
        label,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let path = root.join("store.db");
    (root, path)
}

#[test]
fn offline_readers_accept_literal_uri_characters_and_see_the_live_wal() {
    let (root, _) = scratch_db("literal-path");
    for folder in ["vault#daily", "vault%20daily"] {
        let path = root.join(folder).join("store.db");
        std::fs::create_dir(path.parent().unwrap()).unwrap();
        let store = store_at(&path, 0x77);
        store
            .with_raw_conn(|conn| {
                conn.execute_batch("PRAGMA wal_autocheckpoint=0; PRAGMA wal_checkpoint(TRUNCATE);")
            })
            .unwrap();
        let id = "apikey:offline-wal-probe";
        let record =
            VaultRecord::new_static(CredentialKind::ApiKey, "test", b"dummy".to_vec(), None);
        store
            .create_audited(id, &record, AuditCtx::admin(AuditOp::Put))
            .unwrap();
        store.open_intent(id, 1, "dummy-hash").unwrap();

        let (rows, _) =
            list_meta_read_only_with_schema(&path).expect("read live store by literal path");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, id);
        assert_eq!(count_refresh_intents_read_only(&path).unwrap(), 1);
        assert_eq!(
            verify_audit_chain_read_only(&path, &MasterKey::from_bytes([0x77; MASTER_KEY_LEN]))
                .unwrap(),
            None
        );
    }
}

#[test]
fn restore_report_accepts_a_literal_hash_and_percent_in_the_copy_path() {
    let (root, source) = scratch_db("restore-literal-path");
    {
        let conn = rusqlite::Connection::open(&source).unwrap();
        conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        conn.execute_batch(
            "CREATE TABLE handles (revoked INTEGER);
             CREATE TABLE refresh_intent (credential_id TEXT);
             CREATE TABLE read_grants (principal_id TEXT);
             INSERT INTO handles VALUES (0);",
        )
        .unwrap();
    }
    let dir = root.join("vault#daily%20x");
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("store.db");
    std::fs::copy(source, &path).unwrap();
    assert!(!dir.join("store.db-wal").exists());
    let report =
        restore_resurrection_read_only(&path).expect("read the restored copy by literal path");
    assert_eq!(report.live_handles, 1);
}

/// The restore report answers on a file the house read-only form CANNOT open.
///
/// A restored store carries a WAL-mode header with no `-wal` companion, and every
/// other read-only helper here uses `?mode=ro`, which refuses exactly that with
/// SQLite error 14. So this asserts BOTH arms: mode=ro fails on the artifact, and the
/// report succeeds on it. Testing only the success arm would pass against an ordinary
/// store and never exercise the reason the function opens differently.
#[test]
fn the_restore_report_reads_a_wal_header_with_no_sidecar() {
    let (_root, path) = scratch_db("restored");
    {
        let c = rusqlite::Connection::open(&path).expect("create");
        c.pragma_update(None, "journal_mode", "WAL").expect("wal");
        c.execute_batch(
            "CREATE TABLE handles (handle_hash TEXT, revoked INTEGER);
                 CREATE TABLE refresh_intent (credential_id TEXT);
                 CREATE TABLE read_grants (principal_id TEXT);
                 CREATE TABLE cortexkit_fence (epoch INTEGER);
                 INSERT INTO handles VALUES ('a', 0), ('b', 0), ('c', 1);
                 INSERT INTO refresh_intent VALUES ('oauth:x');
                 INSERT INTO read_grants VALUES ('p');
                 INSERT INTO cortexkit_fence VALUES (227);",
        )
        .expect("seed");
        // NO checkpoint. A TRUNCATE checkpoint rewrites the header back to (1,1) =
        // rollback, and the fixture then opens under mode=ro and proves nothing --
        // which is exactly what the first version of this test did. The artifact
        // under test is a file whose header still says WAL (2,2) while its `-wal` is
        // gone, and that is what engram's online-backup output actually is: verified
        // against a real captured generation, header bytes 18/19 = 2,2, mode=ro
        // refusing it with SQLite error 14.
    }
    // Drop the companions WITHOUT checkpointing, which is how a restored file arrives.
    drop(std::fs::remove_file(format!("{}-wal", path.display())));
    drop(std::fs::remove_file(format!("{}-shm", path.display())));

    // *** WHY `immutable=1` RATHER THAN THE HOUSE `?mode=ro`, RESOLVED. ***
    //
    // The honest answer is a property of the OPENER, not of the file, and it took a
    // wrong turn to find: a restored copy refuses mode=ro with SQLite error 14 under
    // the sqlite3 CLI (3.54.0) and SILENTLY SUCCEEDS under the sqlite rusqlite links
    // here (3.46.0). Measured both ways on the same bytes.
    //
    // I first read that as two different FILES -- my fixture "opened anyway" while a
    // real restored artifact refused -- and recorded the difference as unexplained. I
    // had two files and one opener, and concluded the files differed, inside a
    // comparison whose entire purpose was to isolate a difference. A hand-made WAL
    // database with its companions removed refuses identically once opened through
    // the same library.
    //
    // SO THE DURABLE PROPERTY IS THE POSITIVE ONE, and it is what this test asserts:
    // `immutable=1` reads a restored copy correctly under BOTH libraries, while
    // mode=ro's behaviour flipped between them. Asserting the refusal would pin a
    // library version's mood rather than anything about the vault.
    //
    // AND THE DISJUNCTION THAT LOOKS RIGHT IS ALSO WRONG, which is worth recording
    // because it is the natural next idea: "without immutable the copy is either
    // refused OR reports fewer rows" fails on the real artifact, where both forms
    // return 127. The backup API produces a file complete at the reader's end mark,
    // so there is no uncheckpointed tail for the older library to miss. That
    // disjunction holds for a MID-WRITE copy and not for a captured one -- same
    // shape, different provenance.

    // ARM 2: the report reads it, and reports the REVOKED handle as not resurrected.
    // Print the linked version with the evidence: the two behaviours above are
    // indistinguishable in a test log without it, so a future reader debugging this
    // cannot tell which one they are looking at.
    let linked: String = rusqlite::Connection::open_in_memory()
        .expect("mem")
        .query_row("SELECT sqlite_version()", [], |r| r.get(0))
        .expect("version");
    println!("linked sqlite {linked}");

    let r = restore_resurrection_read_only(&path).expect("report must read it");
    assert_eq!(
        r.live_handles, 2,
        "only unrevoked handles are resurrected: 3 rows, 1 revoked"
    );
    assert_eq!(r.open_intents, 1, "the dangling intent must be counted");
    assert_eq!(r.read_grants, 1);
    assert_eq!(
        r.fence_epoch,
        Some(227),
        "the fence epoch is what a restoring machine would inherit"
    );
}

/// A missing fence table reports ABSENT, never zero.
///
/// Zero would tell an operator the placement is fence-safe when nothing was read --
/// the same shape as a health snapshot reporting 0 credentials for an unreadable
/// store, which this repo already fixed once by omitting the counts instead.
#[test]
fn a_missing_fence_table_is_absent_rather_than_zero() {
    let (_root, path) = scratch_db("nofence");
    {
        let c = rusqlite::Connection::open(&path).expect("create");
        c.execute_batch(
            "CREATE TABLE handles (handle_hash TEXT, revoked INTEGER);
                 CREATE TABLE refresh_intent (credential_id TEXT);
                 CREATE TABLE read_grants (principal_id TEXT);",
        )
        .expect("seed");
    }
    let r = restore_resurrection_read_only(&path).expect("report");
    assert_eq!(
        r.fence_epoch, None,
        "no fence table means no epoch to inherit, which is not an epoch of 0"
    );
}
/// The ONLINE grant listing orders and separates rows the same way the offline one
/// does. Both feed the same rendered table, so a divergence would show as an
/// operator seeing different output depending on whether a daemon happened to be
/// running -- with nothing in either report saying which path answered.
///
/// *** THIS EXISTS BECAUSE THE STANDING MUTATION ARM WENT INERT AND SAID SO. ***
/// `ck auth grants` used to reach `list_read_grants` on every invocation; the
/// lease-free read verbs (b4dc8ff) gave it `list_read_grants_read_only` when no
/// daemon is reachable, which is what the CLI test exercises. The release gate's arm
/// mutates THIS function, so from that commit its mutant was behaviourally inert:
/// the named test passed with the defect installed, and the arm reported "expected
/// to redden, but it passed" rather than a false green.
///
/// The lesson is about the SHAPE rather than this function: adding a second path to
/// a behaviour does not split its coverage evenly -- it moves the test to one side
/// and leaves the other bare, and nothing about the passing suite says which side
/// the test landed on.
#[test]
fn the_online_grant_listing_keeps_read_and_sign_separate_and_orders_by_prefix() {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let root = TestTempDir::new(format!(
        "ck-grantorder-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let db = root.join("store.db");
    let descriptor = StorageDescriptor {
        module_id: "cortexkit-credentials".into(),
        storage_namespace: "vault".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: db.to_string_lossy().into_owned(),
        },
    };
    let sqlite = open_sqlite(&descriptor).expect("open");
    EncryptedStore::migrate(&sqlite).expect("migrate");
    let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([9u8; 32])).expect("store");

    for (prefix, op) in [
        ("z:", GrantOperation::Sign),
        ("z:", GrantOperation::Read),
        ("a:", GrantOperation::Sign),
    ] {
        store
            .create_read_grant_audited(
                "reserved",
                "agent",
                SelectorKind::Exact,
                prefix,
                op,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("create grant");
    }

    let listed = store.list_read_grants().expect("list");
    let seen: Vec<(String, String)> = listed
        .iter()
        .map(|g| (g.selector.clone(), g.operation.as_str().to_string()))
        .collect();

    assert_eq!(
        seen,
        vec![
            ("a:".to_string(), "sign".to_string()),
            ("z:".to_string(), "read".to_string()),
            ("z:".to_string(), "sign".to_string()),
        ],
        "every grant needs its own row, ordered by selector then operation; collapsing \
             read and sign hides half an authority set from the operator reading it"
    );
    let bytes = seen
        .iter()
        .map(|(selector, op)| format!("{selector} {op}\n"))
        .collect::<String>();
    assert_eq!(
        bytes.as_bytes(),
        b"a: sign\nz: read\nz: sign\n",
        "read/sign output remains byte-identical"
    );
    let _ = std::fs::remove_dir_all(root);
}

/// A store carrying a migration this binary does not have must refuse to open.
///
/// Simulates the rollback shape directly: apply the real chain, then record a higher
/// version in the migrator's own ledger -- what a newer binary would have left
/// behind. `migrate` must then fail and must NAME BOTH VERSIONS, because the
/// operator's next decision (roll forward, or restore the matching store) needs the
/// target rather than only the complaint.
#[test]
fn a_store_ahead_of_this_binary_refuses_to_migrate() {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let root = TestTempDir::new(format!(
        "ck-cred-ahead-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let db = root.join("store.db");
    let descriptor = StorageDescriptor {
        module_id: "cortexkit-credentials".into(),
        storage_namespace: "vault".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: db.to_string_lossy().into_owned(),
        },
    };
    let store = open_sqlite(&descriptor).expect("open");
    EncryptedStore::migrate(&store).expect("first migrate applies the real chain");

    let ahead = newest_migration_version() + 1;
    store
        .with_conn(|c| {
            c.execute(
                "INSERT INTO cortexkit_schema_version (namespace, version, applied_at_unix) \
                     VALUES (?1, ?2, 0)",
                rusqlite::params![SCHEMA_NAMESPACE, ahead],
            )
        })
        .expect("record a migration this binary does not have");

    let err =
        EncryptedStore::migrate(&store).expect_err("a store ahead of this binary must refuse");
    let rendered = err.to_string();
    assert!(
        rendered.contains(&ahead.to_string())
            && rendered.contains(&newest_migration_version().to_string()),
        "the refusal must name BOTH versions so the operator knows the target: {rendered}"
    );
    // AND WHICH BINARY IS BEHIND. Two artifacts open this store and each carries
    // its own chain, so the ordinary cause is that they were built at different
    // times. A consumer hit exactly that on 2026-09-19 -- ck-auth rebuilt hours
    // after ck-claustrum -- and read the refusal as a vault defect, because
    // "roll forward" cannot be acted on without knowing what to roll.
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .expect("a test binary has a name");
    assert!(
        rendered.contains(&exe),
        "the refusal must name the running executable ({exe}), or the operator \
             cannot tell which of ck-auth and ck-claustrum is behind: {rendered}"
    );
    assert!(
        rendered.contains("ck-auth") && rendered.contains("ck-claustrum"),
        "the refusal must name both artifacts, since the fix is to rebuild them \
             from one revision: {rendered}"
    );
    let _ = std::fs::remove_dir_all(root);
}

use super::*;
use crate::key::MASTER_KEY_LEN;
use crate::oauth::OAuthCredential;
use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};

fn tmp_store(seed: u8) -> (TestTempDir, EncryptedStore) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let root = TestTempDir::new(format!(
        "ck-cred-store-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let store = store_at(&root.join("store.db"), seed);
    (root, store)
}

fn store_at(db: &std::path::Path, seed: u8) -> EncryptedStore {
    let descriptor = StorageDescriptor {
        module_id: "cortexkit-credentials".into(),
        storage_namespace: "vault".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: db.to_string_lossy().into_owned(),
        },
    };
    let store = open_sqlite(&descriptor).expect("open");
    EncryptedStore::migrate(&store).expect("migrate");
    let key = MasterKey::from_bytes([seed; MASTER_KEY_LEN]);
    EncryptedStore::open(store, key).expect("open vault")
}

// An authorizer belongs to one SQLite connection. Statements prepared on a
// pooled reader therefore cannot increment this writer-only count.
fn writer_selects(store: &EncryptedStore) -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    let count = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&count);
    store
        .with_raw_conn(|conn| {
            conn.authorizer(Some(move |context: AuthContext<'_>| {
                if matches!(context.action, AuthAction::Select) {
                    observed.fetch_add(1, Ordering::Relaxed);
                }
                Authorization::Allow
            }));
            Ok(())
        })
        .unwrap();
    count
}

#[test]
fn public_read_snapshots_issue_no_selects_on_the_writer() {
    let (_root, store) = tmp_store(0x79);
    let id = "apikey:read-pool";
    let record = VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None);
    store.create(id, &record).unwrap();
    let handle = mint_handle().unwrap();
    store
        .put_handle_hash(&handle.hash, id, AuditCtx::admin(AuditOp::MintHandle))
        .unwrap();
    store
        .create_read_grant_audited(
            "reserved",
            "consumer",
            SelectorKind::Exact,
            id,
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    let selects = writer_selects(&store);
    let declared = DeclaredGrantSet::empty();

    assert_eq!(store.get(id).unwrap().payload.expose(), b"key");
    assert_eq!(store.resolve_handle(&handle.raw).unwrap(), id);
    assert_eq!(
        store
            .resolve_handle_with_incarnation(&handle.raw)
            .unwrap()
            .0,
        id
    );
    assert_eq!(store.meta(id).unwrap().record_version, 1);
    assert_eq!(store.list_meta().unwrap()[0].0, id);
    assert!(store
        .read_grant_covers("reserved", "consumer", id, GrantOperation::Read, &declared)
        .unwrap());
    assert_eq!(
        store
            .list_scoped_snapshot("reserved", "consumer", &declared)
            .unwrap()
            .rows[0]
            .id,
        id
    );
    assert_eq!(
        store
            .watch_scoped_snapshot("reserved", "consumer", &declared)
            .unwrap()
            .0
            .rows[0]
            .id,
        id
    );
    store.connector_inventory().unwrap();
    assert_eq!(selects.load(Ordering::Relaxed), 0);
}

#[test]
fn only_a_committed_row_change_wakes_write_subscribers() {
    let (_root, store) = tmp_store(0x79);
    let mut writes = store.subscribe_writes();
    let handle = mint_handle().unwrap();
    let revoke = || store.revoke_handle(&handle.raw, AuditCtx::admin(AuditOp::RevokeHandle));
    assert_eq!(revoke().unwrap(), None);
    assert!(
        !writes.has_changed().unwrap(),
        "revoking an unknown handle changed no rows"
    );

    store.create("id", &oauth_record()).unwrap();
    assert!(
        writes.has_changed().unwrap(),
        "a committed insert wakes subscribers"
    );
    writes.borrow_and_update();
    let rolled_back = store.fenced_write(|tx| {
        tx.execute("DELETE FROM credentials WHERE credential_id = 'id'", [])?;
        Err::<(), _>(rusqlite::Error::InvalidQuery)
    });
    assert!(rolled_back.is_err());
    assert!(store.meta("id").is_ok());
    assert!(
        !writes.has_changed().unwrap(),
        "rolled-back changes do not wake subscribers"
    );
}

#[test]
fn unchanged_github_app_permission_observations_do_not_wake_readers() {
    let (_root, store) = tmp_store(0x79);
    let id = "id";
    store.create(id, &oauth_record()).unwrap();
    let mut writes = store.subscribe_writes();
    let permissions = BTreeMap::from([("contents".to_owned(), "read".to_owned())]);

    store.observe_github_app_permissions(id, 2, &permissions);
    assert!(
        !writes.has_changed().unwrap(),
        "a superseded mint changes no row"
    );
    store.observe_github_app_permissions(id, 1, &permissions);
    assert!(
        writes.has_changed().unwrap(),
        "a new observation wakes inventory readers"
    );
    writes.borrow_and_update();
    store.observe_github_app_permissions(id, 1, &permissions);
    assert!(
        !writes.has_changed().unwrap(),
        "repeating the same observation changes no row"
    );
}

#[test]
fn pending_enrollment_poll_issues_no_selects_on_the_writer() {
    let (_root, store) = tmp_store(0x79);
    let secret = "a".repeat(64);
    let now = 1_000_000;
    let hash = enrollment_secret_hash(&secret).unwrap();
    let request = store
        .propose_enrollment_at("pending-probe", &hash, now)
        .unwrap();
    let writes = store.subscribe_writes();
    let selects = writer_selects(&store);
    assert!(matches!(
        store.poll_enrollment_at(&request.request_id, &secret, now),
        Ok(EnrollmentPoll::Pending)
    ));
    assert_eq!(selects.load(Ordering::Relaxed), 0);
    assert!(!writes.has_changed().unwrap());

    assert!(matches!(
        store.poll_enrollment_at(&request.request_id, &"b".repeat(64), now),
        Err(EnrollmentError::Refused(EnrollmentRefusal::NotFound))
    ));
    assert!(
        selects.load(Ordering::Relaxed) > 0,
        "documented diagnostic event still uses the writer"
    );
    assert!(writes.has_changed().unwrap());
}

#[test]
fn pending_enrollment_poll_still_refuses_after_a_fence_handover() {
    let (_root, store) = tmp_store(0x79);
    let secret = "a".repeat(64);
    let now = 1_000_000;
    let hash = enrollment_secret_hash(&secret).unwrap();
    let request = store
        .propose_enrollment_at("pending-probe", &hash, now)
        .unwrap();
    store
        .with_raw_conn(|conn| conn.execute("UPDATE cortexkit_fence SET epoch = epoch + 1", []))
        .unwrap();
    let writes = store.subscribe_writes();
    assert!(matches!(
        store.poll_enrollment_at(&request.request_id, &secret, now),
        Err(EnrollmentError::Store(StoreOpError::Fenced { .. }))
    ));
    assert!(store.is_fenced_out());
    assert!(!writes.has_changed().unwrap());
}

#[test]
fn unadmitted_broker_action_and_unknown_rotation_roll_back_without_waking() {
    let (_root, store) = tmp_store(0x79);
    assert!(store.store.epoch() > 0);
    let fence = || {
        store
            .with_raw_conn(|conn| {
                conn.query_row(
                    "SELECT epoch FROM cortexkit_fence WHERE id = 0",
                    [],
                    |row| row.get::<_, i64>(0),
                )
            })
            .unwrap()
    };
    // Both calls tentatively claim the epoch before reaching their refusal.
    // A commit would persist that claim even though the domain rows did not change.
    store
        .with_raw_conn(|conn| conn.execute("UPDATE cortexkit_fence SET epoch = 0", []))
        .unwrap();
    let writes = store.subscribe_writes();
    assert!(matches!(
        store.request_broker_action(
            None,
            serde_json::Value::Null,
            |_| unreachable!(),
            || unreachable!()
        ),
        Err(BrokerActionRequestError::NotFound)
    ));
    assert_eq!(fence(), 0);
    assert!(!writes.has_changed().unwrap());
    assert!(matches!(
        store.rotate_enrollment(&"a".repeat(64), 1),
        Err(EnrollmentError::Refused(EnrollmentRefusal::NotFound))
    ));
    assert_eq!(fence(), 0);
    assert!(!writes.has_changed().unwrap());
}

#[test]
fn migration_enables_full_sync_for_commits_and_checkpoints() {
    let (_dir, store) = tmp_store(0x57);
    store
        .store
        .with_conn(|conn| {
            for (pragma, expected) in [
                ("synchronous", 2),
                ("fullfsync", 1),
                ("checkpoint_fullfsync", 1),
            ] {
                let actual: i64 = conn.pragma_query_value(None, pragma, |row| row.get(0))?;
                assert_eq!(actual, expected, "PRAGMA {pragma}");
            }
            Ok(())
        })
        .unwrap();
}

#[test]
fn refresh_intent_is_healthy_at_the_age_limit_and_overdue_one_ms_later() {
    use crate::health::{VaultHealthStatus, MAX_REFRESH_INTENT_AGE_MS};
    let (_dir, store) = tmp_store(0x59);
    let id = "oauth:pending";
    store.create(id, &oauth_record()).unwrap();
    store.open_intent(id, 1, "intent-hash").unwrap();
    let started_at_ms = store.read_intent(id).unwrap().unwrap().started_at_ms;
    let at_limit = store.health_snapshot_at(started_at_ms + MAX_REFRESH_INTENT_AGE_MS);
    assert_eq!(at_limit.status, VaultHealthStatus::Ok);
    assert_eq!(at_limit.open_intents, 1);
    assert_eq!(at_limit.overdue_intents, 0);

    let past_limit = store.health_snapshot_at(started_at_ms + MAX_REFRESH_INTENT_AGE_MS + 1);
    assert_eq!(past_limit.status, VaultHealthStatus::Degraded);
    assert_eq!(past_limit.open_intents, 1);
    assert_eq!(past_limit.overdue_intents, 1);
    assert_eq!(past_limit.overdue_intent_ids, [id]);
}

#[test]
fn health_counts_intents_and_states_without_inventory_or_intent_details() {
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    let (_dir, store) = tmp_store(0x59);
    store.create("oauth:healthy", &oauth_record()).unwrap();
    store
        .open_intent("oauth:healthy", 1, "intent-hash")
        .unwrap();
    store
        .with_raw_conn(|conn| {
            conn.authorizer(Some(|context: AuthContext<'_>| match context.action {
                AuthAction::Read {
                    table_name: "credential_gateway_settings",
                    ..
                }
                | AuthAction::Read {
                    table_name: "refresh_intent",
                    column_name: "old_refresh_hash",
                } => Authorization::Deny,
                _ => Authorization::Allow,
            }));
            Ok(())
        })
        .unwrap();
    let health = store.health_snapshot();
    assert_eq!(health.status, crate::health::VaultHealthStatus::Ok);
    assert_eq!(health.active, 1);
    assert_eq!(health.open_intents, 1);
}

#[test]
fn a_plain_credential_read_does_not_hash_the_envelope() {
    let (_dir, store) = tmp_store(0x59);
    store.create("oauth:hashing", &oauth_record()).unwrap();
    ENVELOPE_DIGEST_COUNT.set(0);
    assert_eq!(store.get("oauth:hashing").unwrap().record_version, 1);
    assert_eq!(ENVELOPE_DIGEST_COUNT.get(), 0);
    let read = store
        .get_with_stale_pending_and_digest("oauth:hashing")
        .unwrap();
    assert_eq!(read.stored_digest_hex.len(), 64);
    assert_eq!(ENVELOPE_DIGEST_COUNT.get(), 1);
}

#[test]
fn logout_refuses_github_app_webhook_companions() {
    let (_dir, store) = tmp_store(0x58);
    assert!(matches!(
        store.retire_and_revoke_all_audited(
            "opaque:github-app-webhook:example",
            AuditCtx::admin(AuditOp::Invalidate),
        ),
        Err(StoreOpError::GitHubAppCompanionProtected)
    ));
}

#[path = "store_ssh_enrollment_tests.rs"]
mod ssh_enrollment;

#[test]
fn signature_audit_is_public_sha256_while_seal_audit_is_keyed() {
    let (_root, store) = tmp_store(0x6d);
    let id = "opaque:key-use-audit";
    let payload = b"published signed bytes";
    let record =
        VaultRecord::new_static(CredentialKind::Opaque, "operator", payload.to_vec(), None);
    store.create(id, &record).unwrap();
    let incarnation = store.credential_incarnation(id).unwrap();
    let sign = store
        .append_signature_audit(id, (1, &incarnation), payload, "operator")
        .unwrap();
    let seal = store
        .append_seal_audit(id, (1, &incarnation), payload, "operator")
        .unwrap();
    let plain = hex32(&payload_hash(payload));
    let keyed = hex32(&audit::payload_fingerprint(&store.audit_key, payload));
    assert_eq!(sign.payload_hash.as_deref(), Some(plain.as_str()));
    assert_ne!(seal.payload_hash.as_deref(), Some(plain.as_str()));
    assert_eq!(seal.payload_hash.as_deref(), Some(keyed.as_str()));
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[test]
fn confidential_audit_payloads_are_keyed_and_preserve_legacy_chain() {
    use hmac::{Hmac, Mac};

    let (_root, mut store) = tmp_store(0x6b);
    let payload = b"0420";
    let plain = hex32(&payload_hash(payload));
    // Independently compute the two HMAC steps, rather than using the writer's helper.
    let mut derive = <Hmac<Sha256> as Mac>::new_from_slice(&*store.audit_key).unwrap();
    derive.update(b"cortexkit-credentials/audit-payload-key/v1");
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&derive.finalize().into_bytes()).unwrap();
    mac.update(payload);
    let keyed = hex32(&mac.finalize().into_bytes().into());
    assert_ne!(keyed, plain);

    let legacy = store
        .append_audit(&AuditRecord {
            op: AuditOp::Put,
            credential_id: Some("opaque:legacy".into()),
            payload_hash: Some(plain.clone()),
            actor: "operator".into(),
            alarm: None,
        })
        .unwrap();
    let record =
        VaultRecord::new_static(CredentialKind::Opaque, "operator", payload.to_vec(), None);
    let id = "opaque:keyed-audit";
    store.create(id, &record).unwrap();
    let incarnation = store.credential_incarnation(id).unwrap();
    store
        .overwrite_cas(id, &record, &payload_hash(payload))
        .unwrap();
    store
        .overwrite_unconditional_audited(id, &record, AuditCtx::admin(AuditOp::Overwrite))
        .unwrap();
    store
        .commit_refresh(
            id,
            3,
            &store.credential_incarnation(id).unwrap(),
            &record,
            None,
        )
        .unwrap();
    store
        .set_identity_audited(
            id,
            RecordIdentity::default(),
            AuditCtx::admin(AuditOp::SetIdentity),
        )
        .unwrap();
    store
        .append_signature_audit(id, (5, &incarnation), payload, "operator")
        .unwrap();
    store
        .append_seal_audit(id, (5, &incarnation), payload, "operator")
        .unwrap();
    let rows = store.read_audit(None).unwrap();
    assert_eq!(rows.len(), 8);
    assert_eq!(rows[0], legacy);
    for row in &rows[1..] {
        if row.op == "sign" {
            assert_eq!(row.payload_hash.as_deref(), Some(plain.as_str()));
            continue;
        }
        assert_ne!(
            row.payload_hash.as_deref(),
            Some(plain.as_str()),
            "{}",
            row.op
        );
        assert_eq!(
            row.payload_hash.as_deref(),
            Some(keyed.as_str()),
            "{}",
            row.op
        );
    }
    assert_eq!(store.verify_audit_chain().unwrap(), None);

    store
        .rotate_master_key(MasterKey::from_bytes([0x6c; MASTER_KEY_LEN]))
        .unwrap();
    store
        .append_seal_audit(id, (5, &incarnation), payload, "operator")
        .unwrap();
    assert_eq!(store.read_audit(None).unwrap()[0], legacy);
    assert_eq!(
        store.read_audit(Some(1)).unwrap()[0]
            .payload_hash
            .as_deref(),
        Some(keyed.as_str())
    );
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

/// Migration 6 must make old grants explicitly read-only while allowing a new
/// sign grant for the same principal and prefix. Both facts are needed: a default
/// can hide the backfill, and the old primary key would otherwise collapse the two
/// independent authorities into one row.
#[test]
fn migration_six_backfills_existing_read_grants_without_blocking_sign_grants() {
    let conn = rusqlite::Connection::open_in_memory().expect("open sqlite");
    conn.execute_batch(
        "CREATE TABLE read_grants (\
                 principal_kind TEXT NOT NULL, \
                 principal_id TEXT NOT NULL, \
                 credential_prefix TEXT NOT NULL, \
                 created_at_ms INTEGER NOT NULL, \
                 PRIMARY KEY (principal_kind, principal_id, credential_prefix)\
             );",
    )
    .expect("create v5 grant table");
    for prefix in ["github_app:", "signing:agent-assertion:"] {
        conn.execute(
            "INSERT INTO read_grants \
                 (principal_kind, principal_id, credential_prefix, created_at_ms) \
                 VALUES ('reserved', 'prefrontal-core', ?1, 1)",
            [prefix],
        )
        .expect("seed legacy read grant");
    }

    let migration = MIGRATIONS
        .iter()
        .find(|migration| migration.version == 6)
        .expect("migration 6 exists");
    conn.execute_batch(migration.statements)
        .expect("apply migration 6");

    let mut statement = conn
        .prepare(
            "SELECT credential_prefix, operation FROM read_grants \
                 ORDER BY credential_prefix",
        )
        .expect("prepare backfill query");
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .expect("query backfill rows")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("decode backfill rows");
    assert_eq!(
        rows,
        [
            ("github_app:".to_string(), "read".to_string()),
            ("signing:agent-assertion:".to_string(), "read".to_string()),
        ],
        "every legacy grant must remain a read grant after migration"
    );
    conn.execute(
        "INSERT INTO read_grants \
             (principal_kind, principal_id, credential_prefix, operation, created_at_ms) \
             VALUES ('reserved', 'prefrontal-core', 'signing:agent-assertion:', 'sign', 2)",
        [],
    )
    .expect("read and sign grants must coexist for one prefix");
}

/// Migration 7 adds only a nullable diagnostic column. In particular, it must not
/// rewrite any audit transcript: audit MACs cover historical fixed fields and remain
/// evidence for rows created before permission observations existed.
#[test]
fn migration_seven_preserves_existing_rows_and_audit_macs() {
    let conn = rusqlite::Connection::open_in_memory().expect("open sqlite");
    conn.execute_batch(
        "CREATE TABLE credentials (\
                 credential_id TEXT PRIMARY KEY, \
                 record_version INTEGER NOT NULL, \
                 key_id TEXT NOT NULL, \
                 state TEXT NOT NULL, \
                 envelope BLOB NOT NULL, \
                 updated_at_ms INTEGER NOT NULL, \
                 stale_pending INTEGER NOT NULL DEFAULT 0\
             ); \
             CREATE TABLE audit_log (\
                 seq INTEGER PRIMARY KEY AUTOINCREMENT, \
                 ts_ms INTEGER NOT NULL, \
                 op TEXT NOT NULL, \
                 credential_id TEXT, \
                 payload_hash TEXT, \
                 actor TEXT NOT NULL, \
                 alarm INTEGER NOT NULL DEFAULT 0, \
                 alarm_reason TEXT, \
                 prev_mac TEXT NOT NULL, \
                 entry_mac TEXT NOT NULL\
             );",
    )
    .expect("create v6 tables");
    conn.execute(
            "INSERT INTO credentials \
                 (credential_id, record_version, key_id, state, envelope, updated_at_ms, stale_pending) \
             VALUES ('github-app', 4, 'old-key', 'active', X'010203', 99, 1)",
            [],
        )
        .expect("seed legacy credential");
    for (seq, mac) in [(1, "mac-before"), (2, "mac-after")] {
        conn.execute(
                "INSERT INTO audit_log \
                     (seq, ts_ms, op, credential_id, payload_hash, actor, alarm, alarm_reason, prev_mac, entry_mac) \
                 VALUES (?1, 7, 'put', 'github-app', 'hash', 'vault', 0, NULL, 'previous', ?2)",
                rusqlite::params![seq, mac],
            )
            .expect("seed historical audit entry");
    }
    let credential_before: (i64, String, String, Vec<u8>, i64, i64) = conn
        .query_row(
            "SELECT record_version, key_id, state, envelope, updated_at_ms, stale_pending \
                 FROM credentials WHERE credential_id = 'github-app'",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .expect("read legacy credential");
    let macs_before = conn
        .prepare("SELECT entry_mac FROM audit_log ORDER BY seq")
        .expect("prepare audit MAC read")
        .query_map([], |row| row.get::<_, String>(0))
        .expect("read audit MACs")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("decode audit MACs");

    let migration = MIGRATIONS
        .iter()
        .find(|migration| migration.version == 7)
        .expect("migration 7 exists");
    conn.execute_batch(migration.statements)
        .expect("apply migration 7 to a populated v6 store");

    let credential_after: (i64, String, String, Vec<u8>, i64, i64, Option<String>) = conn
        .query_row(
            "SELECT record_version, key_id, state, envelope, updated_at_ms, stale_pending, \
                        last_github_app_permissions \
                 FROM credentials WHERE credential_id = 'github-app'",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .expect("read migrated credential");
    assert_eq!(
        (
            &credential_after.0,
            &credential_after.1,
            &credential_after.2,
            &credential_after.3,
            &credential_after.4,
            &credential_after.5,
        ),
        (
            &credential_before.0,
            &credential_before.1,
            &credential_before.2,
            &credential_before.3,
            &credential_before.4,
            &credential_before.5,
        ),
        "adding diagnostic metadata must not alter an existing credential row"
    );
    assert!(
        credential_after.6.is_none(),
        "a legacy credential has no synthetic first observation"
    );
    let macs_after = conn
        .prepare("SELECT entry_mac FROM audit_log ORDER BY seq")
        .expect("prepare post-migration audit MAC read")
        .query_map([], |row| row.get::<_, String>(0))
        .expect("read post-migration audit MACs")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("decode post-migration audit MACs");
    assert_eq!(
        macs_after, macs_before,
        "migration 7 must leave every historical audit MAC byte-identical"
    );
}

/// EVERY write path refuses an empty non-OAuth payload, not merely the one that
/// happens to be covered elsewhere.
///
/// The guard lives in `seal_record` -- a chokepoint every writer passes through --
/// rather than in `VaultRecord::new_static`, which only debug_asserts the KIND. That
/// is the right shape, because a constructor is sidesteppable by a struct literal
/// and a chokepoint is not. But "every writer passes through it" is a claim about
/// the call graph, and that is precisely the kind of claim that stops being true
/// quietly.
///
/// So this enumerates the writers rather than trusting the chokepoint. Prompted by
/// the sibling defect in a peer's code: an invariant stated explicitly in one arm of
/// a function and silently inherited in the other, where the CORRECT arm is what
/// makes the incorrect one invisible to a reader.
#[test]
fn every_write_path_refuses_an_empty_non_oauth_payload() {
    let (_root, store) = tmp_store(0x5A);
    let empty = VaultRecord::new_static(CredentialKind::ApiKey, "test", Vec::new(), None);

    assert!(
        store.create("apikey:empty", &empty).is_err(),
        "create must refuse an empty payload"
    );
    assert!(
        store
            .create_audited("apikey:empty", &empty, AuditCtx::admin(AuditOp::Put))
            .is_err(),
        "create_audited must refuse an empty payload"
    );

    // Seed a good record, then try to REPLACE it with an empty one. The replace
    // paths are the dangerous ones: overwriting a working credential with zero bytes
    // reads downstream as an authentication failure rather than as corruption.
    let good = VaultRecord::new_static(CredentialKind::ApiKey, "test", b"real".to_vec(), None);
    store.create("apikey:one", &good).expect("seed");
    assert!(
        store
            .overwrite_unconditional_audited("apikey:one", &empty, AuditCtx::admin(AuditOp::Put))
            .is_err(),
        "overwrite_unconditional_audited must refuse an empty payload"
    );

    // POSITIVE ARM: the seeded record survives the refused write. A refusal that
    // damaged the row on its way out would satisfy every assertion above.
    let loaded = store.get("apikey:one").expect("reload the seeded record");
    assert_eq!(
        loaded.payload.expose(),
        b"real",
        "a refused write must leave the existing record untouched"
    );
}

/// EVERY write path refuses custody-tombstone material, not merely the importer
/// that happens to parse it.
///
/// A custody tombstone is a sentinel in a consumer's credential store marking
/// "the real material lives in the vault". It is the one string that is
/// never a credential, and storing it inverts custody: the vault would then serve
/// the marker that means the vault holds the secret, and the real family would
/// exist nowhere. When refusal was enforced only by individual importers, a
/// generic `put --replace --payload-file <path>` reached the store
/// and replaced a working credential with the marker.
///
/// Entrance checks are the wrong shape for this: they enumerate the doors, and the
/// door that matters is the one added next. The unattended re-sealer is the live
/// caller that makes it concrete -- it reads a consumer's store and re-seals what it
/// finds, so the moment that store carries the tombstone the sealer is holding the
/// sentinel as if it were a token.
#[test]
fn operator_deposits_refuse_short_term_bedrock_keys_and_accept_long_term_ones() {
    // apikey:amazon-bedrock held a short-term key for 95 days after it had already
    // expired, reported active the whole time. Both operator sinks must refuse that
    // form, and a long-term key must still store.
    let (_dir, store) = tmp_store(171);
    let short_term = VaultRecord::new_static(
        CredentialKind::ApiKey,
        "test",
        b"bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29tLz9BY3Rpb249Q2FsbFdpdGhCZWFyZXJUb2tlbg=="
            .to_vec(),
        None,
    );
    let refused = store
        .create_audited(
            "apikey:amazon-bedrock",
            &short_term,
            AuditCtx::admin(AuditOp::Put),
        )
        .unwrap_err();
    assert!(
        matches!(refused, StoreOpError::ShortTermBedrockKey { .. }),
        "{refused}"
    );
    assert!(refused.to_string().contains("long-term Bedrock API key"));
    let long_term = VaultRecord::new_static(
        CredentialKind::ApiKey,
        "test",
        b"ABSKQmVkcm9ja0FQSUtleS1leGFtcGxl".to_vec(),
        None,
    );
    store
        .create_audited(
            "apikey:amazon-bedrock",
            &long_term,
            AuditCtx::admin(AuditOp::Put),
        )
        .expect("a long-term key stores");
    let replaced = store
        .overwrite_unconditional_audited(
            "apikey:amazon-bedrock",
            &short_term,
            AuditCtx::admin(AuditOp::Overwrite),
        )
        .unwrap_err();
    assert!(matches!(replaced, StoreOpError::ShortTermBedrockKey { .. }));
    assert_eq!(
        store.get("apikey:amazon-bedrock").unwrap().payload.expose(),
        b"ABSKQmVkcm9ja0FQSUtleS1leGFtcGxl",
        "the refused overwrite left the long-term key in place"
    );
}

#[test]
fn cas_overwrite_refuses_short_term_bedrock_keys() {
    let (_dir, store) = tmp_store(171);
    let id = "apikey:amazon-bedrock";
    let initial =
        VaultRecord::new_static(CredentialKind::ApiKey, "test", b"initial".to_vec(), None);
    store.create(id, &initial).unwrap();
    let short_term = VaultRecord::new_static(
        CredentialKind::ApiKey,
        "test",
        b"bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29tLz9BY3Rpb249Q2FsbFdpdGhCZWFyZXJUb2tlbg=="
            .to_vec(),
        None,
    );
    assert!(matches!(
        store.overwrite_cas_audited(
            id,
            &short_term,
            &payload_hash(initial.payload.expose()),
            AuditCtx::admin(AuditOp::Overwrite)
        ),
        Err(StoreOpError::ShortTermBedrockKey { .. })
    ));
    assert_eq!(store.meta(id).unwrap().record_version, 1);
}

#[test]
fn every_write_path_refuses_custody_tombstone_material() {
    let (_root, store) = tmp_store(0x5B);
    let tombstone = VaultRecord::new_static(
        CredentialKind::ApiKey,
        "test",
        b"claustrum-tombstone:v1:anthropic".to_vec(),
        None,
    );

    assert!(
        store.create("apikey:tomb", &tombstone).is_err(),
        "create must refuse tombstone material"
    );
    assert!(
        store
            .create_audited("apikey:tomb", &tombstone, AuditCtx::admin(AuditOp::Put))
            .is_err(),
        "create_audited must refuse tombstone material"
    );

    // The replace paths are the dangerous ones: this is the reported defect, where
    // a working credential is overwritten by the marker.
    let good = VaultRecord::new_static(CredentialKind::ApiKey, "test", b"real".to_vec(), None);
    store.create("apikey:live", &good).expect("seed");
    assert!(
        store
            .overwrite_unconditional_audited(
                "apikey:live",
                &tombstone,
                AuditCtx::admin(AuditOp::Put)
            )
            .is_err(),
        "overwrite_unconditional_audited must refuse tombstone material"
    );

    // OAUTH ARM: the same sentinel arriving in a token field rather than a payload.
    // The source parsers reject it, but a caller constructing the credential
    // directly does not pass through them, and both fields are reachable -- the
    // consumer-side tombstone has been written in each.
    let mut tombstoned_access = oauth_record();
    tombstoned_access
        .oauth
        .as_mut()
        .expect("oauth")
        .access_token = "claustrum-tombstone:v1:anthropic".to_string().into();
    assert!(
        store
            .create("oauth:tomb-access", &tombstoned_access)
            .is_err(),
        "an access token carrying the sentinel must be refused"
    );

    let mut tombstoned_refresh = oauth_record();
    tombstoned_refresh
        .oauth
        .as_mut()
        .expect("oauth")
        .refresh_token = "claustrum-tombstone:v1:anthropic".to_string().into();
    assert!(
        store
            .create("oauth:tomb-refresh", &tombstoned_refresh)
            .is_err(),
        "a refresh token carrying the sentinel must be refused"
    );

    // POSITIVE ARM: the seeded record survives every refusal above, and ordinary
    // material still writes. A guard that matched too broadly -- or damaged the row
    // on its way out -- would satisfy the refusals and fail here.
    let loaded = store.get("apikey:live").expect("reload the seeded record");
    assert_eq!(
        loaded.payload.expose(),
        b"real",
        "a refused write must leave the existing record untouched"
    );
    store
        .create("oauth:ordinary", &oauth_record())
        .expect("an ordinary OAuth record must still be storable");
    store
        .create(
            "apikey:mentions",
            &VaultRecord::new_static(
                CredentialKind::ApiKey,
                "test",
                b"sk-claustrum-tombstone:v1:anthropic".to_vec(),
                None,
            ),
        )
        .expect("the sentinel is refused as a PREFIX, not as a substring");
}

fn oauth_record() -> VaultRecord {
    VaultRecord::new_oauth(
        "opencode",
        "anthropic",
        OAuthCredential {
            access_token: "access".to_string().into(),
            refresh_token: "refresh".to_string().into(),
            expires_at_ms: Some(9_999),
            token_url: "https://t.test/token".into(),
            client_id: Some("c".into()),
            client_secret: None,
            scopes: vec!["scope-a".into(), "scope-b".into()],
        },
        b"payload-bytes".to_vec(),
    )
}

#[test]
fn home_watch_candidates_open_active_and_needs_reauth_without_returning_secrets() {
    let (_root, store) = tmp_store(193);
    let mut record = oauth_record().with_identity(RecordIdentity {
        account_id: Some("account".into()),
        email: None,
        org_name: Some("workspace".into()),
    });
    let oauth = record.oauth.as_mut().unwrap();
    oauth.access_token = "home-watch-private-access".to_string().into();
    oauth.refresh_token = "home-watch-private-refresh".to_string().into();
    record.detected_plan = Some(crate::plan_detection::DetectedPlan {
        tier: Some("pro".into()),
        raw: Some("provider-pro".into()),
        observed_at_ms: 42,
    });
    for id in ["active", "needs", "retired", "corrupt"] {
        store.create(id, &record).unwrap();
    }
    store
        .invalidate_and_revoke_all_audited("needs", AuditCtx::admin(AuditOp::Invalidate))
        .unwrap();
    store
        .retire_and_revoke_all_audited("retired", AuditCtx::admin(AuditOp::Invalidate))
        .unwrap();
    store.quarantine("corrupt").unwrap();
    store
        .create(
            "static",
            &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"static-key".to_vec(), None),
        )
        .unwrap();

    let rows = store.home_watch_candidates().unwrap();
    assert_eq!(
        rows.iter()
            .map(|row| row.credential_id.as_str())
            .collect::<Vec<_>>(),
        ["active", "needs", "static"]
    );
    for (row, state) in rows
        .iter()
        .take(2)
        .zip([RecordState::Active, RecordState::NeedsReauth])
    {
        assert_eq!(row.state, state);
        assert_eq!(row.record_version, 1);
        assert_eq!(row.kind, CredentialKind::Oauth);
        assert_eq!(row.refresh_adapter.as_deref(), Some("anthropic"));
        assert_eq!(row.identity, record.identity);
        assert_eq!(row.detected_plan, record.detected_plan);
        assert!(row.is_refreshable());
    }
    assert!(!rows[2].is_refreshable());
    let debug = format!("{rows:?}");
    for secret in [
        "payload-bytes",
        "home-watch-private-access",
        "home-watch-private-refresh",
        "static-key",
    ] {
        assert!(
            !debug.contains(secret),
            "candidate Debug exposed credential material"
        );
    }
    assert!(!debug.contains("expires_at"));
}

#[test]
fn home_watch_candidates_skip_bad_envelopes_and_decodes_without_writing() {
    let (_root, store) = tmp_store(194);
    for id in ["good", "bad-envelope", "bad-record"] {
        store.create(id, &oauth_record()).unwrap();
    }
    let bad_record = envelope::seal(
        &store.key,
        b"not a record",
        &RecordBinding {
            credential_id: "bad-record",
            record_version: 1,
        },
    )
    .unwrap();
    store
        .with_raw_conn(|conn| {
            conn.execute(
                "UPDATE credentials SET envelope = X'00' WHERE credential_id = 'bad-envelope'",
                [],
            )?;
            conn.execute(
                "UPDATE credentials SET envelope = ?1 WHERE credential_id = 'bad-record'",
                [&bad_record],
            )?;
            Ok(())
        })
        .unwrap();
    let before = store
        .with_raw_conn(|conn| Ok(conn.total_changes()))
        .unwrap();
    let tip = store.audit_tip().unwrap();
    let mut writes = store.subscribe_writes();
    let rows = store.home_watch_candidates().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].credential_id, "good");
    assert_eq!(
        store.meta("bad-envelope").unwrap().state,
        RecordState::Active
    );
    assert_eq!(store.meta("bad-record").unwrap().state, RecordState::Active);
    assert_eq!(
        store
            .with_raw_conn(|conn| Ok(conn.total_changes()))
            .unwrap(),
        before
    );
    assert_eq!(store.audit_tip().unwrap(), tip);
    assert!(!writes.has_changed().unwrap());
    assert!(store.recent_auth_events(10).unwrap().is_empty());
    // Prove the receiver is connected to real commits, not an inert test signal.
    store.create("later", &oauth_record()).unwrap();
    assert!(writes.has_changed().unwrap());
    writes.borrow_and_update();
}

#[test]
fn home_watch_candidates_fail_on_query_errors() {
    let (_root, store) = tmp_store(195);
    store
        .with_raw_conn(|conn| {
            conn.execute_batch("ALTER TABLE credentials RENAME COLUMN envelope TO unavailable")
        })
        .unwrap();
    assert!(store.home_watch_candidates().is_err());
}

fn held_plan_rows(store: &EncryptedStore) -> usize {
    store
        .with_raw_conn(|conn| {
            conn.query_row("SELECT COUNT(*) FROM held_detected_plans", [], |row| {
                row.get(0)
            })
        })
        .unwrap()
}

fn hold_test_plan(store: &EncryptedStore, record: &VaultRecord) {
    store
        .hold_detected_plan(
            "oauth:anthropic",
            record.record_version,
            &refresh_token_hash(record.oauth.as_ref().unwrap().access_token.expose()),
            &record.identity,
            &crate::plan_detection::DetectedPlan {
                tier: Some("max_20x".into()),
                raw: Some("default_claude_max_20x".into()),
                observed_at_ms: 123,
            },
        )
        .unwrap();
}

#[test]
fn migration_32_adds_held_plans_without_rewriting_records_and_refuses_older_binaries() {
    let root = TestTempDir::new("ck-held-plan-migration");
    let descriptor = StorageDescriptor {
        module_id: "cortexkit-credentials".into(),
        storage_namespace: "vault".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: root.join("store.db").to_string_lossy().into_owned(),
        },
    };
    let sqlite = open_sqlite(&descriptor).unwrap();
    migrate_through_for_test(&sqlite, 31).unwrap();
    assert!(!sqlite
        .with_conn(|conn| table_exists(conn, "held_detected_plans"))
        .unwrap());
    let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([205; 32])).unwrap();
    store.create("oauth:anthropic", &oauth_record()).unwrap();
    let record = oauth_record();
    let audit_before = store.read_audit(None).unwrap();
    EncryptedStore::migrate(&store.store).unwrap();
    EncryptedStore::migrate(&store.store).unwrap();
    assert_eq!(store.get("oauth:anthropic").unwrap(), record);
    let audit_after = store.read_audit(None).unwrap();
    assert_eq!(audit_after.len(), audit_before.len());
    assert_eq!(
        audit_after.last().unwrap().entry_mac,
        audit_before.last().unwrap().entry_mac
    );
    let columns = store
        .with_raw_conn(|conn| {
            let mut stmt = conn.prepare("PRAGMA table_info(held_detected_plans)")?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, bool>(3)?,
                    row.get::<_, bool>(5)?,
                ))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap();
    assert_eq!(
        columns,
        vec![
            ("credential_id".into(), "TEXT".into(), false, true),
            ("record_version".into(), "INTEGER".into(), true, false),
            ("token_hash".into(), "TEXT".into(), true, false),
            ("identity".into(), "TEXT".into(), true, false),
            ("tier".into(), "TEXT".into(), false, false),
            ("raw".into(), "TEXT".into(), false, false),
            ("observed_at_ms".into(), "INTEGER".into(), true, false),
        ]
    );
    let recorded = store.with_raw_conn(read_schema_version).unwrap();
    assert_eq!(recorded, newest_migration_version());
    let error = refuse_store_ahead_of_binary(recorded, 31)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains(&recorded.to_string()) && error.contains("31"),
        "{error}"
    );
    hold_test_plan(&store, &record);
    assert_eq!(held_plan_rows(&store), 1);
}

#[test]
fn incarnation_migration_backfills_distinct_non_null_row_identities() {
    let root = TestTempDir::new("ck-incarnation-migration");
    let descriptor = StorageDescriptor {
        module_id: "cortexkit-credentials".into(),
        storage_namespace: "vault".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: root.join("store.db").to_string_lossy().into_owned(),
        },
    };
    let sqlite = open_sqlite(&descriptor).unwrap();
    migrate_through_for_test(&sqlite, 32).unwrap();
    let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([205; 32])).unwrap();
    for id in ["oauth:anthropic", "oauth:openai"] {
        store.create(id, &oauth_record()).unwrap();
    }
    let before = store.read_audit(None).unwrap();
    EncryptedStore::migrate(&store.store).unwrap();
    let a = store.credential_incarnation("oauth:anthropic").unwrap();
    let b = store.credential_incarnation("oauth:openai").unwrap();
    assert_eq!(a.len(), 32);
    assert_eq!(b.len(), 32);
    assert_ne!(a, b);
    assert!(a
        .bytes()
        .chain(b.bytes())
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
    let not_null: bool = store
        .with_raw_conn(|conn| {
            conn.query_row(
                "SELECT [notnull] FROM pragma_table_info('credentials') WHERE name = 'incarnation'",
                [],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert!(not_null);
    assert_eq!(store.read_audit(None).unwrap(), before);
    EncryptedStore::migrate(&store.store).unwrap();
    assert_eq!(store.credential_incarnation("oauth:anthropic").unwrap(), a);
    assert_eq!(store.get("oauth:anthropic").unwrap(), oauth_record());
}

#[test]
fn incarnation_insert_generates_identity_even_with_equal_creation_timestamps() {
    let (_root, store) = tmp_store(151);
    store.create("id", &oauth_record()).unwrap();
    // Model two deposits dated in the same millisecond without racing a clock.
    store
        .with_raw_conn(|conn| conn.execute("UPDATE credentials SET created_at_ms = 1", []))
        .unwrap();
    let a = store.credential_incarnation("id").unwrap();
    store
        .remove_audited("id", AuditCtx::admin(AuditOp::Remove))
        .unwrap();
    store.create("id", &oauth_record()).unwrap();
    let b = store.credential_incarnation("id").unwrap();
    store
        .with_raw_conn(|conn| conn.execute("UPDATE credentials SET created_at_ms = 1", []))
        .unwrap();
    assert_eq!(a.len(), 32);
    assert_eq!(b.len(), 32);
    assert_ne!(a, b);
    assert_eq!(store.credential_incarnation("id").unwrap(), b);
}

#[test]
fn held_detected_plans_reject_and_remove_mismatched_bindings() {
    let (_root, store) = tmp_store(201);
    store.create("oauth:anthropic", &oauth_record()).unwrap();
    let record = store.get("oauth:anthropic").unwrap();
    for mismatch in [
        "UPDATE held_detected_plans SET record_version = 0",
        "UPDATE held_detected_plans SET identity = '{\"account_id\":\"other\"}'",
        "UPDATE held_detected_plans SET token_hash = 'wrong-token-hash'",
    ] {
        hold_test_plan(&store, &record);
        assert_eq!(held_plan_rows(&store), 1);
        store
            .with_raw_conn(|conn| conn.execute(mismatch, []))
            .unwrap();
        assert_eq!(
            store
                .held_detected_plan("oauth:anthropic", &record)
                .unwrap(),
            None
        );
        assert_eq!(held_plan_rows(&store), 0, "{mismatch}");
    }
}

#[test]
fn held_detected_plans_stale_reader_cannot_discard_newer_observation() {
    let (_root, store) = tmp_store(206);
    store.create("oauth:anthropic", &oauth_record()).unwrap();
    let old = store.get("oauth:anthropic").unwrap();
    store
        .commit_refresh(
            "oauth:anthropic",
            old.record_version,
            &store.credential_incarnation("oauth:anthropic").unwrap(),
            &old,
            None,
        )
        .unwrap();
    let current = store.get("oauth:anthropic").unwrap();
    hold_test_plan(&store, &current);
    assert_eq!(
        store.held_detected_plan("oauth:anthropic", &old).unwrap(),
        None
    );
    assert_eq!(held_plan_rows(&store), 1);
    assert_eq!(
        store
            .held_detected_plan("oauth:anthropic", &current)
            .unwrap()
            .unwrap()
            .tier
            .as_deref(),
        Some("max_20x")
    );
}

#[test]
fn held_detected_plans_keep_first_observation_and_clear_atomically_on_refresh() {
    let (_root, store) = tmp_store(202);
    store.create("oauth:anthropic", &oauth_record()).unwrap();
    let record = store.get("oauth:anthropic").unwrap();
    let audit_before = store.read_audit(None).unwrap();
    hold_test_plan(&store, &record);
    let plan = store
        .held_detected_plan("oauth:anthropic", &record)
        .unwrap()
        .unwrap();
    assert_eq!(
        held_plan_rows(&store),
        1,
        "reading must not consume a valid plan"
    );
    let other = crate::plan_detection::DetectedPlan {
        tier: Some("pro".into()),
        raw: None,
        observed_at_ms: 999,
    };
    store
        .hold_detected_plan(
            "oauth:anthropic",
            record.record_version,
            &refresh_token_hash("access"),
            &record.identity,
            &other,
        )
        .unwrap();
    assert_eq!(
        store
            .held_detected_plan("oauth:anthropic", &record)
            .unwrap(),
        Some(plan.clone())
    );
    assert_eq!(store.get("oauth:anthropic").unwrap(), record);
    let audit_after = store.read_audit(None).unwrap();
    assert_eq!(audit_after.len(), audit_before.len());
    assert_eq!(
        audit_after.last().unwrap().entry_mac,
        audit_before.last().unwrap().entry_mac
    );

    let mut next = record.clone();
    next.detected_plan = Some(plan);
    store
        .commit_refresh(
            "oauth:anthropic",
            1,
            &store.credential_incarnation("oauth:anthropic").unwrap(),
            &next,
            None,
        )
        .unwrap();
    assert_eq!(held_plan_rows(&store), 0);
    // A slow response from the previous token cannot recreate a consumed row.
    hold_test_plan(&store, &record);
    assert_eq!(held_plan_rows(&store), 0);
    let next = store.get("oauth:anthropic").unwrap();
    store
        .hold_detected_plan(
            "oauth:anthropic",
            next.record_version,
            &refresh_token_hash("access"),
            &next.identity,
            &other,
        )
        .unwrap();
    hold_test_plan(&store, &record);
    assert_eq!(
        store.held_detected_plan("oauth:anthropic", &next).unwrap(),
        Some(other)
    );
}

#[test]
fn held_detected_plans_are_removed_with_replacement_and_removal() {
    let (_root, store) = tmp_store(203);
    store.create("oauth:anthropic", &oauth_record()).unwrap();
    let record = store.get("oauth:anthropic").unwrap();
    hold_test_plan(&store, &record);
    assert_eq!(held_plan_rows(&store), 1);
    let mut replacement = record.clone();
    replacement.identity.account_id = Some("another-account".into());
    store
        .overwrite_unconditional_audited(
            "oauth:anthropic",
            &replacement,
            AuditCtx::admin(AuditOp::Login),
        )
        .unwrap();
    assert_eq!(held_plan_rows(&store), 0);
    let replacement = store.get("oauth:anthropic").unwrap();
    hold_test_plan(&store, &replacement);
    assert_eq!(held_plan_rows(&store), 1);
    store
        .remove_audited("oauth:anthropic", AuditCtx::admin(AuditOp::Remove))
        .unwrap();
    assert_eq!(held_plan_rows(&store), 0);
    hold_test_plan(&store, &replacement);
    assert_eq!(held_plan_rows(&store), 0);
}

#[test]
fn held_detected_plans_do_not_take_the_writer_fence() {
    let (_root, store) = tmp_store(204);
    store.create("oauth:anthropic", &oauth_record()).unwrap();
    let record = store.get("oauth:anthropic").unwrap();
    store
        .with_raw_conn(|conn| {
            conn.execute("UPDATE cortexkit_fence SET epoch = 999 WHERE id = 0", [])
        })
        .unwrap();
    hold_test_plan(&store, &record);
    assert_eq!(held_plan_rows(&store), 1);
    assert!(store
        .held_detected_plan("oauth:anthropic", &record)
        .unwrap()
        .is_some());
    assert!(!store.is_fenced_out());
    assert!(matches!(
        store.commit_refresh(
            "oauth:anthropic",
            1,
            &store.credential_incarnation("oauth:anthropic").unwrap(),
            &record,
            None
        ),
        Err(StoreOpError::Fenced { .. })
    ));
    assert_eq!(
        held_plan_rows(&store),
        1,
        "failed commits must retain the plan"
    );
}

fn openai_record(account_id: &str, payload: &[u8]) -> VaultRecord {
    use base64::Engine as _;

    let header =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
    let claims = serde_json::json!({
        "https://api.openai.com/auth": { "chatgpt_account_id": account_id },
    });
    let claims =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
    let access_token = format!("{header}.{claims}.sig");
    VaultRecord::new_oauth(
        "opencode",
        "openai",
        OAuthCredential {
            access_token: access_token.into(),
            refresh_token: format!("refresh-{account_id}").into(),
            expires_at_ms: Some(9_999),
            token_url: "https://t.test/token".into(),
            client_id: Some("c".into()),
            client_secret: None,
            scopes: vec!["scope-a".into(), "scope-b".into()],
        },
        payload.to_vec(),
    )
}

/// The usable-scan reads a REAL sealed store and reaches its stranded arm.
///
/// `is_serviceable` is unit-tested on hand-built credentials, which proves the
/// predicate and nothing about whether the scan wires it to the bytes on disk. This
/// seals records through the ordinary write path and reads them back through the
/// lease-free scan, so a scan that mislabelled every record -- or never called the
/// predicate -- fails here.
#[test]
fn the_usable_scan_reaches_its_stranded_arm_on_a_real_store() {
    use crate::usable::{scan, Usability};

    let (root, store) = tmp_store(41);
    store.create("good:oauth", &oauth_record()).expect("create");

    // An OAuth record with neither token: the state that needs an operator login
    // and that no metadata read can see.
    let mut dead = oauth_record();
    if let Some(o) = dead.oauth.as_mut() {
        o.access_token = String::new().into();
        o.refresh_token = String::new().into();
    }
    store.create("dead:oauth", &dead).expect("create stranded");

    // tmp_store derives its key from the seed, so the scan can reconstruct the
    // same one without an accessor that would exist only for tests.
    let key = MasterKey::from_bytes([41u8; MASTER_KEY_LEN]);
    drop(store); // release the single-writer lease before the read-only open

    let conn = crate::usable::open_store_read_only(&root.join("store.db")).expect("open ro");
    let rows = scan(&conn, &key).expect("scan");

    let dead_row = rows
        .iter()
        .find(|r| r.credential_id == "dead:oauth")
        .expect("the stranded record is in the report");
    assert_eq!(
        dead_row.usability,
        Usability::Stranded,
        "an oauth record with neither token is stranded"
    );

    // DISAMBIGUATOR: a scan that marked everything stranded would satisfy the
    // assertion above. The healthy record must come back serviceable.
    let good_row = rows
        .iter()
        .find(|r| r.credential_id == "good:oauth")
        .expect("the healthy record is in the report");
    assert!(
        matches!(good_row.usability, Usability::Serviceable { .. }),
        "a record with both tokens is serviceable, got {:?}",
        good_row.usability
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn create_then_get_round_trips() {
    let (root, store) = tmp_store(1);
    store
        .create("opencode:anthropic", &oauth_record())
        .expect("create");
    let got = store.get("opencode:anthropic").expect("get");
    assert_eq!(got.payload.expose(), b"payload-bytes");
    assert_eq!(got.record_version, 1);
    assert_eq!(got.oauth.unwrap().access_token.expose(), "access");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn create_only_rejects_duplicate() {
    let (root, store) = tmp_store(2);
    store.create("id", &oauth_record()).expect("first create");
    match store.create("id", &oauth_record()) {
        Err(StoreOpError::AlreadyExists) => {}
        other => panic!("expected AlreadyExists, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn create_accepts_a_supplied_openai_identity_when_the_claim_agrees() {
    use crate::record::RecordIdentity;

    let (root, store) = tmp_store(60);
    let record = openai_record("acct-same", b"token").with_identity(RecordIdentity {
        account_id: Some("acct-same".to_string()),
        email: Some("same@example.com".to_string()),
        org_name: None,
    });

    store
        .create("oauth:openai", &record)
        .expect("matching identity creates");

    assert_eq!(
        store
            .get("oauth:openai")
            .expect("read created record")
            .identity,
        record.identity
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn create_refuses_a_supplied_openai_identity_when_the_claim_differs_without_writing() {
    use crate::record::RecordIdentity;

    let (root, store) = tmp_store(61);
    let record = openai_record("acct-derived", b"token").with_identity(RecordIdentity {
        account_id: Some("acct-supplied".to_string()),
        email: Some("supplied@example.com".to_string()),
        org_name: None,
    });
    let tip_before = store.audit_tip().expect("read initial audit tip");

    let err = store
        .create("oauth:openai", &record)
        .expect_err("a supplied identity that contradicts the token claim must refuse");

    assert!(matches!(
        err,
        StoreOpError::SuppliedIdentityContradictsClaim {
            ref credential_id,
            ref supplied_account_id,
            ref derived_account_id,
        } if credential_id == "oauth:openai"
            && supplied_account_id == "acct-supplied"
            && derived_account_id == "acct-derived"
    ));
    assert!(
        err.to_string().contains("drop `--account-id`")
            && err
                .to_string()
                .contains("the token's own claim is authoritative"),
        "{err}"
    );
    assert!(matches!(
        store.get("oauth:openai"),
        Err(StoreOpError::NotFound)
    ));
    assert_eq!(
        store.audit_tip().expect("read audit tip after refusal"),
        tip_before,
        "a refused create must not advance the audit chain"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn create_accepts_a_supplied_identity_for_an_adapter_without_a_claim() {
    use crate::record::RecordIdentity;

    let (root, store) = tmp_store(62);
    let record = oauth_record().with_identity(RecordIdentity {
        account_id: Some("acct-anthropic".to_string()),
        email: Some("anthropic@example.com".to_string()),
        org_name: None,
    });

    store
        .create("oauth:anthropic", &record)
        .expect("non-derivable adapter keeps supplied identity behavior");
    assert_eq!(
        store
            .get("oauth:anthropic")
            .expect("read created record")
            .identity,
        record.identity
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn create_attaches_a_derived_openai_identity_when_none_is_supplied() {
    let (root, store) = tmp_store(63);
    store
        .create("oauth:openai", &openai_record("acct-derived", b"token"))
        .expect("create with a derivable claim");

    assert_eq!(
        store
            .get("oauth:openai")
            .expect("read created record")
            .identity
            .account_id
            .as_deref(),
        Some("acct-derived")
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn create_refuses_a_control_character_in_a_derived_openai_identity_without_writing() {
    let (root, store) = tmp_store(64);
    let record = openai_record("acct-\u{0007}", b"token");
    let tip_before = store.audit_tip().expect("read initial audit tip");

    let err = store
        .create("oauth:openai", &record)
        .expect_err("a derived identity must be validated before it is sealed");

    assert!(
        matches!(err, StoreOpError::Encode(ref message) if message.contains("control")),
        "expected identity validation error, got {err}"
    );
    assert!(matches!(
        store.get("oauth:openai"),
        Err(StoreOpError::NotFound)
    ));
    assert_eq!(
        store.audit_tip().expect("read audit tip after refusal"),
        tip_before,
        "a refused create must not advance the audit chain"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// `retire_and_revoke_all_audited` is the compound behind `ck auth logout`:
/// mark `retired`, clear any dangling intent, and revoke EVERY live handle, all in
/// one fenced transaction with both audit entries inside it.
///
/// The compound exists because doing it as two calls is crash-partial: a crash
/// between them leaves a dead credential still resolvable by handle — a token the
/// operator believes is withdrawn but which still serves. So the assertions below
/// pin all four effects TOGETHER, plus the reversibility that distinguishes logout
/// from `remove`: the row and its audit history survive.
#[test]
fn logout_retires_clears_intent_and_revokes_every_handle_atomically() {
    let (root, store) = tmp_store(2);
    store.create("out", &oauth_record()).expect("create out");
    store.create("keep", &oauth_record()).expect("create keep");
    // TWO live handles: "revoke all" is only meaningful past the first, and a loop
    // that stopped after one would otherwise pass.
    let live: Vec<_> = (0..2)
        .map(|_| {
            let h = mint_handle().expect("mint");
            store
                .put_handle_hash(&h.hash, "out", AuditCtx::vault(AuditOp::MintHandle))
                .expect("store handle");
            h.raw
        })
        .collect();
    let sibling = mint_handle().expect("mint");
    store
        .put_handle_hash(&sibling.hash, "keep", AuditCtx::vault(AuditOp::MintHandle))
        .expect("store sibling handle");
    store.open_intent("out", 1, "rhash").expect("open intent");

    let outcome = store
        .retire_and_revoke_all_audited("out", AuditCtx::admin(AuditOp::Invalidate))
        .expect("logout");
    assert_eq!(
        outcome.handles_revoked, 2,
        "every live handle must be revoked, not just one"
    );
    assert!(
        outcome.state_changed,
        "a live credential's state must report as changed"
    );

    // All four effects, together.
    assert_eq!(
        store.meta("out").expect("meta").state,
        RecordState::Retired,
        "logout must record an intentional retirement rather than a failure"
    );
    assert!(
        store.read_intent("out").expect("read intent").is_none(),
        "a dangling refresh intent must be cleared in the same transaction"
    );
    for (i, raw) in live.iter().enumerate() {
        assert!(
            matches!(store.resolve_handle(raw), Err(StoreOpError::NotFound)),
            "handle {i} must no longer resolve"
        );
    }
    // The sibling is untouched: logout is scoped to one credential.
    assert_eq!(store.meta("keep").expect("meta").state, RecordState::Active);
    assert_eq!(
        store
            .resolve_handle(&sibling.raw)
            .expect("sibling resolves"),
        "keep"
    );

    // REVERSIBILITY \u2014 what makes this `logout` and not `remove`: the row and its
    // history are still there, so a later replace restores service.
    let entries = store.read_audit(None).expect("read audit");
    assert!(
        entries
            .iter()
            .any(|e| e.op == "invalidate" && e.credential_id.as_deref() == Some("out")),
        "the invalidate must be audited"
    );
    assert!(
        entries
            .iter()
            .any(|e| e.op == "revoke_handle" && e.credential_id.as_deref() == Some("out")),
        "the handle revocation must be audited in the same transaction"
    );
    store
        .verify_audit_chain()
        .expect("chain verifies after logout");
    store
        .overwrite_unconditional_audited("out", &oauth_record(), AuditCtx::admin(AuditOp::Put))
        .expect("a logged-out credential can be restored");
    assert_eq!(
        store.meta("out").expect("meta").state,
        RecordState::Active,
        "logout must be reversible"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// Retiring a failed credential is an operator acknowledgement that clears the
/// health alarm without deleting the stored material.
#[test]
fn logout_retires_needs_reauth_and_clears_its_health_alarm() {
    let (root, store) = tmp_store(4);
    store.create("retire-me", &oauth_record()).expect("create");
    store.invalidate("retire-me").expect("invalidate");

    let before = crate::health::VaultHealth::summarize(
        &store.list_meta().expect("list before retirement"),
        0,
        false,
    );
    assert_eq!(before.status, crate::health::VaultHealthStatus::Degraded);

    let outcome = store
        .retire_and_revoke_all_audited("retire-me", AuditCtx::admin(AuditOp::Invalidate))
        .expect("retire needs_reauth");
    assert!(
        outcome.state_changed,
        "needs_reauth must transition to retired"
    );
    assert_eq!(
        store.meta("retire-me").expect("retired meta").state,
        RecordState::Retired
    );

    let after = crate::health::VaultHealth::summarize(
        &store.list_meta().expect("list after retirement"),
        0,
        false,
    );
    assert_eq!(after.status, crate::health::VaultHealthStatus::Ok);
    assert_eq!(after.retired_ids, vec!["retire-me".to_string()]);
    let _ = std::fs::remove_dir_all(&root);
}

/// `remove_audited` permanently deletes the row + intent + handle rows in one
/// fenced transaction, appends a `remove` audit entry, and frees the id for a
/// future create. A missing id is a loud NotFound, and removal must not disturb
/// other credentials.
#[test]
fn remove_deletes_row_handles_and_intent_and_frees_the_id() {
    let (root, store) = tmp_store(2);
    store.create("keep", &oauth_record()).expect("create keep");
    store.create("gone", &oauth_record()).expect("create gone");
    store
        .put_handle_hash("deadbeef", "gone", AuditCtx::vault(AuditOp::MintHandle))
        .expect("mint handle");
    store.open_intent("gone", 1, "rhash").expect("open intent");
    // Diagnostic events for both, so removal can be shown to take one and spare
    // the other. These are the only rows in the store with no other reclaim path:
    // the per-credential cap trims on INSERT, and a removed credential never gets
    // another insert.
    for id in ["gone", "keep"] {
        store
            .record_auth_event(
                id,
                AuthObservation {
                    kind: "consumer_report",
                    provider_status: Some(401),
                    detail: None,
                    reporter_source: None,
                    principal: None,
                },
                Some(1),
            )
            .expect("record event");
    }

    // Unknown id: loud NotFound, nothing audited for it.
    match store.remove_audited("nope", AuditCtx::vault(AuditOp::Remove)) {
        Err(StoreOpError::NotFound) => {}
        other => panic!("expected NotFound, got {other:?}"),
    }

    store
        .remove_audited("gone", AuditCtx::vault(AuditOp::Remove))
        .expect("remove");

    // Row gone, intent gone, handle unresolvable; sibling untouched.
    assert!(matches!(store.meta("gone"), Err(StoreOpError::NotFound)));
    assert!(store.read_intent("gone").expect("read intent").is_none());
    assert!(store.meta("keep").is_ok());
    // Diagnostics went with it, and ONLY its own: a removal that swept the table
    // would take the history of every credential still in service.
    let events = store.recent_auth_events(100).expect("read events");
    assert!(
        !events.iter().any(|e| e.credential_id == "gone"),
        "a removed credential's events must go with it -- nothing else can reclaim them"
    );
    assert_eq!(
        events.iter().filter(|e| e.credential_id == "keep").count(),
        1,
        "a sibling credential's events must survive the removal"
    );
    // The audit chain records the removal and still verifies end-to-end.
    let entries = store.read_audit(None).expect("read audit");
    let last = entries.last().expect("has entries");
    assert_eq!(last.op, "remove");
    assert_eq!(last.credential_id.as_deref(), Some("gone"));
    store
        .verify_audit_chain()
        .expect("chain verifies after remove");
    // The id is free for a NEW credential (fresh v1 chain).
    store.create("gone", &oauth_record()).expect("recreate");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn unconditional_overwrite_replaces_needs_reauth_record_and_keeps_handle() {
    let (root, store) = tmp_store(20);
    // A credential imported from the wrong source whose refresh token is dead:
    // mark it needs_reauth (as a failed refresh would), and mint a handle for it.
    store.create("opencode:google", &oauth_record()).unwrap();
    let h = mint_handle().unwrap();
    store
        .put_handle_hash(
            &h.hash,
            "opencode:google",
            AuditCtx::admin(AuditOp::MintHandle),
        )
        .unwrap();
    store.invalidate("opencode:google").unwrap();
    // A CAS overwrite cannot even read it (get on a needs_reauth row fails closed).
    assert!(matches!(
        store.get("opencode:google"),
        Err(StoreOpError::NeedsReauth)
    ));
    // The unconditional overwrite (the --replace path) replaces it regardless of
    // state, resets it to active, and is immediately gettable again.
    store
        .overwrite_unconditional_audited(
            "opencode:google",
            &oauth_record(),
            AuditCtx::admin(AuditOp::Import),
        )
        .unwrap();
    let rec = store.get("opencode:google").expect("active after replace");
    assert!(rec.record_version >= 2, "version bumped past the original");
    // The pre-existing handle STILL resolves to the same id — no re-mint needed.
    assert_eq!(
        store.resolve_handle(&h.raw).unwrap(),
        "opencode:google",
        "handle survives the replace"
    );
    // Replacing an ABSENT id is NotFound (not a silent create).
    assert!(matches!(
        store.overwrite_unconditional_audited(
            "nope",
            &oauth_record(),
            AuditCtx::admin(AuditOp::Import)
        ),
        Err(StoreOpError::NotFound)
    ));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn unconditional_overwrite_preserves_existing_identity_when_openai_claim_agrees() {
    use crate::record::RecordIdentity;

    let (root, store) = tmp_store(24);
    let existing = openai_record("acct-original", b"old-token").with_identity(RecordIdentity {
        account_id: Some("acct-original".to_string()),
        email: Some("original@example.com".to_string()),
        org_name: Some("Original Organization".to_string()),
    });
    store.create("oauth:openai", &existing).expect("create");

    store
        .overwrite_unconditional_audited(
            "oauth:openai",
            &openai_record("acct-original", b"rotated-token"),
            AuditCtx::admin(AuditOp::Import),
        )
        .expect("replace");

    assert_eq!(
        store.get("oauth:openai").expect("read").identity,
        existing.identity,
        "a token-only re-import must retain the account identity already attached to the id"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn unconditional_overwrite_refuses_to_preserve_identity_for_a_different_openai_account() {
    use crate::record::RecordIdentity;

    let (root, store) = tmp_store(57);
    let existing = openai_record("acct-retained", b"old-token").with_identity(RecordIdentity {
        account_id: Some("acct-retained".to_string()),
        email: Some("retained@example.com".to_string()),
        org_name: Some("Retained Organization".to_string()),
    });
    store.create("oauth:openai", &existing).expect("create");
    let before = store.get("oauth:openai").expect("read before replace");

    let err = store
        .overwrite_unconditional_audited(
            "oauth:openai",
            &openai_record("acct-incoming", b"new-token"),
            AuditCtx::admin(AuditOp::Import),
        )
        .expect_err("a different incoming account must be refused");

    let message = err.to_string();
    assert!(message.contains("acct-retained"), "{message}");
    assert!(message.contains("acct-incoming"), "{message}");
    assert!(message.contains("--account-id <new>"), "{message}");
    assert!(message.contains("--clear-identity"), "{message}");

    match err {
        StoreOpError::AccountIdentityMismatch {
            credential_id,
            retained_account_id,
            incoming_account_id,
        } => {
            assert_eq!(credential_id, "oauth:openai");
            assert_eq!(retained_account_id, "acct-retained");
            assert_eq!(incoming_account_id, "acct-incoming");
        }
        other => panic!("expected typed account mismatch, got {other}"),
    }
    let after = store.get("oauth:openai").expect("read after refusal");
    assert_eq!(
        after.record_version, before.record_version,
        "version changed"
    );
    assert_eq!(after.payload, before.payload, "token bytes changed");
    assert_eq!(after.oauth, before.oauth, "OAuth material changed");
    assert_eq!(after.identity, before.identity, "identity changed");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn unconditional_overwrite_preserves_identity_when_adapter_cannot_derive_an_account() {
    use crate::record::RecordIdentity;

    let (root, store) = tmp_store(58);
    let existing = oauth_record().with_identity(RecordIdentity {
        account_id: Some("acct-retained".to_string()),
        email: Some("retained@example.com".to_string()),
        org_name: None,
    });
    store.create("oauth:anthropic", &existing).expect("create");

    store
        .overwrite_unconditional_audited(
            "oauth:anthropic",
            &oauth_record(),
            AuditCtx::admin(AuditOp::Import),
        )
        .expect("an adapter without a live account claim keeps prior behavior");

    assert_eq!(
        store.get("oauth:anthropic").expect("read").identity,
        existing.identity
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn unconditional_overwrite_preserves_identity_when_openai_account_derivation_fails() {
    use crate::record::RecordIdentity;

    let (root, store) = tmp_store(59);
    let existing = openai_record("acct-retained", b"old-token").with_identity(RecordIdentity {
        account_id: Some("acct-retained".to_string()),
        email: Some("retained@example.com".to_string()),
        org_name: None,
    });
    store.create("oauth:openai", &existing).expect("create");
    let mut incoming = openai_record("unused", b"opaque-new-token");
    incoming.oauth.as_mut().expect("OAuth").access_token = "not-a-jwt".to_string().into();

    store
        .overwrite_unconditional_audited(
            "oauth:openai",
            &incoming,
            AuditCtx::admin(AuditOp::Import),
        )
        .expect("an undecodable incoming token cannot contradict the retained label");

    let after = store.get("oauth:openai").expect("read replacement");
    assert_eq!(after.payload.expose(), b"opaque-new-token");
    assert_eq!(after.identity, existing.identity);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn unconditional_overwrite_uses_explicit_identity_for_a_different_openai_account() {
    use crate::record::RecordIdentity;

    let (root, store) = tmp_store(25);
    let existing = openai_record("acct-original", b"old-token").with_identity(RecordIdentity {
        account_id: Some("acct-original".to_string()),
        email: Some("original@example.com".to_string()),
        org_name: None,
    });
    let incoming = openai_record("acct-replacement", b"new-token").with_identity(RecordIdentity {
        account_id: Some("acct-replacement".to_string()),
        email: Some("replacement@example.com".to_string()),
        org_name: Some("Replacement Organization".to_string()),
    });
    store.create("oauth:openai", &existing).expect("create");

    store
        .overwrite_unconditional_audited(
            "oauth:openai",
            &incoming,
            AuditCtx::admin(AuditOp::Import),
        )
        .expect("replace");

    assert_eq!(
        store.get("oauth:openai").expect("read").identity,
        incoming.identity,
        "explicit import identity must replace stale account metadata"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn unconditional_overwrite_keeps_an_identity_empty_when_both_records_lack_one() {
    let (root, store) = tmp_store(26);
    store
        .create("oauth:anthropic", &oauth_record())
        .expect("create");

    store
        .overwrite_unconditional_audited(
            "oauth:anthropic",
            &oauth_record(),
            AuditCtx::admin(AuditOp::Import),
        )
        .expect("replace");

    assert!(
        store
            .get("oauth:anthropic")
            .expect("read")
            .identity
            .is_empty(),
        "a replacement cannot synthesize identity where neither record supplied it"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn unconditional_overwrite_can_clear_identity_for_a_different_openai_account() {
    use crate::record::RecordIdentity;

    let (root, store) = tmp_store(27);
    let existing = openai_record("acct-original", b"old-token").with_identity(RecordIdentity {
        account_id: Some("acct-original".to_string()),
        email: Some("original@example.com".to_string()),
        org_name: None,
    });
    store.create("oauth:openai", &existing).expect("create");

    store
        .overwrite_unconditional_with_identity_policy_audited(
            "oauth:openai",
            &openai_record("acct-replacement", b"new-token"),
            false,
            AuditCtx::admin(AuditOp::Import),
        )
        .expect("replace with clear");

    assert!(
        store.get("oauth:openai").expect("read").identity.is_empty(),
        "an explicit clear must not be mistaken for token-only replace preservation"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn unconditional_overwrite_repairs_a_corrupt_record_without_inventing_identity() {
    use crate::record::RecordIdentity;

    let (root, store) = tmp_store(28);
    let existing = oauth_record().with_identity(RecordIdentity {
        account_id: Some("acct-original".to_string()),
        email: Some("original@example.com".to_string()),
        org_name: None,
    });
    store.create("oauth:anthropic", &existing).expect("create");
    store
        .with_raw_conn(|conn| {
            conn.execute(
                "UPDATE credentials SET envelope = X'00' WHERE credential_id = 'oauth:anthropic'",
                [],
            )
        })
        .expect("corrupt envelope");

    store
        .overwrite_unconditional_audited(
            "oauth:anthropic",
            &oauth_record(),
            AuditCtx::admin(AuditOp::Import),
        )
        .expect("repair replace");

    assert!(
        store
            .get("oauth:anthropic")
            .expect("read repaired record")
            .identity
            .is_empty(),
        "a corrupt record cannot supply identity, but it must not block token repair"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn identity_writes_reject_empty_and_control_character_account_ids() {
    use crate::record::RecordIdentity;

    let (root, store) = tmp_store(56);
    store
        .create("oauth:anthropic", &oauth_record())
        .expect("seed record");
    let empty = store
        .set_identity_audited(
            "oauth:anthropic",
            RecordIdentity {
                account_id: Some(String::new()),
                email: None,
                org_name: None,
            },
            AuditCtx::admin(AuditOp::SetIdentity),
        )
        .expect_err("empty account id must be rejected at the store sink");
    assert!(
        matches!(empty, StoreOpError::Encode(ref message) if message.contains("account_id")),
        "the returned error must name the invalid non-secret field: {empty}"
    );

    let control_record = oauth_record().with_identity(RecordIdentity {
        account_id: Some("acct\u{0007}bad".to_string()),
        email: None,
        org_name: None,
    });
    let control = store
        .overwrite_unconditional_audited(
            "oauth:anthropic",
            &control_record,
            AuditCtx::admin(AuditOp::Import),
        )
        .expect_err("control characters must be rejected for replacement identity too");
    assert!(
        matches!(control, StoreOpError::Encode(ref message) if message.contains("account_id")),
        "the returned error must name the invalid non-secret field: {control}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn set_identity_reseals_same_oauth_material_and_audits_the_metadata_change() {
    use crate::record::RecordIdentity;

    let (root, store) = tmp_store(29);
    let existing = oauth_record();
    let payload_before = existing.payload.clone();
    let oauth_before = existing.oauth.clone();
    store.create("oauth:anthropic", &existing).expect("create");
    let handle = mint_handle().expect("mint handle");
    store
        .put_handle_hash(
            &handle.hash,
            "oauth:anthropic",
            AuditCtx::admin(AuditOp::MintHandle),
        )
        .expect("store handle");
    store
        .with_raw_conn(|conn| {
            conn.execute(
                "UPDATE credentials SET stale_pending = 1 WHERE credential_id = 'oauth:anthropic'",
                [],
            )
        })
        .expect("seed stale marker");
    let version_before = store.meta("oauth:anthropic").expect("meta").record_version;

    store
        .set_identity_audited(
            "oauth:anthropic",
            RecordIdentity {
                account_id: Some("acct-set".to_string()),
                email: Some("set@example.com".to_string()),
                org_name: Some("Set Organization".to_string()),
            },
            AuditCtx::admin(AuditOp::SetIdentity),
        )
        .expect("set identity");

    let record = store.get("oauth:anthropic").expect("read");
    let meta = store.meta("oauth:anthropic").expect("meta");
    assert_eq!(
        record.payload, payload_before,
        "identity must not rotate payload bytes"
    );
    assert_eq!(
        record.oauth, oauth_before,
        "identity must not replace OAuth material"
    );
    assert_eq!(record.identity.account_id.as_deref(), Some("acct-set"));
    assert_eq!(
        meta.state,
        RecordState::Active,
        "identity must not alter lifecycle state"
    );
    assert_eq!(
        meta.record_version,
        version_before + 1,
        "re-sealing advances version"
    );
    assert!(
        meta.stale_pending,
        "identity-only writes must not clear a consumer's pending refresh verdict"
    );
    assert_eq!(
        store.resolve_handle(&handle.raw).expect("resolve handle"),
        "oauth:anthropic",
        "identity-only writes must retain existing capability handles"
    );
    assert_eq!(
        store
            .read_audit(None)
            .expect("audit")
            .last()
            .expect("entry")
            .op,
        "set_identity"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn set_identity_allows_a_decryptable_needs_reauth_record() {
    use crate::record::RecordIdentity;

    let (root, store) = tmp_store(30);
    store
        .create("oauth:anthropic", &oauth_record())
        .expect("create");
    store.invalidate("oauth:anthropic").expect("invalidate");

    store
        .set_identity_audited(
            "oauth:anthropic",
            RecordIdentity {
                account_id: Some("acct-labelled".to_string()),
                email: None,
                org_name: None,
            },
            AuditCtx::admin(AuditOp::SetIdentity),
        )
        .expect("set identity while needs reauth");
    assert_eq!(
        store.meta("oauth:anthropic").expect("meta").state,
        RecordState::NeedsReauth,
        "identity metadata must not reactivate the credential"
    );
    store
        .reactivate_audited("oauth:anthropic", AuditCtx::admin(AuditOp::Reactivate))
        .expect("reactivate");
    assert_eq!(
        store
            .get("oauth:anthropic")
            .expect("read after reactivation")
            .identity
            .account_id
            .as_deref(),
        Some("acct-labelled")
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn replacement_normalizes_a_legacy_email_only_identity() {
    use crate::record::RecordIdentity;

    let (root, store) = tmp_store(57);
    let mut legacy = oauth_record();
    legacy.identity = RecordIdentity {
        account_id: None,
        email: Some("legacy@example.com".to_string()),
        org_name: None,
    };
    let blob = store
        .seal_record("oauth:anthropic", &legacy)
        .expect("seal legacy");
    store
        .create("oauth:anthropic", &oauth_record())
        .expect("seed");
    store
        .with_raw_conn(|conn| {
            conn.execute(
                "UPDATE credentials SET envelope = ?1 WHERE credential_id = 'oauth:anthropic'",
                rusqlite::params![blob],
            )
        })
        .expect("seed legacy envelope");
    store
        .overwrite_unconditional_audited(
            "oauth:anthropic",
            &oauth_record(),
            AuditCtx::admin(AuditOp::Import),
        )
        .expect("replace");
    assert!(
        store
            .get("oauth:anthropic")
            .expect("read")
            .identity
            .is_empty(),
        "legacy email-only metadata must not become a served identity"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn set_identity_returns_a_typed_corrupt_error_for_an_undecodable_envelope() {
    use crate::record::RecordIdentity;

    let (root, store) = tmp_store(58);
    store
        .create("oauth:anthropic", &oauth_record())
        .expect("seed");
    let blob = envelope::seal(
        &store.key,
        b"not a vault record",
        &RecordBinding {
            credential_id: "oauth:anthropic",
            record_version: 1,
        },
    )
    .expect("seal malformed body");
    store
        .with_raw_conn(|conn| {
            conn.execute(
                "UPDATE credentials SET envelope = ?1 WHERE credential_id = 'oauth:anthropic'",
                rusqlite::params![blob],
            )
        })
        .expect("seed malformed envelope");
    assert!(matches!(
        store.set_identity_audited(
            "oauth:anthropic",
            RecordIdentity {
                account_id: Some("acct".to_string()),
                email: None,
                org_name: None,
            },
            AuditCtx::admin(AuditOp::SetIdentity),
        ),
        Err(StoreOpError::Corrupt(_))
    ));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn set_identity_returns_a_typed_decrypt_error_for_invalid_ciphertext() {
    use crate::record::RecordIdentity;

    let (root, store) = tmp_store(59);
    store
        .create("oauth:anthropic", &oauth_record())
        .expect("seed");
    store
        .with_raw_conn(|conn| {
            conn.execute(
                "UPDATE credentials SET envelope = X'00' WHERE credential_id = 'oauth:anthropic'",
                [],
            )
        })
        .expect("seed invalid ciphertext");
    assert!(matches!(
        store.set_identity_audited(
            "oauth:anthropic",
            RecordIdentity {
                account_id: Some("acct".to_string()),
                email: None,
                org_name: None,
            },
            AuditCtx::admin(AuditOp::SetIdentity),
        ),
        Err(StoreOpError::Decrypt(_))
    ));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn empty_static_payload_is_rejected_before_any_write_or_audit() {
    let (_root, store) = tmp_store(42);
    let empty = VaultRecord::new_static(CredentialKind::ApiKey, "test", Vec::new(), None);

    let audit_before = store.read_audit(None).expect("audit before").len();
    assert!(store.create("apikey:empty", &empty).is_err());
    assert!(matches!(
        store.meta("apikey:empty"),
        Err(StoreOpError::NotFound)
    ));
    assert_eq!(
        store.read_audit(None).expect("audit after create").len(),
        audit_before
    );

    let valid =
        VaultRecord::new_static(CredentialKind::ApiKey, "test", b"non-empty".to_vec(), None);
    store.create("apikey:kept", &valid).expect("seed valid");
    let before = store.get("apikey:kept").expect("read seed");
    let audit_before_overwrites = store.read_audit(None).expect("audit seeded").len();

    assert!(store
        .overwrite_cas(
            "apikey:kept",
            &empty,
            &payload_hash(before.payload.expose()),
        )
        .is_err());
    let after_cas = store.get("apikey:kept").expect("read after CAS refusal");
    assert_eq!(after_cas.record_version, before.record_version);
    assert_eq!(after_cas.payload, before.payload);
    assert_eq!(
        store.read_audit(None).expect("audit after CAS").len(),
        audit_before_overwrites
    );

    assert!(store
        .overwrite_unconditional_audited("apikey:kept", &empty, AuditCtx::admin(AuditOp::Put),)
        .is_err());
    let after_unconditional = store
        .get("apikey:kept")
        .expect("read after unconditional refusal");
    assert_eq!(after_unconditional.record_version, before.record_version);
    assert_eq!(after_unconditional.payload, before.payload);
    assert_eq!(
        store
            .read_audit(None)
            .expect("audit after unconditional")
            .len(),
        audit_before_overwrites
    );
}

#[test]
fn refresh_only_oauth_record_may_be_stored_empty() {
    let (_root, store) = tmp_store(43);
    let record = VaultRecord::new_oauth(
        "import",
        "anthropic",
        OAuthCredential {
            access_token: String::new().into(),
            refresh_token: "refresh-only".to_string().into(),
            expires_at_ms: None,
            token_url: "https://t.test/token".into(),
            client_id: Some("c".into()),
            client_secret: None,
            scopes: vec![],
        },
        Vec::new(),
    );
    assert!(record.payload.expose().is_empty());
    assert!(!record
        .oauth
        .as_ref()
        .expect("oauth")
        .refresh_token
        .expose()
        .is_empty());

    store
        .create("oauth:refresh-only", &record)
        .expect("refresh-only OAuth must remain storable");
    assert!(store
        .get("oauth:refresh-only")
        .expect("read refresh-only")
        .payload
        .expose()
        .is_empty());
}

#[test]
fn version_gated_quarantine_cannot_poison_a_replacement() {
    let (_root, store) = tmp_store(44);
    let original =
        VaultRecord::new_static(CredentialKind::ApiKey, "test", b"original".to_vec(), None);
    store.create("apikey:race", &original).expect("seed");
    let replacement = VaultRecord::new_static(
        CredentialKind::ApiKey,
        "test",
        b"replacement".to_vec(),
        None,
    );
    store
        .overwrite_unconditional_audited("apikey:race", &replacement, AuditCtx::admin(AuditOp::Put))
        .expect("replace");

    assert!(!store
        .quarantine_if_version("apikey:race", 1)
        .expect("stale quarantine CAS"));
    let kept = store.get("apikey:race").expect("replacement stays active");
    assert_eq!(kept.record_version, 2);
    assert_eq!(kept.payload.expose(), b"replacement");
    assert!(store
        .quarantine_if_version("apikey:race", 2)
        .expect("current quarantine CAS"));
    assert_eq!(
        store.meta("apikey:race").expect("meta").state,
        RecordState::Corrupt
    );
}

#[test]
fn stale_failed_reads_do_not_quarantine_replacement_material() {
    let (_root, store) = tmp_store(151);
    store.create("id", &oauth_record()).unwrap();
    let incarnation = store.credential_incarnation("id").unwrap();
    let invalid_plaintext = envelope::seal(
        &store.key,
        b"not a record",
        &RecordBinding {
            credential_id: "id",
            record_version: 1,
        },
    );
    store
        .overwrite_unconditional_audited("id", &oauth_record(), AuditCtx::admin(AuditOp::Put))
        .unwrap();
    assert!(matches!(
        store.decode_record_row("id", (1, &incarnation), "active", 0, &[0, 1]),
        Err(StoreOpError::Decrypt(_))
    ));
    assert_eq!(store.meta("id").unwrap().state, RecordState::Active);
    let blob = invalid_plaintext.unwrap();
    assert!(matches!(
        store.decode_record_row("id", (1, &incarnation), "active", 0, &blob),
        Err(StoreOpError::Corrupt(_))
    ));
    assert_eq!(store.meta("id").unwrap().state, RecordState::Active);
}

#[test]
fn incarnation_failed_read_cannot_quarantine_a_recreated_version_one() {
    let (_root, store) = tmp_store(151);
    store.create("id", &oauth_record()).unwrap();
    let incarnation = store.credential_incarnation("id").unwrap();
    store
        .remove_audited("id", AuditCtx::admin(AuditOp::Remove))
        .unwrap();
    store.create("id", &oauth_record()).unwrap();
    assert!(matches!(
        store.decode_record_row("id", (1, &incarnation), "active", 0, &[0, 1]),
        Err(StoreOpError::NotFound)
    ));
    assert_eq!(store.meta("id").unwrap().state, RecordState::Active);
}

#[test]
fn consumer_reports_only_invalidate_active_records() {
    let (_root, store) = tmp_store(152);
    for state in [
        RecordState::Active,
        RecordState::NeedsReauth,
        RecordState::Retired,
        RecordState::Corrupt,
    ] {
        let id = state.as_str();
        store.create(id, &oauth_record()).unwrap();
        store
            .store
            .with_conn(|conn| {
                conn.execute(
                    "UPDATE credentials SET state = ?1 WHERE credential_id = ?2",
                    rusqlite::params![state.as_str(), id],
                )
            })
            .unwrap();
        let before = store.read_audit(None).unwrap().len();
        let applied = store
            .invalidate_if_version_reported(id, 1, AuditCtx::admin(AuditOp::Invalidate), None)
            .unwrap();
        assert_eq!(applied, state == RecordState::Active, "{state:?}");
        assert_eq!(
            store.meta(id).unwrap().state,
            if applied {
                RecordState::NeedsReauth
            } else {
                state
            }
        );
        assert_eq!(
            store.read_audit(None).unwrap().len(),
            before + usize::from(applied)
        );
        assert!(!store
            .invalidate_if_version_reported(id, 1, AuditCtx::admin(AuditOp::Invalidate), None)
            .unwrap());
        assert_eq!(
            store.read_audit(None).unwrap().len(),
            before + usize::from(applied)
        );
    }
}

#[test]
fn operator_invalidations_preserve_corrupt_and_audit_only_transitions() {
    let (_root, store) = tmp_store(153);
    store.create("id", &oauth_record()).unwrap();
    store.quarantine("id").unwrap();
    let before = store.read_audit(None).unwrap().len();
    store
        .invalidate_audited("id", AuditCtx::admin(AuditOp::Invalidate))
        .unwrap();
    assert_eq!(store.meta("id").unwrap().state, RecordState::Corrupt);
    let outcome = store
        .invalidate_and_revoke_all_audited("id", AuditCtx::admin(AuditOp::Invalidate))
        .unwrap();
    assert!(!outcome.state_changed);
    assert_eq!(store.meta("id").unwrap().state, RecordState::Corrupt);
    assert_eq!(store.read_audit(None).unwrap().len(), before);
    store.create("live", &oauth_record()).unwrap();
    store
        .invalidate_audited("live", AuditCtx::admin(AuditOp::Invalidate))
        .unwrap();
    let after = store.read_audit(None).unwrap().len();
    store
        .invalidate_audited("live", AuditCtx::admin(AuditOp::Invalidate))
        .unwrap();
    assert_eq!(store.read_audit(None).unwrap().len(), after);
}

#[test]
fn replacement_refuses_explicit_identity_that_contradicts_claim() {
    let (_root, store) = tmp_store(154);
    store
        .create("oauth:openai", &openai_record("original", b"old"))
        .unwrap();
    let incoming = openai_record("claimed", b"new").with_identity(crate::record::RecordIdentity {
        account_id: Some("supplied".into()),
        ..Default::default()
    });
    let before = store.read_audit(None).unwrap().len();
    for preserve in [true, false] {
        assert!(matches!(
            store.overwrite_unconditional_with_identity_policy_audited(
                "oauth:openai",
                &incoming,
                preserve,
                AuditCtx::admin(AuditOp::Put)
            ),
            Err(StoreOpError::SuppliedIdentityContradictsClaim { .. })
        ));
    }
    assert_eq!(store.get("oauth:openai").unwrap().record_version, 1);
    assert_eq!(store.read_audit(None).unwrap().len(), before);
}

#[test]
fn cas_overwrite_refuses_explicit_identity_that_contradicts_claim() {
    let (_dir, store) = tmp_store(154);
    let id = "oauth:openai";
    let initial = openai_record("original", b"old");
    store.create(id, &initial).unwrap();
    let incoming = openai_record("claimed", b"new").with_identity(crate::record::RecordIdentity {
        account_id: Some("supplied".into()),
        ..Default::default()
    });
    let before = store.read_audit(None).unwrap().len();
    assert!(matches!(
        store.overwrite_cas_audited(
            id,
            &incoming,
            &payload_hash(initial.payload.expose()),
            AuditCtx::admin(AuditOp::Put)
        ),
        Err(StoreOpError::SuppliedIdentityContradictsClaim { .. })
    ));
    assert_eq!(store.meta(id).unwrap().record_version, 1);
    assert_eq!(store.read_audit(None).unwrap().len(), before);
}

#[test]
fn refresh_commit_cannot_restore_non_active_records() {
    let (_root, store) = tmp_store(155);
    for state in [
        RecordState::NeedsReauth,
        RecordState::Retired,
        RecordState::Corrupt,
    ] {
        let id = state.as_str();
        store.create(id, &oauth_record()).unwrap();
        store.open_intent(id, 1, "old-hash").unwrap();
        store
            .store
            .with_conn(|conn| {
                conn.execute(
                    "UPDATE credentials SET state = ?1 WHERE credential_id = ?2",
                    rusqlite::params![state.as_str(), id],
                )
            })
            .unwrap();
        let before = store.read_audit(None).unwrap().len();
        assert!(matches!(
            store.commit_refresh(
                id,
                1,
                &store.credential_incarnation(id).unwrap(),
                &oauth_record(),
                None
            ),
            Err(StoreOpError::CasMismatch)
        ));
        assert_eq!(store.meta(id).unwrap().state, state);
        assert_eq!(store.meta(id).unwrap().record_version, 1);
        assert!(store.read_intent(id).unwrap().is_some());
        assert_eq!(store.read_audit(None).unwrap().len(), before);
    }
    store.create("active", &oauth_record()).unwrap();
    store.open_intent("active", 1, "old-hash").unwrap();
    assert_eq!(
        store
            .commit_refresh(
                "active",
                1,
                &store.credential_incarnation("active").unwrap(),
                &oauth_record(),
                None
            )
            .unwrap(),
        2
    );
    assert!(store.read_intent("active").unwrap().is_none());
}

#[test]
fn removal_reports_only_live_handles_and_revoke_all_is_idempotent() {
    let (_root, store) = tmp_store(156);
    store.create("id", &oauth_record()).unwrap();
    let revoked = mint_handle().unwrap();
    let live = mint_handle().unwrap();
    for handle in [&revoked, &live] {
        store
            .put_handle_hash(&handle.hash, "id", AuditCtx::admin(AuditOp::MintHandle))
            .unwrap();
    }
    store
        .revoke_handle(&revoked.raw, AuditCtx::admin(AuditOp::RevokeHandle))
        .unwrap();
    assert_eq!(
        store
            .remove_audited("id", AuditCtx::admin(AuditOp::Remove))
            .unwrap(),
        1
    );
    assert!(matches!(
        store.resolve_handle(&live.raw),
        Err(StoreOpError::NotFound)
    ));
    let before = store.read_audit(None).unwrap().len();
    assert_eq!(
        store
            .revoke_all_handles("absent", AuditCtx::admin(AuditOp::RevokeHandle))
            .unwrap(),
        0
    );
    assert_eq!(store.read_audit(None).unwrap().len(), before);
    store.create("live", &oauth_record()).unwrap();
    let handle = mint_handle().unwrap();
    store
        .put_handle_hash(&handle.hash, "live", AuditCtx::admin(AuditOp::MintHandle))
        .unwrap();
    assert_eq!(
        store
            .revoke_all_handles("live", AuditCtx::admin(AuditOp::RevokeHandle))
            .unwrap(),
        1
    );
    let after = store.read_audit(None).unwrap().len();
    assert_eq!(
        store
            .revoke_all_handles("live", AuditCtx::admin(AuditOp::RevokeHandle))
            .unwrap(),
        0
    );
    assert_eq!(store.read_audit(None).unwrap().len(), after);
}

#[test]
fn get_missing_is_not_found() {
    let (root, store) = tmp_store(3);
    match store.get("absent") {
        Err(StoreOpError::NotFound) => {}
        other => panic!("expected NotFound, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn overwrite_cas_matches_and_bumps_version() {
    let (root, store) = tmp_store(4);
    store.create("id", &oauth_record()).expect("create");
    let cur = store.get("id").expect("get");
    let expect = payload_hash(cur.payload.expose());
    let mut next = oauth_record();
    next.payload = b"new-payload".to_vec().into();
    store.overwrite_cas("id", &next, &expect).expect("cas ok");
    let got = store.get("id").expect("get after cas");
    assert_eq!(got.payload.expose(), b"new-payload");
    assert_eq!(got.record_version, 2, "version bumped on overwrite");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn overwrite_cas_mismatch_rejected() {
    let (root, store) = tmp_store(5);
    store.create("id", &oauth_record()).expect("create");
    let wrong = payload_hash(b"not the current payload");
    match store.overwrite_cas("id", &oauth_record(), &wrong) {
        Err(StoreOpError::CasMismatch) => {}
        other => panic!("expected CasMismatch, got {other:?}"),
    }
    // The record is unchanged after a rejected CAS.
    assert_eq!(store.get("id").unwrap().record_version, 1);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn invalidate_marks_needs_reauth() {
    let (root, store) = tmp_store(6);
    store.create("id", &oauth_record()).expect("create");
    store.invalidate("id").expect("invalidate");
    match store.get("id") {
        Err(StoreOpError::NeedsReauth) => {}
        other => panic!("expected NeedsReauth, got {other:?}"),
    }
    assert_eq!(store.meta("id").unwrap().state, RecordState::NeedsReauth);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn corrupt_envelope_quarantines_only_that_record() {
    let (root, store) = tmp_store(7);
    store.create("good", &oauth_record()).expect("create good");
    store.create("bad", &oauth_record()).expect("create bad");
    // Corrupt the 'bad' row's ciphertext directly (simulate at-rest damage).
    store
        .store
        .with_conn(|c| {
            c.execute(
                "UPDATE credentials SET envelope = X'00010203' WHERE credential_id = 'bad'",
                [],
            )
        })
        .expect("corrupt bad");
    // 'bad' fails closed and is quarantined; 'good' still serves.
    match store.get("bad") {
        Err(StoreOpError::Decrypt(_)) => {}
        other => panic!("expected Decrypt, got {other:?}"),
    }
    assert_eq!(
        store.meta("bad").unwrap().state,
        RecordState::Corrupt,
        "bad row quarantined"
    );
    // A second get on the now-quarantined row is a clean Quarantined error.
    match store.get("bad") {
        Err(StoreOpError::Quarantined) => {}
        other => panic!("expected Quarantined on re-get, got {other:?}"),
    }
    assert_eq!(
        store.get("good").unwrap().payload.expose(),
        b"payload-bytes",
        "good still serves"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn wrong_key_fails_closed_at_open() {
    // A vault sealed under one key, then OPENED with a DIFFERENT key: the wrong
    // key fails to decrypt the sealed audit key, so open() itself fails closed
    // (KeyMismatch) — the vault never opens under the wrong key, and nothing
    // panics. This is stronger than the old per-record check: a wrong key is
    // rejected up front, before any credential is touched.
    let (root, store) = tmp_store(8);
    store.create("id", &oauth_record()).expect("create");
    let db_path = root.join("store.db");

    // Release the first store's single-writer lease before re-opening, then
    // re-open the same database under a different master key.
    drop(store);
    let descriptor = StorageDescriptor {
        module_id: "cortexkit-credentials".into(),
        storage_namespace: "vault".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: db_path.to_string_lossy().into_owned(),
        },
    };
    let reopened = open_sqlite(&descriptor).expect("reopen");
    let result = EncryptedStore::open(reopened, MasterKey::from_bytes([0xEE; MASTER_KEY_LEN]));
    match result {
        Err(StoreOpError::Decrypt(EnvelopeError::KeyMismatch { .. })) => {}
        Err(other) => panic!("expected KeyMismatch at open under wrong key, got {other:?}"),
        Ok(_) => panic!("expected open to fail closed under the wrong key"),
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn list_meta_reports_without_decrypt() {
    let (root, store) = tmp_store(9);
    store.create("a", &oauth_record()).expect("a");
    store.create("b", &oauth_record()).expect("b");
    store.invalidate("b").expect("invalidate b");
    let metas = store.list_meta().expect("list");
    assert_eq!(metas.len(), 2);
    let by_id: std::collections::HashMap<_, _> = metas.into_iter().collect();
    assert_eq!(by_id["a"].state, RecordState::Active);
    assert_eq!(by_id["b"].state, RecordState::NeedsReauth);
    assert_eq!(by_id["a"].key_id_hex, store.key_id().to_hex());
    let _ = std::fs::remove_dir_all(&root);
}

// AN UNKNOWN HANDLE MUST BE DISTINGUISHABLE FROM A REAL ONE ON THE ADMIN PATH.
//
// The false assurance this closes: the CLI printed one success line for a live handle,
// an already-revoked one, and one that never existed. An operator who pasted a
// truncated handle was told a bearer credential was dead while it kept serving -- and
// a capability handle is exactly the thing whose deadness must never be guessed.
//
// DELIBERATELY NOT THE READ-SURFACE RULE. `credential.get` answers identically for
// revoked and unknown handles because its callers are strangers holding bearer tokens
// and the difference is an enumeration oracle. This path is master-key gated: a caller
// who reaches it can already read the whole store, so the distinction gives away
// nothing and withholding it costs the operator the one fact they asked for.
#[test]
fn revoking_an_unknown_handle_is_distinguishable_from_revoking_a_real_one() {
    let (root, store) = tmp_store(11);
    store.create("opencode:anthropic", &oauth_record()).unwrap();
    let h = mint_handle().expect("mint");
    store
        .put_handle_hash(
            &h.hash,
            "opencode:anthropic",
            AuditCtx::admin(AuditOp::MintHandle),
        )
        .unwrap();

    let real = store
        .revoke_handle(&h.raw, AuditCtx::admin(AuditOp::RevokeHandle))
        .expect("revoke real");
    assert_eq!(
        real.as_deref(),
        Some("opencode:anthropic"),
        "a real revocation must name the credential that lost the door"
    );

    let unknown = store
        .revoke_handle(
            "ckh_not-a-real-handle",
            AuditCtx::admin(AuditOp::RevokeHandle),
        )
        .expect("revoke unknown");
    assert!(
        unknown.is_none(),
        "an unknown handle must report that nothing matched, not a success"
    );

    // A repeated revoke is not another state transition.
    let again = store
        .revoke_handle(&h.raw, AuditCtx::admin(AuditOp::RevokeHandle))
        .expect("revoke again");
    assert_eq!(again, None);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn hash_revoke_is_targeted_attributed_and_idempotent() {
    let (_root, store) = tmp_store(110);
    store.create("opencode:anthropic", &oauth_record()).unwrap();
    let handles = [mint_handle().unwrap(), mint_handle().unwrap()];
    for h in &handles {
        store
            .put_handle_hash(
                &h.hash,
                "opencode:anthropic",
                AuditCtx::admin(AuditOp::MintHandle),
            )
            .unwrap();
    }
    let before = store.read_audit(None).unwrap().len();
    assert_eq!(
        store
            .revoke_handle_by_hash_audited(&handles[0].hash, AuditCtx::admin(AuditOp::RevokeHandle))
            .unwrap()
            .as_deref(),
        Some("opencode:anthropic")
    );
    assert!(matches!(
        store.resolve_handle(&handles[0].raw),
        Err(StoreOpError::NotFound)
    ));
    assert_eq!(
        store.resolve_handle(&handles[1].raw).unwrap(),
        "opencode:anthropic"
    );
    for (index, h) in handles.iter().enumerate() {
        let revoked: i64 = store
            .store
            .with_conn(|conn| {
                conn.query_row(
                    "SELECT revoked FROM handles WHERE handle_hash = ?1",
                    [&h.hash],
                    |row| row.get(0),
                )
            })
            .unwrap();
        assert_eq!(revoked, if index == 0 { 1 } else { 0 });
    }
    let entries = store.read_audit(None).unwrap();
    assert_eq!(entries.len(), before + 1);
    let revokes: Vec<_> = entries.iter().filter(|e| e.op == "revoke_handle").collect();
    assert_eq!(revokes.len(), 1);
    assert_eq!(
        revokes[0].credential_id.as_deref(),
        Some("opencode:anthropic")
    );
    let repeat = store
        .revoke_handle_by_hash_audited(&handles[0].hash, AuditCtx::admin(AuditOp::RevokeHandle))
        .unwrap();
    assert_eq!(
        store.read_audit(None).unwrap().len(),
        before + 1,
        "repeat must not grow audit"
    );
    assert_eq!(repeat, None);
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[test]
fn raw_revoke_repeat_does_not_append_audit() {
    let (_root, store) = tmp_store(111);
    store.create("opencode:anthropic", &oauth_record()).unwrap();
    let h = mint_handle().unwrap();
    store
        .put_handle_hash(
            &h.hash,
            "opencode:anthropic",
            AuditCtx::admin(AuditOp::MintHandle),
        )
        .unwrap();
    assert!(store
        .revoke_handle(&h.raw, AuditCtx::admin(AuditOp::RevokeHandle))
        .unwrap()
        .is_some());
    let before = store.read_audit(None).unwrap().len();
    let repeat = store
        .revoke_handle(&h.raw, AuditCtx::admin(AuditOp::RevokeHandle))
        .unwrap();
    assert_eq!(
        store.read_audit(None).unwrap().len(),
        before,
        "repeat must not grow audit"
    );
    assert_eq!(repeat, None);
}

#[test]
fn hash_revoke_unknown_and_malformed_do_not_append_audit() {
    let (_root, store) = tmp_store(112);
    let before = store.read_audit(None).unwrap().len();
    assert_eq!(
        store
            .revoke_handle_by_hash_audited(&"a".repeat(64), AuditCtx::admin(AuditOp::RevokeHandle))
            .unwrap(),
        None
    );
    for hash in ["a".repeat(63), "A".repeat(64)] {
        assert!(store
            .revoke_handle_by_hash_audited(&hash, AuditCtx::admin(AuditOp::RevokeHandle))
            .is_err());
    }
    assert_eq!(store.read_audit(None).unwrap().len(), before);
}

/// The predecessor query must exclude the handle just minted, exclude revoked
/// rows, stay inside its own credential, and order newest first.
///
/// Every one of those four is a way the advisory could mislead rather than help:
/// including self makes a first mint look like a replacement, including revoked
/// rows tells an operator to revoke a dead door, crossing credentials names
/// somebody else's handle as theirs to kill, and wrong order buries the likely
/// predecessor under older ones.
#[test]
fn predecessor_query_excludes_self_revoked_and_other_credentials() {
    let (root, store) = tmp_store(114);
    let path = root.path().join("store.db");
    store.create("apikey:a", &oauth_record()).unwrap();
    store.create("apikey:b", &oauth_record()).unwrap();

    let first = mint_handle().unwrap();
    let second = mint_handle().unwrap();
    let dead = mint_handle().unwrap();
    let elsewhere = mint_handle().unwrap();
    for (h, id) in [
        (&first, "apikey:a"),
        (&second, "apikey:a"),
        (&dead, "apikey:a"),
        (&elsewhere, "apikey:b"),
    ] {
        store
            .put_handle_hash(&h.hash, id, AuditCtx::admin(AuditOp::MintHandle))
            .unwrap();
    }
    store
        .revoke_handle(&dead.raw, AuditCtx::admin(AuditOp::RevokeHandle))
        .unwrap();

    // A FIRST mint has no predecessor: asking about the only handle must be empty,
    // which is the arm that keeps the advisory silent.
    let (only_root, only_store) = tmp_store(115);
    only_store.create("apikey:a", &oauth_record()).unwrap();
    let lone = mint_handle().unwrap();
    only_store
        .put_handle_hash(&lone.hash, "apikey:a", AuditCtx::admin(AuditOp::MintHandle))
        .unwrap();
    assert!(
        other_live_handles_read_only(&only_root.path().join("store.db"), "apikey:a", &lone.hash)
            .unwrap()
            .is_empty(),
        "a credential's only handle must not be reported as its own predecessor"
    );

    let got = other_live_handles_read_only(&path, "apikey:a", &second.hash).unwrap();
    let hashes: Vec<&str> = got.iter().map(|(h, _)| h.as_str()).collect();
    assert_eq!(
        hashes,
        vec![first.hash.as_str()],
        "expected only the live sibling on this credential: self excluded, revoked \
             excluded, other credential excluded"
    );
    assert_ne!(
        hashes.first().copied(),
        Some(dead.hash.as_str()),
        "a revoked handle must never be offered for revocation"
    );
    assert_ne!(
        hashes.first().copied(),
        Some(elsewhere.hash.as_str()),
        "a handle on another credential must never be named here"
    );

    // Ordering: with two live siblings the newest comes first.
    let third = mint_handle().unwrap();
    store
        .put_handle_hash(
            &third.hash,
            "apikey:a",
            AuditCtx::admin(AuditOp::MintHandle),
        )
        .unwrap();
    let ordered = other_live_handles_read_only(&path, "apikey:a", &second.hash).unwrap();
    assert_eq!(ordered.len(), 2);
    assert!(
        ordered[0].1 >= ordered[1].1,
        "newest first, so the likeliest predecessor is not buried"
    );
}

/// A minted handle must be traceable to its mint by the SAME join that already
/// works for revocations, so an operator auditing live bearer material can name
/// the actor and the moment for each one.
///
/// The second arm is the load-bearing half: it asserts the row carries the hash
/// of THIS handle rather than merely a non-null value, so filling the field with
/// anything else still fails. Without it the test passes on a mint that records
/// the wrong door.
#[test]
fn a_mint_names_the_handle_it_created() {
    let (_root, store) = tmp_store(113);
    store.create("opencode:anthropic", &oauth_record()).unwrap();
    let mine = mint_handle().unwrap();
    let other = mint_handle().unwrap();
    store
        .put_handle_hash(
            &mine.hash,
            "opencode:anthropic",
            AuditCtx::admin(AuditOp::MintHandle),
        )
        .unwrap();

    let mint = store
        .read_audit(None)
        .unwrap()
        .into_iter()
        .find(|e| e.op == AuditOp::MintHandle.as_str())
        .expect("the mint is in the chain");
    assert_eq!(
        mint.payload_hash.as_deref(),
        Some(mine.hash.as_str()),
        "the mint row must carry THIS handle's hash, so it joins handles.handle_hash"
    );
    assert_ne!(
        mint.payload_hash.as_deref(),
        Some(other.hash.as_str()),
        "a mint must not be attributable to a handle it did not create"
    );
    assert_eq!(mint.credential_id.as_deref(), Some("opencode:anthropic"));
}

#[test]
fn handle_mint_resolve_revoke() {
    let (root, store) = tmp_store(10);
    store.create("opencode:anthropic", &oauth_record()).unwrap();
    let h = mint_handle().expect("mint");
    assert!(h.raw.starts_with("ckh_"));
    assert_eq!(h.hash, handle_hash(&h.raw));
    store
        .put_handle_hash(
            &h.hash,
            "opencode:anthropic",
            AuditCtx::admin(AuditOp::MintHandle),
        )
        .unwrap();
    // Resolve maps the raw handle to its credential id.
    assert_eq!(store.resolve_handle(&h.raw).unwrap(), "opencode:anthropic");
    // Revoke makes it resolve to NotFound (uniform with an unknown handle).
    store
        .revoke_handle(&h.raw, AuditCtx::admin(AuditOp::RevokeHandle))
        .unwrap();
    assert!(matches!(
        store.resolve_handle(&h.raw),
        Err(StoreOpError::NotFound)
    ));
    // An unknown handle is also NotFound (no distinction leaked).
    assert!(matches!(
        store.resolve_handle("ckh_bogus"),
        Err(StoreOpError::NotFound)
    ));
    // The mint and the revoke are BOTH recorded in the tamper-evident audit chain
    // (atomically, in their own fenced txns), and the chain still verifies.
    let entries = store.read_audit(None).unwrap();
    let ops: Vec<&str> = entries.iter().map(|e| e.op.as_str()).collect();
    assert!(ops.contains(&"mint_handle"), "mint audited: {ops:?}");
    assert!(ops.contains(&"revoke_handle"), "revoke audited: {ops:?}");
    assert_eq!(
        store.verify_audit_chain().unwrap(),
        None,
        "chain intact after mint+revoke"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn revoke_all_handles_for_credential() {
    let (root, store) = tmp_store(11);
    store.create("id", &oauth_record()).unwrap();
    let h1 = mint_handle().unwrap();
    let h2 = mint_handle().unwrap();
    store
        .put_handle_hash(&h1.hash, "id", AuditCtx::admin(AuditOp::MintHandle))
        .unwrap();
    store
        .put_handle_hash(&h2.hash, "id", AuditCtx::admin(AuditOp::MintHandle))
        .unwrap();
    let n = store
        .revoke_all_handles("id", AuditCtx::admin(AuditOp::RevokeHandle))
        .unwrap();
    assert_eq!(n, 2, "both handles revoked");
    assert!(matches!(
        store.resolve_handle(&h1.raw),
        Err(StoreOpError::NotFound)
    ));
    assert!(matches!(
        store.resolve_handle(&h2.raw),
        Err(StoreOpError::NotFound)
    ));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn audit_chain_appends_and_verifies() {
    let (root, store) = tmp_store(12);
    let e1 = store
        .append_audit(&AuditRecord {
            op: crate::audit::AuditOp::Put,
            credential_id: Some("id".into()),
            payload_hash: Some("abcd".into()),
            actor: "offline-cli".into(),
            alarm: None,
        })
        .expect("append 1");
    assert_eq!(e1.seq, 1);
    assert_eq!(e1.prev_mac, crate::audit::GENESIS_MAC);
    let e2 = store
        .append_audit(&AuditRecord {
            op: crate::audit::AuditOp::Overwrite,
            credential_id: Some("id".into()),
            payload_hash: Some("ef01".into()),
            actor: "offline-cli".into(),
            alarm: Some(AlarmReason::OverwriteWithoutCas),
        })
        .expect("append 2");
    assert_eq!(e2.seq, 2);
    assert_eq!(e2.prev_mac, e1.entry_mac, "chain links");
    assert!(e2.alarm);
    // The full chain verifies under the store's master-key-derived audit key.
    assert_eq!(store.verify_audit_chain().unwrap(), None);
    // read_audit returns chain order, oldest first.
    let all = store.read_audit(None).unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].seq, 1);
    assert_eq!(all[1].seq, 2);
    let _ = std::fs::remove_dir_all(&root);
}

/// Revocation audit rows identify the credential whose state changed;
/// an unknown handle changes no state and must not grow the durable chain.
#[test]
fn a_revocation_names_the_credential_that_lost_a_door() {
    let (_root, store) = tmp_store(41);
    let ctx = AuditCtx::vault(AuditOp::MintHandle);
    store.create("attrib", &oauth_record()).expect("create");
    let h = mint_handle().expect("mint");
    store.put_handle_hash(&h.hash, "attrib", ctx).expect("mint");

    store
        .revoke_handle(&h.raw, AuditCtx::vault(AuditOp::RevokeHandle))
        .expect("revoke");
    let entries = store.read_audit(None).expect("read chain");
    let revoked: Vec<_> = entries.iter().filter(|e| e.op == "revoke_handle").collect();
    assert_eq!(revoked.len(), 1, "one revocation recorded");
    assert_eq!(
        revoked[0].credential_id.as_deref(),
        Some("attrib"),
        "the chain must name which credential lost access; without it a rotation's \
             blast radius is not reconstructable from the chain alone"
    );

    store
        .revoke_handle(
            "ckh_this-handle-never-existed",
            AuditCtx::vault(AuditOp::RevokeHandle),
        )
        .expect("idempotent on an unknown handle");
    let entries = store.read_audit(None).expect("read chain");
    let revoked: Vec<_> = entries.iter().filter(|e| e.op == "revoke_handle").collect();
    assert_eq!(
        revoked.len(),
        1,
        "a no-op must not append another audit row"
    );
}

#[test]
fn audit_tip_pair_exposes_tail_truncation_with_reused_sequence() {
    let (root, store) = tmp_store(21);
    store
        .append_audit(&AuditRecord {
            op: crate::audit::AuditOp::Put,
            credential_id: Some("id".into()),
            payload_hash: Some("first".into()),
            actor: "offline-cli".into(),
            alarm: None,
        })
        .expect("append first");
    let tail = store
        .append_audit(&AuditRecord {
            op: crate::audit::AuditOp::Overwrite,
            credential_id: Some("id".into()),
            payload_hash: Some("original-tail".into()),
            actor: "offline-cli".into(),
            alarm: None,
        })
        .expect("append original tail");
    let observed = (tail.seq, tail.entry_mac.clone());

    let conn = rusqlite::Connection::open(root.join("store.db")).expect("open raw store");
    conn.execute("DELETE FROM audit_log WHERE seq = ?1", [tail.seq])
        .expect("delete tail");
    drop(conn);

    let replacement = store
        .append_audit(&AuditRecord {
            op: crate::audit::AuditOp::Overwrite,
            credential_id: Some("id".into()),
            payload_hash: Some("replacement-tail".into()),
            actor: "fresh-legitimate-writer".into(),
            alarm: None,
        })
        .expect("append replacement tail");

    assert_eq!(
        replacement.seq, observed.0,
        "deletion plus a fresh append can return the sequence to its old value"
    );
    assert_ne!(
        replacement.entry_mac, observed.1,
        "the MAC at a reused sequence must reveal that the row bytes changed"
    );
    assert_eq!(
        store.audit_tip().expect("read tip").expect("tip exists"),
        (replacement.seq, replacement.entry_mac)
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn rotate_master_key_rewraps_and_chain_stays_verifiable() {
    let (root, mut store) = tmp_store(20);
    store.create("a", &oauth_record()).expect("create a");
    store.create("b", &oauth_record()).expect("create b");
    // The audit chain has two put entries; capture its length.
    let before = store.read_audit(None).unwrap().len();
    assert!(store.verify_audit_chain().unwrap().is_none());

    // Rotate to a new master key.
    let new_key = MasterKey::from_bytes([0x77; MASTER_KEY_LEN]);
    let new_key_id = new_key.key_id();
    store.rotate_master_key(new_key).expect("rotate");

    // Records are still readable (re-wrapped under the new key), unchanged plaintext.
    assert_eq!(store.get("a").unwrap().payload.expose(), b"payload-bytes");
    assert_eq!(store.get("b").unwrap().payload.expose(), b"payload-bytes");
    // The key_id columns were swapped to the new fingerprint.
    assert_eq!(store.meta("a").unwrap().key_id_hex, new_key_id.to_hex());
    // The chain is STILL one continuously-verifiable sequence (stable audit key)
    // and grew by exactly one RotateMasterKey entry.
    assert_eq!(
        store.verify_audit_chain().unwrap(),
        None,
        "chain spans rotation"
    );
    let after = store.read_audit(None).unwrap();
    assert_eq!(after.len(), before + 1);
    assert_eq!(after.last().unwrap().op, "rotate_master_key");
    assert!(
        after.last().unwrap().credential_id.is_none(),
        "vault-global entry"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn rotated_vault_reopens_only_under_new_key() {
    let (root, mut store) = tmp_store(21);
    store.create("a", &oauth_record()).unwrap();
    // Minted BEFORE the rotation: a consumer's live grant, which must survive both
    // the rewrap and the close/reopen below.
    let handle = mint_handle().expect("mint a pre-rotation handle");
    store
        .put_handle_hash(&handle.hash, "a", AuditCtx::admin(AuditOp::MintHandle))
        .expect("record the handle");
    let db_path = root.join("store.db");
    let new_key = MasterKey::from_bytes([0x88; MASTER_KEY_LEN]);
    store
        .rotate_master_key(MasterKey::from_bytes([0x88; MASTER_KEY_LEN]))
        .unwrap();
    drop(store);

    let descriptor = StorageDescriptor {
        module_id: "cortexkit-credentials".into(),
        storage_namespace: "vault".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: db_path.to_string_lossy().into_owned(),
        },
    };
    // The OLD key no longer opens the vault (audit-key decrypt fails closed).
    let reopened = open_sqlite(&descriptor).unwrap();
    let old_result = EncryptedStore::open(reopened, MasterKey::from_bytes([20u8; MASTER_KEY_LEN]));
    assert!(
        old_result.is_err(),
        "old key must not reopen a rotated vault"
    );
    // The NEW key opens it and the records are intact.
    let reopened = open_sqlite(&descriptor).unwrap();
    let store = EncryptedStore::open(reopened, new_key).expect("new key opens");
    assert_eq!(store.get("a").unwrap().payload.expose(), b"payload-bytes");
    assert_eq!(store.verify_audit_chain().unwrap(), None);

    // A ROTATION MUST NOT REVOKE ANYONE'S ACCESS. Handles are hashed, not sealed,
    // so nothing in the rewrap should touch them -- but that is an argument from
    // how the code is written today, and a future rewrap that rebuilt rows
    // wholesale would silently cut off every consumer while every assertion above
    // still passed. Consumers hold these values and cannot tell a revoked handle
    // from an unknown one (both answer NotFound, deliberately), so the failure
    // would surface as an unexplained fleet-wide outage.
    let resolved = store
        .resolve_handle(&handle.raw)
        .expect("the pre-rotation handle still resolves");
    assert_eq!(
        resolved, "a",
        "a handle minted before the rotation must still name its credential"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn audit_chain_detects_tampering() {
    let (root, store) = tmp_store(13);
    for i in 0..3 {
        store
            .append_audit(&AuditRecord {
                op: crate::audit::AuditOp::RefreshCommit,
                credential_id: Some(format!("id{i}")),
                payload_hash: Some("hh".into()),
                actor: "conn-1".into(),
                alarm: None,
            })
            .unwrap();
    }
    assert_eq!(
        store.verify_audit_chain().unwrap(),
        None,
        "clean chain verifies"
    );
    // Tamper with a row's payload_hash directly (a key-less attacker editing the
    // db) — the HMAC no longer matches, so verification flags the broken seq.
    store
        .with_raw_conn(|c| {
            c.execute(
                "UPDATE audit_log SET payload_hash = 'tampered' WHERE seq = 2",
                [],
            )
        })
        .unwrap();
    assert_eq!(
        store.verify_audit_chain().unwrap(),
        Some(2),
        "tampered entry detected"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn audit_verifiers_reject_a_noncanonical_alarm() {
    let seed = 13;
    let (root, store) = tmp_store(seed);
    let path = root.join("store.db");
    let key = MasterKey::from_bytes([seed; MASTER_KEY_LEN]);
    store
        .append_audit(&AuditRecord {
            op: AuditOp::Put,
            credential_id: None,
            payload_hash: None,
            actor: "test".into(),
            alarm: Some(crate::audit::AlarmReason::AdminWrite),
        })
        .unwrap();
    assert!(store.read_audit(None).unwrap()[0].alarm);
    assert_eq!(verify_audit_chain_read_only(&path, &key).unwrap(), None);
    store
        .with_raw_conn(|conn| conn.execute("UPDATE audit_log SET alarm = 2", []))
        .unwrap();
    assert!(store.verify_audit_chain().is_err());
    assert!(verify_audit_chain_read_only(&path, &key).is_err());
    assert!(store.read_audit(None).is_err());
    assert!(read_audit_read_only(&path, None).is_err());
}

#[test]
fn audit_verifiers_stop_reading_at_the_first_broken_entry() {
    let seed = 13;
    let (root, store) = tmp_store(seed);
    let path = root.join("store.db");
    let key = MasterKey::from_bytes([seed; MASTER_KEY_LEN]);
    let record = AuditRecord {
        op: AuditOp::Put,
        credential_id: None,
        payload_hash: None,
        actor: "test".into(),
        alarm: None,
    };
    store.append_audit(&record).unwrap();
    store.append_audit(&record).unwrap();
    // The first row has a bad MAC. Decoding the second row is an error, so
    // the result distinguishes stopping at the first row from reading both.
    store
        .with_raw_conn(|conn| {
            conn.execute_batch(
                "UPDATE audit_log SET actor = 'changed' WHERE seq = 1;\
         UPDATE audit_log SET actor = X'FF' WHERE seq = 2;",
            )
        })
        .unwrap();
    assert_eq!(store.verify_audit_chain().unwrap(), Some(1));
    assert_eq!(verify_audit_chain_read_only(&path, &key).unwrap(), Some(1));
}

#[test]
fn a_fenced_write_latches_fenced_out() {
    let (root, store) = tmp_store(21);
    store.create("id", &oauth_record()).expect("create");
    // Not fenced out on a healthy store.
    assert!(!store.is_fenced_out());

    // Simulate a newer writer having claimed the database at a higher epoch, so
    // the next fenced write is rejected — exactly the lease-handover race.
    store
        .with_raw_conn(|c| c.execute("UPDATE cortexkit_fence SET epoch = 999 WHERE id = 0", []))
        .expect("bump fence epoch above the holder");

    // A real durable mutation now: it must be Fenced AND latch the flag.
    match store.invalidate("id") {
        Err(StoreOpError::Fenced { .. }) => {}
        other => panic!("expected Fenced, got {other:?}"),
    }
    assert!(
        store.is_fenced_out(),
        "a rejected fenced write must latch the fenced-out signal"
    );

    // The signal drives the health snapshot to Failing even though the stale
    // read of the row still succeeds (Active).
    let metas = store.list_meta().expect("list_meta still reads");
    let health = crate::health::VaultHealth::summarize(&metas, 0, store.is_fenced_out());
    assert_eq!(health.status, crate::health::VaultHealthStatus::Failing);
    assert!(health.fenced_out);
    let _ = std::fs::remove_dir_all(&root);
}

/// A corrupt record is repaired by REPLACE, not by an inverse of quarantine.
///
/// Pins the claim the quarantine doc comment makes, because a comment describing a
/// repair path is worth less than a test that fails if the path closes. The costly
/// misreading is quiet: a reader who believes corrupt is unrecoverable reaches for
/// `remove`, which deletes the row and every handle with it, turning a one-command
/// fix into an operator ceremony for a platform-issued key.
#[test]
fn a_corrupt_record_is_repaired_by_replace_and_keeps_its_handles() {
    let (root, store) = tmp_store(11);
    let rec = VaultRecord::new_static(CredentialKind::ApiKey, "test", b"one".to_vec(), None);
    store.create("id", &rec).expect("create");
    let handle = mint_handle().expect("mint");
    store
        .put_handle_hash(&handle.hash, "id", AuditCtx::admin(AuditOp::MintHandle))
        .expect("put handle");
    store.quarantine("id").expect("quarantine");
    assert!(matches!(
        store.meta("id").expect("meta").state,
        RecordState::Corrupt
    ));

    let fresh = VaultRecord::new_static(CredentialKind::ApiKey, "test", b"two".to_vec(), None);
    store
        .overwrite_unconditional_audited("id", &fresh, AuditCtx::admin(AuditOp::Put))
        .expect("replace");

    let meta = store.meta("id").expect("meta");
    assert!(
        matches!(meta.state, RecordState::Active),
        "replace must clear corrupt, or the doc comment is lying about the repair path"
    );
    assert_eq!(store.get("id").expect("read back").payload.expose(), b"two");
    // The handle survives -- which is the whole reason replace beats remove here.
    assert_eq!(
        store.resolve_handle(&handle.raw).expect("resolve"),
        "id",
        "the repair must not cost consumers their handles"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Reactivate clears needs_reauth or retired, leaves the SECRET alone, and refuses
/// corrupt.
///
/// Three properties in one test because they are one guarantee: this verb contradicts
/// a VERDICT, it never repairs BYTES. Corrupt is excluded precisely because it IS a
/// claim about our own bytes -- clearing it would return known-broken material to
/// service, and no operator assertion makes an undecryptable envelope decrypt.
#[test]
fn reactivate_clears_needs_reauth_or_retired_without_touching_the_secret_and_refuses_corrupt() {
    let (root, store) = tmp_store(7);
    let rec = VaultRecord::new_static(CredentialKind::ApiKey, "test", b"the-secret".to_vec(), None);
    store.create("live", &rec).expect("create");
    store.create("retired", &rec).expect("create retired");
    store.create("broken", &rec).expect("create broken");

    store
        .invalidate_and_revoke_all_audited("live", AuditCtx::admin(AuditOp::Invalidate))
        .expect("invalidate");
    assert!(matches!(
        store.meta("live").expect("meta").state,
        RecordState::NeedsReauth
    ));

    let changed = store
        .reactivate_audited("live", AuditCtx::admin(AuditOp::Reactivate))
        .expect("reactivate");
    assert!(changed, "a needs_reauth credential must reactivate");
    assert!(matches!(
        store.meta("live").expect("meta").state,
        RecordState::Active
    ));
    assert_eq!(
        store.get("live").expect("read back").payload.expose(),
        b"the-secret",
        "reactivate must not disturb the stored material"
    );

    store
        .retire_and_revoke_all_audited("retired", AuditCtx::admin(AuditOp::Invalidate))
        .expect("retire");
    let retired_changed = store
        .reactivate_audited("retired", AuditCtx::admin(AuditOp::Reactivate))
        .expect("reactivate retired");
    assert!(retired_changed, "a retired credential must reactivate");
    assert!(matches!(
        store.meta("retired").expect("retired meta").state,
        RecordState::Active
    ));

    // A TRANSITION, not a repeatable write: a retry loop must not append to the
    // untrimmable audit chain.
    let again = store
        .reactivate_audited("live", AuditCtx::admin(AuditOp::Reactivate))
        .expect("second reactivate");
    assert!(!again, "reactivating an active credential must be a no-op");

    // CORRUPT IS REFUSED. The arm that keeps the verb honest.
    store.quarantine("broken").expect("quarantine");
    let corrupt_changed = store
        .reactivate_audited("broken", AuditCtx::admin(AuditOp::Reactivate))
        .expect("reactivate corrupt");
    assert!(
        !corrupt_changed,
        "a corrupt record must NOT reactivate: its own bytes failed"
    );
    assert!(
        matches!(
            store.meta("broken").expect("meta").state,
            RecordState::Corrupt
        ),
        "the corrupt record must still be corrupt"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn fenced_out_never_clears_on_a_later_successful_write() {
    // The latch is one-way, and this is the arm that pins it. Every OTHER field of
    // the health snapshot is recomputed from a fresh scan, so a reader could
    // reasonably assume this one recovers too, and "clear the flag when writes work
    // again" is a natural-looking change. It would be wrong: regaining the fence
    // means the OTHER lease holder went away, not that this instance recovered
    // authority, so clearing on a later success resumes serving as the authority on
    // the strength of a race. Recovery is a restart. Without this assertion the
    // one-way property is only a comment.
    let (root, store) = tmp_store(21);
    store.create("id", &oauth_record()).expect("create");

    let held: i64 = store
        .with_raw_conn(|c| {
            c.query_row("SELECT epoch FROM cortexkit_fence WHERE id = 0", [], |r| {
                r.get(0)
            })
        })
        .expect("read the epoch this store holds");

    // Simulate a competing writer taking the lease: raising the stored fence epoch
    // above the one this store holds makes its next durable write be rejected.
    store
        .with_raw_conn(|c| c.execute("UPDATE cortexkit_fence SET epoch = 999 WHERE id = 0", []))
        .expect("bump fence epoch above the holder");
    assert!(matches!(
        store.invalidate("id"),
        Err(StoreOpError::Fenced { .. })
    ));
    assert!(store.is_fenced_out(), "precondition: the latch is set");

    // Now make writes succeed again by restoring the epoch this store holds --
    // standing in for the competing holder having exited.
    store
        .with_raw_conn(|c| c.execute("UPDATE cortexkit_fence SET epoch = ?1 WHERE id = 0", [held]))
        .expect("restore the held epoch");

    // The write goes through: this is a genuine success, not a second rejection,
    // so the assertion below is about the latch rather than about the write failing.
    store.invalidate("id").expect("the write now succeeds");

    assert!(
        store.is_fenced_out(),
        "a later successful write must NOT clear the fenced-out latch: this process \
             cannot regain lost write authority, only a restart can"
    );
    let metas = store.list_meta().expect("list_meta");
    let health = crate::health::VaultHealth::summarize(&metas, 0, store.is_fenced_out());
    assert_eq!(
        health.status,
        crate::health::VaultHealthStatus::Failing,
        "health must stay Failing until the process is replaced"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn version_gated_invalidate_hits_on_matching_version() {
    let (root, store) = tmp_store(30);
    store.create("id", &oauth_record()).expect("create"); // record_version 1
    let ctx = AuditCtx {
        op: AuditOp::ReportAuthFailure,
        actor: "conn-1",
        alarm: None,
    };
    // Reporting the CURRENT version (1) invalidates and returns true.
    let hit = store
        .invalidate_if_version_audited("id", 1, ctx)
        .expect("version-gated invalidate");
    assert!(hit, "a report for the current version must invalidate");
    assert_eq!(store.meta("id").unwrap().state, RecordState::NeedsReauth);
    // And it audited exactly one ReportAuthFailure entry.
    let reports = store
        .read_audit(None)
        .unwrap()
        .into_iter()
        .filter(|e| e.op == "report_auth_failure")
        .count();
    assert_eq!(reports, 1, "a hitting version-CAS audits the invalidation");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn version_gated_invalidate_is_a_silent_noop_on_stale_version() {
    let (root, store) = tmp_store(31);
    store.create("id", &oauth_record()).expect("create"); // record_version 1
                                                          // Simulate the vault having refreshed to a newer version after the consumer was
                                                          // served v1: overwrite unconditionally so the current version moves to 2.
    store
        .overwrite_unconditional_audited("id", &oauth_record(), AuditCtx::vault(AuditOp::Overwrite))
        .expect("bump to version 2");
    assert_eq!(store.meta("id").unwrap().record_version, 2);

    let ctx = AuditCtx {
        op: AuditOp::ReportAuthFailure,
        actor: "conn-1",
        alarm: None,
    };
    // A stale report for the SERVED version (1) must be a silent no-op: it does NOT
    // invalidate the fresh v2 credential, returns false, and audits nothing.
    let hit = store
        .invalidate_if_version_audited("id", 1, ctx)
        .expect("stale version-gated invalidate");
    assert!(
        !hit,
        "a report for a superseded version must not invalidate"
    );
    assert_eq!(
        store.meta("id").unwrap().state,
        RecordState::Active,
        "the fresh credential is untouched by a stale report"
    );
    let reports = store
        .read_audit(None)
        .unwrap()
        .into_iter()
        .filter(|e| e.op == "report_auth_failure")
        .count();
    assert_eq!(reports, 0, "a stale version-CAS no-op audits nothing");
    let _ = std::fs::remove_dir_all(&root);
}

/// A report for the replaced version must not schedule an unnecessary second refresh.
#[test]
fn report_for_stale_version_does_not_re_stale_the_fresh_token() {
    let (root, store) = tmp_store(64);
    store.create("id", &oauth_record()).expect("create");
    store
        .overwrite_unconditional_audited(
            "id",
            &oauth_record(),
            AuditCtx::vault(AuditOp::RefreshCommit),
        )
        .expect("replace v1 with fresh v2");

    let changed = store
        .mark_stale_if_version_reported(
            "id",
            1,
            AuditCtx::vault(AuditOp::ReportAuthFailure),
            AuthObservation {
                kind: "consumer_report_stale",
                provider_status: Some(401),
                detail: None,
                reporter_source: None,
                principal: None,
            },
        )
        .expect("stale report is accepted");
    assert!(!changed, "the v1 report must not match the v2 row");
    let meta = store.meta("id").expect("fresh metadata");
    assert_eq!(meta.record_version, 2);
    assert!(matches!(meta.state, RecordState::Active));
    assert!(
        !meta.stale_pending,
        "a stale report must not set the marker on the fresh token"
    );
    let events = store.recent_auth_events(10).expect("events");
    assert_eq!(events[0].kind, "consumer_report_stale");
    assert!(
        !events[0].applied,
        "the stale report must be diagnostic-only"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// The no-op case is the one worth explaining, so it must leave a diagnostic row.
///
/// A report naming a superseded version changes nothing and audits nothing -- both
/// correct. The consequence was that a consumer acting on stale state, which is a
/// real thing to want to know about, was invisible afterwards. `auth_events` records
/// the observation either way and marks whether it applied.
#[test]
fn a_stale_report_is_still_recorded_as_an_observation_that_did_not_apply() {
    let (root, store) = tmp_store(63);
    store.create("id", &oauth_record()).expect("create");
    store
        .overwrite_unconditional_audited("id", &oauth_record(), AuditCtx::vault(AuditOp::Overwrite))
        .expect("bump to version 2");

    let ctx = AuditCtx {
        op: AuditOp::ReportAuthFailure,
        actor: "conn-1",
        alarm: None,
    };
    let obs = AuthObservation {
        kind: "consumer_report",
        provider_status: Some(401),
        detail: None,
        reporter_source: None,
        principal: None,
    };

    // Stale report against v1 while the store holds v2.
    let hit = store
        .invalidate_if_version_reported("id", 1, ctx, Some(obs))
        .expect("stale report");
    assert!(!hit, "a superseded version must not invalidate");
    assert_eq!(
        store.meta("id").unwrap().state,
        RecordState::Active,
        "the fresh credential is untouched"
    );

    let events = store.recent_auth_events(10).expect("read events");
    assert_eq!(events.len(), 1, "the no-op must still be recorded");
    assert_eq!(events[0].provider_status, Some(401));
    assert_eq!(events[0].record_version, Some(1));
    assert!(
        !events[0].applied,
        "the row must say the observation did NOT change the credential -- that is \
             what separates a stale report from a real one"
    );

    // THE DISAMBIGUATOR: a matching report records `applied = true`. Without this
    // arm, an implementation writing `applied = false` unconditionally passes.
    let hit = store
        .invalidate_if_version_reported("id", 2, ctx, Some(obs))
        .expect("current report");
    assert!(hit, "a report at the served version must invalidate");
    let events = store.recent_auth_events(10).expect("read events");
    assert_eq!(events.len(), 2);
    assert!(
        events[0].applied,
        "a report at the current version must record as applied"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// A handle can be minted for a credential that is already `needs_reauth`, and
/// the compound invalidate revokes only handles that exist WHEN IT RUNS.
///
/// Both halves are load-bearing for a consumer holding a handle across a
/// credential dying and being repaired — the handle must survive, because the
/// alternative is re-provisioning every consumer after every provider hiccup.
///
/// So the two orderings are both reachable and mean different things:
/// invalidate-then-mint leaves a live handle, mint-then-invalidate revokes it.
/// AFTER EITHER, THE CREDENTIAL READS `needs_reauth` — identical state, opposite
/// handle state — so anything checking only the credential cannot tell them
/// apart. That is what makes the second arm worth writing: it pins the handle row
/// `remove` reports how many handles it deleted, and the count is real.
///
/// A consumer holding a capability handle cannot be told by the vault that its
/// credential is gone: handles are bearer tokens and nothing records who holds
/// one, so the holder's next fetch gets a bare `not_found`. The count is the only
/// warning available and it is only actionable at the moment of removal --
/// observed live, a removed credential left a stale entry in a consumer's handle
/// file which blinded three healthy sibling accounts until they noticed
/// independently.
///
/// Both arms, because a function returning a constant satisfies either one alone:
/// two handles must report two, and none must report zero so the CLI can stay
/// silent rather than warning about consumers that cannot exist.
#[test]
fn remove_reports_how_many_handles_stopped_resolving() {
    let (root, store) = tmp_store(73);
    let ctx = AuditCtx::vault(AuditOp::MintHandle);

    store
        .create("with-handles", &oauth_record())
        .expect("create");
    for _ in 0..2 {
        let h = mint_handle().expect("mint");
        store
            .put_handle_hash(&h.hash, "with-handles", ctx)
            .expect("store handle");
    }
    store.create("bare", &oauth_record()).expect("create bare");

    let n = store
        .remove_audited("with-handles", AuditCtx::admin(AuditOp::Remove))
        .expect("remove");
    assert_eq!(
        n, 2,
        "the count must be the number of handles that just stopped resolving"
    );

    let none = store
        .remove_audited("bare", AuditCtx::admin(AuditOp::Remove))
        .expect("remove bare");
    assert_eq!(
        none, 0,
        "a credential with no handles must report zero, so the operator is not \
             warned about consumers that cannot exist"
    );

    let _ = std::fs::remove_dir_all(root);
}

/// A REPEAT logout changes nothing, says so, and writes no audit entry.
///
/// The first call is the control: without it, a function that never reports a
/// change would pass every assertion below.
///
/// Two properties, and they fail differently. The OUTCOME must report no change,
/// because a CLI that prints plain success on a no-op reads as broken -- observed
/// live: three consecutive logouts against one already-dead credential, three
/// identical success messages, an identical listing after each. The AUDIT CHAIN
/// must not grow, because it is tamper-evident and therefore untrimmable: an
/// operator repeating a logout would otherwise extend it without bound with
/// entries recording that nothing happened.
#[test]
fn a_repeat_logout_changes_nothing_and_appends_no_audit_entry() {
    let (root, store) = tmp_store(71);
    store.create("dead", &oauth_record()).expect("create");
    let h = mint_handle().expect("mint");
    store
        .put_handle_hash(&h.hash, "dead", AuditCtx::vault(AuditOp::MintHandle))
        .expect("store handle");

    // CONTROL: the first logout genuinely mutates.
    let first = store
        .invalidate_and_revoke_all_audited("dead", AuditCtx::admin(AuditOp::Invalidate))
        .expect("first logout");
    assert!(
        first.state_changed && first.handles_revoked == 1,
        "the first logout must actually invalidate and revoke: {first:?}"
    );
    assert!(
        first.changed_anything(),
        "a logout that killed a live credential must report a change"
    );

    let entries_after_first = store.read_audit(None).expect("read audit").len();

    // The repeat.
    let second = store
        .invalidate_and_revoke_all_audited("dead", AuditCtx::admin(AuditOp::Invalidate))
        .expect("second logout");
    assert!(
        !second.changed_anything(),
        "a logout against an already-dead credential with no live handles must \
             report that nothing changed, or the CLI cannot tell an operator why the \
             listing is identical: {second:?}"
    );
    assert!(
        !second.state_changed && second.handles_revoked == 0,
        "no state flip and no revocation on the repeat: {second:?}"
    );

    let entries_after_second = store.read_audit(None).expect("read audit").len();
    assert_eq!(
        entries_after_first, entries_after_second,
        "the tamper-evident chain must not grow on a no-op -- it cannot be \
             trimmed, so a repeated logout would extend it without bound"
    );

    // The record still exists: logout is reversible, which is exactly why it
    // stays listed and why `remove` is the verb for making it go away.
    assert_eq!(
        store.meta("dead").expect("meta").state,
        RecordState::NeedsReauth,
        "logout keeps the row"
    );

    let _ = std::fs::remove_dir_all(root);
}

/// as the discriminator, and would fail if minting ever started refusing a dead
/// credential.
#[test]
fn a_handle_mints_for_a_dead_credential_and_invalidate_only_revokes_what_exists() {
    let (root, store) = tmp_store(67);
    let ctx = AuditCtx::vault(AuditOp::MintHandle);

    // invalidate -> mint: the compound has nothing to revoke, then the mint lands.
    store.create("id", &oauth_record()).expect("create");
    let revoked = store
        .invalidate_and_revoke_all_audited("id", AuditCtx::vault(AuditOp::Invalidate))
        .expect("invalidate");
    assert_eq!(
        revoked.handles_revoked, 0,
        "nothing to revoke before a handle exists"
    );
    let live = mint_handle().expect("mint");
    store
        .put_handle_hash(&live.hash, "id", ctx)
        .expect("minting for a needs_reauth credential must succeed");
    assert_eq!(
        store.resolve_handle(&live.raw).expect("resolve"),
        "id",
        "the handle must RESOLVE: this is the state production reaches on its own, \
             and resolution selects on revoked = 0"
    );

    // mint -> invalidate: same credential state, opposite handle state.
    store.create("id2", &oauth_record()).expect("create");
    let dead = mint_handle().expect("mint");
    store.put_handle_hash(&dead.hash, "id2", ctx).expect("mint");
    let revoked = store
        .invalidate_and_revoke_all_audited("id2", AuditCtx::vault(AuditOp::Invalidate))
        .expect("invalidate");
    assert_eq!(
        revoked.handles_revoked, 1,
        "an existing handle IS revoked by the operator verb"
    );
    assert!(
        matches!(store.resolve_handle(&dead.raw), Err(StoreOpError::NotFound)),
        "revoked, while the credential reads needs_reauth exactly as above"
    );

    assert_eq!(
        store.meta("id").unwrap().state,
        store.meta("id2").unwrap().state,
        "the credential state cannot discriminate the two orderings -- which is \
             why the handle row is the guard"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// A repeated report audits ONCE, because the chain cannot be trimmed.
///
/// The version guard does not bound this on its own: invalidating does not bump
/// `record_version`, so a consumer reporting the same version twice matches twice,
/// and every match appends to a log that is append-only by design. Requiring an
/// actual state transition makes the repeat a no-op.
///
/// The second arm is the disambiguator: a guard that simply refused everything
/// would satisfy the first assertion alone.
#[test]
fn a_repeated_report_audits_once_but_is_recorded_every_time() {
    let (root, store) = tmp_store(65);
    store.create("id", &oauth_record()).expect("create");
    let ctx = AuditCtx {
        op: AuditOp::ReportAuthFailure,
        actor: "conn-1",
        alarm: None,
    };
    let obs = AuthObservation {
        kind: "consumer_report",
        provider_status: Some(401),
        detail: None,
        reporter_source: None,
        principal: None,
    };

    // First report at the served version: a real transition.
    let hit = store
        .invalidate_if_version_reported("id", 1, ctx, Some(obs))
        .expect("first report");
    assert!(hit, "the first report must invalidate");

    // Six more identical reports. The credential is already needs_reauth, and the
    // version has not moved, so each still MATCHES the version guard.
    for _ in 0..6 {
        let hit = store
            .invalidate_if_version_reported("id", 1, ctx, Some(obs))
            .expect("repeat report");
        assert!(!hit, "a repeat changes nothing and must report so");
    }

    let audited = store
        .read_audit(None)
        .unwrap()
        .into_iter()
        .filter(|e| e.op == "report_auth_failure")
        .count();
    assert_eq!(
        audited, 1,
        "only the transition may append to the untrimmable chain; got {audited}"
    );

    // THE DISAMBIGUATOR: every report is still recorded as a diagnostic, which is
    // the table that CAN be bounded. A guard that dropped these too would pass the
    // assertion above while destroying the evidence of the loop.
    let events = store.recent_auth_events(100).expect("read events");
    assert_eq!(
        events.len(),
        7,
        "every report must still be recorded as an observation"
    );
    assert_eq!(
        events.iter().filter(|e| e.applied).count(),
        1,
        "exactly one of them applied"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// A flood against one credential is bounded, and cannot evict another's history.
///
/// Recording an observation even when it changes nothing is the point of this
/// table, and the cost is that a formerly silent no-op now always writes. Nothing
/// upstream refuses one -- the read surface's limiter alarms on a report flood and
/// lets the call through -- so the bound lives at the insert.
///
/// The per-credential scope is the load-bearing part: under a global cap, one
/// consumer looping on one credential would evict every other credential's
/// history -- the rows that explain whatever failure is being diagnosed.
#[test]
fn an_event_flood_is_bounded_per_credential_and_spares_other_credentials() {
    let (root, store) = tmp_store(64);
    store
        .create("noisy", &oauth_record())
        .expect("create noisy");
    store
        .create("quiet", &oauth_record())
        .expect("create quiet");

    // One event for the quiet credential, which must survive the flood.
    store
        .record_auth_event(
            "quiet",
            AuthObservation {
                kind: "refresh_failed",
                provider_status: Some(503),
                detail: Some("status"),
                reporter_source: None,
                principal: None,
            },
            Some(1),
        )
        .expect("quiet event");

    // Well past the cap, as a stuck consumer would produce.
    let flood = AUTH_EVENTS_PER_CREDENTIAL + 40;
    for _ in 0..flood {
        store
            .record_auth_event(
                "noisy",
                AuthObservation {
                    kind: "consumer_report",
                    provider_status: Some(401),
                    detail: None,
                    reporter_source: None,
                    principal: None,
                },
                Some(1),
            )
            .expect("noisy event");
    }

    let events = store.recent_auth_events(10_000).expect("read events");
    let noisy = events.iter().filter(|e| e.credential_id == "noisy").count();
    let quiet = events.iter().filter(|e| e.credential_id == "quiet").count();

    assert_eq!(
        noisy as u32, AUTH_EVENTS_PER_CREDENTIAL,
        "a flood must be trimmed to the cap, not grow without bound"
    );
    assert_eq!(
        quiet, 1,
        "a flood against one credential must not evict another's history -- those \
             are the rows an operator reads during the incident"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn rotate_quarantines_undecryptable_rows_and_reports_them() {
    let (root, mut store) = tmp_store(40);
    store.create("good", &oauth_record()).expect("create good");
    store.create("bad", &oauth_record()).expect("create bad");
    // Corrupt "bad"'s envelope directly (a key-less db edit): it will fail to decrypt
    // under the OLD key during rotation, so it cannot be re-wrapped.
    store
        .with_raw_conn(|c| {
            c.execute(
                "UPDATE credentials SET envelope = X'00010203' WHERE credential_id = 'bad'",
                [],
            )
        })
        .expect("corrupt bad envelope");

    let new_key = MasterKey::from_bytes([0x41; MASTER_KEY_LEN]);
    let quarantined = store.rotate_master_key(new_key).expect("rotate");
    // The undecryptable row is surfaced, not silently skipped behind a success.
    assert_eq!(quarantined, vec!["bad".to_string()]);
    assert_eq!(store.meta("bad").unwrap().state, RecordState::Corrupt);
    // The good record re-wrapped under the new key and still reads.
    assert_eq!(
        store.get("good").expect("good readable").payload.expose(),
        b"payload-bytes"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn read_db_key_id_fails_closed_on_a_corrupt_anchor() {
    let (root, store) = tmp_store(50);
    store.create("id", &oauth_record()).expect("create");
    // Corrupt the sealed audit-key row's plaintext key_id fingerprint (the resolve
    // anchor). This must be distinguished from an ABSENT row (a new vault) and fail
    // closed, not silently downgrade to the bootstrap path.
    store
        .with_raw_conn(|c| {
            c.execute(
                "UPDATE vault_secrets SET key_id = 'not-hex' WHERE name = ?1",
                rusqlite::params![AUDIT_KEY_SECRET_NAME],
            )
        })
        .expect("corrupt anchor");
    // The test module is inside store.rs, so it can reach the private inner store.
    match EncryptedStore::read_db_key_id(&store.store) {
        Err(StoreError::Backend(m)) => assert!(m.contains("corrupt anchor"), "got: {m}"),
        other => panic!("a corrupt anchor must fail closed, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// An exact selector is ordinary text, not a SQL pattern: `%` and `_` must never
/// authorize an unrelated id by acting as wildcards.
#[test]
fn exact_selectors_are_literal_not_like_patterns() {
    let (root, store) = tmp_store(51);
    store
        .create_read_grant_audited(
            "reserved",
            "prefrontal-core",
            SelectorKind::Exact,
            "github%_app:agent",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .expect("create grant");

    assert!(
        store
            .read_grant_covers(
                "reserved",
                "prefrontal-core",
                "github%_app:agent",
                GrantOperation::Read,
                &DeclaredGrantSet::empty(),
            )
            .expect("check exact literal"),
        "the byte-equal id must be covered"
    );
    assert!(
        !store
            .read_grant_covers(
                "reserved",
                "prefrontal-core",
                "githubZZapp:agent",
                GrantOperation::Read,
                &DeclaredGrantSet::empty(),
            )
            .expect("check unrelated id"),
        "percent and underscore in a grant must not widen it as SQL LIKE wildcards"
    );
    let _ = std::fs::remove_dir_all(root);
}

/// PINS THE LITERAL, deliberately, so adding a migration REDDENS rather than
/// silently changing what this binary declares to the supervisor.
///
/// The manifest publishes this number, so a new migration is a change to a
/// fleet-visible declaration and not only to the schema. A relationship assertion
/// (`== MIGRATIONS.iter().max()`) would move with the list and prove nothing about
/// the value; the literal is what makes the author look at the manifest.
#[test]
fn the_newest_migration_version_is_pinned_because_the_manifest_declares_it() {
    assert_eq!(
        newest_migration_version(),
        55,
        "the newest migration changed. This value is DECLARED in the module manifest \
             as store_schema_version, so a supervisor comparing declared-against-actual \
             sees it. Update the literal, and note the manifest consequence."
    );

    // Semantics, not just the value: `newest` must be the MAXIMUM, not the last
    // element. They agree while the list stays sorted, and diverge the first time
    // someone inserts out of order -- which is exactly when a silent wrong answer
    // would be least expected.
    for m in MIGRATIONS {
        assert!(
            m.version <= newest_migration_version(),
            "migration {} exceeds the reported newest -- newest_migration_version is \
                 returning a position rather than a maximum",
            m.version
        );
    }
}
