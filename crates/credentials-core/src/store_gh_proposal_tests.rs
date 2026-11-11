use super::*;
use crate::record::{CredentialKind, VaultRecord};
use crate::store::{taxonomy_tests, GhManifestSource, GhManifestVersion};
use rusqlite::types::Value;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Barrier};

const V28: &[u8] = include_bytes!("../tests/fixtures/gh-manifest-v28.json");
const NOW: i64 = 1_794_355_300_123;
const MEMBER: &str = "fed-computer:22222222222222222222222222222222";
const AGENT: &str = "agent_4444444444444444";
const REPO: &str = "Octo-Owner/New-Repo";
const TABLES: [&str; 5] = [
    "gh_manifests",
    "gh_manifest_proposals",
    "gh_manifest_activations",
    "gh_manifest_activation_audits",
    "audit_log",
];

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn framed_hash(fields: &[&str]) -> String {
    let bytes: Vec<u8> = fields
        .iter()
        .flat_map(|field| {
            (field.len() as u64)
                .to_le_bytes()
                .into_iter()
                .chain(field.bytes())
        })
        .collect();
    hash(&bytes)
}

fn snapshot(store: &EncryptedStore) -> Vec<Vec<Vec<Value>>> {
    store
        .with_raw_conn(|conn| {
            TABLES
                .iter()
                .map(|table| {
                    let mut stmt =
                        conn.prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))?;
                    let count = stmt.column_count();
                    let rows = stmt
                        .query_map([], |row| {
                            (0..count)
                                .map(|i| row.get(i))
                                .collect::<rusqlite::Result<Vec<_>>>()
                        })?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    Ok(rows)
                })
                .collect()
        })
        .unwrap()
}

fn store_bytes(store: &EncryptedStore, number: i64, bytes: &[u8]) {
    store
        .store_gh_manifest(
            &GhManifestVersion {
                version: number,
                manifest_bytes: bytes,
                manifest_sha256: &hash(bytes),
                key_id: "0123456789abcdef",
                signature: &[7; 64],
                signed_at_ms: NOW,
                source: GhManifestSource::Import,
                approval_audit_seq: None,
            },
            AuditCtx::admin(AuditOp::GhManifestStore),
        )
        .unwrap();
}

fn add_root(store: &EncryptedStore) {
    use base64::Engine as _;
    let der =
        ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(der.as_ref())
    );
    let record = VaultRecord::new_static(
        CredentialKind::SigningKey,
        "operator",
        pem.into_bytes(),
        None,
    );
    store
        .create_audited(
            GH_MANIFEST_ROOT_KEY_ID,
            &record,
            AuditCtx::admin(AuditOp::Put),
        )
        .unwrap();
}

fn add_member(store: &EncryptedStore) {
    store
        .set_federation_self_member_audited(MEMBER, AuditCtx::admin(AuditOp::FederationSelfSet))
        .unwrap();
}

fn ready(label: &str) -> (crate::test_support::TestTempDir, EncryptedStore) {
    let (root, store) = taxonomy_tests::rig(label, 191);
    add_root(&store);
    add_member(&store);
    store_bytes(&store, 28, V28);
    (root, store)
}

fn input(repo: &str) -> GhManifestProposalInput {
    GhManifestProposalInput {
        agent_id: AGENT.into(),
        app_id: 42,
        app_slug: "repo-bot".into(),
        repo: repo.into(),
        installation_permissions: BTreeMap::from([
            ("pull_requests".into(), "write".into()),
            ("metadata".into(), "read".into()),
            ("contents".into(), "admin".into()),
        ]),
    }
}

#[test]
fn gh_manifest_proposal_oauth_read_never_quarantines_or_writes() {
    let (_root, store) = ready("manifest-read-only-oauth");
    let id = "github_app:repo-bot";
    let credential = crate::oauth::OAuthCredential {
        access_token: "test-token".to_owned().into(),
        refresh_token: "test-key".to_owned().into(),
        expires_at_ms: Some(0),
        token_url: String::new(),
        client_id: Some("test-client".into()),
        client_secret: None,
        scopes: vec![],
    };
    store
        .create(
            id,
            &VaultRecord::new_oauth("test", "github_app", credential, b"test-token".to_vec()),
        )
        .unwrap();
    let all_rows = || {
        let mut rows = snapshot(&store);
        rows.push(
            store
                .with_raw_conn(|conn| {
                    let mut stmt =
                        conn.prepare("SELECT * FROM credentials ORDER BY credential_id")?;
                    let count = stmt.column_count();
                    let rows = stmt
                        .query_map([], |row| {
                            (0..count)
                                .map(|i| row.get(i))
                                .collect::<rusqlite::Result<Vec<Value>>>()
                        })?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    Ok(rows)
                })
                .unwrap(),
        );
        rows
    };
    let before = all_rows();
    assert_eq!(
        store
            .github_app_oauth_for_manifest_proposal(id)
            .unwrap()
            .unwrap()
            .access_token
            .expose(),
        "test-token"
    );
    assert!(store
        .github_app_oauth_for_manifest_proposal("github_app:missing")
        .unwrap()
        .is_none());
    assert!(store
        .github_app_oauth_for_manifest_proposal(GH_MANIFEST_ROOT_KEY_ID)
        .unwrap()
        .is_none());
    assert_eq!(all_rows(), before);
    store.invalidate(id).unwrap();
    let before = all_rows();
    assert!(store
        .github_app_oauth_for_manifest_proposal(id)
        .unwrap()
        .is_none());
    assert_eq!(all_rows(), before);
    store
        .with_raw_conn(|conn| {
            conn.execute(
                "UPDATE credentials SET state='active',envelope=x'00' WHERE credential_id=?1",
                [id],
            )
        })
        .unwrap();
    let before = all_rows();
    assert!(matches!(
        store.github_app_oauth_for_manifest_proposal(id),
        Err(StoreOpError::Decrypt(_))
    ));
    assert_eq!(all_rows(), before);
    // A valid seal with an invalid record exercises record decoding separately from
    // opening the envelope.
    let blob = super::super::envelope::seal(
        &store.key,
        b"not a record",
        &super::super::RecordBinding {
            credential_id: id,
            record_version: 1,
        },
    )
    .unwrap();
    store
        .with_raw_conn(|conn| {
            conn.execute(
                "UPDATE credentials SET envelope=?2 WHERE credential_id=?1",
                params![id, blob],
            )
        })
        .unwrap();
    let before = all_rows();
    assert!(matches!(
        store.github_app_oauth_for_manifest_proposal(id),
        Err(StoreOpError::Corrupt(_))
    ));
    assert_eq!(all_rows(), before);
}

fn propose(store: &EncryptedStore, now: i64) -> GhManifestProposal {
    let prepared = store.prepare_gh_manifest_proposal(input(REPO)).unwrap();
    store
        .propose_gh_manifest_binding(&prepared, "reserved:plexus", || true, || now)
        .unwrap()
}

fn activation(store: &EncryptedStore, version: i64, retired: bool, verdict: &str) {
    store
        .with_raw_conn(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO gh_manifest_activations \
         (member_id,version,payload_sha256,verdict,reason,reported_at_ms,retired_at_ms) \
         VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    MEMBER,
                    version,
                    "a".repeat(64),
                    verdict,
                    if verdict == "invalid" {
                        Some("bad")
                    } else {
                        None
                    },
                    NOW,
                    if retired { Some(NOW) } else { None }
                ],
            )
        })
        .unwrap();
}

#[test]
fn gh_manifest_one_tap_missing_off_malformed_and_changes_are_audited_once() {
    let (root, store) = taxonomy_tests::rig("manifest-one-tap", 192);
    let path = root.join("store.db");
    assert_eq!(
        manifest_one_tap_status_read_only(&root.join("absent.db")).unwrap(),
        "off"
    );
    assert!(!root.join("absent.db").exists());
    assert_eq!(manifest_one_tap_status_read_only(&path).unwrap(), "off");
    assert!(!store.manifest_one_tap_enabled());
    let mut expected = Vec::new();
    for (enabled, changed) in [
        (false, true),
        (false, false),
        (true, true),
        (true, false),
        (false, true),
    ] {
        let before = snapshot(&store);
        let old_setting = store
            .with_raw_conn(|conn| {
                conn.query_row(
                    "SELECT value,updated_at_ms FROM settings WHERE name=?1",
                    [MANIFEST_ONE_TAP_SETTING],
                    |row| Ok((row.get::<_, Value>(0)?, row.get::<_, i64>(1)?)),
                )
                .optional()
            })
            .unwrap();
        assert_eq!(
            store
                .set_manifest_one_tap_audited(
                    enabled,
                    AuditCtx::route_admin(AuditOp::GhManifestOneTapSet, "offline-cli")
                )
                .unwrap(),
            changed
        );
        assert_eq!(store.manifest_one_tap_enabled(), enabled);
        assert_eq!(
            manifest_one_tap_status_read_only(&path).unwrap(),
            if enabled { "on" } else { "off" }
        );
        if changed {
            expected.push(if enabled {
                "46d058fc4ef77f3fd874fde10d5335b24dbbb60eb4f66d45d732ab1c5b0d7250"
            } else {
                "69a57fcf27b39980093d7313846dd4879f4f80d83d4453fa43addc073712c57e"
            });
        } else {
            assert_eq!(snapshot(&store), before);
            assert_eq!(
                store
                    .with_raw_conn(|conn| conn
                        .query_row(
                            "SELECT value,updated_at_ms FROM settings WHERE name=?1",
                            [MANIFEST_ONE_TAP_SETTING],
                            |row| Ok((row.get::<_, Value>(0)?, row.get::<_, i64>(1)?)),
                        )
                        .optional())
                    .unwrap(),
                old_setting
            );
        }
        let audit = store.read_audit(None).unwrap();
        assert_eq!(audit.len(), expected.len());
        for (row, hash) in audit.iter().zip(&expected) {
            assert_eq!(row.op, "gh_manifest_one_tap_set");
            assert_eq!(row.actor, "offline-cli");
            assert_eq!(row.credential_id, None);
            assert_eq!(row.payload_hash.as_deref(), Some(*hash));
        }
    }
    for malformed in [
        Value::Text("on".into()),
        Value::Text("TRUE".into()),
        Value::Integer(1),
        Value::Blob(b"true".to_vec()),
    ] {
        store
            .with_raw_conn(|conn| {
                conn.execute(
                    "UPDATE settings SET value=?1 WHERE name=?2",
                    params![malformed, MANIFEST_ONE_TAP_SETTING],
                )
            })
            .unwrap();
        let before = snapshot(&store);
        assert!(!store.manifest_one_tap_enabled());
        assert_eq!(
            manifest_one_tap_status_read_only(&path).unwrap(),
            "unreadable"
        );
        assert_eq!(snapshot(&store), before);
        let count = store.read_audit(None).unwrap().len();
        assert!(store
            .set_manifest_one_tap_audited(false, AuditCtx::admin(AuditOp::GhManifestOneTapSet))
            .unwrap());
        assert!(!store
            .set_manifest_one_tap_audited(false, AuditCtx::admin(AuditOp::GhManifestOneTapSet))
            .unwrap());
        assert_eq!(store.read_audit(None).unwrap().len(), count + 1);
    }
    drop(store);
    assert_eq!(manifest_one_tap_status_read_only(&path).unwrap(), "off");
}

#[test]
fn gh_manifest_one_tap_setting_rolls_back_on_audit_failure() {
    let (_root, store) = taxonomy_tests::rig("manifest-gate-rollback", 193);
    store.with_raw_conn(|conn| conn.execute_batch(
        "CREATE TRIGGER fail_gate_audit BEFORE INSERT ON audit_log WHEN NEW.op='gh_manifest_one_tap_set' \
         BEGIN SELECT RAISE(ABORT, 'forced audit failure'); END;"
    )).unwrap();
    let before = snapshot(&store);
    assert!(store
        .set_manifest_one_tap_audited(true, AuditCtx::admin(AuditOp::GhManifestOneTapSet))
        .is_err());
    assert_eq!(snapshot(&store), before);
    assert!(!store.manifest_one_tap_enabled());
    store
        .with_raw_conn(|conn| {
            assert_eq!(
                conn.query_row(
                    "SELECT COUNT(*) FROM settings WHERE name=?1",
                    [MANIFEST_ONE_TAP_SETTING],
                    |row| row.get::<_, i64>(0)
                )?,
                0
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn gh_manifest_proposal_home_setup_requires_active_root_version_and_self_member() {
    for missing in ["root", "inactive_root", "version", "member"] {
        let (_root, store) = taxonomy_tests::rig(&format!("manifest-setup-{missing}"), 194);
        if missing != "root" {
            add_root(&store);
        }
        if missing == "inactive_root" {
            store.invalidate(GH_MANIFEST_ROOT_KEY_ID).unwrap();
        }
        if missing != "version" {
            store_bytes(&store, 28, V28);
        }
        if missing != "member" {
            add_member(&store);
        }
        let before = snapshot(&store);
        assert_eq!(
            store.check_gh_manifest_setup(),
            Err(GhManifestProposalError::ManifestSetupIncomplete),
            "{missing}"
        );
        assert_eq!(
            store.prepare_gh_manifest_proposal(input(REPO)).unwrap_err(),
            GhManifestProposalError::ManifestSetupIncomplete,
            "{missing}"
        );
        assert_eq!(snapshot(&store), before);
    }
    let (_root, store) = ready("manifest-setup-complete");
    let before = snapshot(&store);
    store.check_gh_manifest_setup().unwrap();
    store.prepare_gh_manifest_proposal(input(REPO)).unwrap();
    assert_eq!(snapshot(&store), before);
}

#[test]
fn gh_manifest_proposal_checks_newest_bindings_case_insensitively_before_later_checks() {
    let (_root, store) = ready("manifest-bindings");
    let latest = std::str::from_utf8(V28)
        .unwrap()
        .replace("\"manifest_version\": 28", "\"manifest_version\": 30")
        .replace("agent_1111111111111111", AGENT);
    // A binding refusal must precede both an ahead activation and bad formatting.
    let compact =
        serde_json::to_vec(&serde_json::from_str::<serde_json::Value>(&latest).unwrap()).unwrap();
    store_bytes(&store, 30, &compact);
    activation(&store, 31, false, "valid");
    for (repo, error) in [
        (
            "Zulu/Existing",
            GhManifestProposalError::AlreadyBound {
                version: 30,
                manifest_sha256: hash(&compact),
            },
        ),
        (
            "zULU/eXISTING",
            GhManifestProposalError::AlreadyBound {
                version: 30,
                manifest_sha256: hash(&compact),
            },
        ),
        ("Alpha/Other", GhManifestProposalError::BoundToOtherAgent),
        ("aLPHA/oTHER", GhManifestProposalError::BoundToOtherAgent),
        (REPO, GhManifestProposalError::StaleBase),
    ] {
        let before = snapshot(&store);
        assert_eq!(
            store.prepare_gh_manifest_proposal(input(repo)).unwrap_err(),
            error,
            "{repo}"
        );
        assert_eq!(snapshot(&store), before);
    }
}

#[test]
fn gh_manifest_proposal_checks_only_non_retired_ahead_activations() {
    let (_root, store) = ready("manifest-ahead");
    for verdict in ["valid", "invalid"] {
        activation(&store, 29, false, verdict);
        let before = snapshot(&store);
        assert_eq!(
            store.prepare_gh_manifest_proposal(input(REPO)).unwrap_err(),
            GhManifestProposalError::StaleBase
        );
        assert_eq!(snapshot(&store), before);
    }
    for (version, retired) in [(29, true), (28, false), (27, false)] {
        activation(&store, version, retired, "valid");
        let before = snapshot(&store);
        store.prepare_gh_manifest_proposal(input(REPO)).unwrap();
        assert_eq!(snapshot(&store), before);
    }
}

#[test]
fn gh_manifest_proposal_refuses_non_reproducible_bytes_without_writes() {
    let (_root, store) = ready("manifest-non-reproducible");
    let latest = std::str::from_utf8(V28)
        .unwrap()
        .replace("\"manifest_version\": 28", "\"manifest_version\": 29");
    store_bytes(&store, 29, latest.trim_end().as_bytes());
    let before = snapshot(&store);
    assert_eq!(
        store.prepare_gh_manifest_proposal(input(REPO)).unwrap_err(),
        GhManifestProposalError::NotReproducible
    );
    assert_eq!(snapshot(&store), before);
}

#[test]
fn gh_manifest_proposal_stores_exact_build_full_name_jcs_permissions_and_commitments() {
    let (_root, store) = ready("manifest-proposal-fields");
    assert!(
        !store.manifest_one_tap_enabled(),
        "the module, not this storage primitive, applies the gate"
    );
    let before = snapshot(&store);
    let proposal = propose(&store, NOW);
    assert_eq!(proposal.agent_id, AGENT);
    assert_eq!(proposal.app_id, 42);
    assert_eq!(proposal.app_slug, "repo-bot");
    assert_eq!(proposal.repo, REPO);
    assert_eq!(proposal.base_version, 28);
    assert_eq!(proposal.created_at_ms, NOW);
    assert_eq!(proposal.expires_at_ms, NOW + 86_400_000);
    let alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    assert_eq!(proposal.proposal_id.len(), 26);
    assert!(proposal
        .proposal_id
        .starts_with(['0', '1', '2', '3', '4', '5', '6', '7']));
    let ulid = proposal
        .proposal_id
        .chars()
        .fold(0u128, |value, character| {
            (value << 5) | alphabet.find(character).expect("canonical ULID character") as u128
        });
    assert_eq!((ulid >> 80) as i64, NOW);
    assert_eq!(
        proposal.installation_permissions,
        br#"{"contents":"admin","metadata":"read","pull_requests":"write"}"#
    );
    let expected = std::str::from_utf8(V28).unwrap()
        .replace("\"manifest_version\": 28", "\"manifest_version\": 29")
        .replace("\"issued_at_unix_secs\": 1794355200", "\"issued_at_unix_secs\": 1794355300")
        .replace("\"cortexkit/opencode-sidebar\": \"agent_3333333333333333\"\n",
            "\"cortexkit/opencode-sidebar\": \"agent_3333333333333333\",\n    \"Octo-Owner/New-Repo\": \"agent_4444444444444444\"\n");
    assert_eq!(proposal.manifest_bytes, expected.as_bytes());
    assert_eq!(proposal.manifest_sha256, hash(expected.as_bytes()));
    let expected_statement = format!(
        "{{\"agent_id\":\"{AGENT}\",\"app_slug\":\"repo-bot\",\"expires_at_ms\":{},\"installation_permissions\":{{\"contents\":\"admin\",\"metadata\":\"read\",\"pull_requests\":\"write\"}},\"manifest_sha256\":\"{}\",\"manifest_version\":29,\"prior_sha256\":\"{}\",\"prior_version\":28,\"proposal_id\":\"{}\",\"repo\":\"{REPO}\",\"v\":\"ck-manifest-binding-statement/v1\"}}",
        NOW + 86_400_000, hash(expected.as_bytes()), hash(V28), proposal.proposal_id);
    assert_eq!(proposal.statement_bytes, expected_statement.as_bytes());
    assert_eq!(
        proposal.statement_sha256,
        hash(expected_statement.as_bytes())
    );
    let after = snapshot(&store);
    for table in [0, 2, 3] {
        assert_eq!(after[table], before[table]);
    }
    assert_eq!(after[1].len(), 1);
    assert_eq!(after[4].len(), before[4].len() + 1);
    store.with_raw_conn(|conn| {
        let stored = conn.query_row(
            "SELECT proposal_id,agent_id,app_id,app_slug,repo,installation_permissions,base_version, \
             manifest_bytes,manifest_sha256,statement_bytes,statement_sha256,created_at_ms,expires_at_ms \
             FROM gh_manifest_proposals", [], proposal_row)?;
        assert_eq!(stored, proposal);
        let state: (String,Option<String>,Option<String>) = conn.query_row(
            "SELECT state,approved_envelope_sha256,approved_fingerprint FROM gh_manifest_proposals", [],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?;
        assert_eq!(state, ("pending".into(),None,None));
        Ok(())
    }).unwrap();
    let audit = store.read_audit(None).unwrap();
    let last = audit.last().unwrap();
    assert_eq!(last.op, "gh_manifest_propose");
    assert_eq!(last.actor, "reserved:plexus");
    assert_eq!(
        last.credential_id.as_deref(),
        Some(format!("gh-manifest-proposal|{}", proposal.proposal_id).as_str())
    );
    assert_eq!(
        last.payload_hash.as_deref(),
        Some(
            framed_hash(&[
                AGENT,
                REPO,
                "28",
                &proposal.manifest_sha256,
                &proposal.statement_sha256,
            ])
            .as_str()
        )
    );
}

#[test]
fn gh_manifest_proposal_refuses_non_ascii_permissions_without_writes() {
    let (_root, store) = ready("manifest-proposal-permissions");
    let before = snapshot(&store);
    let mut request = input(REPO);
    request.installation_permissions = BTreeMap::from([
        ("\u{e000}".into(), "read".into()),
        ("😀".into(), "write".into()),
    ]);
    let prepared = store.prepare_gh_manifest_proposal(request).unwrap();
    assert!(matches!(
        store.propose_gh_manifest_binding(&prepared, "reserved:plexus", || true, || NOW),
        Err(GhManifestProposalError::NotReproducible)
    ));
    assert_eq!(snapshot(&store), before);
}

#[test]
fn gh_manifest_proposal_version_race_refuses_stale_base_without_any_writes() {
    let (_root, store) = ready("manifest-proposal-version-race");
    let store = Arc::new(store);
    let prepared = store.prepare_gh_manifest_proposal(input(REPO)).unwrap();
    let (checked, proceed) = std::sync::mpsc::channel();
    let writing = Arc::clone(&store);
    let job = std::thread::spawn(move || {
        proceed.recv().unwrap();
        let next = std::str::from_utf8(V28)
            .unwrap()
            .replace("\"manifest_version\": 28", "\"manifest_version\": 29");
        store_bytes(&writing, 29, next.as_bytes());
    });
    checked.send(()).unwrap();
    job.join().unwrap();
    let before = snapshot(&store);
    assert_eq!(
        store.propose_gh_manifest_binding(&prepared, "reserved:plexus", || true, || NOW),
        Err(GhManifestProposalError::StaleBase)
    );
    assert_eq!(snapshot(&store), before);
}

#[test]
fn gh_manifest_proposal_concurrent_proposes_return_one_unchanged_row_and_audit() {
    let (_root, store) = ready("manifest-proposal-concurrent");
    let store = Arc::new(store);
    let barrier = Arc::new(Barrier::new(3));
    let jobs: Vec<_> = [REPO, "oCTO-oWNER/nEW-rEPO"]
        .into_iter()
        .map(|repo| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let prepared = store.prepare_gh_manifest_proposal(input(repo)).unwrap();
            std::thread::spawn(move || {
                barrier.wait();
                store
                    .propose_gh_manifest_binding(&prepared, "reserved:plexus", || true, || NOW)
                    .unwrap()
            })
        })
        .collect();
    barrier.wait();
    let replies: Vec<_> = jobs.into_iter().map(|job| job.join().unwrap()).collect();
    assert_eq!(replies[0], replies[1]);
    let audit = store.read_audit(None).unwrap();
    assert_eq!(
        audit
            .iter()
            .filter(|row| row.op == "gh_manifest_propose")
            .count(),
        1
    );
    assert_eq!(
        audit
            .iter()
            .filter(|row| row.op == "gh_manifest_proposal_state")
            .count(),
        0
    );
    assert_eq!(snapshot(&store)[1].len(), 1);
    let mut repeated = input(REPO);
    repeated.app_id = 99;
    repeated
        .installation_permissions
        .insert("contents".into(), "read".into());
    let prepared = store.prepare_gh_manifest_proposal(repeated).unwrap();
    let before = snapshot(&store);
    assert_eq!(
        store
            .propose_gh_manifest_binding(&prepared, "reserved:plexus", || true, || NOW + 1)
            .unwrap(),
        replies[0]
    );
    assert_eq!(snapshot(&store), before);
}

#[test]
fn gh_manifest_proposal_expiry_boundary_reuses_then_replaces_once() {
    let (_root, store) = ready("manifest-proposal-expiry");
    let first = propose(&store, NOW);
    let before = snapshot(&store);
    assert_eq!(propose(&store, first.expires_at_ms - 1), first);
    assert_eq!(snapshot(&store), before);
    let second = propose(&store, first.expires_at_ms);
    assert_ne!(second.proposal_id, first.proposal_id);
    assert_eq!(second.created_at_ms, first.expires_at_ms);
    assert_eq!(second.expires_at_ms, first.expires_at_ms + 86_400_000);
    let after = snapshot(&store);
    for table in [0, 2, 3] {
        assert_eq!(after[table], before[table]);
    }
    assert_eq!(after[1].len(), 2);
    assert_eq!(after[4].len(), before[4].len() + 2);
    store
        .with_raw_conn(|conn| {
            let state: String = conn.query_row(
                "SELECT state FROM gh_manifest_proposals WHERE proposal_id=?1",
                [&first.proposal_id],
                |row| row.get(0),
            )?;
            assert_eq!(state, "expired");
            let state: String = conn.query_row(
                "SELECT state FROM gh_manifest_proposals WHERE proposal_id=?1",
                [&second.proposal_id],
                |row| row.get(0),
            )?;
            assert_eq!(state, "pending");
            Ok(())
        })
        .unwrap();
    let audit = store.read_audit(None).unwrap();
    let new = &audit[audit.len() - 2..];
    assert_eq!(
        new.iter().map(|row| row.op.as_str()).collect::<Vec<_>>(),
        ["gh_manifest_proposal_state", "gh_manifest_propose"]
    );
    assert_eq!(
        new[0].credential_id.as_deref(),
        Some(format!("gh-manifest-proposal|{}", first.proposal_id).as_str())
    );
    assert_eq!(
        new[0].payload_hash.as_deref(),
        Some(framed_hash(&["pending", "expired"]).as_str())
    );
    assert_eq!(propose(&store, second.expires_at_ms - 1), second);
    assert_eq!(snapshot(&store), after);
}

#[test]
fn gh_manifest_proposal_admission_holds_writer_and_admitted_completion_ignores_deadline() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let (root, store) = ready("manifest-proposal-admission");
    let prepared = store.prepare_gh_manifest_proposal(input(REPO)).unwrap();
    let competing = Connection::open(root.join("store.db")).unwrap();
    competing.busy_timeout(std::time::Duration::ZERO).unwrap();
    let calls = AtomicUsize::new(0);
    let before = snapshot(&store);
    let denied = store.propose_gh_manifest_binding(
        &prepared,
        "reserved:plexus",
        || {
            calls.fetch_add(1, Ordering::SeqCst);
            assert!(
                competing
                    .execute_batch("BEGIN IMMEDIATE; ROLLBACK;")
                    .is_err(),
                "admission must run with the SQL writer held"
            );
            false
        },
        || panic!("a denied write must not read the clock or build a statement"),
    );
    assert_eq!(denied, Err(GhManifestProposalError::GithubUnavailable));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(snapshot(&store), before);
    let deadline_elapsed = AtomicBool::new(false);
    let admitted = store
        .propose_gh_manifest_binding(
            &prepared,
            "reserved:plexus",
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                assert!(!deadline_elapsed.load(Ordering::SeqCst));
                true
            },
            || {
                deadline_elapsed.store(true, Ordering::SeqCst);
                NOW
            },
        )
        .unwrap();
    assert!(deadline_elapsed.load(Ordering::SeqCst));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(admitted.created_at_ms, NOW);
    assert_eq!(snapshot(&store)[1].len(), 1);
}

#[test]
fn gh_manifest_proposal_waiting_for_writer_past_deadline_writes_nothing() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let (_root, store) = ready("manifest-proposal-writer-deadline");
    let store = Arc::new(store);
    let prepared = store.prepare_gh_manifest_proposal(input(REPO)).unwrap();
    let before = snapshot(&store);
    let elapsed = Arc::new(AtomicBool::new(false));
    let (attempting, attempted) = std::sync::mpsc::channel();
    let writing = Arc::clone(&store);
    let elapsed_for_job = Arc::clone(&elapsed);
    let job = store
        .fenced_write(|_| {
            let job = std::thread::spawn(move || {
                attempting.send(()).unwrap();
                writing.propose_gh_manifest_binding(
                    &prepared,
                    "reserved:plexus",
                    || !elapsed_for_job.load(Ordering::SeqCst),
                    || NOW,
                )
            });
            attempted.recv().unwrap();
            elapsed.store(true, Ordering::SeqCst);
            Ok(job)
        })
        .unwrap();
    assert_eq!(
        job.join().unwrap(),
        Err(GhManifestProposalError::GithubUnavailable)
    );
    assert_eq!(snapshot(&store), before);
}

#[test]
fn gh_manifest_proposal_expiry_replacement_rolls_back_every_table_on_late_audit_failure() {
    let (_root, store) = ready("manifest-proposal-expiry-rollback");
    let first = propose(&store, NOW);
    store.with_raw_conn(|conn|conn.execute_batch(
        "CREATE TRIGGER fail_proposal_audit BEFORE INSERT ON audit_log WHEN NEW.op='gh_manifest_propose' \
         BEGIN SELECT RAISE(ABORT,'forced proposal audit failure'); END;"
    )).unwrap();
    let before = snapshot(&store);
    let prepared = store.prepare_gh_manifest_proposal(input(REPO)).unwrap();
    assert_eq!(
        store.propose_gh_manifest_binding(
            &prepared,
            "reserved:plexus",
            || true,
            || first.expires_at_ms
        ),
        Err(GhManifestProposalError::StoreError)
    );
    assert_eq!(snapshot(&store), before);
    assert_eq!(
        store.propose_gh_manifest_binding(
            &prepared,
            "reserved:plexus",
            || false,
            || first.expires_at_ms
        ),
        Err(GhManifestProposalError::GithubUnavailable)
    );
    assert_eq!(snapshot(&store), before);
}
