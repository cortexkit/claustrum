//! Operator `put` / `delete` / `revoke` and the lease-free `ck auth secret` listing.
//!
//! The happy paths reuse the phone channel's own release machinery (a grant is created
//! by a signed envelope, then `secret.use` releases), because the point of an operator put
//! is that the resulting record is indistinguishable from a deposited one.
//!
use super::super::*;
use super::operator::list_agent_secrets_read_only;
#[allow(unused_imports)]
use super::operator::{
    OperatorGrantRow, OperatorPhoneRow, OperatorSecretListing, OperatorSecretRow,
};
use crate::agent_secret::{SecretMaterial, SecretPut};
use crate::secret::Secret;
use crate::store::taxonomy_tests::rig;
use crate::store::PhoneOperation;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::json;
use serde_json::Value;
use std::sync::Arc;

const FP: &str = "11111111111111111111111111111111";
const MEMBER: &str = "fed-computer:22222222222222222222222222222222";
const NOW: i64 = 1_700_000_000_000;
const CANARY: &[u8] = b"material-canary-9f3a";

fn api_key_put(name: &str, location: Option<&str>) -> SecretPut {
    SecretPut {
        kind: "agent_api_key".into(),
        name: name.into(),
        host: Some("x.test".into()),
        path_prefix: Some("/repos/a".into()),
        location: Some(location.unwrap_or("authorization_bearer").to_owned()),
        origin: None,
        material_b64url: URL_SAFE_NO_PAD.encode(
            crate::agent_secret::deposit_plaintext(&SecretMaterial::ApiKey(Secret::new(
                CANARY.to_vec(),
            )))
            .expose(),
        ),
    }
}

fn signer() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}

fn phone(store: &EncryptedStore, op: &PhoneOperation, now: i64) -> Value {
    store
        .secret_phone_operation(FP, Some("pair-A"), now, op, || true, || now)
        .unwrap()
}

fn setup(tag: &str) -> (crate::test_support::TestTempDir, Arc<EncryptedStore>) {
    let (root, store) = rig(tag, 73);
    store.ensure_secret_deposit_key().unwrap();
    store
        .set_federation_self_member_audited(MEMBER, AuditCtx::admin(AuditOp::FederationSelfSet))
        .unwrap();
    phone(
        &store,
        &PhoneOperation::Register {
            deposit_pub: vec![2; 32],
            approval_pub: signer()
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
        },
        NOW,
    );
    (root, Arc::new(store))
}

/// Approve whatever `secret.use` asks for, with the signed envelope the phone would send.
fn approve(store: &EncryptedStore, now: i64) -> Value {
    let call = crate::agent_secret::SecretUse {
        name: "ops-key".into(),
        sender: crate::agent_secret::SecretSender::Aft,
        scope: crate::agent_secret::AskingScope {
            owner: "reserved:prefrontal-core".into(),
            kind: "head".into(),
            scope_ref: "H".into(),
            epoch: 1,
        },
        worker_parent: None,
        coverage: "scope".into(),
        agent_id: Some("agent-A".into()),
        target: crate::agent_secret::UseTarget::ApiKey {
            scheme: "https".into(),
            host: "x.test".into(),
            port: 443,
            path: "/repos/a/issues/1".into(),
        },
    };
    let request = store
        .secret_use(&call, || now)
        .map_or_else(|e| e.body(), |o| o.reply);
    let statement = URL_SAFE_NO_PAD
        .decode(request["statement_b64url"].as_str().unwrap())
        .unwrap();
    let envelope = serde_json::to_vec(&json!({
        "v":"ck-secret-use-envelope/v1",
        "items":[{"request_id":request["request_id"],"statement_sha256":sha256_hex(&statement)}],
        "decision":"allow","duration":"permanent","grant_expires_at_ms":0,
        "device_fingerprint":FP,"issued_at_ms":now,
    }))
    .unwrap();
    let signature: Signature = signer().sign(&envelope);
    phone(
        store,
        &PhoneOperation::Approve {
            envelope,
            signature: signature.to_der().as_bytes().to_vec(),
            card_ref: None,
        },
        now,
    );
    request
}

fn sha256_hex(bytes: &[u8]) -> String {
    // Plain lowercase hex of SHA-256, which is what a statement digest is. Deliberately
    // not the audit chain's framed `payload_hash`.
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn counts(store: &EncryptedStore) -> Vec<i64> {
    store
        .store
        .with_conn(|conn| {
            let mut counts = Vec::new();
            for table in [
                "agent_secrets",
                "secret_grants",
                "secret_pending_requests",
                "audit_log",
                "auth_events",
            ] {
                counts.push(
                    conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?,
                );
            }
            Ok(counts)
        })
        .unwrap()
}

/// The listing reader takes a file path, so each rig hands back the store file too.
fn by_path(path: &std::path::Path) -> Option<OperatorSecretListing> {
    list_agent_secrets_read_only(path).unwrap()
}

fn store_file(root: &crate::test_support::TestTempDir) -> std::path::PathBuf {
    root.join("store.db")
}

#[test]
fn operator_put_defaults_to_bearer_and_the_record_releases() {
    let (_root, store) = setup("op-put-release");
    // The CLI is what defaults `--location`; here the operator names it explicitly, which
    // is what the CLI's default produces.
    let stored = store
        .secret_put_audited(
            &api_key_put("ops-key", Some("authorization_bearer")),
            "offline-cli",
        )
        .unwrap();
    assert_eq!(stored["status"], "stored");
    assert_eq!(
        stored["incarnation"].as_str().unwrap().len(),
        32,
        "{stored}"
    );
    assert_eq!(
        store
            .store
            .with_conn(|c| c.query_row(
                "SELECT state FROM agent_secrets WHERE name='ops-key'",
                [],
                |r| { r.get::<_, String>(0) }
            ))
            .unwrap(),
        "active"
    );
    approve(&store, NOW);
    let call = crate::agent_secret::SecretUse {
        name: "ops-key".into(),
        sender: crate::agent_secret::SecretSender::Aft,
        scope: crate::agent_secret::AskingScope {
            owner: "reserved:prefrontal-core".into(),
            kind: "head".into(),
            scope_ref: "H".into(),
            epoch: 1,
        },
        worker_parent: None,
        coverage: "scope".into(),
        agent_id: None,
        target: crate::agent_secret::UseTarget::ApiKey {
            scheme: "https".into(),
            host: "x.test".into(),
            port: 443,
            path: "/repos/a".into(),
        },
    };
    let outcome = store.secret_use(&call, || NOW + 1).unwrap();
    assert_eq!(outcome.reply["status"], "released");
    let key = URL_SAFE_NO_PAD
        .decode(outcome.reply["key_b64url"].as_str().unwrap())
        .unwrap();
    assert_eq!(key, CANARY);
    assert_eq!(outcome.reply["location"], "authorization_bearer");
}

#[test]
fn operator_put_is_create_only_for_live_and_corrupt_rows() {
    let (_root, store) = setup("op-put-create-only");
    store
        .secret_put_audited(&api_key_put("ops-key", None), "offline-cli")
        .unwrap();
    let before = counts(&store);
    let error = store
        .secret_put_audited(&api_key_put("ops-key", None), "offline-cli")
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "name_exists: an agent secret already holds this name; delete it first"
    );
    store
        .store
        .with_conn(|c| {
            c.execute(
                "UPDATE agent_secrets SET state='corrupt' WHERE name='ops-key'",
                [],
            )?;
            Ok(())
        })
        .unwrap();
    let refused = store
        .secret_put_audited(&api_key_put("ops-key", None), "offline-cli")
        .unwrap_err();
    assert_eq!(refused.wire_code(), Some("name_exists"));
    assert_eq!(counts(&store)[0..3], before[0..3]);
}

#[test]
fn operator_put_validates_the_scope_material_and_name_like_a_deposit() {
    let (_root, store) = setup("op-put-validation");
    let before = counts(&store);
    // An API key without a location: the location is always explicit in the byte layouts,
    // and only the CLI fills the bearer default, so the store itself must refuse.
    let mut absent = api_key_put("ops-key", None);
    absent.location = None;
    let error = store
        .secret_put_audited(&absent, "offline-cli")
        .unwrap_err();
    assert_eq!(error.wire_code(), Some("invalid_credential_id"), "{error}");
    // A location the phone path refuses (a forbidden header name) must fail here too.
    assert!(store
        .secret_put_audited(&api_key_put("ops-key", Some("header:Host")), "offline-cli")
        .is_err());
    // A site login whose fields do not match its kind.
    let mut mixed = api_key_put("ops-key", None);
    mixed.origin = Some("https://x.test".into());
    assert!(store.secret_put_audited(&mixed, "offline-cli").is_err());
    // Framing that is not the deposit plaintext layout.
    let mut unfolded = api_key_put("ops-key", None);
    unfolded.material_b64url = URL_SAFE_NO_PAD.encode(CANARY);
    let error = store
        .secret_put_audited(&unfolded, "offline-cli")
        .unwrap_err();
    // The refusal names no byte of the material.
    assert!(
        !format!("{error:?}").contains("material-canary"),
        "{error:?}"
    );
    // Base64 that is not strict: a padding character must be refused.
    let mut padded = api_key_put("ops-key", None);
    padded.material_b64url.push('=');
    assert!(store.secret_put_audited(&padded, "offline-cli").is_err());
    // Name grammar.
    let mut bad_name = api_key_put("bad name", None);
    bad_name.host = Some("x.test".into());
    assert!(store.secret_put_audited(&bad_name, "offline-cli").is_err());
    assert_eq!(counts(&store), before);
}

#[test]
fn operator_put_keeps_material_out_of_audit_debug_and_errors() {
    let (root, store) = setup("op-put-canary");
    let put = api_key_put("ops-key", None);
    let debugged = format!("{put:?}");
    assert!(!debugged.contains("material-canary"), "{debugged}");
    // The base64 of the framed plaintext carries the canary; a hex digest of the sealed
    // row would not, but an operator decoding the payload would see it, so assert the
    // encoded form is absent from both the Debug render and the audit payload.
    let encoded = put.material_b64url.clone();
    assert!(!debugged.contains(&encoded), "{debugged}");
    store.secret_put_audited(&put, "offline-cli").unwrap();
    let payloads = store
        .store
        .with_conn(|c| {
            let mut stmt = c.prepare(
                "SELECT payload_hash, actor, credential_id FROM audit_log WHERE op='secret_store'",
            )?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, Option<String>>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .unwrap();
    assert_eq!(payloads.len(), 1);
    let (hash, actor, target) = &payloads[0];
    let hash = hash.as_deref().unwrap_or_default();
    assert_eq!(actor, "offline-cli");
    assert_eq!(target.as_deref(), Some("secret|ops-key"));
    // A canary long enough to be recognisable in any encoding an audit payload uses:
    // the framed plaintext's base64 and the SHA-256 of the material itself.
    let canary_hex: String = CANARY.iter().map(|b| format!("{b:02x}")).collect();
    let canary_b64 = URL_SAFE_NO_PAD.encode(CANARY);
    let canary_sha = sha256_hex(CANARY);
    for rendering in [&canary_hex, &canary_b64, &canary_sha] {
        assert!(!hash.contains(rendering.as_str()), "{hash}");
    }
    // The row itself is sealed: the plaintext never sits in a column.
    let envelope: Vec<u8> = store
        .store
        .with_conn(|c| {
            c.query_row(
                "SELECT envelope FROM agent_secrets WHERE name='ops-key'",
                [],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert!(
        !envelope
            .windows(CANARY.len())
            .any(|window| window == CANARY),
        "sealed row carries the plaintext bytes"
    );
    // The same renderings must be absent from the row's scope metadata, so a reader
    // cannot recover the material from a column that was meant to be metadata only.
    let metadata = format!("{:?}", by_path(&store_file(&root)));
    for rendering in [&canary_hex, &canary_b64, &canary_sha] {
        assert!(!metadata.contains(rendering.as_str()), "{metadata}");
    }
}

#[test]
fn operator_delete_removes_the_record_its_grants_and_its_pending_requests() {
    let (_root, store) = setup("op-delete");
    store
        .secret_put_audited(&api_key_put("ops-key", None), "offline-cli")
        .unwrap();
    approve(&store, NOW);
    // An unrelated diagnostic row under another subject must survive.
    store
        .store
        .with_conn(|c| {
            c.execute(
                "INSERT INTO auth_events (credential_id, kind, ts_ms) VALUES ('apikey:ops-key','secret_use_refusal',1)",
                [],
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        store
            .secret_operator_delete_audited("ops-key", "offline-cli")
            .unwrap(),
        json!({"status":"deleted"})
    );
    let after = store
        .store
        .with_conn(|c| {
            Ok((
                c.query_row("SELECT count(*) FROM agent_secrets", [], |r| {
                    r.get::<_, i64>(0)
                })?,
                c.query_row("SELECT count(*) FROM secret_grants", [], |r| {
                    r.get::<_, i64>(0)
                })?,
                c.query_row(
                    "SELECT count(*) FROM auth_events WHERE credential_id='apikey:ops-key'",
                    [],
                    |r| r.get::<_, i64>(0),
                )?,
            ))
        })
        .unwrap();
    assert_eq!(after, (0, 0, 1));
    // A second delete finds nothing to remove, and says so as the store's own absence.
    assert!(matches!(
        store
            .secret_operator_delete_audited("ops-key", "offline-cli")
            .unwrap_err(),
        StoreOpError::NotFound
    ));
}

#[test]
fn operator_delete_removes_a_corrupt_row_without_opening_it() {
    let (_root, store) = setup("op-delete-corrupt");
    store
        .secret_put_audited(&api_key_put("ops-key", None), "offline-cli")
        .unwrap();
    store
        .store
        .with_conn(|c| {
            c.execute(
                "UPDATE agent_secrets SET state='corrupt', envelope=x'00' WHERE name='ops-key'",
                [],
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        store
            .secret_operator_delete_audited("ops-key", "offline-cli")
            .unwrap(),
        json!({"status":"deleted"})
    );
    let hash: String = store
        .store
        .with_conn(|c| {
            c.query_row(
                "SELECT payload_hash FROM audit_log WHERE op='secret_delete'",
                [],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert_eq!(hash.len(), 64, "{hash}");
}

#[test]
fn operator_revoke_removes_one_grant_and_answers_not_found_afterwards() {
    let (_root, store) = setup("op-revoke");
    store
        .secret_put_audited(&api_key_put("ops-key", None), "offline-cli")
        .unwrap();
    approve(&store, NOW);
    let (id, name): (String, String) = store
        .store
        .with_conn(|c| {
            c.query_row("SELECT grant_id, secret_name FROM secret_grants", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
        })
        .unwrap();
    assert_eq!(name, "ops-key");
    assert_eq!(
        store
            .secret_operator_revoke_audited(&id, "offline-cli")
            .unwrap(),
        json!({"outcome":"revoked"})
    );
    let audit: (String, String) = store
        .store
        .with_conn(|c| {
            c.query_row(
                "SELECT actor, credential_id FROM audit_log WHERE op='secret_grant_revoke'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
        })
        .unwrap();
    assert_eq!(
        audit,
        ("offline-cli".to_string(), "secret|ops-key".to_string())
    );
    assert_eq!(
        store
            .secret_operator_revoke_audited(&id, "offline-cli")
            .unwrap(),
        json!({"outcome":"not_found"})
    );
    // The secret itself is untouched.
    assert_eq!(counts(&store)[0], 1);
}

#[test]
fn read_only_listing_reports_scopes_grants_and_excludes_secrets_from_the_deposit_namespace() {
    let (root, store) = setup("op-list");
    store
        .secret_put_audited(&api_key_put("ops-key", None), "offline-cli")
        .unwrap();
    approve(&store, NOW);
    let listing = by_path(&store_file(&root)).expect("agent-secret tables exist");
    assert_eq!(listing.secrets.len(), 1);
    let row = &listing.secrets[0];
    assert_eq!(row.name, "ops-key");
    assert_eq!(row.state, "active");
    assert_eq!(row.host.as_deref(), Some("x.test"));
    assert_eq!(row.path_prefix.as_deref(), Some("/repos/a"));
    assert_eq!(row.location.as_deref(), Some("authorization_bearer"));
    assert_eq!(row.grants.len(), 1);
    assert_eq!(row.grants[0].duration, "permanent");
    assert!(row.grants[0].expires_at_ms.is_none());
    // Nothing points at the reserved deposit key: the namespace is fenced out of the
    // name grammar the operator deletes and puts through.
    assert!(listing.secrets.iter().all(|s| !s.name.contains('|')));
}

#[test]
fn read_only_listing_reports_phone_keys_as_current_superseded_or_unobserved() {
    // `setup` registers a phone, and registering records that lookup as the fingerprint's
    // observation, so this vault starts out `current as of` the registration time.
    let (root, store) = setup("op-list-phones");
    let current = by_path(&store_file(&root)).unwrap();
    assert_eq!(current.phones.len(), 1);
    assert_eq!(current.phones[0].current_since_ms, Some(NOW));
    assert!(!current.phones[0].unobserved);
    let observed = |pairing: Option<&str>, at: i64| {
        store.observe_secret_phone(FP, pairing, at).unwrap();
    };
    // A later lookup that sees another pairing: superseded.
    observed(Some("pair-B"), NOW + 1);
    let superseded = by_path(&store_file(&root)).unwrap();
    assert!(superseded.phones[0].current_since_ms.is_none());
    assert_eq!(
        superseded.phones[0].observed_pairing_id.as_deref(),
        Some("pair-B")
    );
    // A lookup that found the device absent: also superseded, and still observed.
    observed(None, NOW + 2);
    let absent = by_path(&store_file(&root)).unwrap();
    assert!(absent.phones[0].current_since_ms.is_none());
    assert!(absent.phones[0].observed_pairing_id.is_none());
    assert!(!absent.phones[0].unobserved);
    // The unobserved state needs a key row with no observation at all, which is what a
    // vault holds between a restore of the key table and its first lookup.
    let (fresh_root, fresh) = rig("op-list-unobserved", 76);
    fresh
        .store
        .with_conn(|conn| {
            conn.execute(
                "INSERT INTO secret_phone_keys (fingerprint,pairing_id,deposit_pub,approval_pub,created_at_ms) VALUES (?1,'pair-A',?2,?3,1)",
                rusqlite::params![
                    FP,
                    vec![2u8; 32],
                    signer()
                        .verifying_key()
                        .to_encoded_point(false)
                        .as_bytes()
                        .to_vec()
                ],
            )?;
            Ok(())
        })
        .unwrap();
    let unobserved = by_path(&store_file(&fresh_root)).unwrap();
    assert_eq!(unobserved.phones.len(), 1);
    assert!(unobserved.phones[0].unobserved, "{unobserved:?}");
    assert!(unobserved.phones[0].current_since_ms.is_none());
}

#[test]
fn read_only_listing_says_a_pre_migration_store_has_no_agent_secret_tables() {
    use cortexkit_store::{open_sqlite, Isolation, StorageBackend, StorageDescriptor};
    let root = crate::test_support::TestTempDir::new(format!(
        "op-list-premigration-{}",
        std::process::id()
    ));
    let path = root.join("store.db");
    let sqlite = open_sqlite(&StorageDescriptor {
        module_id: "claustrum".into(),
        storage_namespace: "op-list-premigration".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: path.to_string_lossy().into_owned(),
        },
    })
    .unwrap();
    // One migration short of the agent-secret tables, built by the real chain.
    crate::store::migrate_through_for_test(&sqlite, crate::store::AGENT_SECRET_SCHEMA_VERSION - 1)
        .unwrap();
    drop(sqlite);
    assert_eq!(list_agent_secrets_read_only(&path).unwrap(), None);
}

#[path = "store_secret_flow_schema_tests.rs"]
mod flow_schema_tests;
