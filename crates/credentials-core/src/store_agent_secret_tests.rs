use super::*;
use crate::agent_secret::{SecretMaterial, SecretScope};
use crate::secret::Secret;
use crate::store::taxonomy_tests::rig;

fn scope() -> SecretScope {
    SecretScope::ApiKey {
        host: "x.test".into(),
        path_prefix: None,
        location: "authorization_bearer".into(),
    }
}
fn insert_secret(store: &EncryptedStore, name: &str, incarnation: &str) {
    let blob = agent_secret::seal(
        &store.key,
        incarnation,
        name,
        &scope(),
        &SecretMaterial::ApiKey(Secret::new(b"canary-key".to_vec())),
    )
    .unwrap();
    store.fenced_write(|tx| {
        tx.execute("INSERT INTO agent_secrets (name, kind, incarnation, state, host, location, record_version, key_id, envelope, created_at_ms) VALUES (?1, 'agent_api_key', ?2, 'active', 'x.test', 'authorization_bearer', 1, ?3, ?4, 0)", rusqlite::params![name, incarnation, store.key_id.to_hex(), blob])?;
        Ok(())
    }).unwrap();
}

#[test]
fn migration_27_creates_exactly_six_secret_tables() {
    let (_root, store) = rig("secret-schema", 50);
    assert_eq!(newest_migration_version(), 27);
    let tables = store.store.with_conn(|conn| {
        let mut stmt = conn.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND (name = 'agent_secrets' OR name LIKE 'secret_%') ORDER BY name")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
    }).unwrap();
    assert_eq!(
        tables,
        [
            "agent_secrets",
            "secret_deposit_tombstones",
            "secret_grants",
            "secret_pending_requests",
            "secret_phone_keys",
            "secret_phone_observations"
        ]
    );
    insert_secret(&store, "Example", "00000000000000000000000000000000");
    assert!(store
        .fenced_write(|tx| tx.execute("UPDATE agent_secrets SET location = NULL", []))
        .is_err());
    assert!(store
        .fenced_write(|tx| tx.execute("UPDATE agent_secrets SET location = ''", []))
        .is_err());
}

#[test]
fn every_secret_table_blocks_audit_key_regeneration() {
    let inserts = [
        "INSERT INTO agent_secrets VALUES ('Example', 'agent_api_key', '00000000000000000000000000000000', 'active', 'x.test', NULL, 'authorization_bearer', NULL, 1, 'key', x'00', 0)",
        "INSERT INTO secret_phone_keys VALUES ('fp', 'pairing', zeroblob(32), zeroblob(65), 0)",
        "INSERT INTO secret_phone_observations VALUES ('fp', NULL, 0)",
        "INSERT INTO secret_pending_requests (request_id, request_kind, secret_name, incarnation, member_id, statement_bytes, statement_sha256, request_expires_at_ms) VALUES ('req', 'delete', 'Example', 'inc', 'member', x'00', 'hash', 0)",
        "INSERT INTO secret_grants (grant_id, secret_name, incarnation, scope_owner, scope_kind, scope_ref, coverage, duration, expires_at_ms, granted_at_ms, envelope_sha256) VALUES ('grant', 'Example', 'inc', 'owner', 'head', 'ref', 'scope', 'once', 0, 0, 'hash')",
        "INSERT INTO secret_deposit_tombstones VALUES ('id', 'digest', 'member', 'inc')",
    ];
    for (i, insert) in inserts.iter().enumerate() {
        let (_root, store) = rig(&format!("secret-audit-{i}"), 51);
        store
            .fenced_write(|tx| {
                tx.execute("DELETE FROM vault_secrets", [])?;
                tx.execute_batch(insert)?;
                Ok(())
            })
            .unwrap();
        assert!(
            matches!(
                load_or_create_audit_key(&store.store, &store.key),
                Err(StoreOpError::CorruptVault(_))
            ),
            "a secret table with a missing audit key is a corrupt vault: {insert}"
        );
        store
            .store
            .with_conn(|conn| {
                assert_eq!(
                    conn.query_row("SELECT count(*) FROM vault_secrets", [], |r| r
                        .get::<_, i64>(0))?,
                    0
                );
                assert_eq!(
                    conn.query_row("SELECT count(*) FROM credentials", [], |r| r
                        .get::<_, i64>(0))?,
                    0
                );
                Ok(())
            })
            .unwrap();
    }
}

#[test]
fn rotation_rewraps_secrets_and_quarantines_without_an_extra_audit_row() {
    let (_root, mut store) = rig("secret-rotate", 52);
    let incarnation = "00000000000000000000000000000000";
    insert_secret(&store, "Good", incarnation);
    insert_secret(&store, "Broken", "11111111111111111111111111111111");
    store
        .fenced_write(|tx| {
            tx.execute(
                "UPDATE agent_secrets SET envelope = x'00' WHERE name = 'Broken'",
                [],
            )
        })
        .unwrap();
    let old_key = MasterKey::from_bytes([52; 32]);
    assert_eq!(
        store
            .rotate_master_key(MasterKey::from_bytes([53; 32]))
            .unwrap(),
        ["secret|Broken"]
    );
    let (blob, key_id, state) = store
        .store
        .with_conn(|conn| {
            conn.query_row(
                "SELECT envelope, key_id, state FROM agent_secrets WHERE name = 'Good'",
                [],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                },
            )
        })
        .unwrap();
    assert_eq!(state, "active");
    assert_eq!(key_id, store.key_id.to_hex());
    assert_eq!(
        agent_secret::open(&store.key, incarnation, "Good", &scope(), &blob).unwrap(),
        SecretMaterial::ApiKey(Secret::new(b"canary-key".to_vec()))
    );
    assert!(agent_secret::open(&old_key, incarnation, "Good", &scope(), &blob).is_err());
    let state: String = store
        .store
        .with_conn(|conn| {
            conn.query_row(
                "SELECT state FROM agent_secrets WHERE name = 'Broken'",
                [],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert_eq!(state, "corrupt");
    let audit = store.read_audit(None).unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].op, "rotate_master_key");
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[test]
fn deposit_bootstrap_is_idempotent_and_payload_hash_is_framed_key_id() {
    assert_eq!(
        deposit_key_creation_hash("0123456789abcdef"),
        "1537cf2a171f76d454f169f286923918910e22e4f9cdfa27a9e044692f663175"
    );
    let (_root, store) = rig("secret-bootstrap", 54);
    store.ensure_secret_deposit_key().unwrap();
    let key = store.secret_deposit_public_key().unwrap();
    store.ensure_secret_deposit_key().unwrap();
    assert_eq!(store.secret_deposit_public_key().unwrap(), key);
    assert_eq!(key.key_id, sha256_hex_of_bytes(&key.public_key)[..16]);
    let audit = store.read_audit(None).unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].op, "secret_deposit_key_create");
    assert_eq!(audit[0].actor, "vault");
    assert_eq!(audit[0].credential_id.as_deref(), Some(DEPOSIT_KEY_ID));
    let mut payload = Vec::new();
    agent_secret::push_field(&mut payload, key.key_id.as_bytes());
    assert_eq!(
        audit[0].payload_hash.as_deref(),
        Some(sha256_hex_of_bytes(&payload).as_str())
    );
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[test]
fn unusable_deposit_keys_are_not_replaced_and_report_setup_incomplete() {
    for (i, fault) in [
        "UPDATE credentials SET state = 'needs_reauth'",
        "UPDATE credentials SET envelope = x'00'",
    ]
    .iter()
    .enumerate()
    {
        let (_root, store) = rig(&format!("secret-key-fault-{i}"), 55);
        store.ensure_secret_deposit_key().unwrap();
        store.fenced_write(|tx| tx.execute(fault, [])).unwrap();
        store.ensure_secret_deposit_key().unwrap();
        assert!(matches!(
            store.secret_deposit_public_key(),
            Err(StoreOpError::SecretSetupIncomplete)
        ));
        assert_eq!(store.read_audit(None).unwrap().len(), 1);
    }
    for kind in [CredentialKind::ApiKey, CredentialKind::KemKey] {
        let (_root, store) = rig("secret-key-kind", 56);
        store
            .create(
                DEPOSIT_KEY_ID,
                &VaultRecord::new_static(kind, "test", b"not-a-key".to_vec(), None),
            )
            .unwrap();
        store.ensure_secret_deposit_key().unwrap();
        assert!(matches!(
            store.secret_deposit_public_key(),
            Err(StoreOpError::SecretSetupIncomplete)
        ));
        assert_eq!(store.read_audit(None).unwrap().len(), 1);
    }
}

#[test]
fn deposit_key_fence_refuses_grants_handles_and_operator_mutation() {
    let (_root, store) = rig("secret-key-fence", 57);
    store.ensure_secret_deposit_key().unwrap();
    let before = store.secret_deposit_public_key().unwrap();
    for operation in [
        GrantOperation::Read,
        GrantOperation::List,
        GrantOperation::Sign,
        GrantOperation::Open,
        GrantOperation::Seal,
    ] {
        assert!(matches!(
            store.create_read_grant_audited(
                "reserved",
                "callosum",
                SelectorKind::Exact,
                DEPOSIT_KEY_ID,
                operation,
                AuditCtx::admin(AuditOp::GrantCreate)
            ),
            Err(StoreOpError::NotFound)
        ));
    }
    assert!(matches!(
        store.put_handle_hash("hash", DEPOSIT_KEY_ID, AuditCtx::admin(AuditOp::MintHandle)),
        Err(StoreOpError::NotFound)
    ));
    assert!(store
        .remove_audited(DEPOSIT_KEY_ID, AuditCtx::admin(AuditOp::Remove))
        .is_err());
    assert!(store.invalidate(DEPOSIT_KEY_ID).is_err());
    assert!(store
        .retire_and_revoke_all_audited(DEPOSIT_KEY_ID, AuditCtx::admin(AuditOp::Invalidate))
        .is_err());
    assert!(store
        .invalidate_and_revoke_all_audited(DEPOSIT_KEY_ID, AuditCtx::admin(AuditOp::Invalidate))
        .is_err());
    let replacement = VaultRecord::new_static(
        CredentialKind::ApiKey,
        "test",
        b"replacement".to_vec(),
        None,
    );
    assert!(matches!(
        store.accept_incoming_transfer_audited(&crate::federation::TransferAcceptance {
            sender_member: "fed-computer:00000000000000000000000000000000".into(),
            transfer_id: "00000000000000000000000000000000".into(),
            body_hash: "0".repeat(64),
            credential_id: DEPOSIT_KEY_ID.into(),
            record: replacement.clone(),
            categories: vec![],
            provider_ids: vec![],
            replace: true,
        }),
        Err(StoreOpError::NotFound)
    ));
    assert!(store
        .overwrite_unconditional_audited(
            DEPOSIT_KEY_ID,
            &replacement,
            AuditCtx::admin(AuditOp::Overwrite)
        )
        .is_err());
    assert_eq!(store.secret_deposit_public_key().unwrap(), before);
    assert_eq!(store.read_audit(None).unwrap().len(), 1);
}
