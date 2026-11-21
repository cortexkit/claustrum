//! SSH enrollment store tests.

use super::*;
use crate::admin_ops::{
    apply, AdminAuditOp, AdminOpBody, StoreMode, ADMIN_OP_SCHEMA_V1, ADMIN_OP_SCHEMA_V2,
};
use crate::record::{AgentSsh, AgentSshTarget};
use base64::Engine;

const ID: &str = "signing:ssh-enrollment";

fn key() -> VaultRecord {
    let der =
        ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(der.as_ref())
    );
    VaultRecord::new_static(
        CredentialKind::SigningKey,
        "operator",
        pem.into_bytes(),
        None,
    )
}

fn targets(host: &str) -> Vec<AgentSshTarget> {
    vec![AgentSshTarget {
        user: Some("root".into()),
        host: host.into(),
        port: Some(22),
    }]
}

fn allow(store: &EncryptedStore, host: &str) -> serde_json::Value {
    apply(
        store,
        AdminOpBody::SshKeyAgentAllow {
            v: ADMIN_OP_SCHEMA_V2,
            id: ID.into(),
            targets: targets(host),
        },
        "route:operator",
    )
    .unwrap()
}

fn enabled(store: &EncryptedStore, on: bool) {
    store
        .set_secret_local_programs_audited(on, AuditCtx::admin(AuditOp::SecretLocalProgramsSet))
        .unwrap();
}

fn seed_state(store: &EncryptedStore, id: &str, tag: &str) {
    let incarnation = store.credential_incarnation(id).unwrap();
    store.fenced_write(|tx| {
                tx.execute("INSERT INTO secret_grants (grant_id,secret_name,incarnation,scope_owner,scope_kind,scope_ref,coverage,duration,expires_at_ms,granted_at_ms,envelope_sha256) VALUES (?1,?2,?3,'aft','session','scope','scope','hour',9999999999999,1,'hash')", rusqlite::params![tag,id,incarnation])?;
                tx.execute("INSERT INTO secret_pending_requests (request_id,request_kind,secret_name,incarnation,member_id,statement_bytes,statement_sha256,request_expires_at_ms) VALUES (?1,'approve',?2,?3,'phone',X'01','hash',9999999999999)", rusqlite::params![tag,id,incarnation])?;
                tx.execute("INSERT INTO secret_release_receipts VALUES ('requester',?1,'hash',?2,'once',?1,X'01',X'02',9999999999999)", rusqlite::params![tag,incarnation])?;
                Ok(())
            }).unwrap();
}

fn assert_cleaned(store: &EncryptedStore, id: &str, tag: &str) {
    store.store.with_conn(|conn| {
                for table in ["secret_grants", "secret_pending_requests"] {
                    let count: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {table} WHERE secret_name=?1"), [id], |r| r.get(0))?;
                    assert_eq!(count, 0, "{table}");
                }
                let receipt: (String, Vec<u8>, Vec<u8>, i64) = conn.query_row("SELECT aad_sha256,enc,ciphertext,expires_at_ms FROM secret_release_receipts WHERE requester='requester' AND nonce=?1", [tag], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
                assert_eq!(receipt, ("invalidated".into(), vec![], vec![], 9999999999999));
                Ok(())
            }).unwrap();
}

#[test]
fn allow_replaces_targets_noop_preserves_state_and_deny_clears_authority_while_off() {
    let (_root, store) = tmp_store(0xa1);
    store.create(ID, &key()).unwrap();
    assert!(matches!(
        apply(
            &store,
            AdminOpBody::SshKeyAgentAllow {
                v: ADMIN_OP_SCHEMA_V2,
                id: ID.into(),
                targets: targets("192.0.2.1")
            },
            "operator"
        ),
        Err(StoreOpError::SecretLocalProgramsDisabled)
    ));
    assert_eq!(store.read_audit(Some(20)).unwrap().len(), 1);
    enabled(&store, true);
    assert_eq!(
        allow(&store, "192.0.2.1"),
        serde_json::json!({"targets":targets("192.0.2.1")})
    );
    seed_state(&store, ID, "old");
    let version = store.get(ID).unwrap().record_version;
    let tip = store.read_audit(Some(1)).unwrap();
    allow(&store, "192.0.2.1");
    assert_eq!(store.get(ID).unwrap().record_version, version);
    assert_eq!(store.read_audit(Some(1)).unwrap(), tip);
    store
        .store
        .with_conn(|c| {
            assert_eq!(
                c.query_row("SELECT count(*) FROM secret_grants", [], |r| r
                    .get::<_, i64>(0))?,
                1
            );
            Ok(())
        })
        .unwrap();
    allow(&store, "192.0.2.2");
    assert_eq!(
        store.get(ID).unwrap().agent_ssh.unwrap().targets,
        targets("192.0.2.2")
    );
    assert_cleaned(&store, ID, "old");
    seed_state(&store, ID, "denied");
    enabled(&store, false);
    let result = apply(
        &store,
        AdminOpBody::SshKeyAgentDeny {
            v: ADMIN_OP_SCHEMA_V2,
            id: ID.into(),
        },
        "route:operator",
    )
    .unwrap();
    assert_eq!(result, serde_json::json!({"targets":[]}));
    assert!(store.get(ID).unwrap().agent_ssh.is_none());
    assert_cleaned(&store, ID, "denied");
    enabled(&store, true);
    allow(&store, "192.0.2.2");
    assert_cleaned(&store, ID, "denied");
    let audit = store.read_audit(Some(20)).unwrap();
    assert_eq!(
        audit
            .iter()
            .filter(|r| r.op == "ssh_key_agent_allow")
            .count(),
        3
    );
    assert_eq!(
        audit
            .iter()
            .filter(|r| r.op == "ssh_key_agent_deny")
            .count(),
        1
    );
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[test]
fn generic_admin_writes_refuse_incoming_enrollment_for_every_mode_and_identity_policy() {
    let (_root, store) = tmp_store(0xa2);
    store.create(ID, &key()).unwrap();
    let original = store.get(ID).unwrap();
    let mut marked = key();
    marked.agent_ssh = Some(AgentSsh {
        targets: targets("::1"),
    });
    for mode in [
        StoreMode::Create,
        StoreMode::ReplaceCas {
            expected_hash_hex: hex32(&payload_hash(original.payload.expose())),
        },
        StoreMode::ReplaceUnconditional,
    ] {
        let error = apply(
            &store,
            AdminOpBody::Store {
                v: ADMIN_OP_SCHEMA_V1,
                id: ID.into(),
                record: Box::new(marked.clone()),
                audit_op: AdminAuditOp::Overwrite,
                mode,
            },
            "operator",
        )
        .unwrap_err();
        assert_eq!(error.wire_code(), Some("invalid_params"));
    }
    let error = apply(
        &store,
        AdminOpBody::StoreWithIdentityPolicy {
            v: ADMIN_OP_SCHEMA_V1,
            id: ID.into(),
            record: Box::new(marked),
            audit_op: AdminAuditOp::Overwrite,
            clear_identity: true,
        },
        "operator",
    )
    .unwrap_err();
    assert_eq!(error.wire_code(), Some("invalid_params"));
    assert_eq!(store.get(ID).unwrap(), original);
    assert_eq!(store.read_audit(Some(20)).unwrap().len(), 1);
}

#[test]
fn signing_overwrites_clear_ssh_state_even_when_the_old_envelope_is_corrupt() {
    for mode in 0..3 {
        let (_root, store) = tmp_store(0xa3);
        store.create(ID, &key()).unwrap();
        store.create("signing:other", &key()).unwrap();
        enabled(&store, true);
        allow(&store, "::1");
        seed_state(&store, ID, "replaced");
        seed_state(&store, "signing:other", "other");
        let old = store.get(ID).unwrap();
        let incarnation = store.credential_incarnation(ID).unwrap();
        if mode != 0 {
            store
                .fenced_write(|tx| {
                    tx.execute(
                        "UPDATE credentials SET envelope=X'00' WHERE credential_id=?1",
                        [ID],
                    )
                })
                .unwrap();
        }
        let replacement = key();
        let op = if mode == 2 {
            AdminOpBody::StoreWithIdentityPolicy {
                v: ADMIN_OP_SCHEMA_V1,
                id: ID.into(),
                record: Box::new(replacement),
                audit_op: AdminAuditOp::Overwrite,
                clear_identity: true,
            }
        } else {
            AdminOpBody::Store {
                v: ADMIN_OP_SCHEMA_V1,
                id: ID.into(),
                record: Box::new(replacement),
                audit_op: AdminAuditOp::Overwrite,
                mode: if mode == 0 {
                    StoreMode::ReplaceCas {
                        expected_hash_hex: hex32(&payload_hash(old.payload.expose())),
                    }
                } else {
                    StoreMode::ReplaceUnconditional
                },
            }
        };
        apply(&store, op, "operator").unwrap();
        assert!(store.get(ID).unwrap().agent_ssh.is_none());
        assert_eq!(store.credential_incarnation(ID).unwrap(), incarnation);
        assert_cleaned(&store, ID, "replaced");
        store
            .store
            .with_conn(|c| {
                assert_eq!(
                    c.query_row(
                        "SELECT aad_sha256 FROM secret_release_receipts WHERE nonce='other'",
                        [],
                        |r| r.get::<_, String>(0)
                    )?,
                    "hash"
                );
                assert_eq!(
                    c.query_row(
                        "SELECT count(*) FROM secret_grants WHERE secret_name='signing:other'",
                        [],
                        |r| r.get::<_, i64>(0)
                    )?,
                    1
                );
                Ok(())
            })
            .unwrap();
    }
}

#[test]
fn removing_an_enrolled_key_invalidates_receipts_and_recreation_has_no_authority() {
    let (_root, store) = tmp_store(0xa4);
    store.create(ID, &key()).unwrap();
    enabled(&store, true);
    allow(&store, "::1");
    seed_state(&store, ID, "removed");
    let incarnation = store.credential_incarnation(ID).unwrap();
    store
        .remove_audited(ID, AuditCtx::admin(AuditOp::Remove))
        .unwrap();
    assert_cleaned(&store, ID, "removed");
    store.create(ID, &key()).unwrap();
    assert_ne!(store.credential_incarnation(ID).unwrap(), incarnation);
    assert!(store.get(ID).unwrap().agent_ssh.is_none());
}

#[test]
fn allow_refuses_unreadable_card_ids_without_writing() {
    let (_root, store) = tmp_store(0xa6);
    enabled(&store, true);
    let accepted = format!("signing:{}", "é".repeat(124));
    assert_eq!(accepted.len(), 256);
    store.create(&accepted, &key()).unwrap();
    apply(
        &store,
        AdminOpBody::SshKeyAgentAllow {
            v: ADMIN_OP_SCHEMA_V2,
            id: accepted.clone(),
            targets: targets("::1"),
        },
        "operator",
    )
    .unwrap();
    assert!(store.get(&accepted).unwrap().agent_ssh.is_some());

    let ids = [
        "signing:".to_owned(),
        format!("{accepted}x"),
        "signing:line\nbreak".to_owned(),
        "signing:format\u{e007f}control".to_owned(),
        "signing:line\u{2028}separator".to_owned(),
        "signing:paragraph\u{2029}separator".to_owned(),
    ];
    for (index, id) in ids.iter().enumerate() {
        store.create(id, &key()).unwrap();
        let tag = format!("card-id-{index}");
        seed_state(&store, id, &tag);
        let before = store.store.with_conn(|conn| {
                    conn.query_row("SELECT record_version,envelope,updated_at_ms FROM credentials WHERE credential_id=?1", [id], |r| Ok((r.get::<_,i64>(0)?, r.get::<_,Vec<u8>>(1)?, r.get::<_,i64>(2)?)))
                }).unwrap();
        let audit = store.read_audit(None).unwrap();
        let error = apply(
            &store,
            AdminOpBody::SshKeyAgentAllow {
                v: ADMIN_OP_SCHEMA_V2,
                id: id.clone(),
                targets: targets("::1"),
            },
            "operator",
        )
        .unwrap_err();
        assert!(matches!(error, StoreOpError::InvalidAgentSsh));
        assert_eq!(error.wire_code(), Some("invalid_params"));
        assert_eq!(error.wire_class(), Some("permanent"));
        assert_eq!(store.read_audit(None).unwrap(), audit);
        store.store.with_conn(|conn| {
                    let after = conn.query_row("SELECT record_version,envelope,updated_at_ms FROM credentials WHERE credential_id=?1", [id], |r| Ok((r.get::<_,i64>(0)?, r.get::<_,Vec<u8>>(1)?, r.get::<_,i64>(2)?)))?;
                    assert_eq!(after, before);
                    for table in ["secret_grants", "secret_pending_requests"] {
                        let count: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {table} WHERE secret_name=?1"), [id], |r| r.get(0))?;
                        assert_eq!(count, 1, "{table}");
                    }
                    let receipt: (String, Vec<u8>, Vec<u8>) = conn.query_row("SELECT aad_sha256,enc,ciphertext FROM secret_release_receipts WHERE requester='requester' AND nonce=?1", [&tag], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
                    assert_eq!(receipt, ("hash".into(), vec![1], vec![2]));
                    Ok(())
                }).unwrap();
        assert!(store.get(id).unwrap().agent_ssh.is_none());
    }
}

#[test]
fn allow_refuses_wrong_id_kind_and_non_ed25519_without_writes() {
    let (_root, store) = tmp_store(0xa5);
    enabled(&store, true);
    store.create("opaque:ssh", &key()).unwrap();
    store
        .create(
            ID,
            &VaultRecord::new_static(
                CredentialKind::SigningKey,
                "operator",
                b"not a key".to_vec(),
                None,
            ),
        )
        .unwrap();
    store
        .create(
            "signing:wrong-kind",
            &VaultRecord::new_static(
                CredentialKind::Opaque,
                "operator",
                key().payload.expose().to_vec(),
                None,
            ),
        )
        .unwrap();
    let tip = store.read_audit(Some(1)).unwrap();
    for id in ["opaque:ssh", ID, "signing:wrong-kind"] {
        assert!(matches!(
            store.set_agent_ssh_audited(
                id,
                Some(AgentSsh {
                    targets: targets("::1")
                }),
                "operator"
            ),
            Err(StoreOpError::InvalidAgentSsh)
        ));
    }
    assert_eq!(store.read_audit(Some(1)).unwrap(), tip);
}

#[test]
fn sealing_and_refresh_refuse_marks_on_non_signing_or_non_ed25519_records() {
    let (_root, store) = tmp_store(0xa6);
    let mut marked = key();
    marked.agent_ssh = Some(AgentSsh {
        targets: targets("::1"),
    });
    assert!(store.seal_record(ID, &marked).is_ok());
    assert!(matches!(
        store.seal_record("opaque:ssh", &marked),
        Err(StoreOpError::InvalidAgentSsh)
    ));
    store.create("opaque:ssh", &key()).unwrap();
    assert!(matches!(
        store.commit_refresh(
            "opaque:ssh",
            1,
            &store.credential_incarnation("opaque:ssh").unwrap(),
            &marked,
            None
        ),
        Err(StoreOpError::InvalidAgentSsh)
    ));
    marked.kind = CredentialKind::Opaque;
    assert!(matches!(
        store.seal_record(ID, &marked),
        Err(StoreOpError::InvalidAgentSsh)
    ));
    marked.kind = CredentialKind::SigningKey;
    marked.payload = b"not an Ed25519 key".to_vec().into();
    assert!(matches!(
        store.seal_record(ID, &marked),
        Err(StoreOpError::InvalidAgentSsh)
    ));
    assert!(store.get("opaque:ssh").unwrap().agent_ssh.is_none());
}

#[test]
fn master_key_rotation_preserves_ssh_enrollment_grants_and_receipts() {
    let (_root, mut store) = tmp_store(0xa8);
    store.create(ID, &key()).unwrap();
    enabled(&store, true);
    allow(&store, "::1");
    seed_state(&store, ID, "rotation");
    let old = store.get(ID).unwrap();
    let incarnation = store.credential_incarnation(ID).unwrap();
    assert!(store
        .rotate_master_key(MasterKey::from_bytes([0xa9; MASTER_KEY_LEN]))
        .unwrap()
        .is_empty());
    assert_eq!(store.get(ID).unwrap(), old);
    assert_eq!(store.credential_incarnation(ID).unwrap(), incarnation);
    store
        .store
        .with_conn(|c| {
            assert_eq!(
                c.query_row(
                    "SELECT count(*) FROM secret_grants WHERE grant_id='rotation'",
                    [],
                    |r| r.get::<_, i64>(0)
                )?,
                1
            );
            assert_eq!(
                c.query_row(
                    "SELECT count(*) FROM secret_pending_requests WHERE request_id='rotation'",
                    [],
                    |r| r.get::<_, i64>(0)
                )?,
                1
            );
            assert_eq!(
                c.query_row(
                    "SELECT aad_sha256 FROM secret_release_receipts WHERE nonce='rotation'",
                    [],
                    |r| r.get::<_, String>(0)
                )?,
                "hash"
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn enrollment_cleanup_and_audit_failure_roll_back_together() {
    let (_root, store) = tmp_store(0xa7);
    store.create(ID, &key()).unwrap();
    enabled(&store, true);
    allow(&store, "::1");
    seed_state(&store, ID, "rollback");
    let old = store.get(ID).unwrap();
    store.fenced_write(|tx| tx.execute_batch("CREATE TRIGGER fail_ssh_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;")).unwrap();
    assert!(store.set_agent_ssh_audited(ID, None, "operator").is_err());
    assert_eq!(store.get(ID).unwrap(), old);
    store
        .store
        .with_conn(|c| {
            assert_eq!(
                c.query_row(
                    "SELECT count(*) FROM secret_grants WHERE grant_id='rollback'",
                    [],
                    |r| r.get::<_, i64>(0)
                )?,
                1
            );
            assert_eq!(
                c.query_row(
                    "SELECT count(*) FROM secret_pending_requests WHERE request_id='rollback'",
                    [],
                    |r| r.get::<_, i64>(0)
                )?,
                1
            );
            assert_eq!(
                c.query_row(
                    "SELECT aad_sha256 FROM secret_release_receipts WHERE nonce='rollback'",
                    [],
                    |r| r.get::<_, String>(0)
                )?,
                "hash"
            );
            Ok(())
        })
        .unwrap();
}
