use super::*;
use crate::gh_manifest::MANIFEST_BINDING_ENVELOPE_V1_TAG;
use crate::record::{CredentialKind, VaultRecord};
use crate::store::{taxonomy_tests, GhManifestProposalInput, PhoneOperation};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use ring::signature::KeyPair as _;
use std::collections::BTreeMap;

const NOW: i64 = 1_794_355_300_123;
const FP: &str = "11111111111111111111111111111111";
const MEMBER: &str = "fed-computer:22222222222222222222222222222222";
const V28: &[u8] = include_bytes!("../tests/fixtures/gh-manifest-v28.json");
const SEED: u8 = 197;

fn hash(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

fn signer() -> SigningKey {
    SigningKey::from_bytes((&[7; 32]).into()).unwrap()
}

fn root_key() -> (VaultRecord, Vec<u8>) {
    let der =
        ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(der.as_ref()).unwrap();
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(der.as_ref())
    );
    (
        VaultRecord::new_static(
            CredentialKind::SigningKey,
            "operator",
            pem.into_bytes(),
            None,
        ),
        pair.public_key().as_ref().to_vec(),
    )
}

fn run(store: &EncryptedStore, op: &PhoneOperation, now: i64) -> Result<Value, SecretError> {
    store.secret_phone_operation(FP, Some("pair-A"), now, op, || true, || now)
}

fn ready(label: &str) -> (crate::test_support::TestTempDir, EncryptedStore, Vec<u8>) {
    let (dir, store) = taxonomy_tests::rig(label, SEED);
    let (record, public) = root_key();
    store
        .create_audited(
            GH_MANIFEST_ROOT_KEY_ID,
            &record,
            AuditCtx::admin(AuditOp::Put),
        )
        .unwrap();
    store
        .set_federation_self_member_audited(MEMBER, AuditCtx::admin(AuditOp::FederationSelfSet))
        .unwrap();
    store
        .store_gh_manifest(
            &GhManifestVersion {
                version: 28,
                manifest_bytes: V28,
                manifest_sha256: &hash(V28),
                key_id: "0123456789abcdef",
                signature: &[7; 64],
                signed_at_ms: NOW,
                source: GhManifestSource::Import,
                approval_audit_seq: None,
            },
            AuditCtx::admin(AuditOp::GhManifestStore),
        )
        .unwrap();
    run(
        &store,
        &PhoneOperation::Register {
            deposit_pub: crate::kem::public_half(&crate::kem::generate_key().unwrap())
                .unwrap()
                .0,
            approval_pub: signer()
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
        },
        NOW,
    )
    .unwrap();
    (dir, store, public)
}

fn propose(store: &EncryptedStore, repo: &str, now: i64) -> GhManifestProposal {
    let prepared = store
        .prepare_gh_manifest_proposal(GhManifestProposalInput {
            agent_id: "agent_4444444444444444".into(),
            app_id: 42,
            app_slug: "repo-bot".into(),
            repo: repo.into(),
            installation_permissions: BTreeMap::from([
                ("contents".into(), "write".into()),
                ("metadata".into(), "read".into()),
            ]),
        })
        .unwrap();
    store
        .propose_gh_manifest_binding(&prepared, "reserved:plexus", || true, || now)
        .unwrap()
}

fn envelope(p: &GhManifestProposal, issued: i64) -> ManifestBindingEnvelope {
    ManifestBindingEnvelope {
        v: String::from_utf8(MANIFEST_BINDING_ENVELOPE_V1_TAG.to_vec()).unwrap(),
        proposal_id: p.proposal_id.clone(),
        statement_sha256: p.statement_sha256.clone(),
        decision: "allow".into(),
        device_fingerprint: FP.into(),
        issued_at_ms: issued as u64,
    }
}

fn signed_bytes(bytes: Vec<u8>, key: &SigningKey) -> PhoneOperation {
    let signature: Signature = key.sign(&bytes);
    PhoneOperation::ManifestApprove {
        envelope: bytes,
        signature: signature.to_der().as_bytes().to_vec(),
    }
}

fn approve(e: &ManifestBindingEnvelope) -> PhoneOperation {
    signed_bytes(e.canonical_bytes().unwrap(), &signer())
}

fn snapshot(store: &EncryptedStore) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
    store
        .with_raw_conn(|conn| {
            [
                "gh_manifests",
                "gh_manifest_proposals",
                "gh_manifest_activations",
                "gh_manifest_activation_audits",
                "audit_log",
            ]
            .iter()
            .map(|table| {
                let mut stmt = conn.prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))?;
                let count = stmt.column_count();
                let rows = stmt
                    .query_map([], |r| {
                        (0..count)
                            .map(|i| r.get(i))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .collect()
        })
        .unwrap()
}

fn refuses(store: &EncryptedStore, op: &PhoneOperation, now: i64, error: SecretError) {
    let before = snapshot(store);
    assert_eq!(run(store, op, now), Err(error));
    assert_eq!(
        snapshot(store),
        before,
        "refusal must not sign or change the five protected tables"
    );
}

#[test]
fn gh_manifest_approval_commits_signature_audits_siblings_and_persistent_exact_resend() {
    let (dir, store, public) = ready("manifest-approval-success");
    let p = propose(&store, "Octo/New", NOW);
    let sibling = propose(&store, "Octo/Other", NOW + 1);
    let e = envelope(&p, NOW + 10);
    let op = approve(&e);
    let expected = json!({"status":"approved", "proposal_id":p.proposal_id, "version":29, "manifest_sha256":hash(&p.manifest_bytes)});
    let before = snapshot(&store);
    assert_eq!(run(&store, &op, NOW + 10).unwrap(), expected);
    let after = snapshot(&store);
    assert_eq!(after[0].len(), before[0].len() + 1);
    assert_eq!(after[4].len(), before[4].len() + 5);
    store.with_raw_conn(|conn| {
        let (bytes, signature, key_id, time, source, seq): (Vec<u8>,Vec<u8>,String,i64,String,i64) = conn.query_row(
            "SELECT manifest_bytes,signature,key_id,signed_at_ms,source,approval_audit_seq FROM gh_manifests WHERE version=29", [],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)))?;
        assert_eq!(bytes, p.manifest_bytes);
        assert_eq!(time, NOW + 10);
        assert_eq!(source, "one_tap");
        assert_eq!(key_id, crate::signing::key_id_for_public(&public));
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &public).verify(&bytes,&signature).unwrap();
        let mut changed = bytes; changed[0] ^= 1;
        assert!(ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &public).verify(&changed,&signature).is_err());
        let (id, digest, actor): (String,String,String) = conn.query_row(
            "SELECT credential_id,payload_hash,actor FROM audit_log WHERE seq=?1 AND op='approval'", [seq],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        assert_eq!(id, GH_MANIFEST_ROOT_KEY_ID); assert_eq!(digest, hash(&p.manifest_bytes));
        assert!(actor.ends_with(&format!("approver:fed-phone:{FP}")));
        let (state, digest, fp): (String,String,String) = conn.query_row(
            "SELECT state,approved_envelope_sha256,approved_fingerprint FROM gh_manifest_proposals WHERE proposal_id=?1", [&p.proposal_id],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        assert_eq!((state,digest,fp), ("approved".into(), hash(&e.canonical_bytes().unwrap()), FP.into()));
        assert_eq!(conn.query_row("SELECT state FROM gh_manifest_proposals WHERE proposal_id=?1", [&sibling.proposal_id], |r| r.get::<_,String>(0))?, "superseded");
        let mut stmt = conn.prepare("SELECT op FROM audit_log WHERE seq>=?1 ORDER BY seq")?;
        let ops = stmt.query_map([seq], |r| r.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        assert_eq!(ops, ["approval", "gh_manifest_sign", "gh_manifest_proposal_state", "gh_manifest_store", "gh_manifest_proposal_state"]);
        Ok(())
    }).unwrap();
    assert!(store.verify_audit_chain().is_ok());
    assert_eq!(
        run(&store, &op, NOW + 10 + SECRET_ISSUE_SKEW_LIMIT_MS).unwrap(),
        expected
    );
    assert_eq!(snapshot(&store), after);
    refuses(
        &store,
        &approve(&envelope(&sibling, NOW + 11)),
        NOW + 11,
        SecretError::Superseded,
    );
    drop(store);
    let sqlite = cortexkit_store::open_sqlite(&cortexkit_store::StorageDescriptor {
        module_id: "claustrum".into(),
        storage_namespace: "taxonomy-manifest-approval-success".into(),
        isolation: cortexkit_store::Isolation::Module,
        backend: cortexkit_store::StorageBackend::Sqlite {
            path: dir.join("store.db").to_string_lossy().into_owned(),
        },
    })
    .unwrap();
    let store =
        EncryptedStore::open(sqlite, crate::key::MasterKey::from_bytes([SEED; 32])).unwrap();
    assert_eq!(run(&store, &op, NOW + 11).unwrap(), expected);
    assert_eq!(snapshot(&store), after);
    refuses(
        &store,
        &approve(&envelope(&p, NOW + 11)),
        NOW + 11,
        SecretError::ApprovalInvalid,
    );
    refuses(
        &store,
        &op,
        NOW + 11 + SECRET_ISSUE_SKEW_LIMIT_MS,
        SecretError::ApprovalInvalid,
    );
}

#[test]
fn gh_manifest_approval_invalid_envelopes_precede_state_refusals_and_write_nothing() {
    let (_dir, store, _) = ready("manifest-approval-invalid");
    let p = propose(&store, "Octo/New", NOW);
    let valid = envelope(&p, NOW);
    let mut cases = Vec::new();
    let mut e = valid.clone();
    e.proposal_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV".into();
    cases.push((e, NOW));
    let mut e = valid.clone();
    e.statement_sha256 = "a".repeat(64);
    cases.push((e, NOW));
    let mut e = valid.clone();
    e.device_fingerprint = "2".repeat(32);
    cases.push((e, NOW));
    let mut e = valid.clone();
    e.issued_at_ms = (NOW - 1) as u64;
    cases.push((e, NOW));
    let mut e = valid.clone();
    e.issued_at_ms = (NOW + SECRET_ISSUE_SKEW_LIMIT_MS + 1) as u64;
    cases.push((e, NOW));
    cases.push((valid.clone(), NOW + SECRET_ISSUE_SKEW_LIMIT_MS + 1));
    for (e, now) in cases {
        refuses(&store, &approve(&e), now, SecretError::ApprovalInvalid);
    }
    let wrong_key = SigningKey::from_bytes((&[8; 32]).into()).unwrap();
    refuses(
        &store,
        &signed_bytes(valid.canonical_bytes().unwrap(), &wrong_key),
        NOW,
        SecretError::ApprovalInvalid,
    );
    let bytes = valid.canonical_bytes().unwrap();
    let mut noncanonical = bytes.clone();
    noncanonical.push(b'\n');
    refuses(
        &store,
        &signed_bytes(noncanonical, &signer()),
        NOW,
        SecretError::ApprovalInvalid,
    );
    refuses(
        &store,
        &PhoneOperation::ManifestApprove {
            envelope: bytes,
            signature: vec![0],
        },
        NOW,
        SecretError::ApprovalInvalid,
    );

    for state in ["superseded", "expired"] {
        store
            .with_raw_conn(|conn| {
                conn.execute(
                    "UPDATE gh_manifest_proposals SET state=?1 WHERE proposal_id=?2",
                    params![state, p.proposal_id],
                )
            })
            .unwrap();
        let mut mismatched = valid.clone();
        mismatched.statement_sha256 = "b".repeat(64);
        refuses(
            &store,
            &approve(&mismatched),
            NOW,
            SecretError::ApprovalInvalid,
        );
        refuses(
            &store,
            &approve(&valid),
            NOW,
            if state == "superseded" {
                SecretError::Superseded
            } else {
                SecretError::Expired
            },
        );
    }
}

#[test]
fn gh_manifest_approval_expiry_checks_now_and_issue_time_at_the_exact_boundary() {
    for (label, now_delta, issue_delta) in [("now", 0, -1), ("issue", -1, 0), ("both", 0, 0)] {
        let (_dir, store, _) = ready(&format!("manifest-expiry-{label}"));
        let p = propose(&store, "Octo/New", NOW);
        refuses(
            &store,
            &approve(&envelope(&p, p.expires_at_ms + issue_delta)),
            p.expires_at_ms + now_delta,
            SecretError::Expired,
        );
    }
    let (_dir, store, _) = ready("manifest-expiry-last-valid");
    let p = propose(&store, "Octo/New", NOW);
    assert_eq!(
        run(
            &store,
            &approve(&envelope(&p, p.expires_at_ms - 1)),
            p.expires_at_ms - 1
        )
        .unwrap()["status"],
        "approved"
    );
    let (_dir, store, _) = ready("manifest-expiry-replaced");
    let old = propose(&store, "Octo/New", NOW);
    let replacement = propose(&store, "Octo/New", old.expires_at_ms);
    assert_ne!(replacement.proposal_id, old.proposal_id);
    refuses(
        &store,
        &approve(&envelope(&old, old.expires_at_ms)),
        old.expires_at_ms,
        SecretError::Expired,
    );
}

#[test]
fn gh_manifest_approval_pipeline_precedence_and_setup_requirements() {
    let (_dir, store) = taxonomy_tests::rig("manifest-pipeline", SEED);
    let op = PhoneOperation::ManifestApprove {
        envelope: vec![],
        signature: vec![],
    };
    refuses(&store, &op, NOW, SecretError::PhoneNotRegistered);
    assert_eq!(
        store.secret_phone_operation(FP, Some("pair-A"), NOW, &op, || false, || NOW),
        Err(SecretError::PairingUnavailable)
    );
    for (home, self_member, expected) in [
        (
            "fed-computer:33333333333333333333333333333333",
            Some(MEMBER),
            "secret_home_elsewhere",
        ),
        (
            "fed-computer:33333333333333333333333333333333",
            None,
            "remote_setup_incomplete",
        ),
    ] {
        store.with_raw_conn(|conn| {
            conn.execute("INSERT OR REPLACE INTO settings (name,value,updated_at_ms) VALUES ('secrets.home_member',?1,0)",[home])?;
            conn.execute("DELETE FROM settings WHERE name=?1",[crate::federation::SELF_MEMBER_SETTING])?;
            if let Some(member) = self_member { conn.execute("INSERT INTO settings (name,value,updated_at_ms) VALUES (?1,?2,0)",params![crate::federation::SELF_MEMBER_SETTING,member])?; }
            Ok(())
        }).unwrap();
        let before = snapshot(&store);
        let result = run(&store, &op, NOW).unwrap();
        assert_eq!(result["error"]["code"], expected);
        if self_member.is_some() {
            assert_eq!(result["error"]["remedy_member"], home);
        }
        assert_eq!(snapshot(&store), before);
    }
    for missing in ["root", "base", "member"] {
        let (_dir, store, _) = ready(&format!("manifest-setup-{missing}"));
        if missing == "base" {
            store
                .with_raw_conn(|conn| {
                    conn.execute_batch(
                        "DROP TRIGGER gh_manifests_no_delete; DELETE FROM gh_manifests;",
                    )
                })
                .unwrap();
        } else {
            store
                .with_raw_conn(|conn| {
                    if missing == "root" {
                        conn.execute(
                            "UPDATE credentials SET state='deleted' WHERE credential_id=?1",
                            [GH_MANIFEST_ROOT_KEY_ID],
                        )?;
                    } else {
                        conn.execute(
                            "DELETE FROM settings WHERE name=?1",
                            [crate::federation::SELF_MEMBER_SETTING],
                        )?;
                    }
                    Ok(())
                })
                .unwrap();
        }
        refuses(&store, &op, NOW, SecretError::ManifestSetupIncomplete);
        assert_eq!(
            store.secret_phone_operation(FP, Some("new-pair"), NOW, &op, || true, || NOW),
            Err(SecretError::PhoneNotRegistered)
        );
    }
}

#[test]
fn gh_manifest_approval_domain_separation_rejects_both_cross_envelopes_before_crypto() {
    use crate::agent_secret::{ApprovalEnvelope, ApprovalItem, USE_ENVELOPE_TAG};
    let (_dir, store, _) = ready("manifest-domain-separation");
    let p = propose(&store, "Octo/New", NOW);
    let secret = ApprovalEnvelope {
        v: String::from_utf8(USE_ENVELOPE_TAG.to_vec()).unwrap(),
        items: vec![ApprovalItem {
            request_id: p.proposal_id.clone(),
            statement_sha256: p.statement_sha256.clone(),
        }],
        decision: "allow".into(),
        duration: "once".into(),
        grant_expires_at_ms: 0,
        device_fingerprint: FP.into(),
        issued_at_ms: NOW as u64,
    };
    let secret_bytes = secret.canonical_bytes().unwrap();
    // Empty crypto inputs cannot be reached by these strict deserializations.
    assert!(serde_json::from_slice::<ManifestBindingEnvelope>(&secret_bytes).is_err());
    refuses(
        &store,
        &PhoneOperation::ManifestApprove {
            envelope: secret_bytes,
            signature: vec![],
        },
        NOW,
        SecretError::ApprovalInvalid,
    );
    let manifest_bytes = envelope(&p, NOW).canonical_bytes().unwrap();
    assert!(serde_json::from_slice::<ApprovalEnvelope>(&manifest_bytes).is_err());
    assert!(matches!(
        ApprovalEnvelope::verify(&manifest_bytes, &[], &[], FP),
        Err(SecretError::ApprovalInvalid)
    ));
    refuses(
        &store,
        &PhoneOperation::Approve {
            envelope: manifest_bytes,
            signature: vec![],
            card_ref: None,
        },
        NOW,
        SecretError::ApprovalInvalid,
    );
}

#[test]
fn gh_manifest_approval_rederives_every_statement_field_including_permissions() {
    for (field, replacement) in [
        ("v", json!("other/v1")),
        ("proposal_id", json!("01ARZ3NDEKTSV4RRFFQ69G5FAV")),
        ("agent_id", json!("agent_other")),
        ("app_slug", json!("other-bot")),
        ("repo", json!("Octo/Other")),
        ("installation_permissions", json!({"contents":"admin"})),
        ("manifest_version", json!(30)),
        ("manifest_sha256", json!("a".repeat(64))),
        ("prior_version", json!(27)),
        ("prior_sha256", json!("b".repeat(64))),
        ("expires_at_ms", json!(NOW + 1000)),
    ] {
        let (_dir, store, _) = ready(&format!("manifest-commitment-{field}"));
        let mut p = propose(&store, "Octo/New", NOW);
        let mut statement: Value = serde_json::from_slice(&p.statement_bytes).unwrap();
        statement[field] = replacement;
        p.statement_bytes = serde_json::to_vec(&statement).unwrap();
        p.statement_sha256 = hash(&p.statement_bytes);
        store.with_raw_conn(|conn| conn.execute(
            "UPDATE gh_manifest_proposals SET statement_bytes=?2,statement_sha256=?3 WHERE proposal_id=?1",
            params![p.proposal_id,p.statement_bytes,p.statement_sha256])).unwrap();
        refuses(
            &store,
            &approve(&envelope(&p, NOW)),
            NOW,
            SecretError::ApprovalInvalid,
        );
    }
}

#[test]
fn gh_manifest_approval_rejects_byte_tampering_and_coherent_extra_manifest_edits() {
    use crate::gh_manifest::ManifestValue;
    for change in [
        "manifest_bytes",
        "statement_bytes",
        "permissions",
        "second_binding",
        "tiers",
    ] {
        let (_dir, store, _) = ready(&format!("manifest-tamper-{change}"));
        let mut p = propose(&store, "Octo/New", NOW);
        if change == "statement_bytes" {
            p.statement_bytes.push(b' ');
        } else if change == "permissions" {
            store.with_raw_conn(|conn| conn.execute("UPDATE gh_manifest_proposals SET installation_permissions=?2 WHERE proposal_id=?1",
                params![p.proposal_id,br#"{"contents":"admin"}"#.as_slice()])).unwrap();
        } else if change == "manifest_bytes" {
            p.manifest_bytes.push(b' ');
        } else {
            let mut value: ManifestValue = serde_json::from_slice(&p.manifest_bytes).unwrap();
            let ManifestValue::Object(entries) = &mut value else {
                panic!("manifest object")
            };
            if change == "second_binding" {
                let (_, ManifestValue::Object(bindings)) = entries
                    .iter_mut()
                    .find(|(key, _)| key == "bindings")
                    .unwrap()
                else {
                    panic!("bindings")
                };
                bindings.push((
                    "Octo/Hidden".into(),
                    ManifestValue::String("agent_hidden".into()),
                ));
            } else {
                entries
                    .iter_mut()
                    .find(|(key, _)| key == "tiers")
                    .unwrap()
                    .1 = ManifestValue::Object(vec![]);
            }
            p.manifest_bytes = serde_json::to_vec_pretty(&value).unwrap();
            p.manifest_bytes.push(b'\n');
            let changed = GhManifest::parse_reproducible(&p.manifest_bytes).unwrap();
            p.manifest_sha256 = hash(&p.manifest_bytes);
            let statement = ManifestBindingStatement::new(
                p.proposal_id.clone(),
                p.agent_id.clone(),
                p.app_slug.clone(),
                p.repo.clone(),
                serde_json::from_slice(&p.installation_permissions).unwrap(),
                &changed,
                &GhManifest::parse_reproducible(V28).unwrap(),
                p.expires_at_ms,
            )
            .unwrap();
            p.statement_bytes = statement.canonical_bytes().unwrap();
            p.statement_sha256 = hash(&p.statement_bytes);
        }
        store.with_raw_conn(|conn| conn.execute("UPDATE gh_manifest_proposals SET manifest_bytes=?2,manifest_sha256=?3,statement_bytes=?4,statement_sha256=?5 WHERE proposal_id=?1",
            params![p.proposal_id,p.manifest_bytes,p.manifest_sha256,p.statement_bytes,p.statement_sha256])).unwrap();
        refuses(
            &store,
            &approve(&envelope(&p, NOW)),
            NOW,
            SecretError::ApprovalInvalid,
        );
    }
}

#[test]
fn gh_manifest_approval_replacement_key_signs_after_its_audit_and_base_movement_refuses() {
    let (_dir, store, old_public) = ready("manifest-replacement-approval");
    let p = propose(&store, "Octo/New", NOW);
    let (record, public) = root_key();
    store
        .overwrite_unconditional_audited(
            GH_MANIFEST_ROOT_KEY_ID,
            &record,
            AuditCtx::admin(AuditOp::Overwrite),
        )
        .unwrap();
    // Approving an already-pending proposal is independent of the proposal gate.
    store
        .set_manifest_one_tap_audited(false, AuditCtx::admin(AuditOp::GhManifestOneTapSet))
        .unwrap();
    assert_eq!(
        run(&store, &approve(&envelope(&p, NOW)), NOW).unwrap()["status"],
        "approved"
    );
    store.with_raw_conn(|conn| {
        let signature: Vec<u8> = conn.query_row("SELECT signature FROM gh_manifests WHERE version=29",[],|r|r.get(0))?;
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519,&public).verify(&p.manifest_bytes,&signature).unwrap();
        assert!(ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519,&old_public).verify(&p.manifest_bytes,&signature).is_err());
        let (overwrite,sign): (i64,i64) = conn.query_row("SELECT (SELECT MAX(seq) FROM audit_log WHERE op='overwrite'),(SELECT MAX(seq) FROM audit_log WHERE op='gh_manifest_sign')",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
        assert!(overwrite<sign);
        Ok(())
    }).unwrap();
    let (_dir, store, _) = ready("manifest-base-moved");
    let p = propose(&store, "Octo/New", NOW);
    let next = GhManifest::parse_reproducible(V28)
        .unwrap()
        .build_next("Octo/Other", "agent_other", NOW / 1000)
        .unwrap();
    store
        .store_gh_manifest(
            &GhManifestVersion {
                version: 29,
                manifest_bytes: &next.to_bytes(),
                manifest_sha256: &next.manifest_sha256(),
                key_id: "0123456789abcdef",
                signature: &[7; 64],
                signed_at_ms: NOW,
                source: GhManifestSource::Import,
                approval_audit_seq: None,
            },
            AuditCtx::admin(AuditOp::GhManifestStore),
        )
        .unwrap();
    refuses(
        &store,
        &approve(&envelope(&p, NOW)),
        NOW,
        SecretError::Superseded,
    );
    // Even a stale pending marker cannot bypass the newest-base comparison.
    store
        .with_raw_conn(|conn| {
            conn.execute(
                "UPDATE gh_manifest_proposals SET state='pending' WHERE proposal_id=?1",
                [&p.proposal_id],
            )
        })
        .unwrap();
    refuses(
        &store,
        &approve(&envelope(&p, NOW)),
        NOW,
        SecretError::Superseded,
    );
}

#[test]
fn gh_manifest_approval_failed_commit_returns_store_error_and_rolls_back_all_rows() {
    let (_dir, store, _) = ready("manifest-approval-commit-failure");
    let p = propose(&store, "Octo/New", NOW);
    let sibling = propose(&store, "Octo/Other", NOW);
    store.with_raw_conn(|conn| {
        conn.execute_batch("PRAGMA foreign_keys=ON;
            CREATE TABLE commit_parent (id INTEGER PRIMARY KEY);
            CREATE TABLE commit_child (id INTEGER REFERENCES commit_parent(id) DEFERRABLE INITIALLY DEFERRED);
            CREATE TRIGGER fail_manifest_commit AFTER INSERT ON gh_manifests BEGIN INSERT INTO commit_child VALUES (1); END;")?;
        assert_eq!(conn.query_row("PRAGMA foreign_keys",[],|r|r.get::<_,i64>(0))?,1);
        Ok(())
    }).unwrap();
    refuses(
        &store,
        &approve(&envelope(&p, NOW)),
        NOW,
        SecretError::StoreError,
    );
    store
        .with_raw_conn(|conn| {
            assert_eq!(
                conn.query_row("SELECT COUNT(*) FROM commit_child", [], |r| r
                    .get::<_, i64>(0))?,
                0
            );
            assert_eq!(
                conn.query_row(
                    "SELECT state FROM gh_manifest_proposals WHERE proposal_id=?1",
                    [sibling.proposal_id],
                    |r| r.get::<_, String>(0)
                )?,
                "pending"
            );
            conn.execute_batch("DROP TRIGGER fail_manifest_commit;")
        })
        .unwrap();
    assert_eq!(
        run(&store, &approve(&envelope(&p, NOW)), NOW).unwrap()["status"],
        "approved"
    );
}
