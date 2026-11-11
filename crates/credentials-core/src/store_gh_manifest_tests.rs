use super::*;
use crate::audit::{AuditOp, AuditRecord};
use crate::key::MasterKey;
use crate::store::{
    migrate_through_for_test, taxonomy_tests, GrantOperation, SelectorKind,
    GH_MANIFEST_SCHEMA_VERSION,
};
use rusqlite::types::Value;

const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const P1: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const P2: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAW";
const P3: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAX";
const PERMISSIONS: &[u8] = br#"{"contents":"write","pull_requests":"write"}"#;
const TABLES: [&str; 5] = [
    "gh_manifests",
    "gh_manifest_proposals",
    "gh_manifest_activations",
    "gh_manifest_activation_audits",
    "audit_log",
];

fn version(number: i64) -> GhManifestVersion<'static> {
    GhManifestVersion {
        version: number,
        manifest_bytes: b"verified manifest bytes",
        manifest_sha256: HASH,
        key_id: "0123456789abcdef",
        signature: &[7; 64],
        signed_at_ms: 99,
        source: GhManifestSource::Import,
        approval_audit_seq: None,
    }
}

fn store_version(store: &EncryptedStore, number: i64) -> Result<(), StoreOpError> {
    store.store_gh_manifest(&version(number), AuditCtx::admin(AuditOp::GhManifestStore))
}

fn proposal(
    conn: &rusqlite::Connection,
    id: &str,
    agent: &str,
    repo: &str,
    base: i64,
    state: &str,
) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO gh_manifest_proposals \
         (proposal_id, agent_id, app_id, app_slug, repo, installation_permissions, base_version, \
          manifest_bytes, manifest_sha256, statement_bytes, statement_sha256, created_at_ms, expires_at_ms, state) \
         VALUES (?1, ?2, 1, 'bot', ?3, ?4, ?5, X'0102', ?6, X'0304', ?6, 10, 86400010, ?7)",
        rusqlite::params![id, agent, repo, PERMISSIONS, base, HASH, state],
    )
}

fn rows(conn: &rusqlite::Connection, table: &str) -> rusqlite::Result<Vec<Vec<Value>>> {
    let mut stmt = conn.prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))?;
    let count = stmt.column_count();
    let rows = stmt
        .query_map([], |row| {
            (0..count)
                .map(|i| row.get(i))
                .collect::<rusqlite::Result<_>>()
        })?
        .collect();
    rows
}

fn snapshot(store: &EncryptedStore) -> Vec<Vec<Vec<Value>>> {
    store
        .with_raw_conn(|conn| TABLES.iter().map(|table| rows(conn, table)).collect())
        .unwrap()
}

fn root_key() -> (VaultRecord, Vec<u8>) {
    use base64::Engine as _;
    use ring::signature::KeyPair as _;
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

fn sign_and_store(
    store: &EncryptedStore,
    tx: &rusqlite::Transaction<'_>,
    number: i64,
    bytes: &[u8],
) -> rusqlite::Result<crate::signing::Signature> {
    use base64::Engine as _;
    let hash = hex32(&payload_hash(bytes));
    let approval = append_audit_tx(
        tx,
        &store.audit_key,
        &AuditRecord {
            op: AuditOp::Approval,
            credential_id: Some(GH_MANIFEST_ROOT_KEY_ID.into()),
            payload_hash: Some(hash.clone()),
            actor: "test/approver:owner".into(),
            alarm: None,
        },
    )?;
    let signature = store
        .sign_gh_manifest(tx, bytes, AuditCtx::admin(AuditOp::GhManifestSign))
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let raw: [u8; 64] = base64::engine::general_purpose::STANDARD
        .decode(&signature.signature_b64)
        .unwrap()
        .try_into()
        .unwrap();
    store.store_gh_manifest_in_tx(
        tx,
        &GhManifestVersion {
            version: number,
            manifest_bytes: bytes,
            manifest_sha256: &hash,
            key_id: &signature.key_id,
            signature: &raw,
            signed_at_ms: 123,
            source: GhManifestSource::Ceremony,
            approval_audit_seq: Some(approval.seq),
        },
        AuditCtx::admin(AuditOp::GhManifestStore),
    )?;
    Ok(signature)
}

#[test]
fn gh_manifest_sign_serializes_key_replacement_before_or_after_all_signed_rows() {
    use base64::Engine as _;
    use std::sync::{mpsc, Arc};
    let (_root, store) = taxonomy_tests::rig("manifest-sign-replacement", 179);
    let store = Arc::new(store);
    let (original, first_public) = root_key();
    let (replacement, second_public) = root_key();
    store
        .create_audited(
            GH_MANIFEST_ROOT_KEY_ID,
            &original,
            AuditCtx::admin(AuditOp::Put),
        )
        .unwrap();
    let (writer_held, writer_ready) = mpsc::channel();
    let (attempting, attempted) = mpsc::channel();
    let replacing = Arc::clone(&store);
    let replacement_job = std::thread::spawn(move || {
        writer_ready.recv().unwrap();
        attempting.send(()).unwrap();
        replacing.overwrite_unconditional_audited(
            GH_MANIFEST_ROOT_KEY_ID,
            &replacement,
            AuditCtx::admin(AuditOp::Overwrite),
        )
    });
    let first = store
        .fenced_write(|tx| {
            writer_held.send(()).unwrap();
            attempted.recv().unwrap();
            sign_and_store(&store, tx, 1, b"first manifest")
        })
        .unwrap();
    replacement_job.join().unwrap().unwrap();
    let second = store
        .fenced_write(|tx| sign_and_store(&store, tx, 2, b"second manifest"))
        .unwrap();
    for (signature, public, other_public, bytes) in [
        (
            &first,
            &first_public,
            &second_public,
            b"first manifest".as_slice(),
        ),
        (
            &second,
            &second_public,
            &first_public,
            b"second manifest".as_slice(),
        ),
    ] {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&signature.signature_b64)
            .unwrap();
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public)
            .verify(bytes, &raw)
            .unwrap();
        assert!(
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, other_public)
                .verify(bytes, &raw)
                .is_err()
        );
        assert_eq!(signature.key_id, crate::signing::key_id_for_public(public));
    }
    let audit = store.read_audit(None).unwrap();
    assert_eq!(
        audit.iter().map(|row| row.op.as_str()).collect::<Vec<_>>(),
        [
            "put",
            "approval",
            "gh_manifest_sign",
            "gh_manifest_store",
            "overwrite",
            "approval",
            "gh_manifest_sign",
            "gh_manifest_store",
        ]
    );
    for (index, hash) in [
        (
            2,
            "2aec5060ec1b1501b0c6216c98f7df76f6c96d1bab5c96c3fc369c363b995842",
        ),
        (
            6,
            "aa098371a12bbf87dda8655241f8b229c00e93011ab0bb494e32aad60e36b438",
        ),
    ] {
        assert_eq!(
            audit[index].credential_id.as_deref(),
            Some(GH_MANIFEST_ROOT_KEY_ID)
        );
        assert_eq!(audit[index].payload_hash.as_deref(), Some(hash));
    }
    assert!(!store.get(GH_MANIFEST_ROOT_KEY_ID).unwrap().operator_sign);
    store.verify_audit_chain().unwrap();
}

#[test]
fn gh_manifest_sign_rolls_back_with_its_caller_and_fails_closed_on_audit_error() {
    let (_root, store) = taxonomy_tests::rig("manifest-sign-rollback", 180);
    store
        .create(GH_MANIFEST_ROOT_KEY_ID, &root_key().0)
        .unwrap();
    let before = snapshot(&store);
    assert!(store
        .fenced_write(|tx| {
            sign_and_store(&store, tx, 1, b"manifest")?;
            Err::<(), _>(rusqlite::Error::InvalidQuery)
        })
        .is_err());
    assert_eq!(snapshot(&store), before);
    store
        .with_raw_conn(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER deny_manifest_sign BEFORE INSERT ON audit_log \
         WHEN NEW.op = 'gh_manifest_sign' BEGIN SELECT RAISE(ABORT, 'test audit fault'); END;",
            )
        })
        .unwrap();
    assert!(store
        .fenced_write(|tx| sign_and_store(&store, tx, 1, b"manifest"))
        .is_err());
    assert_eq!(snapshot(&store), before);
}

#[test]
fn gh_manifest_sign_requires_an_active_usable_signing_key_without_writes() {
    let (_root, store) = taxonomy_tests::rig("manifest-sign-unavailable", 181);
    let refuse = || {
        let before = snapshot(&store);
        store
            .fenced_write(|tx| {
                assert!(store
                    .sign_gh_manifest(tx, b"manifest", AuditCtx::admin(AuditOp::GhManifestSign))
                    .is_err());
                Ok(())
            })
            .unwrap();
        assert_eq!(snapshot(&store), before);
    };
    refuse();
    store
        .create(
            GH_MANIFEST_ROOT_KEY_ID,
            &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"not a key".to_vec(), None),
        )
        .unwrap();
    refuse();
    store
        .overwrite_unconditional_audited(
            GH_MANIFEST_ROOT_KEY_ID,
            &VaultRecord::new_static(
                CredentialKind::SigningKey,
                "test",
                b"not a key".to_vec(),
                None,
            ),
            AuditCtx::admin(AuditOp::Overwrite),
        )
        .unwrap();
    refuse();
    store
        .overwrite_unconditional_audited(
            GH_MANIFEST_ROOT_KEY_ID,
            &root_key().0,
            AuditCtx::admin(AuditOp::Overwrite),
        )
        .unwrap();
    store.invalidate(GH_MANIFEST_ROOT_KEY_ID).unwrap();
    refuse();
}

#[test]
fn gh_manifest_root_exact_sign_grant_is_refused_without_writes() {
    let (_root, store) = taxonomy_tests::rig("manifest-grant-fence", 182);
    for principal_kind in ["reserved", "enrolled"] {
        let before = store
            .with_raw_conn(|conn| {
                Ok((
                    rows(conn, "read_grants")?,
                    rows(conn, "audit_log")?,
                    conn.total_changes(),
                ))
            })
            .unwrap();
        assert!(matches!(
            store.create_read_grant_audited(
                principal_kind,
                "manifest-consumer",
                SelectorKind::Exact,
                GH_MANIFEST_ROOT_KEY_ID,
                GrantOperation::Sign,
                AuditCtx::admin(AuditOp::GrantCreate)
            ),
            Err(StoreOpError::NotFound)
        ));
        let after = store
            .with_raw_conn(|conn| {
                Ok((
                    rows(conn, "read_grants")?,
                    rows(conn, "audit_log")?,
                    conn.total_changes(),
                ))
            })
            .unwrap();
        assert_eq!(after, before);
    }
    for operation in [
        GrantOperation::Read,
        GrantOperation::List,
        GrantOperation::Open,
        GrantOperation::Seal,
    ] {
        store
            .create_read_grant_audited(
                "reserved",
                "manifest-consumer",
                SelectorKind::Exact,
                GH_MANIFEST_ROOT_KEY_ID,
                operation,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap();
    }
    store
        .create_read_grant_audited(
            "reserved",
            "manifest-consumer",
            SelectorKind::Exact,
            "signing:other:1",
            GrantOperation::Sign,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
}

#[test]
fn gh_manifests_are_insert_only_and_versions_strictly_increase() {
    let (_root, store) = taxonomy_tests::rig("gh-insert-only", 171);
    store_version(&store, 28).unwrap();
    let before = snapshot(&store);
    for sql in [
        "UPDATE gh_manifests SET manifest_bytes = X'00' WHERE version = 28",
        "DELETE FROM gh_manifests WHERE version = 28",
        "INSERT INTO gh_manifests SELECT 27, manifest_bytes, manifest_sha256, key_id, signature, signed_at_ms, source, approval_audit_seq FROM gh_manifests",
        "INSERT OR REPLACE INTO gh_manifests SELECT * FROM gh_manifests",
    ] {
        let error = store.with_raw_conn(|conn| conn.execute(sql, [])).unwrap_err();
        assert!(error.to_string().contains("gh_manifests"), "{error}");
        assert_eq!(snapshot(&store), before);
    }
    store_version(&store, 29).unwrap();
    assert_eq!(snapshot(&store)[0].len(), 2);
}

#[test]
fn pending_repo_uniqueness_is_case_insensitive_and_only_pending() {
    let (_root, store) = taxonomy_tests::rig("gh-pending-repo", 172);
    store.with_raw_conn(|conn| {
        proposal(conn, P1, "agent-A", "Owner/Repo", 28, "pending")?;
        let error = proposal(conn, P2, "agent-A", "owner/repo", 28, "pending").unwrap_err();
        assert_eq!(error.sqlite_error().unwrap().extended_code, rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE);
        proposal(conn, P2, "agent-B", "owner/repo", 28, "pending")?;
        proposal(conn, P3, "agent-A", "owner/repo", 28, "expired")?;
        conn.execute("UPDATE gh_manifest_proposals SET state = 'expired' WHERE proposal_id = ?1", [P1])?;
        proposal(conn, "01ARZ3NDEKTSV4RRFFQ69G5FAY", "agent-A", "OWNER/REPO", 28, "pending")?;
        let stored: (String, Vec<u8>) = conn.query_row(
            "SELECT repo, installation_permissions FROM gh_manifest_proposals WHERE proposal_id = ?1",
            [P1], |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(stored, ("Owner/Repo".into(), PERMISSIONS.to_vec()));
        Ok(())
    }).unwrap();
}

#[test]
fn storing_a_version_supersedes_every_older_pending_proposal_and_audits_once() {
    let (_root, store) = taxonomy_tests::rig("gh-supersede", 173);
    store_version(&store, 28).unwrap();
    store
        .with_raw_conn(|conn| {
            proposal(conn, P1, "agent-A", "Owner/One", 27, "pending")?;
            proposal(conn, P2, "agent-B", "Owner/Two", 28, "pending")?;
            proposal(conn, P3, "agent-C", "Owner/Three", 29, "pending")?;
            proposal(
                conn,
                "01ARZ3NDEKTSV4RRFFQ69G5FAY",
                "agent-D",
                "Owner/Four",
                27,
                "expired",
            )?;
            Ok(())
        })
        .unwrap();
    let audit_len = store.read_audit(None).unwrap().len();
    store_version(&store, 29).unwrap();
    let states = store
        .with_raw_conn(|conn| {
            conn.prepare(
                "SELECT proposal_id, state FROM gh_manifest_proposals ORDER BY proposal_id",
            )?
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap();
    assert_eq!(
        states,
        [
            (P1.into(), "superseded".into()),
            (P2.into(), "superseded".into()),
            (P3.into(), "pending".into()),
            ("01ARZ3NDEKTSV4RRFFQ69G5FAY".into(), "expired".into()),
        ]
    );
    let audit = store.read_audit(None).unwrap();
    let new = &audit[audit_len..];
    assert_eq!(new.len(), 3);
    assert_eq!(new[0].op, "gh_manifest_store");
    assert_eq!(new[0].credential_id.as_deref(), Some("gh-manifest|29"));
    for (entry, id) in new[1..].iter().zip([P1, P2]) {
        assert_eq!(entry.op, "gh_manifest_proposal_state");
        assert_eq!(
            entry.credential_id,
            Some(format!("gh-manifest-proposal|{id}"))
        );
        assert_eq!(
            entry.payload_hash.as_deref(),
            Some("4389d17859f50df81be3b3ee41036ed3f92d3bb1b882bdfe840773771f5a2c59")
        );
    }
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[test]
fn failed_manifest_insert_or_late_audit_leaves_all_five_tables_unchanged() {
    let (_root, store) = taxonomy_tests::rig("gh-rollback", 174);
    store_version(&store, 28).unwrap();
    store.with_raw_conn(|conn| {
        proposal(conn, P1, "agent-A", "Owner/One", 28, "pending")?;
        proposal(conn, P2, "agent-B", "Owner/Two", 28, "pending")?;
        conn.execute_batch("INSERT INTO gh_manifest_activations VALUES ('member', 28, 'digest', 'valid', NULL, 99, NULL); \
            INSERT INTO gh_manifest_activation_audits VALUES ('member', 28, 'valid');")
    }).unwrap();
    let before = snapshot(&store);
    assert!(store_version(&store, 28).is_err());
    assert_eq!(snapshot(&store), before);
    let mut ceremony = version(29);
    ceremony.source = GhManifestSource::Ceremony;
    assert!(store
        .store_gh_manifest(&ceremony, AuditCtx::admin(AuditOp::GhManifestStore))
        .is_err());
    assert_eq!(snapshot(&store), before);
    store.with_raw_conn(|conn| conn.execute_batch(&format!(
        "CREATE TRIGGER fail_second_state_audit BEFORE INSERT ON audit_log \
         WHEN NEW.op = 'gh_manifest_proposal_state' AND NEW.credential_id = 'gh-manifest-proposal|{P2}' \
         BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;"
    ))).unwrap();
    let error = store_version(&store, 29).unwrap_err();
    assert!(
        error.to_string().contains("injected audit failure"),
        "{error}"
    );
    assert_eq!(
        snapshot(&store),
        before,
        "roll back even the first sibling's transition and audit"
    );
}

#[test]
fn manifest_migration_preserves_populated_credentials_and_every_historical_audit_byte() {
    let (_root, sqlite) = taxonomy_tests::sqlite("gh-migration", 175);
    migrate_through_for_test(&sqlite, GH_MANIFEST_SCHEMA_VERSION - 1).unwrap();
    let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([175; 32])).unwrap();
    for id in ["legacy-one", "legacy-two"] {
        store
            .create_audited(
                id,
                &taxonomy_tests::api_record(),
                AuditCtx::admin(AuditOp::Put),
            )
            .unwrap();
    }
    store
        .append_audit(&AuditRecord {
            op: AuditOp::Approval,
            credential_id: Some("legacy-one".into()),
            payload_hash: Some(HASH.into()),
            actor: "offline-cli/approver:operator".into(),
            alarm: None,
        })
        .unwrap();
    let before = store
        .with_raw_conn(|conn| Ok((rows(conn, "credentials")?, rows(conn, "audit_log")?)))
        .unwrap();
    assert_eq!(before.0.len(), 2);
    assert_eq!(before.1.len(), 3);
    migrate_through_for_test(&store.store, GH_MANIFEST_SCHEMA_VERSION).unwrap();
    let after = store
        .with_raw_conn(|conn| Ok((rows(conn, "credentials")?, rows(conn, "audit_log")?)))
        .unwrap();
    assert_eq!(
        after, before,
        "sealed credential rows and complete historical audit transcripts stay byte-identical"
    );
    for table in &TABLES[..4] {
        assert!(
            store
                .with_raw_conn(|conn| rows(conn, table))
                .unwrap()
                .is_empty(),
            "{table}"
        );
    }
    assert_eq!(store.verify_audit_chain().unwrap(), None);
}

#[test]
fn manifest_schema_enforces_report_shapes_and_approval_state() {
    let (_root, store) = taxonomy_tests::rig("gh-report-shape", 176);
    store.with_raw_conn(|conn| {
        conn.execute_batch(
            "INSERT INTO gh_manifest_activations VALUES ('retired-only', NULL, NULL, NULL, NULL, NULL, 1); \
             INSERT INTO gh_manifest_activations VALUES ('valid', 28, 'hash', 'valid', NULL, 1, NULL); \
             INSERT INTO gh_manifest_activations VALUES ('invalid', 28, 'hash', 'invalid', 'bad signature', 1, 2); \
             INSERT INTO gh_manifest_activation_audits VALUES ('valid', 28, 'valid'); \
             INSERT INTO gh_manifest_activation_audits VALUES ('valid', 28, 'invalid');"
        )?;
        for sql in [
            "INSERT INTO gh_manifest_activations VALUES ('missing-retirement', NULL, NULL, NULL, NULL, NULL, NULL)",
            "INSERT INTO gh_manifest_activations VALUES ('partial', 28, NULL, 'valid', NULL, 1, NULL)",
            "INSERT INTO gh_manifest_activations VALUES ('invalid-without-reason', 28, 'hash', 'invalid', NULL, 1, NULL)",
            "INSERT INTO gh_manifest_activations VALUES ('unknown', 28, 'hash', 'unknown', NULL, 1, NULL)",
            "INSERT INTO gh_manifest_activation_audits VALUES ('valid', 28, 'valid')",
            "INSERT INTO gh_manifest_activation_audits VALUES ('valid', 28, 'unknown')",
        ] {
            assert!(conn.execute(sql, []).is_err(), "{sql}");
        }
        proposal(conn, P1, "agent-A", "Owner/Repo", 28, "pending")?;
        for sql in [
            "UPDATE gh_manifest_proposals SET state = 'approved'",
            "UPDATE gh_manifest_proposals SET approved_fingerprint = 'phone'",
            "UPDATE gh_manifest_proposals SET state = 'unknown'",
        ] {
            assert!(conn.execute(sql, []).is_err(), "{sql}");
        }
        conn.execute("UPDATE gh_manifest_proposals SET state = 'approved', approved_envelope_sha256 = ?1, approved_fingerprint = 'phone'", [HASH])?;
        Ok(())
    }).unwrap();
}

#[test]
fn manifest_audit_records_pin_subjects_field_order_and_framing() {
    use crate::audit::AlarmReason;

    // Fixed commitments were computed independently using little-endian u64
    // byte lengths followed by UTF-8 bytes, not the production framing helper.
    let cases = [
        (
            GhManifestAudit::Propose {
                proposal_id: P1,
                agent_id: "agent-A",
                repo: "Owner/Repo",
                base_version: 28,
                manifest_sha256: HASH,
                statement_sha256:
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            },
            "gh_manifest_propose",
            format!("gh-manifest-proposal|{P1}"),
            "b65b356f34665a5f1dacd7fc12c22fcbce36ddd4fa69a83fb3ebd8333083ea72",
        ),
        (
            GhManifestAudit::ProposalState {
                proposal_id: P1,
                from: "pending",
                to: "superseded",
            },
            "gh_manifest_proposal_state",
            format!("gh-manifest-proposal|{P1}"),
            "4389d17859f50df81be3b3ee41036ed3f92d3bb1b882bdfe840773771f5a2c59",
        ),
        (
            GhManifestAudit::Sign {
                manifest_sha256: HASH,
            },
            "gh_manifest_sign",
            "signing:gh-manifest-root:1".into(),
            HASH,
        ),
        (
            GhManifestAudit::Store {
                version: 29,
                source: "import",
                manifest_sha256: HASH,
            },
            "gh_manifest_store",
            "gh-manifest|29".into(),
            "7f03dd7b621ab8f7378bc4beafd06f8b0f6b5da3fddf946573232932505b474d",
        ),
        (
            GhManifestAudit::Activation {
                member_id: "member-A",
                version: 29,
                verdict: "valid",
            },
            "gh_manifest_activation",
            "gh-manifest-activation|member-A".into(),
            "89e37b0bf148129c2de8c802ffdd9e065c4eb82024b1456d727150d85f8ea827",
        ),
        (
            GhManifestAudit::Retire {
                member_id: "member-A",
                retired_at_ms: 12345,
            },
            "gh_manifest_retire",
            "gh-manifest-activation|member-A".into(),
            "0e121345de96ad80c683972f4e29d073632fcf38efff30210292cf5acacf1928",
        ),
    ];
    for (metadata, op, subject, hash) in cases {
        let record = metadata.record("operator", Some(AlarmReason::AdminWrite));
        assert_eq!(record.op.as_str(), op);
        assert_eq!(record.credential_id.as_deref(), Some(subject.as_str()));
        assert_eq!(record.payload_hash.as_deref(), Some(hash));
        assert_eq!(record.actor, "operator");
        assert_eq!(record.alarm, Some(AlarmReason::AdminWrite));
    }
}
