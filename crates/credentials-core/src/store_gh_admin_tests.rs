use super::*;
use crate::admin_ops::{apply, AdminOpBody, ADMIN_OP_SCHEMA_V1, ADMIN_OP_SCHEMA_V2};
use crate::record::{CredentialKind, VaultRecord};
use crate::store::GH_MANIFEST_ROOT_KEY_ID;
use crate::store::{taxonomy_tests, GhManifestProposalInput};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use std::collections::BTreeMap;

const V28: &str = include_str!("../tests/fixtures/gh-manifest-v28.json");
const MEMBER: &str = "fed-computer:11111111111111111111111111111111";
const OTHER: &str = "fed-computer:22222222222222222222222222222222";
const SEED: u8 = 197;

fn rig(
    label: &str,
) -> (
    crate::test_support::TestTempDir,
    EncryptedStore,
    Ed25519KeyPair,
) {
    let (dir, store) = taxonomy_tests::rig(label, SEED);
    // RFC 8032 test-vector seed in a v1 PKCS#8 envelope.
    let seed = crate::enrollment::decode_lower_hex_32(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    )
    .unwrap();
    let der = [
        &[48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32][..],
        &seed,
    ]
    .concat();
    let pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der).unwrap();
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        STANDARD.encode(&der)
    );
    store
        .put_legacy_manifest_root_for_tests(
            &VaultRecord::new_static(
                CredentialKind::SigningKey,
                "operator",
                pem.into_bytes(),
                None,
            ),
            AuditCtx::admin(AuditOp::Put),
        )
        .unwrap();
    (dir, store, pair)
}

fn envelope(pair: &Ed25519KeyPair, bytes: &str) -> GhManifestHandoffEnvelope {
    GhManifestHandoffEnvelope {
        key_id: crate::signing::key_id_for_public(pair.public_key().as_ref()),
        manifest_bytes: bytes.into(),
        signature: STANDARD.encode(pair.sign(bytes.as_bytes()).as_ref()),
    }
}

fn import(pair: &Ed25519KeyPair, bytes: &str) -> AdminOpBody {
    AdminOpBody::ManifestImport {
        v: ADMIN_OP_SCHEMA_V2,
        envelope: envelope(pair, bytes),
    }
}

fn sign(bytes: &str) -> AdminOpBody {
    AdminOpBody::ManifestSign {
        v: ADMIN_OP_SCHEMA_V2,
        manifest_bytes: bytes.into(),
        approver: "named-owner".into(),
    }
}

fn run(store: &EncryptedStore, op: AdminOpBody) -> Result<Value, StoreOpError> {
    apply(store, op, "test-admin")
}

type Snapshot = Vec<Vec<Vec<rusqlite::types::Value>>>;
fn snapshot(store: &EncryptedStore) -> Snapshot {
    store
        .with_raw_conn(|conn| {
            [
                "gh_manifests",
                "agent_policies",
                "gh_manifest_proposals",
                "gh_manifest_activations",
                "gh_manifest_activation_audits",
                "audit_log",
            ]
            .iter()
            .map(|table| {
                conn.prepare(&format!("SELECT * FROM {table} ORDER BY 1, 2, 3"))?
                    .query_map([], |row| {
                        (0..row.as_ref().column_count())
                            .map(|column| row.get(column))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap()
}

fn refuses(store: &EncryptedStore, op: AdminOpBody, message: &str) {
    let before = snapshot(store);
    let error = run(store, op).unwrap_err();
    assert!(error.to_string().contains(message), "{error:?}");
    assert_eq!(
        snapshot(store),
        before,
        "refusals cannot change any manifest or audit table"
    );
}

fn propose(store: &EncryptedStore) -> String {
    store
        .set_federation_self_member_audited(MEMBER, AuditCtx::admin(AuditOp::FederationSelfSet))
        .unwrap();
    store
        .set_manifest_one_tap_audited(true, AuditCtx::admin(AuditOp::GhManifestOneTapSet))
        .unwrap();
    let prepared = store
        .prepare_gh_manifest_proposal(GhManifestProposalInput {
            agent_id: "agent_4444444444444444".into(),
            app_id: 42,
            app_slug: "repo-bot".into(),
            repo: "Octo/New".into(),
            installation_permissions: BTreeMap::from([("contents".into(), "write".into())]),
        })
        .unwrap();
    store
        .propose_gh_manifest_binding(&prepared, "test-admin", || true, || 1_794_355_300_123)
        .unwrap()
        .proposal_id
}

#[test]
fn gh_manifest_admin_import_checks_key_id_and_signature_without_writes() {
    let (_dir, store, pair) = rig("manifest-admin-import-checks");
    let mut wrong_id = envelope(&pair, V28);
    wrong_id.key_id = "0".repeat(16);
    refuses(
        &store,
        AdminOpBody::ManifestImport {
            v: ADMIN_OP_SCHEMA_V2,
            envelope: wrong_id,
        },
        "key_id_mismatch",
    );
    let mut bad_signature = envelope(&pair, V28);
    let mut raw = STANDARD.decode(&bad_signature.signature).unwrap();
    raw[0] ^= 1;
    bad_signature.signature = STANDARD.encode(raw);
    refuses(
        &store,
        AdminOpBody::ManifestImport {
            v: ADMIN_OP_SCHEMA_V2,
            envelope: bad_signature,
        },
        "invalid_manifest_signature",
    );
    let mut changed = envelope(&pair, V28);
    changed.manifest_bytes = V28.replace("agent_3333333333333333", "agent_5555555555555555");
    refuses(
        &store,
        AdminOpBody::ManifestImport {
            v: ADMIN_OP_SCHEMA_V2,
            envelope: changed,
        },
        "invalid_manifest_signature",
    );
    for signature in ["not base64".into(), STANDARD.encode([1; 63])] {
        let mut bad = envelope(&pair, V28);
        bad.signature = signature;
        refuses(
            &store,
            AdminOpBody::ManifestImport {
                v: ADMIN_OP_SCHEMA_V2,
                envelope: bad,
            },
            "invalid_manifest_signature",
        );
    }
    let result = run(&store, import(&pair, V28)).unwrap();
    assert_eq!(result["version"], 28);
    assert_eq!(
        result["manifest_sha256"],
        "91244891c498b3e51997604e9edf30f75b6bf10edfd2021c5fefeef518384bb5"
    );
    store.with_raw_conn(|conn| {
        let row = conn.query_row("SELECT source, signed_at_ms, approval_audit_seq, manifest_bytes, signature FROM gh_manifests", [], |r|
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, Option<i64>>(2)?, r.get::<_, Vec<u8>>(3)?, r.get::<_, Vec<u8>>(4)?)))?;
        assert_eq!(row.0, "import");
        assert_eq!(row.1, 1_794_355_200_000);
        assert_eq!(row.2, None);
        assert_eq!(row.3, V28.as_bytes());
        assert_eq!(row.4, pair.sign(V28.as_bytes()).as_ref());
        let ops = conn.prepare("SELECT op FROM audit_log WHERE op LIKE 'gh_manifest_%' OR op = 'approval' ORDER BY seq")?
            .query_map([], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        assert_eq!(ops, ["gh_manifest_store"]);
        Ok(())
    }).unwrap();
}

#[test]
fn gh_manifest_admin_import_and_sign_refuse_bad_versions_and_non_reproducible_bytes() {
    let (_dir, store, pair) = rig("manifest-admin-versions");
    run(&store, import(&pair, V28)).unwrap();
    for bytes in [
        V28.to_owned(),
        V28.replace("\"manifest_version\": 28", "\"manifest_version\": 27"),
    ] {
        refuses(&store, import(&pair, &bytes), "invalid_manifest_version");
        refuses(&store, sign(&bytes), "invalid_manifest_version");
    }
    for bytes in [
        V28.replace("  \"manifest_version\": 28,\n", ""),
        V28.replace("\"manifest_version\": 28", "\"manifest_version\": 0"),
        V28.replace("\"manifest_version\": 28", "\"manifest_version\": \"29\""),
    ] {
        refuses(&store, import(&pair, &bytes), "manifest_version");
        refuses(&store, sign(&bytes), "manifest_version");
    }
    let next = V28.replace("\"manifest_version\": 28", "\"manifest_version\": 29");
    for bytes in [
        next.trim_end().into(),
        format!("{next}\n"),
        next.replace("  ", "    "),
    ] {
        refuses(&store, import(&pair, &bytes), "not_reproducible");
        refuses(&store, sign(&bytes), "not_reproducible");
    }
}

#[test]
fn gh_manifest_admin_sign_commits_approval_sign_store_and_supersedes_atomically() {
    let (_dir, store, pair) = rig("manifest-admin-sign-success");
    run(&store, import(&pair, V28)).unwrap();
    let proposal = propose(&store);
    let next = V28.replace("\"manifest_version\": 28", "\"manifest_version\": 30");
    let result = run(&store, sign(&next)).unwrap();
    assert_eq!(result["version"], 30);
    let signed: GhManifestHandoffEnvelope =
        serde_json::from_value(result["envelope"].clone()).unwrap();
    assert_eq!(signed.manifest_bytes, next);
    assert_eq!(
        signed.key_id,
        crate::signing::key_id_for_public(pair.public_key().as_ref())
    );
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pair.public_key().as_ref())
        .verify(
            next.as_bytes(),
            &STANDARD.decode(&signed.signature).unwrap(),
        )
        .unwrap();
    store.with_raw_conn(|conn| {
        let ops = conn.prepare("SELECT op FROM audit_log WHERE op IN ('approval', 'gh_manifest_sign', 'gh_manifest_store', 'gh_manifest_proposal_state') ORDER BY seq")?
            .query_map([], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        assert_eq!(ops, ["gh_manifest_store", "approval", "gh_manifest_sign", "gh_manifest_store", "gh_manifest_proposal_state"]);
        let row = conn.query_row("SELECT m.source, m.approval_audit_seq, a.op, a.credential_id, a.payload_hash, a.actor FROM gh_manifests AS m JOIN audit_log AS a ON a.seq = m.approval_audit_seq WHERE m.version = 30", [], |r|
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?, r.get::<_, String>(5)?)))?;
        assert_eq!(row.0, "ceremony");
        assert!(row.1 > 0);
        assert_eq!(row.2, "approval");
        assert_eq!(row.3, GH_MANIFEST_ROOT_KEY_ID);
        assert_eq!(row.4, result["manifest_sha256"].as_str().unwrap());
        assert_eq!(row.5, "test-admin/approver:named-owner");
        assert_eq!(conn.query_row("SELECT state FROM gh_manifest_proposals WHERE proposal_id = ?1", [&proposal], |r| r.get::<_, String>(0))?, "superseded");
        Ok(())
    }).unwrap();
    assert!(store.verify_audit_chain().is_ok());
}

#[test]
fn gh_manifest_admin_sign_failed_commit_leaves_no_version_or_audit_row() {
    let (_dir, store, pair) = rig("manifest-admin-commit-failure");
    run(&store, import(&pair, V28)).unwrap();
    let proposal = propose(&store);
    store.with_raw_conn(|conn| {
        conn.execute_batch("PRAGMA foreign_keys=ON;
            CREATE TABLE commit_parent (id INTEGER PRIMARY KEY);
            CREATE TABLE commit_child (id INTEGER REFERENCES commit_parent(id) DEFERRABLE INITIALLY DEFERRED);
            CREATE TRIGGER fail_manifest_commit AFTER INSERT ON gh_manifests BEGIN INSERT INTO commit_child VALUES (1); END;")?;
        assert_eq!(conn.query_row("PRAGMA foreign_keys", [], |r| r.get::<_, i64>(0))?, 1);
        Ok(())
    }).unwrap();
    let next = V28.replace("\"manifest_version\": 28", "\"manifest_version\": 29");
    refuses(&store, sign(&next), "FOREIGN KEY constraint failed");
    store
        .with_raw_conn(|conn| {
            assert_eq!(
                conn.query_row("SELECT COUNT(*) FROM commit_child", [], |r| r
                    .get::<_, i64>(0))?,
                0
            );
            assert_eq!(
                conn.query_row(
                    "SELECT state FROM gh_manifest_proposals WHERE proposal_id = ?1",
                    [&proposal],
                    |r| r.get::<_, String>(0)
                )?,
                "pending"
            );
            conn.execute_batch("DROP TRIGGER fail_manifest_commit")
        })
        .unwrap();
    assert_eq!(run(&store, sign(&next)).unwrap()["version"], 29);
}

#[test]
fn gh_manifest_admin_sign_requires_an_active_root_and_rolls_back_unusable_key() {
    let (_dir, store) = taxonomy_tests::rig("manifest-admin-setup", SEED);
    refuses(&store, sign(V28), "manifest_setup_incomplete");
    store
        .put_legacy_manifest_root_for_tests(
            &VaultRecord::new_static(
                CredentialKind::ApiKey,
                "operator",
                b"not-a-signing-key".to_vec(),
                None,
            ),
            AuditCtx::admin(AuditOp::Put),
        )
        .unwrap();
    refuses(&store, sign(V28), "manifest_setup_incomplete");
    let (_dir, store, _) = rig("manifest-admin-inactive-root");
    store
        .with_raw_conn(|conn| {
            conn.execute(
                "UPDATE credentials SET state='retired' WHERE credential_id=?1",
                [GH_MANIFEST_ROOT_KEY_ID],
            )
        })
        .unwrap();
    refuses(&store, sign(V28), "manifest_setup_incomplete");
    let (_dir, store) = taxonomy_tests::rig("manifest-admin-broken-root", SEED);
    store
        .put_legacy_manifest_root_for_tests(
            &VaultRecord::new_static(
                CredentialKind::SigningKey,
                "operator",
                b"not-a-private-key".to_vec(),
                None,
            ),
            AuditCtx::admin(AuditOp::Put),
        )
        .unwrap();
    refuses(&store, sign(V28), "unusable manifest signing key");
}

#[test]
fn gh_manifest_admin_export_reproduces_retained_envelope_after_restart_without_signing() {
    let (dir, store, pair) = rig("manifest-admin-export");
    run(&store, import(&pair, V28)).unwrap();
    let signed = run(
        &store,
        sign(&V28.replace("\"manifest_version\": 28", "\"manifest_version\": 29")),
    )
    .unwrap();
    store
        .with_raw_conn(|conn| {
            conn.execute(
                "UPDATE credentials SET state='retired' WHERE credential_id=?1",
                [GH_MANIFEST_ROOT_KEY_ID],
            )
        })
        .unwrap();
    let before = snapshot(&store);
    let retained = serde_json::to_vec(&signed["envelope"]).unwrap();
    drop(store);
    let sqlite = cortexkit_store::open_sqlite(&cortexkit_store::StorageDescriptor {
        module_id: "claustrum".into(),
        storage_namespace: "taxonomy-manifest-admin-export".into(),
        isolation: cortexkit_store::Isolation::Module,
        backend: cortexkit_store::StorageBackend::Sqlite {
            path: dir.join("store.db").to_string_lossy().into_owned(),
        },
    })
    .unwrap();
    let store =
        EncryptedStore::open(sqlite, crate::key::MasterKey::from_bytes([SEED; 32])).unwrap();
    let exported = run(
        &store,
        AdminOpBody::ManifestExport {
            v: ADMIN_OP_SCHEMA_V2,
            version: 29,
        },
    )
    .unwrap();
    assert_eq!(serde_json::to_vec(&exported).unwrap(), retained);
    assert_eq!(
        run(
            &store,
            AdminOpBody::ManifestExport {
                v: ADMIN_OP_SCHEMA_V2,
                version: 28
            }
        )
        .unwrap(),
        serde_json::to_value(envelope(&pair, V28)).unwrap()
    );
    assert_eq!(snapshot(&store), before);
    refuses(
        &store,
        AdminOpBody::ManifestExport {
            v: ADMIN_OP_SCHEMA_V2,
            version: 30,
        },
        "not found",
    );
}

#[test]
fn gh_manifest_admin_list_includes_expected_and_retired_computers_without_writes() {
    let (_dir, store, pair) = rig("manifest-admin-list");
    store
        .set_federation_self_member_audited(MEMBER, AuditCtx::admin(AuditOp::FederationSelfSet))
        .unwrap();
    store.with_raw_conn(|conn| conn.execute(
        "INSERT INTO member_grants (member_id, operation, selector_kind, selector, pairing_id, created_at_ms, source) \
         VALUES (?1, 'secret_use', 'none', '', 'pairing', 1, 'operator')", [OTHER],
    )).unwrap();
    run(&store, import(&pair, V28)).unwrap();
    store
        .report_gh_manifest_active(
            &super::super::GhManifestActivationReport {
                member_id: OTHER,
                version: 28,
                payload_sha256: &"a".repeat(64),
                verdict: super::super::GhManifestVerdict::Invalid,
                reason: Some("wrong hash"),
                reported_at_ms: 45,
            },
            AuditCtx::admin(AuditOp::GhManifestActivation),
        )
        .unwrap();
    let before = snapshot(&store);
    let listed = run(
        &store,
        AdminOpBody::ManifestList {
            v: ADMIN_OP_SCHEMA_V2,
        },
    )
    .unwrap();
    assert_eq!(
        listed["versions"],
        json!([{
            "version": 28, "source": "import", "manifest_sha256": "91244891c498b3e51997604e9edf30f75b6bf10edfd2021c5fefeef518384bb5", "signed_at_ms": 1_794_355_200_000_i64,
        }])
    );
    assert_eq!(
        listed["computers"],
        json!([
            {"member_id": MEMBER, "expected": true, "version": null, "payload_sha256": null, "verdict": null, "reason": null, "reported_at_ms": null, "retired_at_ms": null},
            {"member_id": OTHER, "expected": true, "version": 28, "payload_sha256": "a".repeat(64), "verdict": "invalid", "reason": "wrong hash", "reported_at_ms": 45, "retired_at_ms": null},
        ])
    );
    assert_eq!(snapshot(&store), before);
    let result = run(
        &store,
        AdminOpBody::ManifestRetireMachine {
            v: ADMIN_OP_SCHEMA_V2,
            member_id: OTHER.into(),
        },
    )
    .unwrap();
    assert_eq!(result, json!({"retired": true, "member_id": OTHER}));
    let after_retire = snapshot(&store);
    let listed = run(
        &store,
        AdminOpBody::ManifestList {
            v: ADMIN_OP_SCHEMA_V2,
        },
    )
    .unwrap();
    assert_eq!(listed["computers"][1]["expected"], false);
    assert_eq!(listed["computers"][1]["version"], Value::Null);
    assert_eq!(listed["computers"][1]["reported_at_ms"], Value::Null);
    assert!(listed["computers"][1]["retired_at_ms"].as_i64().is_some());
    assert_eq!(snapshot(&store), after_retire);
    assert_eq!(
        store
            .gh_manifest_active_status(28)
            .unwrap()
            .unwrap()
            .computers
            .len(),
        1
    );
    store
        .with_raw_conn(|conn| {
            assert_eq!(
                conn.query_row(
                    "SELECT COUNT(*) FROM audit_log WHERE op='gh_manifest_retire'",
                    [],
                    |r| r.get::<_, i64>(0)
                )?,
                1
            );
            Ok(())
        })
        .unwrap();
    refuses(
        &store,
        AdminOpBody::ManifestRetireMachine {
            v: ADMIN_OP_SCHEMA_V2,
            member_id: "not-a-member".into(),
        },
        "member",
    );
}

#[test]
fn gh_manifest_admin_one_tap_uses_audited_setting_and_reports_unreadable_values() {
    let (_dir, store, pair) = rig("manifest-admin-one-tap");
    assert_eq!(
        run(
            &store,
            AdminOpBody::ManifestOneTapStatus {
                v: ADMIN_OP_SCHEMA_V2
            }
        )
        .unwrap(),
        json!({"one_tap": "off"})
    );
    for (enabled, changed) in [(true, true), (true, false), (false, true), (false, false)] {
        assert_eq!(
            run(
                &store,
                AdminOpBody::ManifestOneTapSet {
                    v: ADMIN_OP_SCHEMA_V2,
                    enabled
                }
            )
            .unwrap(),
            json!({"one_tap": enabled, "changed": changed})
        );
        assert_eq!(store.manifest_one_tap_enabled(), enabled);
    }
    store
        .with_raw_conn(|conn| {
            assert_eq!(
                conn.query_row(
                    "SELECT COUNT(*) FROM audit_log WHERE op='gh_manifest_one_tap_set'",
                    [],
                    |r| r.get::<_, i64>(0)
                )?,
                2
            );
            conn.execute(
                "UPDATE settings SET value='malformed' WHERE name='manifest.one_tap'",
                [],
            )
        })
        .unwrap();
    let before = snapshot(&store);
    assert_eq!(
        run(
            &store,
            AdminOpBody::ManifestOneTapStatus {
                v: ADMIN_OP_SCHEMA_V2
            }
        )
        .unwrap(),
        json!({"one_tap": "unreadable"})
    );
    assert!(!store.manifest_one_tap_enabled());
    assert_eq!(snapshot(&store), before);
    // Import and manifest signing do not depend on the one-tap switch.
    run(&store, import(&pair, V28)).unwrap();
    run(
        &store,
        sign(&V28.replace("\"manifest_version\": 28", "\"manifest_version\": 29")),
    )
    .unwrap();
}

#[test]
fn gh_manifest_admin_schema_roundtrips_and_debug_omits_manifest_bytes() {
    let (_dir, store, pair) = rig("manifest-admin-schema");
    let variants = [
        import(&pair, V28),
        sign(V28),
        AdminOpBody::ManifestExport {
            v: ADMIN_OP_SCHEMA_V2,
            version: 28,
        },
        AdminOpBody::ManifestList {
            v: ADMIN_OP_SCHEMA_V2,
        },
        AdminOpBody::ManifestRetireMachine {
            v: ADMIN_OP_SCHEMA_V2,
            member_id: MEMBER.into(),
        },
        AdminOpBody::ManifestOneTapSet {
            v: ADMIN_OP_SCHEMA_V2,
            enabled: true,
        },
        AdminOpBody::ManifestOneTapStatus {
            v: ADMIN_OP_SCHEMA_V2,
        },
    ];
    for op in variants {
        assert!(op.has_valid_schema_version());
        assert!(!op.requires_daemon());
        let bytes = op.to_bytes().unwrap();
        let decoded: AdminOpBody = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded.to_bytes().unwrap(), bytes);
        assert!(!format!("{op:?}").contains("worker_reads"));
        let mut wrong: Value = serde_json::from_slice(&bytes).unwrap();
        wrong["v"] = json!(ADMIN_OP_SCHEMA_V1);
        refuses(
            &store,
            serde_json::from_value(wrong).unwrap(),
            "unsupported admin op schema",
        );
    }
}

#[test]
fn gh_manifest_admin_import_refuses_a_retired_root_without_writes() {
    let (_dir, store, pair) = rig("manifest-admin-import-retired-root");
    store
        .with_raw_conn(|conn| {
            conn.execute(
                "UPDATE credentials SET state='retired' WHERE credential_id=?1",
                [GH_MANIFEST_ROOT_KEY_ID],
            )
        })
        .unwrap();
    refuses(&store, import(&pair, V28), "manifest_setup_incomplete");
}

const POLICY_ONE: &str = r#"{"bindings":[{"agent":"worker","identity":"github_app:worker","resources":["org/r"],"service":"github"}],"issued_at_unix_secs":1,"root_key_id":"21fe31dfa154a261","rule_sets":{},"schema":"ck-agent-policy/v1","version":1}"#;
const POLICY_HASH: &str = "d891be81ae8bd5dd7590df23c6d6595005e85b3ba0d30b6c529d550cfda4aad4";
const POLICY_STORE_HASH: &str = "62a6ba3b3462c51f637ced5830763c1f01a355646afe6f6f6a95583a16bf465c";

fn manifest(version: i64, bindings: &[(&str, &str)]) -> String {
    let bindings = bindings.iter().copied().collect::<BTreeMap<_, _>>();
    serde_json::to_string_pretty(
        &json!({"manifest_version": version, "issued_at_unix_secs": 1, "bindings": bindings}),
    )
    .unwrap()
        + "\n"
}

fn policy_sign(manifest_version: i64, policy: &str) -> AdminOpBody {
    AdminOpBody::AgentPolicySign {
        v: ADMIN_OP_SCHEMA_V2,
        policy_bytes: policy.into(),
        manifest_version,
        approver: "named-owner".into(),
    }
}

fn policy_list(store: &EncryptedStore) -> Value {
    run(
        store,
        AdminOpBody::AgentPolicyList {
            v: ADMIN_OP_SCHEMA_V2,
        },
    )
    .unwrap()
}

#[test]
fn policy_admin_failed_store_audit_rolls_back_approval_signature_and_pairing() {
    let (_dir, store, _pair) = rig("policy-audit-failure");
    run(&store, sign(&manifest(42, &[("Org/R", "worker")]))).unwrap();
    store.with_raw_conn(|conn| conn.execute_batch(
        "CREATE TRIGGER reject_policy_audit BEFORE INSERT ON audit_log \
         WHEN NEW.op = 'agent_policy_store' BEGIN SELECT RAISE(ABORT, 'refused policy audit'); END;",
    )).unwrap();
    refuses(&store, policy_sign(42, POLICY_ONE), "refused policy audit");
    store
        .with_raw_conn(|conn| conn.execute_batch("DROP TRIGGER reject_policy_audit;"))
        .unwrap();
    assert_eq!(
        run(&store, policy_sign(42, POLICY_ONE)).unwrap()["version"],
        1
    );
    store.verify_audit_chain().unwrap();
}

#[test]
fn policy_admin_ceremony_preserves_pairing_and_pins_audit_and_envelope() {
    let (_dir, store, pair) = rig("policy-ceremony");
    assert_eq!(
        policy_list(&store),
        json!({"policies": [], "head": null, "active": null})
    );
    let bindings = [("Org/R", "worker")];
    for version in [41, 42] {
        run(&store, sign(&manifest(version, &bindings))).unwrap();
    }
    refuses(
        &store,
        policy_sign(41, POLICY_ONE),
        "policy_manifest_not_newest",
    );
    assert!(matches!(
        run(&store, policy_sign(40, POLICY_ONE)),
        Err(StoreOpError::NotFound)
    ));
    for (bytes, reason) in [
        (
            POLICY_ONE.replace("org/r", "org/other"),
            "policy_binding_conflict",
        ),
        (
            POLICY_ONE.replace("21fe31dfa154a261", "0000000000000000"),
            "policy_root_key_id_mismatch",
        ),
        (
            POLICY_ONE.replace("\"version\":1", "\"version\":2"),
            "invalid_policy_version",
        ),
        (format!("{POLICY_ONE}\n"), "policy is not canonical JSON"),
    ] {
        refuses(&store, policy_sign(42, &bytes), reason);
    }
    let result = run(&store, policy_sign(42, POLICY_ONE)).unwrap();
    assert_eq!(result["version"], 1);
    assert_eq!(result["policy_sha256"], POLICY_HASH);
    assert_eq!(result["envelope"]["policy"], POLICY_ONE);
    assert_eq!(result["envelope"]["key_id"], "21fe31dfa154a261");
    let signature = STANDARD
        .decode(result["envelope"]["signature_b64"].as_str().unwrap())
        .unwrap();
    let input = crate::agent_policy::signed_input(POLICY_ONE.as_bytes()).unwrap();
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pair.public_key().as_ref())
        .verify(&input, &signature)
        .unwrap();

    store.with_raw_conn(|conn| {
        let rows = conn.prepare("SELECT seq, op, credential_id, payload_hash, actor FROM audit_log ORDER BY seq DESC LIMIT 3")?
            .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        assert_eq!(rows.iter().rev().map(|(_, op, id, digest, actor)| (op.as_str(), id.as_str(), digest.as_str(), actor.as_str())).collect::<Vec<_>>(), [
            ("approval", GH_MANIFEST_ROOT_KEY_ID, POLICY_HASH, "test-admin/approver:named-owner"),
            ("agent_policy_sign", GH_MANIFEST_ROOT_KEY_ID, POLICY_HASH, "test-admin/approver:named-owner"),
            ("agent_policy_store", "gh-manifest|42", POLICY_STORE_HASH, "test-admin/approver:named-owner"),
        ]);
        assert_eq!(conn.query_row("SELECT approval_seq FROM agent_policies", [], |row| row.get::<_, i64>(0))?, rows[2].0);
        Ok(())
    }).unwrap();

    refuses(
        &store,
        policy_sign(42, POLICY_ONE),
        "policy_manifest_already_paired",
    );
    let next = manifest(43, &bindings);
    refuses(&store, import(&pair, &next), "manifest_import_after_policy");
    refuses(
        &store,
        sign(&manifest(43, &[("Org/Other", "worker")])),
        "policy_binding_conflict",
    );
    refuses(
        &store,
        sign(&manifest(43, &[("Org/R", "worker"), ("org/r", "worker")])),
        "ManifestProjectionCollision",
    );
    run(&store, sign(&next)).unwrap();
    let policy_two = POLICY_ONE.replace("\"version\":1", "\"version\":2");
    refuses(
        &store,
        policy_sign(
            43,
            &policy_two.replace("github_app:worker", "github_app:other"),
        ),
        "policy_binding_conflict",
    );
    run(&store, policy_sign(43, &policy_two)).unwrap();

    store
        .set_federation_self_member_audited(MEMBER, AuditCtx::admin(AuditOp::FederationSelfSet))
        .unwrap();
    let report = |version, manifest_text: &str| {
        store
            .report_gh_manifest_active(
                &super::super::GhManifestActivationReport {
                    member_id: MEMBER,
                    version,
                    payload_sha256: &GhManifest::parse_reproducible(manifest_text.as_bytes())
                        .unwrap()
                        .manifest_sha256(),
                    verdict: super::super::GhManifestVerdict::Valid,
                    reason: None,
                    reported_at_ms: 1,
                },
                AuditCtx::admin(AuditOp::GhManifestActivation),
            )
            .unwrap();
    };
    report(42, &manifest(42, &bindings));
    let before = snapshot(&store);
    let listed = policy_list(&store);
    assert_eq!(listed["head"], 2);
    assert_eq!(listed["active"], 1);
    let policies = listed["policies"].as_array().unwrap();
    assert_eq!(policies.len(), 2);
    assert_eq!(
        policies[0].as_object().unwrap().keys().collect::<Vec<_>>(),
        [
            "approval_seq",
            "key_id",
            "manifest_version",
            "policy_sha256",
            "signed_at_ms",
            "source",
            "version",
        ]
    );
    assert_eq!(policies[0]["version"], 1);
    assert_eq!(policies[0]["manifest_version"], 42);
    assert_eq!(policies[0]["source"], "ceremony");
    assert_eq!(policies[1]["version"], 2);
    assert_eq!(snapshot(&store), before);
    report(43, &next);
    assert_eq!(policy_list(&store)["active"], 2);
    let before = snapshot(&store);
    let export = |version| {
        run(
            &store,
            AdminOpBody::AgentPolicyExport {
                v: ADMIN_OP_SCHEMA_V2,
                version,
            },
        )
    };
    assert_eq!(export(1).unwrap(), result["envelope"]);
    assert!(matches!(export(9), Err(StoreOpError::NotFound)));
    assert_eq!(snapshot(&store), before);
}

#[test]
fn policy_admin_competing_ceremonies_cannot_both_commit() {
    let (_dir, store, _pair) = rig("policy-manifest-ceremony-race");
    run(&store, sign(&manifest(42, &[("org/r", "worker")]))).unwrap();
    let new_manifest = manifest(43, &[("org/other", "worker")]);
    assert!(GhManifest::parse_reproducible(new_manifest.as_bytes()).is_ok());
    assert!(crate::agent_policy::AgentPolicy::parse_canonical(POLICY_ONE.as_bytes()).is_ok());
    assert_eq!(store.latest_gh_manifest_metadata().unwrap().unwrap().0, 42);
    assert!(policy_list(&store)["head"].is_null());

    let start = std::sync::Barrier::new(2);
    let (policy, manifest) = std::thread::scope(|scope| {
        let policy = scope.spawn(|| {
            start.wait();
            run(&store, policy_sign(42, POLICY_ONE))
        });
        let manifest = scope.spawn(|| {
            start.wait();
            run(&store, sign(&new_manifest))
        });
        (policy.join().unwrap(), manifest.join().unwrap())
    });
    assert!(
        match (&policy, &manifest) {
            (Ok(_), Err(error)) => error.to_string().contains("policy_binding_conflict"),
            (Err(error), Ok(_)) => error.to_string().contains("policy_manifest_not_newest"),
            _ => false,
        },
        "unexpected outcomes: policy={policy:?}, manifest={manifest:?}"
    );
}

#[test]
fn policy_admin_derive_normalizes_and_refuses_identity_and_pairing_changes() {
    let (_dir, store, _pair) = rig("policy-derive");
    let bindings = [("Org/Z", "zeta"), ("Org/C", "alpha"), ("Org/A", "alpha")];
    run(
        &store,
        sign(&manifest(40, &[("Org/R", "alpha"), ("org/r", "alpha")])),
    )
    .unwrap();
    let derive_op =
        |manifest_version, identities: &[(&str, &str)]| AdminOpBody::AgentPolicyDerive {
            v: ADMIN_OP_SCHEMA_V2,
            manifest_version,
            identities: identities
                .iter()
                .map(|(agent, id)| (agent.to_string(), id.to_string()))
                .collect(),
        };
    refuses(&store, derive_op(40, &[]), "ManifestProjectionCollision");
    refuses(
        &store,
        policy_sign(40, POLICY_ONE),
        "ManifestProjectionCollision",
    );
    run(&store, sign(&manifest(41, &bindings))).unwrap();
    refuses(&store, derive_op(40, &[]), "policy_manifest_not_newest");
    refuses(
        &store,
        derive_op(41, &[("alpha", "github_app:alpha")]),
        "policy_identities_do_not_match_manifest_agents",
    );
    let ids = [("zeta", "github_app:zeta"), ("alpha", "github_app:alpha")];
    let with_extra = [ids[0], ids[1], ("extra", "github_app:extra")];
    refuses(
        &store,
        derive_op(41, &with_extra),
        "policy_identities_do_not_match_manifest_agents",
    );
    refuses(
        &store,
        derive_op(41, &ids),
        "policy_identity_not_active_github_app",
    );
    for id in [
        "github_app:alpha",
        "github_app:zeta",
        "github_app:alternate",
    ] {
        store
            .create_audited(
                id,
                &VaultRecord::new_oauth(
                    "operator",
                    "github_app",
                    crate::oauth::OAuthCredential {
                        access_token: "sample".to_string().into(),
                        refresh_token: "test-only".to_string().into(),
                        expires_at_ms: None,
                        token_url: String::new(),
                        client_id: Some("sample-id".into()),
                        client_secret: None,
                        scopes: Vec::new(),
                    },
                    Vec::new(),
                ),
                AuditCtx::admin(AuditOp::Put),
            )
            .unwrap();
    }
    refuses(
        &store,
        derive_op(41, &[("zeta", "github_app:alpha"), ids[1]]),
        "SharedIdentity",
    );
    let before = snapshot(&store);
    let text = run(&store, derive_op(41, &ids)).unwrap();
    assert_eq!(snapshot(&store), before);
    let text = text.as_str().unwrap();
    assert!(!text.ends_with('\n'));
    let policy = crate::agent_policy::AgentPolicy::parse_canonical(text.as_bytes()).unwrap();
    assert_eq!(policy.version, 1);
    assert_eq!(policy.bindings[0].agent, "alpha");
    assert_eq!(policy.bindings[0].resources, ["org/a", "org/c"]);
    assert_eq!(policy.bindings[1].agent, "zeta");
    assert_eq!(
        run(&store, policy_sign(41, text)).unwrap()["envelope"]["policy"],
        text
    );
    refuses(
        &store,
        derive_op(41, &ids),
        "policy_manifest_already_paired",
    );
    run(&store, sign(&manifest(42, &bindings))).unwrap();
    refuses(
        &store,
        derive_op(42, &[("zeta", "github_app:alternate"), ids[1]]),
        "policy_binding_conflict",
    );
}
