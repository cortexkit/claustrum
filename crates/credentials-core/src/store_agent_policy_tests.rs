use super::*;
use crate::agent_policy::{github_default_rule_set, AGENT_POLICY_SCHEMA_V1};
use crate::gh_manifest::GhManifest;
use crate::key::MasterKey;
use crate::store::{
    append_audit_tx, migrate_through_for_test, read_schema_version, taxonomy_tests, AuditCtx,
    AuditOp, AuditRecord, CredentialKind, GhManifestSource, GhManifestVersion, GrantOperation,
    SelectorKind, VaultRecord,
};
use base64::prelude::{Engine, BASE64_STANDARD};
use ring::signature::{Ed25519KeyPair, KeyPair};
use rusqlite::{params_from_iter, types::Value, Connection, ErrorCode};

const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY_ID: &str = "0123456789abcdef";

fn assert_constraint(result: rusqlite::Result<usize>, case: &str) {
    let error = result.expect_err(case);
    assert_eq!(
        error.sqlite_error_code(),
        Some(ErrorCode::ConstraintViolation),
        "{case}: {error}"
    );
}

fn raw_manifest(conn: &Connection, version: i64) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO gh_manifests VALUES (?1, X'01', ?2, ?3, ?4, 1, 'import', NULL)",
        params![version, HASH, KEY_ID, &[4_u8; 64][..]],
    )
}

fn raw_policy(version: i64, manifest_version: i64) -> [Value; 9] {
    [
        version.into(),
        vec![1_u8].into(),
        HASH.to_owned().into(),
        KEY_ID.to_owned().into(),
        vec![7_u8; 64].into(),
        100_i64.into(),
        "ceremony".to_owned().into(),
        1_i64.into(),
        manifest_version.into(),
    ]
}

fn policy_state(conn: &Connection, manifest_version: i64) -> rusqlite::Result<(Option<i64>, bool)> {
    let head = conn.query_row("SELECT MAX(version) FROM agent_policies", [], |r| r.get(0))?;
    let paired = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM agent_policies WHERE manifest_version = ?1)",
        [manifest_version],
        |r| r.get(0),
    )?;
    Ok((head, paired))
}

#[test]
fn active_policy_reads_role_reports_and_pairing_from_one_snapshot() {
    use crate::federation::SELF_MEMBER_SETTING;
    use crate::store::SECRET_HOME_SETTING;

    let (dir, store) = taxonomy_tests::rig("active-policy-snapshot", 77);
    let member = "fed-computer:22222222222222222222222222222222";
    let home = "fed-computer:33333333333333333333333333333333";
    let writer = Connection::open(dir.join("store.db")).unwrap();
    let setting = |name, value| {
        writer
            .execute(
                "INSERT INTO settings (name, value, updated_at_ms) VALUES (?1, ?2, 1) \
             ON CONFLICT(name) DO UPDATE SET value = excluded.value",
                params![name, value],
            )
            .unwrap();
    };
    let report = |version| {
        writer.execute(
            "INSERT INTO gh_manifest_activations (member_id, version, payload_sha256, verdict, reported_at_ms) \
             VALUES (?1, ?2, ?3, 'valid', 1) ON CONFLICT(member_id) DO UPDATE SET version = excluded.version",
            params![member, version, HASH],
        ).unwrap();
    };
    setting(SELF_MEMBER_SETTING, member);
    setting(SECRET_HOME_SETTING, "self");
    for (version, manifest_version) in [(1, 41), (2, 42)] {
        raw_manifest(&writer, manifest_version).unwrap();
        let mut row = raw_policy(version, manifest_version);
        row[1] = format!("{{\"version\":{version}}}").into_bytes().into();
        writer
            .execute(
                "INSERT INTO agent_policies VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params_from_iter(row),
            )
            .unwrap();
    }
    report(41);
    let policy = store
        .with_raw_conn(|conn| active_agent_policy_read(conn, || report(42)))
        .unwrap()
        .1
        .unwrap();
    assert_eq!((policy.version, policy.manifest_version), (1, 41));
    assert_eq!(store.active_agent_policy().unwrap().1.unwrap().version, 2);

    report(41);
    let (role, policy) = store
        .with_raw_conn(|conn| {
            active_agent_policy_read(conn, || {
                // Distinct commits: there is never a serving snapshot where P2 is active.
                setting(SECRET_HOME_SETTING, home);
                report(42);
            })
        })
        .unwrap();
    assert!(matches!(role, SecretHomeRole::Home { .. }));
    assert_eq!(policy.unwrap().policy_text, "{\"version\":1}");
    let (role, policy) = store.active_agent_policy().unwrap();
    assert!(matches!(role, SecretHomeRole::Remote { .. }));
    assert!(policy.is_none());
}

#[test]
fn migration_51_rejects_invalid_policy_columns_in_an_empty_table() {
    let (_dir, store) = taxonomy_tests::rig("policy-sql-column-checks", 61);
    store.with_raw_conn(|conn| {
        conn.pragma_update(None, "foreign_keys", false)?;
        raw_manifest(conn, 1)?;
        let baseline = raw_policy(1, 1);
        const INSERT: &str = "INSERT INTO agent_policies VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";
        assert_constraint(conn.execute(
            "INSERT INTO agent_policies (policy_bytes, policy_sha256, key_id, signature, \
             signed_at_ms, source, approval_seq, manifest_version) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params_from_iter(&baseline[1..]),
        ), "omitted version");

        let refuse = |index: usize, value: Value| {
            let mut row = baseline.clone();
            row[index] = value;
            assert_constraint(conn.execute(INSERT, params_from_iter(&row)), &format!("column {index}: {:?}", row[index]));
            assert_eq!(policy_state(conn, 1).unwrap(), (None, false));
        };
        for index in 0..baseline.len() {
            refuse(index, Value::Null);
        }
        for index in [0, 5, 7, 8] {
            refuse(index, Value::Real(1.5));
            refuse(index, Value::Text("not numeric".into()));
        }
        for index in [0, 5, 7] {
            refuse(index, Value::Integer(0));
            refuse(index, Value::Integer(-1));
        }
        refuse(1, Value::Blob(vec![]));
        refuse(1, Value::Text("a".into()));
        refuse(4, Value::Blob(vec![0; 63]));
        refuse(4, Value::Text("a".repeat(64)));
        for (index, width) in [(2, 64), (3, 16)] {
            refuse(index, Value::Blob(vec![b'a'; width]));
            refuse(index, Value::Text("a".repeat(width - 1)));
            refuse(index, Value::Text("A".repeat(width)));
            refuse(index, Value::Text(format!("{}\0f", "a".repeat(width))));
            refuse(index, Value::Text(format!("{}\0", "a".repeat(width - 1))));
        }
        refuse(6, Value::Text("import".into()));
        refuse(6, Value::Text("ceremony\0suffix".into()));
        refuse(6, Value::Blob(b"ceremony".to_vec()));
        refuse(8, Value::Integer(2));

        let mut valid = baseline;
        valid[0] = Value::Text("1".into());
        assert_eq!(conn.execute(INSERT, params_from_iter(&valid))?, 1);
        assert_eq!(policy_state(conn, 1)?, (Some(1), true));
        Ok(())
    }).unwrap();
}

#[test]
fn migration_51_policy_triggers_keep_rows_insert_only_and_paired_once() {
    let (_dir, store) = taxonomy_tests::rig("policy-sql-triggers", 62);
    store.with_raw_conn(|conn| {
        raw_manifest(conn, 1)?;
        raw_manifest(conn, 2)?;
        raw_manifest(conn, 3)?;
        conn.execute("INSERT INTO agent_policies VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)", params_from_iter(raw_policy(2, 1)))?;
        for recursive in [false, true] {
            conn.pragma_update(None, "recursive_triggers", recursive)?;
            assert_constraint(conn.execute("INSERT OR REPLACE INTO agent_policies VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)", params_from_iter(raw_policy(3, 1))), "replacement of a paired manifest");
            assert_eq!(policy_state(conn, 1)?, (Some(2), true));
            assert_constraint(conn.execute("INSERT OR REPLACE INTO agent_policies VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)", params_from_iter(raw_policy(2, 2))), "replacement of a policy version");
            assert_constraint(conn.execute("INSERT INTO agent_policies VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)", params_from_iter(raw_policy(1, 3))), "decreasing version");
            assert_constraint(conn.execute("UPDATE agent_policies SET signed_at_ms = 101", []), "update of a stored policy");
            assert_constraint(conn.execute("DELETE FROM agent_policies", []), "delete of a stored policy");
            let kept: (i64, i64, i64) = conn.query_row("SELECT version, manifest_version, signed_at_ms FROM agent_policies", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            assert_eq!(kept, (2, 1, 100));
        }
        assert_eq!(conn.execute("INSERT INTO agent_policies VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)", params_from_iter(raw_policy(3, 2)))?, 1);
        Ok(())
    }).unwrap();
}

#[test]
fn migration_51_binds_github_app_metadata_to_one_credential() {
    let (_dir, store) = taxonomy_tests::rig("policy-app-identity-columns", 63);
    for id in ["github_app:sample", "apikey:sample"] {
        store.create(id, &taxonomy_tests::api_record()).unwrap();
    }
    store.with_raw_conn(|conn| {
        let write = |credential, id: Value, slug: Value| conn.execute(
            "UPDATE credentials SET github_app_id = ?1, github_app_slug = ?2 WHERE credential_id = ?3",
            params![id, slug, credential],
        );
        let app = "github_app:sample";
        let text = |s: &str| Value::Text(s.into());
        assert_constraint(conn.execute("UPDATE credentials SET github_app_id = '31' WHERE credential_id = ?1", [app]), "updating only the App id");
        assert_constraint(write(app, Value::Null, text("sample")), "missing App id");
        assert_constraint(write(app, text("31"), Value::Null), "missing App slug");
        assert_constraint(write("apikey:sample", text("31"), text("sample")), "non-App credential");
        for invalid in ["", "0", "01", "+1", "-1", "1.5", "1 ", " 1", "3x", "٣", "31\0suffix"] {
            assert_constraint(write(app, text(invalid), text("sample")), invalid);
        }
        for (id, slug) in [
            (Value::Blob(b"31".to_vec()), text("sample")),
            (text("31"), Value::Blob(b"sample".to_vec())),
            (text("31"), text("other")),
            (text("31"), text("sample\0other")),
        ] {
            assert_constraint(write(app, id, slug), "malformed App metadata pair");
        }
        assert_eq!(write(app, text("31"), text("sample"))?, 1);
        assert_eq!(write(app, Value::Null, Value::Null)?, 1);
        Ok(())
    }).unwrap();
}

#[test]
fn migration_51_preserves_every_grant_and_generation_in_a_schema_50_vault() {
    let (_dir, sqlite) = taxonomy_tests::sqlite("policy-grants-upgrade", 64);
    migrate_through_for_test(&sqlite, 50).unwrap();
    let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([64; 32])).unwrap();
    let initial_generation = store.grants_generation().unwrap();
    use GrantOperation::*;
    for (i, (op, kind, selector)) in [
        (Read, SelectorKind::Exact, "github_app:sample"),
        (Sign, SelectorKind::Category, "custom"),
        (Open, SelectorKind::Exact, "key"),
        (List, SelectorKind::Category, "custom"),
        (Deposit, SelectorKind::Category, "browser-session"),
        (AccountToken, SelectorKind::Audience, "cortexkit-runners"),
        (Seal, SelectorKind::Exact, "key"),
    ]
    .into_iter()
    .enumerate()
    {
        store
            .create_read_grant_audited(
                "reserved",
                &format!("principal-{i}"),
                kind,
                selector,
                op,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap();
    }
    let grants = store.list_read_grants().unwrap();
    let generation = store.grants_generation().unwrap();
    let audit = store.read_audit(None).unwrap();
    assert_eq!(grants.len(), 7);
    assert_eq!(generation, initial_generation + 7);
    assert_eq!(store.with_raw_conn(read_schema_version).unwrap(), 50);
    EncryptedStore::migrate(&store.store).unwrap();
    assert_eq!(store.with_raw_conn(read_schema_version).unwrap(), 51);
    assert_eq!(store.list_read_grants().unwrap(), grants);
    assert_eq!(store.grants_generation().unwrap(), generation);
    assert_eq!(store.read_audit(None).unwrap(), audit);

    store
        .with_raw_conn(|conn| {
            for (kind, op) in [
                ("exact", "unknown"),
                ("category", "seal"),
                ("exact", "account_token"),
                ("audience", "policy_token"),
                ("category", "policy_token"),
            ] {
                assert_constraint(conn.execute(
                "INSERT INTO read_grants VALUES ('reserved', 'sql', ?1, 'selector', ?2, 123)",
                params![kind, op],
            ), &format!("{kind} {op}"));
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(
        "policy_token".parse::<GrantOperation>().unwrap(),
        PolicyToken
    );
    assert_eq!(PolicyToken.as_str(), "policy_token");
    assert_eq!(
        serde_json::to_string(&PolicyToken).unwrap(),
        "\"policy_token\""
    );
    assert!(SelectorKind::Category
        .validate_operation(PolicyToken)
        .is_err());
    assert!(SelectorKind::Audience
        .validate_operation(PolicyToken)
        .is_err());
    store
        .create_read_grant_audited(
            "reserved",
            "policy-client",
            SelectorKind::Exact,
            "github_app:sample",
            PolicyToken,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    assert!(store
        .list_read_grants()
        .unwrap()
        .iter()
        .any(|g| g.operation == PolicyToken && g.selector == "github_app:sample"));
    assert_eq!(store.grants_generation().unwrap(), generation + 1);
}

fn install_root(store: &EncryptedStore) -> Ed25519KeyPair {
    let der = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(der.as_ref()).unwrap();
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        BASE64_STANDARD.encode(der.as_ref())
    );
    store
        .create_audited(
            GH_MANIFEST_ROOT_KEY_ID,
            &VaultRecord::new_static(
                CredentialKind::SigningKey,
                "operator",
                pem.into_bytes(),
                None,
            ),
            AuditCtx::admin(AuditOp::Put),
        )
        .unwrap();
    pair
}

fn audit_fixture(
    store: &EncryptedStore,
    tx: &Transaction<'_>,
    op: AuditOp,
    credential: &str,
    digest: &str,
) -> rusqlite::Result<i64> {
    Ok(append_audit_tx(
        tx,
        &store.audit_key,
        &AuditRecord {
            op,
            credential_id: Some(credential.into()),
            payload_hash: Some(digest.into()),
            actor: "test/approver:owner".into(),
            alarm: None,
        },
    )?
    .seq)
}

fn sign_manifest_fixture(
    store: &EncryptedStore,
    tx: &Transaction<'_>,
    version: i64,
    source: GhManifestSource,
    approval_digest: Option<&str>,
) -> rusqlite::Result<(i64, String)> {
    let text = format!("{{\n  \"manifest_version\": {version},\n  \"issued_at_unix_secs\": 1,\n  \"bindings\": {{}}\n}}\n");
    let manifest = GhManifest::parse_reproducible(text.as_bytes()).unwrap();
    let digest = manifest.manifest_sha256();
    let approval = audit_fixture(
        store,
        tx,
        AuditOp::Approval,
        GH_MANIFEST_ROOT_KEY_ID,
        approval_digest.unwrap_or(&digest),
    )?;
    let signature = store
        .sign_gh_manifest(
            tx,
            text.as_bytes(),
            AuditCtx::admin(AuditOp::GhManifestSign),
        )
        .unwrap();
    let raw = BASE64_STANDARD
        .decode(signature.signature_b64)
        .unwrap()
        .try_into()
        .unwrap();
    store.store_gh_manifest_in_tx(
        tx,
        &GhManifestVersion {
            version,
            manifest_bytes: text.as_bytes(),
            manifest_sha256: &digest,
            key_id: &signature.key_id,
            signature: &raw,
            signed_at_ms: 100,
            source,
            approval_audit_seq: Some(approval),
        },
        AuditCtx::admin(AuditOp::GhManifestStore),
    )?;
    Ok((approval, digest))
}

fn policy_fixture(version: i64, key_id: &str) -> AgentPolicy {
    AgentPolicy {
        schema: AGENT_POLICY_SCHEMA_V1.into(),
        version,
        issued_at_unix_secs: 1,
        root_key_id: key_id.into(),
        rule_sets: [("github".into(), github_default_rule_set().unwrap())].into(),
        bindings: vec![],
    }
}

struct SignedFixture {
    bytes: Vec<u8>,
    digest: String,
    signature: [u8; 64],
}

impl SignedFixture {
    fn new(pair: &Ed25519KeyPair, bytes: Vec<u8>) -> Self {
        Self {
            signature: pair
                .sign(&signed_input(&bytes).unwrap())
                .as_ref()
                .try_into()
                .unwrap(),
            digest: policy_sha256(&bytes),
            bytes,
        }
    }

    fn set_evidence<'a>(&'a self, row: &AgentPolicyVersion<'a>) -> AgentPolicyVersion<'a> {
        AgentPolicyVersion {
            policy_bytes: &self.bytes,
            policy_sha256: &self.digest,
            signature: &self.signature,
            ..*row
        }
    }
}

#[test]
fn typed_policy_store_refuses_each_ceremony_mismatch_without_consuming_version_or_pairing() {
    use StoreAgentPolicyError::*;
    let (_dir, store) = taxonomy_tests::rig("typed-policy-ceremony", 65);
    let pair = install_root(&store);
    let key_id = crate::signing::key_id_for_public(pair.public_key().as_ref());

    for (i, case) in [
        "canonical",
        "digest",
        "key id",
        "body root key id",
        "body version",
        "signature",
        "absent approval",
        "wrong approval op",
        "wrong approval credential",
        "wrong approval payload",
        "missing manifest",
        "unrecognized default",
    ]
    .into_iter()
    .enumerate()
    {
        let version = i as i64 + 1;
        store
            .fenced_write(|tx| {
                let manifest_version = version + 100;
                sign_manifest_fixture(
                    &store,
                    tx,
                    manifest_version,
                    GhManifestSource::Ceremony,
                    None,
                )?;
                let policy = policy_fixture(version, &key_id);
                let evidence = SignedFixture::new(&pair, policy.canonical_bytes().unwrap());
                let row = AgentPolicyVersion {
                    version,
                    manifest_version,
                    key_id: &key_id,
                    signed_at_ms: 100,
                    source: AgentPolicySource::Ceremony,
                    approval_seq: audit_fixture(
                        &store,
                        tx,
                        AuditOp::Approval,
                        GH_MANIFEST_ROOT_KEY_ID,
                        &evidence.digest,
                    )?,
                    policy_bytes: &evidence.bytes,
                    policy_sha256: &evidence.digest,
                    signature: &evidence.signature,
                };
                let try_store = |candidate: &AgentPolicyVersion<'_>| {
                    store.store_agent_policy_in_tx(tx, candidate)
                };
                let correct_approval_for = |evidence: &SignedFixture| {
                    audit_fixture(
                        &store,
                        tx,
                        AuditOp::Approval,
                        GH_MANIFEST_ROOT_KEY_ID,
                        &evidence.digest,
                    )
                };
                let rejected = match case {
                    "canonical" => {
                        let mut bytes = evidence.bytes.clone();
                        bytes.push(b'\n');
                        let altered = SignedFixture::new(&pair, bytes);
                        let bad = AgentPolicyVersion {
                            approval_seq: correct_approval_for(&altered)?,
                            ..altered.set_evidence(&row)
                        };
                        matches!(try_store(&bad), Err(Policy(PolicyError::NotCanonical)))
                    }
                    "digest" => matches!(
                        try_store(&AgentPolicyVersion {
                            policy_sha256: HASH,
                            ..row
                        }),
                        Err(DigestMismatch)
                    ),
                    "key id" => matches!(
                        try_store(&AgentPolicyVersion {
                            key_id: KEY_ID,
                            ..row
                        }),
                        Err(KeyIdMismatch)
                    ),
                    "body root key id" | "unrecognized default" => {
                        let mut altered = policy;
                        if case == "body root key id" {
                            altered.root_key_id = KEY_ID.into();
                        } else {
                            altered.rule_sets.get_mut("github").unwrap().source.sha256 =
                                HASH.into();
                        }
                        let altered = SignedFixture::new(&pair, altered.canonical_bytes().unwrap());
                        let bad = AgentPolicyVersion {
                            approval_seq: correct_approval_for(&altered)?,
                            ..altered.set_evidence(&row)
                        };
                        let result = try_store(&bad);
                        if case == "body root key id" {
                            matches!(result, Err(RootKeyIdMismatch))
                        } else {
                            matches!(result, Err(Policy(PolicyError::UnknownDefaultDigest)))
                        }
                    }
                    "body version" => matches!(
                        try_store(&AgentPolicyVersion {
                            version: version + 1,
                            ..row
                        }),
                        Err(VersionMismatch)
                    ),
                    "signature" => {
                        // A valid root signature over the bare document is not a policy signature.
                        let raw = pair.sign(&evidence.bytes);
                        let signature = raw.as_ref().try_into().unwrap();
                        matches!(
                            try_store(&AgentPolicyVersion { signature, ..row }),
                            Err(InvalidSignature)
                        )
                    }
                    "absent approval" => matches!(
                        try_store(&AgentPolicyVersion {
                            approval_seq: i64::MAX,
                            ..row
                        }),
                        Err(ApprovalMismatch)
                    ),
                    "wrong approval op"
                    | "wrong approval credential"
                    | "wrong approval payload" => {
                        let (op, credential, digest) = match case {
                            "wrong approval op" => (
                                AuditOp::GhManifestSign,
                                GH_MANIFEST_ROOT_KEY_ID,
                                evidence.digest.as_str(),
                            ),
                            "wrong approval credential" => {
                                (AuditOp::Approval, "signing:other", evidence.digest.as_str())
                            }
                            _ => (AuditOp::Approval, GH_MANIFEST_ROOT_KEY_ID, HASH),
                        };
                        let approval_seq = audit_fixture(&store, tx, op, credential, digest)?;
                        matches!(
                            try_store(&AgentPolicyVersion {
                                approval_seq,
                                ..row
                            }),
                            Err(ApprovalMismatch)
                        )
                    }
                    "missing manifest" => matches!(
                        try_store(&AgentPolicyVersion {
                            manifest_version: i64::MAX,
                            ..row
                        }),
                        Err(MissingManifest)
                    ),
                    _ => unreachable!("{case}"),
                };
                assert!(rejected, "{case} must return its typed refusal");
                assert_eq!(
                    policy_state(tx, manifest_version)?,
                    ((version > 1).then_some(version - 1), false),
                    "{case}"
                );
                try_store(&row).unwrap();
                assert_eq!(policy_state(tx, manifest_version)?, (Some(version), true));
                Ok(())
            })
            .unwrap();
    }
}

#[test]
fn typed_policy_store_requires_the_one_tap_manifests_own_approval() {
    let (_dir, store) = taxonomy_tests::rig("typed-policy-one-tap", 66);
    let pair = install_root(&store);
    let key_id = crate::signing::key_id_for_public(pair.public_key().as_ref());
    store
        .fenced_write(|tx| {
            let (approval_seq, _) =
                sign_manifest_fixture(&store, tx, 1, GhManifestSource::Ceremony, None)?;
            let evidence =
                SignedFixture::new(&pair, policy_fixture(1, &key_id).canonical_bytes().unwrap());
            let row = AgentPolicyVersion {
                version: 1,
                manifest_version: 1,
                key_id: &key_id,
                signed_at_ms: 100,
                source: AgentPolicySource::OneTap,
                approval_seq,
                policy_bytes: &evidence.bytes,
                policy_sha256: &evidence.digest,
                signature: &evidence.signature,
            };
            assert!(matches!(
                store.store_agent_policy_in_tx(tx, &row),
                Err(StoreAgentPolicyError::ManifestSourceMismatch)
            ));
            assert_eq!(policy_state(tx, 1)?, (None, false));
            let policy_approval = audit_fixture(
                &store,
                tx,
                AuditOp::Approval,
                GH_MANIFEST_ROOT_KEY_ID,
                &evidence.digest,
            )?;
            store
                .store_agent_policy_in_tx(
                    tx,
                    &AgentPolicyVersion {
                        source: AgentPolicySource::Ceremony,
                        approval_seq: policy_approval,
                        ..row
                    },
                )
                .unwrap();
            assert_eq!(policy_state(tx, 1)?, (Some(1), true));

            let (approval_seq, digest) =
                sign_manifest_fixture(&store, tx, 2, GhManifestSource::OneTap, None)?;
            let evidence =
                SignedFixture::new(&pair, policy_fixture(2, &key_id).canonical_bytes().unwrap());
            let row = AgentPolicyVersion {
                version: 2,
                manifest_version: 2,
                approval_seq,
                ..evidence.set_evidence(&row)
            };
            for wrong_hash in [HASH, &digest] {
                let other_approval_seq = audit_fixture(
                    &store,
                    tx,
                    AuditOp::Approval,
                    GH_MANIFEST_ROOT_KEY_ID,
                    wrong_hash,
                )?;
                assert!(matches!(
                    store.store_agent_policy_in_tx(
                        tx,
                        &AgentPolicyVersion {
                            approval_seq: other_approval_seq,
                            ..row
                        }
                    ),
                    Err(StoreAgentPolicyError::ApprovalMismatch)
                ));
                assert_eq!(policy_state(tx, 2)?, (Some(1), false));
            }
            store.store_agent_policy_in_tx(tx, &row).unwrap();
            assert_eq!(policy_state(tx, 2)?, (Some(2), true));

            let (approval_seq, _) =
                sign_manifest_fixture(&store, tx, 3, GhManifestSource::OneTap, Some(HASH))?;
            let evidence =
                SignedFixture::new(&pair, policy_fixture(3, &key_id).canonical_bytes().unwrap());
            let row = AgentPolicyVersion {
                version: 3,
                manifest_version: 3,
                approval_seq,
                ..evidence.set_evidence(&row)
            };
            assert!(matches!(
                store.store_agent_policy_in_tx(tx, &row),
                Err(StoreAgentPolicyError::ApprovalMismatch)
            ));
            assert_eq!(policy_state(tx, 3)?, (Some(2), false));
            let policy_approval = audit_fixture(
                &store,
                tx,
                AuditOp::Approval,
                GH_MANIFEST_ROOT_KEY_ID,
                &evidence.digest,
            )?;
            store
                .store_agent_policy_in_tx(
                    tx,
                    &AgentPolicyVersion {
                        source: AgentPolicySource::Ceremony,
                        approval_seq: policy_approval,
                        ..row
                    },
                )
                .unwrap();
            assert_eq!(policy_state(tx, 3)?, (Some(3), true));
            Ok(())
        })
        .unwrap();
}
