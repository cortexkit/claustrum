use super::*;
use crate::federation::{
    ingress::{map_route_caller, map_route_caller_with_phone},
    MappingGate, RouteCaller,
};
use credentials_core::{
    audit::{AuditCtx, AuditOp},
    gh_manifest::{ManifestBindingEnvelope, MANIFEST_BINDING_ENVELOPE_V1_TAG},
    record::{CredentialKind, VaultRecord},
    store::{GhManifestProposal, GhManifestProposalInput, GhManifestSource, GhManifestVersion},
};
use credentials_core::{key::MasterKey, test_support::TestTempDir};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
use subc_protocol::Principal;

const FP: &str = "11111111111111111111111111111111";
fn rig(tag: &str) -> (TestTempDir, Arc<EncryptedStore>) {
    let root = TestTempDir::new(format!("secret-phone-{tag}-{}", std::process::id()));
    let descriptor = cortexkit_store::StorageDescriptor {
        module_id: "claustrum".into(),
        storage_namespace: tag.into(),
        isolation: cortexkit_store::Isolation::Module,
        backend: cortexkit_store::StorageBackend::Sqlite {
            path: root.join("store.db").to_string_lossy().into_owned(),
        },
    };
    let sqlite = cortexkit_store::open_sqlite(&descriptor).unwrap();
    EncryptedStore::migrate(&sqlite).unwrap();
    let store = EncryptedStore::open(sqlite, MasterKey::from_bytes([91; 32])).unwrap();
    (root, Arc::new(store))
}
fn paired() -> Value {
    json!({"devices":[{"class":"phone","fingerprint":FP,"pairing_id":"pair-A"}]})
}
fn code(answer: PhoneAnswer) -> String {
    match answer {
        PhoneAnswer::Reply(v) => v["error"]["code"].as_str().unwrap().to_owned(),
        PhoneAnswer::InvalidParams(_) => "invalid_params".into(),
        PhoneAnswer::PermissionsOperatorRequired => "permissions_operator_required".into(),
    }
}

#[test]
fn phone_mapping_requires_both_gates_and_exact_authenticated_harness() {
    let callosum = Principal::Reserved {
        module_id: "callosum".into(),
    };
    for member in [MappingGate::On, MappingGate::Off, MappingGate::Unreadable] {
        for phone in [MappingGate::On, MappingGate::Off, MappingGate::Unreadable] {
            let harness = format!("fed-phone:{FP}");
            let actual = map_route_caller_with_phone(&callosum, &harness, member, phone);
            let expected = if member == MappingGate::On && phone == MappingGate::On {
                RouteCaller::Phone(FP.into())
            } else if member == MappingGate::Off {
                RouteCaller::Principal(None)
            } else {
                RouteCaller::Refused
            };
            assert_eq!(actual, expected);
            assert!(actual.principal().is_none());
            for malformed in [
                "fed-phone:",
                "fed-phone:1111111111111111111111111111111A",
                "fed-phone:1111111111111111111111111111111",
                "fed-phone:111111111111111111111111111111111",
            ] {
                assert!(!matches!(
                    map_route_caller_with_phone(&callosum, malformed, member, phone),
                    RouteCaller::Phone(_)
                ));
            }
            for principal in [
                Principal::Direct,
                Principal::Reserved {
                    module_id: "aft".into(),
                },
                Principal::Unverified,
            ] {
                assert_eq!(
                    map_route_caller_with_phone(&principal, &harness, member, phone),
                    RouteCaller::Principal(Some(principal))
                );
            }
            for harness in [
                "callosum-self",
                "fed-computer:22222222222222222222222222222222",
                "fed-watch:abc",
            ] {
                assert_eq!(
                    map_route_caller_with_phone(&callosum, harness, member, phone),
                    map_route_caller(&callosum, harness, member)
                );
            }
        }
    }
}

#[tokio::test]
async fn phone_allowlist_and_bearers_fail_before_lookup() {
    let (_root, store) = rig("allowlist");
    assert_eq!(PHONE_OPS.len(), 8);
    for method in [
        "credential.get",
        "credential.get_scoped",
        "auth.watch_scoped",
        "admin.secret_phone_gate_set",
        "credential.remote_token",
    ] {
        let polled = AtomicBool::new(false);
        let result = serve_with_lookup(
            Arc::clone(&store),
            FP,
            method,
            &json!({}),
            tokio::time::Instant::now() + PHONE_OP_DEADLINE,
            async {
                polled.store(true, Ordering::SeqCst);
                Some(paired())
            },
        )
        .await;
        assert_eq!(code(result), "not_found", "{method}");
        assert!(!polled.load(Ordering::SeqCst));
    }
    for method in PHONE_OPS {
        for params in [
            json!({"handle":"cs1_bearer"}),
            json!({"enrollment_token":"token"}),
        ] {
            let polled = AtomicBool::new(false);
            let result = serve_with_lookup(
                Arc::clone(&store),
                FP,
                method,
                &params,
                tokio::time::Instant::now() + PHONE_OP_DEADLINE,
                async {
                    polled.store(true, Ordering::SeqCst);
                    Some(paired())
                },
            )
            .await;
            assert_eq!(code(result), "invalid_params");
            assert!(!polled.load(Ordering::SeqCst));
        }
    }
}

#[tokio::test]
async fn phone_grammar_and_size_errors_precede_pairing() {
    assert!(parse(
        "secret.approve",
        &json!({"envelope_b64url":"AA","signature_b64url":"AA","card_ref":"x".repeat(64)})
    )
    .is_ok());
    let (_root, store) = rig("grammar");
    for (method, params, expected) in [
        (
            "secret.approve",
            json!({"envelope_b64url":"AB","signature_b64url":"AA"}),
            "invalid_params",
        ),
        (
            "secret.approve",
            json!({"envelope_b64url":"AA=","signature_b64url":"AA"}),
            "invalid_params",
        ),
        (
            "secret.approve",
            json!({"envelope_b64url":"AA","signature_b64url":"AA","card_ref":"x".repeat(65)}),
            "invalid_params",
        ),
        ("secret.delete", json!({"name":".bad"}), "invalid_params"),
        (
            "secret.delete",
            json!({"name":"x".repeat(65)}),
            "limit_exceeded",
        ),
        ("secret.list", json!({"unexpected":true}), "invalid_params"),
        (
            "secret.revoke_grant",
            json!({"grant_id":"bad"}),
            "invalid_params",
        ),
    ] {
        let polled = AtomicBool::new(false);
        let result = serve_with_lookup(
            Arc::clone(&store),
            FP,
            method,
            &params,
            tokio::time::Instant::now() + PHONE_OP_DEADLINE,
            async {
                polled.store(true, Ordering::SeqCst);
                Some(paired())
            },
        )
        .await;
        assert_eq!(code(result), expected);
        assert!(!polled.load(Ordering::SeqCst));
    }
    let mut d = json!({"deposit_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","member_id":"fed-computer:22222222222222222222222222222222","name":"token","kind":"agent_api_key","host":"x.test","location":"authorization_bearer","enc_b64url":URL_SAFE_NO_PAD.encode([0;32]),"ciphertext_b64url":URL_SAFE_NO_PAD.encode(vec![0;MAX_DEPOSIT_CIPHERTEXT])});
    assert!(parse("secret.deposit", &d).is_ok());
    d["ciphertext_b64url"] = json!(URL_SAFE_NO_PAD.encode(vec![0; MAX_DEPOSIT_CIPHERTEXT + 1]));
    assert!(matches!(
        parse("secret.deposit", &d),
        Err(SecretError::LimitExceeded)
    ));
    d.as_object_mut().unwrap().remove("location");
    assert!(matches!(
        parse("secret.deposit", &d),
        Err(SecretError::InvalidParams)
    ));
}

#[tokio::test]
async fn phone_pairing_is_uncached_and_observation_survives_deadline() {
    let start = tokio::time::Instant::now();
    assert!(before_deadline(
        start + PHONE_OP_DEADLINE - std::time::Duration::from_millis(1),
        start + PHONE_OP_DEADLINE
    ));
    assert!(!before_deadline(
        start + PHONE_OP_DEADLINE,
        start + PHONE_OP_DEADLINE
    ));
    let (root, store) = rig("lookup");
    let far = || tokio::time::Instant::now() + PHONE_OP_DEADLINE;
    assert_eq!(
        code(
            serve_with_lookup(
                Arc::clone(&store),
                FP,
                "secret.list",
                &json!({}),
                far(),
                async { Some(paired()) }
            )
            .await
        ),
        "phone_not_registered"
    );
    let conn = rusqlite::Connection::open(root.join("store.db")).unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT pairing_id FROM secret_phone_observations WHERE fingerprint=?1",
            [FP],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        "pair-A"
    );
    let expired = tokio::time::Instant::now() - std::time::Duration::from_millis(1);
    assert_eq!(code(serve_with_lookup(Arc::clone(&store),FP,"secret.list",&json!({}),expired,async {Some(json!({"devices":[{"class":"phone","fingerprint":FP,"pairing_id":"pair-B"}]}))}).await),"pairing_unavailable");
    assert_eq!(
        conn.query_row(
            "SELECT pairing_id FROM secret_phone_observations WHERE fingerprint=?1",
            [FP],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        "pair-B"
    );
    let (send, recv) = tokio::sync::oneshot::channel();
    assert_eq!(
        code(
            serve_with_lookup(
                Arc::clone(&store),
                FP,
                "secret.list",
                &json!({}),
                expired,
                async { recv.await.ok() }
            )
            .await
        ),
        "pairing_unavailable"
    );
    assert!(send.send(paired()).is_err());
    assert_eq!(
        conn.query_row("SELECT count(*) FROM secret_phone_keys", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        code(
            serve_with_lookup(
                Arc::clone(&store),
                FP,
                "secret.list",
                &json!({}),
                far(),
                async { Some(json!({"devices":[]})) }
            )
            .await
        ),
        "phone_not_registered"
    );
    assert!(conn
        .query_row(
            "SELECT pairing_id FROM secret_phone_observations WHERE fingerprint=?1",
            [FP],
            |r| r.get::<_, Option<String>>(0)
        )
        .unwrap()
        .is_none());
    assert_eq!(
        code(
            serve_with_lookup(
                Arc::clone(&store),
                FP,
                "secret.list",
                &json!({}),
                far(),
                async { Some(json!({"code":"fed_not_ready"})) }
            )
            .await
        ),
        "pairing_unavailable"
    );
}

#[tokio::test]
async fn phone_deposit_keys_skips_pairing_and_requires_setup() {
    let (_root, store) = rig("deposit-keys");
    let polled = AtomicBool::new(false);
    assert_eq!(
        code(
            serve_with_lookup(
                Arc::clone(&store),
                FP,
                "secret.deposit_keys",
                &json!({}),
                tokio::time::Instant::now() + PHONE_OP_DEADLINE,
                async {
                    polled.store(true, Ordering::SeqCst);
                    None
                }
            )
            .await
        ),
        "secret_setup_incomplete"
    );
    assert!(!polled.load(Ordering::SeqCst));
    store.ensure_secret_deposit_key().unwrap();
    store
        .set_federation_self_member_audited(
            "fed-computer:22222222222222222222222222222222",
            credentials_core::audit::AuditCtx::admin(
                credentials_core::audit::AuditOp::FederationSelfSet,
            ),
        )
        .unwrap();
    let response = serve_with_lookup(
        Arc::clone(&store),
        FP,
        "secret.deposit_keys",
        &json!({}),
        tokio::time::Instant::now() + PHONE_OP_DEADLINE,
        async { panic!("deposit_keys must not look up pairing") },
    )
    .await;
    let PhoneAnswer::Reply(body) = response else {
        panic!("expected reply")
    };
    assert_eq!(
        body["member_id"],
        "fed-computer:22222222222222222222222222222222"
    );
    assert_eq!(body["keys"].as_array().unwrap().len(), 1);
    assert_eq!(body["keys"][0]["state"], "current");
    assert_eq!(body["keys"][0]["pub"].as_str().unwrap().len(), 64);
    assert_eq!(
        body["keys"][0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["key_id", "pub", "state"]
    );
}
fn extended_deposit_params(kind: &str, fields: Value) -> Value {
    let mut params = json!({
        "deposit_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "member_id": "fed-computer:22222222222222222222222222222222",
        "name": "token", "kind": kind,
        "enc_b64url": URL_SAFE_NO_PAD.encode([0; 32]), "ciphertext_b64url": "AA"
    });
    params
        .as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    if kind == "agent_api_key" {
        params["location"] = json!("authorization_bearer");
    }
    params
}

#[test]
fn phone_extended_deposit_scope_corpus_pins_grammar_psl_and_precedence() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../credentials-core/tests/vectors/multi-host/secret-scope-match-v1.json"
    ))
    .unwrap();
    for case in corpus["cases"].as_array().unwrap() {
        if case["form"] != "input" {
            continue;
        }
        let params = extended_deposit_params(case["kind"].as_str().unwrap(), case["scope"].clone());
        let parsed = parse("secret.deposit", &params);
        if let Some(expected) = case["expect"].get("scope_refused") {
            assert_eq!(
                parsed.err().unwrap().code(),
                expected.as_str().unwrap(),
                "{}",
                case["case"]
            );
        } else {
            assert!(parsed.is_ok(), "{}: {:?}", case["case"], parsed.err());
        }
    }
}

#[test]
fn phone_extended_deposit_key_sets_are_closed_and_presence_is_by_key() {
    let api = extended_deposit_params("agent_api_key", json!({"rules": [{"host":"*.x.test"}]}));
    let login = extended_deposit_params(
        "site_login",
        json!({"origins": ["https://b.test", "https://a.test"]}),
    );
    for params in [&api, &login] {
        assert!(parse("secret.deposit", params).is_ok());
        for key in params.as_object().unwrap().keys() {
            let mut missing = params.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(parse("secret.deposit", &missing).is_err(), "missing {key}");
        }
        let mut unknown = params.clone();
        unknown["unexpected"] = json!(null);
        assert!(matches!(
            parse("secret.deposit", &unknown),
            Err(SecretError::InvalidParams)
        ));
    }
    for (base, key, value) in [
        (&api, "host", json!(null)),
        (&api, "path_prefix", json!(null)),
        (&api, "origins", json!(["https://a.test", "https://b.test"])),
        (&api, "rules", json!(null)),
        (&api, "rules", json!({"host":"*.x.test"})),
        (&api, "rules", json!([])),
        (&api, "rules", json!([{"host":false}])),
        (
            &api,
            "rules",
            json!([{"host":"*.x.test", "path_prefix":null}]),
        ),
        (&api, "rules", json!([{"host":"*.x.test", "extra":true}])),
        (&login, "origin", json!(null)),
        (&login, "rules", json!([])),
        (&login, "origins", json!(null)),
        (&login, "origins", json!("https://a.test")),
        (&login, "origins", json!([])),
        (&login, "origins", json!([false, "https://a.test"])),
    ] {
        let mut params = base.clone();
        params[key] = value;
        assert!(
            matches!(
                parse("secret.deposit", &params),
                Err(SecretError::InvalidParams)
            ),
            "{params}"
        );
    }
    let PhoneOperation::Deposit(parsed) = parse("secret.deposit", &login).unwrap() else {
        panic!()
    };
    assert_eq!(
        parsed.scope,
        SecretScope::SiteLoginOrigins {
            origins: vec!["https://b.test".into(), "https://a.test".into()]
        }
    );
}

#[test]
fn phone_extended_deposit_accepts_8_rules_and_4_origins_and_refuses_the_next_entry() {
    use credentials_core::agent_secret::{MAX_SECRET_ORIGINS, MAX_SECRET_RULES};
    for (kind, key, cap) in [
        ("agent_api_key", "rules", MAX_SECRET_RULES),
        ("site_login", "origins", MAX_SECRET_ORIGINS),
    ] {
        for count in [cap, cap + 1] {
            let entries: Vec<Value> = (0..count)
                .map(|i| {
                    if key == "rules" {
                        json!({"host":format!("h{i}.test")})
                    } else {
                        json!(format!("https://h{i}.test"))
                    }
                })
                .collect();
            let params = extended_deposit_params(kind, json!({key: entries}));
            let parsed = parse("secret.deposit", &params);
            if count == cap {
                assert!(parsed.is_ok());
            } else {
                assert!(matches!(parsed, Err(SecretError::LimitExceeded)));
            }
        }
    }
}

async fn manifest_phone(store: &Arc<EncryptedStore>, method: &str, params: &Value) -> Value {
    match serve_with_lookup(
        Arc::clone(store),
        FP,
        method,
        params,
        tokio::time::Instant::now() + PHONE_OP_DEADLINE,
        async { Some(paired()) },
    )
    .await
    {
        PhoneAnswer::Reply(reply) => reply,
        _ => panic!("expected a phone result for {method}"),
    }
}

#[tokio::test]
async fn manifest_approve_params_are_exact_and_fail_before_pairing() {
    let (_root, store) = rig("manifest-grammar");
    assert!(is_phone_op("manifest.approve"));
    assert!(matches!(
        parse("manifest.approve", &json!({"envelope_b64url":"AA", "signature_b64url":"AQ"})),
        Ok(PhoneOperation::ManifestApprove { envelope, signature })
            if envelope == [0] && signature == [1]
    ));
    for params in [
        json!(null),
        json!([]),
        json!({}),
        json!({"signature_b64url":"AA"}),
        json!({"envelope_b64url":"AA"}),
        json!({"envelope_b64url":false,"signature_b64url":"AA"}),
        json!({"envelope_b64url":"AA","signature_b64url":null}),
        json!({"envelope_b64url":"AA","signature_b64url":"AA","card_ref":"card"}),
        json!({"envelope_b64url":"AA","signature_b64url":"AA","extra":null}),
        json!({"envelope_b64url":"AB","signature_b64url":"AA"}),
        json!({"envelope_b64url":"AA","signature_b64url":"AA="}),
    ] {
        let polled = AtomicBool::new(false);
        let result = serve_with_lookup(
            Arc::clone(&store),
            FP,
            "manifest.approve",
            &params,
            tokio::time::Instant::now() + PHONE_OP_DEADLINE,
            async {
                polled.store(true, Ordering::SeqCst);
                Some(paired())
            },
        )
        .await;
        assert_eq!(code(result), "invalid_params", "{params}");
        assert!(!polled.load(Ordering::SeqCst));
    }
}

fn manifest_snapshot(root: &TestTempDir) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
    let conn = rusqlite::Connection::open(root.join("store.db")).unwrap();
    [
        "gh_manifests",
        "gh_manifest_proposals",
        "gh_manifest_activations",
        "gh_manifest_activation_audits",
        "audit_log",
    ]
    .map(|table| {
        let mut statement = conn
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .unwrap();
        let columns = statement.column_count();
        statement
            .query_map([], |row| (0..columns).map(|i| row.get(i)).collect())
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    })
    .into()
}

#[tokio::test]
async fn manifest_approve_role_and_registration_refusals_precede_envelope_checks() {
    let (root, store) = rig("manifest-roles");
    let params = json!({"envelope_b64url":"AA", "signature_b64url":"AA"});
    let before = manifest_snapshot(&root);
    assert_eq!(
        manifest_phone(&store, "manifest.approve", &params).await,
        SecretError::PhoneNotRegistered.body()
    );
    assert_eq!(manifest_snapshot(&root), before);
    let home = "fed-computer:33333333333333333333333333333333";
    let member = "fed-computer:22222222222222222222222222222222";
    let conn = rusqlite::Connection::open(root.join("store.db")).unwrap();
    conn.execute(
        "INSERT INTO settings(name,value,updated_at_ms) VALUES('secrets.home_member',?1,0)",
        [home],
    )
    .unwrap();
    for (self_member, expected) in [
        (Some(member), "secret_home_elsewhere"),
        (None, "remote_setup_incomplete"),
    ] {
        conn.execute(
            "DELETE FROM settings WHERE name=?1",
            [credentials_core::federation::SELF_MEMBER_SETTING],
        )
        .unwrap();
        if let Some(member) = self_member {
            store
                .set_federation_self_member_audited(
                    member,
                    credentials_core::audit::AuditCtx::admin(
                        credentials_core::audit::AuditOp::FederationSelfSet,
                    ),
                )
                .unwrap();
        }
        let before = manifest_snapshot(&root);
        let reply = manifest_phone(&store, "manifest.approve", &params).await;
        assert_eq!(reply["error"]["code"], expected);
        assert_eq!(reply["error"]["class"], "permanent");
        if self_member.is_some() {
            assert_eq!(reply["error"]["remedy_member"], home);
        }
        assert_eq!(manifest_snapshot(&root), before);
    }
}

async fn pending_manifest(
    store: &Arc<EncryptedStore>,
) -> (GhManifestProposal, SigningKey, Vec<u8>) {
    use ring::signature::KeyPair as _;
    let der =
        ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(der.as_ref()).unwrap();
    let public = pair.public_key().as_ref().to_vec();
    let record = VaultRecord::new_static(
        CredentialKind::SigningKey,
        "operator",
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(der.as_ref())
        )
        .into_bytes(),
        None,
    );
    store
        .create_audited(
            credentials_core::store::GH_MANIFEST_ROOT_KEY_ID,
            &record,
            AuditCtx::admin(AuditOp::Put),
        )
        .unwrap();
    store
        .set_federation_self_member_audited(
            "fed-computer:22222222222222222222222222222222",
            AuditCtx::admin(AuditOp::FederationSelfSet),
        )
        .unwrap();
    let base = include_bytes!("../../credentials-core/tests/fixtures/gh-manifest-v28.json");
    store
        .store_gh_manifest(
            &GhManifestVersion {
                version: 28,
                manifest_bytes: base,
                manifest_sha256: &manifest_hash(base),
                key_id: &credentials_core::signing::key_id_for_public(&public),
                signature: &pair.sign(base).as_ref().try_into().unwrap(),
                signed_at_ms: wall_now_ms(),
                source: GhManifestSource::Import,
                approval_audit_seq: None,
            },
            AuditCtx::admin(AuditOp::GhManifestStore),
        )
        .unwrap();
    let signer = SigningKey::from_bytes((&[7; 32]).into()).unwrap();
    let (deposit_pub, _) =
        credentials_core::kem::public_half(&credentials_core::kem::generate_key().unwrap())
            .unwrap();
    assert_eq!(
        manifest_phone(
            store,
            "secret.phone_keys_register",
            &json!({
                "deposit_pub":manifest_hex(&deposit_pub),
                "approval_pub":manifest_hex(signer.verifying_key().to_encoded_point(false).as_bytes()),
            }),
        )
        .await,
        json!({"status":"stored"})
    );
    let prepared = store
        .prepare_gh_manifest_proposal(GhManifestProposalInput {
            agent_id: "agent_4444444444444444".into(),
            app_id: 42,
            app_slug: "repo-bot".into(),
            repo: "Octo/New".into(),
            installation_permissions: std::collections::BTreeMap::from([
                ("contents".into(), "write".into()),
                ("metadata".into(), "read".into()),
            ]),
        })
        .unwrap();
    let proposal = store
        .propose_gh_manifest_binding(&prepared, "reserved:plexus", || true, wall_now_ms)
        .unwrap();
    (proposal, signer, public)
}

fn manifest_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn manifest_hash(bytes: &[u8]) -> String {
    manifest_hex(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

fn manifest_envelope(proposal: &GhManifestProposal) -> Vec<u8> {
    ManifestBindingEnvelope {
        v: String::from_utf8(MANIFEST_BINDING_ENVELOPE_V1_TAG.to_vec()).unwrap(),
        proposal_id: proposal.proposal_id.clone(),
        statement_sha256: manifest_hash(&proposal.statement_bytes),
        decision: "allow".into(),
        device_fingerprint: FP.into(),
        issued_at_ms: wall_now_ms() as u64,
    }
    .canonical_bytes()
    .unwrap()
}

#[tokio::test]
async fn manifest_approve_phone_commits_verifiable_bytes_and_resends_across_restart() {
    let (root, store) = rig("manifest-restart");
    let (proposal, signer, public) = pending_manifest(&store).await;
    let envelope = manifest_envelope(&proposal);
    let signature: Signature = signer.sign(&envelope);
    let params = json!({
        "envelope_b64url":URL_SAFE_NO_PAD.encode(&envelope),
        "signature_b64url":URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
    });
    let expected = json!({
        "status":"approved", "proposal_id":proposal.proposal_id,
        "version":29, "manifest_sha256":manifest_hash(&proposal.manifest_bytes),
    });
    assert_eq!(
        manifest_phone(&store, "manifest.approve", &params).await,
        expected
    );
    let after = manifest_snapshot(&root);
    let conn = rusqlite::Connection::open(root.join("store.db")).unwrap();
    let (bytes, signature, source): (Vec<u8>, Vec<u8>, String) = conn
        .query_row(
            "SELECT manifest_bytes,signature,source FROM gh_manifests WHERE version=29",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(bytes, proposal.manifest_bytes);
    assert_eq!(source, "one_tap");
    let verifier = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &public);
    verifier.verify(&bytes, &signature).unwrap();
    let mut changed = bytes;
    changed[0] ^= 1;
    assert!(verifier.verify(&changed, &signature).is_err());
    drop(conn);
    drop(store);
    let sqlite = cortexkit_store::open_sqlite(&cortexkit_store::StorageDescriptor {
        module_id: "claustrum".into(),
        storage_namespace: "manifest-restart".into(),
        isolation: cortexkit_store::Isolation::Module,
        backend: cortexkit_store::StorageBackend::Sqlite {
            path: root.join("store.db").to_string_lossy().into_owned(),
        },
    })
    .unwrap();
    let store = Arc::new(EncryptedStore::open(sqlite, MasterKey::from_bytes([91; 32])).unwrap());
    assert_eq!(
        manifest_phone(&store, "manifest.approve", &params).await,
        expected
    );
    assert_eq!(manifest_snapshot(&root), after);
}

#[tokio::test]
async fn manifest_approve_phone_rejects_cross_domain_envelopes_at_strict_parse() {
    use credentials_core::agent_secret::{ApprovalEnvelope, ApprovalItem, USE_ENVELOPE_TAG};
    let (root, store) = rig("manifest-domains");
    let (proposal, _, _) = pending_manifest(&store).await;
    let secret_bytes = ApprovalEnvelope {
        v: String::from_utf8(USE_ENVELOPE_TAG.to_vec()).unwrap(),
        items: vec![ApprovalItem {
            request_id: proposal.proposal_id.clone(),
            statement_sha256: proposal.statement_sha256.clone(),
        }],
        decision: "allow".into(),
        duration: "once".into(),
        grant_expires_at_ms: 0,
        device_fingerprint: FP.into(),
        issued_at_ms: wall_now_ms() as u64,
    }
    .canonical_bytes()
    .unwrap();
    let manifest_bytes = manifest_envelope(&proposal);
    assert!(serde_json::from_slice::<ManifestBindingEnvelope>(&secret_bytes).is_err());
    assert!(serde_json::from_slice::<ApprovalEnvelope>(&manifest_bytes).is_err());
    for (method, envelope) in [
        ("manifest.approve", secret_bytes),
        ("secret.approve", manifest_bytes),
    ] {
        let before = manifest_snapshot(&root);
        // Both strict envelope parsers refuse before the empty signature can be used.
        assert_eq!(
            manifest_phone(
                &store,
                method,
                &json!({"envelope_b64url":URL_SAFE_NO_PAD.encode(envelope), "signature_b64url":""}),
            )
            .await,
            SecretError::ApprovalInvalid.body()
        );
        assert_eq!(manifest_snapshot(&root), before);
    }
}
