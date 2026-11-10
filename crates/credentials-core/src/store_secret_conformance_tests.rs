use super::*;
use crate::agent_secret::{SecretPut, UseTarget};
use crate::store::{PhoneDeposit, PhoneOperation};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use sha2::{Digest, Sha256};

const FP: &str = "11111111111111111111111111111111";
const LOCATION: &str = "authorization_bearer";

#[path = "store_secret_deposit_conformance_tests.rs"]
mod deposit_vectors;

fn signer() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}

fn phone(store: &EncryptedStore, op: &PhoneOperation) -> Result<Value, SecretError> {
    store.secret_phone_operation(FP, Some("pair-A"), NOW, op, || true, || NOW)
}

fn conformance_setup(tag: &str) -> (crate::test_support::TestTempDir, EncryptedStore, String) {
    let (root, store) = rig(tag, 57);
    store.ensure_secret_deposit_key().unwrap();
    store
        .set_federation_self_member_audited(MEMBER, AuditCtx::admin(AuditOp::FederationSelfSet))
        .unwrap();
    store
        .set_secret_multi_host_audited(true, AuditCtx::admin(AuditOp::SecretMultiHostSet))
        .unwrap();
    let sender = crate::kem::generate_key().unwrap();
    let (deposit_pub, _) = crate::kem::public_half(&sender).unwrap();
    phone(
        &store,
        &PhoneOperation::Register {
            deposit_pub,
            approval_pub: signer()
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
        },
    )
    .unwrap();
    (root, store, sender)
}

fn material(kind: &str) -> SecretMaterial {
    match kind {
        "agent_api_key" => SecretMaterial::ApiKey(Secret::new(b"conformance-canary".to_vec())),
        "site_login" => SecretMaterial::SiteLogin {
            username: Secret::new("test-user".into()),
            password: Secret::new("test-password".into()),
            otpauth: None,
        },
        _ => panic!("unknown kind: {kind}"),
    }
}

fn put(name: &str, kind: &str, fields: &Value, location: Option<&str>) -> SecretPut {
    SecretPut {
        name: name.into(),
        kind: kind.into(),
        host: fields["host"].as_str().map(str::to_owned),
        path_prefix: fields["path_prefix"].as_str().map(str::to_owned),
        origin: fields["origin"].as_str().map(str::to_owned),
        rules: fields.get("rules").cloned(),
        origins: fields.get("origins").cloned(),
        location: location.map(str::to_owned),
        material_b64url: URL_SAFE_NO_PAD
            .encode(agent_secret::deposit_plaintext(&material(kind)).expose()),
    }
}

fn sealed_deposit(
    store: &EncryptedStore,
    sender: &str,
    name: &str,
    id: &str,
    scope: SecretScope,
    material: &SecretMaterial,
) -> PhoneDeposit {
    let aad = agent_secret::deposit_aad(id, MEMBER, name, &scope).unwrap();
    let (enc, ciphertext) = crate::kem::seal_auth(
        sender,
        &store.secret_deposit_public_key().unwrap().public_key,
        agent_secret::deposit_plaintext(material).expose(),
        agent_secret::DEPOSIT_INFO,
        &aad,
    )
    .unwrap();
    PhoneDeposit {
        deposit_id: id.into(),
        member_id: MEMBER.into(),
        name: name.into(),
        scope,
        enc,
        ciphertext,
    }
}

fn deposit_input(
    store: &EncryptedStore,
    sender: &str,
    name: &str,
    kind: &str,
    fields: &Value,
) -> Result<Value, SecretError> {
    // The phone transport uses this parser before constructing a typed deposit.
    let scope =
        SecretScope::from_input(kind, fields, (kind == "agent_api_key").then_some(LOCATION))?;
    phone(
        store,
        &PhoneOperation::Deposit(sealed_deposit(
            store,
            sender,
            name,
            name,
            scope,
            &material(kind),
        )),
    )
}

fn target(fields: &Value) -> UseTarget {
    if let Some(origin) = fields["origin"].as_str() {
        UseTarget::SiteLogin {
            origin: origin.into(),
        }
    } else {
        UseTarget::ApiKey {
            scheme: fields["scheme"].as_str().unwrap().into(),
            host: fields["host"].as_str().unwrap().into(),
            port: u16::try_from(fields["port"].as_u64().unwrap()).unwrap(),
            path: fields["path"].as_str().unwrap().into(),
        }
    }
}

fn assert_match(
    store: &EncryptedStore,
    name: &str,
    kind: &str,
    target: &UseTarget,
    expected: bool,
) {
    store
        .store
        .with_conn(|conn| {
            // Some corpus targets are deliberately invalid transports (HTTP or a
            // non-default port). Reach the use path's matcher without its preflight.
            let checked = store.check_secret_target(conn, name, SecretSender::Basal, target)?;
            match checked {
                Ok(record) => {
                    assert!(expected, "{name}: unexpected match");
                    assert_eq!(record.material, material(kind), "{name}: opened material");
                }
                Err(refusal) => {
                    assert!(!expected, "{name}: {}", refusal.detail);
                    assert_eq!(refusal.detail, "target", "{name}");
                }
            }
            Ok(())
        })
        .unwrap();
}

fn store_scope_json(store: &EncryptedStore, name: &str, kind: &str, raw: &str) {
    let location = (kind == "agent_api_key").then_some(LOCATION);
    let scope = SecretScope::from_scope_json(kind, location, raw).unwrap_or_else(|_| {
        SecretScope::from_input(
            kind,
            &if kind == "agent_api_key" {
                json!({"rules":[{"host":"*.x.test"}]})
            } else {
                json!({"origins":["https://x.test","https://y.test"]})
            },
            location,
        )
        .unwrap()
    });
    let incarnation = format!("{:x}", Sha256::digest(name.as_bytes()))[..32].to_owned();
    let blob = agent_secret::seal(&store.key, &incarnation, name, &scope, &material(kind)).unwrap();
    store.fenced_write(|tx| {
        tx.execute(
            "INSERT INTO agent_secrets (name,kind,incarnation,state,location,record_version,key_id,envelope,created_at_ms,scope_json) VALUES (?1,?2,?3,'active',?4,1,?5,?6,?7,?8)",
            rusqlite::params![name,kind,incarnation,location,store.key_id.to_hex(),blob,NOW,raw],
        )
    }).unwrap();
}

fn assert_put_refusal(error: StoreOpError, code: &str, name: &str) {
    match code {
        "limit_exceeded" => assert!(
            matches!(&error, StoreOpError::Store(message) if message.starts_with("limit_exceeded:")),
            "{name}: {error}"
        ),
        "invalid_params" => assert_eq!(error.wire_code(), Some("invalid_credential_id"), "{name}"),
        _ => assert_eq!(error.wire_code(), Some(code), "{name}"),
    }
}

#[test]
fn conformance_every_scope_case_reaches_vault_deposit_put_or_stored_use() {
    let (_root, store, sender) = conformance_setup("scope-conformance");
    let corpus: Value = serde_json::from_str(include_str!(
        "../tests/vectors/multi-host/secret-scope-match-v1.json"
    ))
    .unwrap();
    let mut checked = [0; 2];
    for (i, case) in corpus["cases"].as_array().unwrap().iter().enumerate() {
        let label = case["case"].as_str().unwrap();
        let kind = case["kind"].as_str().unwrap();
        let fields = &case["scope"];
        let location = (kind == "agent_api_key").then_some(LOCATION);
        let name = format!("scope-{i}");
        match case["form"].as_str().unwrap() {
            "input" => {
                checked[0] += 1;
                let op = put(&name, kind, fields, location);
                if let Some(code) = case["expect"]["scope_refused"].as_str() {
                    let before = count(&store, "SELECT count(*) FROM agent_secrets");
                    let tombstones =
                        count(&store, "SELECT count(*) FROM secret_deposit_tombstones");
                    let audits = count(
                        &store,
                        "SELECT count(*) FROM audit_log WHERE op='secret_store'",
                    );
                    assert_eq!(
                        deposit_input(&store, &sender, &name, kind, fields)
                            .unwrap_err()
                            .code(),
                        code,
                        "{label}"
                    );
                    assert_put_refusal(
                        store.secret_put_audited(&op, "test").unwrap_err(),
                        code,
                        label,
                    );
                    assert_eq!(
                        count(&store, "SELECT count(*) FROM agent_secrets"),
                        before,
                        "{label}"
                    );
                    assert_eq!(
                        count(&store, "SELECT count(*) FROM secret_deposit_tombstones"),
                        tombstones,
                        "{label}"
                    );
                    assert_eq!(
                        count(
                            &store,
                            "SELECT count(*) FROM audit_log WHERE op='secret_store'"
                        ),
                        audits,
                        "{label}"
                    );
                } else {
                    assert_eq!(
                        store.secret_put_audited(&op, "test").unwrap()["status"],
                        "stored",
                        "{label}"
                    );
                    assert_match(
                        &store,
                        &name,
                        kind,
                        &target(&case["target"]),
                        case["expect"] == "match",
                    );
                }
            }
            "stored" => {
                checked[1] += 1;
                let key = if kind == "agent_api_key" {
                    "rules"
                } else {
                    "origins"
                };
                let raw = fields[key].to_string();
                store_scope_json(&store, &name, kind, &raw);
                let decoded = SecretScope::from_scope_json(kind, location, &raw);
                if let Some(code) = case["expect"]["scope_refused"].as_str() {
                    assert_eq!(decoded.unwrap_err().wire_code(), code, "{label}");
                    store
                        .store
                        .with_conn(|conn| {
                            let checked = store.check_secret_target(
                                conn,
                                &name,
                                SecretSender::Basal,
                                &call().target,
                            )?;
                            assert_eq!(
                                checked.err().expect("bad stored scope must refuse").detail,
                                "sealed_scope",
                                "{label}"
                            );
                            Ok(())
                        })
                        .unwrap();
                } else {
                    decoded.unwrap();
                    assert_match(
                        &store,
                        &name,
                        kind,
                        &target(&case["target"]),
                        case["expect"] == "match",
                    );
                }
            }
            form => panic!("unknown form {form}: {label}"),
        }
    }
    assert_eq!(
        checked,
        [87, 5],
        "every published case must reach a vault path"
    );
}

fn approve_v3(store: &EncryptedStore, call: &SecretUse, expected_scope: &Value) {
    let request = use_reply(store, call, NOW);
    assert_eq!(request["status"], "approval_required");
    let bytes = URL_SAFE_NO_PAD
        .decode(request["statement_b64url"].as_str().unwrap())
        .unwrap();
    let statement: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(statement["v"], "ck-secret-use-statement/v3");
    assert_eq!(&statement["use"], expected_scope);
    let envelope = serde_json::to_vec(&json!({
        "v":"ck-secret-use-envelope/v1",
        "items":[{"request_id":request["request_id"],"statement_sha256":format!("{:x}",Sha256::digest(&bytes))}],
        "decision":"allow","duration":"permanent","grant_expires_at_ms":0,
        "device_fingerprint":FP,"issued_at_ms":NOW,
    })).unwrap();
    let signature: Signature = signer().sign(&envelope);
    assert_eq!(
        phone(
            store,
            &PhoneOperation::Approve {
                envelope,
                signature: signature.to_der().as_bytes().to_vec(),
                card_ref: None,
            }
        )
        .unwrap(),
        json!({"results":[{"request_id":request["request_id"],"outcome":"granted"}]})
    );
}

fn targets_for(fields: &Value) -> Vec<UseTarget> {
    if let Some(rules) = fields["rules"].as_array() {
        rules
            .iter()
            .map(|rule| UseTarget::ApiKey {
                scheme: "https".into(),
                host: rule["host"].as_str().unwrap().replace("*.", "child."),
                port: 443,
                path: rule["path_prefix"]
                    .as_str()
                    .filter(|prefix| !prefix.is_empty())
                    .unwrap_or("/")
                    .into(),
            })
            .collect()
    } else {
        fields["origins"]
            .as_array()
            .unwrap()
            .iter()
            .map(|origin| UseTarget::SiteLogin {
                origin: origin.as_str().unwrap().into(),
            })
            .collect()
    }
}

fn assert_released_for_every_entry(store: &EncryptedStore, call: &mut SecretUse, scope: &Value) {
    let expected = if scope.get("rules").is_some() {
        json!({"status":"released","kind":"agent_api_key","key_b64url":URL_SAFE_NO_PAD.encode(b"conformance-canary"),"location":LOCATION})
    } else {
        json!({"status":"released","kind":"site_login","username":"test-user","password":"test-password"})
    };
    for target in targets_for(scope) {
        call.target = target;
        assert_eq!(use_reply(store, call, NOW), expected, "{}", call.name);
    }
}

fn reopen(root: &std::path::Path, key: u8) -> EncryptedStore {
    let descriptor = cortexkit_store::StorageDescriptor {
        module_id: "claustrum".into(),
        storage_namespace: "multi-host-conformance".into(),
        isolation: cortexkit_store::Isolation::Module,
        backend: cortexkit_store::StorageBackend::Sqlite {
            path: root.join("store.db").to_string_lossy().into_owned(),
        },
    };
    EncryptedStore::open(
        cortexkit_store::open_sqlite(&descriptor).unwrap(),
        MasterKey::from_bytes([key; 32]),
    )
    .unwrap()
}

#[test]
fn conformance_deposit_and_put_list_approve_v3_and_release_every_rule_after_reopen_and_rotation() {
    let cases = [
        (
            "agent_api_key",
            json!({"rules":(0..8).rev().map(|i|json!({"host":format!("api{i}.x.test"),"path_prefix":"/v1"})).collect::<Vec<_>>()}),
            json!({"rules":(0..8).map(|i|json!({"host":format!("api{i}.x.test"),"path_prefix":"/v1"})).collect::<Vec<_>>(),"location":LOCATION}),
        ),
        (
            "site_login",
            json!({"origins":["https://z.test","https://a.test"]}),
            json!({"origins":["https://a.test","https://z.test"]}),
        ),
        (
            "agent_api_key",
            json!({"rules":[{"host":"*.x.test"}]}),
            json!({"rules":[{"host":"*.x.test","path_prefix":""}],"location":LOCATION}),
        ),
    ];
    for route in ["deposit", "put"] {
        for (i, (kind, fields, expected)) in cases.iter().enumerate() {
            let (root, store, sender) = conformance_setup(&format!("e2e-{route}-{i}"));
            let location = (*kind == "agent_api_key").then_some(LOCATION);
            let result = if route == "deposit" {
                phone(
                    &store,
                    &PhoneOperation::Deposit(sealed_deposit(
                        &store,
                        &sender,
                        "key",
                        "e2e-deposit",
                        SecretScope::from_input(kind, fields, location).unwrap(),
                        &material(kind),
                    )),
                )
                .unwrap()
            } else {
                store
                    .secret_put_audited(&put("key", kind, fields, location), "test")
                    .unwrap()
            };
            assert_eq!(result["status"], "stored");
            let listed = phone(&store, &PhoneOperation::List).unwrap();
            assert_eq!(listed["secrets"].as_array().unwrap().len(), 1);
            let entry = &listed["secrets"][0];
            let array = if *kind == "agent_api_key" {
                "rules"
            } else {
                "origins"
            };
            assert_eq!(entry[array], expected[array]);
            for legacy_field in ["host", "path_prefix", "origin"] {
                assert!(entry.get(legacy_field).is_none());
            }
            let raw: String = store
                .store
                .with_conn(|conn| {
                    conn.query_row(
                        "SELECT scope_json FROM agent_secrets WHERE name='key'",
                        [],
                        |r| r.get(0),
                    )
                })
                .unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(&raw).unwrap(),
                expected[array]
            );
            let mut request = call();
            request.sender = if *kind == "agent_api_key" {
                SecretSender::Aft
            } else {
                SecretSender::Cerebellum
            };
            request.target = targets_for(expected).remove(0);
            approve_v3(&store, &request, expected);
            assert_released_for_every_entry(&store, &mut request, expected);
            drop(store);
            let mut reopened = reopen(&root, 57);
            assert_released_for_every_entry(&reopened, &mut request, expected);
            assert!(reopened
                .rotate_master_key(MasterKey::from_bytes([58; 32]))
                .unwrap()
                .is_empty());
            assert_released_for_every_entry(&reopened, &mut request, expected);
            drop(reopened);
            let rotated = reopen(&root, 58);
            assert_released_for_every_entry(&rotated, &mut request, expected);
            assert_eq!(rotated.verify_audit_chain().unwrap(), None);
        }
    }
}

#[test]
fn conformance_corrupt_use_list_vector_reaches_the_stored_decode() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../tests/vectors/multi-host/secret-list-v2.json"
    ))
    .unwrap();
    let mut checked = 0;
    for case in corpus["cases"].as_array().unwrap() {
        if case["operation"] != "secret.use" {
            continue;
        }
        let (_root, store, _sender) = conformance_setup(case["case"].as_str().unwrap());
        let setup = &case["setup"];
        let name = setup["name"].as_str().unwrap();
        store_scope_json(
            &store,
            name,
            setup["kind"].as_str().unwrap(),
            setup["scope_json"].as_str().unwrap(),
        );
        store
            .store
            .with_conn(|conn| {
                let result =
                    store.check_secret_target(conn, name, SecretSender::Basal, &call().target)?;
                assert_eq!(
                    json!(result.err().expect("unreadable scope must refuse").detail),
                    case["expect"]["code"]
                );
                Ok(())
            })
            .unwrap();
        checked += 1;
    }
    assert_eq!(checked, 1);
}
