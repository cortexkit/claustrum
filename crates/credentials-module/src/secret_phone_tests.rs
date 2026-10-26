use super::*;
use crate::federation::{
    ingress::{map_route_caller, map_route_caller_with_phone},
    MappingGate, RouteCaller,
};
use credentials_core::{key::MasterKey, test_support::TestTempDir};
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
    assert_eq!(PHONE_OPS.len(), 7);
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
