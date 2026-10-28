use super::*;
use crate::agent_secret::{
    AskingScope, FlowIdentity, SecretFlowApproval, SecretFlowUse, SecretSender, SecretUse,
    UseTarget,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::Signer, Signature};

const NOW: i64 = 1_700_000_000_000;
const USED_AT: i64 = NOW + 3_000;
const INCARNATION: &str = "0123456789abcdef0123456789abcdef";
const FLOW_GRANT: &str = "01HF7YB0000000000000000001";
const AGENT_GRANT: &str = "01HF7YB0000000000000000002";

fn identity() -> FlowIdentity {
    FlowIdentity {
        flow_id: "daily-fetch".into(),
        version: 7,
        code_hash: "0123456789abcdef".repeat(4),
        install_id: "install-A".into(),
    }
}

fn target(login: bool) -> UseTarget {
    if login {
        UseTarget::SiteLogin {
            origin: "https://x.test".into(),
        }
    } else {
        UseTarget::ApiKey {
            scheme: "https".into(),
            host: "x.test".into(),
            port: 443,
            path: "/repos/a".into(),
        }
    }
}

fn phone(store: &EncryptedStore, op: &PhoneOperation) -> Value {
    let now = if matches!(op, PhoneOperation::List) {
        USED_AT + 1_000
    } else {
        NOW
    };
    store
        .secret_phone_operation(FP, Some("pair-A"), now, op, || true, || now)
        .unwrap()
}

fn approve(store: &EncryptedStore, request: Value, duration: &str) {
    assert_eq!(request["status"], "approval_required", "{request}");
    let statement = URL_SAFE_NO_PAD
        .decode(request["statement_b64url"].as_str().unwrap())
        .unwrap();
    let envelope = serde_json::to_vec(&json!({
        "v": "ck-secret-use-envelope/v1",
        "items": [{
            "request_id": request["request_id"],
            "statement_sha256": hex(&crate::store::payload_hash(&statement)),
        }],
        "decision": "allow",
        "duration": duration,
        "grant_expires_at_ms": 0,
        "device_fingerprint": FP,
        "issued_at_ms": NOW,
    }))
    .unwrap();
    let signature: Signature = approval_signer().sign(&envelope);
    assert_eq!(
        phone(
            store,
            &PhoneOperation::Approve {
                envelope,
                signature: signature.to_der().as_bytes().to_vec(),
                card_ref: None,
            },
        ),
        json!({"results":[{"request_id":request["request_id"],"outcome":"granted"}]}),
    );
}

// Deposit and approval deliberately mint random storage identities. Replace only
// those identities in the fixture store, never in the list reply. Resealing before
// approval keeps the secret usable; grants still come from signed approval.
fn fix_incarnation(
    store: &EncryptedStore,
    name: &str,
    scope: &SecretScope,
    material: &SecretMaterial,
) {
    let blob = agent_secret::seal(&store.key, INCARNATION, name, scope, material).unwrap();
    store
        .fenced_write(|tx| {
            assert_eq!(
                tx.execute(
                    "UPDATE agent_secrets SET incarnation=?1,envelope=?2 WHERE name=?3",
                    rusqlite::params![INCARNATION, blob, name],
                )?,
                1,
            );
            tx.execute(
                "UPDATE secret_deposit_tombstones SET incarnation=?1 WHERE deposit_id=?2",
                rusqlite::params![INCARNATION, ID],
            )?;
            Ok(())
        })
        .unwrap();
}

fn fix_grant_ids(store: &EncryptedStore) {
    store
        .fenced_write(|tx| {
            assert_eq!(
                tx.execute("UPDATE secret_flow_grants SET grant_id=?1", [FLOW_GRANT])?,
                1,
            );
            tx.execute("UPDATE secret_grants SET grant_id=?1", [AGENT_GRANT])?;
            Ok(())
        })
        .unwrap();
}

fn case(label: &str, login: bool, used: bool, agent: bool) -> Value {
    let (_root, store, sender) = setup("secret-list-flow-vector");
    let (name, scope, material) = if login {
        (
            "login",
            SecretScope::SiteLogin {
                origin: "https://x.test".into(),
            },
            SecretMaterial::SiteLogin {
                username: Secret::new("vector-user".into()),
                password: Secret::new("vector-password".into()),
                otpauth: None,
            },
        )
    } else {
        ("key", scope(), key())
    };
    let deposited = phone(
        &store,
        &PhoneOperation::Deposit(deposit(
            &store,
            &sender,
            name,
            ID,
            scope.clone(),
            material.clone(),
        )),
    );
    assert_eq!(deposited["status"], "stored", "{deposited}");
    fix_incarnation(&store, name, &scope, &material);

    let install = SecretFlowApproval {
        name: name.into(),
        flow: identity(),
        target: target(login),
        methods: (!login).then(|| vec!["GET".into()]),
    };
    let requested = store
        .secret_request_flow_approval(&install, || NOW)
        .unwrap();
    approve(&store, requested.reply, "version");
    if agent {
        let requested = store
            .secret_use(
                &SecretUse {
                    name: name.into(),
                    sender: SecretSender::Aft,
                    scope: AskingScope {
                        owner: "reserved:prefrontal-core".into(),
                        kind: "head".into(),
                        scope_ref: "H".into(),
                        epoch: 7,
                    },
                    worker_parent: None,
                    coverage: "scope".into(),
                    agent_id: Some("agent-A".into()),
                    target: target(login),
                },
                || NOW,
            )
            .unwrap();
        approve(&store, requested.reply, "permanent");
    }
    fix_grant_ids(&store);
    if used {
        let outcome = store
            .secret_flow_use(
                &SecretFlowUse {
                    name: name.into(),
                    flow: identity(),
                    target: target(login),
                    method: Some("GET".into()),
                },
                || USED_AT,
            )
            .unwrap();
        assert_eq!(outcome.reply["status"], "released", "{}", outcome.reply);
        assert!(
            outcome.last_use.is_none(),
            "first release commits synchronously"
        );
    }
    let reply = phone(&store, &PhoneOperation::List);
    let secrets = reply["secrets"].as_array().unwrap();
    assert_eq!(secrets.len(), 1);
    let secret = &secrets[0];
    assert_eq!(
        secret["grants"].as_array().unwrap().len(),
        usize::from(agent)
    );
    let grants = secret["flow_grants"].as_array().unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0]["grant_id"], FLOW_GRANT);
    assert_eq!(
        grants[0]["flow"],
        json!({"flow_id":"daily-fetch","version":7,"install_id":"install-A"}),
    );
    assert_eq!(grants[0]["duration"], "version");
    assert_eq!(grants[0].get("methods").is_some(), !login);
    if !login {
        assert_eq!(grants[0]["methods"], json!(["GET"]));
    }
    assert_eq!(
        grants[0].get("last_use_ms"),
        used.then_some(&json!(USED_AT))
    );
    assert_eq!(store.verify_audit_chain().unwrap(), None);

    // The phone route serializes every successful reply inside a `result` envelope.
    let bytes = serde_json::to_vec(&json!({"result": reply})).unwrap();
    json!({
        "case": label,
        "request": {"method": "secret.list", "params": {}},
        "reply_b64url": URL_SAFE_NO_PAD.encode(&bytes),
        "reply_sha256": hex(&crate::store::payload_hash(&bytes)),
        "reply": serde_json::from_slice::<Value>(&bytes).unwrap(),
    })
}

#[test]
fn secret_list_flow_ckios_vectors_are_emitted_by_vault_code_and_pinned() {
    let emitted = serde_json::to_vec_pretty(&json!({
        "v": "ck-secret-list-flow-vectors/v1",
        "cases": [
            case("api_key_flow_grant", false, false, false),
            case("api_key_flow_grant_used", false, true, false),
            case("api_key_agent_and_flow", false, false, true),
            case("site_login_flow_grant", true, false, false),
        ],
    }))
    .unwrap();
    let pinned = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/secret-list-flow-v1.json");
    if std::env::var("CK_EMIT_SECRET_VECTORS").as_deref() == Ok("1") {
        std::fs::write(&pinned, &emitted).unwrap();
        println!("emitted four CKIOS secret.list flow vectors");
    } else {
        assert_eq!(
            emitted,
            std::fs::read(&pinned).expect("pinned CKIOS secret.list flow vectors"),
            "vault-emitted CKIOS secret.list flow vector bytes changed",
        );
    }
}
