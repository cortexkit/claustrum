//! Golden federation messages produced by real home and transfer operations.

use std::sync::Arc;

use base64::Engine as _;
use claustrum_module_probe::federation::ingress::{
    OP_REMOTE_TOKEN, OP_REPORT_AUTH_FAILURE, OP_TRANSFER_DELIVER, REMOTE_TOKEN_INFO,
};
use claustrum_module_probe::federation::transfer::{TransferAad, Transfers, TRANSFER_INFO};
use claustrum_module_probe::federation::{HomeAnswer, HomeVault};
use credentials_core::audit::{AuditCtx, AuditOp};
use credentials_core::federation::{MemberGrantOperation, MemberGrantSelector, VAULT_TRANSFER_ID};
use credentials_core::oauth::OAuthCredential;
use credentials_core::record::{CredentialKind, RecordIdentity, VaultRecord};
use serde_json::{json, Value};

use crate::support::{HomeStore, TwoVaults};

fn fixture() -> Value {
    serde_json::from_str(include_str!("federation_wire_contract.json")).unwrap()
}

fn reply(answer: HomeAnswer) -> Value {
    match answer {
        HomeAnswer::Reply(body) => json!({"result": body}),
        HomeAnswer::InvalidParams(detail) => panic!("unexpected invalid_params: {detail}"),
    }
}

fn install(store: &credentials_core::store::EncryptedStore, scalar: u8, member: &str) -> String {
    let pem = credentials_core::kem::pem_from_scalar(&[scalar; 32]);
    store
        .create_audited(
            VAULT_TRANSFER_ID,
            &VaultRecord::new_static(
                CredentialKind::KemKey,
                "operator",
                pem.as_bytes().to_vec(),
                None,
            ),
            AuditCtx::admin(AuditOp::Put),
        )
        .unwrap();
    store
        .set_federation_self_member_audited(member, AuditCtx::admin(AuditOp::FederationSelfSet))
        .unwrap();
    pem
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn open(sender: &str, recipient: &str, sealed: &Value, info: &[u8], aad: &str) -> Value {
    let b64 = base64::engine::general_purpose::STANDARD;
    let public = credentials_core::kem::public_half(sender).unwrap().0;
    let bytes = credentials_core::kem::open_auth(
        recipient,
        &public,
        &b64.decode(sealed["result"]["enc"].as_str().unwrap())
            .unwrap(),
        &b64.decode(sealed["result"]["ciphertext"].as_str().unwrap())
            .unwrap(),
        info,
        aad.as_bytes(),
    )
    .expect("a real producer envelope must open before its plaintext is compared");
    serde_json::from_slice(&bytes).unwrap()
}

fn normalize_durations(mut token: Value) -> Value {
    // Only clock-dependent values are normalized, after checking their bounds.
    // Field names and presence still come from the home serializer.
    for (field, low, high) in [
        ("expires_in_ms", 3_500_000, 3_600_000),
        ("recheck_in_ms", 50_000, 60_000),
    ] {
        if let Some(value) = token.get_mut(field) {
            let duration = value.as_i64().expect("duration is integer milliseconds");
            assert!((low..=high).contains(&duration), "{field}: {duration}");
            *value = json!(high);
        }
    }
    token
}

#[tokio::test]
async fn federation_token_and_report_fixtures_match_the_home_producer() {
    let root = crate::support::temp_root("federation-wire-producer");
    let vaults = TwoVaults::new(&root).await;
    let home_store = HomeStore::open(&vaults.a.data_dir);
    let requester_store = HomeStore::open(&vaults.b.data_dir);
    let home_pem = install(&home_store.store, 1, vaults.home_member());
    let requester_pem = install(&requester_store.store, 2, vaults.requester_member());
    let (requester_public, key_id) = credentials_core::kem::public_half(&requester_pem).unwrap();
    vaults
        .callosum
        .set_pairing(vaults.requester_member(), Some("fixture-pair"));
    vaults
        .callosum
        .announce_peer_key(vaults.requester_member(), &hex(&requester_public));
    let home = HomeVault::new(Arc::clone(&home_store.engine));
    assert!(home.attach_outbound(vaults.a.outbound.clone()));
    let mut cases = Vec::new();
    for adapter in ["anthropic", "antigravity"] {
        let id = format!("oauth:{adapter}:fixture");
        let access = format!("fixture-{adapter}-access-not-a-secret");
        let refresh = if adapter == "antigravity" {
            "fixture-refresh|fixture-project|fixture-managed-project"
        } else {
            "fixture-refresh"
        };
        let mut record = VaultRecord::new_oauth(
            "operator",
            adapter,
            OAuthCredential {
                access_token: access.clone().into(),
                refresh_token: refresh.to_string().into(),
                expires_at_ms: (adapter == "anthropic")
                    .then(|| crate::support::wall_ms() + 3_600_000),
                token_url: "https://fixture.invalid/token".into(),
                client_id: None,
                client_secret: None,
                scopes: vec![],
            },
            access.into_bytes(),
        );
        record.identity = RecordIdentity {
            account_id: Some(format!("fixture-{adapter}-account")),
            email: Some("fixture@example.invalid".into()),
            org_name: Some("Fixture Team".into()),
        };
        home_store.store.create(&id, &record).unwrap();
        home_store
            .store
            .set_categories_audited(
                &id,
                credentials_core::store::SetCategoryMode::Set,
                &["llm-provider".to_string()],
                AuditCtx::admin(AuditOp::SetCategory),
            )
            .unwrap();
        home_store
            .store
            .create_member_grant_audited(
                vaults.requester_member(),
                MemberGrantOperation::RemoteRead,
                &MemberGrantSelector::Exact(id.clone()),
                "fixture-pair",
            )
            .unwrap();
        let aad = format!(
            r#"{{"credential_id":"{id}","requester":"{}","home":"{}","nonce":"00112233445566778899aabbccddeeff","recipient_key_id":"{key_id}"}}"#,
            vaults.requester_member(),
            vaults.home_member()
        );
        let request =
            json!({"method": OP_REMOTE_TOKEN, "params": {"aad": aad, "min_ttl_ms": 62500}});
        let sealed = reply(
            home.serve(
                vaults.requester_member(),
                OP_REMOTE_TOKEN,
                &request["params"],
            )
            .await,
        );
        let plaintext = normalize_durations(open(
            &home_pem,
            &requester_pem,
            &sealed,
            REMOTE_TOKEN_INFO,
            &aad,
        ));
        assert_eq!(
            plaintext.get("expires_in_ms").is_some(),
            adapter == "anthropic"
        );
        assert_eq!(
            sealed["result"]
                .as_object()
                .unwrap()
                .keys()
                .collect::<Vec<_>>(),
            ["ciphertext", "enc"]
        );
        let report_request = json!({"method": OP_REPORT_AUTH_FAILURE, "params": {
            "credential_id": id, "record_version": 1, "provider_status": 401, "reporter_source": "direct"
        }});
        let report = reply(
            home.serve(
                vaults.requester_member(),
                OP_REPORT_AUTH_FAILURE,
                &report_request["params"],
            )
            .await,
        );
        let cooldown_sealed = reply(
            home.serve(
                vaults.requester_member(),
                OP_REMOTE_TOKEN,
                &request["params"],
            )
            .await,
        );
        let cooldown = normalize_durations(open(
            &home_pem,
            &requester_pem,
            &cooldown_sealed,
            REMOTE_TOKEN_INFO,
            &aad,
        ));
        assert_eq!(cooldown["recheck_in_ms"], 60000);
        let mut bad_report = report_request["params"].clone();
        bad_report["provider_status"] = json!(500);
        let refused_report = reply(
            home.serve(
                vaults.requester_member(),
                OP_REPORT_AUTH_FAILURE,
                &bad_report,
            )
            .await,
        );
        cases.push(json!({"adapter": adapter, "request": request, "plaintext": plaintext, "cooldown_plaintext": cooldown,
            "report_request": report_request, "report": report, "refused_report": refused_report}));
        // Random encapsulations are opened, not compared. The committed sample below is
        // a real home reply used by the forced-open-row test with these synthetic keys.
        if adapter == "anthropic" {
            println!("SEALED_SAMPLE={sealed}");
        }
    }
    let missing = reply(home.serve(vaults.requester_member(), OP_REMOTE_TOKEN,
        &json!({"aad": cases[0]["request"]["params"]["aad"].as_str().unwrap().replace("oauth:anthropic:fixture", "oauth:anthropic:missing")})).await);
    let actual = json!({"cases": cases, "not_found": missing});
    println!("HOME_FIXTURE={actual}");
    assert_eq!(actual, fixture()["home"], "home producer wire drift");
    let sample = &fixture()["sealed_sample"];
    assert_eq!(
        normalize_durations(open(
            &home_pem,
            &requester_pem,
            sample,
            REMOTE_TOKEN_INFO,
            actual["cases"][0]["request"]["params"]["aad"]
                .as_str()
                .unwrap()
        )),
        actual["cases"][0]["plaintext"]
    );
}

#[tokio::test]
async fn federation_transfer_fixture_matches_the_sender_and_receiver() {
    use claustrum_module_probe::federation::transfer::{DeliveryReply, TransferRefusal};
    use credentials_core::federation::IncomingTransferState;
    let root = crate::support::temp_root("transfer-wire-producer");
    let vaults = TwoVaults::new(&root).await;
    let sender = HomeStore::open(&vaults.a.data_dir);
    let receiver = HomeStore::open(&vaults.b.data_dir);
    let sender_pem = install(&sender.store, 1, vaults.home_member());
    let receiver_pem = install(&receiver.store, 2, vaults.requester_member());
    for (member, pem) in [
        (vaults.home_member(), &sender_pem),
        (vaults.requester_member(), &receiver_pem),
    ] {
        vaults.callosum.set_pairing(member, Some("fixture-pair"));
        vaults.callosum.announce_peer_key(
            member,
            &hex(&credentials_core::kem::public_half(pem).unwrap().0),
        );
    }
    receiver
        .store
        .create_member_grant_audited(
            vaults.home_member(),
            MemberGrantOperation::TransferDeliver,
            &MemberGrantSelector::None,
            "fixture-pair",
        )
        .unwrap();
    let id = "apikey:fixture";
    sender
        .store
        .create(
            id,
            &VaultRecord::new_static(
                CredentialKind::ApiKey,
                "operator",
                b"fixture-api-key-not-a-secret".to_vec(),
                None,
            ),
        )
        .unwrap();
    sender
        .store
        .set_categories_audited(
            id,
            credentials_core::store::SetCategoryMode::Set,
            &["llm-provider".to_string()],
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .unwrap();
    let transfers = Transfers::new(Arc::clone(&sender.store));
    assert!(transfers.attach_outbound(vaults.a.outbound.clone()));
    let plan = transfers
        .send_prepare(id, vaults.requester_member())
        .await
        .unwrap();
    let row = transfers.send_commit(&plan).unwrap();
    let aad = String::from_utf8(row.sealed.aad.clone()).unwrap();
    let parsed: TransferAad = serde_json::from_str(&aad).unwrap();
    assert_eq!(
        serde_json::to_string(&parsed).unwrap(),
        aad,
        "the sender's exact serialization order is authenticated"
    );
    assert_eq!(parsed.transfer_id.len(), 32);
    assert!(parsed
        .transfer_id
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    let b64 = base64::engine::general_purpose::STANDARD;
    vaults.callosum.answer(
        crate::support::TARGET_MODULE,
        OP_TRANSFER_DELIVER,
        crate::support::Reply::Ok(json!({"state": "pending"})),
    );
    let sent = transfers.send_deliver(&row, &plan).await;
    assert_eq!(sent.reply.code(), "pending");
    let params = vaults
        .callosum
        .ledger()
        .into_iter()
        .find_map(|entry| match entry {
            crate::support::Ledger::Request { method, params, .. }
                if method == OP_TRANSFER_DELIVER =>
            {
                Some(params)
            }
            _ => None,
        })
        .expect("the sender dispatched delivery params");
    let plaintext = open(
        &sender_pem,
        &receiver_pem,
        &json!({"result": params}),
        TRANSFER_INFO,
        &aad,
    );
    let home = HomeVault::new(Arc::clone(&receiver.engine));
    assert!(home.attach_outbound(vaults.b.outbound.clone()));
    let pending = reply(
        home.serve(vaults.home_member(), OP_TRANSFER_DELIVER, &params)
            .await,
    );
    let receiver_transfers = Transfers::new(Arc::clone(&receiver.store));
    assert!(receiver_transfers.attach_outbound(vaults.b.outbound.clone()));
    receiver_transfers
        .reject(&row.transfer_id, vaults.home_member())
        .unwrap();
    let rejected = reply(
        home.serve(vaults.home_member(), OP_TRANSFER_DELIVER, &params)
            .await,
    );
    let next_plan = transfers
        .send_prepare(id, vaults.requester_member())
        .await
        .unwrap();
    let next = transfers.send_commit(&next_plan).unwrap();
    let next_params = json!({"enc": b64.encode(&next.sealed.enc), "ciphertext": b64.encode(&next.sealed.ciphertext),
        "aad": String::from_utf8(next.sealed.aad).unwrap()});
    let _ = reply(
        home.serve(vaults.home_member(), OP_TRANSFER_DELIVER, &next_params)
            .await,
    );
    receiver_transfers
        .accept(&next.transfer_id, vaults.home_member(), false)
        .await
        .unwrap();
    let accepted = reply(
        home.serve(vaults.home_member(), OP_TRANSFER_DELIVER, &next_params)
            .await,
    );
    let stable_aad = aad.replace(&parsed.transfer_id, "00112233445566778899aabbccddeeff");
    let mut outcomes = vec![];
    for state in [
        IncomingTransferState::Pending,
        IncomingTransferState::Accepted,
        IncomingTransferState::Rejected,
    ] {
        let outcome = DeliveryReply::State(state);
        outcomes.push(json!({"code": outcome.code(), "keep_outgoing": outcome.keeps_row()}));
    }
    let mut errors = vec![];
    for (code, class) in [
        ("transfer_queue_full", "transient"),
        ("callosum_unavailable", "transient"),
        ("home_unavailable", "transient"),
        ("home_unreachable", "transient"),
        ("transfer_expired", "permanent"),
        ("remote_seal_invalid", "permanent"),
        ("transfer_conflict", "permanent"),
        ("transfer_too_large", "permanent"),
        ("transfer_body_invalid", "permanent"),
        ("federation_setup_invalid", "permanent"),
        ("not_found", "permanent"),
    ] {
        let outcome = DeliveryReply::Refused {
            code: code.into(),
            class: class.into(),
        };
        let refusal = TransferRefusal {
            code,
            class,
            remedy_member: None,
            reason: None,
        };
        errors.push(json!({"reply": {"result": {"error": refusal.body()}}, "keep_outgoing": outcome.keeps_row()}));
    }
    let actual = json!({"method": OP_TRANSFER_DELIVER, "aad": stable_aad, "param_fields": params.as_object().unwrap().keys().collect::<Vec<_>>(),
        "plaintext": plaintext, "pending": pending, "accepted": accepted, "rejected": rejected, "sender_actions": outcomes, "errors": errors});
    println!("TRANSFER_FIXTURE={actual}");
    assert_eq!(
        actual,
        fixture()["transfer"],
        "transfer producer wire drift"
    );
}
