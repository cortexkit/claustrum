//! Producer-pinned fleet samples, using synthetic keys and the real store and adapter.
#![forbid(unsafe_code)]

#[path = "federation/support.rs"]
mod support;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use claustrum_module_probe::fleet_ops::{self, Answer};
use credentials_core::audit::{AuditCtx, AuditOp};
use credentials_core::fleet::{FleetPeer, FleetRemoval, FleetWrap, WRAP_DOMAIN, WRAP_KEY_ID};
use credentials_core::record::{CredentialKind, VaultRecord};
use credentials_core::{kem, EncryptedStore};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use subc_protocol::Principal;
use support::{HomeStore, Reply, SharedCallosumStandIn, VaultFixture, TARGET_MODULE};

fn member(n: usize) -> String {
    format!("fed-computer:{n:032x}")
}

fn encode(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode(value: &Value) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(value.as_str().unwrap()).unwrap()
}

fn install(store: &EncryptedStore, n: usize, scalar: u8) -> String {
    let pem = kem::pem_from_scalar(&[scalar; 32]);
    store
        .create_audited(
            WRAP_KEY_ID,
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
        .set_federation_self_member_audited(&member(n), AuditCtx::admin(AuditOp::FederationSelfSet))
        .unwrap();
    pem
}

fn public(pem: &str) -> [u8; 32] {
    kem::public_half(pem).unwrap().0.try_into().unwrap()
}

fn info(from: usize, to: usize) -> Vec<u8> {
    serde_json::to_vec(&json!({"from": member(from), "to": member(to), "v": WRAP_DOMAIN})).unwrap()
}

fn seal_wrap(
    pem: &str,
    recipient: &[u8],
    from: usize,
    to: usize,
    body: &Value,
    ikm: u8,
) -> FleetWrap {
    let (enc, ct) = kem::seal_auth_with_ephemeral_ikm(
        pem,
        recipient,
        &serde_json::to_vec(body).unwrap(),
        &info(from, to),
        b"",
        [ikm; 32],
    )
    .unwrap();
    FleetWrap {
        ct: encode(ct),
        enc: encode(enc),
        from: member(from),
        to: member(to),
        v: WRAP_DOMAIN.into(),
    }
}

fn open_wrap(pem: &str, sender: &[u8], wrap: &FleetWrap) -> Value {
    let plaintext = kem::open_auth(
        pem,
        sender,
        &URL_SAFE_NO_PAD.decode(&wrap.enc).unwrap(),
        &URL_SAFE_NO_PAD.decode(&wrap.ct).unwrap(),
        &serde_json::to_vec(&json!({"from":wrap.from,"to":wrap.to,"v":WRAP_DOMAIN})).unwrap(),
        b"",
    )
    .unwrap();
    let body: Value = serde_json::from_slice(&plaintext).unwrap();
    assert_eq!(
        plaintext,
        serde_json::to_vec(&body).unwrap(),
        "canonical wrap plaintext"
    );
    body
}

fn key(epoch: u32, byte: u8) -> Value {
    json!({"epoch":epoch,"key":encode([byte;32]),"members":[member(1),member(2)],"minter":member(1)})
}

fn wrap_sample(name: &str, wrap: &FleetWrap, plaintext: &Value, ikm: u8) -> Value {
    json!({"name":name,"wrap":wrap,"ephemeral_ikm":encode([ikm;32]),
        "info_utf8":String::from_utf8(info(1,2)).unwrap(),
        "plaintext_utf8":serde_json::to_string(plaintext).unwrap()})
}

async fn call(
    store: &Arc<EncryptedStore>,
    fixture: Option<&VaultFixture>,
    method: &str,
    params: Value,
) -> Value {
    match fleet_ops::serve(
        Arc::clone(store),
        fixture.map(|f| &f.outbound),
        Some(&Principal::Reserved {
            module_id: "entorhinal".into(),
        }),
        method,
        &params,
    )
    .await
    {
        Answer::Reply(reply) => reply,
        // The adapter delegates malformed requests to the transport error path.
        // Keep that distinction explicit rather than inventing an in-result refusal.
        Answer::InvalidParams => json!({"transport_error": subc_protocol::ErrorBody::new(
            "invalid_params", "params not decodable: invalid fleet parameters"
        )}),
    }
}

fn refusal(
    cases: &mut Vec<Value>,
    code: &str,
    class: &str,
    method: &str,
    params: Value,
    reply: Value,
) {
    assert_eq!(reply, json!({"error":{"code":code,"class":class}}));
    cases.push(json!({"method":method,"params":params,"response":reply}));
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fleet-epoch-v1/cases.json")
}

#[tokio::test]
async fn fleet_epoch_samples_are_producer_generated_and_pinned() {
    let root = support::temp_root("fleet-vectors");
    let callosum = SharedCallosumStandIn::start(root.path()).await;
    let a = VaultFixture::new(root.path(), "a", &format!("{:032x}", 1), &callosum);
    let b = VaultFixture::new(root.path(), "b", &format!("{:032x}", 2), &callosum);
    let a_store = HomeStore::open(&a.data_dir).store;
    let b_store = HomeStore::open(&b.data_dir).store;
    let a_pem = install(&a_store, 1, 0x11);
    let b_pem = install(&b_store, 2, 0x22);
    let a_public = public(&a_pem);
    let b_public = public(&b_pem);
    let b_peer = FleetPeer::new(member(2), b_public).unwrap();
    let peers: Vec<Value> = [(1, a_public), (2, b_public)]
        .into_iter()
        .map(|(n, public)| {
            let hex: String = public.iter().map(|byte| format!("{byte:02x}")).collect();
            json!({"fingerprint":format!("{n:032x}"),"class":"computer","key_record":{"keys":{
            "fleet_epoch_wrap_x25519":{"pub":hex,"version":"1"}}}})
        })
        .collect();
    callosum.answer(
        TARGET_MODULE,
        "callosum.peer_keys_read",
        Reply::Ok(json!({"peers":peers})),
    );
    let mut statuses = vec![
        json!({"name":"empty","response":call(&a_store,None,"fleet.epoch_status",json!({})).await}),
    ];
    let mut refusals = Vec::new();
    let seal_params =
        json!({"aad":encode(b"record:identity:7"),"plaintext":encode(b"fleet sample plaintext")});
    for (code, class, method, params, route) in [
        (
            "fleet_epoch_unavailable",
            "transient",
            "fleet.epoch_seal",
            seal_params.clone(),
            false,
        ),
        (
            "fleet_peer_keys_unavailable",
            "transient",
            "fleet.epoch_mint",
            json!({"members":[member(1)]}),
            false,
        ),
        (
            "fleet_members_mismatch",
            "permanent",
            "fleet.epoch_mint",
            json!({"members":[]}),
            true,
        ),
        (
            "fleet_epoch_not_pending",
            "permanent",
            "fleet.epoch_commit",
            json!({"epoch":1,"mint_id":encode([0x55;16])}),
            false,
        ),
        (
            "fleet_epoch_open_failed",
            "permanent",
            "fleet.epoch_open",
            json!({"epoch":1,"nonce":encode([0;24]),"ciphertext":encode([0;16]),"aad":""}),
            false,
        ),
        (
            "fleet_epoch_capacity",
            "permanent",
            "fleet.epoch_mint",
            json!({"members":(1..=65).map(member).collect::<Vec<_>>()}),
            true,
        ),
    ] {
        let reply = call(&a_store, route.then_some(&a), method, params.clone()).await;
        refusal(&mut refusals, code, class, method, params, reply);
    }
    let not_found = match fleet_ops::serve(
        Arc::clone(&a_store),
        None,
        Some(&Principal::Reserved {
            module_id: "other".into(),
        }),
        "fleet.epoch_status",
        &json!({}),
    )
    .await
    {
        Answer::Reply(reply) => reply,
        Answer::InvalidParams => panic!("identity must be checked first"),
    };
    refusal(
        &mut refusals,
        "not_found",
        "permanent",
        "fleet.epoch_status",
        json!({}),
        not_found,
    );
    let invalid = call(
        &a_store,
        None,
        "fleet.epoch_status",
        json!({"unknown":true}),
    )
    .await;
    assert_eq!(invalid["transport_error"]["code"], "invalid_params");
    refusals
        .push(json!({"method":"fleet.epoch_status","params":{"unknown":true},"response":invalid}));

    // Observe the real rotation producer before substituting its random epoch key
    // with a documented synthetic key and deterministically encapsulating it.
    let minted = a_store
        .fleet_epoch_mint(&[member(1), member(2)], std::slice::from_ref(&b_peer))
        .unwrap();
    assert_eq!(minted.wraps.len(), 1);
    assert_eq!(minted.wraps[0].member_id, member(2));
    let mut rotation_body = open_wrap(&b_pem, &a_public, &minted.wraps[0].wrap);
    assert_eq!(decode(&rotation_body["keys"][0]["key"]).len(), 32);
    rotation_body["keys"][0]["key"] = json!(encode([0x31; 32]));
    assert_eq!(
        rotation_body,
        json!({"keys":[key(1,0x31)],"kind":"rotation","v":WRAP_DOMAIN})
    );
    a_store
        .fleet_epoch_discard(minted.epoch, &minted.mint_id)
        .unwrap();
    let rotation = seal_wrap(&a_pem, &b_public, 1, 2, &rotation_body, 0x41);
    let import_params = json!({"wrap":rotation});
    let imported = call(
        &b_store,
        Some(&b),
        "fleet.epoch_import",
        import_params.clone(),
    )
    .await;
    assert_eq!(imported, json!({"epochs":[1],"already_held":false}));
    let mut bad_wrap = serde_json::to_value(&rotation).unwrap();
    let mut bad_ct = decode(&bad_wrap["ct"]);
    bad_ct[0] ^= 1;
    bad_wrap["ct"] = json!(encode(bad_ct));
    let bad_params = json!({"wrap":bad_wrap});
    let bad_reply = call(&b_store, Some(&b), "fleet.epoch_import", bad_params.clone()).await;
    refusal(
        &mut refusals,
        "fleet_wrap_refused",
        "permanent",
        "fleet.epoch_import",
        bad_params,
        bad_reply,
    );

    let first_body = json!({"keys":[key(1,0x31)],"kind":"join","v":WRAP_DOMAIN});
    let seed = seal_wrap(&b_pem, &a_public, 2, 1, &first_body, 0x71);
    a_store
        .fleet_epoch_import(&seed, std::slice::from_ref(&b_peer))
        .unwrap();
    statuses.push(json!({"name":"one_held","response":call(&a_store,None,"fleet.epoch_status",json!({})).await}));
    let produced_join = a_store
        .fleet_epoch_wrap_for(&member(2), std::slice::from_ref(&b_peer))
        .unwrap();
    let join_body = open_wrap(&b_pem, &a_public, &produced_join);
    assert_eq!(join_body, first_body);
    let join = seal_wrap(&a_pem, &b_public, 1, 2, &join_body, 0x42);
    let joined = call(
        &b_store,
        Some(&b),
        "fleet.epoch_import",
        json!({"wrap":join}),
    )
    .await;
    assert_eq!(joined, json!({"epochs":[],"already_held":true}));

    // Production chooses the nonce. Emission captures it once; ordinary runs
    // replay the committed ciphertext and independently exercise a fresh seal.
    let fresh = call(&a_store, None, "fleet.epoch_seal", seal_params.clone()).await;
    let emitting = std::env::var_os("CK_EMIT_FLEET_VECTORS").is_some();
    let sealed = if emitting {
        fresh.clone()
    } else {
        let pinned: Value =
            serde_json::from_slice(&std::fs::read(fixture_path()).expect("generate fleet samples"))
                .unwrap();
        pinned["seal_open"]["response"].clone()
    };
    assert_eq!(decode(&sealed["nonce"]).len(), 24);
    assert_eq!(
        decode(&sealed["ciphertext"]).len(),
        decode(&seal_params["plaintext"]).len() + 16
    );
    let open_params = json!({"epoch":sealed["epoch"],"nonce":sealed["nonce"],
        "ciphertext":sealed["ciphertext"],"aad":seal_params["aad"]});
    let opened = call(&a_store, None, "fleet.epoch_open", open_params.clone()).await;
    assert_eq!(opened, json!({"plaintext":seal_params["plaintext"]}));
    assert_eq!(
        call(&b_store, None, "fleet.epoch_open", open_params.clone()).await,
        opened
    );
    let fresh_open = json!({"epoch":fresh["epoch"],"nonce":fresh["nonce"],
        "ciphertext":fresh["ciphertext"],"aad":seal_params["aad"]});
    assert_eq!(
        call(&a_store, None, "fleet.epoch_open", fresh_open).await,
        opened
    );
    let mut stable_fresh = fresh.clone();
    let mut stable_sample = sealed.clone();
    for field in ["nonce", "ciphertext"] {
        stable_fresh.as_object_mut().unwrap().remove(field);
        stable_sample.as_object_mut().unwrap().remove(field);
        if !emitting {
            assert_ne!(fresh[field], sealed[field]);
        }
    }
    assert_eq!(
        stable_fresh, stable_sample,
        "only nonce and ciphertext may vary"
    );
    let seal_open = json!({"epoch_key":encode([0x31;32]),"request":seal_params,"response":sealed,
        "record_aad_utf8":serde_json::to_string(&json!({"aad":seal_params["aad"],"epoch":1,
            "v":credentials_core::fleet::AAD_DOMAIN})).unwrap(),
        "open_request":open_params,"open_response":opened});

    let multi_body = json!({"keys":[key(1,0x31),key(2,0x32)],"kind":"join","v":WRAP_DOMAIN});
    let seed = seal_wrap(&b_pem, &a_public, 2, 1, &multi_body, 0x72);
    a_store
        .fleet_epoch_import(&seed, std::slice::from_ref(&b_peer))
        .unwrap();
    let produced_multi = a_store
        .fleet_epoch_wrap_for(&member(2), std::slice::from_ref(&b_peer))
        .unwrap();
    let multi_plaintext = open_wrap(&b_pem, &a_public, &produced_multi);
    assert_eq!(multi_plaintext, multi_body);
    let multi = seal_wrap(&a_pem, &b_public, 1, 2, &multi_plaintext, 0x43);
    let multi_imported = call(
        &b_store,
        Some(&b),
        "fleet.epoch_import",
        json!({"wrap":multi}),
    )
    .await;
    assert_eq!(multi_imported, json!({"epochs":[2],"already_held":false}));
    statuses.push(json!({"name":"two_held","response":call(&a_store,None,"fleet.epoch_status",json!({})).await}));

    let pending = a_store
        .fleet_epoch_mint(&[member(1), member(2)], std::slice::from_ref(&b_peer))
        .unwrap();
    assert_eq!(pending.epoch, 3);
    let mut status = call(&a_store, None, "fleet.epoch_status", json!({})).await;
    assert_eq!(status["pending"]["mint_id"], pending.mint_id);
    assert_eq!(decode(&status["pending"]["mint_id"]).len(), 16);
    status["pending"]["mint_id"] = json!(encode([0x55; 16]));
    statuses.push(json!({"name":"pending","response":status}));
    let params = json!({"members":[member(1),member(2)]});
    let reply = call(&a_store, Some(&a), "fleet.epoch_mint", params.clone()).await;
    refusal(
        &mut refusals,
        "fleet_epoch_pending",
        "transient",
        "fleet.epoch_mint",
        params,
        reply,
    );
    a_store
        .fleet_epoch_discard(pending.epoch, &pending.mint_id)
        .unwrap();
    a_store
        .fleet_record_removals(
            &[FleetRemoval {
                member_id: member(2),
                removal_id: "fixture:permanent:1".into(),
            }],
            1,
        )
        .unwrap();
    statuses.push(json!({"name":"blocked","response":call(&a_store,None,"fleet.epoch_status",json!({})).await}));

    // Disk faults exercise the adapter's real opaque corruption and storage errors.
    let conn = rusqlite::Connection::open(b.store_path()).unwrap();
    conn.execute("UPDATE fleet_epochs SET key = X'00' WHERE epoch = 2", [])
        .unwrap();
    let params = json!({"aad":"","plaintext":""});
    let reply = call(&b_store, None, "fleet.epoch_seal", params.clone()).await;
    refusal(
        &mut refusals,
        "corrupt",
        "permanent",
        "fleet.epoch_seal",
        params,
        reply,
    );
    conn.execute("DROP TABLE fleet_removals", []).unwrap();
    let reply = call(&b_store, None, "fleet.epoch_status", json!({})).await;
    refusal(
        &mut refusals,
        "store_error",
        "transient",
        "fleet.epoch_status",
        json!({}),
        reply,
    );
    assert_eq!(refusals.len(), 12);

    let samples = json!({"version":"fleet-epoch-vectors-v1",
        "fixture_keys":{"sender_private_key":encode([0x11;32]),"sender_public_key":encode(a_public),
            "recipient_private_key":encode([0x22;32]),"recipient_public_key":encode(b_public)},
        "seal_open":seal_open,
        "wraps":[wrap_sample("rotation",&rotation,&rotation_body,0x41),
            wrap_sample("one-key-join",&join,&join_body,0x42),
            wrap_sample("multi-key-join",&multi,&multi_plaintext,0x43)],
        "import_responses":{"rotation":imported,"one_key_join":joined,"multi_key_join":multi_imported},
        "refusals":refusals,"statuses":statuses});
    let mut generated = serde_json::to_vec_pretty(&samples).unwrap();
    generated.push(b'\n');
    if emitting {
        std::fs::write(fixture_path(), &generated).unwrap();
        println!("emitted seal/open, 3 auth wraps, 12 refusal codes and 5 status shapes");
    }
    assert_eq!(
        std::fs::read(fixture_path()).unwrap(),
        generated,
        "fleet producer sample bytes changed"
    );
}
