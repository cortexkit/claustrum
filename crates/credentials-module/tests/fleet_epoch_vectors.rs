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
    call_as(store, fixture, "entorhinal", method, params).await
}

async fn call_as(
    store: &Arc<EncryptedStore>,
    fixture: Option<&VaultFixture>,
    module: &str,
    method: &str,
    params: Value,
) -> Value {
    match fleet_ops::serve(
        Arc::clone(store),
        fixture.map(|f| &f.outbound),
        Some(&Principal::Reserved {
            module_id: module.into(),
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

const PREFRONTAL_README: &str = r#"# Prefrontal fleet epoch v1 samples

All keys, plaintext and caller AAD in this folder are synthetic public test
material. `cases.json` is generated by the real encrypted store and fleet adapter
in `tests/fleet_epoch_vectors.rs`. The original `fleet-epoch-vectors-v1` samples
are separate and unchanged.

## Contents

- `epoch_key` is the synthetic epoch-1 key (`31` repeated 32 times in hex),
  installed through the authenticated fleet import path, not raw SQL.
- `seal_open` records a Prefrontal single seal, its inputs, exact AEAD AAD bytes
  in `record_aad_utf8`, and the successful single open on two stores sharing the
  epoch key. `cross_domain_open` reuses those exact epoch, nonce, ciphertext and
  caller AAD bytes as Entorhinal and pins the open refusal.
- `batch` records two Prefrontal seal inputs and outputs, each with a fresh nonce
  under the same epoch and its exact AEAD AAD bytes. Each output opens through
  single open. Its two-item open batch contains the first Prefrontal ciphertext
  followed by `entorhinal_seal.response`, which refuses in Prefrontal's domain.
- `entorhinal_seal` records the single Entorhinal seal used in the mixed batch.
  Both domains use the same epoch key. No domain is accepted in wire parameters.

Bytes use canonical unpadded base64url. `record_aad_utf8` strings contain exact
UTF-8 AEAD associated-data bytes with no trailing newline. To independently
recompute a ciphertext, decode `epoch_key`, its response's 24-byte nonce and its
request's plaintext; encrypt with XChaCha20-Poly1305 using those exact AAD bytes,
then encode the ciphertext followed by its 16-byte tag as unpadded base64url.
Prefrontal's AAD is RFC 8785 JSON with `v` equal to
`ck-fleet-epoch-aad/prefrontal/v1`; Entorhinal retains `ck-fleet-epoch-aad/v1`.

## Verification and regeneration

On the Linux build server, run:

```sh
cargo test --locked -p credentials-module --features credentials-core/test-support \
  --test fleet_epoch_vectors fleet_epoch_prefrontal_samples_are_producer_generated_and_pinned
```

The test replays every committed ciphertext through real open calls, regenerates
and compares every file byte for byte, and exercises fresh single and batch seals.
Production draws each nonce once at emission; normal runs replay that nonce rather
than adding a deterministic-nonce hook. Deliberate regeneration sets
`CK_EMIT_PREFRONTAL_FLEET_VECTORS=1` on the command above and returns all three
folder files from the build-server job. The test generates `README.md` and
`SHA256SUMS` along with `cases.json`; never hand-edit generated sample files.
`SHA256SUMS` pins README and cases, excluding itself.
"#;

fn sample_open(sealed: &Value, aad: &Value) -> Value {
    json!({"epoch":sealed["epoch"],"nonce":sealed["nonce"],
        "ciphertext":sealed["ciphertext"],"aad":aad})
}

fn sample_aad(sealed: &Value, aad: &Value, domain: &str) -> String {
    serde_json::to_string(&json!({"aad":aad,"epoch":sealed["epoch"],"v":domain})).unwrap()
}

fn shared_sample_epoch(
    root: &std::path::Path,
    callosum: &SharedCallosumStandIn,
) -> (Arc<EncryptedStore>, Arc<EncryptedStore>) {
    let a = VaultFixture::new(root, "a", &format!("{:032x}", 1), callosum);
    let b = VaultFixture::new(root, "b", &format!("{:032x}", 2), callosum);
    let a_store = HomeStore::open(&a.data_dir).store;
    let b_store = HomeStore::open(&b.data_dir).store;
    let a_pem = install(&a_store, 1, 0x11);
    let b_pem = install(&b_store, 2, 0x22);
    let plaintext = json!({"keys":[key(1,0x31)],"kind":"join","v":WRAP_DOMAIN});
    a_store
        .fleet_epoch_import(
            &seal_wrap(&b_pem, &public(&a_pem), 2, 1, &plaintext, 0x71),
            &[FleetPeer::new(member(2), public(&b_pem)).unwrap()],
        )
        .unwrap();
    b_store
        .fleet_epoch_import(
            &seal_wrap(&a_pem, &public(&b_pem), 1, 2, &plaintext, 0x72),
            &[FleetPeer::new(member(1), public(&a_pem)).unwrap()],
        )
        .unwrap();
    (a_store, b_store)
}

#[tokio::test]
async fn fleet_epoch_prefrontal_samples_are_producer_generated_and_pinned() {
    use sha2::{Digest, Sha256};

    let root = support::temp_root("fleet-prefrontal-vectors");
    let callosum = SharedCallosumStandIn::start(root.path()).await;
    let (a_store, b_store) = shared_sample_epoch(root.path(), &callosum);

    let folder =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fleet-epoch-prefrontal-v1");
    let emitting = std::env::var_os("CK_EMIT_PREFRONTAL_FLEET_VECTORS").is_some();
    let pinned: Value = if emitting {
        Value::Null
    } else {
        serde_json::from_slice(
            &std::fs::read(folder.join("cases.json")).expect("generate Prefrontal samples"),
        )
        .unwrap()
    };
    let request = json!({"aad":encode(b"room:one:event:7"),"plaintext":encode(b"room event body")});
    let batch_request = json!({"items":[request.clone(),
        {"aad":encode(b"room:one:event:8"),"plaintext":encode(b"second room event")}]});
    let mut responses = Vec::new();
    for (caller, method, params, field) in [
        (
            "prefrontal",
            "fleet.epoch_seal",
            request.clone(),
            "seal_open",
        ),
        (
            "entorhinal",
            "fleet.epoch_seal",
            request.clone(),
            "entorhinal_seal",
        ),
        (
            "prefrontal",
            "fleet.epoch_seal_batch",
            batch_request.clone(),
            "batch",
        ),
    ] {
        let fresh = call_as(&a_store, None, caller, method, params.clone()).await;
        let sealed = if emitting {
            fresh.clone()
        } else {
            pinned[field]["response"].clone()
        };
        let fresh_items = if field == "batch" {
            fresh["items"].as_array().unwrap().clone()
        } else {
            vec![fresh]
        };
        let sample_items = if field == "batch" {
            sealed["items"].as_array().unwrap().clone()
        } else {
            vec![sealed.clone()]
        };
        let requests = if field == "batch" {
            params["items"].as_array().unwrap().clone()
        } else {
            vec![params]
        };
        assert_eq!(sample_items.len(), requests.len());
        for ((fresh, sample), input) in fresh_items.iter().zip(&sample_items).zip(&requests) {
            assert_eq!(sample.as_object().unwrap().len(), 3);
            assert_eq!(sample["epoch"], 1);
            assert_eq!(fresh["epoch"], sample["epoch"]);
            assert_eq!(decode(&sample["nonce"]).len(), 24);
            assert_eq!(
                decode(&sample["ciphertext"]).len(),
                decode(&input["plaintext"]).len() + 16
            );
            for output in [fresh, sample] {
                assert_eq!(
                    call_as(
                        &b_store,
                        None,
                        caller,
                        "fleet.epoch_open",
                        sample_open(output, &input["aad"])
                    )
                    .await,
                    json!({"plaintext":input["plaintext"]})
                );
            }
            if !emitting {
                assert_ne!(fresh["nonce"], sample["nonce"]);
                assert_ne!(fresh["ciphertext"], sample["ciphertext"]);
            }
        }
        if field == "batch" {
            assert_ne!(sample_items[0]["nonce"], sample_items[1]["nonce"]);
        }
        responses.push(sealed);
    }
    let sealed = &responses[0];
    let entorhinal = &responses[1];
    let batch = &responses[2];
    let open_request = sample_open(sealed, &request["aad"]);
    let opened = call_as(
        &a_store,
        None,
        "prefrontal",
        "fleet.epoch_open",
        open_request.clone(),
    )
    .await;
    assert_eq!(opened, json!({"plaintext":request["plaintext"]}));
    let refused = call_as(
        &a_store,
        None,
        "entorhinal",
        "fleet.epoch_open",
        open_request.clone(),
    )
    .await;
    assert_eq!(
        refused,
        json!({"error":{"code":"fleet_epoch_open_failed","class":"permanent"}})
    );
    let batch_open = json!({"items":[sample_open(&batch["items"][0], &request["aad"]), sample_open(entorhinal, &request["aad"])]});
    let batch_opened = call_as(
        &b_store,
        None,
        "prefrontal",
        "fleet.epoch_open_batch",
        batch_open.clone(),
    )
    .await;
    assert_eq!(batch_opened, json!({"items":[opened,refused]}));
    let aad =
        |sealed: &Value, aad: &Value| sample_aad(sealed, aad, "ck-fleet-epoch-aad/prefrontal/v1");
    let samples = json!({"version":"fleet-epoch-prefrontal-vectors-v1","caller":"reserved:prefrontal","epoch_key":encode([0x31;32]),
        "seal_open":{"request":request,"response":sealed,"record_aad_utf8":aad(sealed,&request["aad"]),
            "open_request":open_request,"open_response":opened,
            "cross_domain_open":{"caller":"reserved:entorhinal","request":open_request,"response":refused}},
        "entorhinal_seal":{"caller":"reserved:entorhinal","request":request,"response":entorhinal,
            "record_aad_utf8":sample_aad(entorhinal,&request["aad"],"ck-fleet-epoch-aad/v1")},
        "batch":{"request":batch_request,"response":batch,
            "record_aad_utf8":[aad(&batch["items"][0],&batch_request["items"][0]["aad"]),aad(&batch["items"][1],&batch_request["items"][1]["aad"])],
            "open_request":batch_open,"open_response":batch_opened}});
    let mut cases = serde_json::to_vec_pretty(&samples).unwrap();
    cases.push(b'\n');
    let checksums = format!(
        "{:x}  README.md\n{:x}  cases.json\n",
        Sha256::digest(PREFRONTAL_README.as_bytes()),
        Sha256::digest(&cases)
    );
    for (name, bytes) in [
        ("README.md", PREFRONTAL_README.as_bytes()),
        ("cases.json", cases.as_slice()),
        ("SHA256SUMS", checksums.as_bytes()),
    ] {
        if emitting {
            std::fs::create_dir_all(&folder).unwrap();
            std::fs::write(folder.join(name), bytes).unwrap();
        }
        assert_eq!(
            std::fs::read(folder.join(name)).unwrap(),
            bytes,
            "Prefrontal sample {name} changed"
        );
    }
    println!("verified Prefrontal single seal/open, cross-domain refusal, two-item seal/mixed open batch, and 3 pinned files");
}

const MAGIC_CONTEXT_README: &str = r#"# Magic Context fleet epoch v1 samples

All keys, plaintext and caller AAD in this folder are synthetic public test
material. `cases.json` is generated by the real encrypted store and fleet adapter
in `tests/fleet_epoch_vectors.rs`.

## Contents

- `epoch_key` is the synthetic epoch-1 key (`31` repeated 32 times in hex),
  installed on both stores through authenticated fleet import, not raw SQL.
- `seal_open` records a Magic Context single seal and its successful open on the
  second store. `cross_domain_open` submits the identical open request as
  Prefrontal and pins the refusal.
- `batch` records two ordered Magic Context seal inputs and outputs and their
  successful open batch on the second store. Each item has a separate nonce.

Caller AAD is canonical JSON identifying a memory change. Wire bytes are
canonical unpadded base64url. `record_aad_utf8` contains the exact UTF-8 AEAD
associated-data bytes, with no trailing newline. Its `v` is
`ck-fleet-epoch-aad/magic-context/v1`; the vault selects it from the attested
caller, never from request parameters. To recompute a ciphertext, decode
`epoch_key`, the response's 24-byte nonce, and the request's plaintext. Encrypt
with XChaCha20-Poly1305 using the exact AEAD AAD bytes, then encode the ciphertext
followed by its 16-byte tag as unpadded base64url.

## Verification and regeneration

On the Linux build server, run:

```sh
cargo test --locked -p credentials-module --features credentials-core/test-support \
  --test fleet_epoch_vectors fleet_epoch_magic_context_samples_are_producer_generated_and_pinned
```

The test exercises fresh single and batch seals, replays the committed
ciphertexts through real open calls, and compares all three generated files byte
for byte. Production draws each nonce at emission; normal runs replay those
nonces rather than changing the nonce source. To regenerate, set
`CK_EMIT_MAGIC_CONTEXT_FLEET_VECTORS=1` on the command above and return all three
files from the build-server job. Never hand-edit generated sample files.
`SHA256SUMS` pins README and cases, excluding itself.
"#;

#[tokio::test]
async fn fleet_epoch_magic_context_samples_are_producer_generated_and_pinned() {
    use sha2::{Digest, Sha256};

    const CALLER: &str = "magic-context";
    const DOMAIN: &str = "ck-fleet-epoch-aad/magic-context/v1";
    let root = support::temp_root("fleet-magic-context-vectors");
    let callosum = SharedCallosumStandIn::start(root.path()).await;
    let (a, b) = shared_sample_epoch(root.path(), &callosum);
    let request = json!({
        "aad":encode(br#"{"global_id":"0123456789abcdef0123456789abcdef.42","revision":3,"subject":"ck.fleet.memory.project.pj-example","v":"ck-memory/v1"}"#),
        "plaintext":encode(b"first memory change")
    });
    let requests = [
        request.clone(),
        json!({
            "aad":encode(br#"{"global_id":"0123456789abcdef0123456789abcdef.42","revision":4,"subject":"ck.fleet.memory.project.pj-example","v":"ck-memory/v1"}"#),
            "plaintext":encode(b"second memory change")
        }),
    ];
    let batch_request = json!({"items":requests});
    let fresh = call_as(&a, None, CALLER, "fleet.epoch_seal", request.clone()).await;
    assert_eq!(fresh["epoch"], 1, "single seal reply: {fresh}");
    let fresh_batch = call_as(
        &a,
        None,
        CALLER,
        "fleet.epoch_seal_batch",
        batch_request.clone(),
    )
    .await;
    let fresh_items = fresh_batch["items"]
        .as_array()
        .unwrap_or_else(|| panic!("batch seal reply: {fresh_batch}"));
    assert_eq!(fresh_items.len(), requests.len());
    assert_ne!(fresh_items[0]["nonce"], fresh_items[1]["nonce"]);

    let folder = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/fleet-epoch-magic-context-v1");
    let emitting = std::env::var_os("CK_EMIT_MAGIC_CONTEXT_FLEET_VECTORS").is_some();
    let (sealed, batch) = if emitting {
        (fresh.clone(), fresh_batch.clone())
    } else {
        let pinned: Value =
            serde_json::from_slice(&std::fs::read(folder.join("cases.json")).unwrap()).unwrap();
        (
            pinned["seal_open"]["response"].clone(),
            pinned["batch"]["response"].clone(),
        )
    };
    let batch_items = batch["items"].as_array().unwrap();
    assert_eq!(batch_items.len(), requests.len());
    assert_ne!(batch_items[0]["nonce"], batch_items[1]["nonce"]);
    for ((fresh, sample), input) in std::iter::once((&fresh, &sealed))
        .chain(fresh_items.iter().zip(batch_items))
        .zip(std::iter::once(&request).chain(&requests))
    {
        for output in [fresh, sample] {
            assert_eq!(output.as_object().unwrap().len(), 3);
            assert_eq!(output["epoch"], 1);
            assert_eq!(decode(&output["nonce"]).len(), 24);
            assert_eq!(
                decode(&output["ciphertext"]).len(),
                decode(&input["plaintext"]).len() + 16
            );
        }
        if !emitting {
            assert_ne!(fresh["nonce"], sample["nonce"]);
        }
    }

    let open_batch = |items: &[Value]| {
        let items: Vec<_> = items
            .iter()
            .zip(&requests)
            .map(|(item, input)| sample_open(item, &input["aad"]))
            .collect();
        json!({"items":items})
    };
    let expected_open = json!({"plaintext":request["plaintext"]});
    let expected_batch = json!({"items":[{"plaintext":requests[0]["plaintext"]},{"plaintext":requests[1]["plaintext"]}]});
    assert_eq!(
        call_as(
            &b,
            None,
            CALLER,
            "fleet.epoch_open",
            sample_open(&fresh, &request["aad"])
        )
        .await,
        expected_open
    );
    assert_eq!(
        call_as(
            &b,
            None,
            CALLER,
            "fleet.epoch_open_batch",
            open_batch(fresh_items)
        )
        .await,
        expected_batch
    );

    let open = sample_open(&sealed, &request["aad"]);
    let opened = call_as(&b, None, CALLER, "fleet.epoch_open", open.clone()).await;
    assert_eq!(opened, expected_open);
    let refused = call_as(&b, None, "prefrontal", "fleet.epoch_open", open.clone()).await;
    assert_eq!(
        refused,
        json!({"error":{"code":"fleet_epoch_open_failed","class":"permanent"}})
    );
    let batch_open = open_batch(batch_items);
    let batch_opened = call_as(
        &b,
        None,
        CALLER,
        "fleet.epoch_open_batch",
        batch_open.clone(),
    )
    .await;
    assert_eq!(batch_opened, expected_batch);
    let batch_aad: Vec<_> = batch_items
        .iter()
        .zip(&requests)
        .map(|(item, input)| sample_aad(item, &input["aad"], DOMAIN))
        .collect();
    let samples = json!({
        "version":"fleet-epoch-magic-context-vectors-v1","caller":"reserved:magic-context","epoch_key":encode([0x31;32]),
        "seal_open":{"request":request,"response":sealed,"record_aad_utf8":sample_aad(&sealed,&request["aad"],DOMAIN),
            "open_request":open,"open_response":opened,
            "cross_domain_open":{"caller":"reserved:prefrontal","request":open,"response":refused}},
        "batch":{"request":batch_request,"response":batch,"record_aad_utf8":batch_aad,
            "open_request":batch_open,"open_response":batch_opened}
    });
    let mut cases = serde_json::to_vec_pretty(&samples).unwrap();
    cases.push(b'\n');
    let checksums = format!(
        "{:x}  README.md\n{:x}  cases.json\n",
        Sha256::digest(MAGIC_CONTEXT_README.as_bytes()),
        Sha256::digest(&cases)
    );
    if emitting {
        std::fs::create_dir_all(&folder).unwrap();
    }
    for (name, bytes) in [
        ("README.md", MAGIC_CONTEXT_README.as_bytes()),
        ("cases.json", cases.as_slice()),
        ("SHA256SUMS", checksums.as_bytes()),
    ] {
        if emitting {
            std::fs::write(folder.join(name), bytes).unwrap();
        }
        assert_eq!(
            std::fs::read(folder.join(name)).unwrap(),
            bytes,
            "Magic Context sample {name} changed"
        );
    }
}
