//! Fleet wire operations over real vault stores and the Callosum outbound route.

use crate::support::{
    temp_root, HomeStore, Reply, SharedCallosumStandIn, VaultFixture, TARGET_MODULE,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use claustrum_module_probe::fleet_ops::{self, Answer};
use credentials_core::audit::{AuditCtx, AuditOp};
use credentials_core::fleet::{FleetRemoval, WRAP_KEY_ID};
use credentials_core::store::EncryptedStore;
use serde_json::{json, Value};
use std::sync::Arc;
use subc_protocol::Principal;

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
    pub fn decode(value: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
        (0..value.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16))
            .collect()
    }
}

fn member(n: usize) -> String {
    format!("fed-computer:{n:032x}")
}
fn set_self(store: &EncryptedStore, n: usize) {
    store
        .set_federation_self_member_audited(&member(n), AuditCtx::admin(AuditOp::FederationSelfSet))
        .unwrap();
}

struct Vault {
    fixture: VaultFixture,
    store: Arc<EncryptedStore>,
    n: usize,
}
impl Vault {
    fn new(root: &std::path::Path, n: usize, callosum: &SharedCallosumStandIn) -> Self {
        let fixture =
            VaultFixture::new(root, &format!("vault-{n}"), &format!("{n:032x}"), callosum);
        let store = HomeStore::open(&fixture.data_dir).store;
        store.ensure_fleet_keys(1).unwrap();
        set_self(&store, n);
        Self { fixture, store, n }
    }
    fn peer(&self) -> Value {
        let key = self.store.get(WRAP_KEY_ID).unwrap();
        let (public, _) =
            credentials_core::kem::public_half(std::str::from_utf8(key.payload.expose()).unwrap())
                .unwrap();
        json!({"fingerprint":format!("{:032x}",self.n),"class":"computer","key_record":{"keys":{"fleet_epoch_wrap_x25519":{"pub":hex::encode(public),"version":"1"}}}})
    }
    fn restart(self) -> Self {
        let Self { fixture, store, n } = self;
        drop(store);
        let store = HomeStore::open(&fixture.data_dir).store;
        Self { fixture, store, n }
    }
    async fn call(&self, method: &str, params: Value) -> Value {
        match fleet_ops::serve(
            Arc::clone(&self.store),
            Some(&self.fixture.outbound),
            Some(&Principal::Reserved {
                module_id: "entorhinal".into(),
            }),
            method,
            &params,
        )
        .await
        {
            Answer::Reply(reply) => reply,
            Answer::InvalidParams => panic!("unexpected invalid parameters for {method}"),
        }
    }
    async fn ok(&self, method: &str, params: Value) -> Value {
        let reply = self.call(method, params).await;
        assert!(
            reply.get("error").is_none(),
            "{method} refused: {}",
            reply["error"]
        );
        reply
    }
    async fn mint(&self, members: &[usize]) -> Value {
        self.ok(
            "fleet.epoch_mint",
            json!({"members":members.iter().map(|n|member(*n)).collect::<Vec<_>>()}),
        )
        .await
    }
    async fn commit(&self, mint: &Value) {
        assert_eq!(
            self.ok(
                "fleet.epoch_commit",
                json!({"epoch":mint["epoch"],"mint_id":mint["mint_id"]})
            )
            .await,
            json!({"epoch":mint["epoch"],"state":"current"})
        );
    }
    async fn seal(&self) -> Value {
        self.ok("fleet.epoch_seal", json!({"aad":URL_SAFE_NO_PAD.encode(b"context"),"plaintext":URL_SAFE_NO_PAD.encode(b"shared record")})).await
    }
    async fn open(&self, sealed: &Value) {
        assert_eq!(
            self.ok(
                "fleet.epoch_open",
                json!({"epoch":sealed["epoch"],"nonce":sealed["nonce"],
            "ciphertext":sealed["ciphertext"],"aad":URL_SAFE_NO_PAD.encode(b"context")})
            )
            .await,
            json!({"plaintext":URL_SAFE_NO_PAD.encode(b"shared record")})
        );
    }
    fn remove(&self, n: usize) {
        self.store
            .fleet_record_removals(
                &[FleetRemoval {
                    member_id: member(n),
                    removal_id: "opaque:removal".into(),
                }],
                2,
            )
            .unwrap();
    }
}
fn peers(callosum: &SharedCallosumStandIn, vaults: &[&Vault]) {
    callosum.answer(
        TARGET_MODULE,
        "callosum.peer_keys_read",
        Reply::Ok(json!({"peers":vaults.iter().map(|v|v.peer()).collect::<Vec<_>>()})),
    );
}
fn rotation(mint: &Value, n: usize) -> Value {
    mint["wraps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["member_id"] == member(n))
        .unwrap()["wrap"]
        .clone()
}
fn refused(reply: Value, code: &str, class: &str) {
    assert_eq!(reply, json!({"error":{"code":code,"class":class}}));
}

#[tokio::test]
async fn fleet_two_vault_seal_open_and_join_opens_epoch_one() {
    let root = temp_root("fleet-two-vault");
    let callosum = SharedCallosumStandIn::start(root.path()).await;
    let a = Vault::new(root.path(), 1, &callosum);
    let b = Vault::new(root.path(), 2, &callosum);
    let d = Vault::new(root.path(), 4, &callosum);
    peers(&callosum, &[&a, &b]);
    let mint = a.mint(&[1, 2]).await;
    a.commit(&mint).await;
    assert_eq!(
        b.ok("fleet.epoch_import", json!({"wrap":rotation(&mint,2)}))
            .await,
        json!({"epochs":[1],"already_held":false})
    );
    let old = a.seal().await;
    b.open(&old).await;
    a.open(&b.seal().await).await;
    let second = a.mint(&[1, 2]).await;
    a.commit(&second).await;
    peers(&callosum, &[&a, &b, &d]);
    let joined = a
        .ok("fleet.epoch_wrap_for", json!({"member_id":member(4)}))
        .await;
    assert_eq!(
        d.ok("fleet.epoch_import", joined).await,
        json!({"epochs":[1,2],"already_held":false})
    );
    d.open(&old).await;
    a.open(&d.seal().await).await;
}

#[tokio::test]
async fn fleet_mint_race_loser_discards_before_import_and_never_seals_pending() {
    let root = temp_root("fleet-race");
    let callosum = SharedCallosumStandIn::start(root.path()).await;
    let a = Vault::new(root.path(), 1, &callosum);
    let b = Vault::new(root.path(), 2, &callosum);
    peers(&callosum, &[&a, &b]);
    let winner = a.mint(&[1, 2]).await;
    let loser = b.mint(&[1, 2]).await;
    refused(
        b.call("fleet.epoch_seal", json!({"aad":"","plaintext":""}))
            .await,
        "fleet_epoch_unavailable",
        "transient",
    );
    refused(
        b.call("fleet.epoch_import", json!({"wrap":rotation(&winner,2)}))
            .await,
        "fleet_epoch_pending",
        "transient",
    );
    let discard = json!({"epoch":loser["epoch"],"mint_id":loser["mint_id"]});
    let discarded = b.ok("fleet.epoch_discard", discard.clone()).await;
    assert_eq!(b.ok("fleet.epoch_discard", discard).await, discarded);
    a.commit(&winner).await;
    b.ok("fleet.epoch_import", json!({"wrap":rotation(&winner,2)}))
        .await;
    b.open(&a.seal().await).await;
    refused(
        b.call(
            "fleet.epoch_commit",
            json!({"epoch":loser["epoch"],"mint_id":loser["mint_id"]}),
        )
        .await,
        "fleet_epoch_not_pending",
        "permanent",
    );
}

#[tokio::test]
async fn fleet_self_change_between_mint_and_commit_requires_discard_and_new_mint() {
    let root = temp_root("fleet-self-pending");
    let callosum = SharedCallosumStandIn::start(root.path()).await;
    let a = Vault::new(root.path(), 1, &callosum);
    peers(&callosum, &[]);
    let stale = a.mint(&[1]).await;
    set_self(&a.store, 3);
    refused(
        a.call(
            "fleet.epoch_commit",
            json!({"epoch":stale["epoch"],"mint_id":stale["mint_id"]}),
        )
        .await,
        "fleet_members_mismatch",
        "permanent",
    );
    a.ok(
        "fleet.epoch_discard",
        json!({"epoch":stale["epoch"],"mint_id":stale["mint_id"]}),
    )
    .await;
    let fresh = a.mint(&[3]).await;
    assert_ne!(fresh["mint_id"], stale["mint_id"]);
    a.commit(&fresh).await;
    a.open(&a.seal().await).await;
}

#[tokio::test]
async fn fleet_self_change_across_restart_recovers_and_exports_unchanged_history_to_d() {
    let root = temp_root("fleet-self-history");
    let callosum = SharedCallosumStandIn::start(root.path()).await;
    let mut a = Vault::new(root.path(), 1, &callosum);
    let d = Vault::new(root.path(), 4, &callosum);
    peers(&callosum, &[]);
    let first = a.mint(&[1]).await;
    a.commit(&first).await;
    let old = a.seal().await;
    let second = a.mint(&[1]).await;
    a.commit(&second).await;
    set_self(&a.store, 3);
    a.n = 3;
    a = a.restart();
    refused(
        a.call("fleet.epoch_seal", json!({"aad":"","plaintext":""}))
            .await,
        "fleet_epoch_unavailable",
        "transient",
    );
    a.open(&old).await;
    let recovered = a.mint(&[3]).await;
    a.commit(&recovered).await;
    peers(&callosum, &[&a, &d]);
    let joined = a
        .ok("fleet.epoch_wrap_for", json!({"member_id":member(4)}))
        .await;
    // Open the authenticated join independently to pin historical holders, rather
    // than inferring them from a successful import that also checks membership.
    let wrap = &joined["wrap"];
    let recipient = d.store.get(WRAP_KEY_ID).unwrap();
    let sender = a.peer();
    let public = hex::decode(
        sender
            .pointer("/key_record/keys/fleet_epoch_wrap_x25519/pub")
            .unwrap()
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let info =
        serde_json::to_vec(&json!({"from":member(3),"to":member(4),"v":"ck-fleet-epoch-wrap/v1"}))
            .unwrap();
    let opened = credentials_core::kem::open_auth(
        std::str::from_utf8(recipient.payload.expose()).unwrap(),
        &public,
        &URL_SAFE_NO_PAD
            .decode(wrap["enc"].as_str().unwrap())
            .unwrap(),
        &URL_SAFE_NO_PAD
            .decode(wrap["ct"].as_str().unwrap())
            .unwrap(),
        &info,
        b"",
    )
    .unwrap();
    let contents: Value = serde_json::from_slice(&opened).unwrap();
    assert_eq!(
        contents["keys"][0]["members"],
        json!([member(1), member(4)])
    );
    assert_eq!(
        contents["keys"][1]["members"],
        json!([member(1), member(4)])
    );
    assert_eq!(
        contents["keys"][2]["members"],
        json!([member(3), member(4)])
    );
    d.ok("fleet.epoch_import", joined).await;
    d.open(&old).await;
    a.open(&d.seal().await).await;
}

#[tokio::test]
async fn fleet_lost_mint_recovers_through_status_after_restart_without_reusing_mint_id() {
    let root = temp_root("fleet-lost-mint");
    let callosum = SharedCallosumStandIn::start(root.path()).await;
    let mut a = Vault::new(root.path(), 1, &callosum);
    peers(&callosum, &[]);
    drop(a.mint(&[1]).await);
    a = a.restart();
    let status = a.ok("fleet.epoch_status", json!({})).await;
    assert_eq!(status["current"], Value::Null);
    assert_eq!(status["held"], json!([]));
    assert_eq!(status["pending"]["epoch"], 1);
    let lost_id = status["pending"]["mint_id"].clone();
    a.ok("fleet.epoch_discard", status["pending"].clone()).await;
    let mint = a.mint(&[1]).await;
    assert_eq!(mint["epoch"], 1);
    assert_ne!(mint["mint_id"], lost_id);
    refused(
        a.call("fleet.epoch_commit", json!({"epoch":1,"mint_id":lost_id}))
            .await,
        "fleet_epoch_not_pending",
        "permanent",
    );
    a.commit(&mint).await;
    a.open(&a.seal().await).await;
}

#[tokio::test]
async fn fleet_join_then_remove_blocks_only_holders_who_learned_the_join_until_rotation() {
    let root = temp_root("fleet-join-remove");
    let callosum = SharedCallosumStandIn::start(root.path()).await;
    let a = Vault::new(root.path(), 1, &callosum);
    let b = Vault::new(root.path(), 2, &callosum);
    let d = Vault::new(root.path(), 4, &callosum);
    peers(&callosum, &[&a, &b]);
    let mint = a.mint(&[1, 2]).await;
    a.commit(&mint).await;
    b.ok("fleet.epoch_import", json!({"wrap":rotation(&mint,2)}))
        .await;
    let historical = a.seal().await;
    peers(&callosum, &[&a, &b, &d]);
    let join_d = a
        .ok("fleet.epoch_wrap_for", json!({"member_id":member(4)}))
        .await;
    d.ok("fleet.epoch_import", join_d).await;
    let enlarged = a
        .ok("fleet.epoch_wrap_for", json!({"member_id":member(2)}))
        .await;
    a.remove(4);
    b.remove(4);
    refused(
        a.call("fleet.epoch_seal", json!({"aad":"","plaintext":""}))
            .await,
        "fleet_epoch_unavailable",
        "transient",
    );
    a.open(&b.seal().await).await;
    // A join carrying a now-removed highest holder cannot be merged. A holder
    // learns the join before its tombstone in the complementary ordering below.
    refused(
        b.call("fleet.epoch_import", enlarged.clone()).await,
        "fleet_wrap_refused",
        "permanent",
    );
    let fresh = a.mint(&[1, 2]).await;
    a.commit(&fresh).await;
    b.ok("fleet.epoch_import", json!({"wrap":rotation(&fresh,2)}))
        .await;
    a.open(&b.seal().await).await;
    b.open(&historical).await;
    refused(
        a.call("fleet.epoch_wrap_for", json!({"member_id":member(4)}))
            .await,
        "fleet_members_mismatch",
        "permanent",
    );
}

#[tokio::test]
async fn fleet_imported_holder_union_blocks_sealing_after_joined_member_is_removed() {
    let root = temp_root("fleet-holder-union");
    let callosum = SharedCallosumStandIn::start(root.path()).await;
    let a = Vault::new(root.path(), 1, &callosum);
    let b = Vault::new(root.path(), 2, &callosum);
    let d = Vault::new(root.path(), 4, &callosum);
    peers(&callosum, &[&a, &b]);
    let mint = a.mint(&[1, 2]).await;
    a.commit(&mint).await;
    b.ok("fleet.epoch_import", json!({"wrap":rotation(&mint,2)}))
        .await;
    peers(&callosum, &[&a, &b, &d]);
    a.ok("fleet.epoch_wrap_for", json!({"member_id":member(4)}))
        .await;
    let enlarged = a
        .ok("fleet.epoch_wrap_for", json!({"member_id":member(2)}))
        .await;
    assert_eq!(
        b.ok("fleet.epoch_import", enlarged).await,
        json!({"epochs":[],"already_held":true})
    );
    b.remove(4);
    assert_eq!(
        b.ok("fleet.epoch_status", json!({})).await["sealing_blocked_by"],
        json!([member(4)])
    );
    refused(
        b.call("fleet.epoch_seal", json!({"aad":"","plaintext":""}))
            .await,
        "fleet_epoch_unavailable",
        "transient",
    );
}

#[tokio::test]
async fn fleet_hub_forged_base_and_unpaired_auth_wraps_are_uniformly_refused_without_writes() {
    let root = temp_root("fleet-hub-forgery");
    let callosum = SharedCallosumStandIn::start(root.path()).await;
    let a = Vault::new(root.path(), 1, &callosum);
    let b = Vault::new(root.path(), 2, &callosum);
    peers(&callosum, &[&a, &b]);
    let recipient = hex::decode(
        b.peer()
            .pointer("/key_record/keys/fleet_epoch_wrap_x25519/pub")
            .unwrap()
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let plaintext = serde_json::to_vec(&json!({"keys":[{"epoch":1,"key":URL_SAFE_NO_PAD.encode([42;32]),"members":[member(1),member(2)],"minter":member(1)}],"kind":"rotation","v":"ck-fleet-epoch-wrap/v1"})).unwrap();
    let info =
        serde_json::to_vec(&json!({"from":member(1),"to":member(2),"v":"ck-fleet-epoch-wrap/v1"}))
            .unwrap();
    let rogue = credentials_core::kem::generate_key().unwrap();
    let forged = [
        credentials_core::kem::seal_base(&recipient, &plaintext, &info, b"").unwrap(),
        credentials_core::kem::seal_fleet_auth(&rogue, &recipient, &plaintext, &info).unwrap(),
    ];
    let audit = b.store.read_audit(None).unwrap();
    let status = b.ok("fleet.epoch_status", json!({})).await;
    for (enc, ct) in forged {
        refused(
            b.call(
                "fleet.epoch_import",
                json!({"wrap":{"enc":URL_SAFE_NO_PAD.encode(enc),"ct":URL_SAFE_NO_PAD.encode(ct),
            "from":member(1),"to":member(2),"v":"ck-fleet-epoch-wrap/v1"}}),
            )
            .await,
            "fleet_wrap_refused",
            "permanent",
        );
        assert_eq!(b.ok("fleet.epoch_status", json!({})).await, status);
        assert_eq!(b.store.read_audit(None).unwrap(), audit);
    }
    let mint = a.mint(&[1, 2]).await;
    b.ok("fleet.epoch_import", json!({"wrap":rotation(&mint,2)}))
        .await;
}

#[tokio::test]
async fn fleet_holder_cap_accepts_64_refuses_65_and_import_union_overflow_writes_nothing() {
    let root = temp_root("fleet-holder-cap");
    let callosum = SharedCallosumStandIn::start(root.path()).await;
    let a = Vault::new(root.path(), 1, &callosum);
    let b = Vault::new(root.path(), 2, &callosum);
    let entries = |end: usize| -> Vec<Value> {
        (1..=end)
            .map(|n| {
                let mut entry = if n == 2 { b.peer() } else { a.peer() };
                entry["fingerprint"] = json!(format!("{n:032x}"));
                entry
            })
            .collect()
    };
    callosum.answer(
        TARGET_MODULE,
        "callosum.peer_keys_read",
        Reply::Ok(json!({"peers":entries(65)})),
    );
    let too_many: Vec<_> = (1..=65).map(member).collect();
    refused(
        a.call("fleet.epoch_mint", json!({"members":too_many}))
            .await,
        "fleet_epoch_capacity",
        "permanent",
    );
    callosum.answer(
        TARGET_MODULE,
        "callosum.peer_keys_read",
        Reply::Ok(json!({"peers":entries(63)})),
    );
    let initial: Vec<_> = (1..=63).collect();
    let mint = a.mint(&initial).await;
    a.commit(&mint).await;
    b.ok("fleet.epoch_import", json!({"wrap":rotation(&mint,2)}))
        .await;
    callosum.answer(
        TARGET_MODULE,
        "callosum.peer_keys_read",
        Reply::Ok(json!({"peers":entries(65)})),
    );
    a.ok("fleet.epoch_wrap_for", json!({"member_id":member(64)}))
        .await;
    b.ok("fleet.epoch_wrap_for", json!({"member_id":member(65)}))
        .await;
    let before = a.store.read_audit(None).unwrap();
    refused(
        a.call("fleet.epoch_wrap_for", json!({"member_id":member(65)}))
            .await,
        "fleet_epoch_capacity",
        "permanent",
    );
    assert_eq!(a.store.read_audit(None).unwrap(), before);
    let from_a = a
        .ok("fleet.epoch_wrap_for", json!({"member_id":member(2)}))
        .await;
    let before = b.store.read_audit(None).unwrap();
    let status = b.ok("fleet.epoch_status", json!({})).await;
    let sealed = b.seal().await;
    refused(
        b.call("fleet.epoch_import", from_a).await,
        "fleet_wrap_refused",
        "permanent",
    );
    assert_eq!(b.store.read_audit(None).unwrap(), before);
    assert_eq!(b.ok("fleet.epoch_status", json!({})).await, status);
    b.open(&sealed).await;
}

#[test]
fn fleet_peer_decoder_rejects_ambiguity_and_ignores_noncomputer_or_invalid_keys() {
    let key = credentials_core::kem::public_half(&credentials_core::kem::pem_from_scalar(&[9; 32]))
        .unwrap()
        .0;
    let entry = json!({"fingerprint":format!("{:032x}",1),"class":"computer","key_record":{"keys":{"fleet_epoch_wrap_x25519":{"pub":hex::encode(&key),"version":"1"}}}});
    assert_eq!(
        fleet_ops::decode_peers(&json!({"peers":[entry.clone()]}))
            .unwrap()
            .len(),
        1
    );
    for snapshot in [
        json!({"error":{"code":"fed_not_ready"}}),
        json!({"peers":null}),
        json!({"peers":[entry.clone(),entry.clone()]}),
        json!({"peers":[{"fingerprint":"INVALID"}]}),
        json!({"peers":[null]}),
    ] {
        assert_eq!(
            fleet_ops::decode_peers(&snapshot).unwrap_err(),
            credentials_core::fleet::FleetError::PeerKeysUnavailable
        );
    }
    for class in ["phone", "sim", "unknown"] {
        let mut invalid = entry.clone();
        invalid["class"] = json!(class);
        assert!(fleet_ops::decode_peers(&json!({"peers":[invalid]}))
            .unwrap()
            .is_empty());
    }
    for public in [
        "00".repeat(32),
        hex::encode(&key).to_uppercase(),
        "ab".repeat(31),
        "not-a-key".into(),
    ] {
        let mut invalid = entry.clone();
        invalid["key_record"]["keys"]["fleet_epoch_wrap_x25519"]["pub"] = json!(public);
        assert!(fleet_ops::decode_peers(&json!({"peers":[invalid]}))
            .unwrap()
            .is_empty());
    }
}

#[tokio::test]
async fn fleet_remove_rotate_then_join_keeps_removed_holders_in_open_only_history() {
    let root = temp_root("fleet-remove-rotate-join");
    let callosum = SharedCallosumStandIn::start(root.path()).await;
    let a = Vault::new(root.path(), 1, &callosum);
    let b = Vault::new(root.path(), 2, &callosum);
    let d = Vault::new(root.path(), 4, &callosum);
    peers(&callosum, &[&a, &b]);
    let first = a.mint(&[1, 2]).await;
    a.commit(&first).await;
    let historical = a.seal().await;
    a.remove(2);
    d.remove(2);
    refused(
        a.call("fleet.epoch_seal", json!({"aad":"","plaintext":""}))
            .await,
        "fleet_epoch_unavailable",
        "transient",
    );
    let second = a.mint(&[1]).await;
    a.commit(&second).await;
    peers(&callosum, &[&a, &b, &d]);
    let joined = a
        .ok("fleet.epoch_wrap_for", json!({"member_id":member(4)}))
        .await;
    assert_eq!(
        d.ok("fleet.epoch_import", joined).await,
        json!({"epochs":[1,2],"already_held":false})
    );
    d.open(&historical).await;
    let current = d.seal().await;
    assert_eq!(current["epoch"], 2);
    a.open(&current).await;
}
