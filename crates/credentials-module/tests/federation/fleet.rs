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
        self.call_as("entorhinal", method, params).await
    }
    async fn call_as(&self, module: &str, method: &str, params: Value) -> Value {
        match fleet_ops::serve(
            Arc::clone(&self.store),
            Some(&self.fixture.outbound),
            Some(&Principal::Reserved {
                module_id: module.into(),
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

async fn shared_epoch(a: &Vault, b: &Vault, callosum: &SharedCallosumStandIn) {
    peers(callosum, &[a, b]);
    let mint = a.mint(&[a.n, b.n]).await;
    a.commit(&mint).await;
    b.ok("fleet.epoch_import", json!({"wrap":rotation(&mint,b.n)}))
        .await;
}

fn open_params(sealed: &Value, aad: &str) -> Value {
    json!({"epoch":sealed["epoch"],"nonce":sealed["nonce"],
        "ciphertext":sealed["ciphertext"],"aad":aad})
}

#[tokio::test]
async fn fleet_magic_context_single_round_trip_across_stores_without_audit() {
    let root = temp_root("fleet-magic-context-single");
    let callosum = SharedCallosumStandIn::start(root.path()).await;
    let a = Vault::new(root.path(), 1, &callosum);
    let b = Vault::new(root.path(), 2, &callosum);
    shared_epoch(&a, &b, &callosum).await;
    let before_a = a.store.read_audit(None).unwrap();
    let before_b = b.store.read_audit(None).unwrap();
    let aad = URL_SAFE_NO_PAD.encode(b"memory change aad");
    let plaintext = URL_SAFE_NO_PAD.encode(b"first memory change");
    let sealed = a
        .call_as(
            "magic-context",
            "fleet.epoch_seal",
            json!({"aad":aad,"plaintext":plaintext}),
        )
        .await;
    assert_eq!(sealed["epoch"], 1, "seal reply: {sealed}");
    assert_eq!(
        b.call_as(
            "magic-context",
            "fleet.epoch_open",
            open_params(&sealed, &aad)
        )
        .await,
        json!({"plaintext":plaintext})
    );
    assert_eq!(a.store.read_audit(None).unwrap(), before_a);
    assert_eq!(b.store.read_audit(None).unwrap(), before_b);
}

#[tokio::test]
async fn fleet_magic_context_batch_round_trip_across_stores_without_audit() {
    let root = temp_root("fleet-magic-context-batch");
    let callosum = SharedCallosumStandIn::start(root.path()).await;
    let a = Vault::new(root.path(), 1, &callosum);
    let b = Vault::new(root.path(), 2, &callosum);
    shared_epoch(&a, &b, &callosum).await;
    let before_a = a.store.read_audit(None).unwrap();
    let before_b = b.store.read_audit(None).unwrap();
    let aad = [
        URL_SAFE_NO_PAD.encode(b"revision 3"),
        URL_SAFE_NO_PAD.encode(b"revision 4"),
    ];
    let plaintext = [
        URL_SAFE_NO_PAD.encode(b"first change"),
        URL_SAFE_NO_PAD.encode(b"second change"),
    ];
    let sealed = a
        .call_as(
            "magic-context",
            "fleet.epoch_seal_batch",
            json!({"items":[
                {"aad":aad[0],"plaintext":plaintext[0]}, {"aad":aad[1],"plaintext":plaintext[1]}
            ]}),
        )
        .await;
    let items = sealed["items"]
        .as_array()
        .unwrap_or_else(|| panic!("batch seal reply: {sealed}"));
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["epoch"], 1);
    assert_eq!(items[1]["epoch"], 1);
    assert_ne!(items[0]["nonce"], items[1]["nonce"]);
    let open_items: Vec<_> = items
        .iter()
        .zip(&aad)
        .map(|(item, aad)| open_params(item, aad))
        .collect();
    assert_eq!(
        b.call_as(
            "magic-context",
            "fleet.epoch_open_batch",
            json!({"items":open_items})
        )
        .await,
        json!({"items":[{"plaintext":plaintext[0]},{"plaintext":plaintext[1]}]})
    );
    assert_eq!(a.store.read_audit(None).unwrap(), before_a);
    assert_eq!(b.store.read_audit(None).unwrap(), before_b);
}

#[tokio::test]
async fn fleet_magic_context_domain_refuses_both_directions_with_each_other_caller() {
    let root = temp_root("fleet-magic-context-domains");
    let callosum = SharedCallosumStandIn::start(root.path()).await;
    let a = Vault::new(root.path(), 1, &callosum);
    let b = Vault::new(root.path(), 2, &callosum);
    shared_epoch(&a, &b, &callosum).await;
    let aad = URL_SAFE_NO_PAD.encode(b"same caller aad");
    let plaintext = URL_SAFE_NO_PAD.encode(b"same plaintext");
    let failure = json!({"error":{"code":"fleet_epoch_open_failed","class":"permanent"}});
    for (sealer, other) in [
        ("entorhinal", "magic-context"),
        ("prefrontal", "magic-context"),
        ("magic-context", "entorhinal"),
        ("magic-context", "prefrontal"),
    ] {
        let sealed = a
            .call_as(
                sealer,
                "fleet.epoch_seal",
                json!({"aad":aad,"plaintext":plaintext}),
            )
            .await;
        assert_eq!(sealed["epoch"], 1, "{sealer} seal reply: {sealed}");
        let params = open_params(&sealed, &aad);
        assert_eq!(
            b.call_as(sealer, "fleet.epoch_open", params.clone()).await,
            json!({"plaintext":plaintext})
        );
        assert_eq!(
            b.call_as(other, "fleet.epoch_open", params.clone()).await,
            failure,
            "{sealer} seal opened as {other}"
        );
        assert_eq!(
            b.call_as(other, "fleet.epoch_open_batch", json!({"items":[params]}))
                .await,
            json!({"items":[failure]}),
            "{sealer} seal batch-opened as {other}"
        );
    }
}

#[tokio::test]
async fn fleet_prefrontal_round_trips_across_two_stores_and_retained_epochs_without_audit() {
    let root = temp_root("fleet-prefrontal-round-trip");
    let callosum = SharedCallosumStandIn::start(root.path()).await;
    let a = Vault::new(root.path(), 1, &callosum);
    let b = Vault::new(root.path(), 2, &callosum);
    shared_epoch(&a, &b, &callosum).await;
    let params = json!({"aad":URL_SAFE_NO_PAD.encode(b"room:one"),"plaintext":URL_SAFE_NO_PAD.encode(b"room event")});
    let before = a.store.read_audit(None).unwrap();
    let sealed = a
        .call_as("prefrontal", "fleet.epoch_seal", params.clone())
        .await;
    assert_eq!(sealed["epoch"], 1);
    for vault in [&a, &b] {
        assert_eq!(
            vault
                .call_as(
                    "prefrontal",
                    "fleet.epoch_open",
                    open_params(&sealed, params["aad"].as_str().unwrap())
                )
                .await,
            json!({"plaintext":params["plaintext"]})
        );
    }
    assert_eq!(a.store.read_audit(None).unwrap(), before);
    let next = a.mint(&[1, 2]).await;
    a.commit(&next).await;
    a.remove(2);
    let before = a.store.read_audit(None).unwrap();
    refused(
        a.call_as("prefrontal", "fleet.epoch_seal", params.clone())
            .await,
        "fleet_epoch_unavailable",
        "transient",
    );
    assert_eq!(
        a.call_as(
            "prefrontal",
            "fleet.epoch_open",
            open_params(&sealed, params["aad"].as_str().unwrap())
        )
        .await,
        json!({"plaintext":params["plaintext"]})
    );
    assert_eq!(a.store.read_audit(None).unwrap(), before);
}

#[tokio::test]
async fn fleet_prefrontal_and_entorhinal_cannot_open_each_others_ciphertexts() {
    let root = temp_root("fleet-prefrontal-domain");
    let callosum = SharedCallosumStandIn::start(root.path()).await;
    let a = Vault::new(root.path(), 1, &callosum);
    let b = Vault::new(root.path(), 2, &callosum);
    shared_epoch(&a, &b, &callosum).await;
    let aad = URL_SAFE_NO_PAD.encode(b"same caller aad");
    for (sealer, other) in [("entorhinal", "prefrontal"), ("prefrontal", "entorhinal")] {
        let sealed = a
            .call_as(
                sealer,
                "fleet.epoch_seal",
                json!({"aad":aad,"plaintext":URL_SAFE_NO_PAD.encode(b"same plaintext")}),
            )
            .await;
        assert_eq!(sealed["epoch"], 1);
        let params = open_params(&sealed, &aad);
        assert_eq!(
            b.call_as(sealer, "fleet.epoch_open", params.clone()).await,
            json!({"plaintext":URL_SAFE_NO_PAD.encode(b"same plaintext")})
        );
        refused(
            b.call_as(other, "fleet.epoch_open", params).await,
            "fleet_epoch_open_failed",
            "permanent",
        );
    }
}

#[tokio::test]
async fn fleet_prefrontal_adapter_hides_all_unadmitted_methods_before_parsing() {
    let root = temp_root("fleet-prefrontal-adapter-admission");
    let callosum = SharedCallosumStandIn::start(root.path()).await;
    let a = Vault::new(root.path(), 1, &callosum);
    for method in [
        "fleet.epoch_status",
        "fleet.epoch_mint",
        "fleet.epoch_commit",
        "fleet.epoch_discard",
        "fleet.epoch_import",
        "fleet.epoch_wrap_for",
    ] {
        let unknown = a.call_as("unknown", method, Value::Null).await;
        refused(unknown.clone(), "not_found", "permanent");
        assert_eq!(a.call_as("prefrontal", method, Value::Null).await, unknown);
    }
    for method in [
        "fleet.epoch_seal",
        "fleet.epoch_open",
        "fleet.epoch_seal_batch",
        "fleet.epoch_open_batch",
    ] {
        assert_eq!(
            a.call_as("prefrontal-core", method, Value::Null).await,
            a.call_as("unknown", method, Value::Null).await
        );
    }
}

#[tokio::test]
async fn fleet_batch_single_interoperate_and_mixed_opens_keep_order_and_domains() {
    let root = temp_root("fleet-batch-mixed");
    let callosum = SharedCallosumStandIn::start(root.path()).await;
    let a = Vault::new(root.path(), 1, &callosum);
    let b = Vault::new(root.path(), 2, &callosum);
    shared_epoch(&a, &b, &callosum).await;
    let aad = URL_SAFE_NO_PAD.encode(b"room");
    for (sealer, other) in [("prefrontal", "entorhinal"), ("entorhinal", "prefrontal")] {
        let before = a.store.read_audit(None).unwrap();
        let requests: Vec<_> = [b"one".as_slice(), b"two".as_slice()]
            .into_iter()
            .map(|plaintext| json!({"aad":aad,"plaintext":URL_SAFE_NO_PAD.encode(plaintext)}))
            .collect();
        let sealed = a
            .call_as(sealer, "fleet.epoch_seal_batch", json!({"items":requests}))
            .await;
        let items = sealed["items"].as_array().expect("batch seal items");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["epoch"], 1);
        assert_eq!(items[1]["epoch"], 1);
        assert_ne!(items[0]["nonce"], items[1]["nonce"]);
        for (item, request) in items.iter().zip(&requests) {
            let params = open_params(item, &aad);
            assert_eq!(
                b.call_as(sealer, "fleet.epoch_open", params.clone()).await,
                json!({"plaintext":request["plaintext"]})
            );
            refused(
                b.call_as(other, "fleet.epoch_open", params).await,
                "fleet_epoch_open_failed",
                "permanent",
            );
        }
        let single = a
            .call_as(sealer, "fleet.epoch_seal", requests[0].clone())
            .await;
        let wrong_domain = a
            .call_as(other, "fleet.epoch_seal", requests[1].clone())
            .await;
        let mut tampered = open_params(&items[0], &aad);
        let mut ct = URL_SAFE_NO_PAD
            .decode(tampered["ciphertext"].as_str().unwrap())
            .unwrap();
        ct[0] ^= 1;
        tampered["ciphertext"] = json!(URL_SAFE_NO_PAD.encode(ct));
        let mut unknown = open_params(&items[0], &aad);
        unknown["epoch"] = json!(999);
        let pending = a.mint(&[1, 2]).await;
        let mut pending_open = open_params(&items[0], &aad);
        pending_open["epoch"] = pending["epoch"].clone();
        let good = json!({"plaintext":requests[0]["plaintext"]});
        let failed = json!({"error":{"code":"fleet_epoch_open_failed","class":"permanent"}});
        let unavailable = json!({"error":{"code":"fleet_epoch_unavailable","class":"transient"}});
        let response = a.call_as(sealer, "fleet.epoch_open_batch", json!({"items":[
            open_params(&single,&aad), tampered, unknown, open_params(&wrong_domain,&aad), pending_open, open_params(&items[1],&aad)
        ]})).await;
        assert_eq!(
            response,
            json!({"items":[good,failed,unavailable,failed,unavailable,{"plaintext":requests[1]["plaintext"]}]})
        );
        a.ok(
            "fleet.epoch_discard",
            json!({"epoch":pending["epoch"],"mint_id":pending["mint_id"]}),
        )
        .await;
        // Mint/discard are audited; the read-only crypto calls are not.
        let after = a.store.read_audit(None).unwrap();
        assert_eq!(after.len(), before.len() + 2);
    }
}

#[tokio::test]
async fn fleet_batch_item_count_accepts_256_refuses_257_and_empty_before_store_access() {
    let root = temp_root("fleet-batch-count");
    let callosum = SharedCallosumStandIn::start(root.path()).await;
    let a = Vault::new(root.path(), 1, &callosum);
    let unavailable = json!({"error":{"code":"fleet_epoch_unavailable","class":"transient"}});
    for (method, item) in [
        ("fleet.epoch_seal_batch", json!({"aad":"","plaintext":""})),
        (
            "fleet.epoch_open_batch",
            json!({"epoch":1,"nonce":URL_SAFE_NO_PAD.encode([0;24]),"ciphertext":URL_SAFE_NO_PAD.encode([0;16]),"aad":""}),
        ),
    ] {
        for count in [1, 256] {
            let expected = if method == "fleet.epoch_open_batch" {
                json!({"items":vec![unavailable.clone();count]})
            } else {
                unavailable.clone()
            };
            assert_eq!(
                a.call_as(
                    "prefrontal",
                    method,
                    json!({"items":vec![item.clone();count]}),
                )
                .await,
                expected,
            );
        }
        for count in [0, 257] {
            assert!(
                matches!(
                    fleet_ops::serve(
                        Arc::clone(&a.store),
                        None,
                        Some(&Principal::Reserved {
                            module_id: "prefrontal".into()
                        }),
                        method,
                        &json!({"items":vec![item.clone();count]})
                    )
                    .await,
                    Answer::InvalidParams
                ),
                "{method} {count}"
            );
        }
    }
}

#[tokio::test]
async fn fleet_batch_bytes_accept_eight_mib_refuse_one_byte_more_before_store_access() {
    let root = temp_root("fleet-batch-bytes");
    let callosum = SharedCallosumStandIn::start(root.path()).await;
    let a = Vault::new(root.path(), 1, &callosum);
    let mib = 1024 * 1024;
    let unavailable = json!({"error":{"code":"fleet_epoch_unavailable","class":"transient"}});
    for (method, item) in [
        (
            "fleet.epoch_seal_batch",
            json!({"aad":URL_SAFE_NO_PAD.encode(vec![0;mib]),"plaintext":URL_SAFE_NO_PAD.encode(vec![0;mib])}),
        ),
        (
            "fleet.epoch_open_batch",
            json!({"epoch":1,"nonce":URL_SAFE_NO_PAD.encode([0;24]),"ciphertext":URL_SAFE_NO_PAD.encode(vec![0;mib]),"aad":URL_SAFE_NO_PAD.encode(vec![0;mib])}),
        ),
    ] {
        let mut items = vec![item; 4];
        let expected = if method == "fleet.epoch_open_batch" {
            json!({"items":vec![unavailable.clone();items.len()]})
        } else {
            unavailable.clone()
        };
        assert_eq!(
            a.call_as("prefrontal", method, json!({"items":items}))
                .await,
            expected,
        );
        items.push(if method.contains("seal") {json!({"aad":"AA","plaintext":""})} else {json!({"epoch":1,"nonce":URL_SAFE_NO_PAD.encode([0;24]),"ciphertext":URL_SAFE_NO_PAD.encode([0;16]),"aad":""})});
        if method.contains("open") {
            items[0]["ciphertext"] = json!(URL_SAFE_NO_PAD.encode(vec![0; mib - 15]));
        }
        assert!(
            matches!(
                fleet_ops::serve(
                    Arc::clone(&a.store),
                    None,
                    Some(&Principal::Reserved {
                        module_id: "prefrontal".into()
                    }),
                    method,
                    &json!({"items":items})
                )
                .await,
                Answer::InvalidParams
            ),
            "{method}"
        );
    }
}

#[tokio::test]
async fn fleet_batch_shared_store_failures_return_no_partial_items() {
    let root = temp_root("fleet-batch-shared-failure");
    let callosum = SharedCallosumStandIn::start(root.path()).await;
    let a = Vault::new(root.path(), 1, &callosum);
    let b = Vault::new(root.path(), 2, &callosum);
    shared_epoch(&a, &b, &callosum).await;
    let request = json!({"aad":"","plaintext":""});
    let sealed = a
        .call_as("prefrontal", "fleet.epoch_seal", request.clone())
        .await;
    let open = open_params(&sealed, "");
    a.remove(2);
    assert_eq!(
        a.call_as(
            "prefrontal",
            "fleet.epoch_seal_batch",
            json!({"items":[request.clone(),request.clone()]})
        )
        .await,
        a.call_as("prefrontal", "fleet.epoch_seal", request.clone())
            .await
    );
    assert_eq!(
        a.call_as(
            "prefrontal",
            "fleet.epoch_open_batch",
            json!({"items":[open.clone(),open.clone()]})
        )
        .await,
        json!({"items":[{"plaintext":""},{"plaintext":""}]})
    );
    let conn = rusqlite::Connection::open(a.fixture.store_path()).unwrap();
    conn.execute("DROP TABLE fleet_epochs", []).unwrap();
    for (batch, single, item) in [
        ("fleet.epoch_seal_batch", "fleet.epoch_seal", request),
        ("fleet.epoch_open_batch", "fleet.epoch_open", open),
    ] {
        let failure = a.call_as("prefrontal", single, item.clone()).await;
        refused(failure.clone(), "store_error", "transient");
        assert_eq!(
            a.call_as(
                "prefrontal",
                batch,
                json!({"items":[item.clone(),item.clone()]})
            )
            .await,
            failure
        );
        let mut malformed = item;
        malformed["aad"] = json!("not canonical=");
        assert!(matches!(
            fleet_ops::serve(
                Arc::clone(&a.store),
                None,
                Some(&Principal::Reserved {
                    module_id: "prefrontal".into()
                }),
                batch,
                &json!({"items":[malformed]})
            )
            .await,
            Answer::InvalidParams
        ));
    }
    let conn = rusqlite::Connection::open(b.fixture.store_path()).unwrap();
    conn.execute(
        "DELETE FROM settings WHERE name = ?1",
        [credentials_core::federation::SELF_MEMBER_SETTING],
    )
    .unwrap();
    for (batch, single, item) in [
        (
            "fleet.epoch_seal_batch",
            "fleet.epoch_seal",
            json!({"aad":"","plaintext":""}),
        ),
        (
            "fleet.epoch_open_batch",
            "fleet.epoch_open",
            open_params(&sealed, ""),
        ),
    ] {
        let expected = b.call_as("prefrontal", single, item.clone()).await;
        refused(expected.clone(), "fleet_epoch_unavailable", "transient");
        assert_eq!(
            b.call_as("prefrontal", batch, json!({"items":[item.clone(),item]}))
                .await,
            expected
        );
    }
}

#[tokio::test]
async fn fleet_batch_grammar_and_each_item_caps_refuse_whole_call_before_store_access() {
    let root = temp_root("fleet-batch-grammar");
    let callosum = SharedCallosumStandIn::start(root.path()).await;
    let a = Vault::new(root.path(), 1, &callosum);
    let conn = rusqlite::Connection::open(a.fixture.store_path()).unwrap();
    conn.execute("DROP TABLE fleet_epochs", []).unwrap();
    let cap = 1024 * 1024;
    for (method, valid) in [
        ("fleet.epoch_seal_batch", json!({"aad":"","plaintext":""})),
        (
            "fleet.epoch_open_batch",
            json!({"epoch":1,"nonce":URL_SAFE_NO_PAD.encode([0;24]),"ciphertext":URL_SAFE_NO_PAD.encode([0;16]),"aad":""}),
        ),
    ] {
        let mut invalid = vec![
            Value::Null,
            json!({}),
            json!({"items":null}),
            json!({"items":[],"domain":"prefrontal"}),
        ];
        for (field, value) in [
            ("aad", json!("Zg==")),
            ("aad", json!("+w")),
            ("aad", json!("Zh")),
            ("aad", json!(URL_SAFE_NO_PAD.encode(vec![0; cap + 1]))),
            ("domain", json!("ck-fleet-epoch-aad/v1")),
            ("caller", json!("entorhinal")),
        ]
        .into_iter()
        .chain(if method.contains("seal") {
            vec![
                ("plaintext", json!(URL_SAFE_NO_PAD.encode(vec![0; cap + 1]))),
                ("plaintext", Value::Null),
            ]
        } else {
            vec![
                ("epoch", json!(0)),
                ("epoch", json!(4294967296u64)),
                ("epoch", json!(-1)),
                ("epoch", json!(1.5)),
                ("epoch", json!("1")),
                ("nonce", json!(URL_SAFE_NO_PAD.encode([0; 23]))),
                ("nonce", json!(URL_SAFE_NO_PAD.encode([0; 25]))),
                ("ciphertext", json!(URL_SAFE_NO_PAD.encode([0; 15]))),
                (
                    "ciphertext",
                    json!(URL_SAFE_NO_PAD.encode(vec![0; cap + 17])),
                ),
            ]
        }) {
            let mut bad = valid.clone();
            bad[field] = value;
            invalid.push(json!({"items":[valid.clone(),bad]}));
        }
        for field in valid.as_object().unwrap().keys() {
            let mut missing = valid.clone();
            missing.as_object_mut().unwrap().remove(field);
            invalid.push(json!({"items":[valid.clone(),missing]}));
        }
        for params in invalid {
            assert!(
                matches!(
                    fleet_ops::serve(
                        Arc::clone(&a.store),
                        None,
                        Some(&Principal::Reserved {
                            module_id: "prefrontal".into()
                        }),
                        method,
                        &params
                    )
                    .await,
                    Answer::InvalidParams
                ),
                "{method}"
            );
        }
    }
}
#[tokio::test]
async fn fleet_positional_arrays_refuse_at_request_item_and_wrap_level_before_store_access() {
    let root = temp_root("fleet-positional");
    let callosum = SharedCallosumStandIn::start(root.path()).await;
    let a = Vault::new(root.path(), 1, &callosum);
    let b = Vault::new(root.path(), 2, &callosum);
    shared_epoch(&a, &b, &callosum).await;
    // The keyed forms of the same values are accepted.
    let sealed = a
        .ok("fleet.epoch_seal", json!({"aad":"","plaintext":""}))
        .await;
    let open = open_params(&sealed, "");
    b.ok("fleet.epoch_open_batch", json!({"items":[open.clone()]}))
        .await;
    // Any store access on `c` would answer with a store error, not invalid_params.
    let c = Vault::new(root.path(), 3, &callosum);
    rusqlite::Connection::open(c.fixture.store_path())
        .unwrap()
        .execute("DROP TABLE fleet_epochs", [])
        .unwrap();
    let positional_open = json!([
        open["epoch"],
        open["nonce"],
        open["ciphertext"],
        open["aad"]
    ]);
    let wrap = json!({"ct":URL_SAFE_NO_PAD.encode([0; 16]),"enc":URL_SAFE_NO_PAD.encode([0; 32]),
        "from":member(1),"to":member(3),"v":"1"});
    let positional_wrap = json!([wrap["ct"], wrap["enc"], wrap["from"], wrap["to"], wrap["v"]]);
    for (method, params) in [
        ("fleet.epoch_seal", json!(["", ""])),
        ("fleet.epoch_open", positional_open.clone()),
        (
            "fleet.epoch_seal_batch",
            json!([[{"aad":"","plaintext":""}]]),
        ),
        ("fleet.epoch_seal_batch", json!({"items":[["", ""]]})),
        ("fleet.epoch_open_batch", json!({"items":[positional_open]})),
        ("fleet.epoch_status", json!([])),
        (
            "fleet.epoch_commit",
            json!([1, URL_SAFE_NO_PAD.encode([0; 16])]),
        ),
        ("fleet.epoch_import", json!([wrap])),
        ("fleet.epoch_import", json!({"wrap":positional_wrap})),
        ("fleet.epoch_wrap_for", json!([member(2)])),
    ] {
        assert!(
            matches!(
                fleet_ops::serve(
                    Arc::clone(&c.store),
                    None,
                    Some(&Principal::Reserved {
                        module_id: "entorhinal".into()
                    }),
                    method,
                    &params
                )
                .await,
                Answer::InvalidParams
            ),
            "{method} {params}"
        );
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
