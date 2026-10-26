//! Sealed static-key transfers between two (sometimes three) real vaults.
//!
//! A is the sender and B the receiver unless a test says otherwise. Each is a real
//! store with its own transfer key and self id. A's `Transfers` sends through A's
//! outbound client to the callosum stand-in, and a handler on the stand-in hands each
//! `federation.transfer_deliver` to B's real `HomeVault` as the attested member A, so a
//! send crosses a real route, is sealed by one vault and opened by the other. B's own
//! callosum lookups (A's pairing, A's announced key) go through B's outbound client to
//! the same stand-in.
//!
//! Tests that need an envelope no honest sender would make (an ineligible body, a
//! reused transfer id, a body for a third vault) seal it by hand with the sender's real
//! transfer key and hand it to the receiver's `HomeVault::serve` directly, which is the
//! same entry point the route reaches.
//!
//! Setup uses the store APIs directly: the admin verbs (`transfer init`, `member
//! grant`, `transfer send|accept|reject`) that will call into these paths are not in
//! this crate's CLI yet.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use claustrum_module_probe::federation::ingress::OP_TRANSFER_DELIVER;
use claustrum_module_probe::federation::transfer::{
    AcceptReport, DeliveryReply, TransferAad, Transfers, TRANSFER_INFO,
};
use claustrum_module_probe::federation::{HomeAnswer, HomeVault};
use credentials_core::audit::{AuditCtx, AuditOp};
use credentials_core::federation::{
    IncomingTransferState, MemberGrantOperation, MemberGrantSelector, OutgoingTransferState,
    VAULT_TRANSFER_ID,
};
use credentials_core::record::{CredentialKind, RecordState, VaultRecord};
use credentials_core::store::{EncryptedStore, SetCategoryMode, SetProvidersMode};
use serde_json::{json, Value};

use crate::support::{
    poll_once, resolved_after_advance, wall_ms, Held, HomeStore, Ledger, Reply, Responder,
    TwoVaults, VaultFixture,
};

const API_ID: &str = "apikey:openai";
const PAIR_A: &str = "pair-a";
const PAIR_C: &str = "pair-c";
const DAY_MS: i64 = 24 * 60 * 60 * 1000;
const C_FINGERPRINT: &str = "cc00cc00cc00cc00cc00cc00cc00cc00";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn audit_count(store: &EncryptedStore, op: AuditOp) -> usize {
    store
        .read_audit(None)
        .unwrap()
        .into_iter()
        .filter(|entry| entry.op == op.as_str())
        .count()
}

fn refused_code(reply: &DeliveryReply) -> &str {
    reply.code()
}

/// The `error.code` of a reply body, or its `state`.
fn answer(home_answer: HomeAnswer) -> String {
    match home_answer {
        HomeAnswer::Reply(body) => body
            .get("state")
            .and_then(Value::as_str)
            .or_else(|| body["error"]["code"].as_str())
            .unwrap_or("?")
            .to_string(),
        HomeAnswer::InvalidParams(detail) => format!("invalid_params:{detail}"),
    }
}

// ---------------------------------------------------------------------------------
// One vault
// ---------------------------------------------------------------------------------

/// One member's vault: its store, its transfer key, its home side (which receives
/// deliveries) and its transfer admin ops, on a clock offset from real time.
struct Vault {
    member: String,
    home_store: HomeStore,
    pem: String,
    public: Vec<u8>,
    home: Arc<HomeVault>,
    transfers: Transfers,
    clock_offset: Arc<AtomicI64>,
}

impl Vault {
    /// Open the vault over `fixture`'s data directory. On first open the transfer key
    /// is created and the self id set, as `transfer init --self` does.
    fn open(fixture: &VaultFixture, first: bool, budget: Duration) -> Self {
        let home_store = HomeStore::open(&fixture.data_dir);
        let store = Arc::clone(&home_store.store);
        if first {
            let pem = credentials_core::kem::generate_key().expect("transfer key");
            store
                .create_audited(
                    VAULT_TRANSFER_ID,
                    &VaultRecord::new_static(
                        CredentialKind::KemKey,
                        "operator",
                        pem.into_bytes(),
                        None,
                    ),
                    AuditCtx::admin(AuditOp::Put),
                )
                .expect("transfer init");
            store
                .set_federation_self_member_audited(
                    &fixture.member.member_id,
                    AuditCtx::admin(AuditOp::FederationSelfSet),
                )
                .expect("self id");
        }
        let pem = String::from_utf8(
            store
                .get(VAULT_TRANSFER_ID)
                .unwrap()
                .payload
                .expose()
                .to_vec(),
        )
        .unwrap();
        let (public, _) = credentials_core::kem::public_half(&pem).unwrap();
        let home = HomeVault::new(Arc::clone(&home_store.engine));
        assert!(home.attach_outbound(fixture.outbound.clone()));
        let clock_offset = Arc::new(AtomicI64::new(0));
        let offset = Arc::clone(&clock_offset);
        let transfers = Transfers::new(Arc::clone(&store))
            .with_clock(Arc::new(move || wall_ms() + offset.load(Ordering::SeqCst)))
            .with_budget(budget);
        assert!(transfers.attach_outbound(fixture.outbound.clone()));
        Self {
            member: fixture.member.member_id.clone(),
            home_store,
            pem,
            public,
            home: Arc::new(home),
            transfers,
            clock_offset,
        }
    }

    fn store(&self) -> &EncryptedStore {
        &self.home_store.store
    }

    fn key_id(&self) -> String {
        credentials_core::kem::public_half(&self.pem).unwrap().1
    }

    fn advance(&self, ms: i64) {
        self.clock_offset.fetch_add(ms, Ordering::SeqCst);
    }

    fn incoming(&self) -> Vec<credentials_core::federation::IncomingTransfer> {
        self.store().list_incoming_transfers().unwrap()
    }

    fn pending(&self) -> usize {
        self.incoming()
            .iter()
            .filter(|row| row.state == IncomingTransferState::Pending)
            .count()
    }

    /// Re-read the transfer key after a recovery replaced it.
    fn reload_key(&mut self) {
        self.pem = String::from_utf8(
            self.store()
                .get(VAULT_TRANSFER_ID)
                .unwrap()
                .payload
                .expose()
                .to_vec(),
        )
        .unwrap();
        self.public = credentials_core::kem::public_half(&self.pem).unwrap().0;
    }

    /// `transfer init --replace` after the key is found off `Active` (forced through
    /// the test-only store hook), then re-read the new key.
    fn recover_key(&mut self) -> credentials_core::federation::TransferKeyRecovery {
        assert!(self
            .store()
            .force_vault_transfer_key_state_for_test(RecordState::NeedsReauth)
            .unwrap());
        let recovery = self
            .transfers
            .replace_transfer_key("route-admin")
            .expect("recovery off Active");
        self.reload_key();
        recovery
    }

    /// Hand-seal `body` from this vault to `to` under `transfer_id`, as delivery params.
    fn hand_seal(&self, to: &Vault, transfer_id: &str, credential_id: &str, body: &Value) -> Value {
        self.hand_seal_with(to, transfer_id, credential_id, body, TRANSFER_INFO)
    }

    fn hand_seal_with(
        &self,
        to: &Vault,
        transfer_id: &str,
        credential_id: &str,
        body: &Value,
        info: &[u8],
    ) -> Value {
        let aad = serde_json::to_string(&TransferAad {
            transfer_id: transfer_id.to_string(),
            credential_id: credential_id.to_string(),
            sender: self.member.clone(),
            receiver: to.member.clone(),
            recipient_key_id: to.key_id(),
        })
        .unwrap();
        let (enc, ciphertext) = credentials_core::kem::seal_auth(
            &self.pem,
            &to.public,
            &serde_json::to_vec(body).unwrap(),
            info,
            aad.as_bytes(),
        )
        .expect("hand seal");
        let b64 = base64::engine::general_purpose::STANDARD;
        json!({ "enc": b64.encode(enc), "ciphertext": b64.encode(ciphertext), "aad": aad })
    }
}

/// A transfer body exactly as an honest sender builds one, which a test then bends.
fn body(credential_id: &str, kind: &str, payload: &[u8]) -> Value {
    json!({
        "version": 1,
        "credential_id": credential_id,
        "kind": kind,
        "payload": base64::engine::general_purpose::STANDARD.encode(payload),
        "categories": ["ops-secrets"],
        "identity": {},
        "provider_ids": ["openai"],
        "detected_plan": null,
        "expires_at_ms": null,
    })
}

/// A distinct transfer id per index.
fn tid(index: u32) -> String {
    format!("{:032x}", 0xabc000 + index)
}

// ---------------------------------------------------------------------------------
// Scripted deliveries
// ---------------------------------------------------------------------------------

/// What the stand-in does with one delivery, when a test does not want B's answer.
#[derive(Clone, Debug)]
enum Step {
    /// B's real answer.
    Forward,
    /// B processes the delivery, then the reply is lost: the lost acknowledgement.
    ForwardThenDrop(Held),
    /// The receiver is never reached: callosum refuses with this class.
    Unreachable(&'static str),
}

type Script = Arc<Mutex<VecDeque<Step>>>;

fn deliver_responder(home: Arc<HomeVault>, sender: String, script: Script) -> Responder {
    Responder(Arc::new(move |params: Value| {
        let step = script.lock().unwrap().pop_front().unwrap_or(Step::Forward);
        let home = Arc::clone(&home);
        let sender = sender.clone();
        Box::pin(async move {
            match step {
                Step::Unreachable(code) => Reply::RouteRefusal(code.into()),
                Step::Forward | Step::ForwardThenDrop(_) => {
                    let reply = match home.serve(&sender, OP_TRANSFER_DELIVER, &params).await {
                        HomeAnswer::Reply(body) => Reply::Ok(body),
                        HomeAnswer::InvalidParams(_) => {
                            Reply::RouteRefusal("invalid_params".into())
                        }
                    };
                    match step {
                        Step::ForwardThenDrop(held) => Reply::Hold(held),
                        _ => reply,
                    }
                }
            }
        })
    }))
}

// ---------------------------------------------------------------------------------
// The rig
// ---------------------------------------------------------------------------------

/// A budget long enough for a healthy send, short enough that a lost reply ends the
/// call quickly.
const SEND_BUDGET: Duration = Duration::from_secs(3);

struct Rig {
    root: credentials_core::test_support::TestTempDir,
    vaults: TwoVaults,
    a: Vault,
    b: Vault,
    script: Script,
}

impl Rig {
    async fn new(tag: &str) -> Self {
        let root = crate::support::temp_root(tag);
        let vaults = TwoVaults::new(&root).await;
        let a = Vault::open(&vaults.a, true, SEND_BUDGET);
        let b = Vault::open(&vaults.b, true, SEND_BUDGET);
        vaults
            .callosum
            .announce_peer_key(&a.member, &hex(&a.public));
        vaults
            .callosum
            .announce_peer_key(&b.member, &hex(&b.public));
        vaults.callosum.set_pairing(&a.member, Some(PAIR_A));
        b.store()
            .create_member_grant_audited(
                &a.member,
                MemberGrantOperation::TransferDeliver,
                &MemberGrantSelector::None,
                PAIR_A,
            )
            .expect("transfer_deliver grant");
        let script: Script = Arc::default();
        let rig = Self {
            root,
            vaults,
            a,
            b,
            script,
        };
        rig.route_deliveries();
        rig
    }

    /// Point the stand-in's `federation.transfer_deliver` at B's home, as member A.
    fn route_deliveries(&self) {
        self.vaults.callosum.answer(
            crate::support::TARGET_MODULE,
            OP_TRANSFER_DELIVER,
            Reply::Handler(deliver_responder(
                Arc::clone(&self.b.home),
                self.a.member.clone(),
                Arc::clone(&self.script),
            )),
        );
    }

    /// Script one callosum lookup to fail as callosum says "not ready".
    fn stall_lookup(&self, method: &str) {
        self.vaults.callosum.answer(
            crate::support::TARGET_MODULE,
            method,
            Reply::RouteRefusal("fed_not_ready".into()),
        );
    }

    /// Undo [`Self::stall_lookup`]: forget every scripted answer, then route deliveries
    /// again (the lookups fall back to the recorded pairings and keys).
    fn heal_lookups(&self) {
        self.vaults.callosum.forget_answers();
        self.route_deliveries();
    }

    fn then(&self, step: Step) {
        self.script.lock().unwrap().push_back(step);
    }

    /// A static API key on A, with categories and provider ids that differ from the
    /// catalog defaults, so a test can tell the body's apart from a fresh record's.
    fn api_key_on_a(&self, id: &str, secret: &[u8]) {
        let store = self.a.store();
        store
            .create(
                id,
                &VaultRecord::new_static(CredentialKind::ApiKey, "operator", secret.to_vec(), None),
            )
            .expect("create api key");
        store
            .set_categories_audited(
                id,
                SetCategoryMode::Set,
                &["ops-secrets".to_string()],
                AuditCtx::admin(AuditOp::SetCategory),
            )
            .unwrap();
        store
            .set_providers_audited(
                id,
                SetProvidersMode::Set,
                &["openai".to_string(), "azure".to_string()],
                AuditCtx::admin(AuditOp::SetProviders),
            )
            .unwrap();
    }

    /// Every `federation.transfer_deliver` params the stand-in received, in order.
    fn deliveries(&self) -> Vec<Value> {
        self.vaults
            .callosum
            .ledger()
            .into_iter()
            .filter_map(|row| match row {
                Ledger::Request { method, params, .. } if method == OP_TRANSFER_DELIVER => {
                    Some(params)
                }
                _ => None,
            })
            .collect()
    }

    async fn serve_b(&self, from: &str, params: &Value) -> String {
        answer(self.b.home.serve(from, OP_TRANSFER_DELIVER, params).await)
    }

    /// Restart A: everything in memory is dropped and A's store is opened again.
    fn restart_a(self) -> Self {
        let Rig {
            root,
            vaults,
            a,
            b,
            script,
        } = self;
        drop(a);
        let a = Vault::open(&vaults.a, false, SEND_BUDGET);
        Rig {
            root,
            vaults,
            a,
            b,
            script,
        }
    }

    /// A third vault, C, paired and granted `transfer_deliver` on B, with its key
    /// announced.
    fn vault_c(&self) -> (VaultFixture, Vault) {
        let fixture =
            VaultFixture::new(&self.root, "vault-c", C_FINGERPRINT, &self.vaults.callosum);
        let c = Vault::open(&fixture, true, SEND_BUDGET);
        self.vaults
            .callosum
            .announce_peer_key(&c.member, &hex(&c.public));
        self.vaults.callosum.set_pairing(&c.member, Some(PAIR_C));
        self.b
            .store()
            .create_member_grant_audited(
                &c.member,
                MemberGrantOperation::TransferDeliver,
                &MemberGrantSelector::None,
                PAIR_C,
            )
            .unwrap();
        (fixture, c)
    }
}

// ---------------------------------------------------------------------------------
// Send, deliver, accept
// ---------------------------------------------------------------------------------

/// An API key sent A to B exists on B only after accept, with its id, the body's
/// categories (not the catalog defaults) and its provider ids; each side audits once.
#[tokio::test]
async fn an_api_key_sent_a_to_b_exists_on_b_only_after_accept() {
    let rig = Rig::new("transfer-happy").await;
    rig.api_key_on_a(API_ID, b"sk-transfer-secret");

    let sent = rig
        .a
        .transfers
        .send(API_ID, &rig.b.member)
        .await
        .expect("send");
    assert_eq!(
        sent.reply,
        DeliveryReply::State(IncomingTransferState::Pending)
    );
    assert!(sent.row_kept, "a pending reply keeps the outgoing row");
    assert_eq!(sent.credential_id, API_ID);
    assert_eq!(sent.receiver, rig.b.member);
    assert!(
        rig.b.store().get(API_ID).is_err(),
        "nothing exists before accept"
    );

    let waiting = rig.b.transfers.receive().unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].sender_member, rig.a.member);
    assert_eq!(waiting[0].transfer_id, sent.transfer_id);
    assert_eq!(waiting[0].credential_id, API_ID);
    assert_eq!(waiting[0].kind, "api_key");
    assert_eq!(waiting[0].categories, vec!["ops-secrets".to_string()]);

    let accepted = rig
        .b
        .transfers
        .accept(&sent.transfer_id, &rig.a.member, false)
        .await
        .expect("accept");
    assert_eq!(
        accepted,
        AcceptReport::Accepted {
            credential_id: API_ID.to_string(),
            record_version: 1
        }
    );
    let record = rig.b.store().get(API_ID).unwrap();
    assert_eq!(record.payload.expose(), b"sk-transfer-secret");
    assert_eq!(record.kind, CredentialKind::ApiKey);
    assert_eq!(record.source, "transfer");
    assert_eq!(
        rig.b.store().categories(API_ID).unwrap(),
        vec!["ops-secrets".to_string()],
        "the body's categories, not the catalog's llm-provider default"
    );
    assert_eq!(
        rig.b.store().provider_ids(API_ID).unwrap(),
        vec!["azure".to_string(), "openai".to_string()]
    );
    assert_eq!(audit_count(rig.b.store(), AuditOp::TransferIn), 1);
    assert_eq!(audit_count(rig.a.store(), AuditOp::TransferOut), 1);

    // The sender learns the outcome on its next resume and drops its row.
    let resumed = rig.a.transfers.resume(&sent.transfer_id).await.unwrap();
    assert_eq!(
        resumed.reply,
        DeliveryReply::State(IncomingTransferState::Accepted)
    );
    assert!(!resumed.row_kept);
    assert!(rig
        .a
        .store()
        .outgoing_transfer(&sent.transfer_id)
        .unwrap()
        .is_none());
    assert!(rig.a.store().verify_audit_chain().is_ok());
    assert!(rig.b.store().verify_audit_chain().is_ok());
}

/// Dedup runs before open: an accepted envelope delivered again as a new delivery is
/// answered from the dedup on (sender, body hash) before anything is opened:
/// `accepted`, with no pending row, no record change and no second `transfer_in`.
#[tokio::test]
async fn replaying_an_accepted_envelope_as_a_new_delivery_answers_accepted_and_writes_nothing() {
    let rig = Rig::new("transfer-replay").await;
    rig.api_key_on_a(API_ID, b"sk-replay");
    let sent = rig.a.transfers.send(API_ID, &rig.b.member).await.unwrap();
    rig.b
        .transfers
        .accept(&sent.transfer_id, &rig.a.member, false)
        .await
        .unwrap();
    let envelope = rig.deliveries().pop().expect("the delivered envelope");
    let version = rig.b.store().get(API_ID).unwrap().record_version;

    assert_eq!(rig.serve_b(&rig.a.member, &envelope).await, "accepted");
    assert_eq!(rig.b.pending(), 0, "no pending row");
    assert_eq!(rig.b.incoming().len(), 1, "no second entry of any kind");
    assert_eq!(rig.b.store().get(API_ID).unwrap().record_version, version);
    assert_eq!(audit_count(rig.b.store(), AuditOp::TransferIn), 1);
}

/// A same-hash resend after the sender's grant is revoked answers the uniform
/// `not_found`, and the sender drops its row.
#[tokio::test]
async fn a_same_hash_resend_after_the_grant_is_revoked_answers_not_found() {
    let rig = Rig::new("transfer-revoked").await;
    rig.api_key_on_a(API_ID, b"sk-revoked");
    let sent = rig.a.transfers.send(API_ID, &rig.b.member).await.unwrap();
    rig.b
        .store()
        .revoke_member_grant_audited(
            &rig.a.member,
            MemberGrantOperation::TransferDeliver,
            &MemberGrantSelector::None,
        )
        .unwrap();
    let resumed = rig.a.transfers.resume(&sent.transfer_id).await.unwrap();
    assert_eq!(refused_code(&resumed.reply), "not_found");
    assert!(!resumed.row_kept);
    assert!(rig
        .a
        .store()
        .outgoing_transfer(&sent.transfer_id)
        .unwrap()
        .is_none());
}

/// Send commits before delivery: a fault between the outgoing insert and the
/// `transfer_out` write leaves neither, and nothing is delivered.
#[tokio::test]
async fn a_fault_between_the_outgoing_insert_and_transfer_out_sends_nothing() {
    let rig = Rig::new("transfer-commit-fault").await;
    rig.api_key_on_a(API_ID, b"sk-fault");
    let faulty = Transfers::new(Arc::clone(&rig.a.home_store.store))
        .with_budget(SEND_BUDGET)
        .with_commit_fault(Arc::new(|| true));
    assert!(faulty.attach_outbound(rig.vaults.a.outbound.clone()));
    let refused = faulty.send(API_ID, &rig.b.member).await.unwrap_err();
    assert_eq!(refused.code, "store_error");
    assert!(rig.a.store().list_outgoing_transfers().unwrap().is_empty());
    assert_eq!(audit_count(rig.a.store(), AuditOp::TransferOut), 0);
    assert!(rig.deliveries().is_empty(), "nothing was sent");
    assert!(rig.b.incoming().is_empty());
}

/// Send commits before delivery: a crash after the commit and before delivery, then
/// `--resume`: exactly one `transfer_out`, one pending row on the receiver, and the
/// bytes delivered are the ones committed.
#[tokio::test]
async fn a_crash_after_the_commit_then_resume_yields_one_transfer_out_and_one_pending_row() {
    let rig = Rig::new("transfer-crash").await;
    rig.api_key_on_a(API_ID, b"sk-crash");
    // The delivery never reaches B: the shape of a crash between commit and delivery,
    // as far as anything outside A can tell.
    rig.then(Step::Unreachable("fed_target_unavailable"));
    let sent = rig.a.transfers.send(API_ID, &rig.b.member).await.unwrap();
    assert!(sent.row_kept);
    assert_eq!(refused_code(&sent.reply), "home_unreachable");
    assert!(rig.b.incoming().is_empty());
    let committed = rig
        .a
        .store()
        .outgoing_transfer(&sent.transfer_id)
        .unwrap()
        .unwrap();

    let rig = rig.restart_a();
    let resumed = rig.a.transfers.resume(&sent.transfer_id).await.unwrap();
    assert_eq!(
        resumed.reply,
        DeliveryReply::State(IncomingTransferState::Pending)
    );
    assert_eq!(audit_count(rig.a.store(), AuditOp::TransferOut), 1);
    assert_eq!(rig.b.pending(), 1);
    let b64 = base64::engine::general_purpose::STANDARD;
    for delivered in rig.deliveries() {
        assert_eq!(delivered["enc"], b64.encode(&committed.sealed.enc));
        assert_eq!(
            delivered["ciphertext"],
            b64.encode(&committed.sealed.ciphertext)
        );
        assert_eq!(
            delivered["aad"],
            String::from_utf8(committed.sealed.aad.clone()).unwrap()
        );
    }
    assert_eq!(
        rig.deliveries().len(),
        2,
        "the refused attempt and the resume"
    );
}

/// The lost acknowledgement, step by step.
#[tokio::test]
async fn a_lost_acknowledgement_resolves_stepwise_through_resume_and_accept() {
    let rig = Rig::new("transfer-lost-ack").await;
    rig.api_key_on_a(API_ID, b"sk-lost-ack");

    // Deliver with the reply dropped: one pending row, one transfer_out, no transfer_in.
    let lost_ack = Held::new();
    rig.then(Step::ForwardThenDrop(lost_ack.clone()));
    let sender = Transfers::new(Arc::clone(&rig.a.home_store.store)).with_budget(SEND_BUDGET);
    assert!(sender.attach_outbound(rig.vaults.a.outbound.clone()));
    let to = rig.b.member.clone();
    let mut send = tokio::spawn(async move { sender.send(API_ID, &to).await });
    lost_ack.arrived_before(&mut send).await;
    tokio::time::pause();
    let sent = resolved_after_advance(send, SEND_BUDGET + Duration::from_millis(1))
        .await
        .unwrap();
    tokio::time::resume();
    assert_eq!(refused_code(&sent.reply), "home_unreachable");
    assert!(sent.row_kept);
    assert_eq!(rig.b.pending(), 1);
    assert_eq!(audit_count(rig.a.store(), AuditOp::TransferOut), 1);
    assert_eq!(audit_count(rig.b.store(), AuditOp::TransferIn), 0);

    // --resume: pending, counts unchanged.
    let resumed = rig.a.transfers.resume(&sent.transfer_id).await.unwrap();
    assert_eq!(
        resumed.reply,
        DeliveryReply::State(IncomingTransferState::Pending)
    );
    assert!(resumed.row_kept);
    assert_eq!(rig.b.pending(), 1);
    assert_eq!(rig.b.incoming().len(), 1);
    assert_eq!(audit_count(rig.a.store(), AuditOp::TransferOut), 1);
    assert_eq!(audit_count(rig.b.store(), AuditOp::TransferIn), 0);

    // accept: the entry is accepted, one transfer_in.
    rig.b
        .transfers
        .accept(&sent.transfer_id, &rig.a.member, false)
        .await
        .unwrap();
    let entry = rig
        .b
        .store()
        .incoming_transfer(&rig.a.member, &sent.transfer_id)
        .unwrap()
        .unwrap();
    assert_eq!(entry.state, IncomingTransferState::Accepted);
    assert_eq!(audit_count(rig.b.store(), AuditOp::TransferIn), 1);

    // --resume: accepted, A's outgoing row deleted, counts unchanged.
    let resumed = rig.a.transfers.resume(&sent.transfer_id).await.unwrap();
    assert_eq!(
        resumed.reply,
        DeliveryReply::State(IncomingTransferState::Accepted)
    );
    assert!(!resumed.row_kept);
    assert!(rig
        .a
        .store()
        .outgoing_transfer(&sent.transfer_id)
        .unwrap()
        .is_none());
    assert_eq!(rig.b.incoming().len(), 1);
    assert_eq!(audit_count(rig.a.store(), AuditOp::TransferOut), 1);
    assert_eq!(audit_count(rig.b.store(), AuditOp::TransferIn), 1);
    // A resume of the deleted row says so.
    let gone = rig.a.transfers.resume(&sent.transfer_id).await.unwrap_err();
    assert_eq!(gone.code, "transfer_gone");
}

/// Same transfer id with a different hash is `transfer_conflict`, with no row.
#[tokio::test]
async fn the_same_transfer_id_with_a_different_hash_is_a_conflict() {
    let rig = Rig::new("transfer-conflict").await;
    let first = rig
        .a
        .hand_seal(&rig.b, &tid(1), API_ID, &body(API_ID, "api_key", b"one"));
    let second = rig
        .a
        .hand_seal(&rig.b, &tid(1), API_ID, &body(API_ID, "api_key", b"two"));
    assert_eq!(rig.serve_b(&rig.a.member, &first).await, "pending");
    assert_eq!(
        rig.serve_b(&rig.a.member, &second).await,
        "transfer_conflict"
    );
    assert_eq!(rig.b.incoming().len(), 1);
}

/// Expiry: a same-hash resend of an expired transfer answers `transfer_expired` (the
/// sender drops its row), and a resend of an accepted transfer after the expiry sweep
/// still answers `accepted`.
#[tokio::test]
async fn expiry_answers_transfer_expired_but_an_accepted_resend_stays_accepted() {
    let rig = Rig::new("transfer-expiry").await;
    rig.api_key_on_a(API_ID, b"sk-expiry");
    rig.api_key_on_a("apikey:anthropic", b"sk-accepted");
    let expiring = rig.a.transfers.send(API_ID, &rig.b.member).await.unwrap();
    let accepted = rig
        .a
        .transfers
        .send("apikey:anthropic", &rig.b.member)
        .await
        .unwrap();
    rig.b
        .transfers
        .accept(&accepted.transfer_id, &rig.a.member, false)
        .await
        .unwrap();

    rig.b.advance(8 * DAY_MS);
    assert_eq!(rig.b.transfers.expire().unwrap().0, 1);
    let row = rig
        .b
        .store()
        .incoming_transfer(&rig.a.member, &expiring.transfer_id)
        .unwrap()
        .unwrap();
    assert_eq!(row.state, IncomingTransferState::Expired);
    assert!(row.sealed.is_none(), "expiry purges the sealed bytes");
    assert!(rig.b.transfers.receive().unwrap().is_empty());

    let resent = rig.a.transfers.resume(&expiring.transfer_id).await.unwrap();
    assert_eq!(refused_code(&resent.reply), "transfer_expired");
    assert!(!resent.row_kept);
    let resent = rig.a.transfers.resume(&accepted.transfer_id).await.unwrap();
    assert_eq!(
        resent.reply,
        DeliveryReply::State(IncomingTransferState::Accepted)
    );
    assert_eq!(audit_count(rig.b.store(), AuditOp::TransferIn), 1);
}

/// Two senders using one transfer id are accepted or rejected independently, chosen
/// by `--from`.
#[tokio::test]
async fn two_senders_using_one_transfer_id_are_decided_independently() {
    let rig = Rig::new("transfer-two-senders").await;
    let (_c_fixture, c) = rig.vault_c();
    let from_a = rig
        .a
        .hand_seal(&rig.b, &tid(7), API_ID, &body(API_ID, "api_key", b"from-a"));
    let from_c = rig.c_seal(&c, &tid(7), "apikey:groq", b"from-c");
    assert_eq!(rig.serve_b(&rig.a.member, &from_a).await, "pending");
    assert_eq!(rig.serve_b(&c.member, &from_c).await, "pending");

    let accepted = rig
        .b
        .transfers
        .accept(&tid(7), &rig.a.member, false)
        .await
        .unwrap();
    assert!(
        matches!(accepted, AcceptReport::Accepted { .. }),
        "{accepted:?}"
    );
    assert_eq!(
        rig.b.transfers.reject(&tid(7), &c.member).unwrap(),
        IncomingTransferState::Rejected
    );
    assert_eq!(
        rig.b.store().get(API_ID).unwrap().payload.expose(),
        b"from-a"
    );
    assert!(rig.b.store().get("apikey:groq").is_err());
    let from_c_row = rig
        .b
        .store()
        .incoming_transfer(&c.member, &tid(7))
        .unwrap()
        .unwrap();
    assert_eq!(from_c_row.state, IncomingTransferState::Rejected);
    assert_eq!(audit_count(rig.b.store(), AuditOp::TransferReject), 1);
}

impl Rig {
    fn c_seal(&self, c: &Vault, transfer_id: &str, id: &str, secret: &[u8]) -> Value {
        c.hand_seal(&self.b, transfer_id, id, &body(id, "api_key", secret))
    }
}

/// The envelope A sealed for B, replayed to a third vault, does not open there.
#[tokio::test]
async fn an_envelope_replayed_to_a_third_vault_does_not_open() {
    let rig = Rig::new("transfer-third-vault").await;
    let (_c_fixture, c) = rig.vault_c();
    c.store()
        .create_member_grant_audited(
            &rig.a.member,
            MemberGrantOperation::TransferDeliver,
            &MemberGrantSelector::None,
            PAIR_A,
        )
        .unwrap();
    rig.api_key_on_a(API_ID, b"sk-for-b-only");
    rig.a.transfers.send(API_ID, &rig.b.member).await.unwrap();
    let envelope = rig.deliveries().pop().unwrap();
    let answer = answer(
        c.home
            .serve(&rig.a.member, OP_TRANSFER_DELIVER, &envelope)
            .await,
    );
    assert_eq!(answer, "remote_seal_invalid");
    assert!(c.incoming().is_empty());
}

// ---------------------------------------------------------------------------------
// Eligibility and receive-side validation
// ---------------------------------------------------------------------------------

/// `send` refuses every ineligible record before anything is looked up or committed.
#[tokio::test]
async fn send_refuses_logins_and_vault_held_keys() {
    let rig = Rig::new("transfer-send-ineligible").await;
    let store = rig.a.store();
    let rotating = VaultRecord::new_oauth(
        "opencode",
        "anthropic",
        credentials_core::oauth::OAuthCredential {
            access_token: "access".to_string().into(),
            refresh_token: "refresh".to_string().into(),
            expires_at_ms: None,
            token_url: "https://token.test/oauth".into(),
            client_id: None,
            client_secret: None,
            scopes: vec![],
        },
        b"access".to_vec(),
    );
    let mut not_rotating = rotating.clone();
    not_rotating.refresh_adapter = None;
    store.create("oauth:anthropic:work", &rotating).unwrap();
    store.create("oauth:custom:static", &not_rotating).unwrap();
    store
        .create(
            "signing:agent:1",
            &VaultRecord::new_static(
                CredentialKind::SigningKey,
                "operator",
                b"pem".to_vec(),
                None,
            ),
        )
        .unwrap();
    store
        .create(
            "kem:push",
            &VaultRecord::new_static(
                CredentialKind::KemKey,
                "operator",
                credentials_core::kem::generate_key().unwrap().into_bytes(),
                None,
            ),
        )
        .unwrap();
    for (id, reason) in [
        ("oauth:anthropic:work", "oauth"),
        ("oauth:custom:static", "oauth"),
        ("signing:agent:1", "signing_key"),
        ("kem:push", "kem_key"),
        (VAULT_TRANSFER_ID, "transfer_key"),
    ] {
        let refused = rig.a.transfers.send(id, &rig.b.member).await.unwrap_err();
        assert_eq!(refused.code, "transfer_ineligible", "{id}");
        assert_eq!(refused.reason, Some(reason), "{id}");
    }
    assert!(store.list_outgoing_transfers().unwrap().is_empty());
    assert_eq!(audit_count(store, AuditOp::TransferOut), 0);
    assert!(rig.deliveries().is_empty());
}

/// Hand-sealed, validly encrypted bodies that are not eligible are refused at delivery
/// as `transfer_body_invalid`, with no pending row and no record.
#[tokio::test]
async fn hand_sealed_oauth_and_other_ineligible_bodies_are_refused_at_delivery() {
    let rig = Rig::new("transfer-ineligible-delivery").await;
    for (index, sealed_body) in ineligible_bodies().into_iter().enumerate() {
        let params = rig
            .a
            .hand_seal(&rig.b, &tid(index as u32), API_ID, &sealed_body);
        assert_eq!(
            rig.serve_b(&rig.a.member, &params).await,
            "transfer_body_invalid",
            "{sealed_body}"
        );
    }
    assert!(rig.b.incoming().is_empty());
    assert!(rig.b.store().get(API_ID).is_err());
}

/// The bodies no transfer may carry: logins (with and without OAuth material), the
/// vault-held key kinds, a cookie with an expiry.
fn ineligible_bodies() -> Vec<Value> {
    let mut bodies = Vec::new();
    bodies.push(body(API_ID, "oauth", b"access-token"));
    let mut with_oauth = body(API_ID, "oauth", b"access-token");
    with_oauth["oauth"] = json!({ "refresh_token": "refresh" });
    bodies.push(with_oauth);
    // An allowed kind carrying a refresh adapter or OAuth material. The body format has
    // no field for either, so these are refused at parse (unknown field); the
    // eligibility check never sees them.
    let mut with_adapter = body(API_ID, "api_key", b"sk");
    with_adapter["refresh_adapter"] = json!("anthropic");
    bodies.push(with_adapter);
    let mut api_key_with_oauth = body(API_ID, "api_key", b"sk");
    api_key_with_oauth["oauth"] = json!({ "access_token": "a", "refresh_token": "r" });
    bodies.push(api_key_with_oauth);
    bodies.push(body(API_ID, "signing_key", b"pem"));
    bodies.push(body(API_ID, "kem_key", b"pem"));
    let mut cookie = body(API_ID, "cookie", b"session=abc");
    cookie["expires_at_ms"] = json!(wall_ms() + DAY_MS);
    bodies.push(cookie);
    bodies
}

/// The bodies that pass eligibility but fail a field rule.
fn malformed_bodies() -> Vec<(&'static str, Value)> {
    let mut tier = body(API_ID, "api_key", b"sk");
    tier["detected_plan"] = json!({ "tier": "MAX!", "raw": null, "observed_at_ms": 1 });
    let mut category = body(API_ID, "api_key", b"sk");
    category["categories"] = json!(["Not A Category"]);
    let mut provider = body(API_ID, "api_key", b"sk");
    provider["provider_ids"] = json!(["Bad_Provider"]);
    let mut identity = body(API_ID, "api_key", b"sk");
    identity["identity"] = json!({ "account_id": "a\u{7}b" });
    let mut version = body(API_ID, "api_key", b"sk");
    version["version"] = json!(2);
    let mut unknown = body(API_ID, "api_key", b"sk");
    unknown["note"] = json!("unknown fields are refused");
    vec![
        ("tier", tier),
        ("category", category),
        ("provider", provider),
        ("identity", identity),
        ("version", version),
        ("unknown", unknown),
    ]
}

/// A bad plan tier, a bad category and a bad provider id (and the other field rules)
/// are each refused at delivery.
#[tokio::test]
async fn hand_sealed_bodies_with_a_bad_tier_category_or_provider_id_are_refused_at_delivery() {
    let rig = Rig::new("transfer-malformed-delivery").await;
    for (index, (what, sealed_body)) in malformed_bodies().into_iter().enumerate() {
        let params = rig
            .a
            .hand_seal(&rig.b, &tid(100 + index as u32), API_ID, &sealed_body);
        assert_eq!(
            rig.serve_b(&rig.a.member, &params).await,
            "transfer_body_invalid",
            "{what}"
        );
    }
    assert!(rig.b.incoming().is_empty());
}

/// Validation runs again at accept: a pending row whose body is ineligible or
/// malformed (recorded here without the delivery checks, the way a row from an older
/// build or a damaged store would look) is refused `transfer_body_invalid`, marked
/// rejected with one `transfer_reject` row, and no record, version or handle changes.
#[tokio::test]
async fn hand_sealed_ineligible_and_malformed_bodies_are_refused_at_accept() {
    let rig = Rig::new("transfer-invalid-accept").await;
    // An existing record of the same id, so a version change would show.
    rig.b
        .store()
        .create(
            API_ID,
            &VaultRecord::new_static(
                CredentialKind::ApiKey,
                "operator",
                b"keep-me".to_vec(),
                None,
            ),
        )
        .unwrap();
    let mut bodies = ineligible_bodies();
    bodies.extend(malformed_bodies().into_iter().map(|(_, body)| body));
    for (index, sealed_body) in bodies.iter().enumerate() {
        let transfer_id = tid(200 + index as u32);
        let params = rig.a.hand_seal(&rig.b, &transfer_id, API_ID, sealed_body);
        record_pending_unchecked(rig.b.store(), &rig.a.member, &transfer_id, &params);
        let refused = rig
            .b
            .transfers
            .accept(&transfer_id, &rig.a.member, true)
            .await
            .unwrap_err();
        assert_eq!(refused.code, "transfer_body_invalid", "{sealed_body}");
        let row = rig
            .b
            .store()
            .incoming_transfer(&rig.a.member, &transfer_id)
            .unwrap()
            .unwrap();
        assert_eq!(row.state, IncomingTransferState::Rejected, "{sealed_body}");
    }
    let record = rig.b.store().get(API_ID).unwrap();
    assert_eq!(record.payload.expose(), b"keep-me");
    assert_eq!(record.record_version, 1);
    assert_eq!(rig.b.pending(), 0);
    assert_eq!(audit_count(rig.b.store(), AuditOp::TransferIn), 0);
    assert_eq!(
        audit_count(rig.b.store(), AuditOp::TransferReject),
        bodies.len()
    );
}

/// Record `params` as a pending transfer straight through the store, skipping the
/// delivery checks, so a test can reach accept with a body delivery would refuse.
fn record_pending_unchecked(
    store: &EncryptedStore,
    sender: &str,
    transfer_id: &str,
    params: &Value,
) {
    let b64 = base64::engine::general_purpose::STANDARD;
    let inserted = store
        .insert_incoming_transfer(&credentials_core::federation::NewIncomingTransfer {
            sender_member: sender.to_string(),
            transfer_id: transfer_id.to_string(),
            credential_id: API_ID.to_string(),
            kind: "api_key".to_string(),
            categories: vec![],
            size_bytes: 1,
            sealed: credentials_core::federation::SealedTransfer {
                enc: b64.decode(params["enc"].as_str().unwrap()).unwrap(),
                ciphertext: b64.decode(params["ciphertext"].as_str().unwrap()).unwrap(),
                aad: params["aad"].as_str().unwrap().as_bytes().to_vec(),
            },
            received_at_ms: wall_ms(),
        })
        .unwrap();
    assert_eq!(
        inserted,
        credentials_core::federation::IncomingInsert::Inserted
    );
}

/// An envelope sealed under the token-reply `info` does not open as a transfer.
#[tokio::test]
async fn an_envelope_sealed_for_another_purpose_does_not_open() {
    let rig = Rig::new("transfer-wrong-info").await;
    let params = rig.a.hand_seal_with(
        &rig.b,
        &tid(1),
        API_ID,
        &body(API_ID, "api_key", b"sk"),
        claustrum_module_probe::federation::ingress::REMOTE_TOKEN_INFO,
    );
    assert_eq!(
        rig.serve_b(&rig.a.member, &params).await,
        "remote_seal_invalid"
    );
    // An aad naming another sender than the attested member does not open either.
    let (_c_fixture, c) = rig.vault_c();
    let from_a = rig
        .a
        .hand_seal(&rig.b, &tid(2), API_ID, &body(API_ID, "api_key", b"sk"));
    assert_eq!(rig.serve_b(&c.member, &from_a).await, "remote_seal_invalid");
    assert!(rig.b.incoming().is_empty());
}

// ---------------------------------------------------------------------------------
// Bounds and concurrency
// ---------------------------------------------------------------------------------

/// The dedup runs before the queue bound: with A's queue full, a same-hash resend of a
/// pending transfer answers `pending` and writes nothing, while a new one is
/// `transfer_queue_full` with no row.
#[tokio::test]
async fn a_same_hash_resend_while_the_queue_is_full_answers_pending() {
    let rig = Rig::new("transfer-queue-full").await;
    rig.api_key_on_a(API_ID, b"sk-first");
    let first = rig.a.transfers.send(API_ID, &rig.b.member).await.unwrap();
    for index in 1..8 {
        let params = rig.a.hand_seal(
            &rig.b,
            &tid(index),
            "apikey:groq",
            &body("apikey:groq", "api_key", format!("sk-{index}").as_bytes()),
        );
        assert_eq!(rig.serve_b(&rig.a.member, &params).await, "pending");
    }
    assert_eq!(rig.b.pending(), 8);
    let resent = rig.a.transfers.resume(&first.transfer_id).await.unwrap();
    assert_eq!(
        resent.reply,
        DeliveryReply::State(IncomingTransferState::Pending)
    );
    assert_eq!(rig.b.incoming().len(), 8, "the resend wrote nothing");

    let ninth = rig
        .a
        .hand_seal(&rig.b, &tid(9), API_ID, &body(API_ID, "api_key", b"ninth"));
    assert_eq!(
        rig.serve_b(&rig.a.member, &ninth).await,
        "transfer_queue_full"
    );
    assert_eq!(rig.b.incoming().len(), 8);
}

/// A body over the 64 KiB plaintext cap answers `transfer_too_large` with no row.
#[tokio::test]
async fn an_oversized_body_answers_transfer_too_large_with_no_row() {
    let rig = Rig::new("transfer-too-large").await;
    let normal = rig
        .a
        .hand_seal(&rig.b, &tid(1), API_ID, &body(API_ID, "api_key", b"sk"));
    let mut oversized = normal.clone();
    let b64 = base64::engine::general_purpose::STANDARD;
    oversized["ciphertext"] = json!(b64.encode(vec![7u8; 64 * 1024 + 17]));
    assert_eq!(
        rig.serve_b(&rig.a.member, &oversized).await,
        "transfer_too_large"
    );
    assert!(rig.b.incoming().is_empty());
}

/// Starting from 7 pending, two concurrent distinct deliveries add exactly one row;
/// two concurrent identical deliveries add one row.
#[tokio::test]
async fn concurrent_deliveries_never_overfill_the_queue_or_duplicate_a_row() {
    let rig = Rig::new("transfer-concurrent-deliveries").await;
    for index in 0..7 {
        let params = rig.a.hand_seal(
            &rig.b,
            &tid(index),
            API_ID,
            &body(API_ID, "api_key", format!("sk-{index}").as_bytes()),
        );
        assert_eq!(rig.serve_b(&rig.a.member, &params).await, "pending");
    }
    let x = rig
        .a
        .hand_seal(&rig.b, &tid(20), API_ID, &body(API_ID, "api_key", b"x"));
    let y = rig
        .a
        .hand_seal(&rig.b, &tid(21), API_ID, &body(API_ID, "api_key", b"y"));
    let (one, two) = tokio::join!(
        rig.serve_b(&rig.a.member, &x),
        rig.serve_b(&rig.a.member, &y)
    );
    let mut answers = vec![one, two];
    answers.sort();
    assert_eq!(answers, vec!["pending", "transfer_queue_full"]);
    assert_eq!(rig.b.pending(), 8);

    let rig = Rig::new("transfer-concurrent-identical").await;
    let z = rig
        .a
        .hand_seal(&rig.b, &tid(30), API_ID, &body(API_ID, "api_key", b"z"));
    let (one, two) = tokio::join!(
        rig.serve_b(&rig.a.member, &z),
        rig.serve_b(&rig.a.member, &z)
    );
    assert_eq!((one.as_str(), two.as_str()), ("pending", "pending"));
    assert_eq!(rig.b.incoming().len(), 1);
}

/// Two concurrent accepts of one transfer create one record and one `transfer_in`.
#[tokio::test]
async fn two_concurrent_accepts_create_one_record() {
    let rig = Rig::new("transfer-concurrent-accepts").await;
    rig.api_key_on_a(API_ID, b"sk-once");
    let sent = rig.a.transfers.send(API_ID, &rig.b.member).await.unwrap();
    let (one, two) = tokio::join!(
        rig.b
            .transfers
            .accept(&sent.transfer_id, &rig.a.member, false),
        rig.b
            .transfers
            .accept(&sent.transfer_id, &rig.a.member, false),
    );
    let outcomes = [one.unwrap(), two.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, AcceptReport::Accepted { .. }))
            .count(),
        1,
        "{outcomes:?}"
    );
    assert!(outcomes.contains(&AcceptReport::AlreadyDecided(
        IncomingTransferState::Accepted
    )));
    assert_eq!(rig.b.store().get(API_ID).unwrap().record_version, 1);
    assert_eq!(audit_count(rig.b.store(), AuditOp::TransferIn), 1);
}

// ---------------------------------------------------------------------------------
// Lookups that fail
// ---------------------------------------------------------------------------------

/// `send` to a receiver with no announced key commits nothing.
#[tokio::test]
async fn send_to_a_receiver_with_no_announced_key_commits_nothing() {
    let rig = Rig::new("transfer-no-key").await;
    rig.api_key_on_a(API_ID, b"sk-no-key");
    let stranger = "fed-computer:99999999999999999999999999999999";
    let refused = rig.a.transfers.send(API_ID, stranger).await.unwrap_err();
    assert_eq!(refused.code, "remote_setup_incomplete");
    assert_eq!(refused.remedy_member.as_deref(), Some(stranger));
    rig.stall_lookup("callosum.peer_keys_read");
    let refused = rig
        .a
        .transfers
        .send(API_ID, &rig.b.member)
        .await
        .unwrap_err();
    assert_eq!(refused.code, "callosum_unavailable");
    assert!(rig.a.store().list_outgoing_transfers().unwrap().is_empty());
    assert_eq!(audit_count(rig.a.store(), AuditOp::TransferOut), 0);
    assert!(rig.deliveries().is_empty());
}

/// A failed pairing lookup at delivery is transient: no row on B, and A keeps its row
/// for a resume that then succeeds.
#[tokio::test]
async fn a_failed_pairing_lookup_at_delivery_is_transient_and_keeps_the_row() {
    let rig = Rig::new("transfer-pairing-lookup").await;
    rig.api_key_on_a(API_ID, b"sk-pairing");
    rig.stall_lookup("callosum.paired_devices_read");
    let sent = rig.a.transfers.send(API_ID, &rig.b.member).await.unwrap();
    assert_eq!(refused_code(&sent.reply), "callosum_unavailable");
    assert!(sent.row_kept);
    assert!(rig.b.incoming().is_empty());
    let row = rig
        .a
        .store()
        .outgoing_transfer(&sent.transfer_id)
        .unwrap()
        .unwrap();
    assert_eq!(row.last_reply_code.as_deref(), Some("callosum_unavailable"));

    rig.heal_lookups();
    let resumed = rig.a.transfers.resume(&sent.transfer_id).await.unwrap();
    assert_eq!(
        resumed.reply,
        DeliveryReply::State(IncomingTransferState::Pending)
    );
}

/// A failed key lookup at accept is transient: the row stays pending, no
/// `transfer_reject` is written, and a later accept succeeds.
#[tokio::test]
async fn a_failed_key_lookup_at_accept_is_transient_and_keeps_the_row() {
    let rig = Rig::new("transfer-accept-lookup").await;
    rig.api_key_on_a(API_ID, b"sk-accept-lookup");
    let sent = rig.a.transfers.send(API_ID, &rig.b.member).await.unwrap();
    rig.stall_lookup("callosum.peer_keys_read");
    let refused = rig
        .b
        .transfers
        .accept(&sent.transfer_id, &rig.a.member, false)
        .await
        .unwrap_err();
    assert_eq!(refused.code, "callosum_unavailable");
    assert_eq!(refused.class, "transient");
    assert_eq!(rig.b.pending(), 1);
    assert_eq!(audit_count(rig.b.store(), AuditOp::TransferReject), 0);
    assert!(rig.b.store().get(API_ID).is_err());

    rig.heal_lookups();
    let accepted = rig
        .b
        .transfers
        .accept(&sent.transfer_id, &rig.a.member, false)
        .await
        .unwrap();
    assert!(matches!(accepted, AcceptReport::Accepted { .. }));
}

// ---------------------------------------------------------------------------------
// Transfer-key recovery
// ---------------------------------------------------------------------------------

/// `transfer init --replace` is refused while the key is `Active` and admitted once
/// it is off `Active`; that one transaction marks every pending row rejected with one
/// `transfer_reject` row each.
#[tokio::test]
async fn transfer_init_replace_is_refused_while_active_and_rejects_every_pending_row() {
    let mut rig = Rig::new("transfer-recovery-receiver").await;
    for index in 0..3 {
        let params = rig.a.hand_seal(
            &rig.b,
            &tid(index),
            API_ID,
            &body(API_ID, "api_key", format!("sk-{index}").as_bytes()),
        );
        assert_eq!(rig.serve_b(&rig.a.member, &params).await, "pending");
    }
    let refused = rig
        .b
        .transfers
        .replace_transfer_key("route-admin")
        .unwrap_err();
    assert_eq!(refused.code, "transfer_key_protected");
    assert_eq!(rig.b.pending(), 3);

    let recovery = rig.b.recover_key();
    let mut rejected: Vec<String> = recovery
        .rejected_incoming
        .iter()
        .map(|row| row.transfer_id.clone())
        .collect();
    rejected.sort();
    assert_eq!(rejected, vec![tid(0), tid(1), tid(2)]);
    assert!(rig
        .b
        .incoming()
        .iter()
        .all(|row| row.state == IncomingTransferState::Rejected
            && row.reject_reason.as_deref() == Some("remote_seal_invalid")));
    assert_eq!(audit_count(rig.b.store(), AuditOp::TransferReject), 3);
    assert_eq!(
        rig.b.store().vault_transfer_key_state().unwrap(),
        Some(RecordState::Active)
    );
}

/// After the sender replaces its key, `--resume` sends nothing for its pre-existing
/// outgoing rows, and the ids the recovery reports are exactly those rows.
#[tokio::test]
async fn after_the_senders_key_replacement_resume_sends_nothing_and_the_ids_match() {
    let mut rig = Rig::new("transfer-recovery-sender").await;
    rig.api_key_on_a(API_ID, b"sk-one");
    rig.api_key_on_a("apikey:groq", b"sk-two");
    rig.then(Step::Unreachable("fed_target_unavailable"));
    rig.then(Step::Unreachable("fed_target_unavailable"));
    let one = rig.a.transfers.send(API_ID, &rig.b.member).await.unwrap();
    let two = rig
        .a
        .transfers
        .send("apikey:groq", &rig.b.member)
        .await
        .unwrap();
    assert!(one.row_kept && two.row_kept);
    let delivered_before = rig.deliveries().len();

    let recovery = rig.a.recover_key();
    let mut reported: Vec<(String, String, String)> = recovery
        .abandoned_outgoing
        .iter()
        .map(|row| {
            (
                row.transfer_id.clone(),
                row.credential_id.clone(),
                row.receiver_member.clone(),
            )
        })
        .collect();
    reported.sort();
    let mut expected = vec![
        (
            one.transfer_id.clone(),
            API_ID.to_string(),
            rig.b.member.clone(),
        ),
        (
            two.transfer_id.clone(),
            "apikey:groq".to_string(),
            rig.b.member.clone(),
        ),
    ];
    expected.sort();
    assert_eq!(reported, expected);
    for sent in [&one, &two] {
        let refused = rig.a.transfers.resume(&sent.transfer_id).await.unwrap_err();
        assert_eq!(refused.code, "transfer_abandoned");
        let row = rig
            .a
            .store()
            .outgoing_transfer(&sent.transfer_id)
            .unwrap()
            .unwrap();
        assert_eq!(row.state, OutgoingTransferState::Abandoned);
    }
    assert_eq!(
        rig.deliveries().len(),
        delivered_before,
        "resume sent nothing"
    );
    assert_eq!(audit_count(rig.a.store(), AuditOp::TransferReject), 2);
}

/// A sender's still-pending rows fail at accept after its key changes: they open
/// against the newly announced key, fail, and are marked rejected.
#[tokio::test]
async fn a_senders_pending_rows_fail_at_accept_after_its_key_changes() {
    let mut rig = Rig::new("transfer-recovery-pending").await;
    rig.api_key_on_a(API_ID, b"sk-old-key");
    let sent = rig.a.transfers.send(API_ID, &rig.b.member).await.unwrap();
    rig.a.recover_key();
    rig.vaults
        .callosum
        .announce_peer_key(&rig.a.member, &hex(&rig.a.public));

    let refused = rig
        .b
        .transfers
        .accept(&sent.transfer_id, &rig.a.member, false)
        .await
        .unwrap_err();
    assert_eq!(refused.code, "remote_seal_invalid");
    let row = rig
        .b
        .store()
        .incoming_transfer(&rig.a.member, &sent.transfer_id)
        .unwrap()
        .unwrap();
    assert_eq!(row.state, IncomingTransferState::Rejected);
    assert_eq!(audit_count(rig.b.store(), AuditOp::TransferReject), 1);
    assert!(rig.b.store().get(API_ID).is_err());
}

/// A resend of an already accepted transfer still answers `accepted` after the
/// sender's key change and again after the receiver's.
#[tokio::test]
async fn an_accepted_resend_still_answers_accepted_after_either_sides_key_change() {
    let mut rig = Rig::new("transfer-recovery-accepted").await;
    rig.api_key_on_a(API_ID, b"sk-accepted-before");
    let sent = rig.a.transfers.send(API_ID, &rig.b.member).await.unwrap();
    rig.b
        .transfers
        .accept(&sent.transfer_id, &rig.a.member, false)
        .await
        .unwrap();
    let envelope = rig.deliveries().pop().unwrap();

    rig.a.recover_key();
    rig.vaults
        .callosum
        .announce_peer_key(&rig.a.member, &hex(&rig.a.public));
    assert_eq!(rig.serve_b(&rig.a.member, &envelope).await, "accepted");

    rig.b.recover_key();
    rig.vaults
        .callosum
        .announce_peer_key(&rig.b.member, &hex(&rig.b.public));
    assert_eq!(rig.serve_b(&rig.a.member, &envelope).await, "accepted");
    assert_eq!(audit_count(rig.b.store(), AuditOp::TransferIn), 1);
}

/// One admin budget covers every outbound call a `send` makes: with the key lookup
/// slow and the delivery stalled, the operator still gets a definite reply well inside
/// the CLI's 15 s wait, and the committed row is kept for `--resume`.
#[tokio::test]
async fn a_send_with_a_slow_key_lookup_and_a_stalled_delivery_answers_inside_the_admin_budget() {
    let rig = Rig::new("transfer-admin-budget").await;
    rig.api_key_on_a(API_ID, b"sk-budget");
    let fingerprint = rig
        .b
        .member
        .strip_prefix("fed-computer:")
        .unwrap()
        .to_string();
    let peers = json!({ "peers": [{
        "fingerprint": fingerprint,
        "key_record": { "keys": {
            "vault_transfer_x25519": { "pub": hex(&rig.b.public), "version": "1" },
        } },
    }] });
    let lookup = Held::new();
    let delivery = Held::new();
    rig.vaults.callosum.answer(
        crate::support::TARGET_MODULE,
        "callosum.peer_keys_read",
        Reply::Hold(lookup.clone()),
    );
    rig.vaults.callosum.answer(
        crate::support::TARGET_MODULE,
        OP_TRANSFER_DELIVER,
        Reply::Hold(delivery.clone()),
    );
    // The production budget, not the rig's shortened one.
    let sender = Transfers::new(Arc::clone(&rig.a.home_store.store));
    assert!(sender.attach_outbound(rig.vaults.a.outbound.clone()));
    let to = rig.b.member.clone();
    let mut send = tokio::spawn(async move { sender.send(API_ID, &to).await });
    lookup.arrived_before(&mut send).await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(6)).await;
    assert!(!send.is_finished(), "the key lookup is still held");
    tokio::time::resume();
    lookup.release(Reply::Ok(peers));
    delivery.arrived_before(&mut send).await;
    assert!(
        poll_once(&mut send).await.is_none(),
        "the delivery is still held"
    );
    tokio::time::pause();
    let sent = resolved_after_advance(send, Duration::from_millis(4_001))
        .await
        .expect("a definite reply");
    assert_eq!(refused_code(&sent.reply), "home_unreachable");
    assert!(sent.row_kept);
    assert_eq!(rig.deliveries().len(), 1);
}

/// An `ApiKey` record (an allowed kind) that carries a refresh adapter or an OAuth
/// struct can mint or refresh credentials, as a GitHub App or Meta-style record does.
/// `send` refuses both as `oauth` and writes nothing: no outgoing row, no audit row,
/// no delivery.
#[tokio::test]
async fn send_refuses_an_allowed_kind_carrying_a_refresh_adapter_or_oauth_material() {
    let rig = Rig::new("transfer-send-allowed-kind-oauth").await;
    let store = rig.a.store();
    let mut with_adapter =
        VaultRecord::new_static(CredentialKind::ApiKey, "operator", b"sk-app".to_vec(), None);
    with_adapter.refresh_adapter = Some("github_app".to_string());
    let mut with_oauth = VaultRecord::new_static(
        CredentialKind::ApiKey,
        "operator",
        b"sk-meta".to_vec(),
        None,
    );
    with_oauth.oauth = Some(credentials_core::oauth::OAuthCredential {
        access_token: "access".to_string().into(),
        refresh_token: "refresh".to_string().into(),
        expires_at_ms: None,
        token_url: "https://token.test/oauth".into(),
        client_id: None,
        client_secret: None,
        scopes: vec![],
    });
    store
        .create("apikey:github-app", &with_adapter)
        .expect("store the adapter record");
    store
        .create("apikey:meta", &with_oauth)
        .expect("store the oauth record");
    assert!(store
        .get("apikey:github-app")
        .unwrap()
        .refresh_adapter
        .is_some());
    assert!(store.get("apikey:meta").unwrap().oauth.is_some());

    for id in ["apikey:github-app", "apikey:meta"] {
        let refused = rig.a.transfers.send(id, &rig.b.member).await.unwrap_err();
        assert_eq!(refused.code, "transfer_ineligible", "{id}");
        assert_eq!(refused.reason, Some("oauth"), "{id}");
    }
    assert!(store.list_outgoing_transfers().unwrap().is_empty());
    assert_eq!(audit_count(store, AuditOp::TransferOut), 0);
    assert!(rig.deliveries().is_empty());
    assert!(rig.b.incoming().is_empty());
}

/// A sender that is not A, as callosum would name it.
fn filler_sender(index: u32) -> String {
    format!("fed-computer:{:032x}", 0xf111_0000u64 + u64::from(index))
}

/// Record `count` pending transfers from `sender` straight through the store: queue
/// filler for the total cap, from members that never deliver anything themselves.
fn fill_pending(store: &EncryptedStore, sender: &str, count: u32) {
    for index in 0..count {
        let inserted = store
            .insert_incoming_transfer(&credentials_core::federation::NewIncomingTransfer {
                sender_member: sender.to_string(),
                transfer_id: tid(500 + index),
                credential_id: API_ID.to_string(),
                kind: "api_key".to_string(),
                categories: vec![],
                size_bytes: 1,
                sealed: credentials_core::federation::SealedTransfer {
                    enc: format!("{sender}-{index}-enc").into_bytes(),
                    ciphertext: format!("{sender}-{index}-ct").into_bytes(),
                    aad: b"{}".to_vec(),
                },
                received_at_ms: wall_ms(),
            })
            .unwrap();
        assert_eq!(
            inserted,
            credentials_core::federation::IncomingInsert::Inserted
        );
    }
}

/// The total cap: with 64 pending across other senders, a delivery from A (which has
/// none pending) is `transfer_queue_full` with no row.
#[tokio::test]
async fn sixty_four_pending_in_total_fill_the_queue_for_every_sender() {
    let rig = Rig::new("transfer-total-cap").await;
    for sender in 0..8 {
        fill_pending(rig.b.store(), &filler_sender(sender), 8);
    }
    assert_eq!(rig.b.pending(), 64);
    let params = rig
        .a
        .hand_seal(&rig.b, &tid(1), API_ID, &body(API_ID, "api_key", b"sk"));
    assert_eq!(
        rig.serve_b(&rig.a.member, &params).await,
        "transfer_queue_full"
    );
    assert_eq!(rig.b.pending(), 64);
    assert!(rig
        .b
        .store()
        .incoming_transfer(&rig.a.member, &tid(1))
        .unwrap()
        .is_none());
}

/// Starting from 63 pending in total, two concurrent distinct deliveries from two
/// senders add exactly one row.
#[tokio::test]
async fn from_sixty_three_in_total_two_concurrent_deliveries_add_one_row() {
    let rig = Rig::new("transfer-total-cap-race").await;
    let (_c_fixture, c) = rig.vault_c();
    for sender in 0..7 {
        fill_pending(rig.b.store(), &filler_sender(sender), 8);
    }
    fill_pending(rig.b.store(), &filler_sender(7), 7);
    assert_eq!(rig.b.pending(), 63);
    let from_a = rig
        .a
        .hand_seal(&rig.b, &tid(1), API_ID, &body(API_ID, "api_key", b"from-a"));
    let from_c = rig.c_seal(&c, &tid(2), "apikey:groq", b"from-c");
    let (one, two) = tokio::join!(
        rig.serve_b(&rig.a.member, &from_a),
        rig.serve_b(&c.member, &from_c)
    );
    let mut answers = vec![one, two];
    answers.sort();
    assert_eq!(answers, vec!["pending", "transfer_queue_full"]);
    assert_eq!(rig.b.pending(), 64);
}
