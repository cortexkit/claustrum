//! The federation admin ops, driven through the daemon's own `AdminSurface`: the
//! master-key challenge, the MAC over the op body and the dispatch hook that runs an
//! outbound pre-step, one store commit and an outbound post-step.
//!
//! Each vault here is a real store with a real `AdminSurface` whose outbound client
//! points at the callosum stand-in. A vault that must answer another's federation call
//! (a delivery, a token fetch) does so through its own `HomeVault`, reached from a
//! handler on the stand-in as the attested calling member.

use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use claustrum_module_probe::admin_surface::{AdminOutcome, AdminSurface};
use claustrum_module_probe::federation::ingress::{OP_REMOTE_TOKEN, OP_TRANSFER_DELIVER};
use claustrum_module_probe::federation::{HomeAnswer, RemoteReader};
use credentials_core::admin_auth::{AdminMacKey, TranscriptParts};
use credentials_core::admin_ops::{
    AdminOpBody, ADMIN_OP_SCHEMA_V1, ADMIN_OP_SCHEMA_V2, FEDERATION_REQUIRES_DAEMON,
};
use credentials_core::audit::{AuditCtx, AuditOp};
use credentials_core::federation::{
    member_grant_payload_hash, MemberGrantOperation, MemberGrantSelector, VAULT_TRANSFER_ID,
};
use credentials_core::key::MasterKey;
use credentials_core::oauth::OAuthCredential;
use credentials_core::record::{CredentialKind, VaultRecord};
use credentials_core::store::{EncryptedStore, GrantOperation, SelectorKind, SetCategoryMode};
use serde_json::{json, Value};
use subc_protocol::Principal;

use crate::support::{
    wall_ms, HomeStore, Reply, Responder, TwoVaults, VaultFixture, FAKE_ADAPTERS, TARGET_MODULE,
};

const PAIRED_DEVICES_READ: &str = "callosum.paired_devices_read";
const PEER_KEYS_READ: &str = "callosum.peer_keys_read";
const API_ID: &str = "apikey:openai";
const LOGIN_ID: &str = "oauth:anthropic:work";
const CATEGORY: &str = "llm-provider";
const PAIRING: &str = "pair-1";
/// The key the HomeStore fixture opens every store with, so the caller side of the
/// admin transcript derives the same MAC key the surface verifies with.
const MASTER_KEY: [u8; 32] = [42; 32];
const VAULT_ID: [u8; 32] = [9; 32];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn audit_count(store: &EncryptedStore, op: AuditOp) -> usize {
    store
        .read_audit(None)
        .unwrap()
        .into_iter()
        .filter(|entry| entry.op == op.as_str())
        .count()
}

/// The member id callosum gives the computer with Noise static key `key`, computed
/// here independently of the vault's own code: `fed-computer:` and the first 16 bytes
/// of SHA-256 over the key, as hex.
fn member_for_static_key(key: &[u8; 32]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, key);
    format!("fed-computer:{}", hex(&digest.as_ref()[..16]))
}

/// One member's vault: its store, and its admin surface (whose home also answers
/// federation calls made to this vault).
struct Vault {
    member: String,
    home_store: HomeStore,
    admin: Arc<AdminSurface>,
}

static CHANNEL: AtomicU16 = AtomicU16::new(100);

impl Vault {
    fn open(fixture: &VaultFixture, budget: Option<Duration>) -> Self {
        let home_store = HomeStore::open(&fixture.data_dir);
        let key = MasterKey::from_bytes(MASTER_KEY);
        let mut admin = AdminSurface::new(
            Arc::clone(&home_store.engine),
            AdminMacKey::derive(&key),
            VAULT_ID,
            key.key_id(),
        );
        if let Some(budget) = budget {
            admin = admin.with_federation_budget(budget);
        }
        assert!(admin.home().attach_outbound(fixture.outbound.clone()));
        Self {
            member: fixture.member.member_id.clone(),
            home_store,
            admin: Arc::new(admin),
        }
    }

    fn store(&self) -> &EncryptedStore {
        &self.home_store.store
    }

    /// Create the transfer key and set the self id directly in the store, for tests
    /// whose subject is not `transfer init`. Returns the key's public half as hex.
    fn install_transfer_key(&self) -> String {
        let pem = credentials_core::kem::generate_key().unwrap();
        let (public, _) = credentials_core::kem::public_half(&pem).unwrap();
        self.store()
            .create_audited(
                VAULT_TRANSFER_ID,
                &VaultRecord::new_static(CredentialKind::KemKey, "operator", pem.into_bytes(), None),
                AuditCtx::admin(AuditOp::Put),
            )
            .unwrap();
        self.store()
            .set_federation_self_member_audited(
                &self.member,
                AuditCtx::admin(AuditOp::FederationSelfSet),
            )
            .unwrap();
        hex(&public)
    }

    fn put_api_key(&self) {
        self.store()
            .create(
                API_ID,
                &VaultRecord::new_static(CredentialKind::ApiKey, "operator", b"sk-test".to_vec(), None),
            )
            .unwrap();
    }

    /// Run one admin op as the CLI would: a direct bind, a challenge, the master-key
    /// MAC over the exact op bytes, then the op.
    async fn run(&self, op: &AdminOpBody) -> AdminOutcome {
        run_on(&self.admin, op).await
    }
}

async fn run_on(admin: &AdminSurface, op: &AdminOpBody) -> AdminOutcome {
    let channel = CHANNEL.fetch_add(1, Ordering::Relaxed);
    admin.record_bind_at(channel, 0, Principal::Direct, "");
    let AdminOutcome::Challenge { nonce_hex, .. } =
        admin.challenge_as(channel, 0, Some(&Principal::Direct))
    else {
        panic!("challenge refused");
    };
    let nonce: [u8; 32] = unhex(&nonce_hex).try_into().unwrap();
    let body = op.to_bytes().unwrap();
    let key = MasterKey::from_bytes(MASTER_KEY);
    let tag = AdminMacKey::derive(&key).sign(&TranscriptParts {
        vault_id: &VAULT_ID,
        key_id: key.key_id(),
        nonce: &nonce,
        op_body: &body,
    });
    admin
        .execute_as(channel, 0, Some(&Principal::Direct), &body, &hex(&tag))
        .await
}

fn ok(outcome: AdminOutcome) -> Value {
    match outcome {
        AdminOutcome::Ok(value) => value,
        AdminOutcome::Refused(reason) => panic!("refused: {reason}"),
        AdminOutcome::Challenge { .. } => panic!("unexpected challenge"),
    }
}

fn refusal(outcome: AdminOutcome) -> String {
    match outcome {
        AdminOutcome::Refused(reason) => reason,
        AdminOutcome::Ok(value) => panic!("expected a refusal, got {value}"),
        AdminOutcome::Challenge { .. } => panic!("unexpected challenge"),
    }
}

/// `peer_keys_read`'s reply announcing `public_hex` for `member`, in callosum's shape.
fn peer_keys_reply(member: &str, public_hex: &str) -> Value {
    let fingerprint = member.strip_prefix("fed-computer:").unwrap();
    json!({ "peers": [{
        "fingerprint": fingerprint,
        "key_record": { "keys": { "vault_transfer_x25519": { "pub": public_hex, "version": "1" } } },
    }] })
}

/// Hand `method` calls on the stand-in to `receiver`'s home as the attested `caller`.
fn route_to_home(vaults: &TwoVaults, method: &'static str, receiver: &Vault, caller: &str) {
    let admin = Arc::clone(&receiver.admin);
    let caller = caller.to_string();
    vaults.callosum.answer(
        TARGET_MODULE,
        method,
        Reply::Handler(Responder(Arc::new(move |params: Value| {
            let admin = Arc::clone(&admin);
            let caller = caller.clone();
            Box::pin(async move {
                match admin.home().serve(&caller, method, &params).await {
                    HomeAnswer::Reply(body) => Reply::Ok(body),
                    HomeAnswer::InvalidParams(_) => Reply::RouteRefusal("invalid_params".into()),
                }
            })
        }))),
    );
}

// ---------------------------------------------------------------------------------
// The self id
// ---------------------------------------------------------------------------------

/// `transfer init --self` and `federation self` accept only the id callosum computes
/// for this computer from the `self` key of a version 1.3 `paired_devices_read` reply;
/// a different id, or a reply with no `self`, is refused and nothing is written.
#[tokio::test]
async fn transfer_init_and_federation_self_check_the_id_against_callosums_self_key() {
    let root = crate::support::temp_root("admin-self");
    let vaults = TwoVaults::new(&root).await;
    let b = Vault::open(&vaults.b, None);
    let static_key = [0x5a_u8; 32];
    let actual = member_for_static_key(&static_key);
    let typo = "fed-computer:00000000000000000000000000000001".to_string();
    // A literal 1.3-shaped reply: devices of `{class, fingerprint, pairing_id}`, and
    // this computer's own static key under the top-level `self`.
    vaults.callosum.answer(
        TARGET_MODULE,
        PAIRED_DEVICES_READ,
        Reply::Ok(json!({
            "devices": [{
                "class": "computer",
                "fingerprint": "aa11bb22cc33dd44ee55ff6600112233",
                "pairing_id": "pair-a",
            }],
            "self": { "static_public_key_hex": hex(&static_key) },
        })),
    );

    let init = |member: &str| AdminOpBody::TransferInit {
        v: ADMIN_OP_SCHEMA_V2,
        self_member: member.to_string(),
    };
    let mismatch = refusal(b.run(&init(&typo)).await);
    assert!(mismatch.starts_with("self_member_mismatch/permanent"), "{mismatch}");
    assert!(mismatch.contains(&typo) && mismatch.contains(&actual), "{mismatch}");
    assert!(b.store().meta(VAULT_TRANSFER_ID).is_err());
    assert_eq!(b.store().federation_self_member().unwrap(), None);

    let created = ok(b.run(&init(&actual)).await);
    assert_eq!(created["transfer_key"], "created");
    assert_eq!(
        b.store().federation_self_member().unwrap().as_deref(),
        Some(actual.as_str())
    );
    assert_eq!(
        b.store().get(VAULT_TRANSFER_ID).unwrap().kind,
        CredentialKind::KemKey
    );
    // Callosum can announce the key's public half: the one admitted grant exists.
    assert!(b.store().list_read_grants().unwrap().iter().any(|grant| {
        grant.principal_kind == "reserved"
            && grant.principal_id == "callosum"
            && grant.selector_kind == SelectorKind::Exact
            && grant.selector == VAULT_TRANSFER_ID
            && grant.operation == GrantOperation::Read
    }));
    // Running it again keeps the key.
    assert_eq!(ok(b.run(&init(&actual)).await)["transfer_key"], "existing");

    let set_self = |member: &str| AdminOpBody::FederationSelfSet {
        v: ADMIN_OP_SCHEMA_V2,
        member: member.to_string(),
    };
    let self_rows = audit_count(b.store(), AuditOp::FederationSelfSet);
    let mismatch = refusal(b.run(&set_self(&typo)).await);
    assert!(mismatch.starts_with("self_member_mismatch/permanent"), "{mismatch}");
    assert_eq!(audit_count(b.store(), AuditOp::FederationSelfSet), self_rows);

    // A callosum older than 1.3 sends no `self`: the id cannot be checked, so it is
    // refused rather than accepted unchecked.
    vaults.callosum.answer(
        TARGET_MODULE,
        PAIRED_DEVICES_READ,
        Reply::Ok(json!({ "devices": [] })),
    );
    let unchecked = refusal(b.run(&set_self(&actual)).await);
    assert!(unchecked.starts_with("self_member_unchecked/permanent"), "{unchecked}");
    assert_eq!(audit_count(b.store(), AuditOp::FederationSelfSet), self_rows);
    let unchecked = refusal(b.run(&init(&actual)).await);
    assert!(unchecked.starts_with("self_member_unchecked/permanent"), "{unchecked}");
}

// ---------------------------------------------------------------------------------
// Member grants
// ---------------------------------------------------------------------------------

/// A member grant records the member's current pairing id, which only callosum knows.
/// An unpaired member is `member_not_paired`, a failed lookup `callosum_unavailable`,
/// and a malformed member id is refused before any lookup: none of them writes a row
/// or an audit entry.
#[tokio::test]
async fn member_grant_reads_the_pairing_and_refuses_with_no_row() {
    let root = crate::support::temp_root("admin-member");
    let vaults = TwoVaults::new(&root).await;
    let a = Vault::open(&vaults.a, Some(Duration::from_millis(800)));
    let member = vaults.requester_member().to_string();
    let grant = |member: &str| AdminOpBody::MemberGrant {
        v: ADMIN_OP_SCHEMA_V2,
        member: member.to_string(),
        operation: MemberGrantOperation::RemoteRead,
        selector: MemberGrantSelector::Category(CATEGORY.into()),
    };
    let nothing_written = |a: &Vault| {
        assert!(a.store().list_member_grants().unwrap().is_empty());
        assert_eq!(audit_count(a.store(), AuditOp::MemberGrantCreate), 0);
    };

    for bad in ["fed-computer:XYZ", "fed-phone:11223344556677889900112233445566"] {
        let refused = refusal(a.run(&grant(bad)).await);
        assert!(refused.starts_with("invalid_member_id"), "{refused}");
    }
    assert!(!vaults.callosum.saw_method(PAIRED_DEVICES_READ));
    nothing_written(&a);

    let unpaired = refusal(a.run(&grant(&member)).await);
    assert!(unpaired.starts_with("member_not_paired/permanent"), "{unpaired}");
    nothing_written(&a);

    vaults.callosum.answer(
        TARGET_MODULE,
        PAIRED_DEVICES_READ,
        Reply::RouteRefusal("fed_not_ready".into()),
    );
    let unavailable = refusal(a.run(&grant(&member)).await);
    assert_eq!(unavailable, "callosum_unavailable/transient");
    nothing_written(&a);

    vaults
        .callosum
        .answer(TARGET_MODULE, PAIRED_DEVICES_READ, Reply::Stall);
    let started = Instant::now();
    let stalled = refusal(a.run(&grant(&member)).await);
    assert_eq!(stalled, "callosum_unavailable/transient");
    assert!(started.elapsed() < Duration::from_secs(3));
    nothing_written(&a);

    // Paired: the grant stores the current pairing id, and a re-pair followed by a
    // grant replaces it, with the new id in the audit payload.
    vaults.callosum.forget_answers();
    vaults.callosum.set_pairing(&member, Some(PAIRING));
    let granted = ok(a.run(&grant(&member)).await);
    assert_eq!(granted["pairing_id"], PAIRING);
    vaults.callosum.set_pairing(&member, Some("pair-2"));
    ok(a.run(&grant(&member)).await);
    let grants = a.store().list_member_grants().unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].pairing_id, "pair-2");
    let last = a
        .store()
        .read_audit(None)
        .unwrap()
        .into_iter()
        .filter(|entry| entry.op == AuditOp::MemberGrantCreate.as_str())
        .last()
        .unwrap();
    assert_eq!(
        last.payload_hash.as_deref(),
        Some(
            member_grant_payload_hash(
                MemberGrantOperation::RemoteRead,
                &MemberGrantSelector::Category(CATEGORY.into()),
                "pair-2",
            )
            .as_str()
        )
    );
    assert_eq!(last.actor, member);
}

// ---------------------------------------------------------------------------------
// Send, accept and the budget
// ---------------------------------------------------------------------------------

/// A send's key lookup and delivery share one 10 s budget, so a lookup that stalls
/// most of it and a delivery that never answers still give the operator a definite
/// reply well inside the CLI's 15 s wait: the committed transfer, kept for `--resume`.
#[tokio::test]
async fn a_stalled_key_lookup_and_a_stalled_delivery_give_a_definite_reply_inside_15_s() {
    let root = crate::support::temp_root("admin-stall");
    let vaults = TwoVaults::new(&root).await;
    // The production budget: this test is about the real numbers.
    let b = Vault::open(&vaults.b, None);
    b.install_transfer_key();
    b.put_api_key();
    let receiver = vaults.home_member().to_string();
    let receiver_key = hex(&[7u8; 32]);
    vaults.callosum.answer(
        TARGET_MODULE,
        PEER_KEYS_READ,
        Reply::Delayed(
            Duration::from_secs(6),
            Box::new(Reply::Ok(peer_keys_reply(&receiver, &receiver_key))),
        ),
    );
    vaults
        .callosum
        .answer(TARGET_MODULE, OP_TRANSFER_DELIVER, Reply::Stall);

    let started = Instant::now();
    let report = ok(b
        .run(&AdminOpBody::TransferSend {
            v: ADMIN_OP_SCHEMA_V2,
            credential_id: API_ID.into(),
            to: receiver.clone(),
        })
        .await);
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(15), "took {elapsed:?}");
    assert!(
        elapsed >= Duration::from_secs(6),
        "the delayed lookup did run: {elapsed:?}"
    );
    assert!(vaults.callosum.saw_method(OP_TRANSFER_DELIVER));
    assert_eq!(report["reply"], "home_unreachable");
    assert_eq!(report["reply_class"], "transient");
    assert_eq!(report["row_kept"], true);
    let rows = b.store().list_outgoing_transfers().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].transfer_id, report["transfer_id"].as_str().unwrap());
    assert_eq!(audit_count(b.store(), AuditOp::TransferOut), 1);
}

/// A key lookup that never answers ends the send inside the budget with
/// `callosum_unavailable`, and nothing is committed.
#[tokio::test]
async fn a_key_lookup_that_never_answers_commits_nothing_and_answers_inside_15_s() {
    let root = crate::support::temp_root("admin-stall-lookup");
    let vaults = TwoVaults::new(&root).await;
    let b = Vault::open(&vaults.b, None);
    b.install_transfer_key();
    b.put_api_key();
    vaults
        .callosum
        .answer(TARGET_MODULE, PEER_KEYS_READ, Reply::Stall);
    let started = Instant::now();
    let refused = refusal(
        b.run(&AdminOpBody::TransferSend {
            v: ADMIN_OP_SCHEMA_V2,
            credential_id: API_ID.into(),
            to: vaults.home_member().into(),
        })
        .await,
    );
    assert!(started.elapsed() < Duration::from_secs(15));
    assert_eq!(refused, "callosum_unavailable/transient");
    assert!(b.store().list_outgoing_transfers().unwrap().is_empty());
    assert_eq!(audit_count(b.store(), AuditOp::TransferOut), 0);
    assert!(!vaults.callosum.saw_method(OP_TRANSFER_DELIVER));
}

/// The record's admin lock is held only around the send's synchronous commit: while
/// the key lookup and then the delivery are outstanding, another admin write to the
/// same credential (which takes that lock) finishes at once.
#[tokio::test]
async fn the_admin_lock_is_not_held_across_an_outbound_await() {
    let root = crate::support::temp_root("admin-lock");
    let vaults = TwoVaults::new(&root).await;
    let b = Vault::open(&vaults.b, Some(Duration::from_secs(4)));
    b.install_transfer_key();
    b.put_api_key();
    let receiver = vaults.home_member().to_string();
    vaults.callosum.answer(
        TARGET_MODULE,
        PEER_KEYS_READ,
        Reply::Delayed(
            Duration::from_millis(1_500),
            Box::new(Reply::Ok(peer_keys_reply(&receiver, &hex(&[7u8; 32])))),
        ),
    );
    vaults
        .callosum
        .answer(TARGET_MODULE, OP_TRANSFER_DELIVER, Reply::Stall);

    let admin = Arc::clone(&b.admin);
    let send = tokio::spawn(async move {
        run_on(
            &admin,
            &AdminOpBody::TransferSend {
                v: ADMIN_OP_SCHEMA_V2,
                credential_id: API_ID.into(),
                to: receiver,
            },
        )
        .await
    });
    let set_category = |category: &str| AdminOpBody::SetCategory {
        v: ADMIN_OP_SCHEMA_V2,
        credential_id: API_ID.into(),
        mode: SetCategoryMode::Add,
        categories: vec![category.into()],
    };

    // During the key lookup.
    tokio::time::sleep(Duration::from_millis(400)).await;
    let started = Instant::now();
    ok(b.run(&set_category(CATEGORY)).await);
    assert!(started.elapsed() < Duration::from_millis(500));
    assert!(!send.is_finished(), "the lookup is still outstanding");

    // During the delivery, after the commit.
    tokio::time::sleep(Duration::from_millis(1_600)).await;
    assert_eq!(b.store().list_outgoing_transfers().unwrap().len(), 1);
    let started = Instant::now();
    ok(b.run(&set_category("search")).await);
    assert!(started.elapsed() < Duration::from_millis(500));
    assert!(!send.is_finished(), "the delivery is still outstanding");

    let report = ok(send.await.unwrap());
    assert_eq!(report["row_kept"], true);
}

/// A send from A and the accept on B, both through the admin hook: the record exists
/// on B only after accept, with its categories, and a second accept is a no-op.
#[tokio::test]
async fn send_and_accept_run_through_the_admin_hook() {
    let root = crate::support::temp_root("admin-send-accept");
    let vaults = TwoVaults::new(&root).await;
    let a = Vault::open(&vaults.a, Some(Duration::from_secs(4)));
    let b = Vault::open(&vaults.b, Some(Duration::from_secs(4)));
    let a_public = a.install_transfer_key();
    let b_public = b.install_transfer_key();
    a.put_api_key();
    a.store()
        .set_categories_audited(
            API_ID,
            SetCategoryMode::Set,
            &[CATEGORY.to_string()],
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .unwrap();
    vaults.callosum.announce_peer_key(&a.member, &a_public);
    vaults.callosum.announce_peer_key(&b.member, &b_public);
    vaults.callosum.set_pairing(&a.member, Some(PAIRING));
    b.store()
        .create_member_grant_audited(
            &a.member,
            MemberGrantOperation::TransferDeliver,
            &MemberGrantSelector::None,
            PAIRING,
        )
        .unwrap();
    route_to_home(&vaults, OP_TRANSFER_DELIVER, &b, &a.member);

    let report = ok(a
        .run(&AdminOpBody::TransferSend {
            v: ADMIN_OP_SCHEMA_V2,
            credential_id: API_ID.into(),
            to: b.member.clone(),
        })
        .await);
    assert_eq!(report["reply"], "pending", "{report}");
    assert!(b.store().meta(API_ID).is_err(), "nothing exists before accept");

    let receive = ok(b
        .run(&AdminOpBody::TransferReceive {
            v: ADMIN_OP_SCHEMA_V2,
        })
        .await);
    let pending = receive["pending"].as_array().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0]["sender"], a.member.as_str());
    let transfer_id = pending[0]["transfer_id"].as_str().unwrap().to_string();

    let accept = AdminOpBody::TransferAccept {
        v: ADMIN_OP_SCHEMA_V2,
        transfer_id: transfer_id.clone(),
        from: a.member.clone(),
        replace: false,
    };
    let accepted = ok(b.run(&accept).await);
    assert_eq!(accepted["state"], "accepted");
    assert_eq!(accepted["credential_id"], API_ID);
    assert_eq!(b.store().get(API_ID).unwrap().payload.expose(), b"sk-test");
    assert_eq!(b.store().categories(API_ID).unwrap(), vec![CATEGORY.to_string()]);
    assert_eq!(audit_count(b.store(), AuditOp::TransferIn), 1);

    let again = ok(b.run(&accept).await);
    assert_eq!(again["already_decided"], true);
    assert_eq!(audit_count(b.store(), AuditOp::TransferIn), 1);
}

// ---------------------------------------------------------------------------------
// Remote records
// ---------------------------------------------------------------------------------

fn login_record() -> VaultRecord {
    VaultRecord::new_oauth(
        "opencode",
        "anthropic",
        OAuthCredential {
            access_token: "access-home-1".to_string().into(),
            refresh_token: "refresh-home-1".to_string().into(),
            expires_at_ms: Some(wall_ms() + 3_600_000),
            token_url: "https://token.test/oauth".into(),
            client_id: Some("client".into()),
            client_secret: None,
            scopes: vec![],
        },
        b"access-home-1".to_vec(),
    )
}

/// A as home of an Anthropic-shaped login granted to B, with both transfer keys
/// announced, and A's home answering B's token fetches through the stand-in.
async fn remote_rig(tag: &str) -> (credentials_core::test_support::TestTempDir, TwoVaults, Vault, Vault) {
    let root = crate::support::temp_root(tag);
    let vaults = TwoVaults::new(&root).await;
    let a = Vault::open(&vaults.a, Some(Duration::from_secs(4)));
    let b = Vault::open(&vaults.b, Some(Duration::from_secs(4)));
    let a_public = a.install_transfer_key();
    let b_public = b.install_transfer_key();
    vaults.callosum.announce_peer_key(&a.member, &a_public);
    vaults.callosum.announce_peer_key(&b.member, &b_public);
    vaults.callosum.set_pairing(&b.member, Some(PAIRING));
    a.store().create(LOGIN_ID, &login_record()).unwrap();
    a.store()
        .set_categories_audited(
            LOGIN_ID,
            SetCategoryMode::Set,
            &[CATEGORY.to_string()],
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .unwrap();
    a.store()
        .create_member_grant_audited(
            &b.member,
            MemberGrantOperation::RemoteRead,
            &MemberGrantSelector::Exact(LOGIN_ID.into()),
            PAIRING,
        )
        .unwrap();
    route_to_home(&vaults, OP_REMOTE_TOKEN, &a, &b.member);
    (root, vaults, a, b)
}

fn reader(b: &Vault, fixture: &VaultFixture, adapters: &[&str]) -> Arc<RemoteReader> {
    let reader = RemoteReader::new(
        Arc::clone(&b.home_store.store),
        adapters.iter().map(|name| name.to_string()),
    );
    assert!(reader.attach_outbound(fixture.outbound.clone()));
    Arc::new(reader)
}

/// `remote add` fetches once from the home and stores only its description, through
/// the same reader and reply validation a consumer read uses: a reply naming an adapter
/// this vault does not register is refused with no row. A handle cannot be minted for
/// the remote id, and an id held locally is refused before any fetch.
#[tokio::test]
async fn remote_add_stores_the_home_description_and_refuses_an_unregistered_adapter() {
    let (_root, vaults, _a, b) = remote_rig("admin-remote").await;
    let add = AdminOpBody::RemoteAdd {
        v: ADMIN_OP_SCHEMA_V2,
        credential_id: LOGIN_ID.into(),
        home: vaults.home_member().into(),
    };

    // A vault that registers no `anthropic` adapter.
    let narrow = Arc::new({
        let key = MasterKey::from_bytes(MASTER_KEY);
        let admin = AdminSurface::new(
            Arc::clone(&b.home_store.engine),
            AdminMacKey::derive(&key),
            VAULT_ID,
            key.key_id(),
        );
        assert!(admin.home().attach_outbound(vaults.b.outbound.clone()));
        assert!(admin.attach_remote_reader(reader(&b, &vaults.b, &["openai"])));
        admin
    });
    let refused = refusal(run_on(&narrow, &add).await);
    assert!(refused.starts_with("remote_reply_invalid/permanent"), "{refused}");
    assert!(b.store().list_remote_records().unwrap().is_empty());
    assert_eq!(audit_count(b.store(), AuditOp::RemoteAdd), 0);

    assert!(b
        .admin
        .attach_remote_reader(reader(&b, &vaults.b, &FAKE_ADAPTERS)));
    let added = ok(b.run(&add).await);
    assert_eq!(added["home"], vaults.home_member());
    let records = b.store().list_remote_records().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].refresh_adapter.as_deref(), Some("anthropic"));
    assert_eq!(b.store().remote_inventory().unwrap()[0].categories, vec![CATEGORY.to_string()]);
    assert_eq!(audit_count(b.store(), AuditOp::RemoteAdd), 1);

    let mint = refusal(
        b.run(&AdminOpBody::MintHandle {
            v: ADMIN_OP_SCHEMA_V1,
            id: LOGIN_ID.into(),
        })
        .await,
    );
    assert!(mint.starts_with("remote_record/permanent"), "{mint}");

    b.put_api_key();
    let fetches = vaults.callosum.methods(TARGET_MODULE).len();
    let local = refusal(
        b.run(&AdminOpBody::RemoteAdd {
            v: ADMIN_OP_SCHEMA_V2,
            credential_id: API_ID.into(),
            home: vaults.home_member().into(),
        })
        .await,
    );
    assert!(local.starts_with("credential_id_is_local"), "{local}");
    assert_eq!(vaults.callosum.methods(TARGET_MODULE).len(), fetches);
}

// ---------------------------------------------------------------------------------
// Offline, and the read surface
// ---------------------------------------------------------------------------------

/// Every admin op that needs an outbound call is refused by the shared applier, which
/// is what the offline lease path runs, with `federation_requires_daemon` and before
/// any write: no record, row, setting or audit entry appears.
#[tokio::test]
async fn offline_runs_of_the_outbound_admin_ops_answer_federation_requires_daemon_with_no_write() {
    let root = crate::support::temp_root("admin-offline");
    let fixture_store = HomeStore::open(&root.join("offline"));
    let store = &fixture_store.store;
    store
        .create(
            API_ID,
            &VaultRecord::new_static(CredentialKind::ApiKey, "operator", b"sk".to_vec(), None),
        )
        .unwrap();
    let member = "fed-computer:0123456789abcdef0123456789abcdef".to_string();
    let transfer_id = "00112233445566778899aabbccddeeff".to_string();
    let v = ADMIN_OP_SCHEMA_V2;
    let ops = [
        AdminOpBody::TransferInit {
            v,
            self_member: member.clone(),
        },
        AdminOpBody::FederationSelfSet {
            v,
            member: member.clone(),
        },
        AdminOpBody::TransferSend {
            v,
            credential_id: API_ID.into(),
            to: member.clone(),
        },
        AdminOpBody::TransferResume {
            v,
            transfer_id: transfer_id.clone(),
        },
        AdminOpBody::TransferAccept {
            v,
            transfer_id,
            from: member.clone(),
            replace: false,
        },
        AdminOpBody::RemoteAdd {
            v,
            credential_id: LOGIN_ID.into(),
            home: member.clone(),
        },
        AdminOpBody::MemberGrant {
            v,
            member,
            operation: MemberGrantOperation::TransferDeliver,
            selector: MemberGrantSelector::None,
        },
    ];
    let snapshot = |store: &EncryptedStore| {
        (
            store.read_audit(None).unwrap().len(),
            store.list_meta().unwrap().len(),
            store.list_remote_records().unwrap().len(),
            store.list_member_grants().unwrap().len(),
            store.list_outgoing_transfers().unwrap().len(),
            store.federation_self_member().unwrap(),
        )
    };
    let before = snapshot(store);
    for op in ops {
        assert!(op.requires_daemon(), "{op:?}");
        let name = format!("{op:?}");
        match credentials_core::admin_ops::apply(store, op, "offline-cli") {
            Err(credentials_core::store::StoreOpError::Encode(message)) => {
                assert!(message.starts_with(FEDERATION_REQUIRES_DAEMON), "{name}: {message}")
            }
            other => panic!("{name} was not refused as federation_requires_daemon: {other:?}"),
        }
    }
    assert_eq!(snapshot(store), before);
}

/// The manifest of daemon source files, and which of them may name the transfer
/// sender (`Transfers`, which is what sends): only the federation module that defines
/// it and the admin surface, whose dispatch runs only for an authenticated admin op. So
/// no read-surface op (nor the frame loop, the watch hub or the account-token path) can
/// trigger a send. A new source file fails the manifest until it is classified here.
#[test]
fn the_manifest_shows_no_read_surface_op_can_trigger_a_send() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let may_send = [
        "admin_surface.rs",
        "federation/mod.rs",
        "federation/transfer.rs",
    ];
    let may_not_send = [
        "main.rs",
        "lib.rs",
        "read_surface.rs",
        "limiter.rs",
        "watch_scoped.rs",
        "watch_scoped_tests.rs",
        "account_token.rs",
        "account_token_tests.rs",
        "test_support.rs",
        "federation/ingress.rs",
        "federation/outbound.rs",
        "federation/remote_read.rs",
    ];
    let mut on_disk = Vec::new();
    for dir in ["", "federation"] {
        for entry in std::fs::read_dir(src.join(dir)).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|ext| ext == "rs") {
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                on_disk.push(if dir.is_empty() {
                    name
                } else {
                    format!("{dir}/{name}")
                });
            }
        }
    }
    on_disk.sort();
    let mut classified: Vec<String> = may_send
        .iter()
        .chain(may_not_send.iter())
        .map(|name| name.to_string())
        .collect();
    classified.sort();
    assert_eq!(
        on_disk, classified,
        "a daemon source file was added or removed: classify it in this manifest"
    );

    // Built by concatenation, so this file's own text is never what the scan finds.
    let sender = format!("{}{}", "Trans", "fers");
    for name in may_not_send {
        let text = std::fs::read_to_string(src.join(name)).unwrap();
        assert!(
            !text.contains(&sender),
            "{name} names the transfer sender; only the admin surface may dispatch a send"
        );
    }
    // Positive control: the scan finds the sender where it is used.
    let admin = std::fs::read_to_string(src.join("admin_surface.rs")).unwrap();
    assert!(admin.contains(&format!("{sender}::new")));
    assert!(admin.contains("send_deliver") && admin.contains("fn dispatch_federation"));
}
