//! The home side of federation: what a federation channel's calls get from the home
//! vault, against a real store and the callosum stand-in.
//!
//! The requester (B) is played by the test: it builds the token `aad`, calls the home
//! as the attested harness member, and opens the sealed reply with its own transfer
//! key, exactly as B's remote read will. Setup calls the store APIs directly: the
//! `transfer init` and `member grant` admin verbs that will wrap them do not exist yet.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use claustrum_module_probe::federation::ingress::{
    project_access_token, OP_REMOTE_TOKEN, OP_REPORT_AUTH_FAILURE, OP_TRANSFER_DELIVER,
    REMOTE_TOKEN_INFO,
};
use claustrum_module_probe::federation::{HomeAnswer, HomeVault, HOME_OP_DEADLINE};
use credentials_core::audit::{AuditCtx, AuditOp};
use credentials_core::federation::{MemberGrantOperation, MemberGrantSelector, VAULT_TRANSFER_ID};
use credentials_core::oauth::OAuthCredential;
use credentials_core::record::{CredentialKind, VaultRecord};
use credentials_core::store::SetCategoryMode;
use serde_json::{json, Value};
use tokio::time::Instant;

use crate::support::{
    resolved_after_advance, wait_for_signal, wait_until, Held, HomeStore, Reply, TwoVaults,
};

const PAIRING: &str = "pair-1";
const TOKEN_ID: &str = "oauth:anthropic:work";

/// The only fields a sealed token reply may carry.
const REPLY_FIELDS: [&str; 10] = [
    "payload",
    "expires_in_ms",
    "recheck_in_ms",
    "record_version",
    "project_id",
    "account_id",
    "identity",
    "categories",
    "refresh_adapter",
    "detected_plan",
];

struct Rig {
    _root: credentials_core::test_support::TestTempDir,
    vaults: TwoVaults,
    home_store: HomeStore,
    home: HomeVault,
    /// The home's transfer public key, which B opens replies against.
    home_public: Vec<u8>,
    requester_pem: String,
    requester_key_id: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl Rig {
    /// A home with its self id and transfer key, a requester B that is paired as
    /// [`PAIRING`] and has announced its transfer key.
    async fn new(tag: &str) -> Self {
        Self::build(tag, None).await
    }

    async fn build(
        tag: &str,
        gate: Option<claustrum_module_probe::federation::ingress::IssueAuditGate>,
    ) -> Self {
        let root = crate::support::temp_root(tag);
        let vaults = TwoVaults::new(&root).await;
        let home_store = HomeStore::open(&vaults.a.data_dir);
        let store = &home_store.store;
        let transfer_pem = credentials_core::kem::generate_key().expect("transfer key");
        let (home_public, _) =
            credentials_core::kem::public_half(&transfer_pem).expect("public half");
        store
            .create_audited(
                VAULT_TRANSFER_ID,
                &VaultRecord::new_static(
                    CredentialKind::KemKey,
                    "operator",
                    transfer_pem.into_bytes(),
                    None,
                ),
                AuditCtx::admin(AuditOp::Put),
            )
            .expect("transfer init");
        store
            .set_federation_self_member_audited(
                vaults.home_member(),
                AuditCtx::admin(AuditOp::FederationSelfSet),
            )
            .expect("federation self");

        let requester_pem = credentials_core::kem::generate_key().expect("requester key");
        let (requester_public, requester_key_id) =
            credentials_core::kem::public_half(&requester_pem).expect("requester public");
        let requester = vaults.requester_member().to_string();
        vaults.callosum.set_pairing(&requester, Some(PAIRING));
        vaults
            .callosum
            .announce_peer_key(&requester, &hex(&requester_public));

        let mut home = HomeVault::new(Arc::clone(&home_store.engine));
        if let Some(gate) = gate {
            home = home.with_issue_audit_gate(gate);
        }
        assert!(home.attach_outbound(vaults.a.outbound.clone()));
        Self {
            _root: root,
            vaults,
            home_store,
            home,
            home_public,
            requester_pem,
            requester_key_id,
        }
    }

    fn requester(&self) -> String {
        self.vaults.requester_member().to_string()
    }

    fn store(&self) -> &credentials_core::store::EncryptedStore {
        &self.home_store.store
    }

    /// Create an Anthropic-shaped rotating login in `category`.
    fn add_login(&self, id: &str, category: &str) {
        self.store()
            .create(
                id,
                &oauth_record("anthropic", "access-0", "refresh-0", None),
            )
            .expect("create login");
        self.set_category(id, category);
    }

    fn set_category(&self, id: &str, category: &str) {
        self.store()
            .set_categories_audited(
                id,
                SetCategoryMode::Set,
                &[category.to_string()],
                AuditCtx::admin(AuditOp::SetCategory),
            )
            .expect("set category");
    }

    fn grant(&self, selector: MemberGrantSelector, pairing: &str) {
        self.store()
            .create_member_grant_audited(
                &self.requester(),
                MemberGrantOperation::RemoteRead,
                &selector,
                pairing,
            )
            .expect("member grant");
    }

    fn grant_exact(&self, id: &str) {
        self.grant(MemberGrantSelector::Exact(id.to_string()), PAIRING);
    }

    /// The aad bytes B sends for `id`, with its own self id as requester.
    fn aad(&self, id: &str) -> String {
        self.aad_as(id, &self.requester(), self.vaults.home_member())
    }

    fn aad_as(&self, id: &str, requester: &str, home: &str) -> String {
        format!(
            r#"{{"credential_id":"{id}","requester":"{requester}","home":"{home}","nonce":"00112233445566778899aabbccddeeff","recipient_key_id":"{}"}}"#,
            self.requester_key_id
        )
    }

    async fn call(&self, method: &str, params: Value) -> HomeAnswer {
        self.home.serve(&self.requester(), method, &params).await
    }

    /// `federation.remote_token` for `id`, returning the reply body.
    async fn fetch(&self, id: &str) -> Value {
        self.fetch_aad(&self.aad(id)).await
    }

    async fn fetch_aad(&self, aad: &str) -> Value {
        reply(self.call(OP_REMOTE_TOKEN, json!({ "aad": aad })).await)
    }

    /// Open a sealed reply as B, over the aad B sent.
    fn open(&self, reply: &Value, aad: &str) -> Value {
        let b64 = base64::engine::general_purpose::STANDARD;
        let enc = b64
            .decode(reply["enc"].as_str().expect("enc"))
            .expect("enc b64");
        let ciphertext = b64
            .decode(reply["ciphertext"].as_str().expect("ciphertext"))
            .expect("ciphertext b64");
        let plaintext = credentials_core::kem::open_auth(
            &self.requester_pem,
            &self.home_public,
            &enc,
            &ciphertext,
            REMOTE_TOKEN_INFO,
            aad.as_bytes(),
        )
        .expect("B opens the reply with the home's announced key");
        serde_json::from_slice(&plaintext).expect("reply plaintext is JSON")
    }

    async fn served_token(&self, id: &str) -> Value {
        let aad = self.aad(id);
        let reply = self.fetch_aad(&aad).await;
        assert!(reply.get("error").is_none(), "expected a token: {reply}");
        self.open(&reply, &aad)
    }

    fn audit_ops(&self, op: &str) -> Vec<credentials_core::audit::AuditEntry> {
        self.store()
            .read_audit(None)
            .expect("audit")
            .into_iter()
            .filter(|entry| entry.op == op)
            .collect()
    }
}

fn oauth_record(adapter: &str, access: &str, refresh: &str, secret: Option<&str>) -> VaultRecord {
    VaultRecord::new_oauth(
        "opencode",
        adapter,
        OAuthCredential {
            access_token: access.to_string().into(),
            refresh_token: refresh.to_string().into(),
            expires_at_ms: Some(crate::support::wall_ms() + 3_600_000),
            token_url: "https://token.test/oauth".into(),
            client_id: Some("client".into()),
            client_secret: secret.map(|secret| secret.to_string().into()),
            scopes: vec![],
        },
        access.as_bytes().to_vec(),
    )
}

fn reply(answer: HomeAnswer) -> Value {
    match answer {
        HomeAnswer::Reply(value) => value,
        HomeAnswer::InvalidParams(detail) => panic!("unexpected invalid_params: {detail}"),
    }
}

fn not_found() -> Value {
    json!({ "error": { "code": "not_found", "class": "permanent" } })
}

fn error_code(reply: &Value) -> &str {
    reply["error"]["code"].as_str().unwrap_or("<none>")
}

// ---------------------------------------------------------------------------------
// Serving
// ---------------------------------------------------------------------------------

#[tokio::test]
async fn a_granted_member_gets_the_access_token_sealed_to_its_announced_key() {
    let rig = Rig::new("ingress-serve").await;
    rig.add_login(TOKEN_ID, "llm-provider");
    rig.grant_exact(TOKEN_ID);

    let token = rig.served_token(TOKEN_ID).await;
    assert_eq!(token["payload"], "access-0");
    assert_eq!(token["record_version"], 1);
    assert_eq!(token["refresh_adapter"], "anthropic");
    assert_eq!(token["categories"], json!(["llm-provider"]));
    let expires_in = token["expires_in_ms"].as_i64().expect("an expiring token");
    assert!(
        expires_in > 3_500_000 && expires_in <= 3_600_000,
        "{expires_in}"
    );
    for field in token.as_object().expect("object").keys() {
        assert!(
            REPLY_FIELDS.contains(&field.as_str()),
            "the reply carries a field outside the list: {field}"
        );
    }
    assert!(
        !token.to_string().contains("refresh-0"),
        "the refresh token never leaves the home: {token}"
    );
    assert_eq!(
        rig.home_store.upstream_calls(),
        0,
        "a fresh token needs no refresh"
    );
}

#[tokio::test]
async fn member_first_use_is_recorded_once_per_member_and_credential_only_after_a_serve() {
    let rig = Rig::new("ingress-member-first-use").await;
    rig.add_login(TOKEN_ID, "llm-provider");
    let first_uses = || {
        rig.store()
            .recent_auth_events(500)
            .unwrap()
            .into_iter()
            .filter(|row| row.kind == "scoped_first_use")
            .map(|row| {
                (
                    row.credential_id,
                    row.principal_kind,
                    row.principal_id,
                    row.detail,
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(rig.fetch(TOKEN_ID).await, not_found());
    assert!(
        first_uses().is_empty(),
        "a refused serve records no first use"
    );
    rig.grant_exact(TOKEN_ID);
    rig.served_token(TOKEN_ID).await;
    rig.served_token(TOKEN_ID).await;
    assert_eq!(
        first_uses(),
        vec![(
            TOKEN_ID.into(),
            Some("member".into()),
            Some(rig.requester()),
            Some("read".into())
        )]
    );

    let other = "fed-computer:cccccccccccccccccccccccccccccccc";
    rig.vaults.callosum.set_pairing(other, Some("pair-other"));
    let (public, _) = credentials_core::kem::public_half(&rig.requester_pem).unwrap();
    rig.vaults.callosum.announce_peer_key(other, &hex(&public));
    rig.store()
        .create_member_grant_audited(
            other,
            MemberGrantOperation::RemoteRead,
            &MemberGrantSelector::Exact(TOKEN_ID.into()),
            "pair-other",
        )
        .unwrap();
    let aad = rig.aad_as(TOKEN_ID, other, rig.vaults.home_member());
    for _ in 0..2 {
        let body = reply(
            rig.home
                .serve(other, OP_REMOTE_TOKEN, &json!({ "aad": aad }))
                .await,
        );
        assert!(body.get("enc").is_some(), "expected a sealed token: {body}");
    }
    let rows = first_uses();
    assert_eq!(rows.len(), 2);
    assert!(rows.contains(&(
        TOKEN_ID.into(),
        Some("member".into()),
        Some(other.into()),
        Some("read".into())
    )));

    let second_id = "oauth:anthropic:second";
    rig.add_login(second_id, "llm-provider");
    assert_eq!(rig.fetch(second_id).await, not_found());
    assert_eq!(first_uses().len(), 2);
    rig.grant_exact(second_id);
    rig.served_token(second_id).await;
    assert_eq!(
        first_uses().len(),
        3,
        "a different credential has its own first use"
    );
}

#[tokio::test]
async fn a_reply_opens_only_for_the_aad_it_was_sealed_over() {
    let rig = Rig::new("ingress-aad-binding").await;
    rig.add_login(TOKEN_ID, "llm-provider");
    rig.grant_exact(TOKEN_ID);
    let aad = rig.aad(TOKEN_ID);
    let sealed = rig.fetch_aad(&aad).await;
    let b64 = base64::engine::general_purpose::STANDARD;
    let enc = b64.decode(sealed["enc"].as_str().unwrap()).unwrap();
    let ciphertext = b64.decode(sealed["ciphertext"].as_str().unwrap()).unwrap();
    // The same reply opened as if it answered a request for another credential.
    let other = aad.replace(TOKEN_ID, "oauth:anthropic:other");
    assert!(credentials_core::kem::open_auth(
        &rig.requester_pem,
        &rig.home_public,
        &enc,
        &ciphertext,
        REMOTE_TOKEN_INFO,
        other.as_bytes(),
    )
    .is_err());
    // And under the transfer literal.
    assert!(credentials_core::kem::open_auth(
        &rig.requester_pem,
        &rig.home_public,
        &enc,
        &ciphertext,
        b"cortexkit/claustrum/transfer/v1",
        aad.as_bytes(),
    )
    .is_err());
}

#[tokio::test]
async fn an_upstream_refresh_slower_than_the_home_budget_answers_transient_and_still_persists() {
    let rig = Arc::new(Rig::new("ingress-slow-refresh").await);
    // An expired token: the next read must refresh.
    let mut record = oauth_record("anthropic", "access-0", "refresh-0", None);
    record.oauth.as_mut().unwrap().expires_at_ms = Some(crate::support::wall_ms() - 1_000);
    record.expires_at_ms = Some(crate::support::wall_ms() - 1_000);
    rig.store().create(TOKEN_ID, &record).expect("create");
    rig.grant_exact(TOKEN_ID);
    rig.home_store.slow_upstream(Duration::from_millis(2_000));

    tokio::time::pause();
    let started = Instant::now();
    let first = {
        let rig = Arc::clone(&rig);
        tokio::spawn(async move { rig.fetch(TOKEN_ID).await })
    };
    wait_until(|| rig.home_store.upstream_calls() == 1).await;
    let first = resolved_after_advance(first, HOME_OP_DEADLINE + Duration::from_millis(1)).await;
    let elapsed = started.elapsed();
    assert_eq!(error_code(&first), "home_unavailable", "{first}");
    assert_eq!(first["error"]["class"], "transient");
    assert!(
        elapsed < Duration::from_millis(1_900),
        "answered inside the budget: {elapsed:?}"
    );

    // The refresh keeps running to completion and persists the rotated token.
    tokio::time::advance(Duration::from_millis(500)).await;
    wait_until(|| rig.store().get(TOKEN_ID).unwrap().payload.expose() == b"access-refreshed-1")
        .await;
    rig.home_store.slow_upstream(Duration::ZERO);
    let token = wait_for_signal(rig.served_token(TOKEN_ID)).await;
    assert_eq!(token["payload"], "access-refreshed-1");
    assert_eq!(
        rig.home_store.upstream_calls(),
        1,
        "the next read made no upstream call"
    );
}

// ---------------------------------------------------------------------------------
// Uniform refusals and the op order
// ---------------------------------------------------------------------------------

#[tokio::test]
async fn no_grant_a_stale_pairing_an_unknown_id_and_an_ungranted_category_are_byte_identical() {
    let rig = Rig::new("ingress-uniform").await;
    rig.add_login(TOKEN_ID, "llm-provider");
    rig.add_login("oauth:anthropic:other", "other-category");

    let no_grant = rig.fetch(TOKEN_ID).await;
    let unknown = rig.fetch("oauth:anthropic:missing").await;
    rig.grant(
        MemberGrantSelector::Category("llm-provider".into()),
        PAIRING,
    );
    let ungranted_category = rig.fetch("oauth:anthropic:other").await;
    // Unpair and re-pair with the same key: the grant made under the old pairing id no
    // longer counts.
    rig.vaults
        .callosum
        .set_pairing(&rig.requester(), Some("pair-2"));
    let stale_pairing = rig.fetch(TOKEN_ID).await;

    let bytes = |value: &Value| serde_json::to_vec(value).unwrap();
    assert_eq!(no_grant, not_found());
    for (why, other) in [
        ("unknown id", &unknown),
        ("ungranted category", &ungranted_category),
        ("stale pairing", &stale_pairing),
    ] {
        assert_eq!(bytes(other), bytes(&no_grant), "{why}: {other}");
    }

    // Re-granting under the current pairing restores exactly the selected reach.
    rig.grant(
        MemberGrantSelector::Category("llm-provider".into()),
        "pair-2",
    );
    assert_eq!(rig.served_token(TOKEN_ID).await["payload"], "access-0");
    assert_eq!(rig.fetch("oauth:anthropic:other").await, not_found());

    // Every refusal named the member in auth_events, never callosum.
    let principals = auth_event_principals(&rig, TOKEN_ID);
    assert!(
        !principals.is_empty() && principals.iter().all(|p| p == &rig.requester()),
        "{principals:?}"
    );
}

fn auth_event_principals(rig: &Rig, id: &str) -> Vec<String> {
    let conn = rusqlite::Connection::open(rig.vaults.a.data_dir.join("store.db")).unwrap();
    let mut stmt = conn
        .prepare("SELECT COALESCE(principal_id, '') FROM auth_events WHERE credential_id = ?1")
        .unwrap();
    let rows = stmt
        .query_map([id], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    rows
}

#[tokio::test]
async fn after_a_re_pair_only_grants_made_since_count() {
    let rig = Rig::new("ingress-re-pair").await;
    rig.add_login(TOKEN_ID, "llm-provider");
    rig.add_login("oauth:anthropic:exact-only", "unshared");
    // Exact grants made under the first pairing.
    rig.grant_exact(TOKEN_ID);
    rig.grant_exact("oauth:anthropic:exact-only");
    rig.vaults
        .callosum
        .set_pairing(&rig.requester(), Some("pair-2"));
    // Only the category grant is re-made after the re-pair.
    rig.grant(
        MemberGrantSelector::Category("llm-provider".into()),
        "pair-2",
    );

    assert_eq!(rig.served_token(TOKEN_ID).await["payload"], "access-0");
    assert_eq!(rig.fetch("oauth:anthropic:exact-only").await, not_found());
    // Proof the token above came through the category reach: revoke it, and the old
    // exact grant does not take over.
    rig.store()
        .revoke_member_grant_audited(
            &rig.requester(),
            MemberGrantOperation::RemoteRead,
            &MemberGrantSelector::Category("llm-provider".into()),
        )
        .unwrap();
    assert_eq!(rig.fetch(TOKEN_ID).await, not_found());
}

#[tokio::test]
async fn a_requester_whose_self_id_is_wrong_is_told_to_fix_its_own_setup() {
    let rig = Rig::new("ingress-requester").await;
    rig.add_login(TOKEN_ID, "llm-provider");
    // No grant at all: the setup fact is about the caller, so it precedes the grant.
    let wrong = "fed-computer:ffffffffffffffffffffffffffffffff";
    let reply = rig
        .fetch_aad(&rig.aad_as(TOKEN_ID, wrong, rig.vaults.home_member()))
        .await;
    assert_eq!(error_code(&reply), "remote_setup_incomplete", "{reply}");
    assert_eq!(reply["error"]["class"], "permanent");
    assert_eq!(reply["error"]["remedy_member"], rig.requester());
}

#[tokio::test]
async fn a_request_for_another_home_is_not_found_and_a_home_without_setup_says_so() {
    let rig = Rig::new("ingress-home-setup").await;
    rig.add_login(TOKEN_ID, "llm-provider");
    rig.grant_exact(TOKEN_ID);
    let other_home = "fed-computer:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    let reply = rig
        .fetch_aad(&rig.aad_as(TOKEN_ID, &rig.requester(), other_home))
        .await;
    assert_eq!(reply, not_found());

    // A home with no transfer key names itself as the member to fix.
    let conn = rusqlite::Connection::open(rig.vaults.a.data_dir.join("store.db")).unwrap();
    conn.execute(
        "UPDATE credentials SET state = 'needs_reauth' WHERE credential_id = ?1",
        [VAULT_TRANSFER_ID],
    )
    .unwrap();
    let reply = rig.fetch(TOKEN_ID).await;
    assert_eq!(error_code(&reply), "remote_setup_incomplete", "{reply}");
    assert_eq!(reply["error"]["remedy_member"], rig.vaults.home_member());
}

#[tokio::test]
async fn a_home_with_no_self_id_answers_setup_incomplete() {
    let rig = Rig::new("ingress-no-self").await;
    rig.add_login(TOKEN_ID, "llm-provider");
    rig.grant_exact(TOKEN_ID);
    let conn = rusqlite::Connection::open(rig.vaults.a.data_dir.join("store.db")).unwrap();
    conn.execute(
        "DELETE FROM settings WHERE name = 'federation.self_member'",
        [],
    )
    .unwrap();
    let reply = rig.fetch(TOKEN_ID).await;
    assert_eq!(error_code(&reply), "remote_setup_incomplete", "{reply}");
    assert_eq!(reply["error"]["remedy_member"], rig.vaults.home_member());
}

#[tokio::test]
async fn a_requester_with_no_announced_key_is_told_to_fix_its_own_setup() {
    let rig = Rig::new("ingress-no-key").await;
    rig.add_login(TOKEN_ID, "llm-provider");
    rig.grant_exact(TOKEN_ID);
    // Callosum announces some other key: the aad's key id no longer matches.
    let (other_public, _) =
        credentials_core::kem::public_half(&credentials_core::kem::generate_key().unwrap())
            .unwrap();
    rig.vaults
        .callosum
        .announce_peer_key(&rig.requester(), &hex(&other_public));
    let reply = rig.fetch(TOKEN_ID).await;
    assert_eq!(error_code(&reply), "remote_setup_incomplete", "{reply}");
    assert_eq!(reply["error"]["remedy_member"], rig.requester());
}

#[tokio::test]
async fn an_unpaired_member_is_not_found_and_a_failed_pairing_lookup_is_transient() {
    let rig = Arc::new(Rig::new("ingress-pairing").await);
    rig.add_login(TOKEN_ID, "llm-provider");
    rig.grant_exact(TOKEN_ID);
    rig.vaults.callosum.set_pairing(&rig.requester(), None);
    assert_eq!(rig.fetch(TOKEN_ID).await, not_found());

    rig.vaults.callosum.answer(
        "claustrum",
        "callosum.paired_devices_read",
        Reply::RouteRefusal("fed_not_ready".into()),
    );
    let reply = rig.fetch(TOKEN_ID).await;
    assert_eq!(error_code(&reply), "home_unavailable", "{reply}");
    assert_eq!(reply["error"]["class"], "transient");

    let lookup = Held::new();
    rig.vaults.callosum.answer(
        "claustrum",
        "callosum.paired_devices_read",
        Reply::Hold(lookup.clone()),
    );
    tokio::time::pause();
    let started = Instant::now();
    let mut request = {
        let rig = Arc::clone(&rig);
        tokio::spawn(async move { rig.fetch(TOKEN_ID).await })
    };
    lookup.arrived_before(&mut request).await;
    let reply = resolved_after_advance(request, HOME_OP_DEADLINE + Duration::from_millis(1)).await;
    assert_eq!(error_code(&reply), "home_unavailable", "{reply}");
    assert!(
        started.elapsed() < Duration::from_millis(1_800),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn the_allowlist_bearer_params_and_strict_parsing() {
    let rig = Rig::new("ingress-allowlist").await;
    rig.add_login(TOKEN_ID, "llm-provider");
    rig.grant_exact(TOKEN_ID);
    let aad = rig.aad(TOKEN_ID);
    // Any op outside the allowlist answers not_found. So does a transfer delivery from
    // this member: it holds no transfer_deliver grant, and the grant check runs before
    // the params are read.
    for method in [
        "credential.get",
        "credential.get_scoped",
        "admin.op",
        OP_TRANSFER_DELIVER,
    ] {
        assert_eq!(
            reply(rig.call(method, json!({})).await),
            not_found(),
            "{method}"
        );
    }
    // Bearer params are refused before anything else looks at the request.
    for params in [
        json!({ "aad": aad, "handle": "ckh_x" }),
        json!({ "aad": aad, "enrollment_token": "t" }),
    ] {
        assert!(
            matches!(
                rig.call(OP_REMOTE_TOKEN, params.clone()).await,
                HomeAnswer::InvalidParams(_)
            ),
            "{params}"
        );
    }
    assert!(matches!(
        rig.call(OP_REPORT_AUTH_FAILURE, json!({ "handle": "ckh_x" }))
            .await,
        HomeAnswer::InvalidParams(_)
    ));
    // A supplied key or recipient cannot redirect the seal: it is an unknown field.
    assert!(matches!(
        rig.call(
            OP_REMOTE_TOKEN,
            json!({ "aad": aad, "recipient_public_key": "00" })
        )
        .await,
        HomeAnswer::InvalidParams(_)
    ));
    // The aad is parsed strictly.
    for bad in [
        aad.replace(
            r#","recipient_key_id""#,
            r#","extra":"x","recipient_key_id""#,
        ),
        aad.replace(r#""nonce":"00112233445566778899aabbccddeeff","#, ""),
        aad.replace("00112233445566778899aabbccddeeff", "NOTHEX"),
    ] {
        assert!(
            matches!(
                rig.call(OP_REMOTE_TOKEN, json!({ "aad": bad })).await,
                HomeAnswer::InvalidParams(_)
            ),
            "{bad}"
        );
    }
}

// ---------------------------------------------------------------------------------
// Eligibility and the projection
// ---------------------------------------------------------------------------------

#[tokio::test]
async fn ineligible_and_projection_refused_records_are_the_uniform_not_found_with_a_row() {
    let rig = Rig::new("ingress-projection").await;
    let cases: Vec<(&str, VaultRecord)> = vec![
        ("oauth:anthropic:payload-is-refresh", {
            let mut r = oauth_record("anthropic", "access-x", "refresh-x", None);
            r.payload = credentials_core::secret::SecretBytes::new(b"refresh-x".to_vec());
            r
        }),
        (
            "oauth:anthropic:token-is-refresh-segment",
            oauth_record("anthropic", "seg", "seg|project", None),
        ),
        (
            "oauth:anthropic:token-is-client-secret",
            oauth_record("anthropic", "shh", "refresh-y", Some("shh")),
        ),
        (
            "oauth:meta:token-is-identity-token",
            oauth_record(
                "meta",
                "idt",
                r#"{"identity_token":"idt","refresh_token":"nested"}"#,
                None,
            ),
        ),
        (
            "oauth:meta:token-is-nested-refresh",
            oauth_record(
                "meta",
                "nested",
                r#"{"identity_token":"idt","refresh_token":"nested"}"#,
                None,
            ),
        ),
        ("apikey:static", {
            VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None)
        }),
        ("oauth:anthropic:no-oauth-struct", {
            let mut r = oauth_record("anthropic", "a", "r", None);
            r.oauth = None;
            r
        }),
    ];
    for (id, record) in &cases {
        rig.store().create(id, record).expect("create fixture");
        rig.grant_exact(id);
        assert_eq!(rig.fetch(id).await, not_found(), "{id}");
        assert!(
            auth_event_principals(&rig, id).contains(&rig.requester()),
            "{id}: the refusal is recorded against the member"
        );
    }
    assert!(
        rig.audit_ops("remote_issue").is_empty(),
        "nothing was issued, so nothing was audited"
    );

    // Served: a canonical record and one whose client secret is empty.
    for (id, record) in [
        (
            "oauth:anthropic:canonical",
            oauth_record("anthropic", "tok-a", "ref-a", None),
        ),
        (
            "oauth:anthropic:empty-secret",
            oauth_record("anthropic", "tok-b", "ref-b", Some("")),
        ),
    ] {
        rig.store().create(id, &record).expect("create");
        rig.grant_exact(id);
        assert!(rig.served_token(id).await["payload"].is_string(), "{id}");
    }
}

#[test]
fn the_projection_serves_only_a_payload_that_is_the_non_refresh_access_token() {
    assert_eq!(
        project_access_token(&oauth_record("anthropic", "tok", "ref", None)),
        Some("tok")
    );
    assert_eq!(
        project_access_token(&oauth_record("anthropic", "tok", "ref", Some(""))),
        Some("tok")
    );
    let mut empty = oauth_record("anthropic", "", "ref", None);
    empty.payload = credentials_core::secret::SecretBytes::new(Vec::new());
    assert_eq!(project_access_token(&empty), None, "an empty token");
    let mut mismatched = oauth_record("anthropic", "tok", "ref", None);
    mismatched.payload = credentials_core::secret::SecretBytes::new(b"other".to_vec());
    assert_eq!(
        project_access_token(&mismatched),
        None,
        "payload is not the token"
    );
}

#[tokio::test]
async fn the_transfer_key_and_a_remote_id_are_never_served() {
    let rig = Rig::new("ingress-ineligible-ids").await;
    rig.grant_exact(VAULT_TRANSFER_ID);
    assert_eq!(rig.fetch(VAULT_TRANSFER_ID).await, not_found());
    rig.store()
        .remote_add_audited(&credentials_core::federation::NewRemoteRecord {
            credential_id: "oauth:anthropic:remote".into(),
            home_member: "fed-computer:cccccccccccccccccccccccccccccccc".into(),
            refresh_adapter: Some("anthropic".into()),
            detected_plan: None,
            identity: Default::default(),
            home_version: 3,
            categories: vec![],
        })
        .expect("remote add");
    rig.grant_exact("oauth:anthropic:remote");
    assert_eq!(rig.fetch("oauth:anthropic:remote").await, not_found());
}

// ---------------------------------------------------------------------------------
// Forwarded reports
// ---------------------------------------------------------------------------------

fn stale_and_version(rig: &Rig, id: &str) -> (i64, i64) {
    let conn = rusqlite::Connection::open(rig.vaults.a.data_dir.join("store.db")).unwrap();
    conn.query_row(
        "SELECT stale_pending, record_version FROM credentials WHERE credential_id = ?1",
        [id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .unwrap()
}

#[tokio::test]
async fn a_member_cannot_report_a_static_key_it_reaches_by_category() {
    let rig = Rig::new("ingress-report-static").await;
    rig.store()
        .create(
            "apikey:shared",
            &VaultRecord::new_static(CredentialKind::ApiKey, "test", b"key".to_vec(), None),
        )
        .unwrap();
    rig.set_category("apikey:shared", "llm-provider");
    rig.grant(
        MemberGrantSelector::Category("llm-provider".into()),
        PAIRING,
    );
    let answer = reply(
        rig.call(
            OP_REPORT_AUTH_FAILURE,
            json!({ "credential_id": "apikey:shared", "record_version": 1, "provider_status": 401 }),
        )
        .await,
    );
    assert_eq!(answer["error"], not_found()["error"], "{answer}");
    assert_eq!(answer["accepted"], false);
    assert!(
        rig.store().get("apikey:shared").is_ok(),
        "the key is still served locally"
    );
}

#[tokio::test]
async fn a_report_with_a_non_credential_status_marks_nothing() {
    let rig = Rig::new("ingress-report-500").await;
    rig.add_login(TOKEN_ID, "llm-provider");
    rig.grant_exact(TOKEN_ID);
    let chain_before = rig.store().read_audit(None).unwrap().len();
    let answer = reply(
        rig.call(
            OP_REPORT_AUTH_FAILURE,
            json!({ "credential_id": TOKEN_ID, "record_version": 1, "provider_status": 500 }),
        )
        .await,
    );
    assert_eq!(
        error_code(&answer),
        "report_status_not_credential_death",
        "{answer}"
    );
    assert_eq!(
        stale_and_version(&rig, TOKEN_ID),
        (0, 1),
        "no stale mark, same version"
    );
    assert_eq!(
        rig.store().read_audit(None).unwrap().len(),
        chain_before,
        "no chain row"
    );
    let token = rig.served_token(TOKEN_ID).await;
    assert_eq!(token["payload"], "access-0");
    assert_eq!(
        rig.home_store.upstream_calls(),
        0,
        "no upstream refresh followed"
    );
}

#[tokio::test]
async fn a_hundred_forwarded_reports_at_one_version_add_one_chain_row_naming_the_member() {
    let rig = Rig::new("ingress-report-bound").await;
    rig.add_login(TOKEN_ID, "llm-provider");
    rig.grant_exact(TOKEN_ID);
    for _ in 0..100 {
        let answer = reply(
            rig.call(
                OP_REPORT_AUTH_FAILURE,
                json!({ "credential_id": TOKEN_ID, "record_version": 1, "provider_status": 401 }),
            )
            .await,
        );
        assert_eq!(answer, json!({ "accepted": true }));
    }
    let rows = rig.audit_ops("report_auth_failure");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].actor, rig.requester());
    assert_eq!(stale_and_version(&rig, TOKEN_ID).0, 1, "the mark is set");
    assert!(rig.store().verify_audit_chain().is_ok());
}

// ---------------------------------------------------------------------------------
// remote_issue
// ---------------------------------------------------------------------------------

#[tokio::test]
async fn repeated_fetches_at_one_version_write_one_remote_issue_row_also_after_a_restart() {
    let rig = Rig::new("ingress-issue-bound").await;
    rig.add_login(TOKEN_ID, "llm-provider");
    rig.grant_exact(TOKEN_ID);
    for _ in 0..3 {
        rig.served_token(TOKEN_ID).await;
    }
    let rows = rig.audit_ops("remote_issue");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].credential_id.as_deref(), Some(TOKEN_ID));
    assert_eq!(rows[0].actor, rig.requester());
    assert_eq!(
        rows[0].payload_hash.as_deref(),
        Some(credentials_core::federation::remote_issue_payload_hash(TOKEN_ID, 1).as_str())
    );

    // A restarted home: the first store handle and home are dropped (the store holds
    // the single-writer lease), then a fresh store and home open the same data. The
    // same material appends nothing.
    let requester = rig.requester();
    let aad = rig.aad(TOKEN_ID);
    let Rig {
        _root,
        vaults,
        home_store,
        home,
        ..
    } = rig;
    drop(home);
    drop(home_store);
    let restarted = HomeStore::open(&vaults.a.data_dir);
    let home = HomeVault::new(Arc::clone(&restarted.engine));
    home.attach_outbound(vaults.a.outbound.clone());
    let answer = reply(
        home.serve(&requester, OP_REMOTE_TOKEN, &json!({ "aad": aad }))
            .await,
    );
    assert!(answer.get("enc").is_some(), "{answer}");
    let rows: Vec<_> = restarted
        .store
        .read_audit(None)
        .unwrap()
        .into_iter()
        .filter(|entry| entry.op == "remote_issue")
        .collect();
    assert_eq!(rows.len(), 1);
    assert!(restarted.store.verify_audit_chain().is_ok());
}

/// A gate that pauses the N-th fetch (1-based) at the audit point until released.
fn pause_fetch(
    nth: usize,
) -> (
    claustrum_module_probe::federation::ingress::IssueAuditGate,
    tokio::sync::mpsc::Receiver<tokio::sync::oneshot::Sender<()>>,
) {
    let (reached_tx, reached_rx) = tokio::sync::mpsc::channel(1);
    let count = Arc::new(AtomicUsize::new(0));
    let reached_tx = Arc::new(Mutex::new(Some(reached_tx)));
    let gate: claustrum_module_probe::federation::ingress::IssueAuditGate = Arc::new(move || {
        let count = Arc::clone(&count);
        let reached_tx = Arc::clone(&reached_tx);
        Box::pin(async move {
            if count.fetch_add(1, Ordering::SeqCst) + 1 != nth {
                return;
            }
            let Some(reached) = reached_tx.lock().unwrap().take() else {
                return;
            };
            let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
            let _ = reached.send(resume_tx).await;
            let _ = resume_rx.await;
        })
    });
    (gate, reached_rx)
}

#[tokio::test]
async fn a_fetch_whose_record_was_re_created_underneath_it_releases_nothing() {
    let (gate, mut reached) = pause_fetch(2);
    let rig = Arc::new(Rig::build("ingress-issue-recreate", Some(gate)).await);
    rig.add_login(TOKEN_ID, "llm-provider");
    rig.grant_exact(TOKEN_ID);
    rig.served_token(TOKEN_ID).await;
    assert_eq!(rig.audit_ops("remote_issue").len(), 1);

    tokio::time::pause();
    let paused = {
        let rig = Arc::clone(&rig);
        tokio::spawn(async move {
            let started = Instant::now();
            (rig.fetch(TOKEN_ID).await, started.elapsed())
        })
    };
    let resume = wait_for_signal(reached.recv())
        .await
        .expect("the second fetch reaches the audit point");
    // Delete and re-create the id at version 1 with new material.
    rig.store()
        .remove_audited(TOKEN_ID, AuditCtx::admin(AuditOp::Remove))
        .unwrap();
    rig.store()
        .create(
            TOKEN_ID,
            &oauth_record("anthropic", "access-new", "refresh-new", None),
        )
        .unwrap();
    rig.set_category(TOKEN_ID, "llm-provider");
    resume.send(()).unwrap();
    let (answer, elapsed) = wait_for_signal(paused).await.unwrap();
    assert_eq!(error_code(&answer), "home_unavailable", "{answer}");
    assert!(
        elapsed < Duration::from_millis(1_200),
        "the audit recheck refused it, not the home's deadline: {elapsed:?}"
    );
    assert_eq!(
        rig.audit_ops("remote_issue").len(),
        1,
        "the paused fetch wrote nothing"
    );

    // The next fetch serves the new material and is audited once more.
    assert_eq!(
        wait_for_signal(rig.served_token(TOKEN_ID)).await["payload"],
        "access-new"
    );
    assert_eq!(rig.audit_ops("remote_issue").len(), 2);
}

#[tokio::test]
async fn a_refresh_between_the_serving_read_and_the_audit_releases_nothing() {
    let (gate, mut reached) = pause_fetch(1);
    let rig = Arc::new(Rig::build("ingress-issue-refresh", Some(gate)).await);
    rig.add_login(TOKEN_ID, "llm-provider");
    rig.grant_exact(TOKEN_ID);
    tokio::time::pause();
    let paused = {
        let rig = Arc::clone(&rig);
        tokio::spawn(async move {
            let started = Instant::now();
            (rig.fetch(TOKEN_ID).await, started.elapsed())
        })
    };
    let resume = wait_for_signal(reached.recv())
        .await
        .expect("the fetch reaches the audit point");
    // A refresh lands in between: the stored material is no longer the one read.
    wait_for_signal(
        rig.home_store
            .engine
            .get_with_refresh_status(TOKEN_ID, None, true),
    )
    .await
    .expect("forced refresh");
    resume.send(()).unwrap();
    let (answer, elapsed) = wait_for_signal(paused).await.unwrap();
    assert_eq!(error_code(&answer), "home_unavailable", "{answer}");
    assert_eq!(answer["error"]["class"], "transient");
    assert!(elapsed < Duration::from_millis(1_200), "{elapsed:?}");
    assert!(rig.audit_ops("remote_issue").is_empty(), "no row");
    assert!(
        rusqlite::Connection::open(rig.vaults.a.data_dir.join("store.db"))
            .unwrap()
            .query_row("SELECT COUNT(*) FROM remote_issue_seen", [], |row| row
                .get::<_, i64>(0))
            .unwrap()
            == 0,
        "no seen row"
    );
}
