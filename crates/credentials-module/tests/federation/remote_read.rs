//! The requester side of federation: B's remote read, against a real home vault A
//! behind the callosum stand-in.
//!
//! B is a real `RemoteReader` over its own store, with its own fake wall and monotonic
//! clocks. A is a real `HomeVault` over its own store, reached through the stand-in: a
//! handler on the stand-in passes each `federation.remote_token` and
//! `federation.report_auth_failure` request to A as the attested member B, unless the
//! test scripted a different answer for that call (a crafted sealed reply, a refusal,
//! a frame-level error or a stall). So every fetch crosses a real route, is sealed by
//! one vault and opened by the other.
//!
//! Setup uses the store APIs directly; these tests do not exercise the admin verbs
//! that will call them (`transfer init`, `member grant` and `remote add`).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use claustrum_module_probe::federation::ingress::{
    OP_REMOTE_TOKEN, OP_REPORT_AUTH_FAILURE, REMOTE_TOKEN_INFO,
};
use claustrum_module_probe::federation::remote_read::{fed_provider_module, status_body};
use claustrum_module_probe::federation::{
    HomeAnswer, HomeVault, RemoteAnswer, RemoteGet, RemoteReader, RemoteRefusal,
};
use credentials_core::audit::{AuditCtx, AuditOp};
use credentials_core::federation::{
    MemberGrantOperation, MemberGrantSelector, NewRemoteRecord, RemoteHomeState, RemoteRecord,
    VAULT_TRANSFER_ID,
};
use credentials_core::oauth::OAuthCredential;
use credentials_core::record::{CredentialKind, VaultRecord};
use credentials_core::store::{
    GrantOperation, ScopedListRow, SelectorKind, SetCategoryMode, SetProvidersMode,
};
use serde_json::{json, Value};

use crate::support::{wall_ms, HomeStore, Ledger, Reply, Responder, TwoVaults, FAKE_ADAPTERS};

const PAIRING: &str = "pair-1";
const TOKEN_ID: &str = "oauth:anthropic:work";
const CATEGORY: &str = "llm-provider";
const HOUR_MS: i64 = 3_600_000;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn oauth_record(
    adapter: &str,
    access: &str,
    refresh: &str,
    expires_in: Option<i64>,
) -> VaultRecord {
    VaultRecord::new_oauth(
        "opencode",
        adapter,
        OAuthCredential {
            access_token: access.to_string().into(),
            refresh_token: refresh.to_string().into(),
            expires_at_ms: expires_in.map(|ms| wall_ms() + ms),
            token_url: "https://token.test/oauth".into(),
            client_id: Some("client".into()),
            client_secret: None,
            scopes: vec![],
        },
        access.as_bytes().to_vec(),
    )
}

// ---------------------------------------------------------------------------------
// Scripted home answers
// ---------------------------------------------------------------------------------

/// What the home answers one call with, when a test does not want A's own answer.
#[derive(Clone, Debug)]
enum Step {
    /// A's real answer.
    Forward,
    /// A token reply A never produced, sealed by A's key over the request's aad.
    Token {
        version: u64,
        payload: &'static str,
        expires_in_ms: Option<i64>,
        recheck_in_ms: Option<i64>,
    },
    /// This plaintext, sealed by A's key over the request's aad: for replies that open
    /// but must fail validation.
    Plain(Value),
    /// A valid token plaintext sealed over different aad bytes: it cannot open.
    WrongAad,
    /// The home's reply body as given (a refusal such as `{"error": ...}`).
    Body(Value),
    /// An `Error` frame on the route with this code: a home frame error, or a callosum
    /// refusal class.
    Frame(&'static str),
    /// A broker refusal on channel zero, correlated to the routed request.
    ControlFrame(&'static str),
    /// Never answered.
    Stall,
}

#[derive(Clone, Debug)]
struct Scripted {
    gate: Option<Arc<ScriptGate>>,
    step: Step,
}

#[derive(Debug, Default)]
struct ScriptGate {
    arrived: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl ScriptGate {
    async fn arrived(&self) {
        self.arrived.notified().await;
    }

    fn release(&self) {
        self.release.notify_one();
    }
}

type Script = Arc<Mutex<VecDeque<Scripted>>>;

fn pop(script: &Script) -> Scripted {
    script.lock().unwrap().pop_front().unwrap_or(Scripted {
        gate: None,
        step: Step::Forward,
    })
}

fn token_plaintext(
    version: u64,
    payload: &str,
    expires: Option<i64>,
    recheck: Option<i64>,
) -> Value {
    let mut body = json!({
        "payload": payload,
        "record_version": version,
        "identity": {},
        "categories": [CATEGORY],
        "refresh_adapter": "anthropic",
    });
    if let Some(ms) = expires {
        body["expires_in_ms"] = json!(ms);
    }
    if let Some(ms) = recheck {
        body["recheck_in_ms"] = json!(ms);
    }
    body
}

/// Seal `plaintext` as A would, to B's announced key, over `aad`.
fn seal(home_pem: &str, b_public: &[u8], plaintext: &Value, aad: &str) -> Value {
    let (enc, ciphertext) = credentials_core::kem::seal_auth(
        home_pem,
        b_public,
        &serde_json::to_vec(plaintext).unwrap(),
        REMOTE_TOKEN_INFO,
        aad.as_bytes(),
    )
    .expect("seal");
    let b64 = base64::engine::general_purpose::STANDARD;
    json!({ "enc": b64.encode(enc), "ciphertext": b64.encode(ciphertext) })
}

/// The stand-in handler for one federation op: the next scripted step, or A's answer.
fn responder(
    method: &'static str,
    home: Arc<HomeVault>,
    member: String,
    script: Script,
    home_pem: String,
    b_public: Vec<u8>,
) -> Responder {
    Responder(Arc::new(move |params: Value| {
        let next = pop(&script);
        let home = Arc::clone(&home);
        let member = member.clone();
        let home_pem = home_pem.clone();
        let b_public = b_public.clone();
        Box::pin(async move {
            if let Some(gate) = next.gate {
                gate.arrived.notify_one();
                gate.release.notified().await;
            }
            let aad = params["aad"].as_str().unwrap_or_default().to_string();
            match next.step {
                Step::Forward => match home.serve(&member, method, &params).await {
                    HomeAnswer::Reply(body) => Reply::Ok(body),
                    HomeAnswer::InvalidParams(_) => Reply::RouteRefusal("invalid_params".into()),
                },
                Step::Token {
                    version,
                    payload,
                    expires_in_ms,
                    recheck_in_ms,
                } => Reply::Ok(seal(
                    &home_pem,
                    &b_public,
                    &token_plaintext(version, payload, expires_in_ms, recheck_in_ms),
                    &aad,
                )),
                Step::Plain(plaintext) => Reply::Ok(seal(&home_pem, &b_public, &plaintext, &aad)),
                Step::WrongAad => Reply::Ok(seal(
                    &home_pem,
                    &b_public,
                    &token_plaintext(1, "sealed-for-another-request", Some(HOUR_MS), None),
                    &aad.replace("\"nonce\":\"", "\"nonce\":\"f"),
                )),
                Step::Body(body) => Reply::Ok(body),
                Step::Frame(code) => Reply::RouteRefusal(code.into()),
                Step::ControlFrame(code) => Reply::Permanent(code.into()),
                Step::Stall => Reply::Stall,
            }
        })
    }))
}

// ---------------------------------------------------------------------------------
// The rig
// ---------------------------------------------------------------------------------

struct Rig {
    root: credentials_core::test_support::TestTempDir,
    vaults: TwoVaults,
    a: HomeStore,
    home_pem: String,
    b: HomeStore,
    b_public: Vec<u8>,
    reader: Arc<RemoteReader>,
    /// Added to the real clock to give A's engine (and its report cooldown) its time.
    engine_offset: Arc<AtomicI64>,
    script: Script,
    report_script: Script,
}

fn install_transfer_key(store: &credentials_core::store::EncryptedStore) -> (String, Vec<u8>) {
    let pem = credentials_core::kem::generate_key().expect("transfer key");
    let (public, _) = credentials_core::kem::public_half(&pem).expect("public half");
    store
        .create_audited(
            VAULT_TRANSFER_ID,
            &VaultRecord::new_static(
                CredentialKind::KemKey,
                "operator",
                pem.clone().into_bytes(),
                None,
            ),
            AuditCtx::admin(AuditOp::Put),
        )
        .expect("transfer init");
    (pem, public)
}

fn reader_for(vaults: &TwoVaults, b: &HomeStore) -> Arc<RemoteReader> {
    let wall_clock = vaults.b.clock.clone();
    let mono_clock = vaults.b.clock.clone();
    let reader = RemoteReader::new(
        Arc::clone(&b.store),
        FAKE_ADAPTERS.iter().map(|name| name.to_string()),
    )
    .with_clocks(
        Arc::new(move || wall_clock.wall_ms()),
        Arc::new(move || mono_clock.mono_ms()),
    );
    assert!(reader.attach_outbound(vaults.b.outbound.clone()));
    Arc::new(reader)
}

impl Rig {
    async fn new(tag: &str) -> Self {
        let root = crate::support::temp_root(tag);
        let vaults = TwoVaults::new(&root).await;
        let engine_offset = Arc::new(AtomicI64::new(0));
        let clock: Arc<dyn Fn() -> i64 + Send + Sync> = {
            let offset = Arc::clone(&engine_offset);
            Arc::new(move || wall_ms() + offset.load(Ordering::SeqCst))
        };
        let a = HomeStore::open_with_engine_clock(&vaults.a.data_dir, Arc::clone(&clock));
        let (home_pem, home_public) = install_transfer_key(&a.store);
        a.store
            .set_federation_self_member_audited(
                vaults.home_member(),
                AuditCtx::admin(AuditOp::FederationSelfSet),
            )
            .unwrap();
        let b = HomeStore::open(&vaults.b.data_dir);
        let (_b_pem, b_public) = install_transfer_key(&b.store);
        b.store
            .set_federation_self_member_audited(
                vaults.requester_member(),
                AuditCtx::admin(AuditOp::FederationSelfSet),
            )
            .unwrap();
        let requester = vaults.requester_member().to_string();
        vaults.callosum.set_pairing(&requester, Some(PAIRING));
        vaults
            .callosum
            .announce_peer_key(&requester, &hex(&b_public));
        vaults
            .callosum
            .announce_peer_key(vaults.home_member(), &hex(&home_public));

        let home = HomeVault::new(Arc::clone(&a.engine)).with_cooldown_clock(clock);
        assert!(home.attach_outbound(vaults.a.outbound.clone()));
        let home = Arc::new(home);
        let script: Script = Arc::default();
        let report_script: Script = Arc::default();
        for (method, script) in [
            (OP_REMOTE_TOKEN, &script),
            (OP_REPORT_AUTH_FAILURE, &report_script),
        ] {
            vaults.callosum.answer(
                crate::support::TARGET_MODULE,
                method,
                Reply::Handler(responder(
                    method,
                    Arc::clone(&home),
                    requester.clone(),
                    Arc::clone(script),
                    home_pem.clone(),
                    b_public.clone(),
                )),
            );
        }
        let reader = reader_for(&vaults, &b);
        Self {
            root,
            vaults,
            a,
            home_pem,
            b,
            b_public,
            reader,
            engine_offset,
            script,
            report_script,
        }
    }

    /// A restarted B: the reader and store are dropped (the store holds the
    /// single-writer lease), then both are opened again over the same data. Every
    /// in-memory cache and sequence is gone; only what B stored survives.
    fn restart_b(self) -> Self {
        let Rig {
            root,
            vaults,
            a,
            home_pem,
            b,
            b_public,
            reader,
            engine_offset,
            script,
            report_script,
        } = self;
        drop(reader);
        drop(b);
        let b = HomeStore::open(&vaults.b.data_dir);
        let reader = reader_for(&vaults, &b);
        Rig {
            root,
            vaults,
            a,
            home_pem,
            b,
            b_public,
            reader,
            engine_offset,
            script,
            report_script,
        }
    }

    fn requester(&self) -> String {
        self.vaults.requester_member().to_string()
    }

    fn home_member(&self) -> String {
        self.vaults.home_member().to_string()
    }

    fn then(&self, step: Step) {
        self.script
            .lock()
            .unwrap()
            .push_back(Scripted { gate: None, step });
    }

    fn hold(&self, step: Step) -> Arc<ScriptGate> {
        let gate = Arc::new(ScriptGate::default());
        self.script.lock().unwrap().push_back(Scripted {
            gate: Some(Arc::clone(&gate)),
            step,
        });
        gate
    }

    fn report_then(&self, step: Step) {
        self.report_script
            .lock()
            .unwrap()
            .push_back(Scripted { gate: None, step });
    }

    /// A login on A in [`CATEGORY`], granted to B by exact id under B's current
    /// pairing, and registered on B as a remote record the way `remote add` would:
    /// from A's description of it.
    fn login(&self, id: &str, record: VaultRecord) {
        self.a.store.create(id, &record).expect("create login");
        self.a
            .store
            .set_categories_audited(
                id,
                SetCategoryMode::Set,
                &[CATEGORY.to_string()],
                AuditCtx::admin(AuditOp::SetCategory),
            )
            .expect("set category");
        self.a
            .store
            .create_member_grant_audited(
                &self.requester(),
                MemberGrantOperation::RemoteRead,
                &MemberGrantSelector::Exact(id.to_string()),
                PAIRING,
            )
            .expect("member grant");
        self.add_remote(id, &self.home_member());
    }

    fn add_remote(&self, id: &str, home: &str) -> RemoteRecord {
        let (refresh_adapter, detected_plan, identity, home_version) = match self.a.store.get(id) {
            Ok(record) => (
                record.refresh_adapter,
                record.detected_plan,
                record.identity,
                record.record_version,
            ),
            Err(_) => (Some("anthropic".to_string()), None, Default::default(), 1),
        };
        self.b
            .store
            .remote_add_audited(&NewRemoteRecord {
                credential_id: id.to_string(),
                home_member: home.to_string(),
                refresh_adapter,
                detected_plan,
                identity,
                home_version,
                categories: vec![CATEGORY.to_string()],
            })
            .expect("remote add")
    }

    fn record(&self, id: &str) -> RemoteRecord {
        self.b
            .store
            .remote_record(id)
            .unwrap()
            .expect("a remote record")
    }

    async fn get(&self, id: &str, min_ttl_ms: Option<i64>) -> RemoteAnswer {
        let record = self.record(id);
        self.reader.get(&record, min_ttl_ms).await
    }

    async fn served(&self, id: &str, min_ttl_ms: Option<i64>) -> RemoteGet {
        match self.get(id, min_ttl_ms).await {
            RemoteAnswer::Served(get) => get,
            RemoteAnswer::Refused(refusal) => panic!("expected a token, got {refusal:?}"),
        }
    }

    async fn refused(&self, id: &str, min_ttl_ms: Option<i64>) -> RemoteRefusal {
        match self.get(id, min_ttl_ms).await {
            RemoteAnswer::Refused(refusal) => refusal,
            RemoteAnswer::Served(get) => panic!("expected a refusal, got {get:?}"),
        }
    }

    async fn report(&self, id: &str, version: u64, status: u16) -> Result<(), RemoteRefusal> {
        let record = self.record(id);
        self.reader
            .report(&record, version, status, Some("direct"), None)
            .await
    }

    /// The token requests that reached the stand-in so far.
    fn fetch_params(&self) -> Vec<Value> {
        self.requests(OP_REMOTE_TOKEN)
    }

    fn fetches(&self) -> usize {
        self.fetch_params().len()
    }

    fn requests(&self, method: &str) -> Vec<Value> {
        self.vaults
            .callosum
            .ledger()
            .into_iter()
            .filter_map(|row| match row {
                Ledger::Request {
                    method: seen,
                    params,
                    ..
                } if seen == method => Some(params),
                _ => None,
            })
            .collect()
    }

    /// B's diagnostic rows for `id`, as `kind/detail`.
    fn b_events(&self, id: &str) -> Vec<String> {
        self.b
            .store
            .recent_auth_events(500)
            .unwrap()
            .into_iter()
            .filter(|event| event.credential_id == id)
            .map(|event| format!("{}/{}", event.kind, event.detail.unwrap_or_default()))
            .collect()
    }

    /// B's listing row for `id`, for a module holding an exact read grant on it.
    fn b_row(&self, id: &str) -> ScopedListRow {
        let grants = self
            .b
            .store
            .list_scoped_snapshot("reserved", "broca")
            .unwrap()
            .grants;
        self.reader
            .scoped_rows(&grants)
            .unwrap()
            .into_iter()
            .find(|row| row.id == id)
            .expect("B lists the remote id")
    }

    fn grant_b_module(&self, id: &str) {
        self.b
            .store
            .create_read_grant_audited(
                "reserved",
                "broca",
                SelectorKind::Exact,
                id,
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .expect("B grant");
    }

    fn b_status(&self, id: &str) -> Value {
        status_body(&self.record(id), false)
    }
}

/// The stored record with the fields a fetch outcome may change blanked, so two
/// snapshots compare equal exactly when nothing authoritative moved.
fn authoritative(record: &RemoteRecord) -> RemoteRecord {
    RemoteRecord {
        last_fetch_outcome: None,
        last_fetch_at_ms: None,
        updated_at_ms: 0,
        ..record.clone()
    }
}

fn code(refusal: &RemoteRefusal) -> (&str, &str, Option<&str>) {
    (
        refusal.code,
        refusal.class,
        refusal.remedy_member.as_deref(),
    )
}

/// Whether any record B's store API decrypts carries `needle` in its payload or its
/// OAuth material.
fn b_decrypted_holds(store: &credentials_core::store::EncryptedStore, needle: &str) -> bool {
    store.list_meta().unwrap().into_iter().any(|(id, _)| {
        let Ok(record) = store.get(&id) else {
            return false;
        };
        let payload = String::from_utf8_lossy(record.payload.expose()).into_owned();
        let oauth = record
            .oauth
            .as_ref()
            .map(|oauth| {
                format!(
                    "{}|{}",
                    oauth.access_token.expose(),
                    oauth.refresh_token.expose()
                )
            })
            .unwrap_or_default();
        payload.contains(needle) || oauth.contains(needle)
    })
}

/// Whether any file in `dir` (the store, its `-wal` and `-shm`, anything else) holds
/// `needle` in plaintext.
fn dir_holds(dir: &std::path::Path, needle: &str) -> bool {
    std::fs::read_dir(dir).unwrap().any(|entry| {
        let path = entry.unwrap().path();
        path.is_file()
            && std::fs::read(&path)
                .unwrap()
                .windows(needle.len())
                .any(|window| window == needle.as_bytes())
    })
}

// ---------------------------------------------------------------------------------
// The token route, parity and custody
// ---------------------------------------------------------------------------------

#[tokio::test]
async fn a_consumer_on_b_reads_an_anthropic_token_homed_on_a_and_b_matches_a() {
    let rig = Rig::new("remote-route").await;
    let mut record = oauth_record(
        "anthropic",
        "access-sentinel-0",
        "refresh-sentinel-0",
        Some(HOUR_MS),
    );
    record.identity = credentials_core::record::RecordIdentity {
        account_id: Some("acct-anthropic".into()),
        email: Some("me@example.com".into()),
        org_name: Some("Team".into()),
    };
    rig.login(TOKEN_ID, record);

    let t0_wall = rig.vaults.b.clock.wall_ms();
    let got = rig.served(TOKEN_ID, None).await;
    assert_eq!(got.payload, b"access-sentinel-0");
    assert_eq!(got.record_version, 1);
    assert_eq!(got.account_id.as_deref(), Some("acct-anthropic"));
    assert_eq!(got.email.as_deref(), Some("me@example.com"));
    assert_eq!(got.org_name.as_deref(), Some("Team"));
    assert_eq!(got.project_id, None);
    let expires_in = got.expires_at_ms.expect("an expiring token") - t0_wall;
    assert!(
        expires_in > HOUR_MS - 10_000 && expires_in <= HOUR_MS,
        "the consumer's expiry is B's wall clock at send time plus the home's duration: {expires_in}"
    );
    assert_eq!(rig.fetches(), 1);

    // B's listing row equals A's local one.
    rig.a
        .store
        .create_read_grant_audited(
            "reserved",
            "broca",
            SelectorKind::Exact,
            TOKEN_ID,
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    let a_row = rig
        .a
        .store
        .list_scoped_snapshot("reserved", "broca")
        .unwrap()
        .rows
        .into_iter()
        .find(|row| row.id == TOKEN_ID)
        .expect("A lists it");
    rig.grant_b_module(TOKEN_ID);
    assert_eq!(rig.b_row(TOKEN_ID), a_row);

    // B's status is A's local status plus the two remote fields.
    assert_eq!(
        rig.b_status(TOKEN_ID),
        json!({
            "ready": true,
            "last_error_code": null,
            "lease_held": true,
            "credential_id": TOKEN_ID,
            "record_version": 1,
            "stale_pending": false,
            "remote_home": rig.home_member(),
            "last_fetch_outcome": "ok",
        })
    );

    // Custody: nothing B stores or logs holds either token.
    for needle in ["access-sentinel-0", "refresh-sentinel-0"] {
        assert!(
            !b_decrypted_holds(&rig.b.store, needle),
            "{needle} decrypts on B"
        );
        assert!(
            !dir_holds(&rig.vaults.b.data_dir, needle),
            "{needle} in B's data dir"
        );
        assert!(
            !format!("{:?}", rig.vaults.callosum.ledger()).contains(needle),
            "{needle} in the stand-in's ledger"
        );
    }
    // Negative control: a token persisted through B's normal encrypted store is found
    // by the decrypting check, so that check can fail.
    rig.b
        .store
        .create(
            "apikey:control",
            &VaultRecord::new_static(
                CredentialKind::ApiKey,
                "operator",
                b"access-sentinel-0".to_vec(),
                None,
            ),
        )
        .unwrap();
    assert!(b_decrypted_holds(&rig.b.store, "access-sentinel-0"));
}

/// A JWT whose payload carries ChatGPT's account claim.
fn chatgpt_token(account: &str) -> String {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = b64.encode(br#"{"alg":"none"}"#);
    let payload = b64.encode(
        json!({ "https://api.openai.com/auth": { "chatgpt_account_id": account } })
            .to_string()
            .as_bytes(),
    );
    format!("{header}.{payload}.sig")
}

#[tokio::test]
async fn antigravity_and_chatgpt_projections_match_the_homes_local_get_and_list() {
    let rig = Rig::new("remote-parity").await;
    rig.grant_b_module("antigravity:google");
    rig.grant_b_module("oauth:openai:claim");
    for id in ["antigravity:google", "oauth:openai:claim"] {
        rig.a
            .store
            .create_read_grant_audited(
                "reserved",
                "broca",
                SelectorKind::Exact,
                id,
                GrantOperation::Read,
                AuditCtx::admin(AuditOp::GrantCreate),
            )
            .unwrap();
    }

    rig.login(
        "antigravity:google",
        oauth_record(
            "antigravity",
            "ag-access",
            "ag-refresh|proj-123|managed-456",
            Some(HOUR_MS),
        ),
    );
    let got = rig.served("antigravity:google", None).await;
    assert_eq!(
        got.project_id,
        credentials_core::refresh_adapters::antigravity::effective_project_id(
            "ag-refresh|proj-123|managed-456"
        )
    );
    assert_eq!(got.project_id.as_deref(), Some("managed-456"));

    // A ChatGPT record whose token carries an account claim and whose stored identity
    // is absent. (A stored account id that contradicts the token's claim is refused by
    // the store at create, so that shape cannot be set up on A.)
    let claim = chatgpt_token("acct-claim");
    rig.login(
        "oauth:openai:claim",
        oauth_record("openai", &claim, "rt", Some(HOUR_MS)),
    );

    let got = rig.served("oauth:openai:claim", None).await;
    assert_eq!(got.account_id.as_deref(), Some("acct-claim"));
    assert_eq!(
        got.account_id,
        credentials_core::oauth_login::account_id_for_adapter("openai", &claim)
    );

    let a_rows = rig
        .a
        .store
        .list_scoped_snapshot("reserved", "broca")
        .unwrap()
        .rows;
    for id in ["antigravity:google", "oauth:openai:claim"] {
        let a_row = a_rows.iter().find(|row| row.id == id).expect("A row");
        assert_eq!(&rig.b_row(id), a_row, "{id}: B's row equals A's");
    }
}

// ---------------------------------------------------------------------------------
// Reply validation
// ---------------------------------------------------------------------------------

#[tokio::test]
async fn an_invalid_reply_changes_only_the_fetch_outcome_and_the_cached_token_is_still_served() {
    let rig = Rig::new("remote-invalid-reply").await;
    rig.login(
        TOKEN_ID,
        oauth_record("anthropic", "access-0", "refresh-0", Some(HOUR_MS)),
    );
    rig.served(TOKEN_ID, None).await;
    let established = rig.record(TOKEN_ID);
    assert_eq!(established.last_home_state, RemoteHomeState::Active);

    let faults = [
        ("empty payload", {
            let mut body = token_plaintext(2, "", Some(HOUR_MS), None);
            body["payload"] = json!("");
            body
        }),
        ("control character in email", {
            let mut body = token_plaintext(2, "bad-email-token", Some(HOUR_MS), None);
            body["identity"] = json!({ "account_id": "acct", "email": "me\u{7}@example.com" });
            body
        }),
        ("plan tier MAX!", {
            let mut body = token_plaintext(2, "bad-tier-token", Some(HOUR_MS), None);
            body["detected_plan"] = json!({ "tier": "MAX!", "raw": null, "observed_at_ms": 1 });
            body
        }),
        ("unregistered adapter", {
            let mut body = token_plaintext(2, "bad-adapter-token", Some(HOUR_MS), None);
            body["refresh_adapter"] = json!("not-registered-here");
            body
        }),
    ];
    for (index, (why, plaintext)) in faults.into_iter().enumerate() {
        rig.then(Step::Plain(plaintext));
        // A demand the cached token cannot meet forces the fetch the fault rides on.
        let refusal = rig.refused(TOKEN_ID, Some(3_590_000)).await;
        assert_eq!(
            code(&refusal),
            ("remote_reply_invalid", "permanent", None),
            "{why}"
        );
        let after = rig.record(TOKEN_ID);
        assert_eq!(authoritative(&after), authoritative(&established), "{why}");
        assert_eq!(
            after.last_fetch_outcome.as_deref(),
            Some("remote_reply_invalid")
        );
        let rows: Vec<_> = rig
            .b_events(TOKEN_ID)
            .into_iter()
            .filter(|event| event.contains("remote_reply_invalid"))
            .collect();
        assert_eq!(
            rows.len(),
            index + 1,
            "{why}: one auth_events row per invalid reply"
        );
        // The cached token is still served, with no further fetch.
        let fetches = rig.fetches();
        assert_eq!(
            rig.served(TOKEN_ID, None).await.payload,
            b"access-0",
            "{why}"
        );
        assert_eq!(rig.fetches(), fetches, "{why}");
        assert_eq!(rig.b_status(TOKEN_ID)["ready"], true);
        assert_eq!(rig.b_status(TOKEN_ID)["last_error_code"], Value::Null);
    }
}

// ---------------------------------------------------------------------------------
// Cache and clocks
// ---------------------------------------------------------------------------------

#[tokio::test]
async fn b_forwards_the_callers_demand_plus_the_margin_without_wrapping() {
    let rig = Rig::new("remote-demand").await;
    rig.login(
        TOKEN_ID,
        oauth_record("anthropic", "access-0", "refresh-0", Some(HOUR_MS)),
    );
    rig.served(TOKEN_ID, None).await;
    for min_ttl in [i64::MAX - 1, i64::MAX] {
        rig.get(TOKEN_ID, Some(min_ttl)).await;
    }
    let demands: Vec<i64> = rig
        .fetch_params()
        .iter()
        .map(|params| params["min_ttl_ms"].as_i64().expect("an i64 demand"))
        .collect();
    assert_eq!(demands, vec![62_500, i64::MAX, i64::MAX]);
}

#[tokio::test]
async fn a_cache_hit_makes_no_fetch_and_residence_and_the_skew_bound_reuse() {
    let rig = Rig::new("remote-cache").await;
    rig.login(
        TOKEN_ID,
        oauth_record("anthropic", "access-0", "refresh-0", Some(HOUR_MS)),
    );
    let clock = rig.vaults.b.clock.clone();

    // An hour-lived token read with a 10-minute demand is served, and a second read
    // inside the 300 s window makes no home fetch.
    rig.served(TOKEN_ID, Some(600_000)).await;
    clock.advance(200_000);
    rig.served(TOKEN_ID, Some(600_000)).await;
    assert_eq!(rig.fetches(), 1);
    // Past 300 s of B's monotonic time the entry is no longer resident.
    clock.advance(100_000);
    rig.served(TOKEN_ID, None).await;
    assert_eq!(rig.fetches(), 2);

    // A token with 90 s left is servable for 30 s (the 60 s skew), then refetched.
    clock.advance(300_000);
    rig.then(Step::Token {
        version: 1,
        payload: "short-lived",
        expires_in_ms: Some(90_000),
        recheck_in_ms: None,
    });
    assert_eq!(rig.served(TOKEN_ID, None).await.payload, b"short-lived");
    clock.advance(29_000);
    assert_eq!(rig.served(TOKEN_ID, None).await.payload, b"short-lived");
    assert_eq!(rig.fetches(), 3);
    clock.advance(1_000);
    assert_eq!(rig.served(TOKEN_ID, None).await.payload, b"access-0");
    assert_eq!(
        rig.fetches(),
        4,
        "past expiry minus the skew the token is refetched"
    );
}

#[tokio::test]
async fn a_630_second_token_for_a_600_second_demand_is_refreshed_on_the_home_then_served() {
    let rig = Rig::new("remote-home-refresh").await;
    rig.login(
        TOKEN_ID,
        oauth_record("anthropic", "access-0", "refresh-0", Some(630_000)),
    );
    let got = rig.served(TOKEN_ID, Some(600_000)).await;
    assert_eq!(got.payload, b"access-refreshed-1");
    assert_eq!(got.record_version, 2);
    assert_eq!(rig.a.upstream_calls(), 1);
    assert_eq!(rig.fetches(), 1);
}

#[tokio::test]
async fn a_fresh_reply_that_misses_the_demand_is_ttl_unsatisfiable_after_one_fetch() {
    let rig = Rig::new("remote-ttl").await;
    rig.login(
        TOKEN_ID,
        oauth_record("anthropic", "access-0", "refresh-0", Some(HOUR_MS)),
    );
    rig.then(Step::Token {
        version: 1,
        payload: "seventy-seconds",
        expires_in_ms: Some(70_000),
        recheck_in_ms: None,
    });
    let refusal = rig.refused(TOKEN_ID, Some(30_000)).await;
    assert_eq!(
        code(&refusal),
        ("ttl_unsatisfiable", "context_overflow", None)
    );
    assert_eq!(rig.fetches(), 1);
    assert_eq!(
        rig.record(TOKEN_ID).last_home_state,
        RemoteHomeState::Active
    );
}

#[tokio::test]
async fn ten_concurrent_reads_make_one_fetch_and_a_larger_demand_starts_its_own() {
    let rig = Rig::new("remote-single-flight").await;
    rig.login(
        TOKEN_ID,
        oauth_record("anthropic", "access-0", "refresh-0", Some(HOUR_MS)),
    );
    let shared = rig.hold(Step::Forward);
    let record = rig.record(TOKEN_ID);
    let reads: Vec<_> = (0..10)
        .map(|_| {
            let reader = Arc::clone(&rig.reader);
            let record = record.clone();
            tokio::spawn(async move { reader.get(&record, None).await })
        })
        .collect();
    shared.arrived().await;
    shared.release();
    for read in reads {
        assert!(matches!(read.await.unwrap(), RemoteAnswer::Served(_)));
    }
    assert_eq!(
        rig.fetches(),
        1,
        "ten concurrent reads share one home fetch"
    );

    rig.vaults.b.clock.advance(300_000);
    let held = rig.hold(Step::Forward);
    let small = {
        let reader = Arc::clone(&rig.reader);
        let record = record.clone();
        tokio::spawn(async move { reader.get(&record, None).await })
    };
    held.arrived().await;
    let large = rig.get(TOKEN_ID, Some(600_000)).await;
    assert!(matches!(large, RemoteAnswer::Served(_)));
    assert!(!small.is_finished(), "the smaller fetch is still held");
    held.release();
    assert!(matches!(small.await.unwrap(), RemoteAnswer::Served(_)));
    assert_eq!(
        rig.fetches(),
        3,
        "a larger demand does not join a smaller fetch"
    );
}

#[tokio::test]
async fn the_consumers_expiry_runs_on_bs_clock_whatever_the_wall_offset() {
    let rig = Rig::new("remote-clocks").await;
    let clock = rig.vaults.b.clock.clone();
    for (index, offset) in [600_000i64, -600_000].into_iter().enumerate() {
        let id = format!("oauth:anthropic:offset-{index}");
        rig.login(
            &id,
            oauth_record("anthropic", "access-0", "refresh-0", Some(200_000)),
        );
        clock.set_wall_offset(offset);
        let t0_wall = clock.wall_ms();
        let got = rig.served(&id, None).await;
        let expires_in = got.expires_at_ms.unwrap() - t0_wall;
        assert!(
            expires_in > 190_000 && expires_in <= 200_000,
            "offset {offset}: expires_at_ms is B's wall clock at t0 plus expires_in_ms ({expires_in})"
        );
        let before = rig.fetches();
        clock.advance(139_000);
        rig.served(&id, None).await;
        assert_eq!(
            rig.fetches(),
            before,
            "offset {offset}: still inside expiry minus skew"
        );
        clock.advance(2_000);
        rig.served(&id, None).await;
        assert_eq!(
            rig.fetches(),
            before + 1,
            "offset {offset}: never served past the home's expiry minus 60 s on B's monotonic clock"
        );
    }
}

#[tokio::test]
async fn a_read_after_a_report_reaches_the_home_and_an_older_report_keeps_a_newer_token() {
    let rig = Rig::new("remote-report-read").await;
    // A's record was written more than the report cooldown ago.
    rig.engine_offset.store(61_000, Ordering::SeqCst);
    rig.login(
        TOKEN_ID,
        oauth_record("anthropic", "access-0", "refresh-0", Some(HOUR_MS)),
    );
    assert_eq!(rig.served(TOKEN_ID, None).await.record_version, 1);
    rig.report(TOKEN_ID, 1, 401)
        .await
        .expect("the home accepts the report");
    let got = rig.served(TOKEN_ID, None).await;
    assert_eq!(got.record_version, 2, "the read after the report reaches A");
    assert_eq!(got.payload, b"access-refreshed-1");
    assert_eq!(rig.a.upstream_calls(), 1);
    assert_eq!(rig.fetches(), 2);

    // A report delayed in transit, at the older version, keeps the newer token.
    rig.report(TOKEN_ID, 1, 401)
        .await
        .expect("a stale report is a no-op");
    assert_eq!(rig.served(TOKEN_ID, None).await.record_version, 2);
    assert_eq!(rig.fetches(), 2, "the newer cached token is still served");
}

#[tokio::test]
async fn a_cached_token_is_served_through_a_partition() {
    let rig = Rig::new("remote-partition").await;
    rig.login(
        TOKEN_ID,
        oauth_record("anthropic", "access-0", "refresh-0", Some(HOUR_MS)),
    );
    rig.served(TOKEN_ID, None).await;
    rig.then(Step::Frame("fed_partition"));
    let refusal = rig.refused(TOKEN_ID, Some(3_590_000)).await;
    assert_eq!(code(&refusal), ("home_unreachable", "transient", None));
    assert_eq!(rig.served(TOKEN_ID, None).await.payload, b"access-0");
}

/// A cold read whose discovery (the home's announced-key lookup) never answers ends as a
/// structured `transient` refusal inside the 2.5 s consumer-facing budget, below the
/// consumer client's 3 s reply wait. The budget is checked on tokio's paused clock: the
/// read runs in virtual time, so the build machine's load cannot move the result.
#[tokio::test]
async fn a_cold_read_with_stalled_discovery_is_a_structured_transient_inside_the_budget() {
    let rig = Rig::new("remote-stalled-discovery").await;
    // A second login, read once on the real clock, so the connection and the route to
    // callosum are already open: the cold read below starts at discovery.
    const WARM_ID: &str = "oauth:anthropic:warm";
    rig.login(
        WARM_ID,
        oauth_record("anthropic", "access-warm", "refresh-warm", Some(HOUR_MS)),
    );
    rig.login(
        TOKEN_ID,
        oauth_record("anthropic", "access-0", "refresh-0", Some(HOUR_MS)),
    );
    rig.served(WARM_ID, None).await;
    let fetches = rig.fetches();
    let discovery = crate::support::Held::new();
    rig.vaults.callosum.answer(
        crate::support::TARGET_MODULE,
        "callosum.peer_keys_read",
        Reply::Hold(discovery.clone()),
    );

    tokio::time::pause();
    let started = tokio::time::Instant::now();
    let refusal = rig.refused(TOKEN_ID, None).await;
    let virtual_elapsed = started.elapsed();
    discovery.arrived().await;
    assert_eq!(code(&refusal), ("home_unreachable", "transient", None));
    assert!(
        virtual_elapsed <= claustrum_module_probe::federation::CONSUMER_FACING_DEADLINE,
        "the answer arrives inside the 2.5 s budget, measured on the paused clock: \
         {virtual_elapsed:?}"
    );
    assert_eq!(rig.fetches(), fetches, "no token fetch was sent");
}

#[tokio::test]
async fn a_no_expiry_token_stops_being_served_300_s_after_the_grant_is_revoked() {
    let rig = Rig::new("remote-no-expiry").await;
    rig.login(
        TOKEN_ID,
        oauth_record("anthropic", "access-0", "refresh-0", None),
    );
    let got = rig.served(TOKEN_ID, None).await;
    assert_eq!(got.expires_at_ms, None);
    rig.a
        .store
        .revoke_member_grant_audited(
            &rig.requester(),
            MemberGrantOperation::RemoteRead,
            &MemberGrantSelector::Exact(TOKEN_ID.to_string()),
        )
        .unwrap();
    rig.vaults.b.clock.advance(299_999);
    rig.served(TOKEN_ID, None).await;
    assert_eq!(rig.fetches(), 1);
    rig.vaults.b.clock.advance(1);
    let refusal = rig.refused(TOKEN_ID, None).await;
    assert_eq!(code(&refusal), ("not_found", "permanent", None));
}

#[tokio::test]
async fn a_delayed_reply_from_the_old_home_after_re_homing_changes_nothing() {
    let rig = Rig::new("remote-rehome").await;
    rig.login(
        TOKEN_ID,
        oauth_record("anthropic", "access-0", "refresh-0", Some(HOUR_MS)),
    );
    let held = rig.hold(Step::Forward);
    let old = rig.record(TOKEN_ID);
    let pending = {
        let reader = Arc::clone(&rig.reader);
        let old = old.clone();
        tokio::spawn(async move { reader.get(&old, None).await })
    };
    held.arrived().await;
    rig.b.store.remote_remove_audited(TOKEN_ID).unwrap();
    let home_c = "fed-computer:cccccccccccccccccccccccccccccccc";
    let readded = rig.add_remote(TOKEN_ID, home_c);
    held.release();
    let _ = pending.await.unwrap();

    let now = rig.record(TOKEN_ID);
    assert_eq!(
        now, readded,
        "the late reply from A changed nothing on the re-added record"
    );
    // Nothing from A was cached either: the next read goes to C, which has announced
    // no key, so this vault says whose setup is incomplete without fetching.
    let fetches = rig.fetches();
    let refusal = rig.refused(TOKEN_ID, None).await;
    assert_eq!(
        code(&refusal),
        ("remote_setup_incomplete", "permanent", Some(home_c))
    );
    assert_eq!(rig.fetches(), fetches);
    assert_eq!(
        authoritative(&rig.record(TOKEN_ID)),
        authoritative(&readded),
        "no announced key for the home is outcome only"
    );
}

// ---------------------------------------------------------------------------------
// The report cooldown
// ---------------------------------------------------------------------------------

#[tokio::test]
async fn the_report_cooldown_holds_back_a_second_refresh_and_releases_it_without_another_report() {
    let rig = Rig::new("remote-cooldown").await;
    rig.engine_offset.store(61_000, Ordering::SeqCst);
    rig.login(
        TOKEN_ID,
        oauth_record("anthropic", "access-0", "refresh-0", Some(HOUR_MS)),
    );
    rig.served(TOKEN_ID, None).await;

    // Report at the current version, read: exactly one upstream refresh.
    rig.report(TOKEN_ID, 1, 401).await.unwrap();
    assert_eq!(rig.served(TOKEN_ID, None).await.record_version, 2);
    assert_eq!(rig.a.upstream_calls(), 1);

    // The new version was written just now on A's clock: a report inside the 60 s
    // cooldown does not buy a second upstream call. The home answers the same version
    // with `recheck_in_ms`, and the report stays unresolved.
    rig.engine_offset.store(0, Ordering::SeqCst);
    rig.report(TOKEN_ID, 2, 401).await.unwrap();
    assert_eq!(rig.b_status(TOKEN_ID)["stale_pending"], true);
    let fetches = rig.fetches();
    assert_eq!(rig.served(TOKEN_ID, None).await.record_version, 2);
    assert_eq!(rig.fetches(), fetches + 1);
    assert_eq!(
        rig.a.upstream_calls(),
        1,
        "no second upstream call inside the cooldown"
    );
    assert_eq!(rig.b_status(TOKEN_ID)["stale_pending"], true);
    // The entry is resident only until `recheck_in_ms` runs out.
    rig.vaults.b.clock.advance(30_000);
    rig.served(TOKEN_ID, None).await;
    assert_eq!(rig.fetches(), fetches + 1);

    // Past the cooldown, with no further report: one refresh, and the report resolves.
    rig.engine_offset.store(61_000, Ordering::SeqCst);
    rig.vaults.b.clock.advance(31_000);
    assert_eq!(rig.served(TOKEN_ID, None).await.record_version, 3);
    assert_eq!(rig.a.upstream_calls(), 2);
    assert_eq!(rig.b_status(TOKEN_ID)["stale_pending"], false);
}

#[tokio::test]
async fn a_second_members_report_is_accepted_but_shares_the_credentials_refresh_cooldown() {
    let rig = Rig::new("remote-two-member-cooldown").await;
    rig.engine_offset.store(61_000, Ordering::SeqCst);
    rig.login(
        TOKEN_ID,
        oauth_record("anthropic", "access-0", "refresh-0", Some(HOUR_MS)),
    );
    rig.served(TOKEN_ID, None).await;
    rig.report(TOKEN_ID, 1, 401).await.unwrap();
    assert_eq!(rig.served(TOKEN_ID, None).await.record_version, 2);
    assert_eq!(rig.a.upstream_calls(), 1);

    let member_y = "fed-computer:cccccccccccccccccccccccccccccccc";
    let pem_y = credentials_core::kem::generate_key().unwrap();
    let (public_y, key_id_y) = credentials_core::kem::public_half(&pem_y).unwrap();
    rig.vaults.callosum.set_pairing(member_y, Some("pair-y"));
    rig.vaults
        .callosum
        .announce_peer_key(member_y, &hex(&public_y));
    rig.a
        .store
        .create_member_grant_audited(
            member_y,
            MemberGrantOperation::RemoteRead,
            &MemberGrantSelector::Exact(TOKEN_ID.into()),
            "pair-y",
        )
        .unwrap();
    let offset = Arc::clone(&rig.engine_offset);
    let home = HomeVault::new(Arc::clone(&rig.a.engine))
        .with_cooldown_clock(Arc::new(move || wall_ms() + offset.load(Ordering::SeqCst)));
    assert!(home.attach_outbound(rig.vaults.a.outbound.clone()));
    rig.engine_offset.store(0, Ordering::SeqCst);
    let accepted = home
        .serve(
            member_y,
            OP_REPORT_AUTH_FAILURE,
            &json!({
                "credential_id": TOKEN_ID, "record_version": 2, "provider_status": 403,
            }),
        )
        .await;
    assert!(
        matches!(accepted, HomeAnswer::Reply(ref body) if body == &json!({ "accepted": true }))
    );
    assert_eq!(
        rig.a.upstream_calls(),
        1,
        "accepting a report does not itself refresh"
    );

    let aad = json!({ "credential_id": TOKEN_ID, "requester": member_y,
        "home": rig.home_member(), "nonce": "00112233445566778899aabbccddeeff",
        "recipient_key_id": key_id_y })
    .to_string();
    let fetch_y = || async {
        let HomeAnswer::Reply(body) = home
            .serve(member_y, OP_REMOTE_TOKEN, &json!({ "aad": aad }))
            .await
        else {
            panic!("expected a token reply");
        };
        let b64 = base64::engine::general_purpose::STANDARD;
        let (public_a, _) = credentials_core::kem::public_half(&rig.home_pem).unwrap();
        let plaintext = credentials_core::kem::open_auth(
            &pem_y,
            &public_a,
            &b64.decode(body["enc"].as_str().expect("sealed token"))
                .unwrap(),
            &b64.decode(body["ciphertext"].as_str().unwrap()).unwrap(),
            REMOTE_TOKEN_INFO,
            aad.as_bytes(),
        )
        .unwrap();
        serde_json::from_slice::<Value>(&plaintext).unwrap()
    };
    let deferred = fetch_y().await;
    assert_eq!(deferred["record_version"], 2);
    assert!(deferred["recheck_in_ms"].as_i64().is_some_and(|ms| ms > 0));
    assert_eq!(
        rig.a.upstream_calls(),
        1,
        "Y cannot bypass X's per-credential cooldown"
    );
    let events = rig.a.store.recent_auth_events(500).unwrap();
    assert!(events.iter().any(|row| row.credential_id == TOKEN_ID
        && row.kind == "consumer_report_stale"
        && row.principal_kind.as_deref() == Some("member")
        && row.principal_id.as_deref() == Some(member_y)
        && row.record_version == Some(2)
        && row.applied));
    assert!(events.iter().any(|row| row.credential_id == TOKEN_ID
        && row.kind == "stale_refresh_deferred"
        && row.record_version == Some(2)));

    rig.engine_offset.store(61_000, Ordering::SeqCst);
    let refreshed = fetch_y().await;
    assert_eq!(refreshed["record_version"], 3);
    assert!(refreshed.get("recheck_in_ms").is_none());
    assert_eq!(
        rig.a.upstream_calls(),
        2,
        "the deferred report refreshes without another report"
    );
}

#[tokio::test]
async fn channel_zero_refusals_follow_the_consumer_table_without_waiting() {
    let rig = Rig::new("remote-open-refusal").await;
    rig.login(
        TOKEN_ID,
        oauth_record("anthropic", "access-0", "refresh-0", Some(HOUR_MS)),
    );
    tokio::time::pause();
    // The stand-in answers over TCP; only an explicit advance may spend the budget.
    let io = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    for at_open in [false, true] {
        for (wire, expected) in [
            (
                "fed_not_exposed",
                ("federation_setup_invalid", "permanent", None),
            ),
            ("fed_partition", ("home_unreachable", "transient", None)),
        ] {
            if at_open {
                rig.vaults
                    .callosum
                    .refuse_open(&fed_provider_module(&rig.home_member()), wire);
            } else {
                rig.then(Step::ControlFrame(wire));
            }
            let before = authoritative(&rig.record(TOKEN_ID));
            let started = tokio::time::Instant::now();
            let refusal = rig.refused(TOKEN_ID, None).await;
            assert_eq!(code(&refusal), expected);
            assert_eq!(started.elapsed(), Duration::ZERO);
            assert_eq!(authoritative(&rig.record(TOKEN_ID)), before);
            assert_eq!(
                rig.record(TOKEN_ID).last_fetch_outcome.as_deref(),
                Some(wire)
            );
        }
    }
    assert_eq!(
        rig.fetches(),
        2,
        "only the data-plane refusals received token requests"
    );
    io.abort();
}

// ---------------------------------------------------------------------------------
// The consumer table
// ---------------------------------------------------------------------------------

/// Assert one row's stored effect through list `state` and status `ready` /
/// `last_error_code`.
fn assert_effect(rig: &Rig, id: &str, state: &str, last_error: Value, why: &str) {
    let status = rig.b_status(id);
    assert_eq!(
        status["last_error_code"], last_error,
        "{why}: status last_error_code"
    );
    assert_eq!(
        status["ready"],
        json!(state == "active"),
        "{why}: status ready"
    );
    let row_state = match rig.b_row(id).state {
        credentials_core::record::RecordState::Active => "active",
        credentials_core::record::RecordState::NeedsReauth => "needs_reauth",
        credentials_core::record::RecordState::Corrupt => "corrupt",
        credentials_core::record::RecordState::Retired => "retired",
    };
    assert_eq!(row_state, state, "{why}: list state");
}

/// One consumer-table row: the home's answer, B's expected `(code, class, remedy)`,
/// and `Some((state, error))` when the row sets a state.
type TableRow = (
    Step,
    (&'static str, &'static str, Option<String>),
    Option<(&'static str, &'static str)>,
);

#[tokio::test]
async fn every_consumer_table_row_answers_and_stores_its_effect() {
    let rig = Rig::new("remote-table").await;
    rig.login(
        TOKEN_ID,
        oauth_record("anthropic", "access-0", "refresh-0", Some(HOUR_MS)),
    );
    rig.grant_b_module(TOKEN_ID);
    let home = rig.home_member();
    let b_member = rig.requester();
    let error = |code: &str, class: &str| json!({ "error": { "code": code, "class": class } });

    // (step, (code, class, remedy), Some((state, error)) when the row sets a state)
    let rows: Vec<TableRow> = vec![
        (
            Step::Body(error("corrupt", "permanent")),
            ("corrupt", "permanent", None),
            Some(("corrupt", "corrupt")),
        ),
        (
            Step::Body(error("refresh_failed", "transient")),
            ("refresh_failed", "transient", None),
            None,
        ),
        (
            Step::Body(error("refresh_unsupported", "permanent")),
            ("refresh_unsupported", "permanent", None),
            None,
        ),
        (
            Step::Body(error("vault_locked", "transient")),
            ("vault_locked", "transient", None),
            None,
        ),
        (
            Step::Body(error("store_error", "transient")),
            ("store_error", "transient", None),
            None,
        ),
        (
            Step::Body(error("ttl_unsatisfiable", "context_overflow")),
            ("ttl_unsatisfiable", "context_overflow", None),
            None,
        ),
        (
            Step::Body(json!({ "error": {
                "code": "remote_setup_incomplete", "class": "permanent", "remedy_member": home,
            }})),
            ("remote_setup_incomplete", "permanent", Some(home.clone())),
            Some(("needs_reauth", "remote_setup_incomplete")),
        ),
        (
            Step::Body(json!({ "error": {
                "code": "remote_setup_incomplete", "class": "permanent", "remedy_member": b_member,
            }})),
            (
                "remote_setup_incomplete",
                "permanent",
                Some(b_member.clone()),
            ),
            Some(("needs_reauth", "remote_setup_incomplete")),
        ),
        (
            Step::Body(error("home_unavailable", "transient")),
            ("home_unavailable", "transient", None),
            None,
        ),
        (
            Step::Frame("unknown_method"),
            ("home_unavailable", "transient", None),
            None,
        ),
        (
            Step::Frame("fed_partition"),
            ("home_unreachable", "transient", None),
            None,
        ),
        (
            Step::Frame("fed_busy"),
            ("home_unreachable", "transient", None),
            None,
        ),
        (Step::Stall, ("home_unreachable", "transient", None), None),
        (
            Step::Frame("fed_not_exposed"),
            ("federation_setup_invalid", "permanent", None),
            None,
        ),
        (
            Step::WrongAad,
            ("remote_seal_invalid", "permanent", None),
            Some(("needs_reauth", "remote_seal_invalid")),
        ),
    ];
    for (step, (want_code, want_class, want_remedy), sets) in rows {
        let why = format!("{step:?}");
        // Re-establish an active record with a cold cache before each row.
        rig.vaults.b.clock.advance(300_000);
        rig.served(TOKEN_ID, None).await;
        rig.vaults.b.clock.advance(300_000);
        let before = rig.record(TOKEN_ID);
        rig.then(step);
        let refusal = rig.refused(TOKEN_ID, None).await;
        assert_eq!(
            code(&refusal),
            (want_code, want_class, want_remedy.as_deref()),
            "{why}"
        );
        let after = rig.record(TOKEN_ID);
        assert_eq!(
            after.last_fetch_outcome.as_deref(),
            Some(want_code),
            "{why}"
        );
        match sets {
            Some((state, error)) => {
                assert_effect(&rig, TOKEN_ID, state, json!(error), &why);
                // A state other than active drops the cache: the next read fetches.
                let fetches = rig.fetches();
                rig.served(TOKEN_ID, None).await;
                assert_eq!(rig.fetches(), fetches + 1, "{why}: the cache was dropped");
            }
            None => {
                assert_eq!(
                    authoritative(&after),
                    authoritative(&before),
                    "{why}: outcome only"
                );
                assert_effect(&rig, TOKEN_ID, "active", Value::Null, &why);
            }
        }
    }
    let events = rig.b_events(TOKEN_ID);
    assert!(
        events.contains(&"scoped_read_refusal/home_error_frame:unknown_method".to_string()),
        "an Error frame is recorded naming its code: {events:?}"
    );
    assert!(
        events.contains(&"scoped_read_refusal/remote_seal_invalid".to_string()),
        "{events:?}"
    );
}

#[tokio::test]
async fn real_home_verdicts_not_found_and_needs_reauth_set_their_states_and_never_degrade() {
    let rig = Rig::new("remote-verdicts").await;
    rig.login(
        TOKEN_ID,
        oauth_record("anthropic", "access-0", "refresh-0", Some(HOUR_MS)),
    );
    rig.login(
        "oauth:anthropic:gone",
        oauth_record("anthropic", "a", "r", Some(HOUR_MS)),
    );
    rig.grant_b_module(TOKEN_ID);
    rig.grant_b_module("oauth:anthropic:gone");

    // A home record that needs re-auth answers `needs_reauth` on every read, naming
    // the home, never decaying to `not_found`.
    rig.a.store.invalidate(TOKEN_ID).unwrap();
    for _ in 0..3 {
        let refusal = rig.refused(TOKEN_ID, None).await;
        assert_eq!(
            code(&refusal),
            (
                "needs_reauth",
                "auth_required",
                Some(rig.home_member().as_str())
            )
        );
        assert_effect(
            &rig,
            TOKEN_ID,
            "needs_reauth",
            json!("needs_reauth"),
            "needs_reauth",
        );
    }

    // No current-pairing grant on the home: `not_found`, state needs_reauth.
    rig.a
        .store
        .revoke_member_grant_audited(
            &rig.requester(),
            MemberGrantOperation::RemoteRead,
            &MemberGrantSelector::Exact("oauth:anthropic:gone".to_string()),
        )
        .unwrap();
    let refusal = rig.refused("oauth:anthropic:gone", None).await;
    assert_eq!(code(&refusal), ("not_found", "permanent", None));
    assert_effect(
        &rig,
        "oauth:anthropic:gone",
        "needs_reauth",
        json!("not_found"),
        "not_found",
    );
}

#[tokio::test]
async fn setup_faults_name_the_member_whose_operator_must_fix_them() {
    let rig = Rig::new("remote-setup").await;
    rig.login(
        TOKEN_ID,
        oauth_record("anthropic", "access-0", "refresh-0", Some(HOUR_MS)),
    );

    // B's self id is wrong: the home names B as the attested member, which is the id B
    // must set. Correcting it with the self-id admin path restores reads.
    rig.b
        .store
        .set_federation_self_member_audited(
            "fed-computer:dddddddddddddddddddddddddddddddd",
            AuditCtx::admin(AuditOp::FederationSelfSet),
        )
        .unwrap();
    let refusal = rig.refused(TOKEN_ID, None).await;
    assert_eq!(
        code(&refusal),
        (
            "remote_setup_incomplete",
            "permanent",
            Some(rig.requester().as_str())
        )
    );
    rig.b
        .store
        .set_federation_self_member_audited(
            &rig.requester(),
            AuditCtx::admin(AuditOp::FederationSelfSet),
        )
        .unwrap();
    assert_eq!(rig.served(TOKEN_ID, None).await.payload, b"access-0");

    // A vault with no self id, then with a self id but no transfer key, as requester.
    let c = HomeStore::open(&rig.root.join("vault-c"));
    c.store
        .remote_add_audited(&NewRemoteRecord {
            credential_id: TOKEN_ID.into(),
            home_member: rig.home_member(),
            refresh_adapter: Some("anthropic".into()),
            detected_plan: None,
            identity: Default::default(),
            home_version: 1,
            categories: vec![],
        })
        .unwrap();
    let reader = reader_for(&rig.vaults, &c);
    let record = c.store.remote_record(TOKEN_ID).unwrap().unwrap();
    let RemoteAnswer::Refused(refusal) = reader.get(&record, None).await else {
        panic!("no self id must refuse");
    };
    assert_eq!(code(&refusal), ("transfer_key_missing", "permanent", None));
    let c_member = "fed-computer:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    c.store
        .set_federation_self_member_audited(c_member, AuditCtx::admin(AuditOp::FederationSelfSet))
        .unwrap();
    let RemoteAnswer::Refused(refusal) = reader.get(&record, None).await else {
        panic!("no transfer key must refuse");
    };
    assert_eq!(
        code(&refusal),
        ("transfer_key_missing", "permanent", Some(c_member))
    );
    let stored = c.store.remote_record(TOKEN_ID).unwrap().unwrap();
    assert_eq!(
        stored.last_home_state,
        RemoteHomeState::Active,
        "outcome only"
    );
    assert_eq!(
        stored.last_fetch_outcome.as_deref(),
        Some("transfer_key_missing")
    );
}

// ---------------------------------------------------------------------------------
// Failure reports
// ---------------------------------------------------------------------------------

#[tokio::test]
async fn report_reply_classes_and_a_non_credential_status_refused_before_forwarding() {
    let rig = Rig::new("remote-reports").await;
    rig.login(
        TOKEN_ID,
        oauth_record("anthropic", "access-0", "refresh-0", Some(HOUR_MS)),
    );
    rig.served(TOKEN_ID, None).await;

    // A status that is not credential death never leaves B.
    let refusal = rig.report(TOKEN_ID, 1, 500).await.unwrap_err();
    assert_eq!(
        code(&refusal),
        ("report_status_not_credential_death", "permanent", None)
    );
    assert!(rig.requests(OP_REPORT_AUTH_FAILURE).is_empty());
    assert_eq!(rig.record(TOKEN_ID).reported_version, None);

    // The home accepted it.
    rig.report(TOKEN_ID, 1, 401).await.expect("accepted");
    let forwarded = rig.requests(OP_REPORT_AUTH_FAILURE);
    assert_eq!(
        forwarded,
        vec![json!({
            "credential_id": TOKEN_ID,
            "record_version": 1,
            "provider_status": 401,
            "reporter_source": "direct",
        })]
    );
    assert_eq!(rig.record(TOKEN_ID).reported_version, Some(1));
    assert!(rig
        .b_events(TOKEN_ID)
        .contains(&"consumer_report_stale/forwarded_to_home".to_string()));

    // A permanent callosum class, then transport uncertainty.
    rig.report_then(Step::Frame("fed_not_exposed"));
    let refusal = rig.report(TOKEN_ID, 1, 401).await.unwrap_err();
    assert_eq!(
        code(&refusal),
        ("federation_setup_invalid", "permanent", None)
    );
    rig.report_then(Step::Stall);
    tokio::time::pause();
    let started = tokio::time::Instant::now();
    let refusal = rig.report(TOKEN_ID, 1, 403).await.unwrap_err();
    assert_eq!(code(&refusal), ("home_unreachable", "transient", None));
    assert!(started.elapsed() < Duration::from_millis(2_900));
    tokio::time::resume();

    // The home answered `not_found` (the grant is gone).
    rig.a
        .store
        .revoke_member_grant_audited(
            &rig.requester(),
            MemberGrantOperation::RemoteRead,
            &MemberGrantSelector::Exact(TOKEN_ID.to_string()),
        )
        .unwrap();
    let refusal = rig.report(TOKEN_ID, 1, 401).await.unwrap_err();
    assert_eq!(code(&refusal), ("not_found", "permanent", None));
}

// ---------------------------------------------------------------------------------
// Status and list state
// ---------------------------------------------------------------------------------

#[tokio::test]
async fn status_and_list_state_follow_only_authoritative_outcomes() {
    let rig = Rig::new("remote-state").await;
    rig.login(
        TOKEN_ID,
        oauth_record("anthropic", "access-0", "refresh-0", Some(HOUR_MS)),
    );
    rig.grant_b_module(TOKEN_ID);
    let clock = rig.vaults.b.clock.clone();
    rig.served(TOKEN_ID, None).await;
    clock.advance(300_000);

    // A transient fetch failure leaves `ready` true.
    rig.then(Step::Stall);
    rig.refused(TOKEN_ID, None).await;
    assert_effect(&rig, TOKEN_ID, "active", Value::Null, "transient");

    // A home `needs_reauth` sets the state; a partitioned poll leaves it.
    rig.a.store.invalidate(TOKEN_ID).unwrap();
    rig.refused(TOKEN_ID, None).await;
    assert_effect(
        &rig,
        TOKEN_ID,
        "needs_reauth",
        json!("needs_reauth"),
        "needs_reauth",
    );
    rig.then(Step::Frame("fed_partition"));
    rig.refused(TOKEN_ID, None).await;
    assert_effect(
        &rig,
        TOKEN_ID,
        "needs_reauth",
        json!("needs_reauth"),
        "partitioned poll",
    );
    assert_eq!(
        rig.record(TOKEN_ID).last_fetch_outcome.as_deref(),
        Some("home_unreachable")
    );

    // The first successful read after the repair on the home restores both.
    rig.a
        .store
        .reactivate_audited(TOKEN_ID, AuditCtx::admin(AuditOp::Reactivate))
        .unwrap();
    rig.served(TOKEN_ID, None).await;
    assert_effect(&rig, TOKEN_ID, "active", Value::Null, "repaired");

    // A home `not_found` survives a partition and a restart of B.
    rig.a
        .store
        .revoke_member_grant_audited(
            &rig.requester(),
            MemberGrantOperation::RemoteRead,
            &MemberGrantSelector::Exact(TOKEN_ID.to_string()),
        )
        .unwrap();
    clock.advance(300_000);
    rig.refused(TOKEN_ID, None).await;
    rig.then(Step::Frame("fed_partition"));
    rig.refused(TOKEN_ID, None).await;
    let rig = rig.restart_b();
    assert_eq!(rig.b_status(TOKEN_ID)["last_error_code"], "not_found");
    assert_eq!(rig.b_status(TOKEN_ID)["ready"], false);

    // A fenced-out B is never ready, even for an active remote record.
    let mut active = rig.record(TOKEN_ID);
    active.last_home_state = RemoteHomeState::Active;
    let fenced = status_body(&active, true);
    assert_eq!(fenced["ready"], false);
    assert_eq!(fenced["lease_held"], false);
    assert_eq!(status_body(&active, false)["ready"], true);
}

#[tokio::test]
async fn a_delayed_older_report_never_lowers_the_unresolved_version_across_a_restart() {
    let rig = Rig::new("remote-reported-restart").await;
    rig.engine_offset.store(61_000, Ordering::SeqCst);
    rig.login(
        TOKEN_ID,
        oauth_record("anthropic", "access-0", "refresh-0", Some(HOUR_MS)),
    );
    rig.served(TOKEN_ID, None).await;
    rig.report(TOKEN_ID, 1, 401).await.unwrap();
    assert_eq!(rig.served(TOKEN_ID, None).await.record_version, 2);
    assert_eq!(rig.b_status(TOKEN_ID)["stale_pending"], false);

    // report(v2) inside the home's cooldown, then a delayed report(v1), then the home's
    // same-v2 reply with `recheck_in_ms`: the report stays unresolved.
    rig.engine_offset.store(0, Ordering::SeqCst);
    rig.report(TOKEN_ID, 2, 401).await.unwrap();
    rig.report(TOKEN_ID, 1, 401).await.unwrap();
    assert_eq!(rig.record(TOKEN_ID).reported_version, Some(2));
    assert_eq!(rig.served(TOKEN_ID, None).await.record_version, 2);
    assert_eq!(rig.b_status(TOKEN_ID)["stale_pending"], true);

    let rig = rig.restart_b();
    assert_eq!(rig.record(TOKEN_ID).reported_version, Some(2));
    assert_eq!(
        rig.b_status(TOKEN_ID)["stale_pending"],
        true,
        "also across a restart"
    );

    // A successful fetch at v3 resolves it.
    rig.engine_offset.store(61_000, Ordering::SeqCst);
    assert_eq!(rig.served(TOKEN_ID, None).await.record_version, 3);
    assert_eq!(rig.b_status(TOKEN_ID)["stale_pending"], false);
}

// ---------------------------------------------------------------------------------
// Result ordering
// ---------------------------------------------------------------------------------

fn spawn_get(
    rig: &Rig,
    id: &str,
    min_ttl_ms: Option<i64>,
) -> tokio::task::JoinHandle<RemoteAnswer> {
    let reader = Arc::clone(&rig.reader);
    let record = rig.record(id);
    tokio::spawn(async move { reader.get(&record, min_ttl_ms).await })
}

fn token(version: u64, payload: &'static str) -> Step {
    Step::Token {
        version,
        payload,
        expires_in_ms: Some(HOUR_MS),
        recheck_in_ms: None,
    }
}

#[tokio::test]
async fn a_newer_reply_applied_before_a_delayed_older_one_keeps_version_and_cache() {
    let rig = Rig::new("remote-order-version").await;
    rig.login(
        TOKEN_ID,
        oauth_record("anthropic", "access-0", "refresh-0", Some(HOUR_MS)),
    );
    let held = rig.hold(token(1, "version-1"));
    rig.then(token(2, "version-2"));
    let slow = spawn_get(&rig, TOKEN_ID, None);
    held.arrived().await;
    assert_eq!(
        rig.served(TOKEN_ID, Some(600_000)).await.payload,
        b"version-2"
    );
    assert!(!slow.is_finished(), "the older reply is still held");
    held.release();
    let _ = slow.await.unwrap();
    assert_eq!(rig.record(TOKEN_ID).last_home_version, 2);
    let fetches = rig.fetches();
    assert_eq!(rig.served(TOKEN_ID, None).await.payload, b"version-2");
    assert_eq!(rig.fetches(), fetches, "the cache holds v2");
}

#[tokio::test]
async fn a_delayed_verdict_still_applies_after_a_later_transient_failure() {
    let rig = Rig::new("remote-order-verdict").await;
    rig.login(
        TOKEN_ID,
        oauth_record("anthropic", "access-0", "refresh-0", Some(HOUR_MS)),
    );
    rig.served(TOKEN_ID, None).await;
    let held = rig.hold(Step::Body(
        json!({ "error": { "code": "needs_reauth", "class": "auth_required" } }),
    ));
    rig.then(Step::Frame("fed_partition"));
    let slow = spawn_get(&rig, TOKEN_ID, Some(3_550_000));
    held.arrived().await;
    let transient = rig.refused(TOKEN_ID, Some(3_560_000)).await;
    assert_eq!(transient.code, "home_unreachable");
    held.release();
    let verdict = slow.await.unwrap();
    assert!(matches!(verdict, RemoteAnswer::Refused(ref r) if r.code == "needs_reauth"));
    let record = rig.record(TOKEN_ID);
    assert_eq!(record.last_home_state, RemoteHomeState::NeedsReauth);
    assert_eq!(
        record.last_fetch_outcome.as_deref(),
        Some("home_unreachable")
    );
    let fetches = rig.fetches();
    rig.served(TOKEN_ID, None).await;
    assert_eq!(
        rig.fetches(),
        fetches + 1,
        "the verdict dropped the warm cache"
    );
}

#[tokio::test]
async fn no_caller_is_served_a_fetch_started_before_a_verdict() {
    let rig = Rig::new("remote-order-flight").await;
    rig.login(
        TOKEN_ID,
        oauth_record("anthropic", "access-0", "refresh-0", Some(HOUR_MS)),
    );
    let held = rig.hold(token(1, "slow-success"));
    rig.then(Step::Body(
        json!({ "error": { "code": "needs_reauth", "class": "auth_required" } }),
    ));
    let slow = spawn_get(&rig, TOKEN_ID, None);
    held.arrived().await;
    let verdict = rig.refused(TOKEN_ID, Some(600_000)).await;
    assert_eq!(verdict.code, "needs_reauth");
    // A new small-demand read joins no flight: it fetches on its own.
    let fresh = rig.get(TOKEN_ID, None).await;
    assert_eq!(rig.fetches(), 3);
    if let RemoteAnswer::Served(get) = &fresh {
        assert_ne!(get.payload, b"slow-success");
    }
    held.release();
    match slow.await.unwrap() {
        RemoteAnswer::Refused(refusal) => assert_eq!(refusal.code, "needs_reauth"),
        RemoteAnswer::Served(get) => panic!("served the pre-verdict token: {get:?}"),
    }
}

#[tokio::test]
async fn a_home_re_create_resets_the_version_and_a_delayed_old_reply_does_not_reassert() {
    let rig = Rig::new("remote-order-recreate").await;
    rig.login(
        TOKEN_ID,
        oauth_record("anthropic", "access-0", "refresh-0", Some(HOUR_MS)),
    );
    rig.grant_b_module(TOKEN_ID);
    rig.then(token(5, "version-5"));
    rig.served(TOKEN_ID, None).await;
    assert_eq!(rig.record(TOKEN_ID).last_home_version, 5);
    rig.vaults.b.clock.advance(300_000);

    let held = rig.hold(token(5, "late-version-5"));
    rig.then(token(1, "recreated"));
    let slow = spawn_get(&rig, TOKEN_ID, None);
    held.arrived().await;
    assert_eq!(
        rig.served(TOKEN_ID, Some(600_000)).await.payload,
        b"recreated"
    );
    held.release();
    let _ = slow.await.unwrap();
    assert_eq!(rig.record(TOKEN_ID).last_home_version, 1);
    assert_eq!(rig.b_status(TOKEN_ID)["record_version"], 1);
    assert_eq!(rig.b_row(TOKEN_ID).record_version, 1);
    assert_eq!(rig.served(TOKEN_ID, None).await.payload, b"recreated");
}

// ---------------------------------------------------------------------------------
// B-owned metadata
// ---------------------------------------------------------------------------------

#[tokio::test]
async fn b_owned_metadata_reaches_the_listing_and_a_local_category_grant_covers_it() {
    let rig = Rig::new("remote-metadata").await;
    rig.login(
        TOKEN_ID,
        oauth_record("anthropic", "access-0", "refresh-0", Some(HOUR_MS)),
    );
    let store = &rig.b.store;
    store
        .set_categories_audited(
            TOKEN_ID,
            SetCategoryMode::Add,
            &["custom-team".to_string()],
            AuditCtx::admin(AuditOp::SetCategory),
        )
        .unwrap();
    store
        .set_providers_audited(
            TOKEN_ID,
            SetProvidersMode::Set,
            &["anthropic".to_string()],
            AuditCtx::admin(AuditOp::SetProviders),
        )
        .unwrap();
    store
        .set_plan_audited(TOKEN_ID, Some("max_5x"), AuditCtx::admin(AuditOp::SetPlan))
        .unwrap();
    store
        .create_read_grant_audited(
            "reserved",
            "broca",
            SelectorKind::Category,
            "custom-team",
            GrantOperation::Read,
            AuditCtx::admin(AuditOp::GrantCreate),
        )
        .unwrap();
    let row = rig.b_row(TOKEN_ID);
    assert_eq!(
        row.categories,
        vec!["custom-team".to_string(), CATEGORY.to_string()]
    );
    assert_eq!(row.provider_ids, vec!["anthropic".to_string()]);
    assert_eq!(row.plan_tier.as_deref(), Some("max_5x"));
    assert_eq!(row.plan_tier_source.as_deref(), Some("operator"));
    assert_eq!(row.operations, vec![GrantOperation::Read]);
    assert!(
        store
            .evaluate_scoped_coverage("reserved", "broca", TOKEN_ID, GrantOperation::Read)
            .unwrap()
            .covered
    );
}
