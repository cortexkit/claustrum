use std::{collections::VecDeque, sync::Mutex};

use credentials_core::{
    admin_auth::{AdminMacKey, TranscriptParts},
    admin_ops::{apply, AdminOpBody, FEDERATION_REQUIRES_DAEMON},
    audit::{AuditCtx, AuditOp},
    key::{MasterKey, MASTER_KEY_LEN},
    record::{CredentialKind, VaultRecord},
    refresh_adapters::RefreshError,
    store::{EncryptedStore, SECRET_HOME_SETTING},
    test_support::TestTempDir,
};
use serde_json::{json, Value};
use subc_protocol::{FrameType, Principal};
use tokio::sync::{Barrier, Notify};

use super::*;
use crate::{admin_surface::AdminSurface, read_surface::ReadSurface, OP_ADMIN_OP};

const SEED: u8 = 196;
const ACCOUNT: &str = "01K00000000000000000000080";
const KEY: &str = "01MCC5RM006NDK01XD1WTB7Z1P";
const VAULT_KEY: &str = "signing:ck-account-machine:1";
const SLOT: &str = "01K00000000000000000000080.AAAAAAAAAAAAAAAAAAAAAA";
const TOKEN_MARKER: &str = "fixture-machine-token-redaction-canary";
const OPEN: &str = r#"{"op":"admin.github_app_relay_slot_open","v":1}"#;
const PREPARE: &str =
    r#"{"op":"admin.github_app_manifest_prepare","v":1,"agent":"agent_ab64ea0873bbee0c"}"#;
const AGENT: &str = "agent_ab64ea0873bbee0c";
const CODE: &str = "manifest-code-redaction-canary";
const WEBHOOK_SECRET: &str = "webhook-secret-redaction-canary";
const CLIENT_SECRET: &str = "client-secret-redaction-canary";
const PEM_ARMOUR: &str = "invalid-key-armour-redaction-canary";
const PKCS1_PEM: &str =
    include_str!("../../credentials-core/tests/fixtures/github_app/test_private_key_pkcs1.pem");
const LARGE_APP_ID: u64 = 9_007_199_254_740_993;

fn reply(status: u16, body: Value) -> Step {
    Step::Response(HttpResponse {
        status,
        body: serde_json::to_vec(&body).unwrap(),
    })
}

fn token_fixture() -> String {
    let claims = json!({"iat":1_800_000_000,"exp":1_800_000_900,"account":ACCOUNT,"device":KEY,"aud":"cortexkit-webhook-relay"});
    format!(
        "{TOKEN_MARKER}.{}.fixture",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    )
}

fn exchange() -> Vec<Step> {
    let payload = json!({"purpose":"worker_token","account":ACCOUNT,"key_id":KEY,"aud":"cortexkit-webhook-relay"});
    let challenge = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap()),
        URL_SAFE_NO_PAD.encode([6; 32])
    );
    vec![
        reply(200, json!({"challenge": challenge})),
        reply(200, json!({"jwt": token_fixture()})),
    ]
}

fn slot_reply() -> Value {
    json!({"slot": SLOT, "webhook_url": format!("{RELAY_WEBHOOK_BASE}/{SLOT}/webhook"), "expires_at": "2027-01-15T09:00:00Z"})
}

enum Step {
    Response(HttpResponse),
    Signal(HttpResponse),
    Together(Arc<Barrier>, HttpResponse),
    TransportError,
    Pending,
}

#[derive(Default)]
struct RecordedHttp {
    steps: Mutex<VecDeque<Step>>,
    requests: Mutex<Vec<String>>,
    pending: Notify,
}

impl RecordedHttp {
    async fn next(&self) -> Result<HttpResponse, RefreshError> {
        let step = self
            .steps
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected request");
        match step {
            Step::Response(reply) => Ok(reply),
            Step::Signal(reply) => {
                self.pending.notify_one();
                Ok(reply)
            }
            Step::Together(barrier, reply) => {
                barrier.wait().await;
                Ok(reply)
            }
            Step::TransportError => Err(RefreshError::Transport(TOKEN_MARKER.into())),
            Step::Pending => {
                self.pending.notify_one();
                std::future::pending().await
            }
        }
    }
}

#[async_trait::async_trait]
impl HttpTransport for RecordedHttp {
    async fn post(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        content_type: &str,
        body: Vec<u8>,
    ) -> Result<HttpResponse, RefreshError> {
        self.requests.lock().unwrap().push(url.to_owned());
        assert_eq!(content_type, "application/json");
        if url == RELAY_OPEN_URL {
            assert!(
                headers
                    == [(
                        "Authorization",
                        format!("Bearer {}", token_fixture()).as_str()
                    )],
                "relay POST must carry the machine token"
            );
            assert!(body.is_empty());
        } else if url.starts_with(GITHUB_MANIFEST_BASE) {
            assert!(url.ends_with("/conversions"));
            assert!(body.is_empty());
            assert!(headers.iter().all(|(name, _)| *name != "Authorization"));
        } else {
            assert!(headers.is_empty());
            let body: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["aud"], "cortexkit-webhook-relay");
        }
        self.next().await
    }

    async fn put(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        content_type: &str,
        body: Vec<u8>,
    ) -> Result<HttpResponse, RefreshError> {
        assert_eq!(url, format!("{RELAY_OPEN_URL}/{SLOT}"));
        assert_eq!(content_type, "application/json");
        assert!(
            headers
                == [(
                    "Authorization",
                    format!("Bearer {}", token_fixture()).as_str()
                )]
        );
        assert!(
            serde_json::from_slice::<Value>(&body).unwrap()
                == json!({
                    "app_id": LARGE_APP_ID.to_string(), "webhook_secret": WEBHOOK_SECRET,
                })
        );
        self.requests.lock().unwrap().push(format!("PUT {url}"));
        self.next().await
    }

    async fn get(&self, _: &str, _: &[(&str, &str)]) -> Result<HttpResponse, RefreshError> {
        panic!("unexpected GET")
    }
}

struct Rig {
    admin: Arc<AdminSurface>,
    read: Arc<ReadSurface>,
    store: Arc<EncryptedStore>,
    engine: Arc<RefreshEngine>,
    http: Arc<RecordedHttp>,
    db: rusqlite::Connection,
    _root: TestTempDir,
}

impl Rig {
    fn new(steps: Vec<Step>, machine: bool) -> Self {
        let (read, store, db_path, root) = crate::tests::tmp_surface_with_store(SEED);
        let key = MasterKey::from_bytes([SEED; MASTER_KEY_LEN]);
        let vault_id = credentials_core::vault_id_for(db_path.parent().unwrap()).unwrap();
        let http = Arc::new(RecordedHttp {
            steps: Mutex::new(steps.into()),
            ..RecordedHttp::default()
        });
        let engine = Arc::new(RefreshEngine::new(
            Arc::clone(&store),
            Vec::new(),
            http.clone(),
        ));
        let mut admin = AdminSurface::new(
            engine.clone(),
            AdminMacKey::derive(&key),
            vault_id,
            key.key_id(),
        );
        admin.record_bind_at(1, 1, Principal::Direct, "");
        let machine_path = root.join("machine.json");
        if machine {
            let der =
                ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                    .unwrap();
            let pem = format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
                base64::engine::general_purpose::STANDARD.encode(der.as_ref())
            );
            let public_key = credentials_core::signing::public_key_ed25519(&pem).unwrap();
            store
                .create(
                    VAULT_KEY,
                    &VaultRecord::new_static(
                        CredentialKind::SigningKey,
                        "fixture",
                        pem.into_bytes(),
                        None,
                    ),
                )
                .unwrap();
            let bytes = serde_json::to_vec(&json!({"account":ACCOUNT,"key_id":KEY,"public_key_hex":public_key.public_key_hex,"label":"fixture","vault_key_id":VAULT_KEY})).unwrap();
            std::fs::write(&machine_path, bytes).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&machine_path, std::fs::Permissions::from_mode(0o600))
                    .unwrap();
            }
        }
        admin.github_apps.transport = Some(http.clone());
        admin.github_apps.clock = Some(1_800_000_000_000);
        admin.github_apps.machine_path = Some(machine_path);
        let db = rusqlite::Connection::open(db_path).unwrap();
        Self {
            admin: Arc::new(admin),
            read,
            store,
            engine,
            http,
            db,
            _root: root,
        }
    }

    fn sign(&self, body: &str) -> String {
        let AdminOutcome::Challenge { nonce_hex, .. } =
            self.admin.challenge_as(1, 1, Some(&Principal::Direct))
        else {
            panic!("direct challenge refused")
        };
        let nonce = credentials_core::enrollment::decode_lower_hex_32(&nonce_hex).unwrap();
        self.admin
            .mac_key
            .sign(&TranscriptParts {
                vault_id: &self.admin.vault_id,
                key_id: self.admin.key_id,
                nonce: &nonce,
                op_body: body.as_bytes(),
            })
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    async fn route(&self, channel: u16, body: &str, tag: &str) -> (FrameType, Value) {
        let (frame, bytes) = crate::tests::routed_reply(
            &self.read,
            &self.admin,
            channel,
            OP_ADMIN_OP,
            json!({"op_body":body,"tag_hex":tag}),
        )
        .await;
        assert!(
            !String::from_utf8_lossy(&bytes).contains(TOKEN_MARKER),
            "machine token escaped in a reply frame"
        );
        (frame, serde_json::from_slice(&bytes).unwrap())
    }

    async fn call(&self, body: &str) -> (FrameType, Value) {
        self.route(1, body, &self.sign(body)).await
    }

    fn counts(&self) -> (i64, i64, i64) {
        self.db.query_row("SELECT (SELECT count(*) FROM credentials), (SELECT count(*) FROM audit_log), (SELECT count(*) FROM auth_events)", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).unwrap()
    }

    fn assert_slot_sequence(&self) {
        assert_eq!(
            self.http.requests.lock().unwrap().as_slice(),
            [
                "https://account.cortexkit.io/v1/machine/token/challenge",
                "https://account.cortexkit.io/v1/machine/token",
                RELAY_OPEN_URL,
            ]
        );
    }
}

fn assert_refused((frame, reply): (FrameType, Value), prefix: &str) {
    assert_eq!(frame, FrameType::Error);
    assert_eq!(reply["code"], "admin_refused");
    assert_eq!(
        reply["message"]
            .as_str()
            .unwrap()
            .split_once(": ")
            .unwrap()
            .0,
        prefix
    );
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<String>>);

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        self.0.lock().unwrap().push_str(&format!("{attrs:?}"));
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        self.0.lock().unwrap().push_str(&format!("{values:?}"));
    }
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Fields<'a>(&'a mut String);
        impl tracing::field::Visit for Fields<'_> {
            fn record_debug(&mut self, _: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                use std::fmt::Write;
                write!(self.0, "{value:?}").unwrap();
            }
        }
        event.record(&mut Fields(&mut self.0.lock().unwrap()));
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[tokio::test]
async fn github_app_relay_slot_open_needs_no_grant_and_audits_only_confirmed_open() {
    let capture = Capture::default();
    let _capture = tracing::subscriber::set_default(capture.clone());
    let mut steps = exchange();
    steps.push(reply(201, slot_reply()));
    let rig = Rig::new(steps, true);
    assert!(rig.store.list_read_grants().unwrap().is_empty());
    let before = rig.counts();
    assert_eq!(
        rig.call(OPEN).await,
        (FrameType::Response, json!({"result":slot_reply()}))
    );
    rig.assert_slot_sequence();
    assert_eq!(rig.counts(), (before.0, before.1 + 1, before.2));
    let audit = rig.db.query_row(
        "SELECT op, actor, payload_hash, credential_id FROM audit_log ORDER BY seq DESC LIMIT 1", [],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, Option<String>>(3)?)),
    ).unwrap();
    assert_eq!(audit.0, "github_app.relay_slot_open");
    assert_eq!(audit.1, "route-admin");
    assert!(audit.3.is_none());
    assert_eq!(audit.2.len(), 64);
    assert!(audit.2.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let unkeyed: String = ring::digest::digest(&ring::digest::SHA256, SLOT.as_bytes())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_ne!(audit.2, unkeyed);
    assert!(!audit.2.contains(TOKEN_MARKER));
    assert_eq!(rig.store.verify_audit_chain().unwrap(), None);
    assert!(!capture.0.lock().unwrap().contains(TOKEN_MARKER));
}

#[tokio::test]
async fn github_app_relay_slot_open_refusal_table_is_secret_free_and_never_audits_open() {
    let capture = Capture::default();
    let _capture = tracing::subscriber::set_default(capture.clone());
    for (status, code) in [
        (401, "relay_unavailable_for_account/permanent"),
        (403, "relay_unavailable_for_account/permanent"),
        (404, "relay_unavailable_for_account/permanent"),
        (409, "relay_slot_limit/permanent"),
        (307, "relay_unavailable/transient"),
        (429, "relay_unavailable/transient"),
        (503, "relay_unavailable/transient"),
        (400, "relay_request_refused/permanent"),
        (422, "relay_request_refused/permanent"),
        (200, "relay_reply_invalid/permanent"),
        (202, "relay_reply_invalid/permanent"),
        (204, "relay_reply_invalid/permanent"),
    ] {
        let mut steps = exchange();
        let mut body = slot_reply();
        body["untrusted"] = json!(TOKEN_MARKER);
        steps.push(reply(status, body));
        let rig = Rig::new(steps, true);
        let before = rig.counts();
        assert_refused(rig.call(OPEN).await, code);
        rig.assert_slot_sequence();
        assert_eq!(rig.counts(), before);
    }
    let missing = Rig::new(vec![], false);
    let before = missing.counts();
    assert_refused(
        missing.call(OPEN).await,
        "relay_unavailable_for_account/permanent",
    );
    assert_eq!(missing.counts(), before);
    assert!(missing.http.requests.lock().unwrap().is_empty());

    let mint_error = Rig::new(
        vec![reply(
            400,
            json!({"error":"invalid_request", "detail": TOKEN_MARKER}),
        )],
        true,
    );
    let before = mint_error.counts();
    assert_refused(mint_error.call(OPEN).await, "relay_unavailable/transient");
    assert_eq!(mint_error.http.requests.lock().unwrap().len(), 1);
    assert_eq!(mint_error.counts(), (before.0, before.1, before.2 + 1));
    let events = mint_error.store.recent_auth_events(10).unwrap();
    assert_eq!(events[0].principal_kind.as_deref(), Some("direct"));
    assert!(!format!("{events:?}").contains(TOKEN_MARKER));

    let mut steps = exchange();
    steps.push(Step::TransportError);
    let relay_error = Rig::new(steps, true);
    let before = relay_error.counts();
    assert_refused(relay_error.call(OPEN).await, "relay_unavailable/transient");
    assert_eq!(relay_error.counts(), before);
    relay_error.assert_slot_sequence();
    assert!(!capture.0.lock().unwrap().contains(TOKEN_MARKER));
}

#[tokio::test]
async fn github_app_relay_201_validation_rejects_missing_ill_typed_and_mismatched_fields() {
    let mut bad_bodies = vec![];
    for field in ["slot", "webhook_url", "expires_at"] {
        let mut missing = slot_reply();
        missing.as_object_mut().unwrap().remove(field);
        bad_bodies.push(missing);
        let mut bad = slot_reply();
        bad[field] = json!(42);
        bad_bodies.push(bad);
    }
    for (field, value) in [
        ("slot", "../another-slot"),
        ("webhook_url", "https://hooks.cortexkit.io/v1/github/apps/01K00000000000000000000081.AAAAAAAAAAAAAAAAAAAAAA/webhook"),
        ("webhook_url", "https://hooks.cortexkit.io/v1/github/apps/01K00000000000000000000080.AAAAAAAAAAAAAAAAAAAAAA/webhook?x=1"),
        ("expires_at", "not-a-timestamp"),
    ] {
        let mut invalid = slot_reply();
        invalid[field] = json!(value);
        bad_bodies.push(invalid);
    }
    for body in bad_bodies {
        let mut steps = exchange();
        steps.push(reply(201, body));
        let rig = Rig::new(steps, true);
        let before = rig.counts();
        assert_refused(rig.call(OPEN).await, "relay_reply_invalid/permanent");
        assert_eq!(rig.counts(), before);
        rig.assert_slot_sequence();
    }
}

#[test]
fn github_app_relay_slot_grammar_accepts_only_one_canonical_segment() {
    assert!(valid_relay_slot(SLOT));
    for invalid in [
        "81K00000000000000000000080.AAAAAAAAAAAAAAAAAAAAAA",
        "01k00000000000000000000080.AAAAAAAAAAAAAAAAAAAAAA",
        "01K0000000000000000000080.AAAAAAAAAAAAAAAAAAAAAA",
        "001K00000000000000000000080.AAAAAAAAAAAAAAAAAAAAAA",
        "01K00000000000000000000080.AAAAAAAAAAAAAAAAAAAAA",
        "01K00000000000000000000080.AAAAAAAAAAAAAAAAAAAAAAA",
        "01K00000000000000000000080.AAAAAAAAAAAAAAAAAAAAA=",
        "01K00000000000000000000080.AAAAAAAAAAAAAAAAAAAAA/",
        "01K00000000000000000000080.AAAAAAAAAAAAAAAAAAAA.Q",
    ] {
        assert!(!valid_relay_slot(invalid));
    }
}

#[tokio::test]
async fn github_app_relay_reply_accepts_8_kib_and_refuses_one_byte_more_without_writing() {
    for length in [8192, 8193] {
        let mut body = serde_json::to_vec(&slot_reply()).unwrap();
        body.resize(length, b' ');
        let mut steps = exchange();
        steps.push(Step::Response(HttpResponse { status: 201, body }));
        let rig = Rig::new(steps, true);
        let before = rig.counts();
        let wire = rig.call(OPEN).await;
        rig.assert_slot_sequence();
        if length == 8192 {
            assert_eq!(wire, (FrameType::Response, json!({"result":slot_reply()})));
            assert_eq!(rig.counts(), (before.0, before.1 + 1, before.2));
        } else {
            assert_refused(wire, "relay_reply_invalid/permanent");
            assert_eq!(rig.counts(), before);
        }
    }
}

#[tokio::test]
async fn github_app_relay_slot_open_audit_failure_does_not_release_webhook_url() {
    let mut steps = exchange();
    steps.push(reply(201, slot_reply()));
    let rig = Rig::new(steps, true);
    rig.db
        .execute_batch(
            "CREATE TRIGGER refuse_slot_audit BEFORE INSERT ON audit_log
        BEGIN SELECT RAISE(ABORT, 'injected audit write failure'); END;",
        )
        .unwrap();
    let before = rig.counts();
    let wire = rig.call(OPEN).await;
    assert!(!wire.1.to_string().contains(SLOT));
    assert_refused(wire, "audit_write_failed/permanent");
    rig.assert_slot_sequence();
    assert_eq!(rig.counts(), before);
}

#[tokio::test(start_paused = true)]
async fn github_app_relay_slot_open_deadline_cancels_mint_and_relay_io() {
    for delay_mint in [true, false] {
        let mut steps = if delay_mint { Vec::new() } else { exchange() };
        steps.push(Step::Pending);
        let rig = Rig::new(steps, true);
        let before = rig.counts();
        let tag = rig.sign(OPEN);
        let admin = rig.admin.clone();
        let read = rig.read.clone();
        let mut call = tokio::spawn(async move {
            crate::tests::routed_reply(
                &read,
                &admin,
                1,
                OP_ADMIN_OP,
                json!({"op_body":OPEN,"tag_hex":tag}),
            )
            .await
        });
        tokio::select! {
            _ = rig.http.pending.notified() => {}
            _ = &mut call => panic!("request ended before reaching the delayed HTTP call"),
        }
        tokio::time::advance(crate::federation::ADMIN_OP_BUDGET).await;
        let (frame, bytes) = call.await.unwrap();
        assert_refused(
            (frame, serde_json::from_slice(&bytes).unwrap()),
            "relay_unavailable/transient",
        );
        assert_eq!(rig.counts(), before);
        if delay_mint {
            assert_eq!(rig.http.requests.lock().unwrap().len(), 1);
        } else {
            rig.assert_slot_sequence();
        }
    }
}

#[tokio::test]
async fn github_app_admin_ops_reject_offline_open_and_check_route_admission_before_effects() {
    use crate::federation::RouteCaller;

    let rig = Rig::new(vec![], true);
    rig.store
        .set_federation_member_mapping_audited(true, AuditCtx::admin(AuditOp::FederationGateSet))
        .unwrap();
    rig.store
        .set_secret_phone_mapping_audited(true, AuditCtx::admin(AuditOp::SecretPhoneGateSet))
        .unwrap();
    for (channel, harness) in [
        (2, "fed-computer:11111111111111111111111111111111"),
        (3, "fed-phone:11111111111111111111111111111111"),
    ] {
        rig.admin.record_bind_at(
            channel,
            1,
            Principal::Reserved {
                module_id: "callosum".into(),
            },
            harness,
        );
    }
    assert!(matches!(rig.admin.route_caller(2), RouteCaller::Member(_)));
    assert!(matches!(rig.admin.route_caller(3), RouteCaller::Phone(_)));
    let before = rig.counts();
    let open: AdminOpBody = serde_json::from_str(OPEN).unwrap();
    assert!(open.requires_daemon());
    assert!(
        matches!(apply(&rig.store, open, "offline-cli"), Err(StoreOpError::Encode(reason)) if reason.starts_with(FEDERATION_REQUIRES_DAEMON))
    );
    let prepare: AdminOpBody = serde_json::from_str(PREPARE).unwrap();
    assert!(!prepare.requires_daemon());
    let (frame, reply) = rig.call(PREPARE).await;
    assert_eq!(frame, FrameType::Response);
    assert_eq!(reply["result"]["name"].as_str().unwrap().len(), 32);
    assert_refused(
        rig.call(r#"{"op":"admin.github_app_manifest_prepare","v":1,"agent":"wrong"}"#)
            .await,
        "agent_invalid/permanent",
    );

    let create = create_body(CODE, AGENT, Some(SLOT));
    let create_op: AdminOpBody = serde_json::from_str(&create).unwrap();
    assert!(create_op.requires_daemon());
    assert!(
        matches!(apply(&rig.store, create_op, "offline-cli"), Err(StoreOpError::Encode(reason)) if reason.starts_with(FEDERATION_REQUIRES_DAEMON))
    );
    for body in [OPEN, PREPARE, &create] {
        let valid_direct_tag = rig.sign(body);
        for channel in [2, 3] {
            let (_, reply) = rig.route(channel, body, &valid_direct_tag).await;
            assert!(reply["result"]["slot"].is_null());
            assert!(reply["result"]["name"].is_null());
            assert!(reply["result"]["outcome"].is_null());
        }
        let (frame, reply) = rig.route(1, body, &"00".repeat(32)).await;
        assert_eq!(frame, FrameType::Error);
        assert_eq!(reply["code"], "admin_refused");
        assert_eq!(reply["message"], "auth failed");
    }
    rig.db
        .execute(
            "INSERT INTO settings (name,value,updated_at_ms) VALUES (?1,?2,1)",
            [
                SECRET_HOME_SETTING,
                "fed-computer:22222222222222222222222222222222",
            ],
        )
        .unwrap();
    assert_refused(rig.call(PREPARE).await, "policy_unavailable/permanent");
    let (frame, reply) = rig.call(OPEN).await;
    assert_eq!(frame, FrameType::Error);
    assert_eq!(reply["code"], "admin_refused");
    assert!(reply["message"]
        .as_str()
        .unwrap()
        .starts_with("remote_setup_incomplete/"));
    let (frame, reply) = rig.call(&create).await;
    assert_eq!(frame, FrameType::Error);
    assert_eq!(reply["code"], "admin_refused");
    assert_eq!(reply["message"], "remote_setup_incomplete/permanent");
    assert_eq!(rig.counts(), before);
    assert!(rig.http.requests.lock().unwrap().is_empty());
}

fn conversion(slug: &str) -> Value {
    json!({"id":LARGE_APP_ID,"slug":slug,"pem":PKCS1_PEM,"client_id":"fixture-client-id",
        "client_secret":CLIENT_SECRET,"webhook_secret":WEBHOOK_SECRET})
}

fn create_body(code: &str, agent: &str, slot: Option<&str>) -> String {
    let op = AdminOpBody::GitHubAppCreateComplete {
        v: 1,
        code: code.into(),
        agent: agent.into(),
        slot: slot.map(str::to_owned),
    };
    assert_redacted(&format!("{op:?}"));
    serde_json::to_string(&op).unwrap()
}

fn assert_redacted(text: &str) {
    for secret in [
        CODE,
        WEBHOOK_SECRET,
        CLIENT_SECRET,
        PEM_ARMOUR,
        TOKEN_MARKER,
        PKCS1_PEM.lines().nth(1).unwrap(),
    ] {
        assert!(!text.contains(secret), "secret appeared in an output");
    }
}

fn created(slug: &str) -> Value {
    json!({"outcome":"created", "slug":slug, "app_id":LARGE_APP_ID.to_string(),
        "install_url":format!("https://github.com/apps/{slug}/installations/new")})
}

fn assert_result((frame, value): (FrameType, Value), expected: Value) {
    assert_redacted(&value.to_string());
    assert_eq!(frame, FrameType::Response);
    assert_eq!(value, json!({"result":expected}));
}

fn assert_conversion_audit_redacted(rig: &Rig) {
    let mut stmt = rig
        .db
        .prepare("SELECT op, actor, credential_id, payload_hash, alarm FROM audit_log")
        .unwrap();
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_redacted(&format!("{rows:?}"));
    for (op, actor, id, digest, alarm) in rows {
        if op == "github_app.create_complete" {
            assert_eq!(actor, "route-admin");
            assert!(id.unwrap().starts_with("github_app:"));
            assert_eq!(alarm, 0);
            let digest = digest.unwrap();
            assert_eq!(digest.len(), 64);
            assert!(digest.bytes().all(|b| b.is_ascii_hexdigit()));
        }
    }
    assert_eq!(rig.store.verify_audit_chain().unwrap(), None);
}

#[tokio::test]
async fn github_app_create_complete_commits_record_and_one_audit_before_put() {
    let capture = Capture::default();
    let _capture = tracing::subscriber::set_default(capture.clone());
    let mut steps = vec![reply(201, conversion("created-app"))];
    steps.extend(exchange());
    steps.push(reply(200, json!({"echo": WEBHOOK_SECRET})));
    let rig = Rig::new(steps, true);
    let before = rig.counts();
    let wire = rig.call(&create_body(CODE, AGENT, Some(SLOT))).await;
    assert_result(wire, created("created-app"));
    assert_eq!(rig.counts(), (before.0 + 2, before.1 + 1, before.2));
    let row: (String, String, i64, String, String) = rig.db.query_row(
        "SELECT github_app_id, github_app_slug, github_app_created_at_ms, github_app_agent, github_app_relay_slot FROM credentials WHERE credential_id='github_app:created-app'",
        [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
    ).unwrap();
    assert_eq!(row.0, LARGE_APP_ID.to_string());
    assert_eq!(row.1, "created-app");
    assert!(row.2 > 0);
    assert_eq!(row.3, AGENT);
    assert_eq!(row.4, SLOT);
    let record = rig.store.get("github_app:created-app").unwrap();
    let companion = rig
        .store
        .get("opaque:github-app-webhook:created-app")
        .unwrap();
    assert_redacted(&format!("{record:?} {companion:?}"));
    assert_eq!(record.refresh_adapter.as_deref(), Some("github_app"));
    let oauth = record.oauth.unwrap();
    assert!(oauth.access_token.expose().is_empty());
    assert!(oauth.client_secret.is_none());
    assert!(oauth.refresh_token.expose() == PKCS1_PEM);
    let jwt = GithubAppAdapter::build_app_jwt(&oauth, 1_800_000_000).unwrap();
    let (_, claims) = jwt.split_once('.').unwrap();
    let (claims, signature) = claims.split_once('.').unwrap();
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims).unwrap()).unwrap();
    assert_eq!(claims["iss"], "fixture-client-id");
    assert!(!signature.is_empty());
    let current: Value = serde_json::from_slice(companion.payload.expose()).unwrap();
    assert!(current == json!({"current":WEBHOOK_SECRET}));
    assert_eq!(rig.http.requests.lock().unwrap().len(), 4);
    assert_conversion_audit_redacted(&rig);
    assert_redacted(&capture.0.lock().unwrap());

    let before = rig.counts();
    assert_refused(rig.call(PREPARE).await, "github_app_agent_exists/permanent");
    assert_refused(
        rig.call(&create_body(CODE, AGENT, None)).await,
        "github_app_agent_exists/permanent",
    );
    assert_eq!(rig.counts(), before);
    assert_eq!(rig.http.requests.lock().unwrap().len(), 4);
}

#[tokio::test]
async fn github_app_create_complete_validates_reply_and_flattens_failures() {
    let capture = Capture::default();
    let _capture = tracing::subscriber::set_default(capture.clone());
    let bad_pem = format!("-----BEGIN {PEM_ARMOUR}-----\nAAA=\n-----END {PEM_ARMOUR}-----");
    let mut cases = vec![
        ("id", json!(-1)),
        ("id", json!(0)),
        ("id", json!("123")),
        ("id", json!(4.5)),
        ("slug", json!("../not-a-slug")),
        ("slug", json!(false)),
        ("slug", Value::Null),
        ("pem", json!(bad_pem)),
        ("pem", Value::Null),
        ("client_id", json!("")),
        ("client_id", json!([])),
        ("webhook_secret", json!("")),
        ("webhook_secret", Value::Null),
    ];
    let mut steps: Vec<_> = cases
        .iter()
        .map(|(field, value)| {
            let mut raw = conversion("reply-app");
            if value.is_null() {
                raw.as_object_mut().unwrap().remove(*field);
            } else {
                raw[*field] = value.clone();
            }
            reply(201, raw)
        })
        .collect();
    steps.push(Step::Response(HttpResponse {
        status: 201,
        body: b"{broken".to_vec(),
    }));
    cases.push(("json", Value::Null));
    let rig = Rig::new(steps, true);
    let before = rig.counts();
    for (field, _) in &cases {
        let mut expected = json!({"outcome":"github_app_unsaved","cause":"reply_invalid"});
        if !matches!(*field, "slug" | "json") {
            expected["slug"] = json!("reply-app");
        }
        if !matches!(*field, "id" | "json") {
            expected["app_id"] = json!(LARGE_APP_ID.to_string());
        }
        assert_result(
            rig.call(&create_body(CODE, AGENT, Some(SLOT))).await,
            expected,
        );
        assert_eq!(rig.counts(), before);
    }
    assert_eq!(rig.http.requests.lock().unwrap().len(), cases.len());
    assert_conversion_audit_redacted(&rig);
    assert_redacted(&capture.0.lock().unwrap());
}

#[tokio::test]
async fn github_app_create_complete_conversion_status_table_never_retries() {
    let capture = Capture::default();
    let _capture = tracing::subscriber::set_default(capture.clone());
    let responses = [
        (
            reply(422, conversion("echo")),
            "github_app_code_invalid/permanent",
        ),
        (
            reply(307, conversion("echo")),
            "github_app_conversion_unknown/permanent",
        ),
        (
            reply(500, conversion("echo")),
            "github_app_conversion_unknown/permanent",
        ),
        (
            Step::TransportError,
            "github_app_conversion_unknown/permanent",
        ),
    ];
    for (step, prefix) in responses {
        let rig = Rig::new(vec![step], true);
        let before = rig.counts();
        let wire = rig.call(&create_body(CODE, AGENT, Some(SLOT))).await;
        assert_redacted(&wire.1.to_string());
        assert_refused(wire, prefix);
        assert_eq!(rig.counts(), before);
        let expected = format!("{GITHUB_MANIFEST_BASE}/{CODE}/conversions");
        assert!(rig.http.requests.lock().unwrap().as_slice() == [expected]);
    }
    assert_redacted(&capture.0.lock().unwrap());
}

#[tokio::test]
async fn github_app_create_complete_code_accepts_128_and_refuses_129_before_http() {
    let mut response = conversion("boundary-code");
    response["webhook_secret"] = json!({"malformed": WEBHOOK_SECRET});
    let rig = Rig::new(vec![reply(201, response)], false);
    let before = rig.counts();
    for (code, agent, slot, prefix) in [
        ("a".repeat(129), AGENT, None, "invalid_params/permanent"),
        (String::new(), AGENT, None, "invalid_params/permanent"),
        ("a/b".into(), AGENT, None, "invalid_params/permanent"),
        (
            CODE.into(),
            AGENT,
            Some("../invalid-slot"),
            "invalid_params/permanent",
        ),
        (
            CODE.into(),
            "wrong-agent",
            Some(SLOT),
            "agent_invalid/permanent",
        ),
    ] {
        assert_refused(rig.call(&create_body(&code, agent, slot)).await, prefix);
    }
    assert!(rig.http.requests.lock().unwrap().is_empty());
    assert_eq!(rig.counts(), before);
    let limit = "a".repeat(128);
    assert_result(
        rig.call(&create_body(&limit, AGENT, None)).await,
        created("boundary-code"),
    );
    assert_eq!(rig.counts(), (before.0 + 1, before.1 + 1, before.2));
    assert!(
        rig.http.requests.lock().unwrap().as_slice()
            == [format!("{GITHUB_MANIFEST_BASE}/{limit}/conversions")]
    );
}

#[test]
fn github_app_create_complete_reply_accepts_64_kib_and_refuses_one_byte_more() {
    let mut body = serde_json::to_vec(&conversion("limit")).unwrap();
    body.resize(65_536, b' ');
    assert!(read_conversion(&body, false).is_ok());
    body.push(b' ');
    assert!(
        matches!(read_conversion(&body, false), Err(AdminOutcome::Ok(v)) if v == json!({"outcome":"github_app_unsaved","cause":"reply_invalid"}))
    );
}

#[tokio::test]
async fn github_app_create_complete_put_failure_table_keeps_app_and_companion() {
    let capture = Capture::default();
    let _capture = tracing::subscriber::set_default(capture.clone());
    let mut cases: Vec<_> = [
        (401, "relay_unavailable_for_account"),
        (403, "relay_unavailable_for_account"),
        (404, "relay_slot_expired"),
        (409, "relay_app_mismatch"),
        (429, "relay_unavailable"),
        (307, "relay_unavailable"),
        (503, "relay_unavailable"),
        (418, "relay_request_refused"),
        (201, "relay_reply_invalid"),
        (204, "relay_reply_invalid"),
    ]
    .into_iter()
    .map(|(status, cause)| (reply(status, json!({"echo":WEBHOOK_SECRET})), cause))
    .collect();
    cases.push((Step::TransportError, "relay_unavailable"));
    for (step, cause) in cases {
        let mut steps = vec![reply(201, conversion("relay-app"))];
        steps.extend(exchange());
        steps.push(step);
        let rig = Rig::new(steps, true);
        let before = rig.counts();
        let mut expected = created("relay-app");
        expected["outcome"] = json!("relay_registration_failed");
        expected["cause"] = json!(cause);
        assert_result(
            rig.call(&create_body(CODE, AGENT, Some(SLOT))).await,
            expected,
        );
        assert_eq!(rig.counts(), (before.0 + 2, before.1 + 1, before.2));
        assert_eq!(rig.http.requests.lock().unwrap().len(), 4);
        let companion = rig
            .store
            .get("opaque:github-app-webhook:relay-app")
            .unwrap();
        assert!(
            serde_json::from_slice::<Value>(companion.payload.expose()).unwrap()
                == json!({"current":WEBHOOK_SECRET})
        );
        assert_conversion_audit_redacted(&rig);
    }
    let rig = Rig::new(vec![reply(201, conversion("relay-app"))], false);
    let before = rig.counts();
    let mut expected = created("relay-app");
    expected["outcome"] = json!("relay_registration_failed");
    expected["cause"] = json!("relay_unavailable_for_account");
    assert_result(
        rig.call(&create_body(CODE, AGENT, Some(SLOT))).await,
        expected,
    );
    assert_eq!(rig.counts(), (before.0 + 2, before.1 + 1, before.2));
    assert_eq!(rig.http.requests.lock().unwrap().len(), 1);
    assert_redacted(&capture.0.lock().unwrap());
}

#[test]
fn github_app_relay_put_reply_accepts_8_kib_and_refuses_one_byte_more() {
    assert_eq!(
        confirmed_put(HttpResponse {
            status: 200,
            body: vec![b' '; 8192]
        }),
        Ok(())
    );
    assert_eq!(
        confirmed_put(HttpResponse {
            status: 200,
            body: vec![b' '; 8193]
        }),
        Err(RelayFailure::ReplyInvalid)
    );
}

#[tokio::test]
async fn github_app_create_complete_rejects_local_companion_and_remote_collisions() {
    for id in [
        "github_app:collision",
        "opaque:github-app-webhook:collision",
        "remote",
    ] {
        let rig = Rig::new(vec![reply(201, conversion("collision"))], true);
        if id == "remote" {
            rig.db.execute(
                "INSERT INTO remote_records (credential_id, home_member, incarnation, kind, last_home_version, last_home_state, created_at_ms, updated_at_ms) \
                 VALUES ('github_app:collision', 'another-vault', ?1, 'oauth', 1, 'active', 0, 0)",
                ["0".repeat(32)],
            ).unwrap();
        } else {
            rig.store
                .create(
                    id,
                    &VaultRecord::new_static(
                        CredentialKind::Opaque,
                        "test",
                        b"existing".to_vec(),
                        None,
                    ),
                )
                .unwrap();
            rig.db
                .execute(
                    "UPDATE credentials SET state='needs_reauth' WHERE credential_id=?1",
                    [id],
                )
                .unwrap();
        }
        let before = rig.counts();
        assert_result(
            rig.call(&create_body(CODE, AGENT, Some(SLOT))).await,
            json!({
                "outcome":"github_app_unsaved","slug":"collision","app_id":LARGE_APP_ID.to_string(),"cause":"github_app_exists"
            }),
        );
        assert_eq!(rig.counts(), before);
        assert_eq!(rig.http.requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn github_app_create_complete_rolls_back_rows_if_audit_fails() {
    let capture = Capture::default();
    let _capture = tracing::subscriber::set_default(capture.clone());
    let rig = Rig::new(vec![reply(201, conversion("audit-rollback"))], true);
    rig.db
        .execute_batch(
            "CREATE TRIGGER refuse_create_audit BEFORE INSERT ON audit_log \
         WHEN NEW.op = 'github_app.create_complete' \
         BEGIN SELECT RAISE(ABORT, 'injected audit write failure'); END;",
        )
        .unwrap();
    let before = rig.counts();
    assert_result(
        rig.call(&create_body(CODE, AGENT, Some(SLOT))).await,
        json!({
            "outcome":"github_app_unsaved","slug":"audit-rollback","app_id":LARGE_APP_ID.to_string(),"cause":"store_failed"
        }),
    );
    assert_eq!(rig.counts(), before);
    assert_eq!(rig.http.requests.lock().unwrap().len(), 1);
    assert_conversion_audit_redacted(&rig);
    assert_redacted(&capture.0.lock().unwrap());
}

#[tokio::test]
async fn github_app_create_complete_concurrent_agent_loser_returns_its_own_slug() {
    let rendezvous = Arc::new(Barrier::new(2));
    let rig = Rig::new(
        ["one", "two"]
            .into_iter()
            .map(|slug| {
                Step::Together(
                    rendezvous.clone(),
                    HttpResponse {
                        status: 201,
                        body: serde_json::to_vec(&conversion(slug)).unwrap(),
                    },
                )
            })
            .collect(),
        false,
    );
    let before = rig.counts();
    let admin = &rig.admin.github_apps;
    let (first, second) = tokio::join!(
        admin.create_complete(&rig.engine, "first-code".to_owned().into(), AGENT, None),
        admin.create_complete(&rig.engine, "second-code".to_owned().into(), AGENT, None),
    );
    let (AdminOutcome::Ok(first), AdminOutcome::Ok(second)) = (first, second) else {
        panic!("both requests reached GitHub and must return creation outcomes")
    };
    let (winner, loser) = if first["outcome"] == "created" {
        (first, second)
    } else {
        (second, first)
    };
    let winner_slug = winner["slug"].as_str().unwrap();
    let loser_slug = if winner_slug == "one" { "two" } else { "one" };
    assert_eq!(winner, created(winner_slug));
    assert_eq!(
        loser,
        json!({"outcome":"github_app_unsaved","slug":loser_slug,
        "app_id":LARGE_APP_ID.to_string(), "cause":"github_app_agent_exists"})
    );
    assert!(rig.store.get(&format!("github_app:{winner_slug}")).is_ok());
    assert!(rig.store.get(&format!("github_app:{loser_slug}")).is_err());
    assert_eq!(rig.counts(), (before.0 + 1, before.1 + 1, before.2));
    assert_refused(
        rig.call(&create_body(CODE, AGENT, None)).await,
        "github_app_agent_exists/permanent",
    );
    assert_eq!(rig.http.requests.lock().unwrap().len(), 2);
}

fn spawn_route(rig: &Rig, body: String) -> tokio::task::JoinHandle<(FrameType, Vec<u8>)> {
    let tag = rig.sign(&body);
    let admin = rig.admin.clone();
    let read = rig.read.clone();
    tokio::spawn(async move {
        crate::tests::routed_reply(
            &read,
            &admin,
            1,
            OP_ADMIN_OP,
            json!({"op_body":body,"tag_hex":tag}),
        )
        .await
    })
}

#[tokio::test(start_paused = true)]
async fn github_app_create_complete_lock_deadline_returns_busy_without_writing() {
    let response = HttpResponse {
        status: 201,
        body: serde_json::to_vec(&conversion("busy-app")).unwrap(),
    };
    let rig = Rig::new(vec![Step::Signal(response)], true);
    let lock = rig.engine.acquire_admin_lock("github_app:busy-app").await;
    let before = rig.counts();
    let mut call = spawn_route(&rig, create_body(CODE, AGENT, Some(SLOT)));
    tokio::select! {
        _ = rig.http.pending.notified() => {},
        _ = &mut call => panic!("request did not reach conversion"),
    }
    tokio::time::advance(crate::federation::ADMIN_OP_BUDGET).await;
    let (frame, body) = call.await.unwrap();
    assert_result(
        (frame, serde_json::from_slice(&body).unwrap()),
        json!({
            "outcome":"github_app_unsaved","slug":"busy-app","app_id":LARGE_APP_ID.to_string(),"cause":"busy"
        }),
    );
    drop(lock);
    assert_eq!(rig.counts(), before);
    assert_eq!(rig.http.requests.lock().unwrap().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn github_app_create_complete_keeps_lock_through_put_timeout_or_interruption() {
    for interrupted in [false, true] {
        let mut steps = vec![reply(201, conversion("locked-app"))];
        steps.extend(exchange());
        steps.push(Step::Pending);
        let rig = Rig::new(steps, true);
        let before = rig.counts();
        let mut call = spawn_route(&rig, create_body(CODE, AGENT, Some(SLOT)));
        tokio::select! {
            _ = rig.http.pending.notified() => {},
            _ = &mut call => panic!("request did not reach relay PUT"),
        }
        let lock = rig.engine.acquire_admin_lock("github_app:locked-app");
        let mut lock = std::pin::pin!(lock);
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(
                std::future::Future::poll(lock.as_mut(), cx).is_pending()
            ))
            .await
        );
        assert_eq!(rig.counts(), (before.0 + 2, before.1 + 1, before.2));
        if interrupted {
            call.abort();
            assert!(call.await.unwrap_err().is_cancelled());
        } else {
            tokio::time::advance(crate::federation::ADMIN_OP_BUDGET).await;
            let (frame, body) = call.await.unwrap();
            let mut expected = created("locked-app");
            expected["outcome"] = json!("relay_registration_failed");
            expected["cause"] = json!("relay_unavailable");
            assert_result((frame, serde_json::from_slice(&body).unwrap()), expected);
        }
        drop(lock.await);
        assert_refused(rig.call(PREPARE).await, "github_app_agent_exists/permanent");
        assert_eq!(rig.counts(), (before.0 + 2, before.1 + 1, before.2));
        assert_eq!(rig.http.requests.lock().unwrap().len(), 4);
    }
}
